//! Live Rex Control (`rex.control.v1` over `/api/control`) & Terminal Data Stream
//! (`rex.data.terminal.v1` over `/api/data`) supervisor per configured host.
//!
//! Enforces strict Focus & Block Ownership Isolation:
//! - Viewing a pane defaults to **Peek** (`data.connect` + `terminal.format`, NO `session.own_block`,
//!   NO `session.focus_block`, NO `session.select_window`).
//! - Only `set_ownership(Take)` calls `session.own_block` + `terminal.resize`.
//! - Switching away, closing, or `hand_back` calls `session.disown_block` and sets `releasedByUs`.

use crate::rex::{
    transport::{
        classify_endpoint, open_rex_websocket, wait_fd_readable, ConfiguredHost, RexStream,
        WakePipe, Waker,
    },
    types::{
        make_pane_key, ConnPhase, HostState, OwnershipMode, PaneActivityStatus, PaneSummary,
        SessionSummary,
    },
    vt::VtActor,
};
use base64::{
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
    Engine,
};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tungstenite::{Message, WebSocket};

const CONTROL_PATH: &str = "/api/control";
const CONTROL_SUBPROTOCOL: &str = "rex.control.v1";
const DATA_PATH: &str = "/api/data";
const DATA_SUBPROTOCOL: &str = "rex.data.terminal.v1";

pub type HostStateHook = Arc<dyn Fn(HostEvent) + Send + Sync>;

pub enum HostEvent {
    HostSnapshot {
        host: HostState,
        panes: Vec<(PaneSummary, u64)>,
    },
    PaneStreamPhase {
        key: String,
        phase: ConnPhase,
        problem: Option<String>,
    },
    TerminalUpdated,
}

/// A single claim decides whether the worker can start a write or the caller can cancel it.
pub struct InputDispatch {
    deadline: Instant,
    // 0 = Queued, 1 = ClaimedByWorker, 2 = CancelledBeforeStart
    state: AtomicU8,
}

impl InputDispatch {
    pub fn new(deadline: Instant) -> Self {
        Self {
            deadline,
            state: AtomicU8::new(0),
        }
    }

    pub(crate) fn start(&self) -> bool {
        if Instant::now() >= self.deadline {
            let _ = self
                .state
                .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
            return false;
        }
        self.state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub fn cancel_or_unconfirmed(&self) -> (bool, &'static str) {
        match self
            .state
            .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => (false, "输入未发送：发送期限已过或连接已关闭"),
            Err(1) => (true, "发送结果未确认，请先检查终端再重试"),
            Err(_) => (false, "输入未发送：发送期限已过或连接已关闭"),
        }
    }

    pub fn is_claimed(&self) -> bool {
        self.state.load(Ordering::Acquire) == 1
    }
}

pub struct SendInputReply {
    inner: Option<Box<dyn FnOnce(Result<(), String>) + Send>>,
}

impl SendInputReply {
    pub fn new(f: impl FnOnce(Result<(), String>) + Send + 'static) -> Self {
        Self {
            inner: Some(Box::new(f)),
        }
    }

    #[cfg(test)]
    pub fn from_sender(tx: mpsc::Sender<Result<(), String>>) -> Self {
        Self::new(move |res| {
            let _ = tx.send(res);
        })
    }

    pub fn send(mut self, res: Result<(), String>) -> Result<(), ()> {
        if let Some(f) = self.inner.take() {
            f(res);
        }
        Ok(())
    }
}

impl Drop for SendInputReply {
    fn drop(&mut self) {
        if let Some(f) = self.inner.take() {
            f(Err("连接已关闭".into()));
        }
    }
}

pub enum HostCmd {
    EnsureStream {
        session_id: String,
        block_id: String,
        cols: u16,
        rows: u16,
    },
    CloseStreamsExcept {
        keep_key: Option<String>,
    },
    SendInput {
        dispatch: Arc<InputDispatch>,
        session_id: String,
        block_id: String,
        data: String,
        reply: SendInputReply,
    },
    SetOwnership {
        session_id: String,
        block_id: String,
        mode: OwnershipMode,
        cols: u16,
        rows: u16,
        reply: mpsc::Sender<Result<(), String>>,
    },
    NewSession {
        deadline: Instant,
        label: Option<String>,
        cwd: Option<String>,
        reply: mpsc::Sender<Result<String, String>>,
    },
    CloseBlock {
        session_id: String,
        block_id: String,
        reply: mpsc::Sender<Result<(), String>>,
    },
    ReconnectFreshStream {
        session_id: String,
        block_id: String,
        cols: u16,
        rows: u16,
        failed_gen: u64,
        problem: &'static str,
    },
    Stop,
}

pub struct HostWorkerHandle {
    thread: Option<thread::JoinHandle<()>>,
    tx: mpsc::Sender<HostCmd>,
    waker: Waker,
    stop: Arc<AtomicBool>,
}

impl HostWorkerHandle {
    pub fn spawn(
        cfg: ConfiguredHost,
        proxy_port: Arc<AtomicU16>,
        vt: VtActor,
        active_key: Arc<Mutex<Option<String>>>,
        hook: HostStateHook,
    ) -> io::Result<Self> {
        let (tx, rx) = mpsc::channel::<HostCmd>();
        let (wake_pipe, waker) = WakePipe::new()?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let waker_clone = waker.clone();
        let tx_thread = tx.clone();
        let waker_thread = waker.clone();

        let thread = thread::Builder::new()
            .name(format!("rex-host-{}", cfg.id))
            .stack_size(512 * 1024)
            .spawn(move || {
                run_host_supervisor(
                    cfg,
                    proxy_port,
                    vt,
                    active_key,
                    hook,
                    tx_thread,
                    waker_thread,
                    rx,
                    wake_pipe,
                    stop_thread,
                );
            })?;

        Ok(Self {
            thread: Some(thread),
            tx,
            waker: waker_clone,
            stop,
        })
    }

    #[cfg(test)]
    pub fn from_test_channel(tx: mpsc::Sender<HostCmd>) -> io::Result<Self> {
        let (_wake_pipe, waker) = WakePipe::new()?;
        Ok(Self {
            thread: None,
            tx,
            waker,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn send(&self, cmd: HostCmd) -> Result<(), String> {
        self.tx
            .send(cmd)
            .map_err(|_| "主机工作线程已停止".to_string())?;
        self.waker.wake();
        Ok(())
    }

    pub fn join(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.tx.send(HostCmd::Stop);
        self.waker.wake();
    }

    pub fn wake(&self) {
        self.waker.wake();
    }
}

impl Drop for HostWorkerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ActiveDataStream {
    stop: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    waker: Waker,
}

impl ActiveDataStream {
    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire) && !self.stop.load(Ordering::Acquire)
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.waker.wake();
    }
}

impl Drop for ActiveDataStream {
    fn drop(&mut self) {
        self.stop();
    }
}

struct SessionTrack {
    label: String,
    view_revision: u64,
    window_count: usize,
}

#[derive(Clone)]
struct BlockMeta {
    session_id: String,
    window_id: String,
    window_label: String,
    block_id: String,
    title: String,
    program: String,
    pwd: String,
    status: PaneActivityStatus,
    run_epoch: u64,
    status_kind: Option<String>,
    status_msg: Option<String>,
    owned_by_us: bool,
    released_by_us: bool,
    updated_at_ms: u64,
}

impl BlockMeta {
    fn set_status(&mut self, status: PaneActivityStatus) {
        // A run boundary survives batching of Running and Done into one host snapshot.
        static NEXT_RUN: AtomicU64 = AtomicU64::new(1);
        if self.status != status
            && matches!(
                status,
                PaneActivityStatus::Running
                    | PaneActivityStatus::Blocked
                    | PaneActivityStatus::Error
            )
        {
            self.run_epoch = NEXT_RUN.fetch_add(1, Ordering::Relaxed);
        }
        self.status = status;
    }
}

pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
fn run_host_supervisor(
    cfg: ConfiguredHost,
    proxy_port: Arc<AtomicU16>,
    vt: VtActor,
    active_key: Arc<Mutex<Option<String>>>,
    hook: HostStateHook,
    control_tx: mpsc::Sender<HostCmd>,
    control_waker: Waker,
    rx: mpsc::Receiver<HostCmd>,
    wake_pipe: WakePipe,
    stop: Arc<AtomicBool>,
) {
    let (kind, default_path) = classify_endpoint(&cfg.endpoint);
    let mut reconnect_token: Option<String> = None;
    let mut backoff_ms = 1000u64;
    let mut ever_connected = false;

    while !stop.load(Ordering::Relaxed) {
        hook(HostEvent::HostSnapshot {
            host: HostState {
                id: cfg.id.clone(),
                label: cfg.label.clone(),
                kind,
                endpoint: cfg.endpoint.clone(),
                phase: if ever_connected {
                    ConnPhase::Reconnecting
                } else {
                    ConnPhase::Connecting
                },
                problem: None,
                latency_ms: None,
                path_kind: Some(default_path),
                sessions: Vec::new(),
            },
            panes: Vec::new(),
        });

        let port = proxy_port.load(Ordering::Relaxed);
        let started = Instant::now();
        match connect_and_run_once(
            &cfg,
            port,
            &mut reconnect_token,
            &vt,
            &active_key,
            &hook,
            &control_tx,
            &control_waker,
            &rx,
            &wake_pipe,
            &stop,
        ) {
            Ok(()) => break,
            Err(problem) => {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                if started.elapsed() > Duration::from_secs(10) {
                    ever_connected = true;
                    backoff_ms = 1000;
                }
                hook(HostEvent::HostSnapshot {
                    host: HostState {
                        id: cfg.id.clone(),
                        label: cfg.label.clone(),
                        kind,
                        endpoint: cfg.endpoint.clone(),
                        phase: if ever_connected {
                            ConnPhase::Reconnecting
                        } else {
                            ConnPhase::Failed
                        },
                        problem: Some(problem),
                        latency_ms: None,
                        path_kind: Some(default_path),
                        sessions: Vec::new(),
                    },
                    panes: Vec::new(),
                });

                // Drain immediate commands with error while disconnected so UI never hangs.
                drain_disconnected_cmds(&rx, &stop);
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let _ = wait_fd_readable(-1, wake_pipe.read_fd(), backoff_ms as i32);
                wake_pipe.drain();
                drain_disconnected_cmds(&rx, &stop);
                backoff_ms = (backoff_ms * 2).min(8000);
            }
        }
    }
}

fn drain_disconnected_cmds(rx: &mpsc::Receiver<HostCmd>, stop: &AtomicBool) {
    while let Ok(cmd) = rx.try_recv() {
        let err = Err("主机当前未连接，正在自动重连".to_string());
        match cmd {
            HostCmd::SendInput { reply, .. } => {
                let _ = reply.send(err);
            }
            HostCmd::SetOwnership { reply, .. } | HostCmd::CloseBlock { reply, .. } => {
                let _ = reply.send(err);
            }
            HostCmd::NewSession { reply, .. } => {
                let _ = reply.send(Err("主机当前未连接".into()));
            }
            HostCmd::EnsureStream { .. }
            | HostCmd::CloseStreamsExcept { .. }
            | HostCmd::ReconnectFreshStream { .. } => {}
            HostCmd::Stop => {
                stop.store(true, Ordering::SeqCst);
            }
        }
    }
}

struct ControlRpcConn {
    ws: WebSocket<RexStream>,
    next_id: u64,
    operation_deadline: Option<Instant>,
    queued_events: VecDeque<Value>,
}

impl ControlRpcConn {
    fn call(&mut self, method: &str, payload: Value) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id.to_string();
        let msg = json!({
            "type": "request",
            "id": id,
            "method": method,
            "payload": payload,
        });
        let deadline = Instant::now() + Duration::from_secs(8);
        let deadline = self.operation_deadline.unwrap_or(deadline).min(deadline);
        if Instant::now() >= deadline {
            return Err(format!("RPC {method} timed out"));
        }
        self.ws.get_mut().set_read_deadline(Some(deadline));
        let result = self.call_inner(method, &id, msg, deadline);
        self.ws.get_mut().set_read_deadline(None);
        result
    }

    fn call_inner(
        &mut self,
        method: &str,
        id: &str,
        msg: Value,
        deadline: Instant,
    ) -> Result<Value, String> {
        self.ws
            .send(Message::Text(msg.to_string().into()))
            .map_err(|e| format!("RPC send {method}: {e}"))?;

        loop {
            if Instant::now() > deadline {
                return Err(format!("RPC {method} timed out"));
            }
            match self.ws.read() {
                Ok(Message::Text(txt)) => {
                    let Ok(val) = serde_json::from_str::<Value>(txt.as_str()) else {
                        continue;
                    };
                    match val.get("type").and_then(Value::as_str) {
                        Some("response") if val.get("id").and_then(Value::as_str) == Some(id) => {
                            if let Some(err) = val.get("error").filter(|v| !v.is_null()) {
                                let msg = err
                                    .get("message")
                                    .and_then(Value::as_str)
                                    .unwrap_or("rex rpc error");
                                return Err(format!("{method}: {msg}"));
                            }
                            return Ok(val.get("payload").cloned().unwrap_or_else(|| json!({})));
                        }
                        Some("event") => {
                            self.queued_events.push_back(val);
                        }
                        _ => {}
                    }
                }
                Ok(Message::Ping(_)) => {
                    let _ = self.ws.flush();
                }
                Ok(Message::Close(_)) => return Err("control WS closed".into()),
                Ok(_) => continue,
                Err(tungstenite::Error::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    let fd = self.ws.get_ref().read_fd();
                    let _ = wait_fd_readable(fd, -1, 100);
                }
                Err(e) => return Err(format!("RPC read {method}: {e}")),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_rpc_queued_events(
    rpc: &mut ControlRpcConn,
    cfg: &ConfiguredHost,
    our_client_id: &mut String,
    sessions: &mut HashMap<String, SessionTrack>,
    blocks: &mut HashMap<String, BlockMeta>,
    data_streams: &mut HashMap<String, ActiveDataStream>,
    vt: &VtActor,
    active_key: &Arc<Mutex<Option<String>>>,
) -> bool {
    let mut dirty = false;
    while let Some(ev) = rpc.queued_events.pop_front() {
        dirty |= handle_control_event(
            rpc,
            cfg,
            our_client_id,
            sessions,
            blocks,
            data_streams,
            vt,
            active_key,
            &ev,
        );
    }
    dirty
}

#[allow(clippy::too_many_arguments)]
fn connect_and_run_once(
    cfg: &ConfiguredHost,
    tsnet_port: u16,
    reconnect_token: &mut Option<String>,
    vt: &VtActor,
    active_key: &Arc<Mutex<Option<String>>>,
    hook: &HostStateHook,
    control_tx: &mpsc::Sender<HostCmd>,
    control_waker: &Waker,
    rx: &mpsc::Receiver<HostCmd>,
    wake_pipe: &WakePipe,
    stop: &Arc<AtomicBool>,
) -> Result<(), String> {
    let (kind, default_path) = classify_endpoint(&cfg.endpoint);
    let t0 = Instant::now();
    let cancel = wake_pipe.cancel_watch(stop.clone());
    let mut ws = open_rex_websocket(
        &cfg.endpoint,
        cfg.ssh_key_path.as_deref(),
        tsnet_port,
        CONTROL_PATH,
        CONTROL_SUBPROTOCOL,
        cancel,
    )?;
    ws.get_mut()
        .set_read_deadline(Some(Instant::now() + Duration::from_secs(8)));

    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    let mut hello = json!({
        "type": "hello",
        "api_revision": 19,
        "api_min_revision": 10,
        "client": {
            "kind": "app",
            "platform": platform,
            "name": "rex-zero",
            "version": "0.2.0",
            "label": "CardputerZero"
        }
    });
    if let Some(tok) = reconnect_token.as_deref() {
        hello["reconnect_token"] = json!(tok);
    }
    ws.send(Message::Text(hello.to_string().into()))
        .map_err(|e| format!("send hello: {e}"))?;

    let welcome_txt = loop {
        match ws.read() {
            Ok(Message::Text(t)) => break t.as_str().to_string(),
            Ok(Message::Ping(_)) => {
                let _ = ws.flush();
            }
            Ok(Message::Close(c)) => {
                return Err(format!(
                    "server rejected hello: {}",
                    c.map(|f| f.reason.to_string()).unwrap_or_default()
                ));
            }
            Ok(_) => continue,
            Err(e) => return Err(format!("await welcome: {e}")),
        }
    };
    let latency_ms = t0.elapsed().as_millis().min(9999) as u32;

    let welcome: Value =
        serde_json::from_str(&welcome_txt).map_err(|e| format!("bad welcome JSON: {e}"))?;
    if welcome.get("type").and_then(Value::as_str) != Some("welcome") {
        return Err("first server message was not welcome".into());
    }
    let mut our_client_id = welcome
        .pointer("/client/id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if let Some(tok) = welcome
        .pointer("/client/reconnect_token")
        .and_then(Value::as_str)
    {
        *reconnect_token = Some(tok.to_string());
    }

    let mut rpc = ControlRpcConn {
        ws,
        next_id: 0,
        operation_deadline: None,
        queued_events: VecDeque::new(),
    };

    // Subscribe to all session & block events across the server (`M3.2-status-sweep` across ALL sessions).
    let attach_all = rpc.call("session.attach_all", json!({ "event_scope": "all" }))?;
    let mut sessions: HashMap<String, SessionTrack> = HashMap::new();
    let mut blocks: HashMap<String, BlockMeta> = HashMap::new();
    let mut data_streams: HashMap<String, ActiveDataStream> = HashMap::new();
    let mut last_format_at: HashMap<String, Instant> = HashMap::new();
    let mut next_stream_gen: u64 = 0;
    // Record the last issued generation even after its worker exits and its descriptors close.
    let mut retry_generations: HashMap<String, (u64, u8)> = HashMap::new();

    let mut session_items = attach_all
        .get("sessions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if session_items.is_empty() {
        if let Ok(listed) = rpc.call("session.list", json!({})) {
            if let Some(arr) = listed.get("sessions").and_then(Value::as_array) {
                session_items = arr.clone();
            }
        }
    }

    for item in &session_items {
        let sid = item
            .get("session_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let slabel = item
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or(&sid)
            .to_string();
        if !sid.is_empty() {
            attach_and_sync_session(
                &mut rpc,
                &cfg.id,
                &sid,
                &slabel,
                &mut our_client_id,
                &mut sessions,
                &mut blocks,
            );
        }
    }

    publish_host_snapshot(
        cfg,
        kind,
        default_path,
        latency_ms,
        &sessions,
        &blocks,
        hook,
    );

    // Switch underlying stream to steady-state nonblocking loop for 0% CPU event + RPC loop!
    rpc.ws
        .get_mut()
        .enable_nonblocking_loop()
        .map_err(|e| format!("nonblocking control stream: {e}"))?;

    'control: loop {
        if stop.load(Ordering::Acquire) {
            break;
        }

        data_streams.retain(|_, stream| stream.is_alive());

        // 1. Process any events queued during earlier synchronous RPC calls.
        let mut dirty = drain_rpc_queued_events(
            &mut rpc,
            cfg,
            &mut our_client_id,
            &mut sessions,
            &mut blocks,
            &mut data_streams,
            vt,
            active_key,
        );

        // 2. Drain outbound commands from UI / Engine.
        while let Ok(cmd) = rx.try_recv() {
            if stop.load(Ordering::Acquire) {
                break 'control;
            }
            match cmd {
                HostCmd::Stop => {
                    stop.store(true, Ordering::SeqCst);
                    break;
                }
                HostCmd::CloseStreamsExcept { keep_key } => {
                    data_streams.retain(|k, stream| {
                        if keep_key.as_deref() == Some(k.as_str()) {
                            true
                        } else {
                            retry_generations.remove(k);
                            last_format_at.remove(k);
                            stream.stop();
                            false
                        }
                    });
                }
                HostCmd::EnsureStream {
                    session_id,
                    block_id,
                    cols,
                    rows,
                } => {
                    let key = make_pane_key(&cfg.id, &session_id, &block_id);
                    let alive_now = data_streams
                        .get(&key)
                        .is_some_and(ActiveDataStream::is_alive);
                    if !alive_now {
                        // Stop any inactive background streams on this host so only the viewed pane streams!
                        data_streams.retain(|k, stream| {
                            if k == &key {
                                true
                            } else {
                                retry_generations.remove(k);
                                last_format_at.remove(k);
                                stream.stop();
                                false
                            }
                        });
                        if let Some(dead) = data_streams.remove(&key) {
                            dead.stop();
                        }
                        next_stream_gen += 1;
                        let sgen = next_stream_gen;
                        retry_generations.insert(key.clone(), (sgen, 0));
                        if let Some(stream) = start_block_data_stream(
                            &mut rpc,
                            cfg,
                            tsnet_port,
                            &session_id,
                            &block_id,
                            cols,
                            rows,
                            sgen,
                            vt.clone(),
                            hook.clone(),
                            control_tx.clone(),
                            control_waker.clone(),
                        ) {
                            data_streams.insert(key.clone(), stream);
                        }
                        if let Ok(fmt) = rpc.call(
                            "com.superlogical.terminal.format",
                            json!({
                                "session_id": session_id,
                                "block_id": block_id,
                                "args": { "format": "text", "trim": true, "unwrap": true, "max_bytes": 65536 }
                            }),
                        ) {
                            if let Some(txt) = fmt.get("content").and_then(Value::as_str) {
                                vt.set_format_text(&key, txt.to_string());
                            }
                        }
                        last_format_at.insert(key, Instant::now());
                    } else {
                        let is_running = blocks
                            .get(&block_id)
                            .is_some_and(|b| b.status == PaneActivityStatus::Running);
                        let min_gap = if is_running {
                            Duration::from_millis(1800)
                        } else {
                            Duration::from_secs(6)
                        };
                        if last_format_at.get(&key).map_or(true, |t| t.elapsed() >= min_gap) {
                            last_format_at.insert(key.clone(), Instant::now());
                            rpc.operation_deadline = Some(Instant::now() + Duration::from_millis(1500));
                            if let Ok(fmt) = rpc.call(
                                "com.superlogical.terminal.format",
                                json!({
                                    "session_id": session_id,
                                    "block_id": block_id,
                                    "args": { "format": "text", "trim": true, "unwrap": true, "max_bytes": 65536 }
                                }),
                            ) {
                                if let Some(txt) = fmt.get("content").and_then(Value::as_str) {
                                    vt.set_format_text(&key, txt.to_string());
                                }
                            }
                            rpc.operation_deadline = None;
                        }
                    }
                }
                HostCmd::ReconnectFreshStream {
                    session_id,
                    block_id,
                    cols,
                    rows,
                    failed_gen,
                    problem,
                } => {
                    let key = make_pane_key(&cfg.id, &session_id, &block_id);
                    if !blocks.contains_key(&block_id) {
                        continue;
                    }
                    let Some((generation, retries)) = retry_generations.get_mut(&key) else {
                        continue;
                    };
                    if *generation != failed_gen {
                        continue;
                    }
                    if *retries >= 2 {
                        retry_generations.remove(&key);
                        data_streams.remove(&key);
                        hook(HostEvent::PaneStreamPhase {
                            key,
                            phase: ConnPhase::Failed,
                            problem: Some(problem.into()),
                        });
                    } else {
                        *retries += 1;
                        if let Some(dead) = data_streams.remove(&key) {
                            dead.stop();
                        }
                        next_stream_gen += 1;
                        let sgen = next_stream_gen;
                        *generation = sgen;
                        if let Some(stream) = start_block_data_stream(
                            &mut rpc,
                            cfg,
                            tsnet_port,
                            &session_id,
                            &block_id,
                            cols,
                            rows,
                            sgen,
                            vt.clone(),
                            hook.clone(),
                            control_tx.clone(),
                            control_waker.clone(),
                        ) {
                            data_streams.insert(key, stream);
                        }
                    }
                }
                HostCmd::SendInput {
                    session_id,
                    block_id,
                    data,
                    dispatch,
                    reply,
                } => {
                    if !dispatch.start() {
                        let _ = reply.send(Err("输入未发送：发送期限已过".into()));
                        continue;
                    }
                    rpc.operation_deadline = Some(dispatch.deadline);
                    let res = rpc
                        .call(
                            "com.superlogical.terminal.write",
                            json!({
                                "session_id": session_id,
                                "block_id": block_id,
                                "args": { "data": data }
                            }),
                        )
                        .map(|_| ())
                        .map_err(|e| format!("发送未确认：{e}"));
                    rpc.operation_deadline = None;
                    let _ = reply.send(res);
                }
                HostCmd::SetOwnership {
                    session_id,
                    block_id,
                    mode,
                    cols,
                    rows,
                    reply,
                } => {
                    let res = match mode {
                        OwnershipMode::Take => {
                            let r1 = rpc.call(
                                "session.own_block",
                                json!({
                                    "session_id": session_id,
                                    "block_ids": [block_id],
                                    "mode": "take"
                                }),
                            );
                            match r1 {
                                Ok(_) => {
                                    if let Some(b) = blocks.get_mut(&block_id) {
                                        b.owned_by_us = true;
                                        b.released_by_us = false;
                                    }
                                    publish_host_snapshot(
                                        cfg,
                                        kind,
                                        default_path,
                                        latency_ms,
                                        &sessions,
                                        &blocks,
                                        hook,
                                    );
                                    dirty = false;
                                    match rpc.call(
                                        "com.superlogical.terminal.resize",
                                        json!({
                                            "session_id": session_id,
                                            "block_id": block_id,
                                            "args": { "columns": cols.max(20), "rows": rows.max(6) }
                                        }),
                                    ) {
                                        Ok(_) => Ok(()),
                                        Err(e) => {
                                            Err(format!("已接管控制权，但调整终端尺寸失败: {e}"))
                                        }
                                    }
                                }
                                Err(e) => Err(e),
                            }
                        }
                        OwnershipMode::Peek | OwnershipMode::HandBack => {
                            let r1 = rpc
                                .call(
                                    "session.disown_block",
                                    json!({
                                        "session_id": session_id,
                                        "block_ids": [block_id]
                                    }),
                                )
                                .map(|_| ());
                            match r1 {
                                Ok(()) => {
                                    if let Some(b) = blocks.get_mut(&block_id) {
                                        if b.owned_by_us {
                                            b.owned_by_us = false;
                                            b.released_by_us = true;
                                        }
                                    }
                                    publish_host_snapshot(
                                        cfg,
                                        kind,
                                        default_path,
                                        latency_ms,
                                        &sessions,
                                        &blocks,
                                        hook,
                                    );
                                    dirty = false;
                                    Ok(())
                                }
                                Err(err) => {
                                    // Reconcile actual server ownership in case a timeout occurred after server applied release!
                                    let was_owned =
                                        blocks.get(&block_id).is_some_and(|b| b.owned_by_us);
                                    let mut reconciled_free = false;
                                    if let Ok(view) = rpc
                                        .call("session.view", json!({ "session_id": session_id }))
                                    {
                                        let fallback = sessions
                                            .get(&session_id)
                                            .map(|s| s.label.clone())
                                            .unwrap_or_else(|| session_id.clone());
                                        apply_session_view(
                                            &mut rpc,
                                            &session_id,
                                            &fallback,
                                            &our_client_id,
                                            &view,
                                            &mut sessions,
                                            &mut blocks,
                                        );
                                        if let Some(b) = blocks.get_mut(&block_id) {
                                            if was_owned && !b.owned_by_us {
                                                b.released_by_us = true;
                                                reconciled_free = true;
                                            }
                                        }
                                        publish_host_snapshot(
                                            cfg,
                                            kind,
                                            default_path,
                                            latency_ms,
                                            &sessions,
                                            &blocks,
                                            hook,
                                        );
                                        dirty = false;
                                    }
                                    if reconciled_free {
                                        Ok(())
                                    } else {
                                        Err(err)
                                    }
                                }
                            }
                        }
                    };
                    let _ = reply.send(res);
                }
                HostCmd::NewSession {
                    label,
                    cwd,
                    deadline,
                    reply,
                } => {
                    rpc.operation_deadline = Some(deadline);
                    let mut block_spec = json!({ "flavor": "com.superlogical.terminal.shell" });
                    if let Some(dir) = cwd.filter(|s| !s.trim().is_empty()) {
                        block_spec["options"] = json!({ "cwd": dir });
                    }
                    let mut create_args = json!({
                        "initial_windows": [{
                            "layout": { "block": block_spec }
                        }]
                    });
                    if let Some(lbl) = label.filter(|s| !s.trim().is_empty()) {
                        create_args["label"] = json!(lbl);
                    }
                    match rpc.call("session.create", create_args) {
                        Ok(created) => {
                            let sid = created
                                .get("session_id")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string();
                            attach_and_sync_session(
                                &mut rpc,
                                &cfg.id,
                                &sid,
                                &sid,
                                &mut our_client_id,
                                &mut sessions,
                                &mut blocks,
                            );
                            // Newly created session owns its block by default; disown immediately so we honor Peek default!
                            let result = blocks
                                .values()
                                .find(|b| b.session_id == sid)
                                .map(|b| b.block_id.clone())
                                .ok_or_else(|| {
                                    "attach did not discover the created block".to_string()
                                })
                                .and_then(|bid| {
                                    rpc.call(
                                        "session.disown_block",
                                        json!({"session_id":sid, "block_ids":[bid]}),
                                    )?;
                                    blocks.get_mut(&bid).unwrap().owned_by_us = false;
                                    Ok(make_pane_key(&cfg.id, &sid, &bid))
                                })
                                .map_err(|e| {
                                    format!(
                                        "created session {sid}, but failed to enter Peek mode: {e}"
                                    )
                                });
                            publish_host_snapshot(
                                cfg,
                                kind,
                                default_path,
                                latency_ms,
                                &sessions,
                                &blocks,
                                hook,
                            );
                            dirty = false;
                            let _ = reply.send(result);
                        }
                        Err(e) => {
                            let _ = reply.send(Err(e));
                        }
                    }
                    rpc.operation_deadline = None;
                }
                HostCmd::CloseBlock {
                    session_id,
                    block_id,
                    reply,
                } => {
                    // Defer tearing down local stream & VT until `block.close` succeeds!
                    let res = rpc
                        .call(
                            "block.close",
                            json!({ "session_id": session_id, "block_id": block_id }),
                        )
                        .map(|_| ());
                    if res.is_ok() {
                        let key = make_pane_key(&cfg.id, &session_id, &block_id);
                        if let Some(s) = data_streams.remove(&key) {
                            s.stop();
                        }
                        vt.remove(&key);
                        blocks.remove(&block_id);
                        publish_host_snapshot(
                            cfg,
                            kind,
                            default_path,
                            latency_ms,
                            &sessions,
                            &blocks,
                            hook,
                        );
                        dirty = false;
                    }
                    let _ = reply.send(res);
                }
            }
        }

        // 3. Drain all nonblocking frames from control WebSocket.
        loop {
            if stop.load(Ordering::Acquire) {
                break 'control;
            }
            match rpc.ws.read() {
                Ok(Message::Text(txt)) => {
                    if let Ok(val) = serde_json::from_str::<Value>(txt.as_str()) {
                        if val.get("type").and_then(Value::as_str) == Some("event") {
                            rpc.queued_events.push_back(val);
                        }
                    }
                }
                Ok(Message::Ping(_)) => {
                    let _ = rpc.ws.flush();
                }
                Ok(Message::Close(_))
                | Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                    return Err("control connection closed".into());
                }
                Ok(_) => continue,
                Err(tungstenite::Error::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                    if rpc.queued_events.is_empty() {
                        break;
                    }
                    dirty |= drain_rpc_queued_events(
                        &mut rpc,
                        cfg,
                        &mut our_client_id,
                        &mut sessions,
                        &mut blocks,
                        &mut data_streams,
                        vt,
                        active_key,
                    );
                }
                Err(_) if stop.load(Ordering::Acquire) => break 'control,
                Err(e) => return Err(format!("control read error: {e}")),
            }
        }

        if dirty {
            publish_host_snapshot(
                cfg,
                kind,
                default_path,
                latency_ms,
                &sessions,
                &blocks,
                hook,
            );
        }

        // Park with 0% CPU until socket readable or command waker fires!
        let rfd = rpc.ws.get_ref().read_fd();
        let _ = wait_fd_readable(rfd, wake_pipe.read_fd(), 15_000);
        wake_pipe.drain();
    }
    release_on_shutdown(
        &mut rpc,
        blocks
            .values()
            .filter(|b| b.owned_by_us)
            .map(|b| (b.session_id.as_str(), b.block_id.as_str())),
    );
    Ok(())
}

fn release_on_shutdown<'a>(
    rpc: &mut ControlRpcConn,
    owned: impl Iterator<Item = (&'a str, &'a str)>,
) {
    let deadline = Instant::now() + Duration::from_millis(1500);
    rpc.ws.get_mut().begin_shutdown_writes(deadline);
    let mut sessions = HashMap::<_, Vec<_>>::new();
    for (session, block) in owned {
        sessions.entry(session).or_default().push(block);
    }
    for (session, blocks) in sessions {
        if Instant::now() >= deadline {
            break;
        }
        rpc.next_id += 1;
        let request = json!({"type":"request", "id":rpc.next_id.to_string(),
            "method":"session.disown_block", "payload":{"session_id":session,"block_ids":blocks}});
        if rpc
            .ws
            .send(Message::Text(request.to_string().into()))
            .is_err()
        {
            break;
        }
    }
    let _ = rpc.ws.close(None);
}

fn attach_and_sync_session(
    rpc: &mut ControlRpcConn,
    _host_id: &str,
    session_id: &str,
    fallback_label: &str,
    our_client_id: &mut String,
    sessions: &mut HashMap<String, SessionTrack>,
    blocks: &mut HashMap<String, BlockMeta>,
) {
    let Ok(attached) = rpc.call("session.attach", json!({ "session_id": session_id })) else {
        return;
    };
    if our_client_id.is_empty() {
        if let Some(cid) = attached.get("client_id").and_then(Value::as_str) {
            *our_client_id = cid.to_string();
        }
    }
    if let Some(view) = attached.get("view") {
        apply_session_view(
            rpc,
            session_id,
            fallback_label,
            our_client_id,
            view,
            sessions,
            blocks,
        );
    }
}

fn apply_session_view(
    rpc: &mut ControlRpcConn,
    session_id: &str,
    fallback_label: &str,
    our_client_id: &str,
    view: &Value,
    sessions: &mut HashMap<String, SessionTrack>,
    blocks: &mut HashMap<String, BlockMeta>,
) {
    let rev = view.get("revision").and_then(Value::as_u64).unwrap_or(0);
    if let Some(existing) = sessions.get(session_id) {
        if rev > 0 && rev < existing.view_revision {
            return;
        }
    }
    let slabel = view
        .get("label")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(fallback_label)
        .to_string();

    let windows = view
        .get("windows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut live_bids_in_session: HashSet<String> = HashSet::new();
    let mut new_bids: Vec<String> = Vec::new();

    for win in &windows {
        let wid = win
            .get("window_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let wlabel = win
            .get("label")
            .and_then(Value::as_str)
            .unwrap_or(&wid)
            .to_string();
        let Some(layers) = win.get("layers").and_then(Value::as_array) else {
            continue;
        };
        for layer in layers {
            let Some(lblocks) = layer.get("blocks").and_then(Value::as_array) else {
                continue;
            };
            for lb in lblocks {
                let creator = lb
                    .get("creator_name")
                    .and_then(Value::as_str)
                    .unwrap_or("com.superlogical.terminal");
                if creator != "com.superlogical.terminal" {
                    continue;
                }
                let bid = lb
                    .get("block_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if bid.is_empty() {
                    continue;
                }
                live_bids_in_session.insert(bid.clone());
                let owner = lb.get("owner").and_then(Value::as_str);
                let owned_by_us = !our_client_id.is_empty() && owner == Some(our_client_id);
                let label = lb
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("shell")
                    .to_string();

                if let Some(existing) = blocks.get_mut(&bid) {
                    existing.window_id = wid.clone();
                    existing.window_label = wlabel.clone();
                    existing.owned_by_us = owned_by_us;
                } else {
                    blocks.insert(
                        bid.clone(),
                        BlockMeta {
                            session_id: session_id.to_string(),
                            window_id: wid.clone(),
                            window_label: wlabel.clone(),
                            block_id: bid.clone(),
                            title: label.clone(),
                            program: label,
                            pwd: String::new(),
                            status: PaneActivityStatus::Idle,
                            run_epoch: 0,
                            status_kind: None,
                            status_msg: None,
                            owned_by_us,
                            released_by_us: false,
                            updated_at_ms: unix_ms(),
                        },
                    );
                    new_bids.push(bid);
                }
            }
        }
    }

    blocks.retain(|bid, b| b.session_id != session_id || live_bids_in_session.contains(bid));
    sessions.insert(
        session_id.to_string(),
        SessionTrack {
            label: slabel,
            view_revision: rev,
            window_count: windows.len(),
        },
    );

    // Hydrate terminal metadata for newly discovered blocks.
    for bid in new_bids {
        refresh_block_metadata(rpc, session_id, &bid, blocks, false);
    }
}

fn refresh_block_metadata(
    rpc: &mut ControlRpcConn,
    session_id: &str,
    block_id: &str,
    blocks: &mut HashMap<String, BlockMeta>,
    is_actively_viewed: bool,
) {
    let args = json!({ "session_id": session_id, "block_id": block_id, "args": {} });
    if let Ok(t) = rpc.call("com.superlogical.terminal.title", args.clone()) {
        if let Some(title) = t
            .get("title")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            if let Some(b) = blocks.get_mut(block_id) {
                b.title = title.to_string();
            }
        }
        if let Some(name) = t
            .pointer("/owner/name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            if let Some(b) = blocks.get_mut(block_id) {
                b.program = name.to_string();
            }
        }
    }
    if let Ok(p) = rpc.call("com.superlogical.terminal.pwd", args.clone()) {
        if let Some(pwd) = p
            .get("pwd")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            if let Some(b) = blocks.get_mut(block_id) {
                b.pwd = shorten_pwd(pwd);
            }
        }
    }
    if let Ok(ps) = rpc.call("com.superlogical.terminal.program_status", args) {
        if let Some(records) = ps.get("records").and_then(Value::as_array) {
            if let Some(b) = blocks.get_mut(block_id) {
                apply_status_records(b, records, is_actively_viewed);
            }
        }
    }
}

fn shorten_pwd(raw: &str) -> String {
    let stripped = if let Some(rest) = raw.strip_prefix("file://") {
        rest.find('/').map(|i| &rest[i..]).unwrap_or(rest)
    } else {
        raw
    };
    if let Some(home) = std::env::var_os("HOME") {
        let h = home.to_string_lossy();
        if !h.is_empty() {
            if let Some(rel) = stripped.strip_prefix(h.as_ref()) {
                return if rel.is_empty() {
                    "~".into()
                } else {
                    format!("~{rel}")
                };
            }
        }
    }
    stripped.to_string()
}

fn apply_status_records(b: &mut BlockMeta, records: &[Value], is_actively_viewed: bool) {
    if records.is_empty() {
        return;
    }
    // Pick highest urgency record across OSC 7501 records.
    let mut best: Option<&Value> = None;
    let rank_of = |state: &str| match state {
        "blocked" => 0,
        "error" => 1,
        "done" => 2,
        "working" => 3,
        _ => 4,
    };
    for rec in records {
        let st = rec.get("state").and_then(Value::as_str).unwrap_or("idle");
        if best.is_none_or(|cur| {
            rank_of(st) < rank_of(cur.get("state").and_then(Value::as_str).unwrap_or("idle"))
        }) {
            best = Some(rec);
        }
    }
    let Some(rec) = best else { return };
    let state_str = rec.get("state").and_then(Value::as_str).unwrap_or("idle");
    let next_status = match state_str {
        "blocked" => PaneActivityStatus::Blocked,
        "error" => PaneActivityStatus::Error,
        "working" => PaneActivityStatus::Running,
        "done" => {
            if is_actively_viewed || b.status == PaneActivityStatus::Done {
                PaneActivityStatus::Done
            } else {
                PaneActivityStatus::UnseenDone
            }
        }
        _ => PaneActivityStatus::Idle,
    };
    b.set_status(next_status);
    b.status_kind = rec
        .get("kind")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    b.status_msg = rec
        .get("msg")
        .or_else(|| rec.get("title"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    if let Some(app) = rec
        .get("effective_app")
        .or_else(|| rec.get("app"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        b.program = app.to_string();
    }
    b.updated_at_ms = unix_ms();
}

#[allow(clippy::too_many_arguments)]
fn handle_control_event(
    rpc: &mut ControlRpcConn,
    cfg: &ConfiguredHost,
    our_client_id: &mut String,
    sessions: &mut HashMap<String, SessionTrack>,
    blocks: &mut HashMap<String, BlockMeta>,
    data_streams: &mut HashMap<String, ActiveDataStream>,
    vt: &VtActor,
    active_key: &Arc<Mutex<Option<String>>>,
    raw_event: &Value,
) -> bool {
    let Some(ev_payload) = raw_event.get("payload") else {
        return false;
    };
    let ev_type = ev_payload.get("type").and_then(Value::as_str).unwrap_or("");
    let inner = ev_payload.get("payload").unwrap_or(&Value::Null);

    if ev_type == "session_created" {
        if let Some(sid) = inner.get("session_id").and_then(Value::as_str) {
            let lbl = inner.get("label").and_then(Value::as_str).unwrap_or(sid);
            attach_and_sync_session(rpc, &cfg.id, sid, lbl, our_client_id, sessions, blocks);
            return true;
        }
        return false;
    }
    if ev_type == "session_destroyed" {
        if let Some(sid) = inner.get("session_id").and_then(Value::as_str) {
            sessions.remove(sid);
            let removed_keys: Vec<String> = blocks
                .values()
                .filter(|b| b.session_id == sid)
                .map(|b| make_pane_key(&cfg.id, &b.session_id, &b.block_id))
                .collect();
            for k in removed_keys {
                data_streams.remove(&k);
                vt.remove(&k);
            }
            blocks.retain(|_, b| b.session_id != sid);
            return true;
        }
        return false;
    }

    if ev_type != "session_event" {
        return false;
    }
    let Some(sid) = inner.get("session_id").and_then(Value::as_str) else {
        return false;
    };
    let Some(sev) = inner.get("event") else {
        return false;
    };
    let sev_type = sev.get("type").and_then(Value::as_str).unwrap_or("");
    let sp = sev.get("payload").unwrap_or(&Value::Null);

    match sev_type {
        "session_label_changed" => {
            if let Some(lbl) = sp.get("label").and_then(Value::as_str) {
                if let Some(s) = sessions.get_mut(sid) {
                    s.label = lbl.to_string();
                    return true;
                }
            }
            false
        }
        "session_view_changed" => {
            let rev = sp.get("revision").and_then(Value::as_u64).unwrap_or(0);
            let cur_rev = sessions.get(sid).map(|s| s.view_revision).unwrap_or(0);
            if rev == 0 || rev > cur_rev {
                if let Ok(view) = rpc.call("session.view", json!({ "session_id": sid })) {
                    let fallback = sessions
                        .get(sid)
                        .map(|s| s.label.clone())
                        .unwrap_or_else(|| sid.to_string());
                    apply_session_view(rpc, sid, &fallback, our_client_id, &view, sessions, blocks);
                    return true;
                }
            }
            false
        }
        "block_owner_changed" => {
            if let Some(bid) = sp.get("block_id").and_then(Value::as_str) {
                let owner = sp.get("owner").and_then(Value::as_str);
                if let Some(b) = blocks.get_mut(bid) {
                    b.owned_by_us =
                        !our_client_id.is_empty() && owner == Some(our_client_id.as_str());
                    return true;
                }
            }
            false
        }
        "block_closed" => {
            if let Some(bid) = sp.get("block_id").and_then(Value::as_str) {
                let key = make_pane_key(&cfg.id, sid, bid);
                data_streams.remove(&key);
                vt.remove(&key);
                return blocks.remove(bid).is_some();
            }
            false
        }
        "block_event" => {
            let Some(bid) = sp.get("block_id").and_then(Value::as_str) else {
                return false;
            };
            let key = make_pane_key(&cfg.id, sid, bid);
            let is_viewed = active_key.lock().unwrap().as_deref() == Some(key.as_str());

            let (bev_name, bev_fields) = if let Some(ev_obj) = sp.get("event") {
                (
                    ev_obj
                        .get("type")
                        .or_else(|| ev_obj.get("name"))
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                    ev_obj.get("payload").unwrap_or(ev_obj),
                )
            } else {
                (
                    sp.get("name")
                        .or_else(|| sp.get("event_name"))
                        .and_then(Value::as_str)
                        .unwrap_or(""),
                    sp.get("fields").or_else(|| sp.get("payload")).unwrap_or(sp),
                )
            };

            match bev_name {
                "program_status_changed" => {
                    if let Some(records) = bev_fields.get("records").and_then(Value::as_array) {
                        if let Some(b) = blocks.get_mut(bid) {
                            apply_status_records(b, records, is_viewed);
                        }
                    } else {
                        refresh_block_metadata(rpc, sid, bid, blocks, is_viewed);
                    }
                    // Refresh format text only for the actively viewed pane so background panes
                    // never allocate 32 KiB format buffers or stall the control RPC channel.
                    if is_viewed
                        && blocks.get(bid).is_some_and(|b| {
                            matches!(
                                b.status,
                                PaneActivityStatus::Blocked
                                    | PaneActivityStatus::UnseenDone
                                    | PaneActivityStatus::Done
                            )
                        })
                    {
                        if let Ok(fmt) = rpc.call(
                            "com.superlogical.terminal.format",
                            json!({
                                "session_id": sid,
                                "block_id": bid,
                                "args": { "format": "text", "trim": true, "unwrap": true, "max_bytes": 24576 }
                            }),
                        ) {
                            if let Some(txt) = fmt.get("content").and_then(Value::as_str) {
                                vt.set_format_text(&key, txt.to_string());
                            }
                        }
                    }
                    true
                }
                "title_changed" => {
                    if let Some(t) = bev_fields.get("title").and_then(Value::as_str) {
                        if let Some(b) = blocks.get_mut(bid) {
                            if !t.is_empty() {
                                b.title = t.to_string();
                            }
                            b.updated_at_ms = unix_ms();
                            return true;
                        }
                    }
                    refresh_block_metadata(rpc, sid, bid, blocks, is_viewed);
                    true
                }
                "pwd_changed" => {
                    if let Some(p) = bev_fields.get("pwd").and_then(Value::as_str) {
                        if let Some(b) = blocks.get_mut(bid) {
                            b.pwd = shorten_pwd(p);
                            return true;
                        }
                    }
                    false
                }
                "child_exited" => {
                    let exit_code = bev_fields
                        .get("exit_code")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    if let Some(b) = blocks.get_mut(bid) {
                        b.set_status(if exit_code != 0 {
                            PaneActivityStatus::Error
                        } else if is_viewed {
                            PaneActivityStatus::Done
                        } else {
                            PaneActivityStatus::UnseenDone
                        });
                        b.status_msg = Some(format!("进程已退出 (code {exit_code})"));
                        b.updated_at_ms = unix_ms();
                        return true;
                    }
                    false
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn publish_host_snapshot(
    cfg: &ConfiguredHost,
    kind: crate::rex::types::HostKind,
    path_kind: crate::rex::types::PathKind,
    latency_ms: u32,
    sessions: &HashMap<String, SessionTrack>,
    blocks: &HashMap<String, BlockMeta>,
    hook: &HostStateHook,
) {
    let mut session_summaries: Vec<SessionSummary> = sessions
        .iter()
        .map(|(sid, st)| {
        let pane_count = blocks.values().filter(|b| b.session_id == *sid).count();
            SessionSummary {
                id: sid.clone(),
                label: crate::rex::vt::sanitize_ui_text(&st.label).trim().to_string(),
                window_count: st.window_count,
                pane_count,
            }
        })
        .collect();
    session_summaries.sort_by(|a, b| a.label.cmp(&b.label));

    let panes = blocks
        .values()
        .map(|b| {
            let slabel = sessions
                .get(&b.session_id)
                .map(|s| crate::rex::vt::sanitize_ui_text(&s.label).trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| b.session_id.clone());
            (
                PaneSummary {
                    key: make_pane_key(&cfg.id, &b.session_id, &b.block_id),
                    host_id: cfg.id.clone(),
                    host_label: crate::rex::vt::sanitize_ui_text(&cfg.label).trim().to_string(),
                    session_id: b.session_id.clone(),
                    session_label: slabel,
                    window_id: b.window_id.clone(),
                    window_label: crate::rex::vt::sanitize_ui_text(&b.window_label).trim().to_string(),
                    block_id: b.block_id.clone(),
                    title: crate::rex::vt::sanitize_ui_text(&b.title).trim().to_string(),
                    program: crate::rex::vt::sanitize_ui_text(&b.program).trim().to_string(),
                    pwd: b.pwd.clone(),
                    status: b.status,
                    status_kind: b.status_kind.clone(),
                    status_msg: b
                        .status_msg
                        .as_deref()
                        .map(|m| crate::rex::vt::sanitize_ui_text(m).trim().to_string())
                        .filter(|m| !m.is_empty()),
                    owned_by_us: b.owned_by_us,
                    released_by_us: b.released_by_us,
                    has_draft: false,
                    updated_at_ms: b.updated_at_ms,
                },
                b.run_epoch,
            )
        })
        .collect();

    hook(HostEvent::HostSnapshot {
        host: HostState {
            id: cfg.id.clone(),
            label: cfg.label.clone(),
            kind,
            endpoint: cfg.endpoint.clone(),
            phase: ConnPhase::Live,
            problem: None,
            latency_ms: Some(latency_ms),
            path_kind: Some(path_kind),
            sessions: session_summaries,
        },
        panes,
    });
}

/// Validates a `rex.data.terminal.v1` server binary handshake response:
/// - `0x82` (`[0x82, reason]`) -> rejected/expired ticket or resume token
/// - `0x81` (`32` bytes exact: `[0x81, token(16), 0, 0, 0, retention_le32(4), nonce_le64(8)]` with `nonce != 0`)
fn parse_data_welcome(frame: &[u8]) -> Result<([u8; 16], u64), &'static str> {
    if frame.first() == Some(&0x82) {
        return Err("终端数据流票据已过期，重进窗格可自动刷新");
    }
    if frame.len() != 32 || frame[0] != 0x81 || frame[17..20] != [0, 0, 0] {
        return Err("终端数据流握手响应格式无效");
    }
    let nonce = u64::from_le_bytes(frame[24..32].try_into().unwrap_or([0; 8]));
    if nonce == 0 {
        return Err("终端数据流握手 nonce 无效");
    }
    let mut token = [0u8; 16];
    token.copy_from_slice(&frame[1..17]);
    Ok((token, nonce))
}

#[allow(clippy::too_many_arguments)]
fn start_block_data_stream(
    rpc: &mut ControlRpcConn,
    cfg: &ConfiguredHost,
    tsnet_port: u16,
    session_id: &str,
    block_id: &str,
    cols: u16,
    rows: u16,
    stream_gen: u64,
    vt: VtActor,
    hook: HostStateHook,
    control_tx: mpsc::Sender<HostCmd>,
    control_waker: Waker,
) -> Option<ActiveDataStream> {
    let key = make_pane_key(&cfg.id, session_id, block_id);
    let connect_res = match rpc.call(
        "data.connect",
        json!({
            "session_id": session_id,
            "block_id": block_id,
            "data_ref_id": "terminal",
            "subprotocol": DATA_SUBPROTOCOL
        }),
    ) {
        Ok(res) => res,
        Err(err) => {
            hook(HostEvent::PaneStreamPhase {
                key,
                phase: ConnPhase::Failed,
                problem: Some(err),
            });
            return None;
        }
    };
    let ticket_b64 = connect_res.get("ticket")?.as_str()?;
    let ticket_bytes = URL_SAFE_NO_PAD
        .decode(ticket_b64)
        .or_else(|_| URL_SAFE.decode(ticket_b64))
        .ok()?;
    if ticket_bytes.len() < 16 {
        return None;
    }
    let mut ticket = [0u8; 16];
    ticket.copy_from_slice(&ticket_bytes[..16]);

    let (wake_pipe, waker) = WakePipe::new().ok()?;
    let stop = Arc::new(AtomicBool::new(false));
    let alive = Arc::new(AtomicBool::new(true));
    let snapshot_failed = Arc::new(AtomicBool::new(false));
    vt.begin_stream(
        &key,
        stream_gen,
        cols,
        rows,
        snapshot_failed.clone(),
        waker.clone(),
    );

    let stop_thread = stop.clone();
    let alive_thread = alive.clone();
    let endpoint = cfg.endpoint.clone();
    let ssh_key = cfg.ssh_key_path.clone();
    let sid_owned = session_id.to_string();
    let bid_owned = block_id.to_string();

    if thread::Builder::new()
        .name("rex-zero-data".into())
        .stack_size(256 * 1024)
        .spawn(move || {
            run_data_stream_loop(
                &endpoint,
                ssh_key.as_deref(),
                tsnet_port,
                &sid_owned,
                &bid_owned,
                &key,
                cols,
                rows,
                stream_gen,
                ticket,
                vt,
                hook,
                control_tx,
                control_waker,
                wake_pipe,
                stop_thread,
                alive_thread,
                snapshot_failed,
            );
        })
        .is_err()
    {
        alive.store(false, Ordering::Release);
        return None;
    }

    Some(ActiveDataStream { stop, alive, waker })
}

struct AliveGuard(Arc<AtomicBool>);
impl Drop for AliveGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_data_stream_loop(
    endpoint: &str,
    ssh_key: Option<&str>,
    tsnet_port: u16,
    session_id: &str,
    block_id: &str,
    key: &str,
    cols: u16,
    rows: u16,
    stream_gen: u64,
    initial_ticket: [u8; 16],
    vt: VtActor,
    hook: HostStateHook,
    control_tx: mpsc::Sender<HostCmd>,
    control_waker: Waker,
    wake_pipe: WakePipe,
    stop: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    snapshot_failed: Arc<AtomicBool>,
) {
    let _alive_guard = AliveGuard(alive.clone());
    let mut resume_token: Option<[u8; 16]> = None;
    let mut received_bytes: u64 = 0;

    let request_fresh_ticket = |alive_ref: &AtomicBool, problem| {
        if !stop.load(Ordering::Acquire) {
            alive_ref.store(false, Ordering::Release);
            let _ = control_tx.send(HostCmd::ReconnectFreshStream {
                session_id: session_id.to_string(),
                block_id: block_id.to_string(),
                cols,
                rows,
                failed_gen: stream_gen,
                problem,
            });
            control_waker.wake();
        }
    };

    hook(HostEvent::PaneStreamPhase {
        key: key.to_string(),
        phase: ConnPhase::Connecting,
        problem: None,
    });

    while !stop.load(Ordering::Acquire) {
        if snapshot_failed.load(Ordering::Acquire) {
            request_fresh_ticket(&alive, "终端快照解码失败，重试次数已用尽");
            return;
        }
        let cancel = wake_pipe.cancel_watch(stop.clone());
        let mut ws = match open_rex_websocket(
            endpoint,
            ssh_key,
            tsnet_port,
            DATA_PATH,
            DATA_SUBPROTOCOL,
            cancel,
        ) {
            Ok(s) => s,
            Err(err) => {
                if !stop.load(Ordering::Acquire) {
                    hook(HostEvent::PaneStreamPhase {
                        key: key.to_string(),
                        phase: ConnPhase::Failed,
                        problem: Some(err),
                    });
                }
                return;
            }
        };
        ws.get_mut()
            .set_read_deadline(Some(Instant::now() + Duration::from_secs(8)));

        let is_resume = resume_token.is_some();
        let handshake = if let Some(tok) = resume_token {
            let mut msg = Vec::with_capacity(25);
            msg.push(0x02);
            msg.extend_from_slice(&tok);
            msg.extend_from_slice(&received_bytes.to_le_bytes());
            msg
        } else {
            let mut msg = Vec::with_capacity(17);
            msg.push(0x01);
            msg.extend_from_slice(&initial_ticket);
            msg
        };

        if ws.send(Message::Binary(handshake.into())).is_err() {
            if !stop.load(Ordering::Acquire) {
                hook(HostEvent::PaneStreamPhase {
                    key: key.to_string(),
                    phase: ConnPhase::Failed,
                    problem: Some("发送终端数据流握手失败".into()),
                });
            }
            return;
        }

        let welcome_bin = loop {
            match ws.read() {
                Ok(Message::Binary(b)) => break b,
                Ok(Message::Ping(_)) => {
                    let _ = ws.flush();
                }
                Ok(Message::Pong(_)) => continue,
                Ok(_) | Err(_) => {
                    if !stop.load(Ordering::Acquire) {
                        hook(HostEvent::PaneStreamPhase {
                            key: key.to_string(),
                            phase: ConnPhase::Failed,
                            problem: Some("读取终端数据流握手响应失败".into()),
                        });
                    }
                    return;
                }
            }
        };

        let (next_tok, nonce) = match parse_data_welcome(&welcome_bin) {
            Ok(pair) => pair,
            Err(problem) => {
                if is_resume && welcome_bin.first() == Some(&0x82) {
                    // Resume token expired on server: automatically obtain a fresh ticket & snapshot!
                    request_fresh_ticket(&alive, "终端恢复令牌已失效，重试次数已用尽");
                    return;
                }
                hook(HostEvent::PaneStreamPhase {
                    key: key.to_string(),
                    phase: ConnPhase::Failed,
                    problem: Some(problem.into()),
                });
                return;
            }
        };
        resume_token = Some(next_tok);

        hook(HostEvent::PaneStreamPhase {
            key: key.to_string(),
            phase: ConnPhase::Live,
            problem: None,
        });

        let _ = ws.get_mut().enable_nonblocking_loop();
        let mut first_chunk = !is_resume;
        let mut last_notify = Instant::now() - Duration::from_secs(1);
        let mut pending_notify = false;

        'stream: loop {
            if stop.load(Ordering::Acquire) {
                let _ = ws.close(None);
                return;
            }
            loop {
                if stop.load(Ordering::Acquire) {
                    let _ = ws.close(None);
                    return;
                }
                if snapshot_failed.load(Ordering::Acquire) {
                    request_fresh_ticket(&alive, "终端快照解码失败，重试次数已用尽");
                    let _ = ws.close(None);
                    return;
                }
                match ws.read() {
                    Ok(Message::Binary(chunk)) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        received_bytes += chunk.len() as u64;
                        if !vt.feed_stream(
                            key,
                            stream_gen,
                            cols,
                            rows,
                            nonce,
                            first_chunk,
                            chunk.to_vec(),
                            &stop,
                        ) {
                            let _ = ws.close(None);
                            return;
                        }
                        first_chunk = false;
                        if last_notify.elapsed() >= Duration::from_millis(25) {
                            hook(HostEvent::TerminalUpdated);
                            last_notify = Instant::now();
                            pending_notify = false;
                        } else {
                            pending_notify = true;
                        }
                    }
                    Ok(Message::Ping(_)) => {
                        let _ = ws.flush();
                    }
                    Ok(Message::Close(frame)) => {
                        let code: u16 = frame.as_ref().map(|f| f.code.into()).unwrap_or(1000);
                        if code == 1000 || code == 4000 {
                            return;
                        }
                        break 'stream;
                    }
                    Ok(_) => continue,
                    Err(tungstenite::Error::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(_) => break 'stream,
                }
            }

            let timeout_ms = if pending_notify { 25 } else { 25_000 };
            let rfd = ws.get_ref().read_fd();
            let _ = wait_fd_readable(rfd, wake_pipe.read_fd(), timeout_ms);
            wake_pipe.drain();
            if pending_notify && last_notify.elapsed() >= Duration::from_millis(25) {
                hook(HostEvent::TerminalUpdated);
                last_notify = Instant::now();
                pending_notify = false;
            }
        }

        if stop.load(Ordering::Acquire) {
            return;
        }
        hook(HostEvent::PaneStreamPhase {
            key: key.to_string(),
            phase: ConnPhase::Reconnecting,
            problem: None,
        });
        let _ = wait_fd_readable(-1, wake_pipe.read_fd(), 600);
        wake_pipe.drain();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timed_out_input_distinguishes_cancelled_queue_from_started_write() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let queued = InputDispatch::new(deadline);
        let (queued_unconfirmed, queued_msg) = queued.cancel_or_unconfirmed();
        assert!(!queued_unconfirmed);
        assert!(queued_msg.contains("未发送"));
        assert!(!queued.start());
        let started = InputDispatch::new(deadline);
        assert!(started.start());
        let (started_unconfirmed, started_msg) = started.cancel_or_unconfirmed();
        assert!(started_unconfirmed);
        assert!(started_msg.contains("未确认"));
    }

    #[test]
    fn created_session_requires_peek_and_shutdown_releases_queued_ownership() {
        use std::os::unix::net::UnixListener;
        use tungstenite::handshake::server::{Request, Response};
        let path = std::env::temp_dir().join(format!("rex-control-{}.sock", std::process::id()));
        let listener = UnixListener::bind(&path).unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut ws = tungstenite::accept_hdr(socket, |_: &Request, mut resp: Response| {
                resp.headers_mut().insert(
                    "Sec-WebSocket-Protocol",
                    CONTROL_SUBPROTOCOL.parse().unwrap(),
                );
                Ok(resp)
            })
            .unwrap();
            ws.read().unwrap();
            ws.send(Message::text(
                json!({"type":"welcome","client":{"id":"client"}}).to_string(),
            ))
            .unwrap();
            let mut created = 0;
            let mut shutdown_release = false;
            let mut received_release = false;
            let event = |kind, payload: Value| {
                Message::text(json!({"type":"event","payload":{
                "type":"session_event","payload":{"session_id":"s3","event":{"type":kind,"payload":payload}}
            }}).to_string())
            };
            loop {
                let msg = ws.read().unwrap();
                if msg.is_close() {
                    break;
                }
                let req: Value = serde_json::from_str(msg.to_text().unwrap()).unwrap();
                let mut resp = json!({"type":"response","id":req["id"]});
                let view = json!({"windows":[{"layers":[{"blocks":[{"block_id":format!("b{created}")}]}]}]});
                let method = req["method"].as_str().unwrap();
                match method {
                    "data.connect" => {
                        resp["payload"] = json!({"ticket": URL_SAFE_NO_PAD.encode([0u8;16])})
                    }
                    "session.create" => {
                        created += 1;
                        resp["payload"] = json!({"session_id":format!("s{created}")});
                    }
                    "session.attach" if created == 1 => {
                        resp["error"] = json!({"message":"attach failed"})
                    }
                    "session.attach" => resp["payload"] = json!({"view":view}),
                    "session.disown_block" if created == 2 => {
                        resp["error"] = json!({"message":"release failed"})
                    }
                    "session.disown_block" if shutdown_release => {
                        received_release = true;
                        assert_eq!(
                            req["payload"],
                            json!({"session_id":"s3","block_ids":["b3"]})
                        );
                        continue;
                    }
                    "com.superlogical.terminal.write" => panic!("expired input reached the peer"),
                    "session.view" => {
                        resp["payload"] = view;
                        ws.write(Message::text(resp.to_string())).unwrap();
                        ws.write(event(
                            "block_owner_changed",
                            json!({"block_id":"b3","owner":"client"}),
                        ))
                        .unwrap();
                        ws.flush().unwrap();
                        continue;
                    }
                    _ => {}
                }
                ws.send(Message::text(resp.to_string())).unwrap();
                if method == "data.connect" {
                    let (data_socket, _) = listener.accept().unwrap();
                    data_socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut data =
                        tungstenite::accept_hdr(data_socket, |_: &Request, mut resp: Response| {
                            resp.headers_mut().insert(
                                "Sec-WebSocket-Protocol",
                                DATA_SUBPROTOCOL.parse().unwrap(),
                            );
                            Ok(resp)
                        })
                        .unwrap();
                    assert!(data.read().unwrap().is_binary());
                    let mut welcome = [0u8; 32];
                    welcome[0] = 0x81;
                    welcome[24] = 1;
                    data.send(Message::binary(welcome.to_vec())).unwrap();
                    data.send(Message::binary(b"GHOSTSNP\0\0".to_vec()))
                        .unwrap();
                    assert!(data.read().unwrap().is_close());
                }
                if method == "session.disown_block" && created == 3 {
                    ws.send(event("session_view_changed", json!({"revision":2})))
                        .unwrap();
                    shutdown_release = true;
                }
            }
            assert!(received_release);
        });
        let (updates, snapshots) = mpsc::channel();
        let (phases, stream_updates) = mpsc::channel();
        let (publishing, published_pane) = mpsc::channel();
        let (resume, proceed) = mpsc::channel();
        let proceed = Mutex::new(proceed);
        let saw_pane = AtomicBool::new(false);
        let worker = HostWorkerHandle::spawn(
            ConfiguredHost {
                id: "test".into(),
                label: "test".into(),
                endpoint: format!("unix://{}", path.display()),
                ssh_key_path: None,
            },
            Arc::default(),
            VtActor::spawn(),
            Arc::default(),
            Arc::new(move |ev| {
                if let HostEvent::PaneStreamPhase {
                    phase, ref problem, ..
                } = ev
                {
                    phases.send((phase, problem.clone())).unwrap();
                }
                if let HostEvent::HostSnapshot { host, panes } = ev {
                    if host.phase == ConnPhase::Live {
                        if panes.iter().any(|(p, _)| p.block_id == "b3")
                            && !saw_pane.swap(true, Ordering::AcqRel)
                        {
                            publishing.send(()).unwrap();
                            proceed
                                .lock()
                                .unwrap()
                                .recv_timeout(Duration::from_secs(2))
                                .unwrap();
                        }
                        updates
                            .send(panes.iter().any(|(b, _)| b.owned_by_us))
                            .unwrap();
                    }
                }
            }),
        )
        .unwrap();
        snapshots.recv_timeout(Duration::from_secs(2)).unwrap();
        let (reply, outcome) = mpsc::channel();
        worker
            .send(HostCmd::SendInput {
                session_id: "s".into(),
                block_id: "b".into(),
                data: "expired".into(),
                dispatch: Arc::new(InputDispatch::new(Instant::now())),
                reply: SendInputReply::from_sender(reply),
            })
            .unwrap();
        assert!(outcome
            .recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap_err()
            .contains("未发送"));
        for sid in ["s1", "s2", "s3"] {
            let (reply, result) = mpsc::channel();
            worker
                .send(HostCmd::NewSession {
                    label: None,
                    cwd: None,
                    deadline: Instant::now() + Duration::from_secs(2),
                    reply,
                })
                .unwrap();
            if sid == "s3" {
                published_pane.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(matches!(result.try_recv(), Err(mpsc::TryRecvError::Empty)));
                resume.send(()).unwrap();
            }
            let result = result.recv_timeout(Duration::from_secs(2)).unwrap();
            if sid == "s3" {
                assert_eq!(result.unwrap(), "test|s3|b3");
            } else {
                assert!(result.unwrap_err().starts_with(&format!(
                    "created session {sid}, but failed to enter Peek mode:"
                )));
            }
        }
        while !snapshots.recv_timeout(Duration::from_secs(2)).unwrap() {}
        worker
            .send(HostCmd::EnsureStream {
                session_id: "s3".into(),
                block_id: "b3".into(),
                cols: 40,
                rows: 8,
            })
            .unwrap();
        let mut handshakes = 0;
        loop {
            let (phase, problem) = stream_updates.recv_timeout(Duration::from_secs(2)).unwrap();
            if phase == ConnPhase::Live {
                handshakes += 1;
            }
            if phase == ConnPhase::Failed {
                assert!(problem.unwrap().contains("快照"));
                break;
            }
        }
        assert_eq!(handshakes, 3);
        worker.stop();
        worker.join();
        server.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn data_welcome_requires_exact_32_byte_opcode_reserved_zeros_and_nonzero_nonce() {
        let mut valid = [0u8; 32];
        valid[0] = 0x81;
        valid[1..17].copy_from_slice(&[0xaa; 16]);
        valid[17..20].copy_from_slice(&[0, 0, 0]);
        valid[20..24].copy_from_slice(&60_000u32.to_le_bytes());
        valid[24..32].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());

        let (tok, nonce) = parse_data_welcome(&valid).expect("valid welcome");
        assert_eq!(tok, [0xaa; 16]);
        assert_eq!(nonce, 0x1234_5678_9abc_def0);

        // Reject 2-byte `0x82` REJECT frame:
        assert!(parse_data_welcome(&[0x82, 0x01]).is_err());

        // Reject wrong opcode (e.g. arbitrary >=32 byte frame with first byte != 0x81):
        let mut wrong_op = valid;
        wrong_op[0] = 0x01;
        assert!(parse_data_welcome(&wrong_op).is_err());

        // Reject wrong length (31 or 33 bytes):
        assert!(parse_data_welcome(&valid[..31]).is_err());
        let mut too_long = valid.to_vec();
        too_long.push(0);
        assert!(parse_data_welcome(&too_long).is_err());

        // Reject non-zero reserved bytes `[17..20]`:
        let mut bad_reserved = valid;
        bad_reserved[18] = 1;
        assert!(parse_data_welcome(&bad_reserved).is_err());

        // Reject zero nonce:
        let mut zero_nonce = valid;
        zero_nonce[24..32].copy_from_slice(&0u64.to_le_bytes());
        assert!(parse_data_welcome(&zero_nonce).is_err());
    }
}
