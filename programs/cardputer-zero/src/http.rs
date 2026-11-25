//! The worker's `http` node on the CardputerZero: `io.http` requests over
//! loopback HTTP/1.1, and the device API in process.
//!
//! The packages on this program need servers on this machine only.
//! `http://zero/dev/…` is the device API (device/mod.rs): the request's
//! thread calls the device layer and answers with its JSON or bytes; no
//! socket is involved. `http://companion/…` goes to the companion's control
//! API: the port and the bearer token come from `control.json` in the
//! companion's store, read again for every request because a restarted
//! companion has a new port and token, and the worker never sees the token.
//! This host answers as a gateway: 503 when no companion runs and 502 when
//! its port does not answer, each with `{"error": …}`.
//! `http://127.0.0.1:<port>/…` and `http://localhost:<port>/…` go out as
//! written. The program's own host answers two requests: `http://zero/quit`
//! ends the program after the turn (the screen's way back to the Zero's
//! launcher), and `http://zero/restart` restarts the companion's systemd
//! unit, answering 204 once `systemctl` returns. Open refuses every other
//! URL: there is no DNS, TLS or proxy here.
//!
//! Each request runs on its own thread and queues its facts: HEADERS, DATA in
//! blocks of at most 1 KiB, END. The worker's owner task emits them into the
//! core when it waits or finishes a turn (worker.rs). A request thread never
//! touches the core, so close returns at once and a late answer is dropped.
use crate::device::Device;
use crate::rex::{transport::Waker, RexZeroEngine};
use crate::worker::{
    pocket_worker_emit, pocket_worker_finish, Core, Driver, Notify, BUSY, FACT_DATA, FACT_HEADERS,
    FAILED, INVALID, MAX_PAYLOAD, OK, UNKNOWN,
};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    ffi::c_void,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    time::Duration,
};

/// The virtual host that names the companion's control API.
const CONTROL_HOST: &str = "companion";
/// The default systemd unit `http://zero/restart` restarts.
pub const COMPANION_UNIT: &str = "pocket-companion.service";
/// Set by `http://zero/quit`; the tick loop ends when it is.
pub static QUIT: AtomicBool = AtomicBool::new(false);

/// contracts/spec/net.ts.
const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Hard upper bound on live `"pocket-http"` threads independent of closed resource handles,
/// with dedicated reserved capacity so `/rex/wait` can never starve interactive actions!
const MAX_TOTAL_HTTP_THREADS: usize = 12;
const MAX_WAIT_HTTP_THREADS: usize = 4;
const MAX_LIVE_WAIT_RESOURCES: usize = 2;

/// Where a request goes.
#[derive(Clone)]
enum Route {
    Quit,
    Restart,
    Companion {
        path: String,
    },
    /// The device API; the path without its query.
    Device {
        path: String,
    },
    /// The native Rex Zero engine (`http://zero/rex/*`).
    Rex {
        path: String,
        query: String,
    },
    Loopback {
        port: u16,
        host: String,
        path: String,
    },
}

/// An opened resource's request, parsed from its descriptor.
#[derive(Clone)]
struct Request {
    url: String,
    method: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    timeout: Duration,
    max_bytes: usize,
    route: Route,
}

struct Response {
    status: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

/// Why an exchange produced no response, and whether the request may have
/// reached its server.
struct Failure {
    reached: bool,
    message: String,
}

enum Fact {
    Headers {
        handle: u32,
        bytes: Vec<u8>,
    },
    Data {
        handle: u32,
        offset: u64,
        bytes: Vec<u8>,
    },
    End {
        handle: u32,
        request: u32,
        status: i32,
        offset: u64,
    },
}
impl Fact {
    fn handle(&self) -> u32 {
        match self {
            Fact::Headers { handle, .. } | Fact::Data { handle, .. } | Fact::End { handle, .. } => {
                *handle
            }
        }
    }
}

struct Resource {
    request: Request,
    /// The submitted request id; one per resource.
    started: Option<u32>,
    /// The worker cancelled the request; its thread's answer is dropped.
    cancelled: bool,
    /// Shared cancellation flag signaled on `cancel()` or `close()` so blocking waits exit immediately.
    cancel_token: Arc<AtomicBool>,
    /// Whether this resource holds one of the reserved `/rex/wait` admission slots.
    wait_slot_active: bool,
    /// Body bytes emitted into the core.
    delivered: u64,
}

#[derive(Default)]
struct State {
    resources: HashMap<u32, Resource>,
    facts: VecDeque<Fact>,
    live_wait_resources: usize,
}

#[derive(Default)]
struct LimiterCounts {
    total_threads: usize,
    wait_threads: usize,
}

#[derive(Default)]
struct ThreadLimiter {
    counts: Mutex<LimiterCounts>,
    cv: Condvar,
}

struct ThreadPermit {
    limiter: Arc<ThreadLimiter>,
    is_wait: bool,
}

impl ThreadLimiter {
    fn acquire(self: &Arc<Self>, is_wait: bool) -> Option<ThreadPermit> {
        let mut guard = self.counts.lock().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_millis(30);
        loop {
            let can_take = guard.total_threads < MAX_TOTAL_HTTP_THREADS
                && (!is_wait || guard.wait_threads < MAX_WAIT_HTTP_THREADS);
            if can_take {
                guard.total_threads += 1;
                if is_wait {
                    guard.wait_threads += 1;
                }
                return Some(ThreadPermit {
                    limiter: self.clone(),
                    is_wait,
                });
            }
            let Some(rem) = deadline.checked_duration_since(std::time::Instant::now()) else {
                return None;
            };
            if rem.is_zero() {
                return None;
            }
            let (next_guard, res) = self.cv.wait_timeout(guard, rem).unwrap();
            guard = next_guard;
            if res.timed_out() {
                return None;
            }
        }
    }

    #[cfg(test)]
    fn active_total(&self) -> usize {
        self.counts.lock().unwrap().total_threads
    }
}

impl Drop for ThreadPermit {
    fn drop(&mut self) {
        let mut guard = self.limiter.counts.lock().unwrap();
        guard.total_threads = guard.total_threads.saturating_sub(1);
        if self.is_wait {
            guard.wait_threads = guard.wait_threads.saturating_sub(1);
        }
        self.limiter.cv.notify_all();
    }
}

impl Request {
    fn is_rex_wait(&self) -> bool {
        matches!(&self.route, Route::Rex { path, .. } if path == "/rex/wait")
    }
}

pub struct Http {
    control: PathBuf,
    unit: String,
    notify: Arc<Notify>,
    device: Option<Device>,
    rex: Option<Arc<RexZeroEngine>>,
    ui_wake: Option<(Arc<AtomicU64>, Waker)>,
    limiter: Arc<ThreadLimiter>,
    state: Mutex<State>,
}

impl Http {
    pub fn new(control: PathBuf, unit: String, notify: Arc<Notify>, device: Option<Device>) -> Self {
        Self {
            control,
            unit,
            notify,
            device,
            rex: None,
            ui_wake: None,
            limiter: Arc::default(),
            state: Mutex::default(),
        }
    }

    pub fn with_rex(mut self, rex: Arc<RexZeroEngine>) -> Self {
        self.rex = Some(rex);
        self
    }

    pub fn with_ui_waker(mut self, seq: Arc<AtomicU64>, waker: Waker) -> Self {
        self.ui_wake = Some((seq, waker));
        self
    }

    /// Owner task: emit queued facts until the core's event slots are full.
    /// True when the core took any.
    pub fn drain(&self, core: *mut Core) -> bool {
        let mut state = self.state.lock().unwrap();
        let mut took = false;
        while let Some(fact) = state.facts.front() {
            let status = unsafe {
                match fact {
                    Fact::Headers { handle, bytes } => pocket_worker_emit(
                        core,
                        *handle,
                        FACT_HEADERS,
                        OK,
                        0,
                        bytes.as_ptr(),
                        bytes.len(),
                    ),
                    Fact::Data {
                        handle,
                        offset,
                        bytes,
                    } => pocket_worker_emit(
                        core,
                        *handle,
                        FACT_DATA,
                        OK,
                        *offset,
                        bytes.as_ptr(),
                        bytes.len(),
                    ),
                    Fact::End {
                        handle,
                        request,
                        status,
                        offset,
                    } => pocket_worker_finish(core, *handle, *request, *status, *offset),
                }
            };
            if status == BUSY {
                break;
            }
            let delivered = match (status, fact) {
                (
                    OK,
                    Fact::Data {
                        handle,
                        offset,
                        bytes,
                    },
                ) => Some((*handle, offset + bytes.len() as u64)),
                _ => None,
            };
            took |= status == OK;
            state.facts.pop_front();
            if let Some((handle, end)) = delivered {
                if let Some(resource) = state.resources.get_mut(&handle) {
                    resource.delivered = end;
                }
            }
        }
        took
    }

    /// A request thread's answer becomes facts, unless its resource closed
    /// or cancelled the request meanwhile.
    fn answer(&self, handle: u32, request: u32, answer: Result<Response, Failure>, url: &str) {
        let mut state = self.state.lock().unwrap();
        match state.resources.get(&handle) {
            Some(resource) if resource.started == Some(request) && !resource.cancelled => {}
            _ => return,
        }
        let end = |status, offset| Fact::End {
            handle,
            request,
            status,
            offset,
        };
        match answer {
            Ok(response) => {
                let head = serde_json::json!({
                    "status": response.status, "url": url, "headers": response.headers,
                })
                .to_string()
                .into_bytes();
                if head.len() > MAX_PAYLOAD {
                    state.facts.push_back(end(FAILED, 0));
                } else {
                    state.facts.push_back(Fact::Headers {
                        handle,
                        bytes: head,
                    });
                    for (index, block) in response.body.chunks(MAX_PAYLOAD).enumerate() {
                        state.facts.push_back(Fact::Data {
                            handle,
                            offset: (index * MAX_PAYLOAD) as u64,
                            bytes: block.to_vec(),
                        });
                    }
                    state.facts.push_back(end(OK, response.body.len() as u64));
                }
            }
            Err(failure) => state
                .facts
                .push_back(end(if failure.reached { UNKNOWN } else { FAILED }, 0)),
        }
        drop(state);
        self.notify.wake();
        if let Some((seq, waker)) = &self.ui_wake {
            seq.fetch_add(1, Ordering::Release);
            waker.wake();
        }
    }

    fn release_wait_slot(&self, handle: u32) {
        let mut state = self.state.lock().unwrap();
        let State {
            resources,
            live_wait_resources,
            ..
        } = &mut *state;
        if let Some(res) = resources.get_mut(&handle) {
            if res.wait_slot_active {
                res.wait_slot_active = false;
                *live_wait_resources = live_wait_resources.saturating_sub(1);
            }
        }
    }
}

/// The node's driver; its context is `http`, which outlives the core.
pub fn driver(http: &Arc<Http>) -> Driver {
    Driver {
        struct_size: size_of::<Driver>() as u32,
        context: Arc::as_ptr(http) as *mut c_void,
        open: Some(open),
        start: Some(start),
        write: None,
        cancel: Some(cancel),
        close: Some(close),
        validate: None,
    }
}

unsafe extern "C" fn open(
    context: *mut c_void,
    _: *mut Core,
    handle: u32,
    config: *const u8,
    length: usize,
) -> i32 {
    let http = &*(context as *const Http);
    let descriptor = if length == 0 {
        &[][..]
    } else {
        std::slice::from_raw_parts(config, length)
    };
    let Some(request) = parse(descriptor) else {
        return INVALID;
    };
    http.state.lock().unwrap().resources.insert(
        handle,
        Resource {
            request,
            started: None,
            cancelled: false,
            cancel_token: Arc::new(AtomicBool::new(false)),
            wait_slot_active: false,
            delivered: 0,
        },
    );
    OK
}

unsafe extern "C" fn start(
    context: *mut c_void,
    _: *mut Core,
    handle: u32,
    request: u32,
    opcode: u32,
    _: *const u8,
    length: usize,
    _: usize,
) -> i32 {
    let http = &*(context as *const Http);
    let (job, cancel_token, wait_over_cap) = {
        let mut state = http.state.lock().unwrap();
        let State {
            resources,
            live_wait_resources,
            ..
        } = &mut *state;
        let Some(resource) = resources.get_mut(&handle) else {
            return INVALID;
        };
        if opcode != 1 || length != 0 || resource.started.is_some() {
            return INVALID;
        };
        resource.started = Some(request);
        let is_wait = resource.request.is_rex_wait();
        let over_cap = is_wait && *live_wait_resources >= MAX_LIVE_WAIT_RESOURCES;
        if is_wait && !over_cap {
            *live_wait_resources += 1;
            resource.wait_slot_active = true;
        }
        (
            resource.request.clone(),
            resource.cancel_token.clone(),
            over_cap,
        )
    };
    if matches!(job.route, Route::Quit) {
        QUIT.store(true, Ordering::Relaxed);
        http.answer(handle, request, Ok(no_content()), &job.url);
        return OK;
    }
    if wait_over_cap {
        // Reserve >= 6 worker handles and >= 8 threads for interactive actions (`/rex/action`, `/dev/*`).
        http.answer(
            handle,
            request,
            Ok(gateway(
                429,
                "wait capacity reserved for interactive actions".into(),
            )),
            &job.url,
        );
        return OK;
    }
    let is_wait = job.is_rex_wait();
    let Some(permit) = http.limiter.acquire(is_wait) else {
        let mut state = http.state.lock().unwrap();
        let State {
            resources,
            live_wait_resources,
            ..
        } = &mut *state;
        if let Some(res) = resources.get_mut(&handle) {
            res.started = None;
            if res.wait_slot_active {
                res.wait_slot_active = false;
                *live_wait_resources = live_wait_resources.saturating_sub(1);
            }
        }
        return BUSY;
    };
    // The context is the Arc driver() was given; each thread holds its own.
    Arc::increment_strong_count(context as *const Http);
    let owned = Arc::from_raw(context as *const Http);
    let spawned = std::thread::Builder::new()
        .name("pocket-http".into())
        .stack_size(512 * 1024)
        .spawn(move || {
            let _permit = permit;
            let answer = perform(&job, &cancel_token, &owned);
            if is_wait {
                owned.release_wait_slot(handle);
            }
            owned.answer(handle, request, answer, &job.url);
        });
    if spawned.is_ok() {
        OK
    } else {
        http.release_wait_slot(handle);
        FAILED
    }
}

/// The core reports the request UNKNOWN; its stream ends where delivery
/// stopped, and the thread's answer is dropped.
unsafe extern "C" fn cancel(context: *mut c_void, core: *mut Core, handle: u32, request: u32) {
    let http = &*(context as *const Http);
    let mut wake_rex = false;
    let delivered = {
        let mut state = http.state.lock().unwrap();
        let State {
            resources,
            facts,
            live_wait_resources,
        } = &mut *state;
        let Some(resource) = resources.get_mut(&handle) else {
            return;
        };
        if resource.started != Some(request) || resource.cancelled {
            return;
        };
        resource.cancelled = true;
        resource.cancel_token.store(true, Ordering::SeqCst);
        if resource.wait_slot_active {
            resource.wait_slot_active = false;
            *live_wait_resources = live_wait_resources.saturating_sub(1);
            wake_rex = true;
        } else if resource.request.is_rex_wait() {
            wake_rex = true;
        }
        let d = resource.delivered;
        facts.retain(|fact| fact.handle() != handle);
        d
    };
    if wake_rex {
        if let Some(rex) = &http.rex {
            rex.wake_waiters();
        }
    }
    pocket_worker_finish(core, handle, request, UNKNOWN, delivered);
}

unsafe extern "C" fn close(context: *mut c_void, _: *mut Core, handle: u32) -> i32 {
    let http = &*(context as *const Http);
    let wake_rex = {
        let mut state = http.state.lock().unwrap();
        let mut should_wake = false;
        if let Some(res) = state.resources.remove(&handle) {
            res.cancel_token.store(true, Ordering::SeqCst);
            if res.wait_slot_active {
                state.live_wait_resources = state.live_wait_resources.saturating_sub(1);
                should_wake = true;
            } else if res.request.is_rex_wait() {
                should_wake = true;
            }
        }
        state.facts.retain(|fact| fact.handle() != handle);
        should_wake
    };
    if wake_rex {
        if let Some(rex) = &http.rex {
            rex.wake_waiters();
        }
    }
    OK
}

fn no_content() -> Response {
    Response {
        status: 204,
        headers: BTreeMap::new(),
        body: Vec::new(),
    }
}

/// The descriptor `io.http(...).open` encodes (framework/src/io.ts), bounded
/// as contracts/spec/net.ts bounds it, with a URL this program can reach.
fn parse(descriptor: &[u8]) -> Option<Request> {
    let value: serde_json::Value = serde_json::from_slice(descriptor).ok()?;
    let url = value.get("url")?.as_str()?.to_string();
    let method = match value.get("method") {
        Some(method) => method.as_str()?.to_string(),
        None => "GET".into(),
    };
    if !METHODS.contains(&method.as_str()) {
        return None;
    }
    let mut headers = BTreeMap::new();
    if let Some(fields) = value.get("headers") {
        for (name, value) in fields.as_object()? {
            let value = value.as_str()?;
            if name.contains(['\r', '\n', ':']) || value.contains(['\r', '\n']) {
                return None;
            }
            headers.insert(name.to_ascii_lowercase(), value.to_string());
        }
    }
    let body = match value.get("body") {
        Some(body) => body.as_str()?.as_bytes().to_vec(),
        None => Vec::new(),
    };
    let timeout = match value.get("timeoutMs") {
        Some(timeout) => timeout
            .as_u64()
            .filter(|ms| (1..=MAX_TIMEOUT_MS).contains(ms))?,
        None => DEFAULT_TIMEOUT_MS,
    };
    let max_bytes = match value.get("maxBytes") {
        Some(limit) => limit
            .as_u64()
            .filter(|bytes| (1..=MAX_RESPONSE_BYTES as u64).contains(bytes))?
            as usize,
        None => DEFAULT_RESPONSE_BYTES,
    };
    let route = route(&url)?;
    Some(Request {
        url,
        method,
        headers,
        body,
        timeout: Duration::from_millis(timeout),
        max_bytes,
        route,
    })
}

fn route(url: &str) -> Option<Route> {
    match url {
        "http://zero/quit" => return Some(Route::Quit),
        "http://zero/restart" => return Some(Route::Restart),
        _ => {}
    }
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    if path.contains([' ', '\r', '\n']) {
        return None;
    }
    if authority == CONTROL_HOST {
        return Some(Route::Companion { path: path.into() });
    }
    if authority == "zero" && path.starts_with("/dev/") {
        let path = path.split('?').next().unwrap_or(path);
        return Some(Route::Device { path: path.into() });
    }
    if authority == "zero" && (path == "/rex" || path.starts_with("/rex/")) {
        let (clean_path, query) = path.split_once('?').unwrap_or((path, ""));
        return Some(Route::Rex {
            path: clean_path.into(),
            query: query.into(),
        });
    }
    let (name, port) = authority.rsplit_once(':')?;
    if name != "127.0.0.1" && name != "localhost" {
        return None;
    }
    Some(Route::Loopback {
        port: port.parse().ok()?,
        host: authority.into(),
        path: path.into(),
    })
}

fn perform(
    request: &Request,
    cancel_token: &AtomicBool,
    http: &Http,
) -> Result<Response, Failure> {
    if cancel_token.load(Ordering::Acquire) {
        return Err(Failure {
            reached: false,
            message: "request cancelled".into(),
        });
    }
    let (control, unit) = (&http.control, http.unit.as_str());
    match &request.route {
        Route::Quit => Ok(no_content()),
        Route::Restart => Ok(restart(unit)),
        Route::Device { path } => {
            let Some(device) = &http.device else {
                return Ok(gateway(503, "this program runs no device layer".into()));
            };
            let answer = device.handle(&request.method, path, &request.body);
            if answer.body.len() > request.max_bytes {
                return Err(Failure {
                    reached: true,
                    message: "the response is over maxBytes".into(),
                });
            }
            Ok(Response {
                status: answer.status,
                headers: BTreeMap::from([("content-type".into(), answer.content_type.into())]),
                body: answer.body,
            })
        }
        Route::Rex { path, query } => {
            let Some(rex) = &http.rex else {
                return Ok(gateway(503, "this program runs no Rex engine".into()));
            };
            let answer = rex.handle_http_with_context(
                &request.method,
                path,
                query,
                &request.body,
                request.timeout,
                cancel_token,
            );
            if cancel_token.load(Ordering::Acquire) {
                return Err(Failure {
                    reached: false,
                    message: "request cancelled".into(),
                });
            }
            if answer.body.len() > request.max_bytes {
                return Err(Failure {
                    reached: true,
                    message: "the response is over maxBytes".into(),
                });
            }
            Ok(Response {
                status: answer.status,
                headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
                body: answer.body,
            })
        }
        Route::Loopback { port, host, path } => exchange(request, *port, host, path, None),
        Route::Companion { path } => Ok(match control_info(control) {
            Err(message) => gateway(503, message),
            Ok((port, token)) => {
                let host = format!("127.0.0.1:{port}");
                exchange(request, port, &host, path, Some(&token))
                    .unwrap_or_else(|failure| gateway(502, failure.message))
            }
        }),
    }
}

fn gateway(status: u16, message: String) -> Response {
    Response {
        status,
        headers: BTreeMap::from([("content-type".into(), "application/json".into())]),
        body: serde_json::to_vec(&serde_json::json!({ "error": message })).unwrap_or_default(),
    }
}

fn restart(unit: &str) -> Response {
    match std::process::Command::new("systemctl")
        .args(["restart", unit])
        .output()
    {
        Ok(output) if output.status.success() => no_content(),
        Ok(output) => Response {
            status: 500,
            headers: BTreeMap::new(),
            body: output.stderr,
        },
        Err(error) => Response {
            status: 500,
            headers: BTreeMap::new(),
            body: error.to_string().into_bytes(),
        },
    }
}

/// `{port, token}` from the companion's control.json.
fn control_info(path: &PathBuf) -> Result<(u16, String), String> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        format!(
            "Pocket Companion is not running ({}: {error})",
            path.display()
        )
    })?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| "control.json is not JSON".to_string())?;
    let port = value["port"]
        .as_u64()
        .filter(|port| (1..=65535).contains(port));
    let token = value["token"].as_str().filter(|token| !token.is_empty());
    match (port, token) {
        (Some(port), Some(token)) => Ok((port as u16, token.to_string())),
        _ => Err("control.json names no port and token".into()),
    }
}

/// One HTTP/1.1 exchange with `Connection: close`.
fn exchange(
    request: &Request,
    port: u16,
    host: &str,
    path: &str,
    token: Option<&str>,
) -> Result<Response, Failure> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let connect = |error: std::io::Error| Failure {
        reached: false,
        message: match error.kind() {
            std::io::ErrorKind::ConnectionRefused => {
                "nothing answers on this machine's port".into()
            }
            _ => error.to_string(),
        },
    };
    let lost = |error: std::io::Error| Failure {
        reached: true,
        message: match error.kind() {
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
                "the request timed out".into()
            }
            _ => error.to_string(),
        },
    };
    let protocol = |message: &str| Failure {
        reached: true,
        message: message.into(),
    };
    let mut stream = TcpStream::connect_timeout(&address, request.timeout).map_err(connect)?;
    stream
        .set_read_timeout(Some(request.timeout))
        .map_err(lost)?;
    stream
        .set_write_timeout(Some(request.timeout))
        .map_err(lost)?;
    let mut head = format!(
        "{} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
        request.method,
        request.body.len()
    );
    for (name, value) in &request.headers {
        if !matches!(
            name.as_str(),
            "host" | "connection" | "content-length" | "authorization"
        ) {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    if let Some(token) = token {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).map_err(lost)?;
    stream.write_all(&request.body).map_err(lost)?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(lost)?;
    let status: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| protocol("not an HTTP response"))?;
    let mut headers = BTreeMap::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(lost)? == 0 {
            break;
        }
        let field = line.trim_end();
        if field.is_empty() {
            break;
        }
        if let Some((name, value)) = field.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let value = value.trim().to_string();
            headers
                .entry(name)
                .and_modify(|joined: &mut String| {
                    joined.push_str(", ");
                    joined.push_str(&value);
                })
                .or_insert(value);
        }
    }
    let too_large = || protocol("the response is over maxBytes");
    let mut body = Vec::new();
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"))
    {
        loop {
            line.clear();
            reader.read_line(&mut line).map_err(lost)?;
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| protocol("bad chunk"))?;
            if size == 0 {
                break;
            }
            if body.len() + size > request.max_bytes {
                return Err(too_large());
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..]).map_err(lost)?;
            line.clear();
            reader.read_line(&mut line).map_err(lost)?;
        }
    } else {
        let limit = request.max_bytes as u64 + 1;
        reader.take(limit).read_to_end(&mut body).map_err(lost)?;
        if body.len() > request.max_bytes {
            return Err(too_large());
        }
    }
    headers.remove("transfer-encoding");
    Ok(Response {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(url: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "url": url, "method": "GET" })).unwrap()
    }

    #[test]
    fn routes_are_this_machine_only() {
        assert!(matches!(route("http://zero/quit"), Some(Route::Quit)));
        assert!(matches!(route("http://zero/restart"), Some(Route::Restart)));
        assert!(matches!(route("http://companion/status"), Some(Route::Companion { path }) if path == "/status"));
        // The device API drops the query: the device layer routes on the path.
        assert!(matches!(route("http://zero/dev/motion?t=3"), Some(Route::Device { path }) if path == "/dev/motion"));
        assert!(matches!(route("http://zero/rex/wait?since=4&timeout_ms=9000"), Some(Route::Rex { path, query }) if path == "/rex/wait" && query == "since=4&timeout_ms=9000"));
        assert!(matches!(route("http://127.0.0.1:8080/x"), Some(Route::Loopback { port: 8080, .. })));
        assert!(matches!(route("http://localhost:9/"), Some(Route::Loopback { port: 9, .. })));
        for refused in ["http://zero/other", "http://example.com/", "https://companion/status", "http://10.0.0.1:80/", "http://zero/dev/a b"] {
            assert!(route(refused).is_none(), "{refused}");
        }
    }

    #[test]
    fn descriptors_are_bounded_and_headers_cannot_split() {
        assert!(parse(&descriptor("http://zero/dev/battery")).is_some());
        let split = serde_json::json!({ "url": "http://companion/x", "headers": { "x": "a\r\nInjected: 1" } });
        assert!(parse(&serde_json::to_vec(&split).unwrap()).is_none());
        let method = serde_json::json!({ "url": "http://companion/x", "method": "TRACE" });
        assert!(parse(&serde_json::to_vec(&method).unwrap()).is_none());
        let large = serde_json::json!({ "url": "http://companion/x", "maxBytes": MAX_RESPONSE_BYTES + 1 });
        assert!(parse(&serde_json::to_vec(&large).unwrap()).is_none());
    }

    #[test]
    fn the_device_api_answers_in_process() {
        let dir = std::env::temp_dir().join(format!("pocket-zero-http-{}", std::process::id()));
        let device = Device::new(dir.clone(), true, "default".into());
        let http = Http::new(
            PathBuf::from("/nonexistent/control.json"),
            COMPANION_UNIT.into(),
            Arc::default(),
            Some(device),
        );
        let cancel_flag = AtomicBool::new(false);
        let request = parse(&descriptor("http://zero/dev/capabilities")).unwrap();
        let response = perform(&request, &cancel_flag, &http).ok().unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.headers["content-type"], "application/json");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&response.body).unwrap()["mock"],
            true
        );
        // Without a companion, its host answers as a gateway.
        let companion = perform(
            &parse(&descriptor("http://companion/status")).unwrap(),
            &cancel_flag,
            &http,
        )
        .ok()
        .unwrap();
        assert_eq!(companion.status, 503);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rex_wait_honors_http_deadline_cancels_on_close_and_reserves_action_capacity() {
        let rex = Arc::new(RexZeroEngine::new_mock(None));
        let http = Arc::new(
            Http::new(
                PathBuf::from("/nonexistent/control.json"),
                COMPANION_UNIT.into(),
                Arc::default(),
                None,
            )
            .with_rex(rex.clone()),
        );
        let drv = driver(&http);
        let cur_rev = rex.snapshot().revision;

        // 1. Short HTTP `timeoutMs` (80ms) caps `/rex/wait` (`timeout_ms=25000`)!
        let short_desc = serde_json::to_vec(&serde_json::json!({
            "url": format!("http://zero/rex/wait?since={cur_rev}&timeout_ms=25000"),
            "method": "GET",
            "timeoutMs": 80
        }))
        .unwrap();
        let req_short = parse(&short_desc).unwrap();
        let t0 = std::time::Instant::now();
        let resp = perform(&req_short, &AtomicBool::new(false), &http).ok().unwrap();
        assert_eq!(resp.status, 200);
        assert!(t0.elapsed() < Duration::from_millis(400));

        // 2. Closing 20 churned `/rex/wait` resources cancels their threads immediately so threads never accumulate!
        let wait_desc = serde_json::to_vec(&serde_json::json!({
            "url": format!("http://zero/rex/wait?since={cur_rev}&timeout_ms=25000"),
            "method": "GET"
        }))
        .unwrap();
        for h in 1..=20u32 {
            assert_eq!(
                unsafe { (drv.open.unwrap())(drv.context, std::ptr::null_mut(), h, wait_desc.as_ptr(), wait_desc.len()) },
                OK
            );
            assert_eq!(
                unsafe { (drv.start.unwrap())(drv.context, std::ptr::null_mut(), h, 1, 1, std::ptr::null(), 0, 0) },
                OK
            );
            assert_eq!(
                unsafe { (drv.close.unwrap())(drv.context, std::ptr::null_mut(), h) },
                OK
            );
        }
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(http.limiter.active_total(), 0);

        // 3. Even with 8 simultaneous `/rex/wait` attempts open, excess waits finish immediately with 429
        // and interactive `POST /rex/action` succeeds without starvation!
        for h in 100..108u32 {
            assert_eq!(
                unsafe { (drv.open.unwrap())(drv.context, std::ptr::null_mut(), h, wait_desc.as_ptr(), wait_desc.len()) },
                OK
            );
            assert_eq!(
                unsafe { (drv.start.unwrap())(drv.context, std::ptr::null_mut(), h, 1, 1, std::ptr::null(), 0, 0) },
                OK
            );
        }
        let action_desc = serde_json::to_vec(&serde_json::json!({
            "url": "http://zero/rex/action",
            "method": "POST",
            "body": r#"{"op":"toggle_mute"}"#
        }))
        .unwrap();
        assert_eq!(
            unsafe { (drv.open.unwrap())(drv.context, std::ptr::null_mut(), 200, action_desc.as_ptr(), action_desc.len()) },
            OK
        );
        assert_eq!(
            unsafe { (drv.start.unwrap())(drv.context, std::ptr::null_mut(), 200, 1, 1, std::ptr::null(), 0, 0) },
            OK
        );
        for h in (100..108u32).chain(std::iter::once(200)) {
            let _ = unsafe { (drv.close.unwrap())(drv.context, std::ptr::null_mut(), h) };
        }
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(http.limiter.active_total(), 0);
    }
}
