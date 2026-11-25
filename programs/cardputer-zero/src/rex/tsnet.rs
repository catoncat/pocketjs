//! Userspace `rex-zero-tsnet` child supervisor: lazily spawns `rex-zero-tsnet`,
//! parses newline-delimited JSON state & ping replies on stdout, encodes QR login
//! matrices, and guarantees zero orphan processes on `Drop`.

use crate::rex::{
    qr,
    transport::state_dir,
    types::{PathKind, TailnetPeer, TailnetState},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
};

const MAX_PENDING_STDIN_CMDS: usize = 16;

pub type TailnetCallback = Arc<dyn Fn(TailnetUpdate) + Send + Sync>;

pub enum TailnetUpdate {
    State(TailnetState),
    PingResult {
        peer_ip: String,
        latency_ms: Option<u32>,
        path_kind: Option<PathKind>,
        error: Option<String>,
    },
    ProbeResult {
        dns_name: String,
        rex_endpoint: Option<String>,
    },
}

struct RunningChild {
    child: Child,
    cmd_tx: Option<mpsc::SyncSender<String>>,
    stopped: Arc<AtomicBool>,
    pending: Arc<Mutex<HashMap<i64, PendingCmd>>>,
}

#[allow(dead_code)]
enum PendingCmd {
    Ping { peer_ip: String },
    Probe { dns_name: String },
}

struct SupervisorState {
    generation: u64,
    enabled: bool,
    child: Option<RunningChild>,
}

struct TsnetShared {
    /// Short-lived lock protecting generation, enabled state, active child
    /// handle, and command channel. Never held across blocking I/O or callbacks!
    state: Mutex<SupervisorState>,
    /// Serializes callback emissions with `generation` checks so a retired
    /// reader thread can never deliver a stale update after `stop_locked`.
    emit_gate: Mutex<()>,
    callback: TailnetCallback,
}

impl TsnetShared {
    fn emit_for_gen(&self, my_gen: u64, update: TailnetUpdate) -> bool {
        let _gate = self.emit_gate.lock().unwrap();
        {
            let state = self.state.lock().unwrap();
            if state.generation != my_gen || !state.enabled {
                return false;
            }
        }
        (self.callback)(update);
        true
    }
}

pub struct TsnetSupervisor {
    /// Serializes `set_enabled` and `stop` lifecycle transitions so concurrent
    /// starts/stops can never race, leak an un-reaped child, or install a child
    /// after `stop()` returned.
    lifecycle: Mutex<()>,
    shared: Arc<TsnetShared>,
    next_id: AtomicI64,
}

impl TsnetSupervisor {
    pub fn new(callback: TailnetCallback) -> Self {
        Self {
            lifecycle: Mutex::new(()),
            shared: Arc::new(TsnetShared {
                state: Mutex::new(SupervisorState {
                    generation: 0,
                    enabled: false,
                    child: None,
                }),
                emit_gate: Mutex::new(()),
                callback,
            }),
            next_id: AtomicI64::new(1),
        }
    }

    pub fn set_enabled(
        &self,
        enabled: bool,
        hostname: Option<&str>,
        auth_key: Option<&str>,
    ) -> Result<(), String> {
        if !enabled {
            let _life = self.lifecycle.lock().unwrap();
            self.stop_locked();
            let _gate = self.shared.emit_gate.lock().unwrap();
            (self.shared.callback)(TailnetUpdate::State(TailnetState::default()));
            return Ok(());
        }

        let bin = find_tsnet_binary().ok_or_else(|| {
            "未找到 rex-zero-tsnet 辅助进程（请运行 scripts/build-tsnet.sh 或检查安装包）"
                .to_string()
        })?;
        self.set_enabled_with_bin(&bin, hostname, auth_key)
    }

    fn set_enabled_with_bin(
        &self,
        bin: &Path,
        hostname: Option<&str>,
        auth_key: Option<&str>,
    ) -> Result<(), String> {
        let _life = self.lifecycle.lock().unwrap();
        let clean_auth_key = auth_key.map(str::trim).filter(|s| !s.is_empty());

        // Inspect existing child: detect & reap exited children via `try_wait()`
        // before attempting to reuse a running process.
        let mut exited_notice: Option<String> = None;
        let mut reuse_tx: Option<mpsc::SyncSender<String>> = None;
        let mut dead_to_reap: Option<RunningChild> = None;
        {
            let mut state = self.shared.state.lock().unwrap();
            let wait_res = state.child.as_mut().map(|r| r.child.try_wait());
            match wait_res {
                Some(Ok(None)) => {
                    if clean_auth_key.is_none() {
                        reuse_tx = state.child.as_ref().and_then(|r| r.cmd_tx.clone());
                    }
                }
                Some(Ok(Some(status))) => {
                    state.generation = state.generation.wrapping_add(1);
                    state.enabled = false;
                    if let Some(running) = state.child.take() {
                        running.stopped.store(true, Ordering::SeqCst);
                    }
                    exited_notice = Some(format!("rex-zero-tsnet 已退出 ({status})"));
                }
                Some(Err(e)) => {
                    state.generation = state.generation.wrapping_add(1);
                    state.enabled = false;
                    if let Some(dead) = state.child.take() {
                        dead.stopped.store(true, Ordering::SeqCst);
                        dead_to_reap = Some(dead);
                    }
                    exited_notice = Some(format!("rex-zero-tsnet 状态异常 ({e})"));
                }
                None => {}
            }
        }
        if let Some(mut dead) = dead_to_reap {
            drop(dead.cmd_tx.take());
            let _ = dead.child.kill();
            let _ = dead.child.wait();
        }

        if let Some(err_msg) = exited_notice {
            let _gate = self.shared.emit_gate.lock().unwrap();
            (self.shared.callback)(TailnetUpdate::State(TailnetState {
                enabled: false,
                backend_state: "Exited".into(),
                error: Some(err_msg),
                ..TailnetState::default()
            }));
        }

        if let Some(tx) = reuse_tx {
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let line = format!("{}\n", json!({"id": id, "cmd": "status"}));
            if tx.try_send(line).is_ok() {
                return Ok(());
            }
            // Stdin writer disconnected or wedged -> tear down cleanly and respawn below.
        }

        // Stop any previous running child before spawning a fresh one.
        self.stop_locked();

        let dir = state_dir().join("tsnet");
        std::fs::create_dir_all(&dir).map_err(|e| format!("create tsnet state dir: {e}"))?;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));

        let mut cmd = Command::new(bin);
        cmd.arg("--state-dir").arg(&dir);
        cmd.arg("--hostname").arg(
            hostname
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("rex-zero"),
        );
        // Never pass `authKey` via `--auth-key` argv (visible in `/proc/<pid>/cmdline` / `ps`).
        // `tailnet/main.go` constructs `tsnet.Server{AuthKey: *authKey}` which natively reads
        // `TS_AUTHKEY` from the private child environment when `--auth-key` is omitted.
        cmd.env_remove("TS_AUTHKEY").env_remove("TS_AUTH_KEY");
        if let Some(key) = clean_auth_key {
            cmd.env("TS_AUTHKEY", key);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("启动 {} 失败: {e}", bin.display()))?;
        let Some(stdin) = child.stdin.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("tsnet child missing stdin".into());
        };
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("tsnet child missing stdout".into());
        };

        let pending: Arc<Mutex<HashMap<i64, PendingCmd>>> = Arc::default();
        let stopped = Arc::new(AtomicBool::new(false));
        let (cmd_tx, cmd_rx) = mpsc::sync_channel::<String>(MAX_PENDING_STDIN_CMDS);

        // Dedicated non-blocking stdin writer thread: keeps `state` mutex & `stop()`
        // completely decoupled from stdin pipe backpressure.
        if let Err(e) = thread::Builder::new()
            .name("rex-zero-tsnet-stdin".into())
            .stack_size(128 * 1024)
            .spawn(move || write_tsnet_stdin(stdin, cmd_rx))
        {
            drop(cmd_tx);
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("spawn tsnet stdin writer: {e}"));
        }

        let my_gen = {
            let mut state = self.shared.state.lock().unwrap();
            state.generation = state.generation.wrapping_add(1);
            state.enabled = true;
            state.generation
        };

        {
            let _gate = self.shared.emit_gate.lock().unwrap();
            (self.shared.callback)(TailnetUpdate::State(TailnetState {
                enabled: true,
                backend_state: "Starting".into(),
                ..TailnetState::default()
            }));
        }

        let shared_reader = self.shared.clone();
        let pending_reader = pending.clone();
        let stopped_reader = stopped.clone();
        if let Err(e) = thread::Builder::new()
            .name("rex-zero-tsnet-io".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                read_tsnet_stdout(
                    BufReader::new(stdout),
                    pending_reader,
                    stopped_reader,
                    shared_reader,
                    my_gen,
                )
            })
        {
            stopped.store(true, Ordering::SeqCst);
            {
                let mut state = self.shared.state.lock().unwrap();
                state.generation = state.generation.wrapping_add(1);
                state.enabled = false;
            }
            drop(cmd_tx);
            let _ = child.kill();
            let _ = child.wait();
            {
                let _gate = self.shared.emit_gate.lock().unwrap();
                (self.shared.callback)(TailnetUpdate::State(TailnetState::default()));
            }
            return Err(format!("spawn tsnet reader: {e}"));
        }

        self.shared.state.lock().unwrap().child = Some(RunningChild {
            child,
            cmd_tx: Some(cmd_tx),
            stopped,
            pending,
        });
        Ok(())
    }

    pub fn ping(&self, peer_ip: &str) -> Result<(), String> {
        self.send_cmd(
            json!({ "cmd": "ping", "ip": peer_ip }),
            Some(PendingCmd::Ping {
                peer_ip: peer_ip.to_string(),
            }),
        )
    }

    #[allow(dead_code)]
    pub fn probe_rex(&self, dns_name: &str) -> Result<(), String> {
        self.send_cmd(
            json!({ "cmd": "probe_rex", "dnsName": dns_name }),
            Some(PendingCmd::Probe {
                dns_name: dns_name.to_string(),
            }),
        )
    }

    fn send_cmd(
        &self,
        mut payload: serde_json::Value,
        track: Option<PendingCmd>,
    ) -> Result<(), String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("id".into(), json!(id));
        }
        let mut line = payload.to_string();
        line.push('\n');

        let (cmd_tx, pending) = {
            let state = self.shared.state.lock().unwrap();
            let Some(running) = state.child.as_ref() else {
                return Err("Tailscale 用户态节点尚未启动".into());
            };
            let Some(tx) = running.cmd_tx.clone() else {
                return Err("Tailscale 辅助进程正在关闭".into());
            };
            (tx, running.pending.clone())
        };

        if let Some(cmd_kind) = track {
            pending.lock().unwrap().insert(id, cmd_kind);
        }

        match cmd_tx.try_send(line) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(_)) => {
                pending.lock().unwrap().remove(&id);
                Err("Tailscale 命令队列已满，请稍候重试".into())
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                pending.lock().unwrap().remove(&id);
                Err("Tailscale 辅助进程已退出".into())
            }
        }
    }

    pub fn stop(&self) {
        let _life = self.lifecycle.lock().unwrap();
        self.stop_locked();
    }

    fn stop_locked(&self) {
        let taken = {
            let _gate = self.shared.emit_gate.lock().unwrap();
            let mut state = self.shared.state.lock().unwrap();
            state.generation = state.generation.wrapping_add(1);
            state.enabled = false;
            state.child.take()
        };
        if let Some(mut running) = taken {
            running.stopped.store(true, Ordering::SeqCst);
            // Close channel immediately (never block on stdin write_all!) and
            // terminate + reap the child unconditionally. Killing the child
            // closes the pipe read end so any blocked writer thread exits at once.
            drop(running.cmd_tx.take());
            let _ = running.child.kill();
            let _ = running.child.wait();
        }
    }
}

impl Drop for TsnetSupervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

fn write_tsnet_stdin(mut stdin: ChildStdin, rx: mpsc::Receiver<String>) {
    for line in rx {
        if stdin.write_all(line.as_bytes()).is_err() || stdin.flush().is_err() {
            break;
        }
    }
}

/// Collapses runs of non-ASCII-alphanumeric characters into a single `-` and lowercases ASCII,
/// matching Rex Desktop's `<slug>-rex` hostname convention while keeping hyphens intact so
/// `labnas` and `lab-nas` stay distinct.
pub fn rex_slug_words(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_dash = false;
    for c in s.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

pub fn first_dns_label(dns_name: &str) -> &str {
    dns_name
        .trim()
        .trim_end_matches('.')
        .split('.')
        .next()
        .unwrap_or("")
        .trim()
}

pub fn rex_node_prefix(host_name: &str, dns_name: &str) -> Option<String> {
    let first = first_dns_label(dns_name).to_ascii_lowercase();
    if let Some(p) = first.strip_suffix("-rex") {
        if !p.is_empty() {
            return Some(p.to_string());
        }
    }
    let hn = host_name.trim();
    if hn.len() > 4 && hn.as_bytes()[hn.len() - 4..].eq_ignore_ascii_case(b"-rex") {
        let slug = rex_slug_words(&hn[..hn.len() - 4]);
        if !slug.is_empty() {
            return Some(slug);
        }
    }
    None
}

pub fn is_rex_node_name(host_name: &str, dns_name: &str) -> bool {
    rex_node_prefix(host_name, dns_name).is_some()
}

/// Hyphen-preserving companion lookup keys for an OS peer or saved host.
pub fn peer_companion_keys(host_name: &str, dns_name: &str) -> [Option<String>; 2] {
    if let Some(prefix) = rex_node_prefix(host_name, dns_name) {
        return [Some(prefix), None];
    }
    let dns_key = {
        let f = first_dns_label(dns_name).to_ascii_lowercase();
        (!f.is_empty()).then_some(f)
    };
    let name_key = {
        let s = rex_slug_words(host_name);
        (!s.is_empty()).then_some(s)
    };
    if dns_key == name_key {
        [dns_key, None]
    } else {
        [dns_key, name_key]
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPeer {
    #[serde(default)]
    host_name: String,
    #[serde(default)]
    dns_name: String,
    #[serde(default)]
    ips: Vec<String>,
    #[serde(default)]
    online: bool,
    #[serde(default)]
    cur_addr: String,
    #[serde(default)]
    relay: String,
}

fn read_tsnet_stdout(
    mut reader: impl BufRead,
    pending: Arc<Mutex<HashMap<i64, PendingCmd>>>,
    stopped: Arc<AtomicBool>,
    shared: Arc<TsnetShared>,
    my_gen: u64,
) {
    let mut current = TailnetState {
        enabled: true,
        backend_state: "Starting".into(),
        ..TailnetState::default()
    };
    let mut line = String::new();
    loop {
        line.clear();
        let Ok(n) = reader.read_line(&mut line) else {
            break;
        };
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };
        match val.get("type").and_then(|t| t.as_str()) {
            Some("ready") => {
                if let Some(port) = val.get("proxyPort").and_then(|p| p.as_u64()) {
                    current.proxy_port = port as u16;
                    if !shared.emit_for_gen(my_gen, TailnetUpdate::State(current.clone())) {
                        return;
                    }
                }
            }
            Some("state") => {
                current.enabled = true;
                current.backend_state = val
                    .get("backendState")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Starting")
                    .to_string();
                let auth_url = val
                    .get("authUrl")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if current.auth_url != auth_url {
                    current.qr_matrix = qr::encode_matrix(&auth_url);
                    current.auth_url = auth_url;
                }
                current.tailnet_name = val
                    .get("tailnet")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                current.self_dns = val
                    .get("self")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if let Some(port) = val.get("proxyPort").and_then(|p| p.as_u64()) {
                    current.proxy_port = port as u16;
                }
                if let Some(peers_val) = val.get("peers") {
                    if let Ok(raw_peers) = serde_json::from_value::<Vec<RawPeer>>(peers_val.clone())
                    {
                        let mut rex_by_prefix: HashMap<String, (String, bool)> = HashMap::new();
                        for rp in &raw_peers {
                            let dns_clean = rp.dns_name.trim_end_matches('.').to_ascii_lowercase();
                            if !dns_clean.is_empty() {
                                if let Some(prefix) = rex_node_prefix(&rp.host_name, &dns_clean) {
                                    let replace = match rex_by_prefix.get(&prefix) {
                                        None => true,
                                        Some((_, prev_online)) => rp.online && !*prev_online,
                                    };
                                    if replace {
                                        rex_by_prefix.insert(prefix, (dns_clean, rp.online));
                                    }
                                }
                            }
                        }

                        let mut mapped: Vec<TailnetPeer> = raw_peers
                            .into_iter()
                            .map(|p| {
                                let dns_clean = p.dns_name.trim_end_matches('.').to_ascii_lowercase();
                                let prev = current.peers.iter().find(|old| {
                                    old.dns_name.eq_ignore_ascii_case(&dns_clean)
                                        && !dns_clean.is_empty()
                                });
                                let path_kind = prev.and_then(|o| o.path_kind).or({
                                    if !p.cur_addr.is_empty() {
                                        Some(PathKind::Direct)
                                    } else if !p.relay.is_empty() {
                                        Some(PathKind::Derp)
                                    } else {
                                        None
                                    }
                                });
                                let auto_rex_ep = if !dns_clean.is_empty()
                                    && is_rex_node_name(&p.host_name, &dns_clean)
                                {
                                    Some(format!("https://{dns_clean}"))
                                } else {
                                    peer_companion_keys(&p.host_name, &dns_clean)
                                        .into_iter()
                                        .flatten()
                                        .find_map(|k| rex_by_prefix.get(&k))
                                        .map(|(rex_dns, _)| format!("https://{rex_dns}"))
                                };
                                TailnetPeer {
                                    host_name: p.host_name,
                                    dns_name: dns_clean,
                                    ips: p.ips,
                                    online: p.online,
                                    path_kind,
                                    latency_ms: prev.and_then(|o| o.latency_ms),
                                    rex_endpoint: prev
                                        .and_then(|o| o.rex_endpoint.clone())
                                        .or(auto_rex_ep),
                                    already_added: false,
                                }
                            })
                            .collect();

                        mapped.sort_by(|a, b| {
                            let tier = |p: &TailnetPeer| -> u8 {
                                let is_rex = is_rex_node_name(&p.host_name, &p.dns_name);
                                let has_rex = p.rex_endpoint.is_some();
                                match (p.online, is_rex, has_rex) {
                                    (true, true, _) => 0,
                                    (true, false, true) => 1,
                                    (false, true, _) => 2,
                                    (true, false, false) => 3,
                                    (false, false, _) => 4,
                                }
                            };
                            tier(a)
                                .cmp(&tier(b))
                                .then_with(|| {
                                    a.host_name
                                        .to_ascii_lowercase()
                                        .cmp(&b.host_name.to_ascii_lowercase())
                                })
                                .then_with(|| a.dns_name.cmp(&b.dns_name))
                        });
                        current.peers = mapped;
                    }
                }
                if !shared.emit_for_gen(my_gen, TailnetUpdate::State(current.clone())) {
                    return;
                }
            }
            Some("reply") => {
                let id = val.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                let ok = val.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
                let err = val
                    .get("error")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string);
                let Some(cmd_kind) = pending.lock().unwrap().remove(&id) else {
                    continue;
                };
                match cmd_kind {
                    PendingCmd::Ping { peer_ip } => {
                        let latency_ms = val
                            .get("latencyMs")
                            .and_then(|v| v.as_f64())
                            .map(|ms| ms.round().max(0.0) as u32);
                        let path_kind = match val.get("pathKind").and_then(|v| v.as_str()) {
                            Some("direct") => Some(PathKind::Direct),
                            Some("relay") => Some(PathKind::Relay),
                            Some("derp") => Some(PathKind::Derp),
                            _ => None,
                        };
                        if !shared.emit_for_gen(
                            my_gen,
                            TailnetUpdate::PingResult {
                                peer_ip,
                                latency_ms: if ok { latency_ms } else { None },
                                path_kind: if ok { path_kind } else { None },
                                error: if ok { None } else { err },
                            },
                        ) {
                            return;
                        }
                    }
                    PendingCmd::Probe { dns_name } => {
                        let rex_endpoint = if ok {
                            val.get("rexEndpoint")
                                .and_then(|v| v.as_str())
                                .map(ToString::to_string)
                        } else {
                            None
                        };
                        if !shared.emit_for_gen(
                            my_gen,
                            TailnetUpdate::ProbeResult {
                                dns_name,
                                rex_endpoint,
                            },
                        ) {
                            return;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if !stopped.load(Ordering::Acquire) {
        let _gate = shared.emit_gate.lock().unwrap();
        let should_emit = {
            let mut state = shared.state.lock().unwrap();
            if state.generation != my_gen || !state.enabled {
                false
            } else {
                state.enabled = false;
                true
            }
        };
        if should_emit {
            (shared.callback)(TailnetUpdate::State(TailnetState {
                enabled: false,
                backend_state: "Exited".into(),
                error: Some("rex-zero-tsnet 辅助进程已退出".into()),
                ..TailnetState::default()
            }));
        }
    }
}

pub fn find_tsnet_binary() -> Option<PathBuf> {
    if let Some(env_bin) = std::env::var_os("REX_ZERO_TSNET_BIN") {
        let p = PathBuf::from(env_bin);
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in [
                "rex-zero-tsnet",
                "rex-zero-tsnet-host",
                "rex-zero-tsnet-linux-arm64",
            ] {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }

    let mut candidates = vec![PathBuf::from(
        "/usr/share/APPLaunch/lib/rex-zero/rex-zero-tsnet",
    )];
    let target_bin = if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        ".build/tsnet/rex-zero-tsnet-linux-arm64"
    } else {
        ".build/tsnet/rex-zero-tsnet-host"
    };
    candidates.push(PathBuf::from(target_bin));
    candidates.push(PathBuf::from("../../").join(target_bin));
    candidates.push(PathBuf::from("../../../../").join(target_bin));

    candidates.into_iter().find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn make_temp_script(name: &str, body: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rex-tsnet-test-{}-{}", std::process::id(), name));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("helper.sh");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn auth_key_is_never_passed_in_argv_and_uses_env() {
        let out_file =
            std::env::temp_dir().join(format!("rex-tsnet-argv-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&out_file);
        let script = make_temp_script(
            "argv",
            &format!(
                "#!/bin/sh\nprintf 'ARGS=%s\\nENV=%s\\n' \"$*\" \"$TS_AUTHKEY\" > '{}'\nexit 0\n",
                out_file.display()
            ),
        );

        let sup = TsnetSupervisor::new(Arc::new(|_| {}));
        sup.set_enabled_with_bin(&script, Some("zero-node"), Some("tskey-secret-123"))
            .unwrap();
        thread::sleep(Duration::from_millis(120));
        sup.stop();

        let content = std::fs::read_to_string(&out_file).unwrap();
        assert!(
            !content.contains("--auth-key"),
            "argv must not contain --auth-key: {content}"
        );
        assert!(
            !content
                .lines()
                .next()
                .unwrap_or("")
                .contains("tskey-secret-123"),
            "argv line must not contain secret: {content}"
        );
        assert!(
            content.contains("ENV=tskey-secret-123"),
            "TS_AUTHKEY env must receive key: {content}"
        );
        let _ = std::fs::remove_file(&out_file);
        let _ = std::fs::remove_dir_all(script.parent().unwrap());
    }

    #[test]
    fn reaps_exited_child_and_spawns_replacement() {
        let count_file =
            std::env::temp_dir().join(format!("rex-tsnet-count-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&count_file);
        let script = make_temp_script(
            "reap",
            &format!("#!/bin/sh\necho x >> '{}'\nexit 0\n", count_file.display()),
        );

        let states: Arc<Mutex<Vec<String>>> = Arc::default();
        let st_clone = states.clone();
        let sup = TsnetSupervisor::new(Arc::new(move |u| {
            if let TailnetUpdate::State(s) = u {
                st_clone.lock().unwrap().push(s.backend_state);
            }
        }));

        sup.set_enabled_with_bin(&script, Some("zero"), None)
            .unwrap();
        thread::sleep(Duration::from_millis(150));

        // Child has already exited; enabling again without auth_key must reap & respawn!
        sup.set_enabled_with_bin(&script, Some("zero"), None)
            .unwrap();
        thread::sleep(Duration::from_millis(150));
        sup.stop();

        let lines = std::fs::read_to_string(&count_file).unwrap();
        assert_eq!(
            lines.lines().count(),
            2,
            "expected 2 launches, got:\n{lines}"
        );
        assert!(
            states.lock().unwrap().iter().any(|s| s == "Exited"),
            "expected Exited state to be published: {:?}",
            states.lock().unwrap()
        );
        let _ = std::fs::remove_file(&count_file);
        let _ = std::fs::remove_dir_all(script.parent().unwrap());
    }

    #[test]
    fn stop_is_unstoppable_even_when_stdin_pipe_is_full_and_child_ignores_stdin() {
        // Child sleeps forever and NEVER reads stdin.
        let script = make_temp_script("stall", "#!/bin/sh\nsleep 30\n");
        let sup = TsnetSupervisor::new(Arc::new(|_| {}));
        sup.set_enabled_with_bin(&script, Some("zero"), None)
            .unwrap();

        // Spam large ping payloads to fill kernel stdin pipe + bounded queue.
        let big_payload = "1".repeat(8192);
        let mut saw_full = false;
        for _ in 0..40 {
            match sup.ping(&big_payload) {
                Ok(()) => {}
                Err(e) if e.contains("已满") || e.contains("退出") => {
                    saw_full = true;
                    break;
                }
                Err(_) => break,
            }
        }
        // Whether kernel pipe filled or queue filled, send_cmd never blocked, and
        // stop() must kill & reap promptly (< 500ms).
        let _ = saw_full;
        let t0 = Instant::now();
        sup.stop();
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "stop() blocked for {:?}",
            t0.elapsed()
        );
        let _ = std::fs::remove_dir_all(script.parent().unwrap());
    }

    #[test]
    fn disable_holds_lifecycle_until_stopped_callback_returns() {
        let (entered, started) = mpsc::channel();
        let (release, paused) = mpsc::channel();
        let paused = Mutex::new(paused);
        let sup = TsnetSupervisor::new(Arc::new(move |_| {
            entered.send(()).unwrap();
            paused
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
        }));
        thread::scope(|scope| {
            scope.spawn(|| sup.set_enabled(false, None, None).unwrap());
            started.recv_timeout(Duration::from_secs(1)).unwrap();
            assert!(sup.lifecycle.try_lock().is_err());
            assert!(sup.shared.emit_gate.try_lock().is_err());
            release.send(()).unwrap();
        });
    }

    #[test]
    fn stop_waits_for_inflight_generation_callback() {
        let (entered, started) = mpsc::channel();
        let (release, paused) = mpsc::channel();
        let paused = Mutex::new(paused);
        let sup = Arc::new(TsnetSupervisor::new(Arc::new(move |_| {
            entered.send(()).unwrap();
            paused
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(2))
                .unwrap();
        })));
        sup.shared.state.lock().unwrap().enabled = true;
        thread::scope(|scope| {
            scope.spawn(|| {
                sup.shared
                    .emit_for_gen(0, TailnetUpdate::State(TailnetState::default()))
            });
            started.recv_timeout(Duration::from_secs(1)).unwrap();
            let (done, stopped) = mpsc::channel();
            let supervisor = sup.clone();
            scope.spawn(move || {
                supervisor.stop();
                done.send(()).unwrap();
            });
            assert!(stopped.recv_timeout(Duration::from_millis(50)).is_err());
            assert_eq!(sup.shared.state.lock().unwrap().generation, 0);
            release.send(()).unwrap();
            stopped.recv_timeout(Duration::from_secs(1)).unwrap();
        });
        assert!(!sup
            .shared
            .emit_for_gen(0, TailnetUpdate::State(TailnetState::default())));
    }

    #[test]
    fn retired_reader_generation_discards_buffered_state_and_eof_after_disable() {
        use std::os::fd::FromRawFd;

        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_file = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let mut write_file = unsafe { std::fs::File::from_raw_fd(fds[1]) };

        let states: Arc<Mutex<Vec<TailnetState>>> = Arc::default();
        let st_clone = states.clone();
        let sup = TsnetSupervisor::new(Arc::new(move |u| {
            if let TailnetUpdate::State(s) = u {
                st_clone.lock().unwrap().push(s);
            }
        }));

        let my_gen = {
            let mut st = sup.shared.state.lock().unwrap();
            st.generation = 1;
            st.enabled = true;
            st.generation
        };
        let stopped = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let shared = sup.shared.clone();
        let stopped_r = stopped.clone();
        let reader_handle = thread::spawn(move || {
            read_tsnet_stdout(
                BufReader::new(read_file),
                pending,
                stopped_r,
                shared,
                my_gen,
            );
        });

        writeln!(
            write_file,
            r#"{{"type":"state","backendState":"Running","proxyPort":41111}}"#
        )
        .unwrap();
        write_file.flush().unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if states.lock().unwrap().iter().any(|s| s.proxy_port == 41111) {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(states.lock().unwrap().iter().any(|s| s.proxy_port == 41111));

        // Disable via set_enabled(false) -> increments generation, disables, emits Stopped default.
        sup.set_enabled(false, None, None).unwrap();
        let disabled_idx = states.lock().unwrap().len();

        // Simulate buffered stdout lines & EOF arriving late from the retired generation
        // even with `stopped == false`!
        writeln!(
            write_file,
            r#"{{"type":"state","backendState":"Running","proxyPort":41111}}"#
        )
        .unwrap();
        writeln!(write_file, r#"{{"type":"ready","proxyPort":51111}}"#).unwrap();
        write_file.flush().unwrap();
        drop(write_file);

        reader_handle.join().unwrap();

        let captured = states.lock().unwrap();
        assert_eq!(
            captured.len(),
            disabled_idx,
            "retired reader published after disable: {:?}",
            &captured[disabled_idx..]
        );
        let last = captured.last().unwrap();
        assert!(!last.enabled);
        assert_eq!(last.backend_state, "Stopped");
    }

    #[test]
    fn retired_reader_generation_discards_stale_port_and_exit_after_respawn() {
        use std::os::fd::FromRawFd;

        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_file = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let mut write_file = unsafe { std::fs::File::from_raw_fd(fds[1]) };

        let updates: Arc<Mutex<Vec<(Option<TailnetState>, Option<String>)>>> = Arc::default();
        let up_clone = updates.clone();
        let sup = TsnetSupervisor::new(Arc::new(move |u| match u {
            TailnetUpdate::State(s) => up_clone.lock().unwrap().push((Some(s), None)),
            TailnetUpdate::PingResult { peer_ip, .. } => {
                up_clone.lock().unwrap().push((None, Some(peer_ip)))
            }
            TailnetUpdate::ProbeResult { .. } => {}
        }));

        let gen1 = {
            let mut st = sup.shared.state.lock().unwrap();
            st.generation = 1;
            st.enabled = true;
            1
        };
        let stopped = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(Mutex::new(HashMap::new()));
        pending.lock().unwrap().insert(
            99,
            PendingCmd::Ping {
                peer_ip: "100.64.0.9".into(),
            },
        );
        let shared = sup.shared.clone();
        let reader_handle = thread::spawn(move || {
            read_tsnet_stdout(BufReader::new(read_file), pending, stopped, shared, gen1);
        });

        // Respawn advances generation to 2.
        {
            let mut st = sup.shared.state.lock().unwrap();
            st.generation = 2;
            st.enabled = true;
        }

        // Retired gen 1 emits ready(11111), state(Running), reply(ping), and EOF Exited.
        writeln!(write_file, r#"{{"type":"ready","proxyPort":11111}}"#).unwrap();
        writeln!(
            write_file,
            r#"{{"type":"state","backendState":"Running","proxyPort":11111}}"#
        )
        .unwrap();
        writeln!(
            write_file,
            r#"{{"type":"reply","id":99,"ok":true,"latencyMs":5}}"#
        )
        .unwrap();
        write_file.flush().unwrap();
        drop(write_file);

        reader_handle.join().unwrap();

        assert!(
            updates.lock().unwrap().is_empty(),
            "retired generation must not emit any update after respawn: {:?}",
            updates.lock().unwrap()
        );
    }

    #[test]
    fn rex_peers_sorted_first_and_companion_os_peers_inherit_rex_endpoint() {
        let states = Arc::new(Mutex::new(Vec::<TailnetState>::new()));
        let states_clone = states.clone();
        let sup = TsnetSupervisor::new(Arc::new(move |u| {
            if let TailnetUpdate::State(s) = u {
                states_clone.lock().unwrap().push(s);
            }
        }));
        {
            let mut st = sup.shared.state.lock().unwrap();
            st.generation = 1;
            st.enabled = true;
        }
        let line = concat!(
            r#"{"type":"state","backendState":"Running","proxyPort":10808,"peers":["#,
            r#"{"hostName":"labnas","dnsName":"labnas.example-tailnet.ts.net.","online":true},"#,
            r#"{"hostName":"Alice的Mac Mini","dnsName":"alicemac-mini.example-tailnet.ts.net.","online":true},"#,
            r#"{"hostName":"alice-mac-mini-rex","dnsName":"alice-mac-mini-rex.example-tailnet.ts.net.","online":true},"#,
            r#"{"hostName":"lab-nas-rex","dnsName":"lab-nas-rex.example-tailnet.ts.net.","online":true}"#,
            "]}\n"
        );
        read_tsnet_stdout(
            std::io::Cursor::new(line.as_bytes()),
            Arc::default(),
            Arc::new(AtomicBool::new(false)),
            sup.shared.clone(),
            1,
        );

        let guard = states.lock().unwrap();
        let state = &guard[0];
        assert_eq!(state.peers[0].host_name, "alice-mac-mini-rex");
        assert_eq!(
            state.peers[0].rex_endpoint.as_deref(),
            Some("https://alice-mac-mini-rex.example-tailnet.ts.net")
        );
        assert_eq!(state.peers[1].host_name, "lab-nas-rex");
        assert_eq!(state.peers[2].host_name, "Alice的Mac Mini");
        assert_eq!(
            state.peers[2].rex_endpoint.as_deref(),
            Some("https://alice-mac-mini-rex.example-tailnet.ts.net")
        );
        // `labnas` must NOT inherit `lab-nas-rex`!
        assert_eq!(state.peers[3].host_name, "labnas");
        assert_eq!(state.peers[3].rex_endpoint, None);
    }
}
