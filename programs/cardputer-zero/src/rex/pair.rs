//! 5-Minute Ephemeral Web Pairing Server (`pair_toggle` / `pair_confirm`).
//! Binds a temporary `TcpListener` strictly on an authenticated interface
//! (detected Tailscale WireGuard `100.64.0.0/10` CGNAT IP, or `127.0.0.1:0`
//! loopback for SSH `-L` port forwarding) for 300s, advertises the pairing URL
//! with a 256-bit random session key in the `#k=` URL fragment (never sent over
//! HTTP per RFC 3986), serves a self-contained dark HTML form with pure-JS
//! SHA-256 + HMAC-SHA256-CTR authenticated encryption, and stages decrypted SSH
//! keys, Rex hosts, and Cloud ASR credentials in memory until the user
//! explicitly confirms on the physical CardputerZero keyboard.

use crate::rex::{
    qr,
    transport::{derive_label_from_endpoint, normalize_endpoint, slug_id, ConfiguredHost},
    types::{PairState, PendingPairImport},
};
use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine};
use serde::Deserialize;
use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    io::{ErrorKind, Read, Write},
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const PAIR_TTL: Duration = Duration::from_secs(300);
const CLIENT_IO_DEADLINE: Duration = Duration::from_secs(4);
const POLL_SLICE_MS: i32 = 100;
const MAX_HEADER_BYTES: usize = 8 * 1024;
const MAX_HEADER_LINES: usize = 64;
const MAX_POST_BYTES: usize = 64 * 1024;
const MAX_AUTH_FAILURES: u32 = 5;
const MAX_SEEN_NONCES: usize = 64;

#[derive(Clone, Debug)]
pub struct StagedImport {
    pub hosts: Vec<ConfiguredHost>,
    pub ssh_private_key: Option<String>,
    pub asr_provider: Option<String>,
    pub asr_api_key: Option<String>,
    pub asr_app_id: Option<String>,
    pub asr_endpoint: Option<String>,
    pub summary: String,
    pub from_ip: String,
}

pub type PairCallback = Arc<dyn Fn() + Send + Sync>;

struct ActiveSession {
    session_id: u64,
    url: String,
    pin: String,
    qr_matrix: Option<Vec<Vec<bool>>>,
    expires_at: Instant,
    stop: Arc<AtomicBool>,
    failed_attempts: u32,
    seen_nonces: HashSet<[u8; 16]>,
    staged: Option<(String, StagedImport)>,
}

struct PairInner {
    session: Option<ActiveSession>,
    displayed_token: Option<(u64, String)>,
}

pub struct PairManager {
    inner: Mutex<PairInner>,
    next_session_id: AtomicU64,
    mock: bool,
    callback: PairCallback,
}

impl PairManager {
    pub fn new(mock: bool, callback: PairCallback) -> Self {
        let initial = if mock {
            let mock_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let url = format!("http://100.100.2.250:48291/#k={mock_key}");
            Some(ActiveSession {
                session_id: 1,
                qr_matrix: qr::encode_matrix(&url),
                url,
                pin: "604921".into(),
                expires_at: Instant::now() + PAIR_TTL,
                stop: Arc::new(AtomicBool::new(false)),
                failed_attempts: 0,
                seen_nonces: HashSet::new(),
                staged: None,
            })
        } else {
            None
        };
        Self {
            inner: Mutex::new(PairInner {
                session: initial,
                displayed_token: None,
            }),
            next_session_id: AtomicU64::new(if mock { 2 } else { 1 }),
            mock,
            callback,
        }
    }

    pub fn snapshot(&self) -> PairState {
        self.snapshot_with_seq().1
    }

    #[allow(dead_code)]
    pub fn snapshot_with_seq(&self) -> (u64, PairState) {
        let mut guard = self.inner.lock().unwrap();
        let mut next_displayed: Option<(u64, String)> = None;
        let out = if let Some(sess) = guard.session.as_ref() {
            let now = Instant::now();
            if !self.mock && (sess.stop.load(Ordering::Acquire) || now >= sess.expires_at) {
                sess.stop.store(true, Ordering::SeqCst);
                guard.session = None;
                guard.displayed_token = None;
                return (0, PairState::default());
            }
            let expires_in_sec = if self.mock {
                295
            } else {
                sess.expires_at.saturating_duration_since(now).as_secs() as u32
            };
            let seq = sess.session_id;
            let pending_import = sess.staged.as_ref().map(|(nonce, st)| {
                next_displayed = Some((seq, nonce.clone()));
                PendingPairImport {
                    token: format!("{seq}:{nonce}"),
                    summary: st.summary.clone(),
                    from_ip: st.from_ip.clone(),
                }
            });
            (
                seq,
                PairState {
                    active: true,
                    url: sess.url.clone(),
                    pin: sess.pin.clone(),
                    expires_in_sec,
                    qr_matrix: sess.qr_matrix.clone(),
                    pending_import,
                },
            )
        } else {
            (0, PairState::default())
        };
        guard.displayed_token = next_displayed;
        out
    }

    pub fn toggle(
        self: &Arc<Self>,
        active: bool,
        preferred_ip: Option<&str>,
    ) -> Result<(), String> {
        if !active {
            {
                let mut guard = self.inner.lock().unwrap();
                if let Some(old) = guard.session.take() {
                    old.stop.store(true, Ordering::SeqCst);
                }
                guard.displayed_token = None;
            }
            (self.callback)();
            return Ok(());
        }

        if self.mock {
            let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
            let mock_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
            let url = format!("http://100.100.2.250:48291/#k={mock_key}");
            {
                let mut guard = self.inner.lock().unwrap();
                guard.session = Some(ActiveSession {
                    session_id,
                    qr_matrix: qr::encode_matrix(&url),
                    url,
                    pin: "604921".into(),
                    expires_at: Instant::now() + PAIR_TTL,
                    stop: Arc::new(AtomicBool::new(false)),
                    failed_attempts: 0,
                    seen_nonces: HashSet::new(),
                    staged: None,
                });
                guard.displayed_token = None;
            }
            (self.callback)();
            return Ok(());
        }

        // Generate CSPRNG entropy BEFORE stopping previous session or advertising anything.
        let pin = generate_pin_6()?;
        let session_key = generate_session_key()?;
        let key_hex = hex_encode(&session_key);

        let (listener, bind_ip) = bind_authenticated_listener(preferred_ip)?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("set_nonblocking: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("local_addr: {e}"))?
            .port();
        let is_tailscale = matches!(bind_ip, IpAddr::V4(v4) if is_tailscale_cgnat_v4(v4));
        let ip = bind_ip.to_string();
        let authority = format_authority(&ip, port);
        let url = format!("http://{authority}/#k={key_hex}");
        let qr_matrix = qr::encode_matrix(&url);
        let stop = Arc::new(AtomicBool::new(false));
        let expires_at = Instant::now() + PAIR_TTL;
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);

        // Stop any previous listener and install the new session atomically.
        {
            let mut guard = self.inner.lock().unwrap();
            if let Some(old) = guard.session.take() {
                old.stop.store(true, Ordering::SeqCst);
            }
            guard.displayed_token = None;
            guard.session = Some(ActiveSession {
                session_id,
                url,
                pin: pin.clone(),
                qr_matrix,
                expires_at,
                stop: stop.clone(),
                failed_attempts: 0,
                seen_nonces: HashSet::new(),
                staged: None,
            });
        }

        let mgr = self.clone();
        let spawn_res = thread::Builder::new()
            .name("rex-zero-pair".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                run_pair_listener(
                    listener,
                    session_id,
                    authority,
                    port,
                    is_tailscale,
                    pin,
                    session_key,
                    expires_at,
                    stop,
                    mgr,
                )
            });

        if let Err(e) = spawn_res {
            let mut guard = self.inner.lock().unwrap();
            if guard
                .session
                .as_ref()
                .is_some_and(|s| s.session_id == session_id)
            {
                if let Some(sess) = guard.session.take() {
                    sess.stop.store(true, Ordering::SeqCst);
                }
                guard.displayed_token = None;
            }
            drop(guard);
            (self.callback)();
            return Err(format!("spawn pair server: {e}"));
        }

        (self.callback)();
        Ok(())
    }

    pub fn take_confirmed_import_matching(
        &self,
        approve: bool,
        expected_token: Option<&str>,
    ) -> Result<Option<StagedImport>, &'static str> {
        let mut guard = self.inner.lock().unwrap();
        let (expired, stopped, expected_displayed) = {
            let sess = guard.session.as_ref().ok_or("no pairing session")?;
            let expired = !self.mock && Instant::now() >= sess.expires_at;
            let stopped = sess.stop.load(Ordering::Acquire);
            let expected_displayed = sess
                .staged
                .as_ref()
                .map(|(nonce, _)| (sess.session_id, nonce.clone()));
            (expired, stopped, expected_displayed)
        };
        if expired || stopped {
            if let Some(sess) = guard.session.take() {
                sess.stop.store(true, Ordering::SeqCst);
            }
            guard.displayed_token = None;
            drop(guard);
            (self.callback)();
            return Err("stale or missing pairing token");
        }
        let expected_displayed = expected_displayed.ok_or("no pending import")?;
        if guard.displayed_token.as_ref() != Some(&expected_displayed) {
            return Err("stale or missing pairing token");
        }
        if expected_token
            != Some(format!("{}:{}", expected_displayed.0, expected_displayed.1).as_str())
        {
            return Err("stale or missing pairing token");
        }
        let (_, staged) = guard.session.as_mut().unwrap().staged.take().unwrap();
        guard.displayed_token = None;
        if approve {
            if let Some(sess) = guard.session.take() {
                sess.stop.store(true, Ordering::SeqCst);
            }
            return Ok(Some(staged));
        }
        Ok(None)
    }

    /// Checks whether `nonce` was already used for `session_id` and stages the
    /// decrypted import ONLY if the originating session is still active, not
    /// stopped, not expired, and has no other pending import awaiting confirmation.
    fn stage_import(&self, session_id: u64, nonce: [u8; 16], staged: StagedImport) -> StageOutcome {
        let mut guard = self.inner.lock().unwrap();
        let Some(sess) = guard.session.as_mut() else {
            return StageOutcome::SessionGone;
        };
        if sess.session_id != session_id {
            return StageOutcome::SessionGone;
        }
        if sess.stop.load(Ordering::Acquire) || (!self.mock && Instant::now() >= sess.expires_at) {
            sess.stop.store(true, Ordering::SeqCst);
            guard.session = None;
            guard.displayed_token = None;
            drop(guard);
            (self.callback)();
            return StageOutcome::SessionGone;
        }
        if sess.seen_nonces.contains(&nonce) {
            return StageOutcome::NonceReplayed;
        }
        if sess.staged.is_some() {
            return StageOutcome::PendingConflict;
        }
        if sess.seen_nonces.len() >= MAX_SEEN_NONCES {
            return StageOutcome::SessionGone;
        }
        sess.seen_nonces.insert(nonce);
        sess.staged = Some((hex_encode(&nonce), staged));
        drop(guard);
        (self.callback)();
        StageOutcome::Staged
    }

    /// Records a failed PIN/MAC verification for `session_id`. On the 5th
    /// failure, invalidates and terminates the pairing session immediately.
    fn record_auth_failure(&self, session_id: u64) -> AuthFailureOutcome {
        let mut guard = self.inner.lock().unwrap();
        let Some(sess) = guard.session.as_mut() else {
            return AuthFailureOutcome::SessionGone;
        };
        if sess.session_id != session_id {
            return AuthFailureOutcome::SessionGone;
        }
        if sess.stop.load(Ordering::Acquire) || (!self.mock && Instant::now() >= sess.expires_at) {
            sess.stop.store(true, Ordering::SeqCst);
            guard.session = None;
            guard.displayed_token = None;
            drop(guard);
            (self.callback)();
            return AuthFailureOutcome::SessionGone;
        }
        sess.failed_attempts = sess.failed_attempts.saturating_add(1);
        if sess.failed_attempts >= MAX_AUTH_FAILURES {
            sess.stop.store(true, Ordering::SeqCst);
            guard.session = None;
            guard.displayed_token = None;
            drop(guard);
            (self.callback)();
            return AuthFailureOutcome::LockedOut;
        }
        AuthFailureOutcome::Remaining(MAX_AUTH_FAILURES - sess.failed_attempts)
    }
}

impl Drop for PairManager {
    fn drop(&mut self) {
        let mut guard = self.inner.lock().unwrap();
        if let Some(sess) = guard.session.take() {
            sess.stop.store(true, Ordering::SeqCst);
        }
        guard.displayed_token = None;
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StageOutcome {
    Staged,
    PendingConflict,
    NonceReplayed,
    SessionGone,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AuthFailureOutcome {
    Remaining(u32),
    LockedOut,
    SessionGone,
}

#[allow(clippy::too_many_arguments)]
fn run_pair_listener(
    listener: TcpListener,
    session_id: u64,
    expected_authority: String,
    port: u16,
    is_tailscale: bool,
    expected_pin: String,
    session_key: [u8; 32],
    expires_at: Instant,
    stop: Arc<AtomicBool>,
    mgr: Arc<PairManager>,
) {
    let fd = listener.as_raw_fd();
    while !stop.load(Ordering::Acquire) && Instant::now() < expires_at {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                let peer_ip = peer_addr.ip();
                if !is_authenticated_pair_ip(peer_ip) {
                    drop(stream);
                    continue;
                }
                let _ = handle_pair_client(
                    stream,
                    peer_ip.to_string(),
                    session_id,
                    &expected_authority,
                    port,
                    is_tailscale,
                    &expected_pin,
                    &session_key,
                    expires_at,
                    &stop,
                    &mgr,
                );
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                let rem_ms = expires_at
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .min(POLL_SLICE_MS as u128) as i32;
                if rem_ms <= 0 {
                    break;
                }
                let mut pfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let _ = unsafe { libc::poll(&mut pfd, 1, rem_ms) };
            }
            Err(_) => break,
        }
    }
    let mut guard = mgr.inner.lock().unwrap();
    if guard
        .session
        .as_ref()
        .is_some_and(|s| s.session_id == session_id)
    {
        if let Some(sess) = guard.session.take() {
            sess.stop.store(true, Ordering::SeqCst);
        }
        guard.displayed_token = None;
        drop(guard);
        (mgr.callback)();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedEnvelope {
    v: u8,
    nonce: String,
    ct: String,
    tag: String,
}

#[derive(Deserialize, Default)]
struct DecryptedPairPayload {
    #[serde(default)]
    hosts: String,
    #[serde(default, alias = "sshKey")]
    ssh_key: String,
    #[serde(default, alias = "asrProvider")]
    asr_provider: String,
    #[serde(default, alias = "asrKey", alias = "asrApiKey", alias = "asr_api_key")]
    asr_key: String,
    #[serde(default, alias = "asrAppId")]
    asr_app_id: String,
    #[serde(default, alias = "asrEndpoint")]
    asr_endpoint: String,
}

struct ParsedRequestHead {
    method: String,
    target: String,
    host: Option<String>,
    origin: Option<String>,
    sec_fetch_site: Option<String>,
    content_len: usize,
    has_transfer_encoding: bool,
}

#[allow(clippy::too_many_arguments)]
fn handle_pair_client(
    mut stream: TcpStream,
    from_ip: String,
    session_id: u64,
    expected_authority: &str,
    port: u16,
    is_tailscale: bool,
    expected_pin: &str,
    session_key: &[u8; 32],
    expires_at: Instant,
    stop: &AtomicBool,
    mgr: &PairManager,
) -> std::io::Result<()> {
    stream.set_nonblocking(true)?;
    let now = Instant::now();
    if stop.load(Ordering::Acquire) || now >= expires_at {
        return Ok(());
    }
    let deadline = (now + CLIENT_IO_DEADLINE).min(expires_at);

    let (head_bytes, leftover) = match read_header_block(&mut stream, deadline, stop) {
        Ok(Some(v)) => v,
        Ok(None) => return Ok(()),
        Err(HeaderReadErr::TooLarge) => {
            return send_text(
                &mut stream,
                431,
                "text/plain; charset=utf-8",
                "431 Request Header Fields Too Large",
                deadline,
                stop,
            );
        }
        Err(HeaderReadErr::Io(e)) => return Err(e),
    };

    let req = match parse_request_head(&head_bytes) {
        Ok(r) => r,
        Err(HeaderParseErr::TooManyHeaders) => {
            return send_text(
                &mut stream,
                431,
                "text/plain; charset=utf-8",
                "431 Request Header Fields Too Large",
                deadline,
                stop,
            );
        }
        Err(HeaderParseErr::BadRequest(msg)) => {
            return send_text(
                &mut stream,
                400,
                "text/plain; charset=utf-8",
                msg,
                deadline,
                stop,
            );
        }
    };

    // Validate Host authority (blocks DNS rebinding) and Origin (blocks cross-origin forms/XHR).
    if !validate_host_and_origin(&req, expected_authority) {
        return send_json(
            &mut stream,
            403,
            r#"{"ok":false,"error":"Host 或 Origin 校验失败，请直接访问掌机显示的配对地址"}"#,
            deadline,
            stop,
        );
    }

    let path = req
        .target
        .split_once('?')
        .map(|(p, _)| p)
        .unwrap_or(&req.target);

    if req.method == "GET" && (path == "/" || path == "/index.html") {
        return send_text(
            &mut stream,
            200,
            "text/html; charset=utf-8",
            &render_pair_form(port, is_tailscale),
            deadline,
            stop,
        );
    }

    if req.method == "POST" && (path == "/pair" || path == "/submit") {
        if req.has_transfer_encoding {
            return send_json(
                &mut stream,
                400,
                r#"{"ok":false,"error":"不支持 chunked 传输编码，请使用固定 Content-Length"}"#,
                deadline,
                stop,
            );
        }
        if req.content_len > MAX_POST_BYTES {
            return send_json(
                &mut stream,
                413,
                r#"{"ok":false,"error":"413 Payload Too Large"}"#,
                deadline,
                stop,
            );
        }

        let body = read_exact_body(&mut stream, leftover, req.content_len, deadline, stop)?;

        // Reject plaintext secret-bearing requests immediately before decrypting.
        let raw_json: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => {
                return send_json(
                    &mut stream,
                    400,
                    r#"{"ok":false,"error":"必须通过加密 JSON 信封提交配置，已拒绝明文请求"}"#,
                    deadline,
                    stop,
                );
            }
        };

        if has_plaintext_secret_fields(&raw_json) {
            return send_json(
                &mut stream,
                400,
                r#"{"ok":false,"error":"已拒绝明文凭据提交，请通过扫码页面加密提交"}"#,
                deadline,
                stop,
            );
        }

        let env: EncryptedEnvelope = match serde_json::from_value::<EncryptedEnvelope>(raw_json) {
            Ok(e) if e.v == 1 => e,
            _ => {
                return send_json(
                    &mut stream,
                    400,
                    r#"{"ok":false,"error":"加密信封格式无效（需要 v=1, nonce, ct, tag）"}"#,
                    deadline,
                    stop,
                );
            }
        };

        let Some(nonce) = decode_hex_fixed::<16>(&env.nonce) else {
            return send_json(
                &mut stream,
                400,
                r#"{"ok":false,"error":"nonce 格式无效"}"#,
                deadline,
                stop,
            );
        };
        let Some(tag) = decode_hex_fixed::<32>(&env.tag) else {
            return send_json(
                &mut stream,
                400,
                r#"{"ok":false,"error":"tag 格式无效"}"#,
                deadline,
                stop,
            );
        };
        let Ok(ciphertext) = BASE64_STD.decode(env.ct.as_bytes()) else {
            return send_json(
                &mut stream,
                400,
                r#"{"ok":false,"error":"密文 base64 格式无效"}"#,
                deadline,
                stop,
            );
        };
        if ciphertext.is_empty() || ciphertext.len() > MAX_POST_BYTES {
            return send_json(
                &mut stream,
                400,
                r#"{"ok":false,"error":"密文长度无效"}"#,
                deadline,
                stop,
            );
        }

        let Some(plaintext) =
            decrypt_envelope(session_key, expected_pin, &nonce, &ciphertext, &tag)
        else {
            return match mgr.record_auth_failure(session_id) {
                AuthFailureOutcome::LockedOut => {
                    // `record_auth_failure` just set `stop = true` to terminate the
                    // session; still deliver the final 403 response to this client
                    // under a short bounded deadline before the listener exits.
                    let no_stop = AtomicBool::new(false);
                    let reply_deadline = deadline.min(Instant::now() + Duration::from_millis(500));
                    send_json(
                        &mut stream,
                        403,
                        r#"{"ok":false,"error":"PIN 或配对密钥多次校验失败，本次配对已自动失效，请在掌机重新开启"}"#,
                        reply_deadline,
                        &no_stop,
                    )
                }
                AuthFailureOutcome::SessionGone => send_json(
                    &mut stream,
                    410,
                    r#"{"ok":false,"error":"配对会话已结束或过期，请在掌机重新开启"}"#,
                    deadline,
                    stop,
                ),
                AuthFailureOutcome::Remaining(left) => {
                    let msg = format!(
                        r#"{{"ok":false,"error":"PIN 或配对密钥校验失败（剩余尝试次数：{left}）"}}"#
                    );
                    send_json(&mut stream, 403, &msg, deadline, stop)
                }
            };
        };

        let payload: DecryptedPairPayload = match serde_json::from_slice(&plaintext) {
            Ok(p) => p,
            Err(_) => {
                return send_json(
                    &mut stream,
                    400,
                    r#"{"ok":false,"error":"解密后的配置 JSON 无效"}"#,
                    deadline,
                    stop,
                );
            }
        };

        let hosts_raw = payload.hosts.trim();
        let ssh_key = Some(payload.ssh_key.trim().to_string()).filter(|s| !s.is_empty());
        let asr_provider = Some(payload.asr_provider.trim().to_string()).filter(|s| !s.is_empty());
        let asr_api_key = Some(payload.asr_key.trim().to_string()).filter(|s| !s.is_empty());
        let asr_app_id = Some(payload.asr_app_id.trim().to_string()).filter(|s| !s.is_empty());
        let asr_endpoint = Some(payload.asr_endpoint.trim().to_string()).filter(|s| !s.is_empty());

        let mut hosts = Vec::new();
        for (idx, line) in hosts_raw.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (label, ep) = if let Some((l, r)) = line.split_once('=') {
                (l.trim().to_string(), normalize_endpoint(r))
            } else {
                let norm = normalize_endpoint(line);
                (derive_label_from_endpoint(&norm), norm)
            };
            hosts.push(ConfiguredHost {
                id: slug_id(&label, idx),
                label,
                endpoint: ep,
                ssh_key_path: None,
            });
        }

        let mut parts_desc = Vec::new();
        if !hosts.is_empty() {
            parts_desc.push(format!("{}台主机", hosts.len()));
        }
        if ssh_key.is_some() {
            parts_desc.push("SSH密钥".into());
        }
        if asr_api_key.is_some() {
            parts_desc.push(format!(
                "语音({})",
                asr_provider.as_deref().unwrap_or("openai")
            ));
        }

        if parts_desc.is_empty() {
            return send_json(
                &mut stream,
                400,
                r#"{"ok":false,"error":"未填写任何配置项"}"#,
                deadline,
                stop,
            );
        }

        let staged = StagedImport {
            hosts,
            ssh_private_key: ssh_key,
            asr_provider,
            asr_api_key,
            asr_app_id,
            asr_endpoint,
            summary: parts_desc.join(" + "),
            from_ip,
        };

        return match mgr.stage_import(session_id, nonce, staged) {
            StageOutcome::Staged => send_json(
                &mut stream,
                200,
                r#"{"ok":true,"message":"已加密投递至 CardputerZero，请在掌机物理键盘上按 Enter 确认落盘导入。"}"#,
                deadline,
                stop,
            ),
            StageOutcome::PendingConflict => send_json(
                &mut stream,
                409,
                r#"{"ok":false,"error":"pending import awaiting device confirmation"}"#,
                deadline,
                stop,
            ),
            StageOutcome::NonceReplayed => send_json(
                &mut stream,
                403,
                r#"{"ok":false,"error":"检测到重复提交的加密随机数，请刷新后重试"}"#,
                deadline,
                stop,
            ),
            StageOutcome::SessionGone => send_json(
                &mut stream,
                410,
                r#"{"ok":false,"error":"配对会话已结束或已刷新，请重新扫描掌机二维码"}"#,
                deadline,
                stop,
            ),
        };
    }

    if req.method == "GET" {
        return send_text(
            &mut stream,
            404,
            "text/plain; charset=utf-8",
            "Not Found",
            deadline,
            stop,
        );
    }

    send_text(
        &mut stream,
        405,
        "text/plain; charset=utf-8",
        "Method Not Allowed",
        deadline,
        stop,
    )
}

enum HeaderReadErr {
    TooLarge,
    Io(std::io::Error),
}

enum HeaderParseErr {
    TooManyHeaders,
    BadRequest(&'static str),
}

fn poll_stream(
    stream: &TcpStream,
    events: i16,
    deadline: Instant,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    let fd = stream.as_raw_fd();
    loop {
        if stop.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                ErrorKind::Interrupted,
                "pair server stopped",
            ));
        }
        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "pair client deadline exceeded",
            ));
        };
        if rem.is_zero() {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "pair client deadline exceeded",
            ));
        }
        let slice_ms = rem.as_millis().min(POLL_SLICE_MS as u128).max(1) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, slice_ms) };
        if rc > 0 {
            if (pfd.revents & libc::POLLNVAL) != 0 {
                return Err(std::io::Error::new(ErrorKind::BrokenPipe, "invalid fd"));
            }
            return Ok(());
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }
}

fn read_chunk_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    deadline: Instant,
    stop: &AtomicBool,
) -> std::io::Result<usize> {
    loop {
        if stop.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                ErrorKind::Interrupted,
                "pair server stopped",
            ));
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "pair read deadline exceeded",
            ));
        }
        match stream.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                poll_stream(stream, libc::POLLIN, deadline, stop)?;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

fn write_all_deadline(
    stream: &mut TcpStream,
    mut data: &[u8],
    deadline: Instant,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    while !data.is_empty() {
        if stop.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                ErrorKind::Interrupted,
                "pair server stopped",
            ));
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "pair write deadline exceeded",
            ));
        }
        match stream.write(data) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "short write on pair socket",
                ))
            }
            Ok(n) => data = &data[n..],
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                poll_stream(stream, libc::POLLOUT, deadline, stop)?;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Reads the HTTP request line and headers up to `\r\n\r\n` (or `\n\n`),
/// strictly capped at `MAX_HEADER_BYTES` BEFORE allocating beyond the cap.
fn read_header_block(
    stream: &mut TcpStream,
    deadline: Instant,
    stop: &AtomicBool,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, HeaderReadErr> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];

    loop {
        if let Some((end, sep_len)) = find_header_end(&buf) {
            let leftover = buf[end + sep_len..].to_vec();
            buf.truncate(end);
            return Ok(Some((buf, leftover)));
        }
        if buf.len() >= MAX_HEADER_BYTES {
            return Err(HeaderReadErr::TooLarge);
        }
        let max_read = (MAX_HEADER_BYTES - buf.len()).min(tmp.len());
        let n = read_chunk_deadline(stream, &mut tmp[..max_read], deadline, stop)
            .map_err(HeaderReadErr::Io)?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            return Err(HeaderReadErr::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "truncated HTTP header",
            )));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn find_header_end(buf: &[u8]) -> Option<(usize, usize)> {
    for i in 0..buf.len() {
        if i + 4 <= buf.len() && &buf[i..i + 4] == b"\r\n\r\n" {
            return Some((i, 4));
        }
        if i + 2 <= buf.len() && &buf[i..i + 2] == b"\n\n" {
            return Some((i, 2));
        }
    }
    None
}

fn parse_request_head(head_bytes: &[u8]) -> Result<ParsedRequestHead, HeaderParseErr> {
    let text =
        std::str::from_utf8(head_bytes).map_err(|_| HeaderParseErr::BadRequest("bad utf8"))?;
    let mut lines = text.split('\n');
    let req_line = lines
        .next()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.is_empty())
        .ok_or(HeaderParseErr::BadRequest("empty request line"))?;

    let mut parts = req_line.split_whitespace();
    let method = parts
        .next()
        .ok_or(HeaderParseErr::BadRequest("missing method"))?
        .to_string();
    let target = parts
        .next()
        .ok_or(HeaderParseErr::BadRequest("missing target"))?
        .to_string();

    let mut host: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut sec_fetch_site: Option<String> = None;
    let mut content_len: Option<usize> = None;
    let mut has_transfer_encoding = false;
    let mut header_count = 0usize;

    for raw_line in lines {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        header_count += 1;
        if header_count > MAX_HEADER_LINES {
            return Err(HeaderParseErr::TooManyHeaders);
        }
        let Some((k, v)) = line.split_once(':') else {
            return Err(HeaderParseErr::BadRequest("malformed header"));
        };
        let k = k.trim();
        let v = v.trim();
        if k.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err(HeaderParseErr::BadRequest("duplicate host header"));
            }
            host = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("origin") {
            origin = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("sec-fetch-site") {
            sec_fetch_site = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("transfer-encoding") {
            has_transfer_encoding = true;
        } else if k.eq_ignore_ascii_case("content-length") {
            let parsed = v
                .parse::<usize>()
                .map_err(|_| HeaderParseErr::BadRequest("invalid content-length"))?;
            if let Some(prev) = content_len {
                if prev != parsed {
                    return Err(HeaderParseErr::BadRequest("conflicting content-length"));
                }
            }
            content_len = Some(parsed);
        }
    }

    Ok(ParsedRequestHead {
        method,
        target,
        host,
        origin,
        sec_fetch_site,
        content_len: content_len.unwrap_or(0),
        has_transfer_encoding,
    })
}

fn read_exact_body(
    stream: &mut TcpStream,
    leftover: Vec<u8>,
    content_len: usize,
    deadline: Instant,
    stop: &AtomicBool,
) -> std::io::Result<Vec<u8>> {
    let mut body = Vec::with_capacity(content_len.min(MAX_POST_BYTES));
    let take = leftover.len().min(content_len);
    body.extend_from_slice(&leftover[..take]);
    let mut chunk = [0u8; 4096];
    while body.len() < content_len {
        let want = (content_len - body.len()).min(chunk.len());
        let n = read_chunk_deadline(stream, &mut chunk[..want], deadline, stop)?;
        if n == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "truncated HTTP body",
            ));
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Ok(body)
}

fn validate_host_and_origin(req: &ParsedRequestHead, expected_authority: &str) -> bool {
    let Some(host) = req.host.as_deref() else {
        return false;
    };
    if !host.eq_ignore_ascii_case(expected_authority) {
        return false;
    }
    if let Some(origin) = req.origin.as_deref() {
        let expected_origin = format!("http://{expected_authority}");
        if !origin.eq_ignore_ascii_case(&expected_origin) {
            return false;
        }
    }
    if let Some(site) = req.sec_fetch_site.as_deref() {
        if site.eq_ignore_ascii_case("cross-site") {
            return false;
        }
    }
    true
}

fn has_plaintext_secret_fields(val: &serde_json::Value) -> bool {
    let Some(obj) = val.as_object() else {
        return true;
    };
    for key in [
        "pin",
        "hosts",
        "sshKey",
        "ssh_key",
        "asrKey",
        "asr_key",
        "asrApiKey",
        "asr_api_key",
    ] {
        if obj.contains_key(key) {
            return true;
        }
    }
    false
}

fn send_json(
    stream: &mut TcpStream,
    status: u16,
    json: &str,
    deadline: Instant,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    send_text(
        stream,
        status,
        "application/json; charset=utf-8",
        json,
        deadline,
        stop,
    )
}

fn send_text(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
    deadline: Instant,
    stop: &AtomicBool,
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let bytes = body.as_bytes();
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        bytes.len()
    );
    write_all_deadline(stream, head.as_bytes(), deadline, stop)?;
    write_all_deadline(stream, bytes, deadline, stop)
}

fn render_pair_form(port: u16, is_tailscale: bool) -> String {
    let channel_hint = if is_tailscale {
        format!(
            "已绑定 Tailscale WireGuard 认证加密通道（或经 <code>ssh -L {port}:127.0.0.1:{port} &lt;host&gt;</code> 隧道访问）；"
        )
    } else {
        format!(
            "仅监听本机回环 <code>127.0.0.1:{port}</code>（请通过 <code>ssh -L {port}:127.0.0.1:{port} &lt;host&gt;</code> 隧道访问，或启用 Tailscale WireGuard 端到端加密通道）；"
        )
    };
    format!(
        r##"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rex Zero · 5分钟加密闪配</title>
<style>
body{{background:#12101e;color:#f1f5f9;font-family:system-ui,-apple-system,sans-serif;max-width:480px;margin:0 auto;padding:18px}}
h1{{font-size:18px;color:#38bdf8;margin:0 0 8px}}
.note{{font-size:12px;color:#94a3b8;margin:0 0 12px;line-height:1.5}}
code{{color:#cbd5e1;background:#1e1b2e;padding:1px 4px;border-radius:4px}}
label{{display:block;font-size:13px;color:#94a3b8;margin:12px 0 4px}}
input,textarea,select{{width:100%;box-sizing:border-box;background:#1e1b2e;color:#f8fafc;border:1px solid #334155;border-radius:8px;padding:10px;font-family:ui-monospace,monospace;font-size:13px}}
button{{margin-top:18px;width:100%;background:#38bdf8;color:#0f172a;font-weight:700;border:0;border-radius:8px;padding:12px;font-size:15px;cursor:pointer}}
button:disabled{{opacity:.5;cursor:default}}
.status{{margin-top:12px;padding:10px 12px;border-radius:8px;font-size:13px;display:none}}
.ok{{display:block;background:#0c2d3e;color:#38bdf8;border:1px solid #0284c7}}
.err{{display:block;background:#3b1220;color:#fb7185;border:1px solid #be123c}}
.hidden{{display:none}}
</style></head><body>
<h1>>_ Rex Zero · 加密扫码配对</h1>
<p class="note">{channel_hint}配置会在浏览器端使用二维码内置密钥（#k，不经过网络传输）与 6 位 PIN 进行 HMAC-SHA256 认证加密后再发送。</p>
<form id="f">
<div id="kbox" class="hidden">
<label>会话密钥（仅在手动输入网址时需要，64位十六进制）</label>
<input id="key_input" placeholder="从二维码 #k=... 复制 64 位十六进制密钥" maxlength="64">
</div>
<label>6位配对码 (PIN，见掌机屏幕)</label>
<input id="pin" name="pin" required maxlength="6" inputmode="numeric" pattern="[0-9]{{6}}" placeholder="输入掌机屏幕上的 6 位数字">
<label>Rex 主机列表（每行一个，如 mini=https://mini-rex.ts.net 或 ssh://user@host）</label>
<textarea id="hosts" rows="4" placeholder="mini=https://mini-rex.example-tailnet.ts.net&#10;m1=ssh://dev@m1"></textarea>
<label>SSH 私钥（可选，落盘权限 0600）</label>
<textarea id="ssh_key" rows="4" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
<label>云端语音识别 (ASR) 服务商</label>
<select id="asr_provider"><option value="openai">OpenAI Whisper</option><option value="groq">Groq Whisper Turbo</option><option value="doubao">字节豆包 ASR</option><option value="elevenlabs">ElevenLabs Scribe</option></select>
<label>ASR API Key（可选，落盘权限 0600）</label>
<input id="asr_key" type="password" placeholder="sk-... / gsk_...">
<label>ASR 自定义 Endpoint / AppID（可选）</label>
<input id="asr_endpoint" placeholder="https://api.openai.com">
<input id="asr_app_id" placeholder="豆包 AppID（仅豆包需要）" style="margin-top:6px">
<button id="btn" type="submit">加密投递到掌机确认</button>
<div id="st" class="status"></div>
</form>
<script>
(()=>{{
const K=new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
const r=(x,n)=>(x>>>n)|(x<<(32-n));
function sha256(m){{
const l=m.length,bl=((l+9+63)&~63),b=new Uint8Array(bl);b.set(m);b[l]=0x80;
const dv=new DataView(b.buffer);dv.setUint32(bl-8,Math.floor(l/0x20000000),false);dv.setUint32(bl-4,(l<<3)>>>0,false);
let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
const w=new Uint32Array(64);
for(let o=0;o<bl;o+=64){{
for(let i=0;i<16;i++)w[i]=dv.getUint32(o+i*4,false);
for(let i=16;i<64;i++){{const s0=r(w[i-15],7)^r(w[i-15],18)^(w[i-15]>>>3),s1=r(w[i-2],17)^r(w[i-2],19)^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;}}
let a=h0,c=h1,d=h2,e=h3,f=h4,g=h5,p=h6,q=h7;
for(let i=0;i<64;i++){{
const t1=(q+(r(f,6)^r(f,11)^r(f,25))+((f&g)^(~f&p))+K[i]+w[i])>>>0;
const t2=((r(a,2)^r(a,13)^r(a,22))+((a&c)^(a&d)^(c&d)))>>>0;
q=p;p=g;g=f;f=(e+t1)>>>0;e=d;d=c;c=a;a=(t1+t2)>>>0;
}}
h0=(h0+a)>>>0;h1=(h1+c)>>>0;h2=(h2+d)>>>0;h3=(h3+e)>>>0;h4=(h4+f)>>>0;h5=(h5+g)>>>0;h6=(h6+p)>>>0;h7=(h7+q)>>>0;
}}
const out=new Uint8Array(32),odv=new DataView(out.buffer);
[h0,h1,h2,h3,h4,h5,h6,h7].forEach((v,i)=>odv.setUint32(i*4,v,false));return out;
}}
function cat(...arrs){{const t=arrs.reduce((s,a)=>s+a.length,0),u=new Uint8Array(t);let o=0;for(const a of arrs){{u.set(a,o);o+=a.length;}}return u;}}
function hmac(key,msg){{
let k=key.length>64?sha256(key):key;const ip=new Uint8Array(64),op=new Uint8Array(64);
ip.fill(0x36);op.fill(0x5c);for(let i=0;i<k.length;i++){{ip[i]^=k[i];op[i]^=k[i];}}
return sha256(cat(op,sha256(cat(ip,msg))));
}}
const enc=s=>new TextEncoder().encode(s);
const toHex=u=>Array.from(u,b=>b.toString(16).padStart(2,'0')).join('');
const fromHex=h=>{{if(!/^[0-9a-fA-F]{{64}}$/.test(h))return null;const u=new Uint8Array(32);for(let i=0;i<32;i++)u[i]=parseInt(h.slice(i*2,i*2+2),16);return u;}};
const toB64=u=>{{let s='';for(let i=0;i<u.length;i+=0x8000)s+=String.fromCharCode(...u.subarray(i,i+0x8000));return btoa(s);}};
function encryptPayload(keyBytes,pin,plainBytes){{
const nonce=new Uint8Array(16);crypto.getRandomValues(nonce);
const pb=enc(pin),sep=enc('|');
const encKey=hmac(keyBytes,cat(enc('rex-pair-enc-v1|'),pb,sep,nonce));
const macKey=hmac(keyBytes,cat(enc('rex-pair-mac-v1|'),pb,sep,nonce));
const ct=new Uint8Array(plainBytes.length),ctr=new Uint8Array(4),cdv=new DataView(ctr.buffer);
for(let off=0,blk=0;off<plainBytes.length;off+=32,blk++){{
cdv.setUint32(0,blk,false);const ks=hmac(encKey,cat(nonce,ctr));
const n=Math.min(32,plainBytes.length-off);for(let i=0;i<n;i++)ct[off+i]=plainBytes[off+i]^ks[i];
}}
const tag=hmac(macKey,cat(enc('rex-pair-v1|'),nonce,ct));
return {{v:1,nonce:toHex(nonce),ct:toB64(ct),tag:toHex(tag)}};
}}
const hashK=new URLSearchParams(location.hash.replace(/^#/,'')).get('k')||'';
if(!fromHex(hashK))document.getElementById('kbox').classList.remove('hidden');
const st=document.getElementById('st'),btn=document.getElementById('btn');
const show=(ok,msg)=>{{st.className='status '+(ok?'ok':'err');st.textContent=msg;}};
document.getElementById('f').addEventListener('submit',async ev=>{{
ev.preventDefault();
const kh=(hashK||document.getElementById('key_input').value.trim());
const keyBytes=fromHex(kh);
if(!keyBytes){{show(false,'缺少有效的 64 位会话密钥（请使用手机扫码打开页面，或粘贴 #k 密钥）');return;}}
const pin=document.getElementById('pin').value.trim();
if(!/^[0-9]{{6}}$/.test(pin)){{show(false,'请输入掌机屏幕显示的 6 位数字 PIN');return;}}
const payload={{hosts:document.getElementById('hosts').value,sshKey:document.getElementById('ssh_key').value,asrProvider:document.getElementById('asr_provider').value,asrApiKey:document.getElementById('asr_key').value,asrEndpoint:document.getElementById('asr_endpoint').value,asrAppId:document.getElementById('asr_app_id').value}};
btn.disabled=true;
try{{
const env=encryptPayload(keyBytes,pin,enc(JSON.stringify(payload)));
const resp=await fetch('/pair',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(env)}});
const data=await resp.json().catch(()=>({{ok:false,error:'HTTP '+resp.status}}));
show(resp.ok&&data.ok,data.message||data.error||('HTTP '+resp.status));
}}catch(e){{show(false,'发送失败: '+e);}}finally{{btn.disabled=false;}}
}});
}})();
</script></body></html>"##
    )
}

// ============================================================================
// Pure-Rust SHA-256 + HMAC-SHA256 + Authenticated Encryption (Encrypt-then-MAC)
// ============================================================================

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let pad_len = (data.len() + 9 + 63) & !63;
    let mut buf = vec![0u8; pad_len];
    buf[..data.len()].copy_from_slice(data);
    buf[data.len()] = 0x80;
    buf[pad_len - 8..].copy_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in buf.chunks_exact(64) {
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut p] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = p
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            p = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(p);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k_block = [0u8; 64];
    if key.len() > 64 {
        let digest = sha256(key);
        k_block[..32].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + msg.len());
    for &b in &k_block {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);

    let mut outer = [0u8; 96];
    for i in 0..64 {
        outer[i] = k_block[i] ^ 0x5c;
    }
    outer[64..].copy_from_slice(&inner_hash);
    sha256(&outer)
}

fn derive_pair_subkeys(
    session_key: &[u8; 32],
    pin: &str,
    nonce: &[u8; 16],
) -> ([u8; 32], [u8; 32]) {
    let mut enc_info = Vec::with_capacity(32 + pin.len());
    enc_info.extend_from_slice(b"rex-pair-enc-v1|");
    enc_info.extend_from_slice(pin.as_bytes());
    enc_info.push(b'|');
    enc_info.extend_from_slice(nonce);

    let mut mac_info = Vec::with_capacity(32 + pin.len());
    mac_info.extend_from_slice(b"rex-pair-mac-v1|");
    mac_info.extend_from_slice(pin.as_bytes());
    mac_info.push(b'|');
    mac_info.extend_from_slice(nonce);

    (
        hmac_sha256(session_key, &enc_info),
        hmac_sha256(session_key, &mac_info),
    )
}

fn compute_envelope_tag(mac_key: &[u8; 32], nonce: &[u8; 16], ciphertext: &[u8]) -> [u8; 32] {
    let mut mac_input = Vec::with_capacity(12 + 16 + ciphertext.len());
    mac_input.extend_from_slice(b"rex-pair-v1|");
    mac_input.extend_from_slice(nonce);
    mac_input.extend_from_slice(ciphertext);
    hmac_sha256(mac_key, &mac_input)
}

fn ctr_xor(enc_key: &[u8; 32], nonce: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; data.len()];
    let mut ctr_input = [0u8; 20];
    ctr_input[..16].copy_from_slice(nonce);
    for (blk_idx, (src, dst)) in data.chunks(32).zip(out.chunks_mut(32)).enumerate() {
        ctr_input[16..20].copy_from_slice(&(blk_idx as u32).to_be_bytes());
        let ks = hmac_sha256(enc_key, &ctr_input);
        for i in 0..src.len() {
            dst[i] = src[i] ^ ks[i];
        }
    }
    out
}

fn decrypt_envelope(
    session_key: &[u8; 32],
    expected_pin: &str,
    nonce: &[u8; 16],
    ciphertext: &[u8],
    tag: &[u8; 32],
) -> Option<Vec<u8>> {
    let (enc_key, mac_key) = derive_pair_subkeys(session_key, expected_pin, nonce);
    let expected_tag = compute_envelope_tag(&mac_key, nonce, ciphertext);
    if !constant_time_eq(tag, &expected_tag) {
        return None;
    }
    Some(ctr_xor(&enc_key, nonce, ciphertext))
}

#[cfg(test)]
fn encrypt_envelope(
    session_key: &[u8; 32],
    pin: &str,
    nonce: &[u8; 16],
    plaintext: &[u8],
) -> serde_json::Value {
    let (enc_key, mac_key) = derive_pair_subkeys(session_key, pin, nonce);
    let ct = ctr_xor(&enc_key, nonce, plaintext);
    let tag = compute_envelope_tag(&mac_key, nonce, &ct);
    serde_json::json!({
        "v": 1,
        "nonce": hex_encode(nonce),
        "ct": BASE64_STD.encode(&ct),
        "tag": hex_encode(&tag),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = hex_nibble(b[i * 2])?;
        let lo = hex_nibble(b[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn read_os_random(buf: &mut [u8]) -> Result<(), String> {
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| format!("无法打开 /dev/urandom 获取安全随机数: {e}"))?;
    f.read_exact(buf)
        .map_err(|e| format!("读取 /dev/urandom 失败: {e}"))
}

fn generate_pin_6() -> Result<String, String> {
    // Rejection sampling to avoid modulo bias over [0, 1_000_000).
    const LIMIT: u32 = (u32::MAX / 1_000_000) * 1_000_000;
    let mut bytes = [0u8; 4];
    loop {
        read_os_random(&mut bytes)?;
        let val = u32::from_le_bytes(bytes);
        if val < LIMIT {
            return Ok(format!("{:06}", val % 1_000_000));
        }
    }
}

fn generate_session_key() -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    read_os_random(&mut key)?;
    Ok(key)
}

fn format_authority(ip: &str, port: u16) -> String {
    if ip.contains(':') && !ip.starts_with('[') {
        format!("[{ip}]:{port}")
    } else {
        format!("{ip}:{port}")
    }
}

fn is_tailscale_cgnat_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (octets[1] & 0xc0) == 64
}

fn is_authenticated_pair_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || is_tailscale_cgnat_v4(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || is_tailscale_cgnat_v4(v4))
        }
    }
}

fn verified_tunnel_name(name: &str) -> bool {
    name.starts_with("tailscale")
        || (cfg!(target_os = "macos")
            && name.strip_prefix("utun").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            }))
}

fn detect_tailscale_ip(requested: Option<IpAddr>) -> Option<(Ipv4Addr, CString)> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return None;
    }

    let mut preferred = None;
    let mut cur = ifap;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null()
            && (ifa.ifa_flags & (libc::IFF_UP as u32)) != 0
            && unsafe { (*ifa.ifa_addr).sa_family as i32 } == libc::AF_INET
        {
            let sa = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            let addr = Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr));
            if is_tailscale_cgnat_v4(addr)
                && requested.is_none_or(|ip| ip == IpAddr::V4(addr))
                && !ifa.ifa_name.is_null()
            {
                let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
                if name.to_str().is_ok_and(verified_tunnel_name) {
                    preferred = Some((addr, name.to_owned()));
                    break;
                }
            }
        }
        cur = ifa.ifa_next;
    }

    unsafe { libc::freeifaddrs(ifap) };
    preferred
}

fn bind_tunnel(ip: Ipv4Addr, name: &CStr) -> std::io::Result<TcpListener> {
    let raw = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    super::transport::set_fd_cloexec(raw)?;
    #[cfg(target_os = "linux")]
    let bound = unsafe {
        libc::setsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.to_bytes_with_nul().len() as _,
        )
    };
    #[cfg(target_os = "macos")]
    let bound = {
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(std::io::Error::last_os_error());
        }
        unsafe {
            libc::setsockopt(
                raw,
                libc::IPPROTO_IP,
                libc::IP_BOUND_IF,
                std::ptr::from_ref(&index).cast(),
                std::mem::size_of_val(&index) as _,
            )
        }
    };
    if bound < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as _;
    addr.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    let len = std::mem::size_of_val(&addr);
    #[cfg(target_os = "macos")]
    {
        addr.sin_len = len as _;
    }
    if unsafe { libc::bind(raw, std::ptr::from_ref(&addr).cast(), len as _) } < 0
        || unsafe { libc::listen(raw, 16) } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(TcpListener::from(fd))
}

fn bind_authenticated_listener(
    preferred_ip: Option<&str>,
) -> Result<(TcpListener, IpAddr), String> {
    let requested = preferred_ip
        .map(|raw| {
            raw.trim()
                .parse::<IpAddr>()
                .map_err(|_| format!("无效的配对监听地址: {raw}"))
        })
        .transpose()?;
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    if requested != Some(loopback) {
        if let Some((ip, name)) = detect_tailscale_ip(requested) {
            match bind_tunnel(ip, &name) {
                Ok(listener) => return Ok((listener, IpAddr::V4(ip))),
                Err(e) if requested.is_some() => return Err(format!("绑定配对端口失败: {e}")),
                Err(_) => {}
            }
        } else if requested.is_some() {
            return Err("配对服务禁止绑定未认证的局域网或通配地址".into());
        }
    }
    let listener =
        TcpListener::bind((loopback, 0)).map_err(|e| format!("绑定回环配对端口失败: {e}"))?;
    Ok((listener, loopback))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extract_addr_and_key(url: &str) -> (String, [u8; 32]) {
        let rest = url.strip_prefix("http://").expect("http url");
        let (addr, frag) = rest.split_once("/#k=").expect("fragment key");
        let key = decode_hex_fixed::<32>(frag).expect("64 hex key");
        (addr.to_string(), key)
    }

    fn send_raw_http(addr: &str, req: &str) -> String {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        resp
    }

    #[test]
    fn sha256_and_hmac_match_standard_vectors() {
        // NIST SHA-256("abc")
        assert_eq!(
            hex_encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        assert_eq!(
            hex_encode(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Exact envelope produced by the embedded browser JS helper (`encryptPayload`).
        let key = decode_hex_fixed::<32>(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let nonce = decode_hex_fixed::<16>("07070707070707070707070707070707").unwrap();
        let ct = BASE64_STD
            .decode("8wu+tlm4hDSO9csTQ2sRmCvOhf+XerTwFkQcMBUTzTlMIpyunsRgh1yc55BBNxswZRLTOJ2mAWE19MYjohhK")
            .unwrap();
        let tag = decode_hex_fixed::<32>(
            "5d2bbe2fe973b68f84b0e0fc843bd4a5651be445367a10a162c9342d9490cf7c",
        )
        .unwrap();
        let plain =
            decrypt_envelope(&key, "604921", &nonce, &ct, &tag).expect("JS envelope decrypts");
        assert_eq!(
            String::from_utf8(plain).unwrap(),
            r#"{"hosts":"mini=https://mini-rex.ts.net","asrApiKey":"gsk_test"}"#
        );
    }

    #[test]
    fn ephemeral_pair_server_enforces_encryption_pin_host_origin_and_headers() {
        let mgr = Arc::new(PairManager::new(false, Arc::new(|| {})));
        mgr.toggle(true, Some("127.0.0.1")).unwrap();
        let snap = mgr.snapshot();
        assert!(snap.active);
        assert_eq!(snap.pin.len(), 6);
        assert!(snap.qr_matrix.is_some());
        assert!(
            !snap.url.contains("?pin="),
            "PIN must never be in query string"
        );
        assert!(
            snap.url.contains("/#k="),
            "session key must be in URL fragment"
        );

        let (addr, key) = extract_addr_and_key(&snap.url);
        let wrong_pin = format!("{:06}", (snap.pin.parse::<u32>().unwrap() + 1) % 1_000_000);
        assert_ne!(wrong_pin, snap.pin);

        // 1. Plaintext form/JSON secret POST must be rejected (400) and stage nothing.
        {
            let body = format!(
                r#"{{"pin":"{}","hosts":"mini=https://mini.ts.net","asrApiKey":"gsk_plain"}}"#,
                snap.pin
            );
            let req = format!(
                "POST /pair HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let resp = send_raw_http(&addr, &req);
            assert!(resp.starts_with("HTTP/1.1 400"), "resp={resp}");
            assert!(mgr.snapshot().pending_import.is_none());
        }

        // 2. DNS rebinding / bad Host and cross-origin Origin rejected with 403.
        {
            let req = "GET / HTTP/1.1\r\nHost: evil.example:1234\r\n\r\n";
            let resp = send_raw_http(&addr, req);
            assert!(resp.starts_with("HTTP/1.1 403"), "resp={resp}");

            let req2 = format!(
                "POST /pair HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://evil.example\r\nContent-Length: 2\r\n\r\n{{}}"
            );
            let resp2 = send_raw_http(&addr, &req2);
            assert!(resp2.starts_with("HTTP/1.1 403"), "resp2={resp2}");
        }

        // 3. Oversized headers (> 8 KiB) rejected with 431 before body read.
        {
            let big_hdr = "X-Pad: ".to_string() + &"a".repeat(9000);
            let req = format!("GET / HTTP/1.1\r\nHost: {addr}\r\n{big_hdr}\r\n\r\n");
            let resp = send_raw_http(&addr, &req);
            assert!(resp.starts_with("HTTP/1.1 431"), "resp={resp}");
        }

        // 4. Guaranteed-wrong PIN encrypted POST rejected with 403 and stages nothing BEFORE valid POST.
        {
            let plain = serde_json::json!({
                "hosts": "mini=https://mini.ts.net",
                "asrProvider": "groq",
                "asrApiKey": "gsk_wrong",
            });
            let env = encrypt_envelope(&key, &wrong_pin, &[1u8; 16], plain.to_string().as_bytes());
            let body = env.to_string();
            let req = format!(
                "POST /pair HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let resp = send_raw_http(&addr, &req);
            assert!(resp.starts_with("HTTP/1.1 403"), "resp={resp}");
            assert!(
                mgr.snapshot().pending_import.is_none(),
                "wrong PIN must not stage any import"
            );
        }

        // 5. Valid encrypted POST with exact PIN & fragment key succeeds and stages import!
        let valid_nonce = [7u8; 16];
        let valid_body = {
            let plain = serde_json::json!({
                "hosts": "mini=https://mini-rex.ts.net",
                "asrProvider": "groq",
                "asrApiKey": "gsk_test",
            });
            encrypt_envelope(&key, &snap.pin, &valid_nonce, plain.to_string().as_bytes())
                .to_string()
        };
        {
            let req = format!(
                "POST /pair HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Length: {}\r\n\r\n{valid_body}",
                valid_body.len()
            );
            let resp = send_raw_http(&addr, &req);
            assert!(resp.starts_with("HTTP/1.1 200"), "resp={resp}");
        }

        // 6. Replaying the exact same encrypted envelope (same nonce) is rejected with 403!
        {
            let req = format!(
                "POST /pair HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Length: {}\r\n\r\n{valid_body}",
                valid_body.len()
            );
            let resp = send_raw_http(&addr, &req);
            assert!(resp.starts_with("HTTP/1.1 403"), "replay resp={resp}");
        }

        let staged_snap = mgr.snapshot();
        assert!(staged_snap.pending_import.is_some());
        let confirmed = mgr
            .take_confirmed_import_matching(true, Some(&staged_snap.pending_import.unwrap().token))
            .unwrap()
            .unwrap();
        assert_eq!(confirmed.hosts.len(), 1);
        assert_eq!(confirmed.hosts[0].label, "mini");
        assert_eq!(confirmed.asr_api_key.as_deref(), Some("gsk_test"));
        assert!(!mgr.snapshot().active);
    }

    #[test]
    fn five_failed_pin_attempts_invalidate_session() {
        let mgr = Arc::new(PairManager::new(false, Arc::new(|| {})));
        mgr.toggle(true, Some("127.0.0.1")).unwrap();
        let snap = mgr.snapshot();
        let (addr, key) = extract_addr_and_key(&snap.url);
        let wrong_pin = format!("{:06}", (snap.pin.parse::<u32>().unwrap() + 7) % 1_000_000);

        for i in 0..MAX_AUTH_FAILURES {
            let env = encrypt_envelope(
                &key,
                &wrong_pin,
                &[i as u8; 16],
                br#"{"hosts":"a=https://a"}"#,
            );
            let body = env.to_string();
            let req = format!(
                "POST /pair HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let resp = send_raw_http(&addr, &req);
            assert!(resp.starts_with("HTTP/1.1 403"), "attempt {i} resp={resp}");
        }

        assert!(
            !mgr.snapshot().active,
            "session must be invalidated after 5 failed auth attempts"
        );
    }

    #[test]
    fn stale_session_id_cannot_stage_and_expired_session_cannot_confirm() {
        let mgr = Arc::new(PairManager::new(false, Arc::new(|| {})));
        mgr.toggle(true, Some("127.0.0.1")).unwrap();
        let (old_id, _) = mgr.snapshot_with_seq();
        mgr.toggle(true, Some("127.0.0.1")).unwrap();
        let (new_id, _) = mgr.snapshot_with_seq();
        assert_ne!(old_id, new_id);

        let dummy = StagedImport {
            hosts: Vec::new(),
            ssh_private_key: None,
            asr_provider: None,
            asr_api_key: Some("sk-old".into()),
            asr_app_id: None,
            asr_endpoint: None,
            summary: "test".into(),
            from_ip: "127.0.0.1".into(),
        };
        assert!(matches!(
            mgr.stage_import(old_id, [1u8; 16], dummy.clone()),
            StageOutcome::SessionGone
        ));
        assert!(mgr.snapshot().pending_import.is_none());

        assert!(matches!(
            mgr.stage_import(new_id, [2u8; 16], dummy),
            StageOutcome::Staged
        ));
        // Force expiry under lock and verify take_confirmed_import rejects it.
        {
            let mut guard = mgr.inner.lock().unwrap();
            guard.session.as_mut().unwrap().expires_at = Instant::now() - Duration::from_secs(1);
        }
        assert!(mgr.take_confirmed_import_matching(true, None).is_err());
        assert!(!mgr.snapshot().active);
    }

    #[test]
    fn ordinary_cgnat_interfaces_and_alternate_loopback_binds_are_rejected() {
        for name in ["en0", "eth0", "wlan0", "wlp1s0", "utunwifi"] {
            assert!(!verified_tunnel_name(name));
        }
        assert!(verified_tunnel_name("tailscale0"));
        assert_eq!(verified_tunnel_name("utun3"), cfg!(target_os = "macos"));
        assert!(bind_authenticated_listener(Some("127.0.0.9")).is_err());
        assert!(bind_authenticated_listener(Some("::1")).is_err());
    }

    #[test]
    fn binds_only_authenticated_interfaces_and_rejects_unauthenticated_lan_ips() {
        // Tailscale CGNAT (100.64.0.0/10) and loopback checks.
        assert!(is_authenticated_pair_ip("127.0.0.1".parse().unwrap()));
        assert!(is_authenticated_pair_ip("127.0.0.9".parse().unwrap()));
        assert!(is_authenticated_pair_ip("::1".parse().unwrap()));
        assert!(is_authenticated_pair_ip("100.64.0.1".parse().unwrap()));
        assert!(is_authenticated_pair_ip("100.127.255.254".parse().unwrap()));

        for bad in [
            "0.0.0.0",
            "192.168.1.10",
            "10.0.0.5",
            "172.16.0.2",
            "100.63.255.255",
            "100.128.0.0",
            "8.8.8.8",
        ] {
            let ip: IpAddr = bad.parse().unwrap();
            assert!(!is_authenticated_pair_ip(ip), "must reject {bad}");
            let mgr = Arc::new(PairManager::new(false, Arc::new(|| {})));
            assert!(
                mgr.toggle(true, Some(bad)).is_err(),
                "toggle must reject unauthenticated IP {bad}"
            );
            assert!(!mgr.snapshot().active);
        }

        // Default toggle(true, None) binds ONLY 100.64.0.0/10 or 127.0.0.1, never 0.0.0.0/RFC1918.
        let mgr = Arc::new(PairManager::new(false, Arc::new(|| {})));
        mgr.toggle(true, None).unwrap();
        let snap = mgr.snapshot();
        let (addr, _) = extract_addr_and_key(&snap.url);
        let host_ip: IpAddr = addr
            .rsplit_once(':')
            .unwrap()
            .0
            .trim_matches(|c| c == '[' || c == ']')
            .parse()
            .unwrap();
        assert!(
            is_authenticated_pair_ip(host_ip),
            "default bind IP must be authenticated, got {host_ip}"
        );

        let port = addr.rsplit_once(':').unwrap().1;
        let get_req = format!("GET / HTTP/1.1\r\nHost: {addr}\r\n\r\n");
        let html = send_raw_http(&addr, &get_req);
        assert!(html.starts_with("HTTP/1.1 200"));
        assert!(html.contains("Tailscale WireGuard"));
        assert!(html.contains(&format!("ssh -L {port}:127.0.0.1:{port}")));
    }

    #[test]
    fn pending_import_cannot_be_overwritten_and_confirmation_binds_to_displayed_token() {
        let mgr = Arc::new(PairManager::new(false, Arc::new(|| {})));
        mgr.toggle(true, Some("127.0.0.1")).unwrap();
        let (sid_a, snap_a) = mgr.snapshot_with_seq();
        let (addr, key) = extract_addr_and_key(&snap_a.url);

        // 1. Stage first import via HTTP /pair.
        let nonce_1 = [0x11u8; 16];
        let body_1 = encrypt_envelope(
            &key,
            &snap_a.pin,
            &nonce_1,
            br#"{"hosts":"first=https://first.ts.net","asrApiKey":"gsk_first"}"#,
        )
        .to_string();
        let req_1 = format!(
            "POST /pair HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Length: {}\r\n\r\n{body_1}",
            body_1.len()
        );
        let resp_1 = send_raw_http(&addr, &req_1);
        assert!(resp_1.starts_with("HTTP/1.1 200"), "resp_1={resp_1}");

        // 2. Second /pair submission while first is awaiting confirmation MUST fail with 409 Conflict!
        let nonce_2 = [0x22u8; 16];
        let body_2 = encrypt_envelope(
            &key,
            &snap_a.pin,
            &nonce_2,
            br#"{"hosts":"second=https://evil.ts.net","asrApiKey":"gsk_evil"}"#,
        )
        .to_string();
        let req_2 = format!(
            "POST /pair HTTP/1.1\r\nHost: {addr}\r\nOrigin: http://{addr}\r\nContent-Length: {}\r\n\r\n{body_2}",
            body_2.len()
        );
        let resp_2 = send_raw_http(&addr, &req_2);
        assert!(resp_2.starts_with("HTTP/1.1 409"), "resp_2={resp_2}");
        assert!(resp_2.contains("pending import awaiting device confirmation"));

        // 3. Cannot confirm BEFORE snapshot() / snapshot_with_seq() has displayed the import.
        assert!(
            mgr.take_confirmed_import_matching(true, None).is_err(),
            "must not confirm an undisplayed pending import"
        );
        assert!(
            mgr.take_confirmed_import_matching(false, None).is_err(),
            "must not reject an undisplayed pending import"
        );

        // 4. Display the pending import via snapshot_with_seq().
        let (sid_disp, disp_snap) = mgr.snapshot_with_seq();
        assert_eq!(sid_disp, sid_a);
        assert!(disp_snap.pending_import.is_some());

        // Mismatched expected_token does NOT consume or reject the pending import.
        let wrong_token = format!("{sid_a}:{}", hex_encode(&nonce_2));
        assert!(mgr
            .take_confirmed_import_matching(true, Some(&wrong_token))
            .is_err());
        assert!(mgr.snapshot().pending_import.is_some());

        // Exact displayed token consumes and returns the first import (not overwritten!).
        assert!(mgr.take_confirmed_import_matching(false, None).is_err());
        let exact_token = disp_snap.pending_import.unwrap().token;
        let confirmed = mgr
            .take_confirmed_import_matching(true, Some(&exact_token))
            .unwrap()
            .expect("exact displayed token must confirm");
        assert_eq!(confirmed.hosts[0].label, "first");
        assert_eq!(confirmed.asr_api_key.as_deref(), Some("gsk_first"));

        // 5. Cross-session race: new session starts (clearing displayed_token);
        // stale token from session A cannot confirm session B's import.
        mgr.toggle(true, Some("127.0.0.1")).unwrap();
        let (sid_b, _) = mgr.snapshot_with_seq();
        assert_ne!(sid_a, sid_b);
        let dummy_b = StagedImport {
            hosts: Vec::new(),
            ssh_private_key: None,
            asr_provider: None,
            asr_api_key: Some("sk-session-b".into()),
            asr_app_id: None,
            asr_endpoint: None,
            summary: "b".into(),
            from_ip: "127.0.0.1".into(),
        };
        let nonce_b = [0x33u8; 16];
        assert!(matches!(
            mgr.stage_import(sid_b, nonce_b, dummy_b),
            StageOutcome::Staged
        ));
        let _ = mgr.snapshot();
        assert!(
            mgr.take_confirmed_import_matching(true, Some(&exact_token))
                .is_err(),
            "stale session token must not confirm new session's import"
        );
        let token_b = format!("{sid_b}:{}", hex_encode(&nonce_b));
        let confirmed_b = mgr
            .take_confirmed_import_matching(true, Some(&token_b))
            .unwrap()
            .expect("session B token confirms session B");
        assert_eq!(confirmed_b.asr_api_key.as_deref(), Some("sk-session-b"));
    }

    #[test]
    fn slowloris_client_is_interrupted_promptly_by_stop() {
        let mgr = Arc::new(PairManager::new(false, Arc::new(|| {})));
        mgr.toggle(true, Some("127.0.0.1")).unwrap();
        let snap = mgr.snapshot();
        let (addr, _) = extract_addr_and_key(&snap.url);

        // Open a connection and send only partial headers, never finishing.
        let mut slow = TcpStream::connect(&addr).unwrap();
        slow.write_all(b"POST /pair HTTP/1.1\r\nHo").unwrap();
        thread::sleep(Duration::from_millis(80));

        // Stopping must abort the slowloris handler promptly (< 1s, not 4s+).
        let t0 = Instant::now();
        mgr.toggle(false, None).unwrap();
        let mut sink = Vec::new();
        let _ = slow.read_to_end(&mut sink);
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "slowloris took {:?} to abort",
            t0.elapsed()
        );
    }
}
