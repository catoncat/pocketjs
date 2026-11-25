//! Pluggable in-memory Cloud ASR (`16 kHz` 16-bit mono PCM -> RIFF WAV -> HTTPS
//! multipart/JSON upload for `openai`, `groq`, `elevenlabs`, and `doubao`).
//! Zero temporary files are ever written to disk, and `HTTPS_PROXY` / `ALL_PROXY`
//! are honored automatically.

use crate::rex::{
    transport::{connect_tcp_with_env_proxy, shared_tls_config, PersistedSettings},
    types::{AsrProvider, AsrState},
};
use base64::{engine::general_purpose::STANDARD as BASE64_STD, Engine};
use rustls::{ClientConnection, StreamOwned};
use rustls_pki_types::ServerName;
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::TcpStream,
    os::fd::RawFd,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
#[cfg(target_os = "linux")]
use std::{
    os::fd::AsRawFd,
    process::{Command, Stdio},
};

const SAMPLE_RATE: u32 = 16_000;
const MAX_RECORD_SECS: usize = 60;
const MAX_SAMPLES: usize = SAMPLE_RATE as usize * MAX_RECORD_SECS;
const ASR_REQUEST_DEADLINE: Duration = Duration::from_secs(25);
const MAX_ASR_HEADER_BYTES: usize = 16 * 1024;
const MAX_ASR_HEADER_LINES: usize = 128;
const MAX_ASR_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 256;

pub type AsrCallback = Arc<dyn Fn(AsrEvent) + Send + Sync>;

pub enum AsrEvent {
    StateChanged(AsrState),
    Transcript { target_key: String, text: String },
}

pub struct AsrEngine {
    stop_flag: Arc<AtomicBool>,
    cancel_flag: Arc<AtomicBool>,
    state: Arc<Mutex<AsrState>>,
    settings: Mutex<PersistedSettings>,
    mock: bool,
    callback: AsrCallback,
}

/// Resolves the executable path for plugin-backed ASR modes (`doubao_free` or custom `plugin`).
pub fn resolve_plugin_path(provider: AsrProvider) -> Option<PathBuf> {
    match provider {
        AsrProvider::Plugin => {
            let custom = crate::rex::transport::config_dir().join("asr-plugin");
            custom.is_file().then_some(custom)
        }
        AsrProvider::DoubaoFree => {
            let custom = crate::rex::transport::config_dir().join("asr-plugin");
            if custom.is_file() {
                return Some(custom);
            }
            let candidates = [
                PathBuf::from("/usr/share/APPLaunch/lib/rex-zero/plugins/doubao-asr-plugin"),
                PathBuf::from("plugins/doubao-asr-plugin.py"),
                PathBuf::from("../../plugins/doubao-asr-plugin.py"),
                PathBuf::from("../../../../plugins/doubao-asr-plugin.py"),
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../../plugins/doubao-asr-plugin.py"),
            ];
            candidates.into_iter().find(|p| p.is_file())
        }
        _ => None,
    }
}

impl AsrEngine {
    pub fn new(initial: PersistedSettings, mock: bool, callback: AsrCallback) -> Self {
        let provider = if mock {
            AsrProvider::DoubaoFree
        } else {
            initial.provider_enum()
        };
        let state = AsrState {
            configured: mock || initial.is_asr_configured(),
            provider,
            recording: false,
            busy: false,
            target_key: None,
            partial: String::new(),
            level: 0.0,
            error: None,
        };
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            cancel_flag: Arc::new(AtomicBool::new(false)),
            state: Arc::new(Mutex::new(state)),
            settings: Mutex::new(initial),
            mock,
            callback,
        }
    }

    pub fn snapshot(&self) -> AsrState {
        self.state.lock().unwrap().clone()
    }

    pub fn update_settings(&self, next: PersistedSettings) {
        let configured = self.mock || next.is_asr_configured();
        let provider = next.provider_enum();
        *self.settings.lock().unwrap() = next;
        let mut st = self.state.lock().unwrap();
        st.configured = configured;
        st.provider = provider;
        st.error = None;
        let snap = st.clone();
        drop(st);
        (self.callback)(AsrEvent::StateChanged(snap));
    }

    pub fn cancel(&self) {
        if self.mock {
            let snap = {
                let mut st = self.state.lock().unwrap();
                if !st.recording && !st.busy {
                    return;
                }
                st.recording = false;
                st.busy = false;
                st.level = 0.0;
                st.partial.clear();
                st.error = None;
                st.clone()
            };
            (self.callback)(AsrEvent::StateChanged(snap));
            return;
        }
        self.cancel_flag.store(true, Ordering::SeqCst);
        self.stop_flag.store(true, Ordering::SeqCst);
    }

    pub fn toggle(&self, target_key: &str) -> Result<(), String> {
        self.toggle_with_spawner(target_key, |f| {
            thread::Builder::new()
                .name("rex-zero-asr".into())
                .stack_size(512 * 1024)
                .spawn(f)
                .map(|_| ())
        })
    }

    fn toggle_with_spawner<F>(&self, target_key: &str, spawn_fn: F) -> Result<(), String>
    where
        F: FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<()>,
    {
        let mut st = self.state.lock().unwrap();
        if st.busy {
            return Err("语音识别正在收尾，请稍候".into());
        }
        if st.recording {
            // Signal active capture thread to finish & transcribe.
            self.stop_flag.store(true, Ordering::SeqCst);
            return Ok(());
        }
        let settings = self.settings.lock().unwrap().clone();
        if !self.mock && !settings.is_asr_configured() {
            let msg = match settings.provider_enum() {
                AsrProvider::Plugin => "未找到 ~/.config/rex-zero/asr-plugin 插件",
                AsrProvider::DoubaoFree => "未找到内置豆包语音插件（请检查 python3）",
                _ => "当前语音引擎未填 Key（可在「设置」切回豆包免Key或扫码导入）",
            };
            st.error = Some(msg.into());
            let snap = st.clone();
            drop(st);
            (self.callback)(AsrEvent::StateChanged(snap));
            return Err(msg.into());
        }

        self.cancel_flag.store(false, Ordering::SeqCst);
        self.stop_flag.store(false, Ordering::SeqCst);
        st.provider = if self.mock {
            AsrProvider::DoubaoFree
        } else {
            settings.provider_enum()
        };
        st.configured = true;
        st.recording = true;
        st.busy = false;
        st.target_key = Some(target_key.to_string());
        st.partial = if self.mock {
            "请允许执行交叉编译并汇报结果".into()
        } else {
            "正在聆听… 回车完成 / Esc取消".into()
        };
        st.level = if self.mock { 0.68 } else { 0.12 };
        st.error = None;
        let initial_snap = st.clone();

        if self.mock {
            drop(st);
            (self.callback)(AsrEvent::StateChanged(initial_snap));
            return Ok(());
        }

        let stop_flag = self.stop_flag.clone();
        let cancel_flag = self.cancel_flag.clone();
        let state = self.state.clone();
        let cb = self.callback.clone();
        let key = target_key.to_string();

        // Spawn while holding `self.state` so rollback on failure is atomic and
        // `recording = true` is never left wedged without a live worker thread.
        let spawn_res = spawn_fn(Box::new(move || {
            cb(AsrEvent::StateChanged(initial_snap));
            run_live_capture(key, settings, stop_flag, cancel_flag, state, cb);
        }));

        if let Err(e) = spawn_res {
            st.recording = false;
            st.busy = false;
            st.target_key = None;
            st.partial.clear();
            st.level = 0.0;
            st.error = Some("无法启动录音线程".into());
            let err_snap = st.clone();
            drop(st);
            (self.callback)(AsrEvent::StateChanged(err_snap));
            return Err(format!("spawn ASR thread: {e}"));
        }

        drop(st);
        Ok(())
    }

    /// Completes mock dictation on the second `asr_toggle` press.
    pub fn finish_mock_if_recording(&self) -> bool {
        if !self.mock {
            return false;
        }
        let (target_key, text, snap) = {
            let mut st = self.state.lock().unwrap();
            if !st.recording {
                return false;
            }
            let key = st.target_key.clone().unwrap_or_default();
            let transcript = if st.partial.is_empty() {
                "请允许执行交叉编译并汇报结果".to_string()
            } else {
                st.partial.clone()
            };
            st.recording = false;
            st.busy = false;
            st.level = 0.0;
            st.partial.clear();
            (key, transcript, st.clone())
        };
        if !target_key.is_empty() {
            (self.callback)(AsrEvent::Transcript { target_key, text });
        }
        (self.callback)(AsrEvent::StateChanged(snap));
        true
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Default)]
struct PluginStreamOutcome {
    latest_partial: String,
    final_text: Option<String>,
    error: Option<String>,
    eof: bool,
}

/// Parses a single JSONL line from a streaming ASR plugin (`{"partial":"..."}` / `{"final":"..."}` / `{"error":"..."}`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn apply_plugin_jsonl_line(
    line: &str,
    outcome: &Mutex<PluginStreamOutcome>,
    cv: &Condvar,
    state: &Mutex<AsrState>,
    cb: &AsrCallback,
) {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return;
    }
    let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
        return;
    };
    let mut notify_snap: Option<AsrState> = None;
    {
        let mut out = outcome.lock().unwrap();
        if let Some(err) = val.get("error").and_then(Value::as_str) {
            let e = err.trim();
            if !e.is_empty() {
                out.error = Some(e.to_string());
                cv.notify_all();
            }
        }
        if let Some(fin) = val.get("final").and_then(Value::as_str) {
            out.final_text = Some(fin.trim().to_string());
            cv.notify_all();
        } else if let Some(par) = val.get("partial").and_then(Value::as_str) {
            let p = par.trim();
            if !p.is_empty() && p != out.latest_partial {
                out.latest_partial = p.to_string();
                let mut st = state.lock().unwrap();
                if st.recording || st.busy {
                    st.partial = p.to_string();
                    notify_snap = Some(st.clone());
                }
            }
        }
    }
    if let Some(snap) = notify_snap {
        cb(AsrEvent::StateChanged(snap));
    }
}

fn run_live_capture(
    target_key: String,
    settings: PersistedSettings,
    stop_flag: Arc<AtomicBool>,
    cancel_flag: Arc<AtomicBool>,
    state: Arc<Mutex<AsrState>>,
    cb: AsrCallback,
) {
    let provider = settings.provider_enum();
    if matches!(provider, AsrProvider::DoubaoFree | AsrProvider::Plugin) {
        run_plugin_streaming_capture(target_key, provider, stop_flag, cancel_flag, state, cb);
        return;
    }

    let capture_res = capture_pcm_16k(&stop_flag, &state, &cb);
    if cancel_flag.load(Ordering::Acquire) {
        let mut st = state.lock().unwrap();
        st.recording = false;
        st.busy = false;
        st.level = 0.0;
        st.partial.clear();
        st.error = None;
        let snap = st.clone();
        drop(st);
        cb(AsrEvent::StateChanged(snap));
        return;
    }
    let samples = match capture_res {
        Ok(s) if s.len() >= 1600 => s,
        Ok(_) => {
            let mut st = state.lock().unwrap();
            st.recording = false;
            st.busy = false;
            st.level = 0.0;
            st.partial.clear();
            st.error = Some("录音太短，已取消".into());
            let snap = st.clone();
            drop(st);
            cb(AsrEvent::StateChanged(snap));
            return;
        }
        Err(err) => {
            let mut st = state.lock().unwrap();
            st.recording = false;
            st.busy = false;
            st.level = 0.0;
            st.partial.clear();
            st.error = Some(err);
            let snap = st.clone();
            drop(st);
            cb(AsrEvent::StateChanged(snap));
            return;
        }
    };

    {
        let mut st = state.lock().unwrap();
        st.recording = false;
        st.busy = true;
        st.level = 0.0;
        st.partial = "云端识别中…".into();
        let snap = st.clone();
        drop(st);
        cb(AsrEvent::StateChanged(snap));
    }

    let wav_bytes = encode_wav_16k_mono(&samples);
    match transcribe_cloud(&settings, &wav_bytes) {
        Ok(text) => {
            let trimmed = text.trim().to_string();
            if !trimmed.is_empty() && !cancel_flag.load(Ordering::Acquire) {
                cb(AsrEvent::Transcript {
                    target_key,
                    text: trimmed,
                });
            }
            let mut st = state.lock().unwrap();
            st.busy = false;
            st.partial.clear();
            st.error = None;
            let snap = st.clone();
            drop(st);
            cb(AsrEvent::StateChanged(snap));
        }
        Err(err) => {
            let mut st = state.lock().unwrap();
            st.busy = false;
            st.partial.clear();
            st.error = Some(err);
            let snap = st.clone();
            drop(st);
            cb(AsrEvent::StateChanged(snap));
        }
    }
}

fn finish_asr_error(state: &Mutex<AsrState>, cb: &AsrCallback, msg: impl Into<String>) {
    let mut st = state.lock().unwrap();
    st.recording = false;
    st.busy = false;
    st.level = 0.0;
    st.partial.clear();
    st.error = Some(msg.into());
    let snap = st.clone();
    drop(st);
    cb(AsrEvent::StateChanged(snap));
}

fn run_plugin_streaming_capture(
    target_key: String,
    provider: AsrProvider,
    stop_flag: Arc<AtomicBool>,
    cancel_flag: Arc<AtomicBool>,
    state: Arc<Mutex<AsrState>>,
    cb: AsrCallback,
) {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (target_key, provider, stop_flag, cancel_flag);
        finish_asr_error(
            &state,
            &cb,
            "实机麦克风录音仅支持 CardputerZero Linux（macOS 请使用 --mock）",
        );
    }

    #[cfg(target_os = "linux")]
    {
        let Some(plugin_path) = resolve_plugin_path(provider) else {
            finish_asr_error(&state, &cb, "未找到语音识别插件");
            return;
        };

        let is_py = plugin_path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("py"))
            || provider == AsrProvider::DoubaoFree;
        let mut plugin_cmd = if is_py {
            let mut c = Command::new("python3");
            c.arg(&plugin_path);
            c
        } else {
            Command::new(&plugin_path)
        };
        plugin_cmd
            .env("PYTHONUNBUFFERED", "1")
            .env("REX_ZERO_ASR_SAMPLE_RATE", "16000")
            .env(
                "REX_ZERO_CONFIG_DIR",
                crate::rex::transport::config_dir(),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut plugin_child = match plugin_cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                finish_asr_error(&state, &cb, format!("启动语音插件失败: {e}"));
                return;
            }
        };

        let Some(mut plugin_stdin) = plugin_child.stdin.take() else {
            let _ = plugin_child.kill();
            let _ = plugin_child.wait();
            finish_asr_error(&state, &cb, "语音插件输入管道不可用");
            return;
        };
        let Some(plugin_stdout) = plugin_child.stdout.take() else {
            drop(plugin_stdin);
            let _ = plugin_child.kill();
            let _ = plugin_child.wait();
            finish_asr_error(&state, &cb, "语音插件输出管道不可用");
            return;
        };

        let outcome = Arc::new((Mutex::new(PluginStreamOutcome::default()), Condvar::new()));
        let outcome_reader = outcome.clone();
        let state_reader = state.clone();
        let cb_reader = cb.clone();
        let reader_handle = thread::Builder::new()
            .name("rex-zero-asr-out".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                let mut rdr = BufReader::new(plugin_stdout);
                let deadline = Instant::now() + Duration::from_secs((MAX_RECORD_SECS + 15) as u64);
                while let Ok(Some(line)) = read_line_bounded(&mut rdr, 16 * 1024, deadline) {
                    apply_plugin_jsonl_line(
                        &line,
                        &outcome_reader.0,
                        &outcome_reader.1,
                        &state_reader,
                        &cb_reader,
                    );
                }
                let mut out = outcome_reader.0.lock().unwrap();
                out.eof = true;
                outcome_reader.1.notify_all();
            });

        let pcm_dev = detect_linux_capture_pcm();
        let mut rec_child = match Command::new("arecord")
            .args([
                "-q",
                "-D",
                &pcm_dev,
                "-f",
                "S16_LE",
                "-r",
                "16000",
                "-c",
                "1",
                "-t",
                "raw",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                drop(plugin_stdin);
                let _ = plugin_child.kill();
                let _ = plugin_child.wait();
                if let Ok(h) = reader_handle {
                    let _ = h.join();
                }
                finish_asr_error(&state, &cb, format!("无法启动麦克风 ({pcm_dev}): {e}"));
                return;
            }
        };

        let mut total_pcm_bytes = 0usize;
        if let Some(mut rec_stdout) = rec_child.stdout.take() {
            let fd = rec_stdout.as_raw_fd();
            let stdin_fd = plugin_stdin.as_raw_fd();
            if set_fd_nonblocking(fd).is_ok() && set_fd_nonblocking(stdin_fd).is_ok() {
                let capture_deadline = Instant::now() + Duration::from_secs(MAX_RECORD_SECS as u64);
                let started = Instant::now();
                let mut last_emit = Instant::now();
                let mut raw_buf = [0u8; 1600];
                let mut carry: Option<u8> = None;
                let mut sum_sq = 0.0f64;
                let mut rms_count = 0usize;

                while !stop_flag.load(Ordering::Acquire)
                    && !cancel_flag.load(Ordering::Acquire)
                    && total_pcm_bytes < MAX_SAMPLES * 2
                    && Instant::now() < capture_deadline
                {
                    if outcome.0.lock().unwrap().error.is_some() {
                        break;
                    }
                    let rem = capture_deadline.saturating_duration_since(Instant::now());
                    let timeout_ms = rem.as_millis().min(100).max(1) as i32;
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
                    if rc <= 0 {
                        continue;
                    }
                    if (pfd.revents & libc::POLLNVAL) != 0 {
                        break;
                    }
                    if (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
                        match rec_stdout.read(&mut raw_buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                total_pcm_bytes = total_pcm_bytes.saturating_add(n);
                                let mut written = 0usize;
                                let mut write_aborted = false;
                                while written < n {
                                    if stop_flag.load(Ordering::Acquire)
                                        || cancel_flag.load(Ordering::Acquire)
                                        || Instant::now() >= capture_deadline
                                        || outcome.0.lock().unwrap().error.is_some()
                                    {
                                        write_aborted = true;
                                        break;
                                    }
                                    match plugin_stdin.write(&raw_buf[written..n]) {
                                        Ok(0) => {
                                            write_aborted = true;
                                            break;
                                        }
                                        Ok(w) => written += w,
                                        Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                            let mut out_pfd = libc::pollfd {
                                                fd: stdin_fd,
                                                events: libc::POLLOUT,
                                                revents: 0,
                                            };
                                            let _ = unsafe { libc::poll(&mut out_pfd, 1, 25) };
                                            if (out_pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                                                write_aborted = true;
                                                break;
                                            }
                                        }
                                        Err(_) => {
                                            write_aborted = true;
                                            break;
                                        }
                                    }
                                }
                                if write_aborted {
                                    break;
                                }
                                let _ = plugin_stdin.flush();

                                let mut idx = 0usize;
                                if let Some(prev) = carry.take() {
                                    if n > 0 {
                                        let s = i16::from_le_bytes([prev, raw_buf[0]]);
                                        let norm = s as f64 / 32768.0;
                                        sum_sq += norm * norm;
                                        rms_count += 1;
                                        idx = 1;
                                    }
                                }
                                while idx + 1 < n {
                                    let s = i16::from_le_bytes([raw_buf[idx], raw_buf[idx + 1]]);
                                    let norm = s as f64 / 32768.0;
                                    sum_sq += norm * norm;
                                    rms_count += 1;
                                    idx += 2;
                                }
                                if idx < n {
                                    carry = Some(raw_buf[idx]);
                                }
                                if rms_count > 0 && last_emit.elapsed() >= Duration::from_millis(120) {
                                    let rms = (sum_sq / rms_count as f64).sqrt() as f32;
                                    let level = (rms * 4.5).clamp(0.04, 1.0);
                                    let secs = started.elapsed().as_secs_f32();
                                    let has_live_words =
                                        !outcome.0.lock().unwrap().latest_partial.is_empty();
                                    let snap = {
                                        let mut st = state.lock().unwrap();
                                        st.level = level;
                                        if !has_live_words {
                                            st.partial = format!("正在聆听 {secs:.1}s…");
                                        }
                                        st.clone()
                                    };
                                    cb(AsrEvent::StateChanged(snap));
                                    last_emit = Instant::now();
                                    sum_sq = 0.0;
                                    rms_count = 0;
                                }
                            }
                            Err(e)
                                if e.kind() == ErrorKind::WouldBlock
                                    || e.kind() == ErrorKind::Interrupted =>
                            {
                                continue;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        }

        let _ = rec_child.kill();
        let _ = rec_child.wait();

        if cancel_flag.load(Ordering::Acquire) {
            drop(plugin_stdin);
            let _ = plugin_child.kill();
            let _ = plugin_child.wait();
            if let Ok(h) = reader_handle {
                let _ = h.join();
            }
            let mut st = state.lock().unwrap();
            st.recording = false;
            st.busy = false;
            st.level = 0.0;
            st.partial.clear();
            st.error = None;
            let snap = st.clone();
            drop(st);
            cb(AsrEvent::StateChanged(snap));
            return;
        }

        if total_pcm_bytes < 3200 {
            drop(plugin_stdin);
            let _ = plugin_child.kill();
            let _ = plugin_child.wait();
            if let Ok(h) = reader_handle {
                let _ = h.join();
            }
            finish_asr_error(&state, &cb, "录音太短，已取消");
            return;
        }

        // Close stdin -> plugin sends FinishSession and emits `{"final": "..."}`.
        drop(plugin_stdin);
        {
            let latest = outcome.0.lock().unwrap().latest_partial.clone();
            let mut st = state.lock().unwrap();
            st.recording = false;
            st.busy = true;
            st.level = 0.0;
            st.partial = if latest.is_empty() {
                "正在收尾识别…".into()
            } else {
                latest
            };
            let snap = st.clone();
            drop(st);
            cb(AsrEvent::StateChanged(snap));
        }

        let fin_deadline = Instant::now() + Duration::from_millis(5500);
        {
            let mut out = outcome.0.lock().unwrap();
            while out.final_text.is_none()
                && out.error.is_none()
                && !out.eof
                && !cancel_flag.load(Ordering::Acquire)
            {
                let Some(rem) = fin_deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                if rem.is_zero() {
                    break;
                }
                let slice = rem.min(Duration::from_millis(100));
                let (next_out, _) = outcome.1.wait_timeout(out, slice).unwrap();
                out = next_out;
            }
        }

        let _ = plugin_child.kill();
        let _ = plugin_child.wait();
        if let Ok(h) = reader_handle {
            let _ = h.join();
        }

        if cancel_flag.load(Ordering::Acquire) {
            let mut st = state.lock().unwrap();
            st.busy = false;
            st.partial.clear();
            st.error = None;
            let snap = st.clone();
            drop(st);
            cb(AsrEvent::StateChanged(snap));
            return;
        }

        let (final_opt, latest_par, err_opt) = {
            let out = outcome.0.lock().unwrap();
            (
                out.final_text.clone(),
                out.latest_partial.clone(),
                out.error.clone(),
            )
        };
        let clean_final = final_opt
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        if clean_final.is_none() {
            if let Some(err) = err_opt {
                finish_asr_error(&state, &cb, err);
                return;
            }
        }

        let resolved = clean_final.unwrap_or_else(|| latest_par.trim().to_string());

        if !resolved.is_empty() {
            cb(AsrEvent::Transcript {
                target_key,
                text: resolved,
            });
            let mut st = state.lock().unwrap();
            st.busy = false;
            st.partial.clear();
            st.error = None;
            let snap = st.clone();
            drop(st);
            cb(AsrEvent::StateChanged(snap));
        } else {
            finish_asr_error(&state, &cb, "未识别到清晰语音");
        }
    }
}

fn capture_pcm_16k(
    stop_flag: &AtomicBool,
    state: &Mutex<AsrState>,
    cb: &AsrCallback,
) -> Result<Vec<i16>, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (stop_flag, state, cb);
        Err("实机麦克风录音仅支持 CardputerZero Linux（macOS 请使用 --mock）".into())
    }

    #[cfg(target_os = "linux")]
    {
        let pcm_dev = detect_linux_capture_pcm();
        let mut child = Command::new("arecord")
            .args([
                "-q",
                "-D",
                &pcm_dev,
                "-f",
                "S16_LE",
                "-r",
                "16000",
                "-c",
                "1",
                "-t",
                "raw",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("无法启动 arecord ({pcm_dev}): {e}"))?;

        let Some(mut stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("arecord 无音频流输出".into());
        };

        let fd = stdout.as_raw_fd();
        let deadline = Instant::now() + Duration::from_secs(MAX_RECORD_SECS as u64);
        let res = read_pcm_from_fd(&mut stdout, fd, stop_flag, deadline, state, cb);

        let _ = child.kill();
        let _ = child.wait();
        res
    }
}

#[allow(dead_code)]
fn set_fd_nonblocking(fd: RawFd) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "fcntl(F_GETFL) 失败: {}",
            std::io::Error::last_os_error()
        ));
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(format!(
            "fcntl(F_SETFL) 失败: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Interruptible non-blocking + `poll()` PCM capture loop with hard wall-clock
/// deadline so a stalled `arecord` never blocks `stop_flag` or child cleanup.
#[allow(dead_code)]
fn read_pcm_from_fd<R: Read>(
    reader: &mut R,
    fd: RawFd,
    stop_flag: &AtomicBool,
    capture_deadline: Instant,
    state: &Mutex<AsrState>,
    cb: &AsrCallback,
) -> Result<Vec<i16>, String> {
    set_fd_nonblocking(fd)?;

    let mut samples: Vec<i16> = Vec::with_capacity(SAMPLE_RATE as usize * 10);
    let mut raw_buf = [0u8; 1600];
    let mut carry: Option<u8> = None;
    let started = Instant::now();
    let mut last_emit = Instant::now();
    let mut sum_sq = 0.0f64;
    let mut rms_count = 0usize;

    while !stop_flag.load(Ordering::Acquire)
        && samples.len() < MAX_SAMPLES
        && Instant::now() < capture_deadline
    {
        let rem = capture_deadline.saturating_duration_since(Instant::now());
        let timeout_ms = rem.as_millis().min(100).max(1) as i32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc == 0 {
            continue;
        }
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if (pfd.revents & libc::POLLNVAL) != 0 {
            break;
        }
        if (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            match reader.read(&mut raw_buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut idx = 0usize;
                    if let Some(prev) = carry.take() {
                        if n > 0 && samples.len() < MAX_SAMPLES {
                            let s = i16::from_le_bytes([prev, raw_buf[0]]);
                            samples.push(s);
                            let norm = s as f64 / 32768.0;
                            sum_sq += norm * norm;
                            rms_count += 1;
                            idx = 1;
                        }
                    }
                    while idx + 1 < n && samples.len() < MAX_SAMPLES {
                        let s = i16::from_le_bytes([raw_buf[idx], raw_buf[idx + 1]]);
                        samples.push(s);
                        let norm = s as f64 / 32768.0;
                        sum_sq += norm * norm;
                        rms_count += 1;
                        idx += 2;
                    }
                    if idx < n && samples.len() < MAX_SAMPLES {
                        carry = Some(raw_buf[idx]);
                    }
                    if rms_count > 0 && last_emit.elapsed() >= Duration::from_millis(120) {
                        let rms = (sum_sq / rms_count as f64).sqrt() as f32;
                        let level = (rms * 4.5).clamp(0.04, 1.0);
                        let secs = started.elapsed().as_secs_f32();
                        let snap = {
                            let mut st = state.lock().unwrap();
                            st.level = level;
                            st.partial = format!("正在聆听 {secs:.1}s…");
                            st.clone()
                        };
                        cb(AsrEvent::StateChanged(snap));
                        last_emit = Instant::now();
                        sum_sq = 0.0;
                        rms_count = 0;
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {
                    continue;
                }
                Err(_) => break,
            }
        }
    }

    Ok(samples)
}

#[cfg(target_os = "linux")]
fn detect_linux_capture_pcm() -> String {
    if let Ok(cards) = std::fs::read_to_string("/proc/asound/cards") {
        for line in cards.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.contains("es8389") || lower.contains("es83") || lower.contains("codec") {
                if let Some(num_str) = line.trim_start().split_whitespace().next() {
                    if let Ok(card_idx) = num_str.parse::<u32>() {
                        return format!("plughw:{card_idx},0");
                    }
                }
            }
        }
    }
    "default".into()
}

pub fn encode_wav_16k_mono(samples: &[i16]) -> Vec<u8> {
    let data_bytes = (samples.len() * 2) as u32;
    let mut out = Vec::with_capacity(44 + data_bytes as usize);
    out.extend_from_slice(b"RIFF");
    out.extend_from_slice(&(36 + data_bytes).to_le_bytes());
    out.extend_from_slice(b"WAVEfmt ");
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); // PCM
    out.extend_from_slice(&1u16.to_le_bytes()); // mono
    out.extend_from_slice(&SAMPLE_RATE.to_le_bytes());
    out.extend_from_slice(&(SAMPLE_RATE * 2).to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&16u16.to_le_bytes());
    out.extend_from_slice(b"data");
    out.extend_from_slice(&data_bytes.to_le_bytes());
    for &s in samples {
        out.extend_from_slice(&s.to_le_bytes());
    }
    out
}

fn transcribe_cloud(settings: &PersistedSettings, wav_bytes: &[u8]) -> Result<String, String> {
    let provider = settings.provider_enum();
    let api_key = settings.effective_api_key(provider);
    let custom_ep = settings.effective_endpoint(provider);

    match provider {
        AsrProvider::Openai | AsrProvider::Groq => {
            let default_base = match provider {
                AsrProvider::Groq => "https://api.groq.com/openai/v1/audio/transcriptions",
                _ => "https://api.openai.com/v1/audio/transcriptions",
            };
            let url = custom_ep
                .map(|ep| {
                    if ep.contains("/audio/transcriptions") {
                        ep.to_string()
                    } else {
                        format!(
                            "{}/v1/audio/transcriptions",
                            ep.trim_end_matches('/')
                        )
                    }
                })
                .unwrap_or_else(|| default_base.to_string());
            let model = match provider {
                AsrProvider::Groq => "whisper-large-v3-turbo",
                _ => "whisper-1",
            };
            let boundary = "----RexZeroAsrBoundary9f8e7d6c";
            let body = build_multipart_wav(
                boundary,
                "file",
                wav_bytes,
                &[("model", model), ("language", "zh")],
            );
            let ct = format!("multipart/form-data; boundary={boundary}");
            let auth = format!("Bearer {api_key}");
            let resp = https_post(&url, &[("Authorization", &auth), ("Content-Type", &ct)], &body)?;
            let val: Value =
                serde_json::from_slice(&resp).map_err(|_| "ASR 响应非有效 JSON".to_string())?;
            val.get("text")
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .ok_or_else(|| format_missing_text_error("ASR", &val))
        }
        AsrProvider::Elevenlabs => {
            let url = custom_ep.unwrap_or("https://api.elevenlabs.io/v1/speech-to-text");
            let boundary = "----RexZeroAsrBoundary9f8e7d6c";
            let body =
                build_multipart_wav(boundary, "file", wav_bytes, &[("model_id", "scribe_v1")]);
            let ct = format!("multipart/form-data; boundary={boundary}");
            let resp = https_post(url, &[("xi-api-key", api_key), ("Content-Type", &ct)], &body)?;
            let val: Value = serde_json::from_slice(&resp)
                .map_err(|_| "ElevenLabs 响应非有效 JSON".to_string())?;
            val.get("text")
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .ok_or_else(|| format_missing_text_error("ElevenLabs", &val))
        }
        AsrProvider::DoubaoFree | AsrProvider::Plugin => {
            Err("插件流式识别不走 WAV 上传通道".into())
        }
        AsrProvider::Doubao => {
            let url = custom_ep
                .unwrap_or("https://openspeech.bytedance.com/api/v3/auc/bigmodel/recognize/flash");
            let app_id = settings.effective_app_id(provider).unwrap_or("");
            let req_id = format!(
                "rex-zero-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
            );
            let payload = json!({
                "user": { "uid": "rex-zero" },
                "audio": {
                    "format": "wav",
                    "rate": 16000,
                    "bits": 16,
                    "channel": 1,
                    "data": BASE64_STD.encode(wav_bytes),
                },
                "request": { "model_name": "bigmodel" }
            });
            let body = serde_json::to_vec(&payload).unwrap_or_default();
            let resp = https_post(
                url,
                &[
                    ("Content-Type", "application/json"),
                    ("X-Api-Key", api_key),
                    ("X-Api-Access-Key", api_key),
                    ("X-Api-App-Key", app_id),
                    ("X-Api-Resource-Id", "volc.bigasr.auc_turbo"),
                    ("X-Api-Request-Id", &req_id),
                    ("X-Api-Sequence", "-1"),
                ],
                &body,
            )?;
            let val: Value = serde_json::from_slice(&resp)
                .map_err(|_| "豆包 ASR 响应非有效 JSON".to_string())?;
            val.pointer("/result/text")
                .or_else(|| val.get("text"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
                .ok_or_else(|| format_missing_text_error("豆包 ASR", &val))
        }
    }
}

fn build_multipart_wav(
    boundary: &str,
    file_field: &str,
    wav_bytes: &[u8],
    fields: &[(&str, &str)],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(wav_bytes.len() + 512);
    for &(k, v) in fields {
        out.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n"
            )
            .as_bytes(),
        );
    }
    out.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; filename=\"speech.wav\"\r\nContent-Type: audio/wav\r\n\r\n"
        )
        .as_bytes(),
    );
    out.extend_from_slice(wav_bytes);
    out.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    out
}

struct ParsedAsrUrl<'a> {
    tls: bool,
    authority: &'a str,
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_and_validate_asr_url(url: &str, allow_test_loopback: bool) -> Result<ParsedAsrUrl<'_>, String> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        if !allow_test_loopback {
            return Err("ASR 接口必须使用 https:// 加密连接".into());
        }
        (false, r)
    } else {
        return Err("ASR 接口必须使用 https:// 加密连接".into());
    };

    if rest.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("ASR URL 包含非法字符".into());
    }

    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err("ASR URL 主机无效".into());
    }

    let (host, port) = if let Some(bracket_rest) = authority.strip_prefix('[') {
        let Some((h, after)) = bracket_rest.split_once(']') else {
            return Err("ASR IPv6 地址格式无效".into());
        };
        let p = if after.is_empty() {
            if tls { 443 } else { 80 }
        } else if let Some(ps) = after.strip_prefix(':') {
            ps.parse::<u16>().map_err(|_| "bad ASR port")?
        } else {
            return Err("ASR 端口格式无效".into());
        };
        (h, p)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().map_err(|_| "bad ASR port")?),
            None => (authority, if tls { 443 } else { 80 }),
        }
    };

    if host.is_empty() {
        return Err("ASR 主机名为空".into());
    }

    if !tls && !(host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost")) {
        return Err("ASR 接口必须使用 https:// 加密连接".into());
    }

    Ok(ParsedAsrUrl {
        tls,
        authority,
        host,
        port,
        path,
    })
}

struct DeadlineTcp {
    inner: TcpStream,
    deadline: Instant,
}

impl DeadlineTcp {
    fn new(inner: TcpStream, deadline: Instant) -> Self {
        Self { inner, deadline }
    }

    fn remaining(&self) -> std::io::Result<Duration> {
        let Some(rem) = self.deadline.checked_duration_since(Instant::now()) else {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "ASR request deadline exceeded",
            ));
        };
        if rem.is_zero() {
            return Err(std::io::Error::new(
                ErrorKind::TimedOut,
                "ASR request deadline exceeded",
            ));
        }
        Ok(rem)
    }
}

impl Read for DeadlineTcp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let rem = self.remaining()?;
            let _ = self.inner.set_read_timeout(Some(rem));
            match self.inner.read(buf) {
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                other => return other,
            }
        }
    }
}

impl Write for DeadlineTcp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let rem = self.remaining()?;
            let _ = self.inner.set_write_timeout(Some(rem));
            match self.inner.write(buf) {
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                other => return other,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = self.remaining()?;
        self.inner.flush()
    }
}

fn https_post(url: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<Vec<u8>, String> {
    https_post_with_deadline(url, headers, body, ASR_REQUEST_DEADLINE)
}

fn https_post_with_deadline(
    url: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    total_timeout: Duration,
) -> Result<Vec<u8>, String> {
    let parsed = parse_and_validate_asr_url(url, cfg!(test))?;
    let deadline = Instant::now() + total_timeout;
    let connect_timeout = deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| "ASR 请求超时".to_string())?;

    let tcp = connect_tcp_with_env_proxy(parsed.host, parsed.port, connect_timeout)
        .map_err(|e| format!("ASR 网络连接失败 ({}:{}): {e}", parsed.host, parsed.port))?;
    let deadline_tcp = DeadlineTcp::new(tcp, deadline);

    let mut req_head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        parsed.path,
        parsed.authority,
        body.len()
    );
    for &(k, v) in headers {
        req_head.push_str(&format!("{k}: {v}\r\n"));
    }
    req_head.push_str("\r\n");

    if parsed.tls {
        let server_name = ServerName::try_from(parsed.host.to_string())
            .map_err(|e| format!("bad TLS host {}: {e}", parsed.host))?;
        let conn = ClientConnection::new(shared_tls_config(), server_name)
            .map_err(|e| format!("TLS init: {e}"))?;
        let mut stream = StreamOwned::new(conn, deadline_tcp);
        write_request_chunked(&mut stream, req_head.as_bytes(), body)
            .map_err(|e| format!("ASR TLS write: {e}"))?;
        read_http_body(stream, deadline)
    } else {
        let mut stream = deadline_tcp;
        write_request_chunked(&mut stream, req_head.as_bytes(), body)
            .map_err(|e| format!("ASR HTTP write: {e}"))?;
        read_http_body(stream, deadline)
    }
}

fn write_request_chunked<W: Write>(stream: &mut W, head: &[u8], body: &[u8]) -> std::io::Result<()> {
    stream.write_all(head)?;
    for chunk in body.chunks(16 * 1024) {
        stream.write_all(chunk)?;
    }
    stream.flush()
}

fn check_deadline(deadline: Instant) -> Result<(), String> {
    if Instant::now() >= deadline {
        Err("ASR 请求超时".into())
    } else {
        Ok(())
    }
}

/// Reads a single `\n`-terminated line strictly capped at `max_bytes` WITHOUT
/// allocating unbounded memory before checking the cap.
fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
    deadline: Instant,
) -> Result<Option<String>, String> {
    let mut buf = Vec::new();
    loop {
        check_deadline(deadline)?;
        let available = reader
            .fill_buf()
            .map_err(|e| format!("ASR HTTP read: {e}"))?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if buf.len().checked_add(take).is_none_or(|n| n > max_bytes) {
                return Err("ASR 响应行超过安全上限".into());
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
        }
        let avail_len = available.len();
        if buf.len().checked_add(avail_len).is_none_or(|n| n > max_bytes) {
            return Err("ASR 响应行超过安全上限".into());
        }
        buf.extend_from_slice(available);
        reader.consume(avail_len);
    }
}

fn read_http_body(stream: impl Read, deadline: Instant) -> Result<Vec<u8>, String> {
    let mut reader = BufReader::new(stream);
    let mut header_bytes = 0usize;

    let status_line = read_line_bounded(&mut reader, MAX_ASR_HEADER_BYTES, deadline)?
        .ok_or_else(|| "ASR HTTP 空响应".to_string())?;
    header_bytes = header_bytes.saturating_add(status_line.len());

    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let mut chunked = false;
    let mut content_length: Option<usize> = None;
    let mut header_lines = 0usize;
    loop {
        let rem_budget = MAX_ASR_HEADER_BYTES.saturating_sub(header_bytes);
        if rem_budget == 0 {
            return Err("ASR 响应头超过 16 KiB 上限".into());
        }
        let Some(line) = read_line_bounded(&mut reader, rem_budget, deadline)? else {
            break;
        };
        header_bytes = header_bytes.saturating_add(line.len());
        if line.trim().is_empty() {
            break;
        }
        header_lines += 1;
        if header_lines > MAX_ASR_HEADER_LINES {
            return Err("ASR 响应头行数超过上限".into());
        }
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            } else if k.eq_ignore_ascii_case("content-length") {
                if let Ok(len) = v.parse::<usize>() {
                    if len > MAX_ASR_RESPONSE_BYTES {
                        return Err("ASR 响应体超过 512 KiB 上限".into());
                    }
                    content_length = Some(len);
                }
            }
        }
    }

    let mut body = Vec::new();
    let mut scratch = [0u8; 8192];
    if chunked {
        loop {
            check_deadline(deadline)?;
            let sz_line = read_line_bounded(&mut reader, MAX_CHUNK_LINE_BYTES, deadline)?
                .ok_or_else(|| "ASR 分块响应意外结束".to_string())?;
            let hex_part = sz_line
                .trim()
                .split(';')
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| "ASR 分块长度格式无效".to_string())?;
            let sz = usize::from_str_radix(hex_part, 16)
                .map_err(|_| "ASR 分块长度格式无效".to_string())?;
            if sz == 0 {
                break;
            }
            // Checked arithmetic BEFORE reading or growing `body`!
            let next_total = body
                .len()
                .checked_add(sz)
                .filter(|&t| t <= MAX_ASR_RESPONSE_BYTES)
                .ok_or_else(|| "ASR 分块响应体超过 512 KiB 上限".to_string())?;
            let _ = next_total;

            let mut remaining = sz;
            while remaining > 0 {
                check_deadline(deadline)?;
                let want = remaining.min(scratch.len());
                let n = reader
                    .read(&mut scratch[..want])
                    .map_err(|e| format!("ASR 分块读取失败: {e}"))?;
                if n == 0 {
                    return Err("ASR 分块数据被截断".into());
                }
                body.extend_from_slice(&scratch[..n]);
                remaining -= n;
            }
            // Consume trailing CRLF after chunk payload with bounded line read.
            let crlf = read_line_bounded(&mut reader, MAX_CHUNK_LINE_BYTES, deadline)?
                .ok_or_else(|| "ASR 分块缺少结尾换行".to_string())?;
            if !crlf.trim().is_empty() {
                return Err("ASR 分块结尾格式无效".into());
            }
        }
    } else {
        let cap = content_length.unwrap_or(MAX_ASR_RESPONSE_BYTES);
        loop {
            if content_length.is_some() && body.len() >= cap {
                body.truncate(cap);
                break;
            }
            check_deadline(deadline)?;
            let want = if content_length.is_some() {
                (cap - body.len()).min(scratch.len())
            } else {
                scratch.len()
            };
            let n = reader
                .read(&mut scratch[..want])
                .map_err(|e| format!("ASR 响应读取失败: {e}"))?;
            if n == 0 {
                break;
            }
            if body.len().checked_add(n).is_none_or(|t| t > MAX_ASR_RESPONSE_BYTES) {
                return Err("ASR 响应体超过 512 KiB 上限".into());
            }
            body.extend_from_slice(&scratch[..n]);
        }
    }

    if !(200..300).contains(&status) {
        return Err(format_sanitized_http_error(status, &body));
    }
    Ok(body)
}

fn allowlisted_error_code(raw: &str) -> Option<&'static str> {
    match raw.trim() {
        "invalid_api_key" => Some("invalid_api_key"),
        "authentication_error" => Some("authentication_error"),
        "unauthorized" => Some("unauthorized"),
        "insufficient_quota" => Some("insufficient_quota"),
        "billing_hard_limit_reached" => Some("billing_hard_limit_reached"),
        "rate_limit_exceeded" => Some("rate_limit_exceeded"),
        "too_many_requests" => Some("too_many_requests"),
        "model_not_found" => Some("model_not_found"),
        "invalid_request_error" => Some("invalid_request_error"),
        "audio_too_short" => Some("audio_too_short"),
        "unsupported_format" => Some("unsupported_format"),
        "server_error" => Some("server_error"),
        "timeout" => Some("timeout"),
        _ => None,
    }
}

fn extract_allowlisted_error_code(val: &Value) -> Option<&'static str> {
    let candidates = [
        val.pointer("/error/code"),
        val.pointer("/error/type"),
        val.get("error_code"),
        val.get("code"),
    ];
    for cand in candidates.into_iter().flatten() {
        if let Value::String(st) = cand {
            if let Some(mapped) = allowlisted_error_code(st) {
                return Some(mapped);
            }
        }
    }
    None
}

fn format_sanitized_http_error(status: u16, body: &[u8]) -> String {
    if let Ok(val) = serde_json::from_slice::<Value>(body) {
        if let Some(code) = extract_allowlisted_error_code(&val) {
            return format!("ASR HTTP {status} ({code})");
        }
    }
    format!("ASR HTTP {status}")
}

fn format_missing_text_error(provider_label: &str, val: &Value) -> String {
    if let Some(code) = extract_allowlisted_error_code(val) {
        return format!("{provider_label} 未返回文本 ({code})");
    }
    format!("{provider_label} 未返回文本")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::os::fd::FromRawFd;

    #[test]
    fn wav_encoder_builds_valid_16k_mono_header() {
        let wav = encode_wav_16k_mono(&[0, 1000, -1000, 32767]);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(wav.len(), 44 + 8);
    }

    #[test]
    fn rejects_plaintext_http_endpoints_in_production_validator() {
        assert!(parse_and_validate_asr_url("http://api.openai.com/v1/audio/transcriptions", false).is_err());
        assert!(parse_and_validate_asr_url("http://127.0.0.1:8080/v1", false).is_err());
        assert!(parse_and_validate_asr_url("http://api.openai.com/v1", true).is_err());
        assert!(parse_and_validate_asr_url("https://api.openai.com/v1/audio/transcriptions", false).is_ok());
        assert!(parse_and_validate_asr_url("http://127.0.0.1:8080/v1", true).is_ok());
    }

    #[test]
    fn scrubs_provider_error_bodies_and_missing_text_json() {
        let secret = "sk-super-secret-api-key-9999";
        let raw = format!(
            r#"{{"error":{{"code":"invalid_api_key","message":"Incorrect API key provided: {secret}"}}}}"#
        );
        let msg = format_sanitized_http_error(401, raw.as_bytes());
        assert_eq!(msg, "ASR HTTP 401 (invalid_api_key)");
        assert!(!msg.contains(secret));

        // Secret placed directly inside `error.code` (even if ASCII-alphanumeric/hyphen)
        // must NEVER be echoed into the sanitized error string.
        let secret_in_code = format!(r#"{{"error":{{"code":"{secret}"}}}}"#);
        let msg2 = format_sanitized_http_error(401, secret_in_code.as_bytes());
        assert_eq!(msg2, "ASR HTTP 401");
        assert!(!msg2.contains(secret));

        // Unknown `error.type` / `error_code` / numeric `code` must also be omitted.
        let unknown_type = format!(r#"{{"error":{{"type":"{secret}"}},"code":12345}}"#);
        let msg_unknown = format_sanitized_http_error(429, unknown_type.as_bytes());
        assert_eq!(msg_unknown, "ASR HTTP 429");
        assert!(!msg_unknown.contains(secret));

        // Known allowlisted codes map to their static labels.
        let rate_raw = br#"{"error":{"code":"rate_limit_exceeded","message":"slow down"}}"#;
        assert_eq!(
            format_sanitized_http_error(429, rate_raw),
            "ASR HTTP 429 (rate_limit_exceeded)"
        );

        // Missing text on 200 must never leak raw JSON payload or secret in error.code.
        let val = json!({"echo_key": secret, "error": {"code": secret}, "status": "ok"});
        let msg3 = format_missing_text_error("ASR", &val);
        assert_eq!(msg3, "ASR 未返回文本");
        assert!(!msg3.contains(secret));
    }

    #[test]
    fn rejects_oversized_chunk_size_and_oversized_headers_without_oom() {
        let deadline = Instant::now() + Duration::from_secs(5);
        // Malicious huge hex chunk size (e.g. 0x7fffffff bytes) must fail BEFORE allocation.
        let malicious_chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7fffffff\r\nabc";
        let err = read_http_body(&malicious_chunked[..], deadline).unwrap_err();
        assert!(err.contains("上限"), "err={err}");

        // Huge header line > 16 KiB must fail cleanly.
        let mut huge_hdr = b"HTTP/1.1 200 OK\r\nX-Big: ".to_vec();
        huge_hdr.extend(std::iter::repeat(b'a').take(20 * 1024));
        huge_hdr.extend_from_slice(b"\r\n\r\n");
        let err2 = read_http_body(&huge_hdr[..], deadline).unwrap_err();
        assert!(err2.contains("上限"), "err2={err2}");

        // Valid small chunked response still parses cleanly.
        let ok_chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n{\"text\":\"hello\"}\r\n0\r\n\r\n";
        let body = read_http_body(&ok_chunked[..], deadline).unwrap();
        assert_eq!(body, br#"{"text":"hello"}"#);
    }

    #[test]
    fn rolls_back_recording_state_if_worker_spawn_fails() {
        let mut cfg = PersistedSettings::default();
        cfg.asr_api_key = "sk-test".into();
        let events: Arc<Mutex<Vec<AsrState>>> = Arc::default();
        let ev_clone = events.clone();
        let engine = AsrEngine::new(
            cfg,
            false,
            Arc::new(move |ev| {
                if let AsrEvent::StateChanged(s) = ev {
                    ev_clone.lock().unwrap().push(s);
                }
            }),
        );

        let err = engine
            .toggle_with_spawner("mini|s1|b1", |_| {
                Err(std::io::Error::new(ErrorKind::OutOfMemory, "mock spawn failure"))
            })
            .unwrap_err();
        assert!(err.contains("spawn ASR thread"));

        let snap = engine.snapshot();
        assert!(!snap.recording, "recording must be rolled back to false");
        assert!(!snap.busy);
        assert!(snap.error.is_some());
        assert_eq!(events.lock().unwrap().last().map(|s| s.recording), Some(false));
    }

    #[test]
    fn stalled_capture_pipe_is_interrupted_promptly_by_stop_flag() {
        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let mut read_file = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let _write_file = unsafe { std::fs::File::from_raw_fd(fds[1]) };

        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = stop.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(80));
            stop_bg.store(true, Ordering::SeqCst);
        });

        let state = Mutex::new(AsrState::default());
        let cb: AsrCallback = Arc::new(|_| {});
        let t0 = Instant::now();
        let samples = read_pcm_from_fd(
            &mut read_file,
            fds[0],
            &stop,
            Instant::now() + Duration::from_secs(10),
            &state,
            &cb,
        )
        .unwrap();
        assert!(samples.is_empty());
        assert!(
            t0.elapsed() < Duration::from_secs(1),
            "stalled pipe took {:?} to interrupt",
            t0.elapsed()
        );
    }

    #[test]
    fn slow_trickle_http_response_hits_monotonic_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            if let Ok((mut s, _)) = listener.accept() {
                let mut sink = [0u8; 512];
                let _ = s.read(&mut sink);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
                // Trickle 1 byte every 80ms for ~2s — must be aborted by 300ms monotonic deadline!
                for _ in 0..25 {
                    if s.write_all(b"a").is_err() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(80));
                }
            }
        });

        let t0 = Instant::now();
        let url = format!("http://{addr}/v1/audio/transcriptions");
        let res = https_post_with_deadline(&url, &[], b"hi", Duration::from_millis(300));
        assert!(res.is_err(), "trickle server should hit deadline");
        assert!(
            t0.elapsed() < Duration::from_millis(900),
            "deadline took {:?}",
            t0.elapsed()
        );
        let _ = server.join();
    }

    #[test]
    fn streaming_jsonl_protocol_updates_partial_and_final_cleanly() {
        let outcome = Mutex::new(PluginStreamOutcome::default());
        let cv = Condvar::new();
        let state = Mutex::new(AsrState {
            configured: true,
            provider: AsrProvider::DoubaoFree,
            recording: true,
            busy: false,
            target_key: Some("mini|s1|b1".into()),
            partial: "正在聆听…".into(),
            level: 0.2,
            error: None,
        });
        let seen_partials: Arc<Mutex<Vec<String>>> = Arc::default();
        let sp = seen_partials.clone();
        let cb: AsrCallback = Arc::new(move |ev| {
            if let AsrEvent::StateChanged(s) = ev {
                sp.lock().unwrap().push(s.partial);
            }
        });

        apply_plugin_jsonl_line(r#"{"status":"ready"}"#, &outcome, &cv, &state, &cb);
        apply_plugin_jsonl_line(r#"{"partial":"你好"}"#, &outcome, &cv, &state, &cb);
        apply_plugin_jsonl_line(r#"{"partial":"你好世界"}"#, &outcome, &cv, &state, &cb);
        apply_plugin_jsonl_line(r#"{"final":"你好，世界！"}"#, &outcome, &cv, &state, &cb);

        let out = outcome.lock().unwrap();
        assert_eq!(out.latest_partial, "你好世界");
        assert_eq!(out.final_text.as_deref(), Some("你好，世界！"));
        assert!(out.error.is_none());
        assert_eq!(
            *seen_partials.lock().unwrap(),
            vec!["你好".to_string(), "你好世界".to_string()]
        );
    }
}
