//! `RexZeroEngine` (`http://zero/rex/*`): unified state coordinator, `Condvar`
//! zero-polling long-poll (`/rex/wait`), `AttentionLedger` + subtle two-tone audio
//! chimes, and action router across `vt`, `protocol`, `tsnet`, `rime`, `asr`, and `pair`.

pub mod asr;
pub mod mock;
pub mod pair;
pub mod protocol;
pub mod qr;
pub mod rime;
pub mod transport;
pub mod tsnet;
pub mod types;
pub mod vt;

use crate::device::Device;
use asr::{AsrEngine, AsrEvent};
use mock::{build_mock_seed, MockPaneExtra};
use pair::PairManager;
use percent_encoding::percent_decode_str;
use protocol::{HostCmd, HostEvent, HostWorkerHandle};
use rime::RimeIme;
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use transport::{
    classify_endpoint, config_dir, discover_initial_hosts, load_drafts, load_saved_hosts,
    load_settings, normalize_endpoint, save_drafts, save_hosts, save_settings, slug_id,
    write_private_file, ConfiguredHost, Waker,
};
use tsnet::{TailnetUpdate, TsnetSupervisor};
use types::{
    make_pane_key, split_pane_key, ActionReply, AttentionSummary, ChimeKind, ConnPhase,
    FleetSnapshot, HostState, OwnershipMode, PaneActivityStatus, PaneSummary, PaneViewPayload,
    PathKind, PeerAddMode, ReaderMessage, ReaderRole, RexAction, TailnetState, VtViewport,
};
use vt::{synthesize_blocked_approval, VtActor};

pub struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
}

struct SharedBus {
    state: Mutex<EngineState>,
    draft_persist_lock: Mutex<()>,
    hosts_persist_lock: Mutex<()>,
    cv: Condvar,
    ui_wake: Mutex<Option<(Arc<AtomicU64>, Waker)>>,
}

impl SharedBus {
    fn persist_drafts(&self, root: &Path) -> std::io::Result<()> {
        let _writer = self.draft_persist_lock.lock().unwrap();
        let (drafts, persisted_vers) = {
            let st = self.state.lock().unwrap();
            (
                committed_drafts_for_disk(&st),
                collect_eligible_unpersisted_vers(&st),
            )
        };
        save_drafts(root, &drafts)?;
        if !persisted_vers.is_empty() {
            let mut st = self.state.lock().unwrap();
            if clear_eligible_unpersisted_vers(&mut st, persisted_vers) {
                st.revision += 1;
                self.notify_ui();
            }
        }
        Ok(())
    }

    fn notify_ui(&self) {
        self.cv.notify_all();
        if let Some((seq, waker)) = self.ui_wake.lock().unwrap().as_ref() {
            seq.fetch_add(1, Ordering::Release);
            waker.wake();
        }
    }
}

struct StagedInput {
    stage_id: String,
    data: String,
    started_draft_ver: u64,
    requested_draft_ver: u64,
    requested_boot_id: Option<String>,
    initial_ver_matched: bool,
}

const MAX_STAGED_INPUT_BYTES: usize = 64 * 1024;
const MAX_PANE_DRAFT_BYTES: usize = 16 * 1024;
const MAX_TOTAL_DRAFTS_BYTES: usize = 96 * 1024;

fn escaped_bytes(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\x08' | '\x0c' => 2,
        '\0'..='\x1f' => 6,
        _ => c.len_utf8(),
    }
}

// Six framing bytes per entry cover both quotes, colon and comma.
fn entry_bytes(key: &str, value: &str) -> usize {
    6 + key
        .chars()
        .chain(value.chars())
        .map(escaped_bytes)
        .sum::<usize>()
}

fn draft_prefix(text: &str, budget: usize) -> &str {
    let mut escaped = 0;
    for (i, c) in text.char_indices() {
        escaped += escaped_bytes(c);
        if escaped > budget || i + c.len_utf8() > MAX_PANE_DRAFT_BYTES {
            return &text[..i];
        }
    }
    text
}

struct DraftReservation {
    reserved_bytes: usize,
    at_ver: u64,
    expires_at: Instant,
    rollback_draft: Option<String>,
    rollback_client_ack: Option<(String, u64)>,
    rollback_unpersisted: bool,
}

fn draft_budget(
    drafts: &BTreeMap<String, String>,
    versions: &HashMap<String, u64>,
    reservations: &HashMap<String, DraftReservation>,
    key: &str,
) -> usize {
    let now = Instant::now();
    let mut keys: std::collections::BTreeSet<&str> = drafts.keys().map(String::as_str).collect();
    for (rk, res) in reservations {
        if rk != key && versions.get(rk) == Some(&res.at_ver) {
            keys.insert(rk.as_str());
        }
    }
    let others: usize = keys
        .into_iter()
        .filter(|&k| k != key)
        .map(|k| {
            let actual = drafts.get(k).map_or(0, |v| entry_bytes(k, v));
            let reserved = reservations
                .get(k)
                .filter(|res| versions.get(k) == Some(&res.at_ver))
                .map_or(0, |res| {
                    let rb = res
                        .rollback_draft
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .map_or(0, |orig| entry_bytes(k, orig));
                    if now < res.expires_at {
                        res.reserved_bytes.max(rb)
                    } else {
                        rb
                    }
                });
            actual.max(reserved)
        })
        .sum();
    MAX_TOTAL_DRAFTS_BYTES.saturating_sub(2 + others + entry_bytes(key, ""))
}

fn collect_eligible_unpersisted_vers(st: &EngineState) -> Vec<(String, u64)> {
    st.draft_unpersisted_vers
        .iter()
        .filter(|(k, &v)| {
            st.draft_versions.get(*k) == Some(&v)
                && !st.draft_reservations.get(*k).is_some_and(|r| r.at_ver == v)
        })
        .map(|(k, &v)| (k.clone(), v))
        .collect()
}

fn clear_eligible_unpersisted_vers(st: &mut EngineState, vers: Vec<(String, u64)>) -> bool {
    let mut cleared_any = false;
    for (k, v) in vers {
        if st.draft_versions.get(&k) == Some(&v)
            && st.draft_unpersisted_vers.get(&k) == Some(&v)
            && !st.draft_reservations.get(&k).is_some_and(|r| r.at_ver == v)
        {
            st.draft_unpersisted_vers.remove(&k);
            cleared_any = true;
        }
    }
    cleared_any
}

fn committed_drafts_for_disk(st: &EngineState) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut all_keys: std::collections::BTreeSet<&str> =
        st.drafts.keys().map(String::as_str).collect();
    for rk in st.draft_reservations.keys() {
        all_keys.insert(rk.as_str());
    }
    for k in all_keys {
        if let Some(res) = st
            .draft_reservations
            .get(k)
            .filter(|r| st.draft_versions.get(k) == Some(&r.at_ver))
        {
            if let Some(orig) = res.rollback_draft.as_ref().filter(|s| !s.is_empty()) {
                out.insert(k.to_string(), orig.clone());
            }
        } else if let Some(val) = st.drafts.get(k).filter(|s| !s.is_empty()) {
            out.insert(k.to_string(), val.clone());
        }
    }
    out
}

fn rollback_draft_reservation(
    st: &mut EngineState,
    key: &str,
    rollback_draft: Option<String>,
    rollback_client_ack: Option<(String, u64)>,
    rollback_unpersisted: bool,
) {
    match rollback_draft {
        Some(orig) if !orig.is_empty() => {
            st.drafts.insert(key.to_string(), orig);
        }
        _ => {
            st.drafts.remove(key);
        }
    }
    let ver = bump_draft_version(st, key);
    st.draft_rolled_back_vers.insert(key.to_string(), ver);
    if rollback_unpersisted {
        st.draft_unpersisted_vers.insert(key.to_string(), ver);
    } else {
        st.draft_unpersisted_vers.remove(key);
    }
    match rollback_client_ack {
        Some(ack) => {
            st.draft_client_acks.insert(key.to_string(), ack);
        }
        None => {
            st.draft_client_acks.remove(key);
        }
    }
}

fn reap_expired_draft_reservations(st: &mut EngineState, now: Instant) -> bool {
    let expired_keys: Vec<String> = st
        .draft_reservations
        .iter()
        .filter(|(_, res)| now >= res.expires_at)
        .map(|(k, _)| k.clone())
        .collect();
    if expired_keys.is_empty() {
        return false;
    }
    let mut mutated = false;
    for k in expired_keys {
        if let Some(res) = st.draft_reservations.remove(&k) {
            if st.draft_versions.get(&k) == Some(&res.at_ver) {
                rollback_draft_reservation(
                    st,
                    &k,
                    res.rollback_draft,
                    res.rollback_client_ack,
                    res.rollback_unpersisted,
                );
                mutated = true;
            }
        }
    }
    if mutated {
        st.revision += 1;
    }
    mutated
}

#[derive(Default)]
struct Completion {
    run_epoch: u64,
    seen: bool,
}

struct EngineState {
    completions: HashMap<String, Completion>,
    revision: u64,
    hosts: Vec<HostState>,
    panes: Vec<PaneSummary>,
    stream_states: HashMap<String, (ConnPhase, Option<String>)>,
    mock_extras: HashMap<String, MockPaneExtra>,
    prev_statuses: HashMap<String, PaneActivityStatus>,
    attention: AttentionSummary,
    tailnet: TailnetState,
    asr: types::AsrState,
    drafts: BTreeMap<String, String>,
    draft_versions: HashMap<String, u64>,
    draft_reservations: HashMap<String, DraftReservation>,
    draft_rolled_back_vers: HashMap<String, u64>,
    draft_unpersisted_vers: HashMap<String, u64>,
    draft_client_acks: HashMap<String, (String, u64)>,
    send_outcomes: BTreeMap<String, types::SendOutcome>,
    send_outcome_order: VecDeque<String>,
    next_draft_ver: u64,
    staged_inputs: HashMap<String, StagedInput>,
    last_pair_active: bool,
    font_preset: u8,
    reader_mode: String,
    mock: bool,
}

fn normalize_reader_mode(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "raw" | "terminal" => "raw".into(),
        _ => "chat".into(),
    }
}

fn apply_font_preset_crisp(_preset: u8) {
    // High-contrast crisp ramp (`1`): pure #FFFFFF stroke cores + 0 halo + smooth anti-aliased diagonals.
    pocket_raster::set_glyph_crisp_threshold(1);
}

fn bump_draft_version(st: &mut EngineState, key: &str) -> u64 {
    st.next_draft_ver += 1;
    st.draft_versions.insert(key.to_string(), st.next_draft_ver);
    st.next_draft_ver
}

fn next_engine_boot_id() -> String {
    static NEXT_ENGINE_SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = NEXT_ENGINE_SEQ.fetch_add(1, Ordering::Relaxed);
    format!("e{:x}-{:x}-{:x}", std::process::id(), protocol::unix_ms(), seq)
}

fn record_send_outcome(
    st: &mut EngineState,
    client_id: &Option<String>,
    client_seq: Option<u64>,
    ok: bool,
    draft_cleared: Option<bool>,
    draft_ver: Option<u64>,
    persist_error: Option<String>,
) -> bool {
    let (Some(cid), Some(cseq)) = (client_id.as_deref(), client_seq) else {
        return false;
    };
    if cid.is_empty() || cseq == 0 {
        return false;
    }
    let id = format!("{cid}:{cseq}");
    if !st.send_outcomes.contains_key(&id) {
        while st.send_outcome_order.len() >= 256 {
            if let Some(oldest) = st.send_outcome_order.pop_front() {
                st.send_outcomes.remove(&oldest);
            }
        }
        st.send_outcome_order.push_back(id.clone());
    }
    st.send_outcomes.insert(
        id,
        types::SendOutcome {
            ok,
            draft_cleared,
            draft_ver,
            persist_error,
        },
    );
    true
}

struct CachedSnapshot {
    battery: (Option<u8>, bool),
    revision: u64,
    pair: types::PairState,
    active_key: Option<String>,
    json: Arc<Vec<u8>>,
}

pub struct RexZeroEngine {
    boot_id: String,
    bus: Arc<SharedBus>,
    config_root: PathBuf,
    device: Option<Device>,
    headless: bool,
    mock: bool,
    vt: VtActor,
    rime: RimeIme,
    asr: Arc<AsrEngine>,
    tsnet: Arc<TsnetSupervisor>,
    tsnet_proxy_port: Arc<AtomicU16>,
    pair: Arc<PairManager>,
    active_pane_key: Arc<Mutex<Option<String>>>,
    workers: Arc<Mutex<HashMap<String, HostWorkerHandle>>>,
    battery_cache: Mutex<Option<(Instant, Option<u8>, bool)>>,
    snapshot_cache: Mutex<Option<CachedSnapshot>>,
}

impl RexZeroEngine {
    pub fn new_mock(device: Option<Device>) -> Self {
        let vt = VtActor::spawn();
        let seed = build_mock_seed(&vt);
        let rime = RimeIme::new();
        let cfg_root = config_dir();
        let settings = load_settings(&cfg_root);

        let prev_statuses = seed
            .panes
            .iter()
            .map(|p| (p.key.clone(), p.status))
            .collect();
        let draft_versions: HashMap<String, u64> = seed
            .drafts
            .keys()
            .enumerate()
            .map(|(i, k)| (k.clone(), (i + 1) as u64))
            .collect();
        let next_draft_ver = draft_versions.len() as u64;

        let bus = Arc::new(SharedBus {
            state: Mutex::new(EngineState {
                completions: HashMap::new(),
                revision: 1,
                hosts: seed.hosts,
                panes: seed.panes,
                stream_states: HashMap::new(),
                mock_extras: seed.extras,
                prev_statuses,
                attention: seed.attention,
                tailnet: seed.tailnet,
                asr: types::AsrState {
                    configured: true,
                    provider: types::AsrProvider::Openai,
                    ..types::AsrState::default()
                },
                drafts: seed.drafts,
                draft_versions,
                draft_reservations: HashMap::new(),
                draft_rolled_back_vers: HashMap::new(),
                draft_unpersisted_vers: HashMap::new(),
                draft_client_acks: HashMap::new(),
                send_outcomes: BTreeMap::new(),
                send_outcome_order: VecDeque::new(),
                next_draft_ver,
                staged_inputs: HashMap::new(),
                last_pair_active: true,
                font_preset: 0,
                reader_mode: "chat".into(),
                mock: true,
            }),
            cv: Condvar::new(),
            draft_persist_lock: Mutex::new(()),
            hosts_persist_lock: Mutex::new(()),
            ui_wake: Mutex::new(None),
        });

        let bus_asr = bus.clone();
        let asr = Arc::new(AsrEngine::new(
            settings,
            true,
            Arc::new(move |ev| apply_asr_event(&bus_asr, None, ev)),
        ));
        {
            bus.state.lock().unwrap().asr = asr.snapshot();
        }

        let bus_pair = bus.clone();
        let pair = Arc::new(PairManager::new(true, Arc::new(move || bump(&bus_pair))));

        let tsnet = Arc::new(TsnetSupervisor::new(Arc::new(|_| {})));
        apply_font_preset_crisp(0);

        Self {
            boot_id: next_engine_boot_id(),
            bus,
            config_root: cfg_root,
            device,
            headless: true,
            mock: true,
            vt,
            rime,
            asr,
            tsnet,
            tsnet_proxy_port: Arc::new(AtomicU16::new(0)),
            pair,
            active_pane_key: Arc::new(Mutex::new(None)),
            workers: Arc::new(Mutex::new(HashMap::new())),
            battery_cache: Mutex::new(None),
            snapshot_cache: Mutex::new(None),
        }
    }

    pub fn new_live(device: Option<Device>, headless: bool, connect_local_macos: bool) -> Self {
        Self::new_live_with_config(config_dir(), device, headless, connect_local_macos, true)
    }

    pub fn new_live_with_config(
        cfg_root: PathBuf,
        device: Option<Device>,
        headless: bool,
        connect_local_macos: bool,
        spawn_discovered_hosts: bool,
    ) -> Self {
        let vt = VtActor::spawn();
        let rime = RimeIme::new();
        let settings = load_settings(&cfg_root);
        let restored_drafts = load_drafts(&cfg_root);
        let draft_versions: HashMap<String, u64> = restored_drafts
            .keys()
            .enumerate()
            .map(|(i, k)| (k.clone(), (i + 1) as u64))
            .collect();
        let next_draft_ver = draft_versions.len() as u64;
        let initial_hosts = if spawn_discovered_hosts {
            discover_initial_hosts(&cfg_root, connect_local_macos)
        } else {
            load_saved_hosts(&cfg_root)
        };
        let proxy_port = Arc::new(AtomicU16::new(0));

        let host_states: Vec<HostState> = initial_hosts
            .iter()
            .map(|h| {
                let (kind, path_kind) = classify_endpoint(&h.endpoint);
                HostState {
                    id: h.id.clone(),
                    label: h.label.clone(),
                    kind,
                    endpoint: h.endpoint.clone(),
                    phase: ConnPhase::Connecting,
                    problem: None,
                    latency_ms: None,
                    path_kind: Some(path_kind),
                    sessions: Vec::new(),
                }
            })
            .collect();

        let mut attention = AttentionSummary::default();
        attention.muted = settings.muted;
        let init_font_preset = settings.font_preset.min(3);
        let init_reader_mode = normalize_reader_mode(&settings.reader_mode);
        apply_font_preset_crisp(init_font_preset);

        let bus = Arc::new(SharedBus {
            state: Mutex::new(EngineState {
                completions: HashMap::new(),
                revision: 1,
                hosts: host_states,
                panes: Vec::new(),
                stream_states: HashMap::new(),
                mock_extras: HashMap::new(),
                prev_statuses: HashMap::new(),
                attention,
                tailnet: TailnetState::default(),
                asr: types::AsrState::default(),
                drafts: restored_drafts,
                draft_versions,
                draft_reservations: HashMap::new(),
                draft_rolled_back_vers: HashMap::new(),
                draft_unpersisted_vers: HashMap::new(),
                draft_client_acks: HashMap::new(),
                send_outcomes: BTreeMap::new(),
                send_outcome_order: VecDeque::new(),
                next_draft_ver,
                staged_inputs: HashMap::new(),
                last_pair_active: false,
                font_preset: init_font_preset,
                reader_mode: init_reader_mode,
                mock: false,
            }),
            cv: Condvar::new(),
            draft_persist_lock: Mutex::new(()),
            hosts_persist_lock: Mutex::new(()),
            ui_wake: Mutex::new(None),
        });

        let bus_asr = bus.clone();
        let cfg_for_asr = cfg_root.clone();
        let asr = Arc::new(AsrEngine::new(
            settings.clone(),
            false,
            Arc::new(move |ev| apply_asr_event(&bus_asr, Some(cfg_for_asr.as_path()), ev)),
        ));
        bus.state.lock().unwrap().asr = asr.snapshot();

        let bus_pair = bus.clone();
        let pair = Arc::new(PairManager::new(false, Arc::new(move || bump(&bus_pair))));

        let active_pane_key = Arc::new(Mutex::new(None));
        let workers: Arc<Mutex<HashMap<String, HostWorkerHandle>>> =
            Arc::new(Mutex::new(HashMap::new()));

        let ts_ctx = TailnetApplyCtx {
            bus: bus.clone(),
            proxy_port: proxy_port.clone(),
            cfg_root: cfg_root.clone(),
            workers: workers.clone(),
            device: device.clone(),
            play_audio: !headless,
            active_pane_key: active_pane_key.clone(),
            vt: vt.clone(),
            spawn_workers: spawn_discovered_hosts,
        };
        let tsnet = Arc::new(TsnetSupervisor::new(Arc::new(move |upd| {
            apply_tailnet_update(&ts_ctx, upd);
        })));

        let engine = Self {
            boot_id: next_engine_boot_id(),
            bus,
            config_root: cfg_root,
            device,
            headless,
            mock: false,
            vt,
            rime,
            asr,
            tsnet,
            tsnet_proxy_port: proxy_port,
            pair,
            active_pane_key,
            workers,
            battery_cache: Mutex::new(None),
            snapshot_cache: Mutex::new(None),
        };

        if spawn_discovered_hosts {
            for h in initial_hosts {
                engine.spawn_host_worker(h);
            }

            if settings.tailnet_enabled {
                let _ = engine
                    .tsnet
                    .set_enabled(true, settings.tailnet_hostname.as_deref(), None);
            }
        }

        engine
    }

    pub fn attach_ui_waker(&self, seq: Arc<AtomicU64>, waker: Waker) {
        *self.bus.ui_wake.lock().unwrap() = Some((seq, waker));
    }

    pub fn wake_waiters(&self) {
        let _guard = self.bus.state.lock().unwrap();
        self.bus.cv.notify_all();
    }

    pub fn shutdown(&self) {
        if !self.mock {
            let _ = self.bus.persist_drafts(&self.config_root);
        }
        let workers = std::mem::take(&mut *self.workers.lock().unwrap());
        for worker in workers.values() {
            worker.stop();
        }
        for worker in workers.into_values() {
            worker.join();
        }
        self.tsnet.stop();
        self.bus.cv.notify_all();
    }

    fn spawn_host_worker(&self, cfg: ConfiguredHost) {
        spawn_host_worker_into(
            &self.workers,
            &self.bus,
            self.device.clone(),
            !self.mock && !self.headless,
            &self.active_pane_key,
            &self.vt,
            &self.tsnet_proxy_port,
            cfg,
        );
    }

    // ---- HTTP Dispatch (`http://zero/rex/*`) -----------------------------------

    #[cfg(test)]
    pub fn handle_http(&self, method: &str, path: &str, query: &str, body: &[u8]) -> HttpReply {
        let never_cancelled = AtomicBool::new(false);
        self.handle_http_with_context(
            method,
            path,
            query,
            body,
            Duration::from_secs(30),
            &never_cancelled,
        )
    }

    pub fn handle_http_with_context(
        &self,
        method: &str,
        path: &str,
        query: &str,
        body: &[u8],
        request_timeout: Duration,
        cancel: &AtomicBool,
    ) -> HttpReply {
        match (method, path) {
            ("GET", "/rex/bootstrap") => HttpReply {
                status: 200,
                body: (*self.snapshot_json_bytes()).clone(),
            },
            ("GET", "/rex/wait") => {
                let params = parse_query(query);
                let since = params
                    .get("since")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                let timeout_ms = params
                    .get("timeout_ms")
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(12_000)
                    .clamp(1, 25_000);
                let effective_timeout = Duration::from_millis(timeout_ms).min(request_timeout);
                let boot_mismatch = params
                    .get("boot_id")
                    .is_some_and(|b| !b.is_empty() && b != &self.boot_id);
                if !boot_mismatch && !self.wait_since(since, effective_timeout, cancel) {
                    return self.json_err(499, "cancelled");
                }
                HttpReply {
                    status: 200,
                    body: (*self.snapshot_json_bytes()).clone(),
                }
            }
            ("GET", "/rex/pane") => {
                let params = parse_query(query);
                let Some(key) = params.get("key").filter(|k| !k.is_empty()) else {
                    return self.json_err(400, "missing pane key");
                };
                let cols = params
                    .get("cols")
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(50)
                    .clamp(20, 300);
                let rows = params
                    .get("rows")
                    .and_then(|s| s.parse::<u16>().ok())
                    .unwrap_or(14)
                    .clamp(5, 120);
                match self.pane_view(key, cols, rows) {
                    Some(payload) => self.json_ok(&payload),
                    None => self.json_err(404, "pane not found"),
                }
            }
            ("POST", "/rex/action") => match serde_json::from_slice::<RexAction>(body) {
                Ok(action) => self.json_ok(&self.execute_action(action)),
                Err(err) => {
                    let mut rep = ActionReply::err(format!("bad RexAction JSON: {err}"));
                    rep.boot_id = Some(self.boot_id.clone());
                    self.json_ok(&rep)
                }
            },
            _ => self.json_err(404, &format!("unknown rex route {method} {path}")),
        }
    }

    fn json_ok(&self, val: &impl serde::Serialize) -> HttpReply {
        HttpReply {
            status: 200,
            body: serde_json::to_vec(val).unwrap_or_else(|_| b"{}".to_vec()),
        }
    }

    fn json_err(&self, status: u16, msg: &str) -> HttpReply {
        HttpReply {
            status,
            body: serde_json::to_vec(&serde_json::json!({ "error": msg })).unwrap_or_default(),
        }
    }

    /// Blocks until `revision > since`, `timeout` elapses, or `cancel` becomes `true`.
    /// Returns `false` if cancelled so the caller skips snapshot serialization and exits immediately.
    fn wait_since(&self, since: u64, timeout: Duration, cancel: &AtomicBool) -> bool {
        if cancel.load(Ordering::Acquire) {
            return false;
        }
        let mut guard = self.bus.state.lock().unwrap();
        if guard.revision > since {
            return true;
        }
        let deadline = Instant::now() + timeout;
        while guard.revision <= since {
            if cancel.load(Ordering::Acquire) {
                return false;
            }
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if rem.is_zero() {
                break;
            }
            let (next_guard, res) = self.bus.cv.wait_timeout(guard, rem).unwrap();
            guard = next_guard;
            if cancel.load(Ordering::Acquire) {
                return false;
            }
            if res.timed_out() {
                break;
            }
        }
        true
    }

    fn snapshot_json_bytes(&self) -> Arc<Vec<u8>> {
        let snap = self.snapshot();
        let active_key = self.active_pane_key.lock().unwrap().clone();
        {
            let cache = self.snapshot_cache.lock().unwrap();
            if let Some(c) = cache.as_ref() {
                if c.battery == (snap.battery_percent, snap.charging)
                    && c.revision == snap.revision
                    && c.pair == snap.pair
                    && c.active_key == active_key
                {
                    return c.json.clone();
                }
            }
        }
        let encoded = Arc::new(serde_json::to_vec(&snap).unwrap_or_else(|_| b"{}".to_vec()));
        *self.snapshot_cache.lock().unwrap() = Some(CachedSnapshot {
            battery: (snap.battery_percent, snap.charging),
            revision: snap.revision,
            pair: snap.pair,
            active_key,
            json: encoded.clone(),
        });
        encoded
    }

    pub fn snapshot(&self) -> FleetSnapshot {
        let (battery_percent, charging) = self.read_battery_cached();
        let ime = self.rime.status();
        // Keep `pair` linearizable with `st.revision`: retry if `st.revision` or `pair` state changed!
        let (pair, active_key, mut st) = loop {
            let rev_before = self.bus.state.lock().unwrap().revision;
            let pair_snap = self.pair.snapshot();
            let active_snap = self.active_pane_key.lock().unwrap().clone();
            let st_guard = self.bus.state.lock().unwrap();
            let pair_after = self.pair.snapshot();
            if st_guard.revision == rev_before
                && pair_snap.active == pair_after.active
                && pair_snap.url == pair_after.url
                && pair_snap.pending_import == pair_after.pending_import
            {
                break (pair_snap, active_snap, st_guard);
            }
        };
        if st.last_pair_active != pair.active {
            st.last_pair_active = pair.active;
            st.revision += 1;
        }
        let _ = reap_expired_draft_reservations(&mut st, Instant::now());
        sync_pane_draft_flags(&mut st);
        sort_panes_by_priority(&mut st.panes);
        recompute_attention_counts(&mut st, active_key.as_deref());
        mark_added_tailnet_peers(&mut st);

        let draft_meta: BTreeMap<String, types::DraftMeta> = st
            .draft_versions
            .iter()
            .map(|(k, &ver)| {
                let (client_id, client_seq) = st
                    .draft_client_acks
                    .get(k)
                    .map(|(cid, cs)| ((!cid.is_empty()).then(|| cid.clone()), *cs))
                    .unwrap_or((None, 0));
                let reservation_rolled_back =
                    st.draft_rolled_back_vers.get(k) == Some(&ver);
                let provisional = st
                    .draft_reservations
                    .get(k)
                    .is_some_and(|r| r.at_ver == ver);
                let unpersisted = provisional || st.draft_unpersisted_vers.get(k) == Some(&ver);
                (
                    k.clone(),
                    types::DraftMeta {
                        ver,
                        client_id,
                        client_seq,
                        reservation_rolled_back,
                        provisional,
                        unpersisted,
                    },
                )
            })
            .collect();

        FleetSnapshot {
            boot_id: Some(self.boot_id.clone()),
            revision: st.revision,
            battery_percent,
            charging,
            hosts: st.hosts.clone(),
            panes: st.panes.clone(),
            attention: st.attention.clone(),
            tailnet: st.tailnet.clone(),
            ime,
            asr: st.asr.clone(),
            pair,
            drafts: st.drafts.clone(),
            draft_meta,
            send_outcomes: st.send_outcomes.clone(),
            font_preset: st.font_preset,
            reader_mode: st.reader_mode.clone(),
            mock: st.mock,
        }
    }

    fn read_battery_cached(&self) -> (Option<u8>, bool) {
        {
            let guard = self.battery_cache.lock().unwrap();
            if let Some((at, pct, chg)) = *guard {
                if at.elapsed() < Duration::from_secs(2) {
                    return (pct, chg);
                }
            }
        }
        let fresh = self.read_battery();
        *self.battery_cache.lock().unwrap() = Some((Instant::now(), fresh.0, fresh.1));
        fresh
    }

    fn read_battery(&self) -> (Option<u8>, bool) {
        if let Some(dev) = &self.device {
            let resp = dev.handle("GET", "/dev/battery", b"");
            if resp.status == 200 {
                if let Ok(v) = serde_json::from_slice::<Value>(&resp.body) {
                    let pct = v.get("percent").and_then(Value::as_u64).map(|n| n as u8);
                    let status = v.get("status").and_then(Value::as_str).unwrap_or("");
                    if pct.is_some() {
                        return (pct, status.eq_ignore_ascii_case("charging"));
                    }
                }
            }
        }
        if self.mock {
            (Some(86), false)
        } else {
            (None, false)
        }
    }

    fn pane_view(&self, key: &str, cols: u16, rows: u16) -> Option<PaneViewPayload> {
        // Validate target pane exists FIRST before changing `active_pane_key` or disowning current pane!
        let other_owned: Vec<String> = {
            let st = self.bus.state.lock().unwrap();
            if !st.panes.iter().any(|p| p.key == key) {
                return None;
            }
            st.panes
                .iter()
                .filter(|p| p.owned_by_us && p.key != key)
                .map(|p| p.key.clone())
                .collect()
        };
        let prev_active = {
            let mut guard = self.active_pane_key.lock().unwrap();
            guard.replace(key.to_string())
        };
        for old_key in other_owned {
            self.auto_disown_if_owned(&old_key);
        }
        if !self.mock && prev_active.as_deref() != Some(key) {
            self.vt.retain_only(Some(key));
            let workers = self.workers.lock().unwrap();
            for worker in workers.values() {
                let _ = worker.send(HostCmd::CloseStreamsExcept {
                    keep_key: Some(key.to_string()),
                });
            }
        }

        let (pane, revision, stream_phase, stream_problem, mock_extra) = {
            let mut st = self.bus.state.lock().unwrap();
            let idx = st.panes.iter().position(|p| p.key == key)?;
            let mut status_cleared = false;
            if st.panes[idx].status == PaneActivityStatus::UnseenDone {
                st.panes[idx].status = PaneActivityStatus::Done;
                st.completions.entry(key.to_string()).or_default().seen = true;
                st.prev_statuses
                    .insert(key.to_string(), PaneActivityStatus::Done);
                status_cleared = true;
            }
            // Always recompute `nextTargetKey` excluding the newly active on-screen pane (`M3.2-activity-chip`),
            // and bump `revision` whenever `unseen_done` clears OR `nextTargetKey` changes!
            let prev_next = st.attention.next_target_key.clone();
            recompute_attention_counts(&mut st, Some(key));
            if status_cleared || st.attention.next_target_key != prev_next {
                st.revision += 1;
                self.bus.notify_ui();
            }
            let pane = st.panes[idx].clone();
            let (s_phase, s_prob) = st
                .stream_states
                .get(key)
                .cloned()
                .unwrap_or((ConnPhase::Live, None));
            let extra = st.mock_extras.get(key).map(|e| {
                (
                    e.live_activity.clone(),
                    e.approval.clone(),
                    e.reader_messages.clone(),
                )
            });
            (pane, st.revision, s_phase, s_prob, extra)
        };

        if !self.mock {
            if let Some((host_id, session_id, block_id)) = split_pane_key(key) {
                if let Some(worker) = self.workers.lock().unwrap().get(host_id) {
                    let _ = worker.send(HostCmd::EnsureStream {
                        session_id: session_id.to_string(),
                        block_id: block_id.to_string(),
                        cols,
                        rows,
                    });
                }
            }
        }

        let extracted = self.vt.extract(key, cols, rows);
        let vt = extracted
            .vt
            .unwrap_or_else(|| VtViewport::empty(cols, rows));

        let (live_activity_text, mut approval, mut reader_messages) =
            if let Some((la, ap, rm)) = mock_extra {
                (la, ap, rm)
            } else {
                (
                    extracted.live_activity.or_else(|| {
                        (pane.status == PaneActivityStatus::Running)
                            .then(|| pane.status_msg.clone())
                            .flatten()
                    }),
                    extracted.approval,
                    extracted.reader_messages,
                )
            };

        if pane.status == PaneActivityStatus::Blocked && approval.is_none() {
            approval = Some(synthesize_blocked_approval(
                Some(&pane.title),
                pane.status_msg.as_deref(),
            ));
        } else if pane.status != PaneActivityStatus::Blocked && self.mock {
            approval = None;
        }

        if reader_messages.is_empty() {
            reader_messages.push(ReaderMessage {
                id: "empty".into(),
                role: ReaderRole::System,
                title: Some(pane.program.clone()),
                body: pane.status_msg.clone().unwrap_or_else(|| {
                    let label = if !pane.window_label.is_empty() {
                        &pane.window_label
                    } else {
                        &pane.title
                    };
                    format!("已连接 {} · {}（按 m 切模式，i 回复）", pane.host_label, label)
                }),
            });
        }

        Some(PaneViewPayload {
            key: pane.key,
            revision,
            title: pane.title,
            window_label: pane.window_label,
            host_label: pane.host_label,
            session_label: pane.session_label,
            program: pane.program,
            pwd: pane.pwd,
            stream_phase,
            stream_problem,
            owned_by_us: pane.owned_by_us,
            released_by_us: pane.released_by_us,
            status: pane.status,
            status_kind: pane.status_kind,
            status_msg: pane.status_msg,
            live_activity_text,
            approval,
            reader_messages,
            raw_lines: extracted.raw_lines,
            vt,
        })
    }

    fn auto_disown_if_owned(&self, key: &str) {
        if self.mock {
            let mut st = self.bus.state.lock().unwrap();
            if let Some(p) = st.panes.iter_mut().find(|p| p.key == key && p.owned_by_us) {
                p.owned_by_us = false;
                p.released_by_us = true;
                st.revision += 1;
                self.bus.notify_ui();
            }
            return;
        }

        let still_owned = self
            .bus
            .state
            .lock()
            .unwrap()
            .panes
            .iter()
            .any(|p| p.key == key && p.owned_by_us);
        if !still_owned {
            return;
        }

        let Some((host_id, session_id, block_id)) = split_pane_key(key) else {
            return;
        };
        let (tx, rx) = mpsc::channel();
        let sent = {
            let guard = self.workers.lock().unwrap();
            guard.get(host_id).is_some_and(|worker| {
                worker
                    .send(HostCmd::SetOwnership {
                        session_id: session_id.to_string(),
                        block_id: block_id.to_string(),
                        mode: OwnershipMode::HandBack,
                        cols: 0,
                        rows: 0,
                        reply: tx,
                    })
                    .is_ok()
            })
        };
        if !sent {
            // Retain `owned_by_us = true` so next switch or shutdown retries!
            return;
        }
        if let Ok(Ok(())) = rx.recv_timeout(Duration::from_secs(2)) {
            let mut st = self.bus.state.lock().unwrap();
            if let Some(p) = st.panes.iter_mut().find(|p| p.key == key && p.owned_by_us) {
                p.owned_by_us = false;
                p.released_by_us = true;
                st.revision += 1;
                self.bus.notify_ui();
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_live_send_input(
        &self,
        key: String,
        full_data: String,
        clear_draft: Option<bool>,
        started_draft_ver: u64,
        initial_ver_matched: bool,
        client_id: Option<String>,
        client_seq: Option<u64>,
        deadline: Instant,
        wait_timeout: Duration,
    ) -> ActionReply {
        let Some((host_id, session_id, block_id)) = split_pane_key(&key) else {
            let mut st = self.bus.state.lock().unwrap();
            if record_send_outcome(&mut st, &client_id, client_seq, false, None, None, None) {
                st.revision += 1;
                self.bus.notify_ui();
            }
            let mut r = ActionReply::err("invalid pane key");
            r.boot_id = Some(self.boot_id.clone());
            return r;
        };
        let dispatch = Arc::new(protocol::InputDispatch::new(deadline));
        let settled = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<ActionReply>();
        {
            let guard = self.workers.lock().unwrap();
            let Some(worker) = guard.get(host_id) else {
                let mut st = self.bus.state.lock().unwrap();
                if record_send_outcome(&mut st, &client_id, client_seq, false, None, None, None) {
                    st.revision += 1;
                    self.bus.notify_ui();
                }
                let mut r = ActionReply::err("unknown host");
                r.boot_id = Some(self.boot_id.clone());
                return r;
            };
            let bus_settle = self.bus.clone();
            let cfg_settle = self.config_root.clone();
            let disp_settle = dispatch.clone();
            let settled_flag = settled.clone();
            let key_settle = key.clone();
            let cid_settle = client_id.clone();
            let boot_settle = self.boot_id.clone();
            let tx_settle = tx.clone();
            let reply_cb = protocol::SendInputReply::new(move |res| match res {
                Ok(()) => {
                    if settled_flag.swap(true, Ordering::AcqRel) {
                        return;
                    }
                    let mut reply = ActionReply::ok();
                    reply.boot_id = Some(boot_settle);
                    if clear_draft == Some(true) {
                        // Lock `draft_persist_lock` -> `state` (canonical lock order) so disk persistence
                        // and `send_outcomes.persist_error` are published atomically before waking `/rex/wait`!
                        let _writer = bus_settle.draft_persist_lock.lock().unwrap();
                        let mut st = bus_settle.state.lock().unwrap();
                        let cur_ver = st
                            .draft_versions
                            .get(&key_settle)
                            .copied()
                            .unwrap_or_default();
                        if initial_ver_matched && cur_ver == started_draft_ver {
                            let removed_ram = st.drafts.remove(&key_settle).is_some();
                            let removed_committed = st
                                .draft_reservations
                                .remove(&key_settle)
                                .and_then(|r| r.rollback_draft)
                                .is_some_and(|s| !s.is_empty());
                            let had_unpersisted =
                                st.draft_unpersisted_vers.get(&key_settle) == Some(&cur_ver);
                            let needs_disk_write =
                                removed_ram || removed_committed || had_unpersisted;
                            let new_ver = if needs_disk_write || client_seq.is_some() {
                                st.draft_rolled_back_vers.remove(&key_settle);
                                bump_draft_version(&mut st, &key_settle)
                            } else {
                                cur_ver
                            };
                            if let Some(cseq) = client_seq {
                                st.draft_client_acks.insert(
                                    key_settle.clone(),
                                    (cid_settle.clone().unwrap_or_default(), cseq),
                                );
                            } else {
                                st.draft_client_acks.remove(&key_settle);
                            }
                            let mut cleared_other_unpersisted = false;
                            let persist_err = if needs_disk_write {
                                let disk_drafts = committed_drafts_for_disk(&st);
                                let eligible_vers = collect_eligible_unpersisted_vers(&st);
                                match save_drafts(&cfg_settle, &disk_drafts) {
                                    Ok(()) => {
                                        st.draft_unpersisted_vers.remove(&key_settle);
                                        cleared_other_unpersisted =
                                            clear_eligible_unpersisted_vers(&mut st, eligible_vers);
                                        None
                                    }
                                    Err(e) => {
                                        st.draft_unpersisted_vers.insert(key_settle.clone(), new_ver);
                                        Some(format!("清理草稿落盘失败: {e}"))
                                    }
                                }
                            } else {
                                st.draft_unpersisted_vers.remove(&key_settle);
                                None
                            };
                            let ack_recorded = record_send_outcome(
                                &mut st,
                                &cid_settle,
                                client_seq,
                                true,
                                Some(true),
                                Some(new_ver),
                                persist_err.clone(),
                            );
                            if needs_disk_write
                                || client_seq.is_some()
                                || ack_recorded
                                || cleared_other_unpersisted
                            {
                                st.revision += 1;
                                bus_settle.notify_ui();
                            }
                            let (cid, cseq) = st
                                .draft_client_acks
                                .get(&key_settle)
                                .map(|(i, s)| ((!i.is_empty()).then(|| i.clone()), Some(*s)))
                                .unwrap_or((None, None));
                            reply.revision = Some(st.revision);
                            reply.draft_cleared = Some(true);
                            reply.draft_ver = Some(new_ver);
                            reply.client_id = cid;
                            reply.client_seq = cseq;
                            reply.persist_error = persist_err;
                        } else {
                            let srv_draft =
                                st.drafts.get(&key_settle).cloned().unwrap_or_default();
                            if record_send_outcome(
                                &mut st,
                                &cid_settle,
                                client_seq,
                                true,
                                Some(false),
                                Some(cur_ver),
                                None,
                            ) {
                                st.revision += 1;
                                bus_settle.notify_ui();
                            }
                            let (cid, cseq) = st
                                .draft_client_acks
                                .get(&key_settle)
                                .map(|(i, s)| ((!i.is_empty()).then(|| i.clone()), Some(*s)))
                                .unwrap_or((None, None));
                            reply.revision = Some(st.revision);
                            reply.draft_cleared = Some(false);
                            reply.draft_ver = Some(cur_ver);
                            reply.client_id = cid;
                            reply.client_seq = cseq;
                            if st.draft_rolled_back_vers.get(&key_settle) == Some(&cur_ver) {
                                reply.reservation_rolled_back = Some(true);
                            }
                            if st
                                .draft_reservations
                                .get(&key_settle)
                                .is_some_and(|r| r.at_ver == cur_ver)
                            {
                                reply.provisional = Some(true);
                            }
                            reply.server_draft = Some(srv_draft);
                        }
                    } else {
                        let mut st = bus_settle.state.lock().unwrap();
                        if record_send_outcome(
                            &mut st,
                            &cid_settle,
                            client_seq,
                            true,
                            None,
                            None,
                            None,
                        ) {
                            st.revision += 1;
                            bus_settle.notify_ui();
                        }
                        reply.revision = Some(st.revision);
                    }
                    let _ = tx_settle.send(reply);
                }
                Err(e) => {
                    let mut err_reply = ActionReply::err(e);
                    err_reply.boot_id = Some(boot_settle);
                    if disp_settle.is_claimed() {
                        // Write already started on the wire: keep sequence unresolved in `send_outcomes`!
                        err_reply.unconfirmed = Some(true);
                    } else if !settled_flag.swap(true, Ordering::AcqRel) {
                        let mut st = bus_settle.state.lock().unwrap();
                        if record_send_outcome(
                            &mut st,
                            &cid_settle,
                            client_seq,
                            false,
                            None,
                            None,
                            None,
                        ) {
                            st.revision += 1;
                            bus_settle.notify_ui();
                        }
                    }
                    let _ = tx_settle.send(err_reply);
                }
            });
            if let Err(e) = worker.send(HostCmd::SendInput {
                dispatch: dispatch.clone(),
                session_id: session_id.to_string(),
                block_id: block_id.to_string(),
                data: full_data,
                reply: reply_cb,
            }) {
                if !settled.swap(true, Ordering::AcqRel) {
                    let mut st = self.bus.state.lock().unwrap();
                    if record_send_outcome(&mut st, &client_id, client_seq, false, None, None, None)
                    {
                        st.revision += 1;
                        self.bus.notify_ui();
                    }
                }
                let mut r = ActionReply::err(e);
                r.boot_id = Some(self.boot_id.clone());
                return r;
            }
        }
        let wait_limit = deadline
            .saturating_duration_since(Instant::now())
            .min(wait_timeout);
        match rx.recv_timeout(wait_limit) {
            Ok(reply) => reply,
            Err(_) => {
                let (unconfirmed, msg) = dispatch.cancel_or_unconfirmed();
                let mut err_reply = ActionReply::err(msg);
                err_reply.boot_id = Some(self.boot_id.clone());
                if unconfirmed {
                    // Worker claimed the write and may still finish after `recv_timeout`:
                    // `SendInputReply` remains alive on the worker and will commit the
                    // terminal outcome to `send_outcomes` + wake `/rex/wait` if it succeeds!
                    err_reply.unconfirmed = Some(true);
                } else if !settled.swap(true, Ordering::AcqRel) {
                    let mut st = self.bus.state.lock().unwrap();
                    if record_send_outcome(&mut st, &client_id, client_seq, false, None, None, None)
                    {
                        st.revision += 1;
                        self.bus.notify_ui();
                    }
                }
                err_reply
            }
        }
    }

    fn execute_action(&self, action: RexAction) -> ActionReply {
        let mut reply = self.execute_action_inner(action);
        reply.boot_id = Some(self.boot_id.clone());
        reply
    }

    fn execute_action_inner(&self, action: RexAction) -> ActionReply {
        match action {
            RexAction::SendInput {
                key,
                data,
                clear_draft,
                stage,
                reset_stage,
                stage_id,
                if_draft_ver,
                if_boot_id,
                client_id,
                client_seq,
            } => {
                let (full_data, started_draft_ver, initial_ver_matched) = {
                    let mut st = self.bus.state.lock().unwrap();
                    let ver = st.draft_versions.get(&key).copied().unwrap_or_default();
                    let boot_ok = if_boot_id
                        .as_deref()
                        .map_or(true, |b| b.is_empty() || b == self.boot_id);
                    if stage == Some(true) {
                        let Some(sid) = stage_id.filter(|s| !s.is_empty()) else {
                            return ActionReply::err("staged send_input requires stageId");
                        };
                        if reset_stage == Some(true) {
                            if data.len() > MAX_STAGED_INPUT_BYTES {
                                return ActionReply::err("staged input exceeds 64 KiB limit");
                            }
                            let requested_ver = if_draft_ver.unwrap_or(ver);
                            st.staged_inputs.insert(
                                key,
                                StagedInput {
                                    stage_id: sid,
                                    data,
                                    started_draft_ver: ver,
                                    requested_draft_ver: requested_ver,
                                    requested_boot_id: if_boot_id.filter(|b| !b.is_empty()),
                                    initial_ver_matched: boot_ok && requested_ver == ver,
                                },
                            );
                        } else {
                            let Some(entry) =
                                st.staged_inputs.get_mut(&key).filter(|e| e.stage_id == sid)
                            else {
                                return ActionReply::err("stale or missing stageId");
                            };
                            if let Some(explicit_ver) = if_draft_ver {
                                if explicit_ver != entry.requested_draft_ver {
                                    return ActionReply::err("staged ifDraftVer mismatch");
                                }
                            }
                            if let Some(explicit_boot) = if_boot_id.as_deref().filter(|b| !b.is_empty()) {
                                if entry.requested_boot_id.as_deref() != Some(explicit_boot) {
                                    return ActionReply::err("staged ifBootId mismatch");
                                }
                            }
                            if entry.data.len() + data.len() > MAX_STAGED_INPUT_BYTES {
                                return ActionReply::err("staged input exceeds 64 KiB limit");
                            }
                            entry.data.push_str(&data);
                        }
                        return ActionReply::ok();
                    }
                    if let Some(id) = stage_id {
                        let Some(stage) = st.staged_inputs.get(&key).filter(|e| e.stage_id == id)
                        else {
                            if record_send_outcome(&mut st, &client_id, client_seq, false, None, None, None) {
                                st.revision += 1;
                                self.bus.notify_ui();
                            }
                            return ActionReply::err("stale or missing stageId");
                        };
                        if let Some(explicit_ver) = if_draft_ver {
                            if explicit_ver != stage.requested_draft_ver {
                                if record_send_outcome(&mut st, &client_id, client_seq, false, None, None, None) {
                                    st.revision += 1;
                                    self.bus.notify_ui();
                                }
                                return ActionReply::err("staged ifDraftVer mismatch");
                            }
                        }
                        if let Some(explicit_boot) = if_boot_id.as_deref().filter(|b| !b.is_empty()) {
                            if stage.requested_boot_id.as_deref() != Some(explicit_boot) {
                                if record_send_outcome(&mut st, &client_id, client_seq, false, None, None, None) {
                                    st.revision += 1;
                                    self.bus.notify_ui();
                                }
                                return ActionReply::err("staged ifBootId mismatch");
                            }
                        }
                        if data.len() > MAX_STAGED_INPUT_BYTES - stage.data.len() {
                            if record_send_outcome(&mut st, &client_id, client_seq, false, None, None, None) {
                                st.revision += 1;
                                self.bus.notify_ui();
                            }
                            return ActionReply::err("staged input exceeds 64 KiB limit");
                        }
                        let mut entry = st.staged_inputs.remove(&key).unwrap();
                        entry.data.push_str(&data);
                        (entry.data, entry.started_draft_ver, entry.initial_ver_matched)
                    } else {
                        st.staged_inputs.remove(&key);
                        let matched = boot_ok && if_draft_ver.map_or(true, |expected| expected == ver);
                        (data, ver, matched)
                    }
                };

                if self.mock {
                    self.vt
                        .write_raw_sync(&key, 50, 14, format!("{full_data}\r\n").into_bytes());
                    let mut approved_now = false;
                    let mut draft_cleared = None;
                    let mut out_ver = None;
                    let mut out_cid = None;
                    let mut out_cseq = None;
                    let mut out_rolled_back = None;
                    let mut out_provisional = None;
                    let mut out_srv_draft = None;
                    let rev = {
                        let mut st = self.bus.state.lock().unwrap();
                        if clear_draft == Some(true) {
                            let cur_ver = st.draft_versions.get(&key).copied().unwrap_or_default();
                            if initial_ver_matched && cur_ver == started_draft_ver {
                                let removed_ram = st.drafts.remove(&key).is_some();
                                let removed_committed = st
                                    .draft_reservations
                                    .remove(&key)
                                    .and_then(|r| r.rollback_draft)
                                    .is_some_and(|s| !s.is_empty());
                                let removed = removed_ram || removed_committed;
                                let new_ver = if removed || client_seq.is_some() {
                                    st.draft_rolled_back_vers.remove(&key);
                                    st.draft_unpersisted_vers.remove(&key);
                                    bump_draft_version(&mut st, &key)
                                } else {
                                    cur_ver
                                };
                                if let Some(cseq) = client_seq {
                                    st.draft_client_acks.insert(
                                        key.clone(),
                                        (client_id.clone().unwrap_or_default(), cseq),
                                    );
                                } else if removed {
                                    st.draft_client_acks.remove(&key);
                                }
                                draft_cleared = Some(true);
                                out_ver = Some(new_ver);
                                if let Some((cid, cs)) = st.draft_client_acks.get(&key) {
                                    out_cid = (!cid.is_empty()).then(|| cid.clone());
                                    out_cseq = Some(*cs);
                                }
                            } else {
                                draft_cleared = Some(false);
                                out_ver = Some(cur_ver);
                                if let Some((cid, cs)) = st.draft_client_acks.get(&key) {
                                    out_cid = (!cid.is_empty()).then(|| cid.clone());
                                    out_cseq = Some(*cs);
                                }
                                if st.draft_rolled_back_vers.get(&key) == Some(&cur_ver) {
                                    out_rolled_back = Some(true);
                                }
                                if st
                                    .draft_reservations
                                    .get(&key)
                                    .is_some_and(|r| r.at_ver == cur_ver)
                                {
                                    out_provisional = Some(true);
                                }
                                out_srv_draft =
                                    Some(st.drafts.get(&key).cloned().unwrap_or_default());
                            }
                        }
                        if let Some(p) = st.panes.iter_mut().find(|p| p.key == key) {
                            if p.status == PaneActivityStatus::Blocked {
                                p.status = PaneActivityStatus::Running;
                                p.status_kind = Some("working".into());
                                p.status_msg = Some("已授权 · 正在编译 Release (aarch64)".into());
                                st.prev_statuses
                                    .insert(key.clone(), PaneActivityStatus::Running);
                                approved_now = true;
                            }
                        }
                        if let Some(ex) = st.mock_extras.get_mut(&key) {
                            if ex.approval.take().is_some() || approved_now {
                                ex.live_activity =
                                    Some("已授权 · 正在编译 Release (aarch64)".into());
                                approved_now = true;
                            }
                            let trimmed = full_data.trim();
                            if !trimmed.is_empty() {
                                ex.reader_messages.push(ReaderMessage {
                                    id: format!("u{}", ex.reader_messages.len() + 1),
                                    role: ReaderRole::User,
                                    title: None,
                                    body: trimmed.to_string(),
                                });
                            }
                        }
                        record_send_outcome(
                            &mut st,
                            &client_id,
                            client_seq,
                            true,
                            draft_cleared,
                            out_ver,
                            None,
                        );
                        st.revision += 1;
                        self.bus.notify_ui();
                        st.revision
                    };
                    if approved_now {
                        self.vt.write_raw_sync(
                            &key,
                            50,
                            14,
                            "\x1b[1;32m✓ 已授权 · 正在编译 Release (aarch64)\x1b[0m\r\n"
                                .as_bytes()
                                .to_vec(),
                        );
                    }
                    let mut reply = ActionReply::ok();
                    reply.revision = Some(rev);
                    reply.draft_cleared = draft_cleared;
                    reply.draft_ver = out_ver;
                    reply.client_id = out_cid;
                    reply.client_seq = out_cseq;
                    reply.reservation_rolled_back = out_rolled_back;
                    reply.provisional = out_provisional;
                    reply.server_draft = out_srv_draft;
                    return reply;
                }

                let deadline = Instant::now() + Duration::from_secs(6);
                self.dispatch_live_send_input(
                    key,
                    full_data,
                    clear_draft,
                    started_draft_ver,
                    initial_ver_matched,
                    client_id,
                    client_seq,
                    deadline,
                    Duration::from_secs(6),
                )
            }

            RexAction::SendKey {
                key,
                key_name,
                mods,
            } => {
                let seq = self.vt.encode_key(&key, &key_name, mods.unwrap_or(0));
                self.execute_action(RexAction::SendInput {
                    key,
                    data: seq,
                    clear_draft: Some(false),
                    stage: None,
                    reset_stage: None,
                    stage_id: None,
                    if_draft_ver: None,
                    if_boot_id: None,
                    client_id: None,
                    client_seq: None,
                })
            }

            RexAction::SetOwnership {
                key,
                mode,
                cols,
                rows,
            } => {
                let c = cols.unwrap_or(50);
                let r = rows.unwrap_or(14);
                if self.mock {
                    if mode == OwnershipMode::Take {
                        self.vt.resize_local(&key, c, r);
                    }
                    let mut st = self.bus.state.lock().unwrap();
                    if let Some(p) = st.panes.iter_mut().find(|p| p.key == key) {
                        match mode {
                            OwnershipMode::Take => {
                                p.owned_by_us = true;
                                p.released_by_us = false;
                            }
                            OwnershipMode::Peek | OwnershipMode::HandBack => {
                                if p.owned_by_us {
                                    p.owned_by_us = false;
                                    p.released_by_us = true;
                                }
                            }
                        }
                        st.revision += 1;
                        self.bus.notify_ui();
                    }
                    return ActionReply::ok();
                }

                let Some((host_id, session_id, block_id)) = split_pane_key(&key) else {
                    return ActionReply::err("invalid pane key");
                };
                let (tx, rx) = mpsc::channel();
                {
                    let guard = self.workers.lock().unwrap();
                    let Some(worker) = guard.get(host_id) else {
                        return ActionReply::err("unknown host");
                    };
                    if let Err(e) = worker.send(HostCmd::SetOwnership {
                        session_id: session_id.to_string(),
                        block_id: block_id.to_string(),
                        mode,
                        cols: c,
                        rows: r,
                        reply: tx,
                    }) {
                        return ActionReply::err(e);
                    }
                }
                match rx.recv_timeout(Duration::from_secs(6)) {
                    Ok(Ok(())) => ActionReply::ok(),
                    Ok(Err(e)) => ActionReply::err(e),
                    Err(_) => ActionReply::err("切换接管超时"),
                }
            }

            RexAction::ScrollVt {
                key,
                delta_lines,
                to_bottom,
            } => {
                self.vt
                    .scroll(&key, delta_lines, to_bottom.unwrap_or(false));
                bump(&self.bus);
                ActionReply::ok()
            }

            RexAction::SaveDraft {
                key,
                text,
                append,
                reserve_bytes,
                if_draft_ver,
                if_boot_id,
                client_id,
                client_seq,
            } => {
                enum SaveOutcome {
                    Early(ActionReply, bool),
                    Committed(u64, u64, Option<String>, Option<u64>, bool, bool),
                }
                let outcome = {
                    let mut st = self.bus.state.lock().unwrap();
                    let now = Instant::now();
                    let dirty_disk = reap_expired_draft_reservations(&mut st, now);
                    if dirty_disk {
                        self.bus.notify_ui();
                    }
                    let cur_ver = st.draft_versions.get(&key).copied().unwrap_or_default();
                    let boot_mismatch = if_boot_id
                        .as_deref()
                        .is_some_and(|b| !b.is_empty() && b != self.boot_id);
                    if boot_mismatch || if_draft_ver.is_some_and(|expected| cur_ver != expected) {
                        let cur_draft = st.drafts.get(&key).cloned().unwrap_or_default();
                        let (cur_cid, cur_cseq) = st
                            .draft_client_acks
                            .get(&key)
                            .map(|(i, s)| ((!i.is_empty()).then(|| i.clone()), Some(*s)))
                            .unwrap_or((None, None));
                        let mut reply = ActionReply::ok();
                        reply.revision = Some(st.revision);
                        reply.draft_ver = Some(cur_ver);
                        reply.client_id = cur_cid;
                        reply.client_seq = cur_cseq;
                        reply.conflict = Some(true);
                        if st.draft_rolled_back_vers.get(&key) == Some(&cur_ver) {
                            reply.reservation_rolled_back = Some(true);
                        }
                        if st
                            .draft_reservations
                            .get(&key)
                            .is_some_and(|r| r.at_ver == cur_ver)
                        {
                            reply.provisional = Some(true);
                        }
                        reply.server_draft = Some(cur_draft);
                        SaveOutcome::Early(reply, dirty_disk)
                    } else {
                        let prior_active_res = st
                            .draft_reservations
                            .get(&key)
                            .filter(|res| res.at_ver == cur_ver && now < res.expires_at)
                            .map(|res| {
                                (
                                    res.reserved_bytes,
                                    res.rollback_draft.clone(),
                                    res.rollback_client_ack.clone(),
                                    res.rollback_unpersisted,
                                )
                            });
                        let existing_in_ram = st.drafts.get(&key).cloned();
                        let (committed_before_chunk, ack_before_chunk, unpersisted_before_chunk) =
                            match &prior_active_res {
                                Some((_, rb, rb_ack, rb_unpers)) => {
                                    (rb.clone(), rb_ack.clone(), *rb_unpers)
                                }
                                None => (
                                    existing_in_ram.clone(),
                                    st.draft_client_acks.get(&key).cloned(),
                                    st.draft_unpersisted_vers.get(&key) == Some(&cur_ver),
                                ),
                            };
                        let mut value = if append == Some(true) {
                            existing_in_ram.unwrap_or_default()
                        } else {
                            String::new()
                        };
                        let active_res_on_append = if append == Some(true) {
                            prior_active_res
                        } else {
                            None
                        };
                        let abort_append_with_rollback =
                            |st: &mut EngineState,
                             bus: &SharedBus,
                             active: Option<(usize, Option<String>, Option<(String, u64)>, bool)>,
                             mut prev_dirty: bool,
                             msg: &str| {
                                if let Some((_, rb, rb_ack, rb_unpers)) = active {
                                    st.draft_reservations.remove(&key);
                                    rollback_draft_reservation(st, &key, rb, rb_ack, rb_unpers);
                                    st.revision += 1;
                                    bus.notify_ui();
                                    prev_dirty = true;
                                }
                                SaveOutcome::Early(ActionReply::err(msg), prev_dirty)
                            };
                        if value.len() + text.len() > MAX_PANE_DRAFT_BYTES {
                            abort_append_with_rollback(
                                &mut st,
                                &self.bus,
                                active_res_on_append,
                                dirty_disk,
                                "draft exceeds 16 KiB limit",
                            )
                        } else {
                            value.push_str(&text);
                            let budget = draft_budget(
                                &st.drafts,
                                &st.draft_versions,
                                &st.draft_reservations,
                                &key,
                            );
                            let over_reserve = append != Some(true)
                                && reserve_bytes.filter(|&b| b > 0).is_some_and(|req_entry| {
                                    let max_entry = budget.saturating_add(entry_bytes(&key, ""));
                                    req_entry > max_entry || req_entry < entry_bytes(&key, &value)
                                });
                            if over_reserve {
                                SaveOutcome::Early(
                                    ActionReply::err("drafts exceed 96 KiB total limit"),
                                    dirty_disk,
                                )
                            } else if !value.is_empty()
                                && draft_prefix(&value, budget).len() < value.len()
                            {
                                abort_append_with_rollback(
                                    &mut st,
                                    &self.bus,
                                    active_res_on_append,
                                    dirty_disk,
                                    "drafts exceed 96 KiB total limit",
                                )
                            } else {
                                let new_entry_bytes = entry_bytes(&key, &value);
                                if value.is_empty() {
                                    st.drafts.remove(&key);
                                } else {
                                    st.drafts.insert(key.clone(), value);
                                }
                                let carry_res = if new_entry_bytes == entry_bytes(&key, "") {
                                    None
                                } else if let Some((prev_bytes, prev_rb, prev_ack, prev_unpers)) =
                                    active_res_on_append
                                {
                                    (prev_bytes > new_entry_bytes)
                                        .then_some((prev_bytes, prev_rb, prev_ack, prev_unpers))
                                } else if append != Some(true) {
                                    reserve_bytes.filter(|&bytes| bytes > new_entry_bytes).map(
                                        |bytes| {
                                            (
                                                bytes,
                                                committed_before_chunk,
                                                ack_before_chunk,
                                                unpersisted_before_chunk,
                                            )
                                        },
                                    )
                                } else {
                                    None
                                };
                                let ver = bump_draft_version(&mut st, &key);
                                st.draft_rolled_back_vers.remove(&key);
                                let is_provisional = carry_res.is_some();
                                let persist_now = if let Some((
                                    res_bytes,
                                    rb_draft,
                                    rb_ack,
                                    rb_unpers,
                                )) = carry_res
                                {
                                    st.draft_reservations.insert(
                                        key.clone(),
                                        DraftReservation {
                                            reserved_bytes: res_bytes,
                                            at_ver: ver,
                                            expires_at: now + Duration::from_secs(15),
                                            rollback_draft: rb_draft,
                                            rollback_client_ack: rb_ack,
                                            rollback_unpersisted: rb_unpers,
                                        },
                                    );
                                    st.draft_unpersisted_vers.insert(key.clone(), ver);
                                    dirty_disk
                                } else {
                                        st.draft_reservations.remove(&key);
                                        if !self.mock {
                                            // Mark unpersisted until `persist_drafts` completes so pre-persistence
                                            // snapshots distinguish in-memory ACK from durable disk commit!
                                            st.draft_unpersisted_vers.insert(key.clone(), ver);
                                        } else {
                                            st.draft_unpersisted_vers.remove(&key);
                                        }
                                        true
                                    };
                                if let Some(cs) = client_seq {
                                    st.draft_client_acks.insert(
                                        key.clone(),
                                        (client_id.clone().unwrap_or_default(), cs),
                                    );
                                } else {
                                    st.draft_client_acks.remove(&key);
                                }
                                let (cid, cseq) = st
                                    .draft_client_acks
                                    .get(&key)
                                    .map(|(i, s)| ((!i.is_empty()).then(|| i.clone()), Some(*s)))
                                    .unwrap_or((None, None));
                                st.revision += 1;
                                let rev = st.revision;
                                self.bus.notify_ui();
                                SaveOutcome::Committed(
                                    ver,
                                    rev,
                                    cid,
                                    cseq,
                                    persist_now,
                                    is_provisional,
                                )
                            }
                        }
                    }
                };
                let (ver, mut rev, cid, cseq, persist_now, is_provisional) = match outcome {
                    SaveOutcome::Early(reply, needs_persist) => {
                        if needs_persist && !self.mock {
                            let _ = self.bus.persist_drafts(&self.config_root);
                        }
                        return reply;
                    }
                    SaveOutcome::Committed(ver, rev, cid, cseq, persist_now, is_provisional) => {
                        (ver, rev, cid, cseq, persist_now, is_provisional)
                    }
                };
                if persist_now && !self.mock {
                    if let Err(e) = self.bus.persist_drafts(&self.config_root) {
                        let mut err_reply = ActionReply::err(format!("保存草稿失败: {e}"));
                        err_reply.revision = Some(rev);
                        err_reply.draft_ver = Some(ver);
                        err_reply.client_id = cid;
                        err_reply.client_seq = cseq;
                        if is_provisional {
                            err_reply.provisional = Some(true);
                        }
                        return err_reply;
                    }
                    rev = self.bus.state.lock().unwrap().revision;
                }
                let mut reply = ActionReply::ok();
                reply.revision = Some(rev);
                reply.draft_ver = Some(ver);
                reply.client_id = cid;
                reply.client_seq = cseq;
                if is_provisional {
                    reply.provisional = Some(true);
                }
                reply
            }

            RexAction::MarkSeen { key } => {
                let active_key = self.active_pane_key.lock().unwrap().clone();
                let mut st = self.bus.state.lock().unwrap();
                if let Some(p) = st.panes.iter_mut().find(|p| p.key == key) {
                    if p.status == PaneActivityStatus::UnseenDone {
                        p.status = PaneActivityStatus::Done;
                        st.completions.entry(key.clone()).or_default().seen = true;
                        st.prev_statuses.insert(key, PaneActivityStatus::Done);
                        recompute_attention_counts(&mut st, active_key.as_deref());
                        st.revision += 1;
                        self.bus.notify_ui();
                    }
                }
                ActionReply::ok()
            }

            RexAction::ToggleMute {} => {
                let muted = {
                    let mut st = self.bus.state.lock().unwrap();
                    st.attention.muted = !st.attention.muted;
                    st.revision += 1;
                    self.bus.notify_ui();
                    st.attention.muted
                };
                if !self.mock {
                    let mut settings = load_settings(&self.config_root);
                    settings.muted = muted;
                    let _ = save_settings(&self.config_root, &settings);
                }
                ActionReply::ok()
            }

            RexAction::NewSession {
                host_id,
                label,
                cwd,
            } => {
                if self.mock {
                    let mut st = self.bus.state.lock().unwrap();
                    let sid = format!("s-mock-{}", st.revision);
                    let bid = "b0".to_string();
                    let key = make_pane_key(&host_id, &sid, &bid);
                    let host_label = st
                        .hosts
                        .iter()
                        .find(|h| h.id == host_id)
                        .map(|h| h.label.clone())
                        .unwrap_or_else(|| host_id.clone());
                    let slabel = label.unwrap_or_else(|| "new-shell".into());
                    st.panes.push(PaneSummary {
                        key: key.clone(),
                        host_id,
                        host_label,
                        session_id: sid,
                        session_label: slabel.clone(),
                        window_id: "w0".into(),
                        window_label: "shell".into(),
                        block_id: bid,
                        title: slabel,
                        program: "zsh".into(),
                        pwd: cwd.unwrap_or_else(|| "~".into()),
                        status: PaneActivityStatus::Idle,
                        status_kind: None,
                        status_msg: None,
                        owned_by_us: false,
                        released_by_us: false,
                        has_draft: false,
                        updated_at_ms: protocol::unix_ms(),
                    });
                    st.revision += 1;
                    self.bus.notify_ui();
                    let mut reply = ActionReply::ok();
                    reply.created_key = Some(key);
                    return reply;
                }

                let (tx, rx) = mpsc::channel();
                {
                    let guard = self.workers.lock().unwrap();
                    let Some(worker) = guard.get(&host_id) else {
                        return ActionReply::err("主机未找到");
                    };
                    if let Err(e) = worker.send(HostCmd::NewSession {
                        deadline: Instant::now() + Duration::from_secs(8),
                        label,
                        cwd,
                        reply: tx,
                    }) {
                        return ActionReply::err(e);
                    }
                }
                match rx.recv_timeout(Duration::from_secs(9)) {
                    Ok(Ok(created_key)) => {
                        let mut r = ActionReply::ok();
                        r.created_key = Some(created_key);
                        r
                    }
                    Ok(Err(e)) => ActionReply::err(e),
                    Err(_) => ActionReply::err("新建会话超时"),
                }
            }

            RexAction::CloseBlock { key } => {
                if self.mock {
                    let mut st = self.bus.state.lock().unwrap();
                    st.panes.retain(|p| p.key != key);
                    st.drafts.remove(&key);
                    bump_draft_version(&mut st, &key);
                    st.staged_inputs.remove(&key);
                    st.prev_statuses.remove(&key);
                    st.completions.remove(&key);
                    st.revision += 1;
                    self.bus.notify_ui();
                    return ActionReply::ok();
                }
                let Some((host_id, session_id, block_id)) = split_pane_key(&key) else {
                    return ActionReply::err("invalid pane key");
                };
                let (tx, rx) = mpsc::channel();
                {
                    let guard = self.workers.lock().unwrap();
                    let Some(worker) = guard.get(host_id) else {
                        return ActionReply::err("unknown host");
                    };
                    if let Err(e) = worker.send(HostCmd::CloseBlock {
                        session_id: session_id.to_string(),
                        block_id: block_id.to_string(),
                        reply: tx,
                    }) {
                        return ActionReply::err(e);
                    }
                }
                match rx.recv_timeout(Duration::from_secs(6)) {
                    Ok(Ok(())) => {
                        let maybe_persist = {
                            let mut st = self.bus.state.lock().unwrap();
                            st.staged_inputs.remove(&key);
                            st.completions.remove(&key);
                            if st.drafts.remove(&key).is_some() {
                                bump_draft_version(&mut st, &key);
                                st.revision += 1;
                                self.bus.notify_ui();
                                true
                            } else {
                                false
                            }
                        };
                        if maybe_persist {
                            let _ = self.bus.persist_drafts(&self.config_root);
                        }
                        ActionReply::ok()
                    }
                    Ok(Err(e)) => ActionReply::err(e),
                    Err(_) => ActionReply::err("关闭窗格超时"),
                }
            }

            RexAction::AddHost {
                label,
                endpoint,
                ssh_key_path,
            } => {
                let mut norm = normalize_endpoint(&endpoint);
                let clean_label = if label.trim().is_empty() {
                    transport::derive_label_from_endpoint(&norm)
                } else {
                    label.trim().to_string()
                };
                let cfg = {
                    let _hosts_guard = (!self.mock).then(|| self.bus.hosts_persist_lock.lock().unwrap());
                    let saved = if self.mock {
                        Vec::new()
                    } else {
                        load_saved_hosts(&self.config_root)
                    };
                    let keyed_ids: std::collections::HashSet<String> = saved
                        .iter()
                        .filter(|s| s.ssh_key_path.is_some())
                        .map(|s| s.id.clone())
                        .collect();
                    let host_id = {
                        let st = self.bus.state.lock().unwrap();
                        if ssh_key_path.is_none() && is_bare_tailnet_ssh(&norm) {
                            let keys = host_tailnet_keys(&norm, &clean_label);
                            if let Some(rex_ep) = find_rex_endpoint_for_keys(&st.tailnet.peers, &keys) {
                                norm = rex_ep;
                            }
                        }
                        let req_keys = host_tailnet_keys(&norm, &clean_label);
                        let adding_https = norm.starts_with("https://") || norm.starts_with("wss://");
                        let existing_id = st
                            .hosts
                            .iter()
                            .find(|h| {
                                if h.id == "local" {
                                    return false;
                                }
                                if adding_https && is_explicit_ssh_host(&h.endpoint, keyed_ids.contains(&h.id)) {
                                    return false;
                                }
                                h.endpoint.eq_ignore_ascii_case(&norm)
                                    || h.label.eq_ignore_ascii_case(&clean_label)
                                    || keys_overlap(&req_keys, &host_tailnet_keys(&h.endpoint, &h.label))
                            })
                            .map(|h| h.id.clone());
                        existing_id.unwrap_or_else(|| {
                            let base = if clean_label.chars().any(|c| c.is_ascii_alphanumeric()) {
                                slug_id(&clean_label, 1)
                            } else {
                                slug_id(&transport::derive_label_from_endpoint(&norm), 1)
                            };
                            allocate_fresh_host_id(&base, adding_https, &st.hosts, &saved)
                        })
                    };
                    let cfg = ConfiguredHost {
                        id: host_id,
                        label: clean_label,
                        endpoint: norm,
                        ssh_key_path,
                    };
                    self.persist_and_apply_host_state(cfg, saved)
                };
                self.respawn_host_worker_if_live(cfg);
                ActionReply::ok()
            }

            RexAction::RemoveHost { host_id } => {
                if let Some(w) = self.workers.lock().unwrap().remove(&host_id) {
                    w.stop();
                }
                let maybe_persist_drafts = {
                    let _hosts_guard = (!self.mock).then(|| self.bus.hosts_persist_lock.lock().unwrap());
                    let has_removed_drafts = {
                        let mut st = self.bus.state.lock().unwrap();
                        st.hosts.retain(|h| h.id != host_id);
                        st.panes.retain(|p| p.host_id != host_id);
                        let prefix = format!("{host_id}|");
                        st.staged_inputs.retain(|k, _| !k.starts_with(&prefix));
                        st.completions.retain(|k, _| !k.starts_with(&prefix));
                        let removed_keys: Vec<String> = st
                            .drafts
                            .keys()
                            .filter(|k| k.starts_with(&prefix))
                            .cloned()
                            .collect();
                        for rk in &removed_keys {
                            st.drafts.remove(rk);
                            bump_draft_version(&mut st, rk);
                        }
                        st.revision += 1;
                        self.bus.notify_ui();
                        !removed_keys.is_empty()
                    };
                    if !self.mock {
                        let mut saved = load_saved_hosts(&self.config_root);
                        saved.retain(|h| h.id != host_id);
                        let _ = save_hosts(&self.config_root, &saved);
                    }
                    has_removed_drafts
                };
                if !self.mock && maybe_persist_drafts {
                    let _ = self.bus.persist_drafts(&self.config_root);
                }
                ActionReply::ok()
            }

            RexAction::ImeCompose {
                raw,
                select_idx,
                page_delta,
                toggle_schema,
            } => {
                let ime_reply =
                    self.rime
                        .compose(&raw, select_idx, page_delta, toggle_schema.unwrap_or(false));
                if toggle_schema == Some(true) {
                    bump(&self.bus);
                }
                let mut reply = ActionReply::ok();
                reply.ime = Some(ime_reply);
                reply
            }

            RexAction::AsrToggle { key } => {
                if self.mock && self.asr.finish_mock_if_recording() {
                    return ActionReply::ok();
                }
                match self.asr.toggle(&key) {
                    Ok(()) => ActionReply::ok(),
                    Err(e) => ActionReply::err(e),
                }
            }

            RexAction::AsrCancel {} => {
                self.asr.cancel();
                ActionReply::ok()
            }

            RexAction::LeavePane {} => {
                let owned_keys: Vec<String> = {
                    let st = self.bus.state.lock().unwrap();
                    st.panes
                        .iter()
                        .filter(|p| p.owned_by_us)
                        .map(|p| p.key.clone())
                        .collect()
                };
                *self.active_pane_key.lock().unwrap() = None;
                for ok in owned_keys {
                    self.auto_disown_if_owned(&ok);
                }
                if !self.mock {
                    self.vt.retain_only(None);
                    let workers = self.workers.lock().unwrap();
                    for worker in workers.values() {
                        let _ = worker.send(HostCmd::CloseStreamsExcept { keep_key: None });
                    }
                }
                let mut st = self.bus.state.lock().unwrap();
                let prev_next = st.attention.next_target_key.clone();
                recompute_attention_counts(&mut st, None);
                if st.attention.next_target_key != prev_next {
                    st.revision += 1;
                    self.bus.notify_ui();
                }
                ActionReply::ok()
            }

            RexAction::AsrConfigure {
                provider,
                api_key,
                app_id,
                endpoint,
            } => {
                let mut settings = load_settings(&self.config_root);
                if settings.asr_key_provider.is_none() && !settings.asr_api_key.trim().is_empty() {
                    let prev_raw = types::AsrProvider::from_name(&settings.asr_provider);
                    let owner = if prev_raw == types::AsrProvider::DoubaoFree {
                        "openai".to_string()
                    } else {
                        settings.asr_provider.clone()
                    };
                    settings.asr_key_provider = Some(owner);
                }
                let target_enum = types::AsrProvider::from_name(&provider);
                let matches_owner = settings.credentials_match_provider(target_enum);
                settings.asr_provider = provider.clone();
                settings.asr_provider_explicit = true;
                if !api_key.trim().is_empty() {
                    settings.asr_api_key = api_key;
                    settings.asr_key_provider = Some(provider);
                    settings.asr_app_id = app_id;
                    settings.asr_endpoint = endpoint;
                } else if matches_owner {
                    if app_id.is_some() {
                        settings.asr_app_id = app_id;
                    }
                    if endpoint.is_some() {
                        settings.asr_endpoint = endpoint;
                    }
                }
                if !self.mock {
                    if let Err(e) = save_settings(&self.config_root, &settings) {
                        return ActionReply::err(format!("保存 ASR 配置失败: {e}"));
                    }
                }
                self.asr.update_settings(settings);
                ActionReply::ok()
            }

            RexAction::TsnetSet {
                enabled,
                hostname,
                auth_key,
            } => {
                if self.mock {
                    let mut st = self.bus.state.lock().unwrap();
                    st.tailnet.enabled = enabled;
                    if enabled {
                        st.tailnet.backend_state = "Running".into();
                        st.tailnet.auth_url.clear();
                        st.tailnet.qr_matrix = None;
                        st.tailnet.proxy_port = 10808;
                    } else {
                        let url = "https://login.tailscale.com/a/rexzero01".to_string();
                        st.tailnet.backend_state = "NeedsLogin".into();
                        st.tailnet.qr_matrix = qr::encode_matrix(&url);
                        st.tailnet.auth_url = url;
                        st.tailnet.proxy_port = 0;
                    }
                    st.revision += 1;
                    self.bus.notify_ui();
                    return ActionReply::ok();
                }

                let mut settings = load_settings(&self.config_root);
                settings.tailnet_enabled = enabled;
                if hostname.is_some() {
                    settings.tailnet_hostname = hostname.clone();
                }
                let _ = save_settings(&self.config_root, &settings);

                match self
                    .tsnet
                    .set_enabled(enabled, hostname.as_deref(), auth_key.as_deref())
                {
                    Ok(()) => ActionReply::ok(),
                    Err(e) => ActionReply::err(e),
                }
            }

            RexAction::TsnetPing { peer_ip } => {
                if self.mock {
                    let mut st = self.bus.state.lock().unwrap();
                    for peer in &mut st.tailnet.peers {
                        if peer.ips.iter().any(|ip| ip == &peer_ip) {
                            peer.latency_ms = Some(2);
                            peer.path_kind = Some(PathKind::Direct);
                        }
                    }
                    st.revision += 1;
                    self.bus.notify_ui();
                    return ActionReply::ok();
                }
                match self.tsnet.ping(&peer_ip) {
                    Ok(()) => ActionReply::ok(),
                    Err(e) => ActionReply::err(e),
                }
            }

            RexAction::TsnetAddPeer {
                dns_name,
                host_name,
                mode,
                ssh_user,
            } => {
                let target = if !dns_name.trim().is_empty() {
                    dns_name.trim()
                } else {
                    host_name.trim()
                };
                let target = target.trim_end_matches('.').to_ascii_lowercase();
                let peer_keys = tsnet::peer_companion_keys(&host_name, &target);
                let clean_ssh_user = ssh_user
                    .map(|u| u.trim().to_string())
                    .filter(|u| !u.is_empty());

                let cfg = {
                    let _hosts_guard = (!self.mock).then(|| self.bus.hosts_persist_lock.lock().unwrap());
                    let saved = if self.mock {
                        Vec::new()
                    } else {
                        load_saved_hosts(&self.config_root)
                    };
                    let keyed_ids: std::collections::HashSet<String> = saved
                        .iter()
                        .filter(|s| s.ssh_key_path.is_some())
                        .map(|s| s.id.clone())
                        .collect();

                    let (endpoint, label, host_id) = {
                        let st = self.bus.state.lock().unwrap();
                        let exact_rex = st
                            .tailnet
                            .peers
                            .iter()
                            .find(|p| p.dns_name.eq_ignore_ascii_case(&target))
                            .and_then(|p| p.rex_endpoint.clone())
                            .filter(|ep| ep.starts_with("http"));
                        let matched_rex_ep = exact_rex
                            .or_else(|| find_rex_endpoint_for_keys(&st.tailnet.peers, &peer_keys));

                        let use_https = clean_ssh_user.is_none()
                            && (mode == PeerAddMode::Https
                                || tsnet::is_rex_node_name(&host_name, &target)
                                || matched_rex_ep.is_some());

                        let endpoint = if use_https {
                            matched_rex_ep.unwrap_or_else(|| format!("https://{target}"))
                        } else {
                            match mode {
                                PeerAddMode::Https => format!("https://{target}"),
                                PeerAddMode::Ssh => match clean_ssh_user {
                                    Some(u) => format!("ssh://{u}@{target}"),
                                    None => format!("ssh://{target}"),
                                },
                            }
                        };

                        let friendly = if tsnet::is_rex_node_name(&host_name, &target) {
                            st.tailnet
                                .peers
                                .iter()
                                .find(|p| {
                                    !tsnet::is_rex_node_name(&p.host_name, &p.dns_name)
                                        && !p.host_name.trim().is_empty()
                                        && keys_overlap(
                                            &peer_keys,
                                            &tsnet::peer_companion_keys(&p.host_name, &p.dns_name),
                                        )
                                })
                                .map(|p| p.host_name.trim().to_string())
                        } else {
                            None
                        };
                        let mut resolved_label = friendly.unwrap_or_else(|| strip_rex_suffix(&host_name));
                        if use_https
                            && st.hosts.iter().any(|h| {
                                h.id != "local"
                                    && is_explicit_ssh_host(&h.endpoint, keyed_ids.contains(&h.id))
                                    && h.label.eq_ignore_ascii_case(&resolved_label)
                            })
                        {
                            resolved_label = format!("{resolved_label} (Rex)");
                        }

                        let existing_id = st
                            .hosts
                            .iter()
                            .find(|h| {
                                if h.id == "local" {
                                    return false;
                                }
                                if use_https && is_explicit_ssh_host(&h.endpoint, keyed_ids.contains(&h.id)) {
                                    return false;
                                }
                                let h_dns = endpoint_dns_host(&h.endpoint);
                                h.endpoint.eq_ignore_ascii_case(&endpoint)
                                    || (!target.is_empty() && h_dns.as_deref() == Some(target.as_str()))
                                    || h.label.eq_ignore_ascii_case(&resolved_label)
                                    || keys_overlap(&peer_keys, &host_tailnet_keys(&h.endpoint, &h.label))
                            })
                            .map(|h| h.id.clone());

                        let resolved_id = existing_id.unwrap_or_else(|| {
                            let primary_key = peer_keys.iter().flatten().next().map(String::as_str);
                            let base = if let Some(pk) = primary_key {
                                slug_id(pk, 2)
                            } else {
                                slug_id(&resolved_label, 2)
                            };
                            allocate_fresh_host_id(&base, use_https, &st.hosts, &saved)
                        });
                        (endpoint, resolved_label, resolved_id)
                    };

                    let cfg = ConfiguredHost {
                        id: host_id,
                        label,
                        endpoint,
                        ssh_key_path: None,
                    };
                    self.persist_and_apply_host_state(cfg, saved)
                };
                self.respawn_host_worker_if_live(cfg);
                ActionReply::ok()
            }

            RexAction::PairToggle { active } => match self.pair.toggle(active, None) {
                Ok(()) => ActionReply::ok(),
                Err(e) => ActionReply::err(e),
            },

            RexAction::PairConfirm { approve, token } => {
                let Some(token) = token else {
                    return ActionReply::err("missing pairing token");
                };
                match self
                    .pair
                    .take_confirmed_import_matching(approve, Some(&token))
                {
                    Ok(Some(imp)) => {
                        if let Err(e) = self.commit_staged_import(imp) {
                            bump(&self.bus);
                            return ActionReply::err(e);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => return ActionReply::err(e),
                }
                bump(&self.bus);
                ActionReply::ok()
            }

            RexAction::SetUiPrefs {
                font_preset,
                reader_mode,
            } => {
                let (next_preset, next_mode) = {
                    let mut st = self.bus.state.lock().unwrap();
                    if let Some(p) = font_preset {
                        st.font_preset = p.min(2);
                        apply_font_preset_crisp(st.font_preset);
                    }
                    if let Some(m) = reader_mode {
                        st.reader_mode = normalize_reader_mode(&m);
                    }
                    st.revision += 1;
                    self.bus.notify_ui();
                    (st.font_preset, st.reader_mode.clone())
                };
                if !self.mock {
                    let mut settings = load_settings(&self.config_root);
                    settings.font_preset = next_preset;
                    settings.reader_mode = next_mode;
                    let _ = save_settings(&self.config_root, &settings);
                }
                ActionReply::ok()
            }
        }
    }

    fn add_or_replace_host(&self, cfg: ConfiguredHost) {
        let finalized = {
            let _hosts_guard = (!self.mock).then(|| self.bus.hosts_persist_lock.lock().unwrap());
            let saved = if self.mock {
                Vec::new()
            } else {
                load_saved_hosts(&self.config_root)
            };
            self.persist_and_apply_host_state(cfg, saved)
        };
        self.respawn_host_worker_if_live(finalized);
    }

    fn persist_and_apply_host_state(
        &self,
        mut cfg: ConfiguredHost,
        mut saved: Vec<ConfiguredHost>,
    ) -> ConfiguredHost {
        let (kind, path_kind) = classify_endpoint(&cfg.endpoint);
        if !self.mock {
            if cfg.ssh_key_path.is_none() && cfg.endpoint.starts_with("ssh://") {
                if let Some(existing_key) = saved
                    .iter()
                    .find(|h| h.id == cfg.id && h.endpoint == cfg.endpoint)
                    .and_then(|h| h.ssh_key_path.clone())
                {
                    cfg.ssh_key_path = Some(existing_key);
                }
            }
            saved.retain(|h| h.id != cfg.id);
            saved.push(cfg.clone());
            let _ = save_hosts(&self.config_root, &saved);
        }
        {
            let mut st = self.bus.state.lock().unwrap();
            st.hosts.retain(|h| h.id != cfg.id);
            st.hosts.push(HostState {
                id: cfg.id.clone(),
                label: cfg.label.clone(),
                kind,
                endpoint: cfg.endpoint.clone(),
                phase: if self.mock {
                    ConnPhase::Live
                } else {
                    ConnPhase::Connecting
                },
                problem: None,
                latency_ms: self.mock.then_some(4),
                path_kind: Some(path_kind),
                sessions: Vec::new(),
            });
            st.revision += 1;
            self.bus.notify_ui();
        }
        cfg
    }

    fn respawn_host_worker_if_live(&self, cfg: ConfiguredHost) {
        if !self.mock {
            if let Some(old) = self.workers.lock().unwrap().remove(&cfg.id) {
                old.stop();
            }
            self.spawn_host_worker(cfg);
        }
    }

    fn commit_staged_import(&self, imp: pair::StagedImport) -> Result<(), String> {
        for host in &imp.hosts {
            transport::parse_endpoint(&host.endpoint)
                .map_err(|e| format!("主机地址无效 ({}): {e}", host.endpoint))?;
        }
        let mut ssh_key_path: Option<String> = None;
        if let Some(pem) = imp.ssh_private_key {
            let mut normalized = pem.replace("\r\n", "\n");
            if !normalized.ends_with('\n') {
                normalized.push('\n');
            }
            let hex_bytes = pocketjs_core::sha256::sha256_hex_prefix::<16>(normalized.as_bytes());
            let hex16 = std::str::from_utf8(&hex_bytes).unwrap_or("paired");
            let key_file = self.config_root.join(format!("ssh/id_paired_{hex16}"));
            write_private_file(&key_file, normalized.as_bytes())
                .map_err(|e| format!("写入 SSH 私钥失败: {e}"))?;
            ssh_key_path = Some(key_file.to_string_lossy().into_owned());
        }

        if let Some(api_key) = imp.asr_api_key {
            let mut settings = load_settings(&self.config_root);
            if let Some(prov) = imp.asr_provider {
                settings.asr_provider = prov;
            } else if matches!(
                types::AsrProvider::from_name(&settings.asr_provider),
                types::AsrProvider::DoubaoFree | types::AsrProvider::Plugin
            ) {
                settings.asr_provider = "openai".into();
            }
            settings.asr_provider_explicit = true;
            settings.asr_key_provider = Some(settings.asr_provider.clone());
            settings.asr_api_key = api_key;
            if imp.asr_app_id.is_some() {
                settings.asr_app_id = imp.asr_app_id;
            }
            if imp.asr_endpoint.is_some() {
                settings.asr_endpoint = imp.asr_endpoint;
            }
            save_settings(&self.config_root, &settings)
                .map_err(|e| format!("保存 ASR 配置失败: {e}"))?;
            self.asr.update_settings(settings);
        }

        for mut host in imp.hosts {
            if host.ssh_key_path.is_none() && host.endpoint.starts_with("ssh://") {
                host.ssh_key_path = ssh_key_path.clone();
            }
            self.add_or_replace_host(host);
        }
        Ok(())
    }
}

impl Drop for RexZeroEngine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ============================================================================
// Event Reduction, Attention Ledger, & Two-Tone Audio Chime
// ============================================================================

fn bump(bus: &SharedBus) {
    let mut st = bus.state.lock().unwrap();
    st.revision += 1;
    bus.notify_ui();
}

fn apply_asr_event(bus: &SharedBus, persist_dir: Option<&Path>, ev: AsrEvent) {
    let maybe_persist = {
        let mut st = bus.state.lock().unwrap();
        let now = Instant::now();
        let mut drafts_changed = reap_expired_draft_reservations(&mut st, now);
        match ev {
            AsrEvent::StateChanged(next_asr) => {
                st.asr = next_asr;
            }
            AsrEvent::Transcript { target_key, text } => {
                let cur_ver = st.draft_versions.get(&target_key).copied().unwrap_or_default();
                let active_res = st
                    .draft_reservations
                    .get(&target_key)
                    .filter(|res| res.at_ver == cur_ver)
                    .map(|res| (res.rollback_draft.clone(), res.rollback_client_ack.clone()));
                let old_owned = match &active_res {
                    Some((rb, _)) => rb.clone().unwrap_or_default(),
                    None => st.drafts.get(&target_key).cloned().unwrap_or_default(),
                };
                let old = old_owned.as_str();
                let sep = if old.is_empty() || old.ends_with(' ') {
                    ""
                } else {
                    " "
                };
                let budget = draft_budget(
                    &st.drafts,
                    &st.draft_versions,
                    &st.draft_reservations,
                    &target_key,
                );
                let mut value = old.to_owned();
                if !text.is_empty() {
                    value.push_str(sep);
                    value.push_str(
                        &text[..text.floor_char_boundary(text.len().min(MAX_PANE_DRAFT_BYTES))],
                    );
                }
                let len = draft_prefix(&value, budget).len();
                if len > old.len() + sep.len() {
                    value.truncate(len);
                    let was_rolled_back = active_res.is_some()
                        || st.draft_rolled_back_vers.get(&target_key) == Some(&cur_ver);
                    if let Some((_, rb_ack)) = active_res {
                        st.draft_reservations.remove(&target_key);
                        match rb_ack {
                            Some(ack) => {
                                st.draft_client_acks.insert(target_key.clone(), ack);
                            }
                            None => {
                                st.draft_client_acks.remove(&target_key);
                            }
                        }
                    }
                    st.drafts.insert(target_key.clone(), value);
                    let new_ver = bump_draft_version(&mut st, &target_key);
                    if was_rolled_back {
                        st.draft_rolled_back_vers.insert(target_key.clone(), new_ver);
                    }
                    if persist_dir.is_some() {
                        st.draft_unpersisted_vers.insert(target_key, new_ver);
                    } else {
                        st.draft_unpersisted_vers.remove(&target_key);
                    }
                    drafts_changed = true;
                }
            }
        }
        st.revision += 1;
        bus.notify_ui();
        drafts_changed
    };
    if let (Some(dir), true) = (persist_dir, maybe_persist) {
        let _ = bus.persist_drafts(dir);
    }
}

struct TailnetApplyCtx {
    bus: Arc<SharedBus>,
    proxy_port: Arc<AtomicU16>,
    cfg_root: PathBuf,
    workers: Arc<Mutex<HashMap<String, HostWorkerHandle>>>,
    device: Option<Device>,
    play_audio: bool,
    active_pane_key: Arc<Mutex<Option<String>>>,
    vt: VtActor,
    spawn_workers: bool,
}

fn spawn_host_worker_into(
    workers: &Arc<Mutex<HashMap<String, HostWorkerHandle>>>,
    bus: &Arc<SharedBus>,
    dev: Option<Device>,
    play_audio: bool,
    active_pane_key: &Arc<Mutex<Option<String>>>,
    vt: &VtActor,
    proxy_port: &Arc<AtomicU16>,
    cfg: ConfiguredHost,
) {
    let bus_hook = bus.clone();
    let active_for_hook = active_pane_key.clone();
    let hook = Arc::new(move |ev: HostEvent| {
        apply_host_event(&bus_hook, dev.as_ref(), play_audio, &active_for_hook, ev);
    });
    if let Ok(handle) = HostWorkerHandle::spawn(
        cfg.clone(),
        proxy_port.clone(),
        vt.clone(),
        active_pane_key.clone(),
        hook,
    ) {
        workers.lock().unwrap().insert(cfg.id, handle);
    }
}

fn strip_rex_suffix(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.len() > 4 && trimmed.as_bytes()[trimmed.len() - 4..].eq_ignore_ascii_case(b"-rex") {
        trimmed[..trimmed.len() - 4].to_string()
    } else {
        trimmed.to_string()
    }
}

fn endpoint_dns_host(endpoint: &str) -> Option<String> {
    let dns_host = match transport::parse_endpoint(endpoint).ok()? {
        transport::ParsedEndpoint::Ssh { host_only, .. } => host_only,
        transport::ParsedEndpoint::Network { host, .. } => host,
        transport::ParsedEndpoint::Unix(_) => return None,
    };
    Some(dns_host.trim_end_matches('.').to_ascii_lowercase())
}

fn host_tailnet_keys(endpoint: &str, label: &str) -> [Option<String>; 2] {
    let Some(dns_host) = endpoint_dns_host(endpoint) else {
        return [None, None];
    };
    if !transport::is_magic_dns(&dns_host) {
        return [None, None];
    }
    tsnet::peer_companion_keys(label, &dns_host)
}

fn keys_overlap(a: &[Option<String>; 2], b: &[Option<String>; 2]) -> bool {
    a.iter()
        .flatten()
        .any(|ka| b.iter().flatten().any(|kb| ka == kb))
}

fn is_explicit_ssh_host(endpoint: &str, has_ssh_key: bool) -> bool {
    let Some(rest) = endpoint.strip_prefix("ssh://") else {
        return false;
    };
    rest.contains('@') || has_ssh_key
}

fn allocate_fresh_host_id(
    base: &str,
    prefer_rex_suffix: bool,
    hosts: &[HostState],
    saved: &[ConfiguredHost],
) -> String {
    let in_use = |candidate: &str| -> bool {
        candidate == "local"
            || hosts.iter().any(|h| h.id == candidate)
            || saved.iter().any(|s| s.id == candidate)
    };
    if !in_use(base) {
        return base.to_string();
    }
    let stem = if prefer_rex_suffix && !base.ends_with("-rex") {
        let rex_id = format!("{base}-rex");
        if !in_use(&rex_id) {
            return rex_id;
        }
        rex_id
    } else {
        base.to_string()
    };
    for n in 2usize.. {
        let candidate = format!("{stem}-{n}");
        if !in_use(&candidate) {
            return candidate;
        }
    }
    unreachable!()
}

fn is_bare_tailnet_ssh(endpoint: &str) -> bool {
    let Some(rest) = endpoint.strip_prefix("ssh://") else {
        return false;
    };
    if rest.contains('@') {
        return false;
    }
    matches!(
        transport::parse_endpoint(endpoint),
        Ok(transport::ParsedEndpoint::Ssh {
            host_only,
            port: None,
            ..
        }) if transport::is_magic_dns(&host_only)
    )
}

fn find_rex_endpoint_for_keys(
    peers: &[types::TailnetPeer],
    keys: &[Option<String>; 2],
) -> Option<String> {
    if keys.iter().all(Option::is_none) {
        return None;
    }
    peers
        .iter()
        .find(|p| {
            tsnet::is_rex_node_name(&p.host_name, &p.dns_name)
                && keys_overlap(keys, &tsnet::peer_companion_keys(&p.host_name, &p.dns_name))
                && p.rex_endpoint
                    .as_deref()
                    .is_some_and(|ep| ep.starts_with("http"))
        })
        .or_else(|| {
            peers.iter().find(|p| {
                keys_overlap(keys, &tsnet::peer_companion_keys(&p.host_name, &p.dns_name))
                    && p.rex_endpoint
                        .as_deref()
                        .is_some_and(|ep| ep.starts_with("http"))
            })
        })
        .and_then(|p| p.rex_endpoint.clone())
}

fn apply_tailnet_update(ctx: &TailnetApplyCtx, upd: TailnetUpdate) {
    let mut should_wake_workers = false;
    let mut has_upgrade_candidates = false;
    {
        let mut st = ctx.bus.state.lock().unwrap();
        match upd {
            TailnetUpdate::State(next) => {
                let prev_proxy = ctx.proxy_port.swap(next.proxy_port, Ordering::Relaxed);
                let was_peers_empty = st.tailnet.peers.is_empty();
                let has_peers = !next.peers.is_empty();
                should_wake_workers =
                    (prev_proxy == 0 && next.proxy_port > 0) || (was_peers_empty && has_peers);
                st.tailnet = next;

                if has_peers {
                    has_upgrade_candidates = st.hosts.iter().any(|h| {
                        h.id != "local"
                            && is_bare_tailnet_ssh(&h.endpoint)
                            && find_rex_endpoint_for_keys(
                                &st.tailnet.peers,
                                &host_tailnet_keys(&h.endpoint, &h.label),
                            )
                            .is_some()
                    });
                }
            }
            TailnetUpdate::PingResult {
                peer_ip,
                latency_ms,
                path_kind,
                error,
            } => {
                st.tailnet.error = error;
                for p in &mut st.tailnet.peers {
                    if p.ips.iter().any(|ip| ip == &peer_ip) {
                        p.latency_ms = latency_ms;
                        if path_kind.is_some() {
                            p.path_kind = path_kind;
                        }
                    }
                }
            }
            TailnetUpdate::ProbeResult {
                dns_name,
                rex_endpoint,
            } => {
                for p in &mut st.tailnet.peers {
                    if p.dns_name == dns_name {
                        p.rex_endpoint = rex_endpoint.clone();
                    }
                }
            }
        }
        st.revision += 1;
        ctx.bus.notify_ui();
    }

    if has_upgrade_candidates {
        let to_respawn: Vec<ConfiguredHost> = {
            let _hosts_guard = ctx.bus.hosts_persist_lock.lock().unwrap();
            let mut saved = load_saved_hosts(&ctx.cfg_root);
            let keyed_ids: std::collections::HashSet<String> = saved
                .iter()
                .filter(|s| s.ssh_key_path.is_some())
                .map(|s| s.id.clone())
                .collect();

            let mut respawn = Vec::new();
            let mut saved_changed = false;
            {
                let mut st = ctx.bus.state.lock().unwrap();
                let peers = st.tailnet.peers.clone();
                for slot in &mut st.hosts {
                    if slot.id == "local"
                        || keyed_ids.contains(&slot.id)
                        || !is_bare_tailnet_ssh(&slot.endpoint)
                    {
                        continue;
                    }
                    let keys = host_tailnet_keys(&slot.endpoint, &slot.label);
                    let Some(new_ep) = find_rex_endpoint_for_keys(&peers, &keys) else {
                        continue;
                    };
                    let old_ep = slot.endpoint.clone();
                    let (kind, path_kind) = classify_endpoint(&new_ep);
                    slot.endpoint = new_ep.clone();
                    slot.kind = kind;
                    slot.path_kind = Some(path_kind);
                    slot.phase = ConnPhase::Connecting;
                    slot.problem = None;
                    if let Some(saved_slot) = saved
                        .iter_mut()
                        .find(|s| s.id == slot.id && s.endpoint == old_ep && s.ssh_key_path.is_none())
                    {
                        saved_slot.endpoint = new_ep.clone();
                        saved_changed = true;
                    }
                    respawn.push(ConfiguredHost {
                        id: slot.id.clone(),
                        label: slot.label.clone(),
                        endpoint: new_ep,
                        ssh_key_path: None,
                    });
                }
                if !respawn.is_empty() {
                    st.revision += 1;
                    ctx.bus.notify_ui();
                }
            }
            if saved_changed {
                let _ = save_hosts(&ctx.cfg_root, &saved);
            }
            respawn
        };

        if ctx.spawn_workers {
            for cfg in to_respawn {
                if let Some(old) = ctx.workers.lock().unwrap().remove(&cfg.id) {
                    old.stop();
                }
                spawn_host_worker_into(
                    &ctx.workers,
                    &ctx.bus,
                    ctx.device.clone(),
                    ctx.play_audio,
                    &ctx.active_pane_key,
                    &ctx.vt,
                    &ctx.proxy_port,
                    cfg,
                );
            }
        }
    }

    if should_wake_workers {
        let guard = ctx.workers.lock().unwrap();
        for worker in guard.values() {
            worker.wake();
        }
    }
}

fn apply_host_event(
    bus: &SharedBus,
    device: Option<&Device>,
    play_audio: bool,
    active_pane_key: &Mutex<Option<String>>,
    ev: HostEvent,
) {
    let active_key = active_pane_key.lock().unwrap().clone();
    let mut chime_to_play: Option<ChimeKind> = None;
    {
        let mut st = bus.state.lock().unwrap();
        match ev {
            HostEvent::HostSnapshot { host, panes } => {
                let host_id = host.id.clone();
                let Some(slot) = st
                    .hosts
                    .iter_mut()
                    .find(|h| h.id == host_id && h.endpoint == host.endpoint)
                else {
                    return;
                };
                *slot = host;

                let mut merged_panes = Vec::with_capacity(panes.len());
                for (mut p, run_epoch) in panes {
                    let prev = st.prev_statuses.get(&p.key).copied();
                    let completion = st.completions.entry(p.key.clone()).or_default();
                    let new_run = run_epoch != 0 && run_epoch != completion.run_epoch;
                    if new_run {
                        completion.run_epoch = run_epoch;
                        completion.seen = false;
                    }
                    match p.status {
                        PaneActivityStatus::UnseenDone if completion.seen => {
                            p.status = PaneActivityStatus::Done
                        }
                        PaneActivityStatus::Done
                            if !new_run
                                && !completion.seen
                                && prev == Some(PaneActivityStatus::UnseenDone) =>
                        {
                            p.status = PaneActivityStatus::UnseenDone
                        }
                        PaneActivityStatus::Done => completion.seen = true,
                        PaneActivityStatus::Running
                        | PaneActivityStatus::Blocked
                        | PaneActivityStatus::Error => completion.seen = false,
                        _ => {}
                    }
                    if prev != Some(p.status) {
                        match p.status {
                            PaneActivityStatus::Blocked => {
                                chime_to_play = Some(ChimeKind::Approval);
                            }
                            PaneActivityStatus::Error if chime_to_play.is_none() => {
                                chime_to_play = Some(ChimeKind::Error);
                            }
                            PaneActivityStatus::UnseenDone if chime_to_play.is_none() => {
                                chime_to_play = Some(ChimeKind::Done);
                            }
                            _ => {}
                        }
                        st.prev_statuses.insert(p.key.clone(), p.status);
                    }
                    merged_panes.push(p);
                }

                st.panes.retain(|p| p.host_id != host_id);
                st.panes.extend(merged_panes);
                sort_panes_by_priority(&mut st.panes);
                recompute_attention_counts(&mut st, active_key.as_deref());

                if let Some(kind) = chime_to_play {
                    if !st.attention.muted {
                        st.attention.chime_seq += 1;
                        st.attention.chime_kind = kind;
                    } else {
                        chime_to_play = None;
                    }
                }
            }
            HostEvent::PaneStreamPhase {
                key,
                phase,
                problem,
            } => {
                st.stream_states.insert(key, (phase, problem));
            }
            HostEvent::TerminalUpdated => {}
        }
        st.revision += 1;
        bus.notify_ui();
    }

    if play_audio {
        if let (Some(kind), Some(dev)) = (chime_to_play, device.cloned()) {
            let _ = thread::Builder::new()
                .name("rex-zero-chime".into())
                .stack_size(128 * 1024)
                .spawn(move || {
                    let _ = dev.handle("POST", "/dev/audio/beep", b"");
                    if kind == ChimeKind::Approval {
                        thread::sleep(Duration::from_millis(140));
                        let _ = dev.handle("POST", "/dev/audio/beep", b"");
                    }
                });
        }
    }
}

fn sync_pane_draft_flags(st: &mut EngineState) {
    for p in &mut st.panes {
        p.has_draft = st.drafts.get(&p.key).is_some_and(|d| !d.is_empty());
    }
}

fn sort_panes_by_priority(panes: &mut [PaneSummary]) {
    panes.sort_by(|a, b| {
        a.status
            .priority_rank()
            .cmp(&b.status.priority_rank())
            .then_with(|| b.updated_at_ms.cmp(&a.updated_at_ms))
            .then_with(|| a.key.cmp(&b.key))
    });
}

fn recompute_attention_counts(st: &mut EngineState, active_key: Option<&str>) {
    let panes = &st.panes;
    let att = &mut st.attention;
    att.blocked_count = panes
        .iter()
        .filter(|p| p.status == PaneActivityStatus::Blocked)
        .count();
    att.error_count = panes
        .iter()
        .filter(|p| p.status == PaneActivityStatus::Error)
        .count();
    att.unseen_done_count = panes
        .iter()
        .filter(|p| p.status == PaneActivityStatus::UnseenDone)
        .count();
    // Off-screen attention exclusion (`M3.2-activity-chip`): exclude the currently viewed
    // `active_key` so pressing `n` always jumps to another waiting background pane!
    att.next_target_key = panes
        .iter()
        .find(|p| p.status.needs_attention() && Some(p.key.as_str()) != active_key)
        .map(|p| p.key.clone());
}

fn mark_added_tailnet_peers(st: &mut EngineState) {
    let hosts = &st.hosts;
    let host_info: Vec<(Option<String>, [Option<String>; 2], bool)> = hosts
        .iter()
        .filter(|h| h.id != "local")
        .map(|h| {
            let explicit_user_ssh =
                h.endpoint.starts_with("ssh://") && h.endpoint["ssh://".len()..].contains('@');
            (
                endpoint_dns_host(&h.endpoint),
                host_tailnet_keys(&h.endpoint, &h.label),
                explicit_user_ssh,
            )
        })
        .collect();
    for peer in &mut st.tailnet.peers {
        let dns_name = peer.dns_name.trim_end_matches('.').to_ascii_lowercase();
        let peer_rex = peer
            .rex_endpoint
            .as_deref()
            .map(|s| s.trim_end_matches('/').to_ascii_lowercase())
            .unwrap_or_default();
        let peer_is_rex = tsnet::is_rex_node_name(&peer.host_name, &dns_name);
        let peer_keys = tsnet::peer_companion_keys(&peer.host_name, &dns_name);
        let key_matched = host_info.iter().any(|(h_dns, h_keys, explicit_ssh)| {
            if peer_is_rex && *explicit_ssh {
                return false;
            }
            (!dns_name.is_empty() && h_dns.as_deref() == Some(dns_name.as_str()))
                || keys_overlap(&peer_keys, h_keys)
        });
        peer.already_added = key_matched
            || hosts.iter().any(|h| {
                h.id != "local"
                    && ((!peer_rex.is_empty()
                        && h.endpoint.trim_end_matches('/').eq_ignore_ascii_case(&peer_rex))
                        || (!peer_is_rex
                            && !peer.host_name.is_empty()
                            && h.label.eq_ignore_ascii_case(&peer.host_name)))
            });
    }
}

fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (k, v) = part.split_once('=').unwrap_or((part, ""));
            let dk = percent_decode_str(k).decode_utf8_lossy().into_owned();
            let dv = percent_decode_str(v).decode_utf8_lossy().into_owned();
            (dk, dv)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tailnet_update_upgrades_bare_ssh_and_companion_add_uses_https_rex() {
        let dir = std::env::temp_dir().join(format!("rex-tailnet-upgrade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        save_hosts(
            &dir,
            &[
                ConfiguredHost {
                    id: "alice-mac-mini".into(),
                    label: "Alice的Mac Mini".into(),
                    endpoint: "ssh://alicemac-mini.example-tailnet.ts.net".into(),
                    ssh_key_path: None,
                },
                ConfiguredHost {
                    id: "explicit-ssh".into(),
                    label: "Explicit SSH".into(),
                    endpoint: "ssh://alice@alicemac-mini.example-tailnet.ts.net".into(),
                    ssh_key_path: None,
                },
            ],
        )
        .unwrap();

        let engine = RexZeroEngine::new_live_with_config(dir.clone(), None, true, false, false);
        let ctx = TailnetApplyCtx {
            bus: engine.bus.clone(),
            proxy_port: engine.tsnet_proxy_port.clone(),
            cfg_root: dir.clone(),
            workers: engine.workers.clone(),
            device: None,
            play_audio: false,
            active_pane_key: engine.active_pane_key.clone(),
            vt: engine.vt.clone(),
            spawn_workers: false,
        };
        apply_tailnet_update(
            &ctx,
            TailnetUpdate::State(TailnetState {
                enabled: true,
                backend_state: "Running".into(),
                proxy_port: 19001,
                peers: vec![
                    types::TailnetPeer {
                        host_name: "alice-mac-mini-rex".into(),
                        dns_name: "alice-mac-mini-rex.example-tailnet.ts.net".into(),
                        ips: vec![],
                        online: true,
                        path_kind: Some(PathKind::Direct),
                        latency_ms: None,
                        rex_endpoint: Some("https://alice-mac-mini-rex.example-tailnet.ts.net".into()),
                        already_added: false,
                    },
                    types::TailnetPeer {
                        host_name: "MacWork".into(),
                        dns_name: "macwork.example-tailnet.ts.net".into(),
                        ips: vec![],
                        online: true,
                        path_kind: Some(PathKind::Direct),
                        latency_ms: None,
                        rex_endpoint: Some("https://macwork-rex.example-tailnet.ts.net".into()),
                        already_added: false,
                    },
                ],
                ..TailnetState::default()
            }),
        );

        let saved = load_saved_hosts(&dir);
        assert_eq!(
            saved[0].endpoint,
            "https://alice-mac-mini-rex.example-tailnet.ts.net"
        );
        assert_eq!(
            saved[1].endpoint,
            "ssh://alice@alicemac-mini.example-tailnet.ts.net"
        );

        // Clicking companion OS peer MacWork even with PeerAddMode::Ssh resolves to https://macwork-rex...
        assert!(
            engine
                .execute_action(RexAction::TsnetAddPeer {
                    dns_name: "macwork.example-tailnet.ts.net".into(),
                    host_name: "MacWork".into(),
                    mode: PeerAddMode::Ssh,
                    ssh_user: None,
                })
                .ok
        );
        // Unicode 6-byte name ("台北") does not panic and preserves explicit SSH host!
        assert!(
            engine
                .execute_action(RexAction::TsnetAddPeer {
                    dns_name: "taipei.example-tailnet.ts.net".into(),
                    host_name: "台北".into(),
                    mode: PeerAddMode::Ssh,
                    ssh_user: None,
                })
                .ok
        );
        // Adding Rex companion when an explicit SSH host shares the machine AND `<base>-rex` is owned by an unrelated saved host preserves BOTH!
        save_hosts(
            &dir,
            &[
                ConfiguredHost {
                    id: "lab-nas".into(),
                    label: "lab-nas".into(),
                    endpoint: "ssh://lab-nas.example-tailnet.ts.net".into(),
                    ssh_key_path: Some("/tmp/id_ed25519".into()),
                },
                ConfiguredHost {
                    id: "lab-nas-rex".into(),
                    label: "Other LAN Box".into(),
                    endpoint: "tcp://10.0.0.5:7297".into(),
                    ssh_key_path: None,
                },
            ],
        )
        .unwrap();
        let engine2 = RexZeroEngine::new_live_with_config(dir.clone(), None, true, false, false);
        assert!(
            engine2
                .execute_action(RexAction::TsnetAddPeer {
                    dns_name: "lab-nas-rex.example-tailnet.ts.net".into(),
                    host_name: "lab-nas-rex".into(),
                    mode: PeerAddMode::Https,
                    ssh_user: None,
                })
                .ok
        );
        let saved2 = load_saved_hosts(&dir);
        assert_eq!(saved2.len(), 3);
        assert_eq!(saved2[0].endpoint, "ssh://lab-nas.example-tailnet.ts.net");
        assert_eq!(saved2[0].ssh_key_path.as_deref(), Some("/tmp/id_ed25519"));
        assert_eq!(saved2[1].endpoint, "tcp://10.0.0.5:7297");
        assert_eq!(saved2[2].id, "lab-nas-rex-2");
        assert_eq!(saved2[2].endpoint, "https://lab-nas-rex.example-tailnet.ts.net");

        let st = engine.bus.state.lock().unwrap();
        let macwork = st.hosts.iter().find(|h| h.label == "MacWork").unwrap();
        assert_eq!(macwork.endpoint, "https://macwork-rex.example-tailnet.ts.net");
        let taipei = st.hosts.iter().find(|h| h.label == "台北").unwrap();
        assert_eq!(taipei.endpoint, "ssh://taipei.example-tailnet.ts.net");
        drop(st);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn draft_writers_snapshot_after_acquiring_disk_lock() {
        let dir = std::env::temp_dir().join(format!("rex-draft-writers-{}", std::process::id()));
        let engine = RexZeroEngine::new_live_with_config(dir.clone(), None, true, false, false);
        let writer = engine.bus.draft_persist_lock.lock().unwrap();
        std::thread::scope(|scope| {
            for text in ["first", "last"] {
                let engine = &engine;
                scope.spawn(move || {
                    assert!(
                        engine
                            .execute_action(RexAction::SaveDraft {
                                key: "pane".into(),
                                text: text.into(),
                                append: None,
                                reserve_bytes: None,
                                if_draft_ver: None,
                                if_boot_id: None,
                                client_id: None,
                                client_seq: None,
                            })
                            .ok
                    );
                });
                let deadline = Instant::now() + Duration::from_secs(2);
                while engine
                    .bus
                    .state
                    .lock()
                    .unwrap()
                    .drafts
                    .get("pane")
                    .map(String::as_str)
                    != Some(text)
                {
                    assert!(Instant::now() < deadline);
                    std::thread::yield_now();
                }
            }
            assert!(!dir.join("drafts.json").exists());
            drop(writer);
        });
        assert_eq!(load_drafts(&dir)["pane"], "last");
        drop(engine);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn final_stage_size_is_checked_before_consuming_prefix() {
        let engine = RexZeroEngine::new_mock(None);
        let send = |data: String, stage| {
            engine.execute_action(RexAction::SendInput {
                key: "test".into(),
                data,
                stage: Some(stage),
                reset_stage: Some(stage),
                stage_id: Some("id".into()),
                clear_draft: None,
                if_draft_ver: None,
                if_boot_id: None,
                client_id: None,
                client_seq: None,
            })
        };
        assert!(send("x".repeat(MAX_STAGED_INPUT_BYTES), true).ok);
        assert!(!send("y".into(), false).ok);
        assert_eq!(
            engine.bus.state.lock().unwrap().staged_inputs["test"]
                .data
                .len(),
            MAX_STAGED_INPUT_BYTES
        );
        assert!(send(String::new(), false).ok);
    }

    #[test]
    fn acknowledged_completion_survives_refresh_until_next_run() {
        let engine = RexZeroEngine::new_mock(None);
        let snapshot = engine.snapshot();
        let pane = snapshot
            .panes
            .iter()
            .find(|p| p.status == PaneActivityStatus::UnseenDone)
            .unwrap();
        let host = snapshot
            .hosts
            .iter()
            .find(|h| h.id == pane.host_id)
            .unwrap();
        let publish = |epoch| {
            apply_host_event(
                &engine.bus,
                None,
                false,
                &engine.active_pane_key,
                HostEvent::HostSnapshot {
                    host: host.clone(),
                    panes: vec![(pane.clone(), epoch)],
                },
            )
        };
        publish(1);
        engine.execute_action(RexAction::MarkSeen {
            key: pane.key.clone(),
        });
        let acknowledged = engine.snapshot().attention;
        publish(1);
        assert_eq!(engine.snapshot().attention, acknowledged);
        publish(2);
        let fresh = engine.snapshot().attention;
        assert_eq!(fresh.unseen_done_count, acknowledged.unseen_done_count + 1);
        assert_eq!(fresh.chime_seq, acknowledged.chime_seq + 1);
    }

    #[test]
    fn battery_changes_invalidate_cached_fleet_without_revision_change() {
        let engine = RexZeroEngine::new_mock(None);
        let rev = engine.snapshot().revision;
        for (percent, charging) in [(60, false), (60, true), (61, true)] {
            *engine.battery_cache.lock().unwrap() = Some((Instant::now(), Some(percent), charging));
            let payload: FleetSnapshot =
                serde_json::from_slice(&engine.snapshot_json_bytes()).unwrap();
            assert_eq!(payload.revision, rev);
            assert_eq!(
                (payload.battery_percent, payload.charging),
                (Some(percent), charging)
            );
        }
    }

    #[test]
    fn invalid_second_paired_host_leaves_credentials_and_hosts_untouched() {
        let dir = std::env::temp_dir().join(format!("rex-invalid-import-{}", std::process::id()));
        let engine = RexZeroEngine::new_live_with_config(dir.clone(), None, true, false, false);
        let hosts = ["ssh://valid", "ssh://bad host"].map(|ep| ConfiguredHost {
            id: ep.into(),
            label: ep.into(),
            endpoint: ep.into(),
            ssh_key_path: None,
        });
        assert!(engine
            .commit_staged_import(pair::StagedImport {
                hosts: hosts.to_vec(),
                ssh_private_key: Some("test".into()),
                asr_provider: None,
                asr_api_key: Some("test".into()),
                asr_app_id: None,
                asr_endpoint: None,
                summary: String::new(),
                from_ip: String::new(),
            })
            .is_err());
        assert!(engine.snapshot().hosts.is_empty());
        for file in ["ssh", "hosts.json", "settings.json"] {
            assert!(!dir.join(file).exists());
        }
        drop(engine);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn added_magic_dns_peer_uses_canonical_endpoint() {
        let engine = RexZeroEngine::new_mock(None);
        for (mode, endpoint) in [
            (PeerAddMode::Ssh, "ssh://User@device.example.ts.net"),
            (PeerAddMode::Https, "https://device.example.ts.net"),
        ] {
            assert!(
                engine
                    .execute_action(RexAction::TsnetAddPeer {
                        dns_name: "Device.Example.TS.NET.".into(),
                        host_name: "device".into(),
                        mode,
                        ssh_user: Some("User".into()),
                    })
                    .ok
            );
            assert!(engine
                .snapshot()
                .hosts
                .iter()
                .any(|h| h.endpoint == endpoint));
        }
    }

    #[test]
    fn stale_stage_cannot_replace_or_commit_another_stage_or_clear_new_draft() {
        let engine = RexZeroEngine::new_mock(None);
        let key = "cp0|s0|b0";
        let send = |id: &str, stage, reset| {
            engine.execute_action(RexAction::SendInput {
                key: key.into(),
                data: id.into(),
                stage: Some(stage),
                reset_stage: Some(reset),
                stage_id: Some(id.into()),
                clear_draft: Some(true),
                if_draft_ver: None,
                if_boot_id: None,
                client_id: None,
                client_seq: None,
            })
        };
        assert!(!send("A", true, false).ok);
        assert!(send("A", true, true).ok);
        assert!(send("B", true, true).ok);
        assert!(!send("A", true, false).ok);
        assert_eq!(
            send("A", false, false).error.as_deref(),
            Some("stale or missing stageId")
        );
        assert!(
            engine
                .execute_action(RexAction::SaveDraft {
                    key: key.into(),
                    text: "edited".into(),
                    append: None,
                    reserve_bytes: None,
                    if_draft_ver: None,
                    if_boot_id: None,
                    client_id: None,
                    client_seq: None,
                })
                .ok
        );
        assert!(send("B", false, false).ok);
        assert_eq!(engine.snapshot().drafts[key], "edited");
    }

    #[test]
    fn drafts_bound_serialized_bytes_and_preserve_utf8_across_asr_and_reload() {
        let engine = RexZeroEngine::new_mock(None);
        let key = "draft-test";
        let save = |key: &str, text: String| {
            engine
                .execute_action(RexAction::SaveDraft {
                    key: key.into(),
                    text,
                    append: None,
                    reserve_bytes: None,
                    if_draft_ver: None,
                    if_boot_id: None,
                    client_id: None,
                    client_seq: None,
                })
                .ok
        };
        assert!(!save(key, "x".repeat(MAX_PANE_DRAFT_BYTES + 1)));
        assert!(save(key, "x".repeat(MAX_PANE_DRAFT_BYTES - 5)));
        apply_asr_event(
            &engine.bus,
            None,
            AsrEvent::Transcript {
                target_key: key.into(),
                text: "你好".into(),
            },
        );
        assert!(engine.snapshot().drafts[key].ends_with(" 你"));
        assert!(save("escaped", "\0".repeat(10000)));
        assert!(!save("another", "\0".repeat(10000)));
        // Verify cross-pane `reserve_bytes` protects existing draft on a second pane before chunk 0 mutates it!
        assert!(save("pane-orig", "KEEP_ORIGINAL".into()));
        let rem_budget = {
            let st = engine.bus.state.lock().unwrap();
            draft_budget(&st.drafts, &st.draft_versions, &st.draft_reservations, "res-1")
        };
        assert!(rem_budget > 4000);
        let r_res1 = engine.execute_action(RexAction::SaveDraft {
            key: "res-1".into(),
            text: "chunk0".into(),
            append: None,
            reserve_bytes: Some(rem_budget - 500),
            if_draft_ver: None,
            if_boot_id: None,
            client_id: None,
            client_seq: None,
        });
        assert!(r_res1.ok);
        let r_res2 = engine.execute_action(RexAction::SaveDraft {
            key: "pane-orig".into(),
            text: "chunk0-would-overwrite".into(),
            append: None,
            reserve_bytes: Some(2000),
            if_draft_ver: None,
            if_boot_id: None,
            client_id: None,
            client_seq: None,
        });
        assert!(!r_res2.ok);
        assert_eq!(engine.snapshot().drafts["pane-orig"], "KEEP_ORIGINAL");

        // Verify expiring an unfinished multi-chunk reservation rolls back chunk 0 to the original draft!
        assert!(save("res-1", "ORIG_BEFORE_STALL".into()));
        let r_stall0 = engine.execute_action(RexAction::SaveDraft {
            key: "res-1".into(),
            text: "partial-chunk-0".into(),
            append: None,
            reserve_bytes: Some(rem_budget - 500),
            if_draft_ver: None,
            if_boot_id: None,
            client_id: None,
            client_seq: None,
        });
        assert!(r_stall0.ok);
        let stall_v0 = r_stall0.draft_ver.unwrap();
        // Force reservation past expiry (>15s pause between chunks):
        engine
            .bus
            .state
            .lock()
            .unwrap()
            .draft_reservations
            .get_mut("res-1")
            .unwrap()
            .expires_at = Instant::now() - Duration::from_secs(1);
        // Another pane now acquires the freed capacity AND triggers rollback of `"res-1"` to `"ORIG_BEFORE_STALL"`!
        let r_other = engine.execute_action(RexAction::SaveDraft {
            key: "pane-orig".into(),
            text: "y".repeat(2000),
            append: None,
            reserve_bytes: None,
            if_draft_ver: None,
            if_boot_id: None,
            client_id: None,
            client_seq: None,
        });
        assert!(r_other.ok);
        assert_eq!(engine.snapshot().drafts["res-1"], "ORIG_BEFORE_STALL");
        // Late append from the stalled client gets a clean conflict carrying `"ORIG_BEFORE_STALL"`:
        let r_late_append = engine.execute_action(RexAction::SaveDraft {
            key: "res-1".into(),
            text: "-chunk-1".into(),
            append: Some(true),
            reserve_bytes: None,
            if_draft_ver: Some(stall_v0),
            if_boot_id: None,
            client_id: None,
            client_seq: None,
        });
        assert_eq!(r_late_append.conflict, Some(true));
        assert_eq!(
            r_late_append.server_draft.as_deref(),
            Some("ORIG_BEFORE_STALL")
        );

        // Superseding reservation inherits `rollback_draft` (never rolling back to an earlier partial prefix),
        // dictation mid-reservation applies onto the committed draft, and rollback budget accounts for `rollback_draft` size!
        let big_committed = "K".repeat(14_000);
        assert!(save("res-1", big_committed.clone()));
        // Start replacing 14 KiB `big_committed` with a 2 KiB reserved save (chunk 0 = `"partA"`):
        let r_sup1 = engine.execute_action(RexAction::SaveDraft {
            key: "res-1".into(),
            text: "partA".into(),
            append: None,
            reserve_bytes: Some(2048),
            if_draft_ver: None,
            if_boot_id: None,
            client_id: None,
            client_seq: None,
        });
        assert!(r_sup1.ok);
        // 1) Capacity accounting still holds `big_committed`'s 14 KiB for rollback until replacement completes:
        let budget_during_shrink = {
            let st = engine.bus.state.lock().unwrap();
            draft_budget(&st.drafts, &st.draft_versions, &st.draft_reservations, "other-check")
        };
        // Supersede `"partA"` with a second reserved save (`"partB"`) BEFORE `"partA"` finished:
        let r_sup2 = engine.execute_action(RexAction::SaveDraft {
            key: "res-1".into(),
            text: "partB".into(),
            append: None,
            reserve_bytes: Some(2048),
            if_draft_ver: None,
            if_boot_id: None,
            client_id: None,
            client_seq: None,
        });
        assert!(r_sup2.ok);
        // 2) `committed_drafts_for_disk` (used when another pane clears/persists) STILL serializes `big_committed`, NOT `"partB"`!
        {
            let mut st = engine.bus.state.lock().unwrap();
            let disk_map = committed_drafts_for_disk(&st);
            assert_eq!(disk_map.get("res-1"), Some(&big_committed));
            let budget_after_sup2 =
                draft_budget(&st.drafts, &st.draft_versions, &st.draft_reservations, "other-check");
            assert_eq!(budget_during_shrink, budget_after_sup2);
            // Even if reservation expires BEFORE being reaped, `committed_drafts_for_disk` (used by another pane's send clear)
            // MUST still serialize `big_committed`, NEVER `"partB"`!
            st.draft_reservations.get_mut("res-1").unwrap().expires_at =
                Instant::now() - Duration::from_secs(1);
            assert_eq!(
                committed_drafts_for_disk(&st).get("res-1"),
                Some(&big_committed)
            );
            // Restore active expiry for the dictation-mid-reservation check below:
            st.draft_reservations.get_mut("res-1").unwrap().expires_at =
                Instant::now() + Duration::from_secs(10);
        }
        // 3) Dictation arriving mid-reservation applies onto `big_committed` (NOT `"partB"`) and invalidates the partial reservation!
        apply_asr_event(
            &engine.bus,
            None,
            AsrEvent::Transcript {
                target_key: "res-1".into(),
                text: "语音保留原稿".into(),
            },
        );
        assert_eq!(
            engine.snapshot().drafts["res-1"],
            format!("{big_committed} 语音保留原稿")
        );
        assert!(engine.snapshot_json_bytes().len() < 256 * 1024);
        let dir = std::env::temp_dir().join(format!("rex-draft-cap-{}", std::process::id()));
        let oversized = (0..12)
            .map(|i| (i.to_string(), "文".repeat(20000)))
            .collect();
        save_drafts(&dir, &oversized).unwrap();
        let restored = load_drafts(&dir);
        save_drafts(&dir, &restored).unwrap();
        let persisted = std::fs::read(dir.join("drafts.json")).unwrap();
        assert_eq!(persisted, serde_json::to_vec(&restored).unwrap());
        assert!(persisted.len() <= MAX_TOTAL_DRAFTS_BYTES);
        std::fs::remove_dir_all(dir).unwrap();
        assert!(serde_json::to_vec(&restored).unwrap().len() <= MAX_TOTAL_DRAFTS_BYTES);
        assert!(restored
            .values()
            .all(|v| v.len() <= MAX_PANE_DRAFT_BYTES && v.ends_with('文')));
    }

    #[test]
    fn mock_engine_serves_bootstrap_wait_pane_and_actions() {
        let engine = Arc::new(RexZeroEngine::new_mock(None));

        // 1. Bootstrap snapshot has multi-host fleet, priority-sorted panes, QR matrices.
        let boot = engine.handle_http("GET", "/rex/bootstrap", "", b"");
        assert_eq!(boot.status, 200);
        let snap: FleetSnapshot = serde_json::from_slice(&boot.body).unwrap();
        assert_eq!(snap.hosts.len(), 5);
        assert_eq!(snap.panes[0].key, "mini|s1|b1");
        assert_eq!(snap.panes[0].status, PaneActivityStatus::Blocked);
        assert_eq!(snap.attention.blocked_count, 1);
        assert_eq!(snap.attention.unseen_done_count, 1);
        assert_eq!(
            snap.attention.next_target_key.as_deref(),
            Some("mini|s1|b1")
        );
        assert!(snap.tailnet.qr_matrix.is_some());
        assert!(snap.pair.qr_matrix.is_some());

        // 2. Viewing `mini|s1|b1` excludes it from `nextTargetKey` (`M3.2-activity-chip`) so `n` jumps to `m1|s3|b0`!
        let mini_resp = engine.handle_http(
            "GET",
            "/rex/pane",
            "key=mini%7Cs1%7Cb1&cols=53&rows=14",
            b"",
        );
        assert_eq!(mini_resp.status, 200);
        assert_eq!(
            engine.snapshot().attention.next_target_key.as_deref(),
            Some("m1|s3|b0")
        );

        // 2b. Pane view for `cp0|s0|b0` renders real `libghostty-vt` spans!
        let cp0_resp =
            engine.handle_http("GET", "/rex/pane", "key=cp0%7Cs0%7Cb0&cols=53&rows=14", b"");
        assert_eq!(cp0_resp.status, 200);
        let cp0_view: PaneViewPayload = serde_json::from_slice(&cp0_resp.body).unwrap();
        assert!(cp0_view.vt.lines.iter().any(|l| !l.is_empty()));

        // 3. Opening `moon|s2|b1` transitions `unseen_done` -> `done` AND bumps revision even though `mini|s1|b1` stays `nextTargetKey`!
        let rev_before_moon = engine.snapshot().revision;
        let moon_resp = engine.handle_http(
            "GET",
            "/rex/pane",
            "key=moon%7Cs2%7Cb1&cols=50&rows=14",
            b"",
        );
        let moon_view: PaneViewPayload = serde_json::from_slice(&moon_resp.body).unwrap();
        assert_eq!(moon_view.status, PaneActivityStatus::Done);
        let snap_after_moon = engine.snapshot();
        assert_eq!(snap_after_moon.attention.unseen_done_count, 0);
        assert!(snap_after_moon.revision > rev_before_moon);

        // 4. Condvar `/rex/wait` wakes immediately when an action bumps `revision`!
        let cur_rev = engine.snapshot().revision;
        let engine_waiter = engine.clone();
        let waiter = thread::spawn(move || {
            let t0 = Instant::now();
            let r = engine_waiter.handle_http(
                "GET",
                "/rex/wait",
                &format!("since={cur_rev}&timeout_ms=5000"),
                b"",
            );
            (
                t0.elapsed(),
                serde_json::from_slice::<FleetSnapshot>(&r.body).unwrap(),
            )
        });
        thread::sleep(Duration::from_millis(25));
        let act = engine.handle_http(
            "POST",
            "/rex/action",
            "",
            br#"{"op":"tsnet_set","enabled":true}"#,
        );
        assert_eq!(act.status, 200);
        let (elapsed, woken_snap) = waiter.join().unwrap();
        assert!(
            elapsed < Duration::from_millis(500),
            "Condvar took {elapsed:?}"
        );
        assert!(woken_snap.revision > cur_rev);
        assert_eq!(woken_snap.tailnet.backend_state, "Running");

        // 5. Ownership take + missing pane 404 validation + automatic hand_back when switching panes!
        engine.handle_http(
            "POST",
            "/rex/action",
            "",
            br#"{"op":"set_ownership","key":"mini|s1|b1","mode":"take","cols":50,"rows":14}"#,
        );
        assert!(
            engine
                .snapshot()
                .panes
                .iter()
                .find(|p| p.key == "mini|s1|b1")
                .unwrap()
                .owned_by_us
        );
        // Requesting a non-existent pane MUST return 404 WITHOUT releasing `mini|s1|b1`!
        let missing_resp = engine.handle_http(
            "GET",
            "/rex/pane",
            "key=ghost%7Cs9%7Cb9&cols=50&rows=14",
            b"",
        );
        assert_eq!(missing_resp.status, 404);
        assert!(
            engine
                .snapshot()
                .panes
                .iter()
                .find(|p| p.key == "mini|s1|b1")
                .unwrap()
                .owned_by_us
        );

        // Switch active pane to `cp0|s0|b0` -> `mini|s1|b1` auto-releases (`releasedByUs: true`)!
        engine.handle_http("GET", "/rex/pane", "key=cp0%7Cs0%7Cb0&cols=50&rows=14", b"");
        let mini_after = engine
            .snapshot()
            .panes
            .into_iter()
            .find(|p| p.key == "mini|s1|b1")
            .unwrap();
        assert!(!mini_after.owned_by_us && mini_after.released_by_us);

        // 6. Chunked `save_draft { append }` + `stageId`-isolated staged `send_input`!
        engine.handle_http(
            "POST",
            "/rex/action",
            "",
            r#"{"op":"save_draft","key":"mini|s1|b1","text":"第一段·"}"#.as_bytes(),
        );
        engine.handle_http(
            "POST",
            "/rex/action",
            "",
            r#"{"op":"save_draft","key":"mini|s1|b1","text":"第二段","append":true}"#.as_bytes(),
        );
        assert_eq!(
            engine
                .snapshot()
                .drafts
                .get("mini|s1|b1")
                .map(String::as_str),
            Some("第一段·第二段")
        );

        // Abandoned staged prefix `"abandoned-"` must NOT leak into an ordinary single-chunk send!
        engine.handle_http(
            "POST",
            "/rex/action",
            "",
            br#"{"op":"send_input","key":"cp0|s0|b0","data":"abandoned-","stage":true,"resetStage":true,"stageId":"s0"}"#,
        );
        engine.handle_http(
            "POST",
            "/rex/action",
            "",
            br#"{"op":"send_input","key":"cp0|s0|b0","data":"clean-single"}"#,
        );
        let cp0_after = serde_json::from_slice::<PaneViewPayload>(
            &engine
                .handle_http("GET", "/rex/pane", "key=cp0%7Cs0%7Cb0&cols=50&rows=14", b"")
                .body,
        )
        .unwrap();
        assert!(cp0_after
            .reader_messages
            .iter()
            .any(|m| m.body == "clean-single"));
        assert!(!cp0_after
            .reader_messages
            .iter()
            .any(|m| m.body.contains("abandoned-")));

        // Matching `stageId` across staged chunks concatenates atomically and updates approval status!
        engine.handle_http(
            "POST",
            "/rex/action",
            "",
            br#"{"op":"send_input","key":"mini|s1|b1","data":"staged-prefix-","stage":true,"resetStage":true,"stageId":"s1"}"#,
        );
        assert_eq!(
            engine
                .snapshot()
                .panes
                .iter()
                .find(|p| p.key == "mini|s1|b1")
                .unwrap()
                .status,
            PaneActivityStatus::Blocked
        );
        engine.handle_http(
            "POST",
            "/rex/action",
            "",
            br#"{"op":"send_input","key":"mini|s1|b1","data":"final-tail","clearDraft":true,"stageId":"s1"}"#,
        );
        let snap_after_send = engine.snapshot();
        assert!(!snap_after_send.drafts.contains_key("mini|s1|b1"));
        let mini_view_resp = engine.handle_http(
            "GET",
            "/rex/pane",
            "key=mini%7Cs1%7Cb1&cols=50&rows=14",
            b"",
        );
        let mini_view: PaneViewPayload = serde_json::from_slice(&mini_view_resp.body).unwrap();
        assert_eq!(mini_view.status, PaneActivityStatus::Running);
        assert_eq!(
            mini_view.live_activity_text.as_deref(),
            Some("已授权 · 正在编译 Release (aarch64)")
        );
        assert!(mini_view
            .reader_messages
            .iter()
            .any(|m| m.body == "staged-prefix-final-tail"));
    }

    #[test]
    fn live_engine_persists_drafts_versions_edits_and_isolates_paired_ssh_keys() {
        let dir = std::env::temp_dir().join(format!(
            "rex-zero-live-test-{}-{}",
            std::process::id(),
            protocol::unix_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);

        // 1. Save draft in live engine #1 and verify disk persistence across restart in engine #2.
        {
            let eng1 = RexZeroEngine::new_live_with_config(dir.clone(), None, true, false, false);
            let reply = eng1.execute_action(RexAction::SaveDraft {
                key: "mini|s1|b1".into(),
                text: "跨重启保留的草稿与语音内容".into(),
                append: Some(false),
                reserve_bytes: None,
                if_draft_ver: None,
                if_boot_id: None,
                client_id: None,
                client_seq: None,
            });
            assert!(reply.ok);
            eng1.shutdown();
        }
        {
            let eng2 = RexZeroEngine::new_live_with_config(dir.clone(), None, true, false, false);
            assert_eq!(
                eng2.snapshot().drafts.get("mini|s1|b1").map(String::as_str),
                Some("跨重启保留的草稿与语音内容")
            );

            // 2. Pair two hosts with DISTINCT SSH keys -> distinct `0600` files, neither overwritten!
            eng2.commit_staged_import(pair::StagedImport {
                hosts: vec![ConfiguredHost {
                    id: "box1".into(),
                    label: "box1".into(),
                    endpoint: "ssh://root@box1".into(),
                    ssh_key_path: None,
                }],
                ssh_private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\nKEY_ONE\n".into()),
                asr_provider: None,
                asr_api_key: None,
                asr_app_id: None,
                asr_endpoint: None,
                summary: "box1".into(),
                from_ip: "127.0.0.1".into(),
            })
            .unwrap();

            eng2.commit_staged_import(pair::StagedImport {
                hosts: vec![ConfiguredHost {
                    id: "box2".into(),
                    label: "box2".into(),
                    endpoint: "ssh://root@box2".into(),
                    ssh_key_path: None,
                }],
                ssh_private_key: Some("-----BEGIN OPENSSH PRIVATE KEY-----\nKEY_TWO\n".into()),
                asr_provider: None,
                asr_api_key: None,
                asr_app_id: None,
                asr_endpoint: None,
                summary: "box2".into(),
                from_ip: "127.0.0.1".into(),
            })
            .unwrap();

            let saved = load_saved_hosts(&dir);
            let k1 = saved
                .iter()
                .find(|h| h.id == "box1")
                .and_then(|h| h.ssh_key_path.as_ref())
                .expect("box1 key");
            let k2 = saved
                .iter()
                .find(|h| h.id == "box2")
                .and_then(|h| h.ssh_key_path.as_ref())
                .expect("box2 key");
            assert_ne!(k1, k2);
            assert!(std::fs::read_to_string(k1).unwrap().contains("KEY_ONE"));
            assert!(std::fs::read_to_string(k2).unwrap().contains("KEY_TWO"));

            // 3. Versioned `SendInput(clearDraft=true)` preserves concurrent draft edits saved while RPC is in flight!
            let (worker_tx, worker_rx) = mpsc::channel::<HostCmd>();
            eng2.workers.lock().unwrap().insert(
                "box1".into(),
                HostWorkerHandle::from_test_channel(worker_tx).unwrap(),
            );
            eng2.execute_action(RexAction::SaveDraft {
                key: "box1|s1|b1".into(),
                text: "旧草稿".into(),
                append: Some(false),
                reserve_bytes: None,
                if_draft_ver: None,
                if_boot_id: None,
                client_id: None,
                client_seq: None,
            });

            let eng2_arc = Arc::new(eng2);
            let eng_sender = eng2_arc.clone();
            let send_join = thread::spawn(move || {
                eng_sender.execute_action(RexAction::SendInput {
                    key: "box1|s1|b1".into(),
                    data: "旧草稿\r".into(),
                    clear_draft: Some(true),
                    stage: None,
                    reset_stage: None,
                    stage_id: None,
                    if_draft_ver: None,
                    if_boot_id: None,
                    client_id: None,
                    client_seq: None,
                })
            });

            // Wait until `SendInput` enters its RPC wait, then save a NEW draft before acknowledging RPC!
            match worker_rx.recv_timeout(Duration::from_secs(2)).unwrap() {
                HostCmd::SendInput { reply, .. } => {
                    eng2_arc.execute_action(RexAction::SaveDraft {
                        key: "box1|s1|b1".into(),
                        text: "发送期间新编辑或ASR追加的内容".into(),
                        append: Some(false),
                        reserve_bytes: None,
                        if_draft_ver: None,
                        if_boot_id: None,
                        client_id: None,
                        client_seq: None,
                    });
                    reply.send(Ok(())).unwrap();
                }
                _ => panic!("expected SendInput"),
            }
            assert!(send_join.join().unwrap().ok);
            assert_eq!(
                eng2_arc
                    .snapshot()
                    .drafts
                    .get("box1|s1|b1")
                    .map(String::as_str),
                Some("发送期间新编辑或ASR追加的内容")
            );
            eng2_arc.shutdown();
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn conditional_save_draft_append_rejects_stale_version_on_concurrent_asr_or_clear() {
        let engine = RexZeroEngine::new_mock(None);
        let key = "mini|s1|b1";

        let cid = "c-test-1".to_string();
        let r0 = engine.execute_action(RexAction::SaveDraft {
            key: key.into(),
            text: "首段内容".into(),
            append: None,
            reserve_bytes: None,
            if_draft_ver: None,
            if_boot_id: None,
            client_id: Some(cid.clone()),
            client_seq: Some(1),
        });
        assert!(r0.ok);
        let v0 = r0.draft_ver.expect("draft_ver returned on chunk 0");
        assert_eq!(r0.client_id.as_deref(), Some("c-test-1"));
        assert_eq!(r0.client_seq, Some(1));
        assert_eq!(
            engine.snapshot().draft_meta.get(key).cloned(),
            Some(types::DraftMeta {
                ver: v0,
                client_id: Some(cid.clone()),
                client_seq: 1,
                reservation_rolled_back: false,
                provisional: false,
                unpersisted: false,
            })
        );

        // Concurrent ASR lands before chunk 1 append!
        apply_asr_event(
            &engine.bus,
            None,
            AsrEvent::Transcript {
                target_key: key.into(),
                text: "语音插队".into(),
            },
        );

        // Stale append with old `v0` must NOT corrupt server draft into "首段内容 语音插队续写段"!
        let r1 = engine.execute_action(RexAction::SaveDraft {
            key: key.into(),
            text: "续写段".into(),
            append: Some(true),
            reserve_bytes: None,
            if_draft_ver: Some(v0),
            if_boot_id: None,
            client_id: Some(cid.clone()),
            client_seq: Some(2),
        });
        assert!(r1.ok);
        assert_eq!(r1.conflict, Some(true));
        assert_eq!(r1.client_id.as_deref(), Some("c-test-1"));
        assert_eq!(r1.client_seq, Some(1));
        assert_eq!(r1.server_draft.as_deref(), Some("首段内容 语音插队"));
        assert_eq!(
            engine.snapshot().drafts.get(key).map(String::as_str),
            Some("首段内容 语音插队")
        );

        // Non-append replacement with stale `if_draft_ver` ALSO conflicts without overwriting ASR!
        let r_stale_overwrite = engine.execute_action(RexAction::SaveDraft {
            key: key.into(),
            text: "旧覆盖".into(),
            append: Some(false),
            reserve_bytes: None,
            if_draft_ver: Some(v0),
            if_boot_id: None,
            client_id: Some(cid.clone()),
            client_seq: Some(3),
        });
        assert_eq!(r_stale_overwrite.conflict, Some(true));
        assert_eq!(
            engine.snapshot().drafts.get(key).map(String::as_str),
            Some("首段内容 语音插队")
        );

        // `SendInput` anchored to `v0` (locked before ASR) delivers input WITHOUT clearing `首段内容 语音插队`!
        let send_stale = engine.execute_action(RexAction::SendInput {
            key: key.into(),
            data: "首段内容\r".into(),
            clear_draft: Some(true),
            stage: None,
            reset_stage: None,
            stage_id: None,
            if_draft_ver: Some(v0),
            if_boot_id: None,
            client_id: Some(cid.clone()),
            client_seq: Some(4),
        });
        assert!(send_stale.ok);
        assert_eq!(send_stale.draft_cleared, Some(false));
        assert_eq!(
            send_stale.server_draft.as_deref(),
            Some("首段内容 语音插队")
        );
        assert_eq!(
            engine.snapshot().drafts.get(key).map(String::as_str),
            Some("首段内容 语音插队")
        );

        // Matching `if_draft_ver` succeeds cleanly.
        let v_cur = r1.draft_ver.unwrap();
        let r2 = engine.execute_action(RexAction::SaveDraft {
            key: key.into(),
            text: "·追加".into(),
            append: Some(true),
            reserve_bytes: None,
            if_draft_ver: Some(v_cur),
            if_boot_id: None,
            client_id: Some(cid.clone()),
            client_seq: Some(5),
        });
        assert!(r2.ok);
        assert_eq!(r2.conflict, None);
        assert_eq!(r2.client_seq, Some(5));
        assert_eq!(
            engine.snapshot().drafts.get(key).map(String::as_str),
            Some("首段内容 语音插队·追加")
        );

        // `SendInput(clearDraft=true)` with matching `if_draft_ver` clears and bumps `draft_versions`!
        let v_before_clear = r2.draft_ver.unwrap();
        let clear_res = engine.execute_action(RexAction::SendInput {
            key: key.into(),
            data: "ok\r".into(),
            clear_draft: Some(true),
            stage: None,
            reset_stage: None,
            stage_id: None,
            if_draft_ver: Some(v_before_clear),
            if_boot_id: None,
            client_id: Some(cid.clone()),
            client_seq: Some(6),
        });
        assert!(clear_res.ok);
        assert_eq!(clear_res.draft_cleared, Some(true));
        assert_eq!(clear_res.client_seq, Some(6));

        let r_after_clear = engine.execute_action(RexAction::SaveDraft {
            key: key.into(),
            text: "过期分片".into(),
            append: Some(true),
            reserve_bytes: None,
            if_draft_ver: Some(v_before_clear),
            if_boot_id: None,
            client_id: Some(cid.clone()),
            client_seq: Some(7),
        });
        assert_eq!(r_after_clear.conflict, Some(true));
        assert!(!engine.snapshot().drafts.contains_key(key));

        // Staged `send_input` anchors `started_draft_ver` at stage 0 and rejects mismatching `if_draft_ver` on commit!
        let r_stage_seed = engine.execute_action(RexAction::SaveDraft {
            key: key.into(),
            text: "初始长稿".into(),
            append: None,
            reserve_bytes: None,
            if_draft_ver: None,
            if_boot_id: None,
            client_id: Some(cid.clone()),
            client_seq: Some(8),
        });
        let v_stage0 = r_stage_seed.draft_ver.unwrap();
        let st0 = engine.execute_action(RexAction::SendInput {
            key: key.into(),
            data: "part1-".into(),
            clear_draft: None,
            stage: Some(true),
            reset_stage: Some(true),
            stage_id: Some("c-test-1-s1".into()),
            if_draft_ver: Some(v_stage0),
            if_boot_id: None,
            client_id: None,
            client_seq: None,
        });
        assert!(st0.ok);
        apply_asr_event(
            &engine.bus,
            None,
            AsrEvent::Transcript {
                target_key: key.into(),
                text: "分段期间ASR".into(),
            },
        );
        let v_after_asr = engine.snapshot().draft_meta.get(key).unwrap().ver;
        assert!(v_after_asr > v_stage0);

        // Explicit mismatching `if_draft_ver` on commit must be rejected!
        let bad_commit = engine.execute_action(RexAction::SendInput {
            key: key.into(),
            data: "part2\r".into(),
            clear_draft: Some(true),
            stage: None,
            reset_stage: None,
            stage_id: Some("c-test-1-s1".into()),
            if_draft_ver: Some(v_after_asr),
            if_boot_id: None,
            client_id: Some(cid.clone()),
            client_seq: Some(9),
        });
        assert!(!bad_commit.ok);
        assert_eq!(bad_commit.error.as_deref(), Some("staged ifDraftVer mismatch"));

        // Omitting `if_draft_ver` on commit STILL enforces `started_draft_ver` (`v_stage0`), preserving ASR!
        let good_commit = engine.execute_action(RexAction::SendInput {
            key: key.into(),
            data: "part2\r".into(),
            clear_draft: Some(true),
            stage: None,
            reset_stage: None,
            stage_id: Some("c-test-1-s1".into()),
            if_draft_ver: None,
            if_boot_id: None,
            client_id: Some(cid.clone()),
            client_seq: Some(9),
        });
        assert!(good_commit.ok);
        assert_eq!(good_commit.draft_cleared, Some(false));
        assert_eq!(
            engine.snapshot().drafts.get(key).map(String::as_str),
            Some("初始长稿 分段期间ASR")
        );

        // Stage reset passing a not-yet-existent future `if_draft_ver` (`v_after_asr + 1`) MUST NOT clear an intervening write that reaches `v_after_asr + 1`!
        let st_future = engine.execute_action(RexAction::SendInput {
            key: key.into(),
            data: "f1-".into(),
            clear_draft: None,
            stage: Some(true),
            reset_stage: Some(true),
            stage_id: Some("c-test-1-s2".into()),
            if_draft_ver: Some(v_after_asr + 1),
            if_boot_id: None,
            client_id: None,
            client_seq: None,
        });
        assert!(st_future.ok);
        apply_asr_event(
            &engine.bus,
            None,
            AsrEvent::Transcript {
                target_key: key.into(),
                text: "未来版本ASR".into(),
            },
        );
        assert_eq!(
            engine.snapshot().draft_meta.get(key).unwrap().ver,
            v_after_asr + 1
        );
        let commit_future = engine.execute_action(RexAction::SendInput {
            key: key.into(),
            data: "f2\r".into(),
            clear_draft: Some(true),
            stage: None,
            reset_stage: None,
            stage_id: Some("c-test-1-s2".into()),
            if_draft_ver: Some(v_after_asr + 1),
            if_boot_id: None,
            client_id: Some(cid),
            client_seq: Some(10),
        });
        assert!(commit_future.ok);
        assert_eq!(commit_future.draft_cleared, Some(false));
        assert_eq!(
            engine.snapshot().drafts.get(key).map(String::as_str),
            Some("初始长稿 分段期间ASR 未来版本ASR")
        );

        // Mismatching `if_boot_id` conflicts on `SaveDraft` and refuses clear on `SendInput` even when numeric `if_draft_ver` matches!
        let cur_same_ver = engine.snapshot().draft_meta.get(key).unwrap().ver;
        let stale_boot_save = engine.execute_action(RexAction::SaveDraft {
            key: key.into(),
            text: "跨实例误覆盖".into(),
            append: Some(false),
            reserve_bytes: None,
            if_draft_ver: Some(cur_same_ver),
            if_boot_id: Some("old-boot-id".into()),
            client_id: Some("c-other".into()),
            client_seq: Some(1),
        });
        assert_eq!(stale_boot_save.conflict, Some(true));
        assert_eq!(
            engine.snapshot().drafts.get(key).map(String::as_str),
            Some("初始长稿 分段期间ASR 未来版本ASR")
        );

        let stale_boot_clear = engine.execute_action(RexAction::SendInput {
            key: key.into(),
            data: "noop\r".into(),
            clear_draft: Some(true),
            stage: None,
            reset_stage: None,
            stage_id: None,
            if_draft_ver: Some(cur_same_ver),
            if_boot_id: Some("old-boot-id".into()),
            client_id: Some("c-other".into()),
            client_seq: Some(2),
        });
        assert!(stale_boot_clear.ok);
        assert_eq!(stale_boot_clear.draft_cleared, Some(false));
        assert_eq!(
            engine.snapshot().drafts.get(key).map(String::as_str),
            Some("初始长稿 分段期间ASR 未来版本ASR")
        );
    }

    #[test]
    fn claimed_send_completing_after_recv_timeout_still_records_outcome_and_clears_draft() {
        let dir = std::env::temp_dir().join(format!(
            "rex-zero-claimed-timeout-{}-{}",
            std::process::id(),
            protocol::unix_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let eng = Arc::new(RexZeroEngine::new_live_with_config(
            dir.clone(),
            None,
            true,
            false,
            false,
        ));
        let (worker_tx, worker_rx) = mpsc::channel::<HostCmd>();
        eng.workers.lock().unwrap().insert(
            "box1".into(),
            HostWorkerHandle::from_test_channel(worker_tx).unwrap(),
        );
        let saved = eng.execute_action(RexAction::SaveDraft {
            key: "box1|s1|b1".into(),
            text: "待发命令".into(),
            append: None,
            reserve_bytes: None,
            if_draft_ver: None,
            if_boot_id: None,
            client_id: Some("c1".into()),
            client_seq: Some(1),
        });
        let v0 = saved.draft_ver.unwrap();

        let eng_call = eng.clone();
        let join = thread::spawn(move || {
            eng_call.dispatch_live_send_input(
                "box1|s1|b1".into(),
                "待发命令\r".into(),
                Some(true),
                v0,
                true,
                Some("c1".into()),
                Some(2),
                Instant::now() + Duration::from_secs(2),
                Duration::from_millis(25),
            )
        });

        let held_reply = match worker_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            HostCmd::SendInput {
                dispatch, reply, ..
            } => {
                assert!(dispatch.start());
                reply
            }
            _ => panic!("expected SendInput"),
        };

        // Wait for `dispatch_live_send_input` to time out while the claimed write is still in flight:
        let timed_out = join.join().unwrap();
        assert!(!timed_out.ok);
        assert_eq!(timed_out.unconfirmed, Some(true));
        // Sequence is NOT falsely recorded as failed while still in flight:
        assert!(!eng.snapshot().send_outcomes.contains_key("c1:2"));

        // Worker now finishes `Ok(())` AFTER `recv_timeout`: outcome & clear MUST still commit!
        held_reply.send(Ok(())).unwrap();
        let snap = eng.snapshot();
        assert!(!snap.drafts.contains_key("box1|s1|b1"));
        assert_eq!(
            snap.send_outcomes.get("c1:2"),
            Some(&types::SendOutcome {
                ok: true,
                draft_cleared: Some(true),
                draft_ver: Some(v0 + 1),
                persist_error: None,
            })
        );

        // Simulate disk persistence failure (blocking `dir/drafts.json` with a directory) when claimed write finishes AFTER `recv_timeout`:
        // `send_outcomes["c1:4"].persist_error` MUST be populated atomically so the client retries clearing disk!
        let saved2 = eng.execute_action(RexAction::SaveDraft {
            key: "box1|s1|b1".into(),
            text: "待清理落盘失败草稿".into(),
            append: None,
            reserve_bytes: None,
            if_draft_ver: None,
            if_boot_id: None,
            client_id: Some("c1".into()),
            client_seq: Some(3),
        });
        let v1 = saved2.draft_ver.unwrap();
        let drafts_path = dir.join("drafts.json");
        let _ = std::fs::remove_file(&drafts_path);
        std::fs::create_dir_all(&drafts_path).unwrap();

        let eng_call2 = eng.clone();
        let join2 = thread::spawn(move || {
            eng_call2.dispatch_live_send_input(
                "box1|s1|b1".into(),
                "待清理落盘失败草稿\r".into(),
                Some(true),
                v1,
                true,
                Some("c1".into()),
                Some(4),
                Instant::now() + Duration::from_secs(2),
                Duration::from_millis(25),
            )
        });
        let held_reply2 = match worker_rx.recv_timeout(Duration::from_secs(1)).unwrap() {
            HostCmd::SendInput {
                dispatch, reply, ..
            } => {
                assert!(dispatch.start());
                reply
            }
            _ => panic!("expected SendInput"),
        };
        let timed_out2 = join2.join().unwrap();
        assert_eq!(timed_out2.unconfirmed, Some(true));
        held_reply2.send(Ok(())).unwrap();
        let snap2 = eng.snapshot();
        let out4 = snap2.send_outcomes.get("c1:4").expect("c1:4 outcome");
        assert!(out4.ok);
        assert_eq!(out4.draft_cleared, Some(true));
        assert!(out4
            .persist_error
            .as_deref()
            .is_some_and(|m| m.contains("清理草稿落盘失败")));
        let _ = std::fs::remove_dir_all(&drafts_path);

        eng.shutdown();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
