//! Authoritative 1:1 JSON wire contract between Rust `RexZeroEngine` (`http://zero/rex/*`)
//! and Solid TSX UI (`app/types.ts`). All struct fields serialize/deserialize in `camelCase`
//! (except compact `VtSpan` single-letter fields `t`, `fg`, `bg`, `b`, `inv`, `u`).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    Local,
    Tailnet,
    Ssh,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnPhase {
    Idle,
    Connecting,
    Live,
    Reconnecting,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Local,
    Direct,
    Relay,
    Derp,
    Ssh,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaneActivityStatus {
    Blocked,
    Error,
    UnseenDone,
    Running,
    Done,
    Idle,
}

impl PaneActivityStatus {
    /// Priority rank for Inbox ordering (lower = higher urgency).
    pub fn priority_rank(self) -> u8 {
        match self {
            Self::Blocked => 0,
            Self::Error => 1,
            Self::UnseenDone => 2,
            Self::Running => 3,
            Self::Done => 4,
            Self::Idle => 5,
        }
    }

    pub fn needs_attention(self) -> bool {
        matches!(self, Self::Blocked | Self::Error | Self::UnseenDone)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub id: String,
    pub label: String,
    pub window_count: usize,
    pub pane_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostState {
    pub id: String,
    pub label: String,
    pub kind: HostKind,
    pub endpoint: String,
    pub phase: ConnPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_kind: Option<PathKind>,
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaneSummary {
    /// Stable composite key: `${hostId}|${sessionId}|${blockId}`
    pub key: String,
    pub host_id: String,
    pub host_label: String,
    pub session_id: String,
    pub session_label: String,
    pub window_id: String,
    pub window_label: String,
    pub block_id: String,
    pub title: String,
    pub program: String,
    pub pwd: String,
    pub status: PaneActivityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_msg: Option<String>,
    pub owned_by_us: bool,
    pub released_by_us: bool,
    pub has_draft: bool,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChimeKind {
    Approval,
    Error,
    Done,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttentionSummary {
    pub blocked_count: usize,
    pub error_count: usize,
    pub unseen_done_count: usize,
    pub next_target_key: Option<String>,
    pub chime_seq: u64,
    pub chime_kind: ChimeKind,
    pub muted: bool,
}

impl Default for AttentionSummary {
    fn default() -> Self {
        Self {
            blocked_count: 0,
            error_count: 0,
            unseen_done_count: 0,
            next_target_key: None,
            chime_seq: 0,
            chime_kind: ChimeKind::None,
            muted: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailnetPeer {
    pub host_name: String,
    pub dns_name: String,
    pub ips: Vec<String>,
    pub online: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_kind: Option<PathKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rex_endpoint: Option<String>,
    pub already_added: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TailnetState {
    pub enabled: bool,
    pub backend_state: String,
    pub auth_url: String,
    pub qr_matrix: Option<Vec<Vec<bool>>>,
    pub tailnet_name: String,
    pub self_dns: String,
    pub proxy_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub peers: Vec<TailnetPeer>,
}

impl Default for TailnetState {
    fn default() -> Self {
        Self {
            enabled: false,
            backend_state: "Stopped".into(),
            auth_url: String::new(),
            qr_matrix: None,
            tailnet_name: String::new(),
            self_dns: String::new(),
            proxy_port: 0,
            error: None,
            peers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImeEngine {
    Librime,
    Builtin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImeSchema {
    PinyinSimp,
    DoublePinyin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImeStatus {
    pub available: bool,
    pub engine: ImeEngine,
    pub schema: ImeSchema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsrProvider {
    DoubaoFree,
    Plugin,
    Doubao,
    Openai,
    Groq,
    Elevenlabs,
}

impl AsrProvider {
    pub fn from_name(name: &str) -> Self {
        match name.trim().to_ascii_lowercase().as_str() {
            "doubao_free" | "doubao-free" | "builtin" | "" => Self::DoubaoFree,
            "plugin" | "custom" => Self::Plugin,
            "doubao" => Self::Doubao,
            "groq" => Self::Groq,
            "elevenlabs" => Self::Elevenlabs,
            "openai" => Self::Openai,
            _ => Self::DoubaoFree,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AsrState {
    pub configured: bool,
    pub provider: AsrProvider,
    pub recording: bool,
    pub busy: bool,
    pub target_key: Option<String>,
    pub partial: String,
    pub level: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Default for AsrState {
    fn default() -> Self {
        Self {
            configured: false,
            provider: AsrProvider::Openai,
            recording: false,
            busy: false,
            target_key: None,
            partial: String::new(),
            level: 0.0,
            error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPairImport {
    pub token: String,
    pub summary: String,
    pub from_ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairState {
    pub active: bool,
    pub url: String,
    pub pin: String,
    pub expires_in_sec: u32,
    pub qr_matrix: Option<Vec<Vec<bool>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_import: Option<PendingPairImport>,
}

impl Default for PairState {
    fn default() -> Self {
        Self {
            active: false,
            url: String::new(),
            pin: String::new(),
            expires_in_sec: 0,
            qr_matrix: None,
            pending_import: None,
        }
    }
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DraftMeta {
    pub ver: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub client_seq: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub reservation_rolled_back: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub provisional: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub unpersisted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SendOutcome {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_cleared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_ver: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persist_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetSnapshot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
    pub revision: u64,
    pub battery_percent: Option<u8>,
    pub charging: bool,
    pub hosts: Vec<HostState>,
    pub panes: Vec<PaneSummary>,
    pub attention: AttentionSummary,
    pub tailnet: TailnetState,
    pub ime: ImeStatus,
    pub asr: AsrState,
    pub pair: PairState,
    pub drafts: BTreeMap<String, String>,
    #[serde(default)]
    pub draft_meta: BTreeMap<String, DraftMeta>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub send_outcomes: BTreeMap<String, SendOutcome>,
    #[serde(default)]
    pub font_preset: u8,
    #[serde(default = "default_reader_mode")]
    pub reader_mode: String,
    pub mock: bool,
}

fn default_reader_mode() -> String {
    "chat".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalOption {
    pub key: String,
    pub label: String,
    pub send: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalCard {
    pub title: String,
    pub detail: String,
    pub options: Vec<ApprovalOption>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReaderRole {
    User,
    Assistant,
    System,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReaderMessage {
    pub id: String,
    pub role: ReaderRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtSpan {
    pub t: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bg: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub b: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub inv: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub u: bool,
}

impl VtSpan {
    pub fn same_style(&self, other: &Self) -> bool {
        self.fg == other.fg
            && self.bg == other.bg
            && self.b == other.b
            && self.inv == other.inv
            && self.u == other.u
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VtViewport {
    pub cols: u16,
    pub rows: u16,
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub cursor_visible: bool,
    pub scroll_offset: u64,
    pub scroll_total: u64,
    pub alt_screen: bool,
    pub lines: Vec<Vec<VtSpan>>,
}

impl VtViewport {
    pub fn empty(cols: u16, rows: u16) -> Self {
        Self {
            cols,
            rows,
            cursor_x: 0,
            cursor_y: 0,
            cursor_visible: true,
            scroll_offset: 0,
            scroll_total: 0,
            alt_screen: false,
            lines: (0..rows).map(|_| Vec::new()).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaneViewPayload {
    pub key: String,
    pub revision: u64,
    pub title: String,
    #[serde(default)]
    pub window_label: String,
    pub host_label: String,
    pub session_label: String,
    pub program: String,
    pub pwd: String,
    pub stream_phase: ConnPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_problem: Option<String>,
    pub owned_by_us: bool,
    pub released_by_us: bool,
    pub status: PaneActivityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_msg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_activity_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalCard>,
    pub reader_messages: Vec<ReaderMessage>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw_lines: Vec<String>,
    pub vt: VtViewport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImeComposeReply {
    pub raw: String,
    pub preedit: String,
    pub candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed: Option<String>,
    pub page: usize,
    pub has_more: bool,
    pub schema: ImeSchema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipMode {
    Peek,
    Take,
    HandBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerAddMode {
    Https,
    Ssh,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RexAction {
    #[serde(rename_all = "camelCase")]
    SendInput {
        key: String,
        data: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        clear_draft: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stage: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reset_stage: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stage_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        if_draft_ver: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        if_boot_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_seq: Option<u64>,
    },
    #[serde(rename_all = "camelCase")]
    SendKey {
        key: String,
        key_name: String,
        #[serde(default)]
        mods: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    SetOwnership {
        key: String,
        mode: OwnershipMode,
        #[serde(default)]
        cols: Option<u16>,
        #[serde(default)]
        rows: Option<u16>,
    },
    #[serde(rename_all = "camelCase")]
    ScrollVt {
        key: String,
        delta_lines: i32,
        #[serde(default)]
        to_bottom: Option<bool>,
    },
    #[serde(rename_all = "camelCase")]
    SaveDraft {
        key: String,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        append: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reserve_bytes: Option<usize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        if_draft_ver: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        if_boot_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_seq: Option<u64>,
    },
    #[serde(rename_all = "camelCase")]
    MarkSeen { key: String },
    #[serde(rename_all = "camelCase")]
    ToggleMute {},
    #[serde(rename_all = "camelCase")]
    NewSession {
        host_id: String,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        cwd: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    CloseBlock { key: String },
    #[serde(rename_all = "camelCase")]
    AddHost {
        label: String,
        endpoint: String,
        #[serde(default)]
        ssh_key_path: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    RemoveHost { host_id: String },
    #[serde(rename_all = "camelCase")]
    ImeCompose {
        raw: String,
        #[serde(default)]
        select_idx: Option<usize>,
        #[serde(default)]
        page_delta: Option<i32>,
        #[serde(default)]
        toggle_schema: Option<bool>,
    },
    #[serde(rename_all = "camelCase")]
    AsrToggle { key: String },
    #[serde(rename_all = "camelCase")]
    AsrCancel {},
    #[serde(rename_all = "camelCase")]
    LeavePane {},
    #[serde(rename_all = "camelCase")]
    AsrConfigure {
        provider: String,
        api_key: String,
        #[serde(default)]
        app_id: Option<String>,
        #[serde(default)]
        endpoint: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    TsnetSet {
        enabled: bool,
        #[serde(default)]
        hostname: Option<String>,
        #[serde(default)]
        auth_key: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    TsnetPing { peer_ip: String },
    #[serde(rename_all = "camelCase")]
    TsnetAddPeer {
        dns_name: String,
        host_name: String,
        mode: PeerAddMode,
        #[serde(default)]
        ssh_user: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    PairToggle { active: bool },
    #[serde(rename_all = "camelCase")]
    PairConfirm {
        #[serde(default)]
        token: Option<String>,
        approve: bool,
    },
    #[serde(rename_all = "camelCase")]
    SetUiPrefs {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        font_preset: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reader_mode: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActionReply {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ime: Option<ImeComposeReply>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_ver: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_cleared: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation_rolled_back: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provisional: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_draft: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persist_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unconfirmed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,
}

impl ActionReply {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            ime: None,
            created_key: None,
            revision: None,
            draft_ver: None,
            client_id: None,
            client_seq: None,
            draft_cleared: None,
            conflict: None,
            reservation_rolled_back: None,
            provisional: None,
            server_draft: None,
            persist_error: None,
            unconfirmed: None,
            boot_id: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
            ime: None,
            created_key: None,
            revision: None,
            draft_ver: None,
            client_id: None,
            client_seq: None,
            draft_cleared: None,
            conflict: None,
            reservation_rolled_back: None,
            provisional: None,
            server_draft: None,
            persist_error: None,
            unconfirmed: None,
            boot_id: None,
        }
    }
}

pub fn make_pane_key(host_id: &str, session_id: &str, block_id: &str) -> String {
    format!("{host_id}|{session_id}|{block_id}")
}

pub fn split_pane_key(key: &str) -> Option<(&str, &str, &str)> {
    let mut parts = key.splitn(3, '|');
    let host = parts.next()?;
    let session = parts.next()?;
    let block = parts.next()?;
    if host.is_empty() || session.is_empty() || block.is_empty() {
        return None;
    }
    Some((host, session, block))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rex_actions_deserialize_exact_typescript_wire_shapes() {
        let cases = [
            r#"{"op":"send_input","key":"mini|s1|b1","data":"y\r","clearDraft":true}"#,
            r#"{"op":"send_input","key":"mini|s1|b1","data":"part1","stage":true,"resetStage":true,"stageId":"s1"}"#,
            r#"{"op":"send_key","key":"mini|s1|b1","keyName":"ArrowUp","mods":4}"#,
            r#"{"op":"set_ownership","key":"mini|s1|b1","mode":"take","cols":53,"rows":14}"#,
            r#"{"op":"set_ownership","key":"mini|s1|b1","mode":"hand_back"}"#,
            r#"{"op":"scroll_vt","key":"cp0|s0|b0","deltaLines":-5,"toBottom":false}"#,
            r#"{"op":"save_draft","key":"mini|s1|b1","text":"你好","append":true}"#,
            r#"{"op":"save_draft","key":"mini|s1|b1","text":"续写","append":true,"ifDraftVer":7}"#,
            r#"{"op":"mark_seen","key":"moon|s2|b1"}"#,
            r#"{"op":"toggle_mute"}"#,
            r#"{"op":"new_session","hostId":"mini","label":"build","cwd":"/tmp"}"#,
            r#"{"op":"close_block","key":"mini|s1|b1"}"#,
            r#"{"op":"add_host","label":"lab","endpoint":"ssh://root@10.0.0.2","sshKeyPath":"/tmp/k"}"#,
            r#"{"op":"remove_host","hostId":"lab"}"#,
            r#"{"op":"ime_compose","raw":"nihao","selectIdx":0,"pageDelta":1,"toggleSchema":false}"#,
            r#"{"op":"asr_toggle","key":"mini|s1|b1"}"#,
            r#"{"op":"asr_configure","provider":"groq","apiKey":"sk-123","endpoint":"https://api.groq.com"}"#,
            r#"{"op":"tsnet_set","enabled":true,"hostname":"rex-zero"}"#,
            r#"{"op":"tsnet_ping","peerIp":"100.64.0.1"}"#,
            r#"{"op":"tsnet_add_peer","dnsName":"mini.ts.net","hostName":"mini","mode":"https"}"#,
            r#"{"op":"pair_toggle","active":true}"#,
            r#"{"op":"pair_confirm","approve":true}"#,
            r#"{"op":"set_ui_prefs","fontPreset":1,"readerMode":"trace"}"#,
        ];

        for raw in cases {
            let parsed: RexAction = serde_json::from_str(raw).expect(raw);
            let roundtrip = serde_json::to_value(&parsed).unwrap();
            assert!(roundtrip.get("op").is_some(), "{raw}");
        }
    }

    #[test]
    fn pane_key_roundtrips_cleanly() {
        let key = make_pane_key("mini", "session:1", "block:2");
        assert_eq!(split_pane_key(&key), Some(("mini", "session:1", "block:2")));
        assert_eq!(split_pane_key("bad|key"), None);
    }
}
