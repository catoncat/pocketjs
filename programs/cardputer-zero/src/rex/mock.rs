//! Rich deterministic `--mock` fleet state for headless `--shot` UI verification
//! and macOS development. Exercises real `libghostty-vt` ANSI rendering on `cp0|s0|b0`
//! (`50×14` compact grid), an interactive permission `ApprovalCard` on `mini|s1|b1`,
//! `unseen_done` on `moon|s2|b1`, QR matrices for `tailnet` (`NeedsLogin`) and `pair`,
//! and crisp Rime/ASR workflows.

use crate::rex::{
    qr,
    types::{
        make_pane_key, ApprovalCard, ApprovalOption, AttentionSummary, ChimeKind, ConnPhase,
        HostKind, HostState, PaneActivityStatus, PaneSummary, PathKind, ReaderMessage, ReaderRole,
        SessionSummary, TailnetPeer, TailnetState,
    },
    vt::VtActor,
};
use std::{
    collections::{BTreeMap, HashMap},
    time::{SystemTime, UNIX_EPOCH},
};

pub struct MockPaneExtra {
    pub live_activity: Option<String>,
    pub approval: Option<ApprovalCard>,
    pub reader_messages: Vec<ReaderMessage>,
}

pub struct MockSeed {
    pub hosts: Vec<HostState>,
    pub panes: Vec<PaneSummary>,
    pub extras: HashMap<String, MockPaneExtra>,
    pub drafts: BTreeMap<String, String>,
    pub tailnet: TailnetState,
    pub attention: AttentionSummary,
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(1_763_740_800_000)
}

pub fn build_mock_seed(vt: &VtActor) -> MockSeed {
    let now_ms = current_unix_ms();

    let hosts = vec![
        HostState {
            id: "cp0".into(),
            label: "cp0 本机".into(),
            kind: HostKind::Local,
            endpoint: "unix:///run/user/1000/rex/server.sock".into(),
            phase: ConnPhase::Live,
            problem: None,
            latency_ms: Some(1),
            path_kind: Some(PathKind::Local),
            sessions: vec![SessionSummary {
                id: "s0".into(),
                label: "ops · cardputer".into(),
                window_count: 1,
                pane_count: 1,
            }],
        },
        HostState {
            id: "mini".into(),
            label: "mini".into(),
            kind: HostKind::Tailnet,
            endpoint: "https://mini-rex.example-tailnet.ts.net".into(),
            phase: ConnPhase::Live,
            problem: None,
            latency_ms: Some(3),
            path_kind: Some(PathKind::Direct),
            sessions: vec![SessionSummary {
                id: "s1".into(),
                label: "rex-zero · build".into(),
                window_count: 2,
                pane_count: 2,
            }],
        },
        HostState {
            id: "moon".into(),
            label: "moon".into(),
            kind: HostKind::Tailnet,
            endpoint: "https://moon-rex.example-tailnet.ts.net".into(),
            phase: ConnPhase::Live,
            problem: None,
            latency_ms: Some(18),
            path_kind: Some(PathKind::Direct),
            sessions: vec![SessionSummary {
                id: "s2".into(),
                label: "codex · gate2".into(),
                window_count: 1,
                pane_count: 1,
            }],
        },
        HostState {
            id: "m1".into(),
            label: "m1".into(),
            kind: HostKind::Ssh,
            endpoint: "ssh://dev@m1".into(),
            phase: ConnPhase::Live,
            problem: None,
            latency_ms: Some(5),
            path_kind: Some(PathKind::Ssh),
            sessions: vec![SessionSummary {
                id: "s3".into(),
                label: "ci · runner".into(),
                window_count: 1,
                pane_count: 1,
            }],
        },
        HostState {
            id: "omarchy".into(),
            label: "omarchy".into(),
            kind: HostKind::Ssh,
            endpoint: "ssh://omarchy".into(),
            phase: ConnPhase::Reconnecting,
            problem: Some("SSH 握手重试中 (2/5)".into()),
            latency_ms: None,
            path_kind: Some(PathKind::Ssh),
            sessions: Vec::new(),
        },
    ];

    let k_mini_b1 = make_pane_key("mini", "s1", "b1");
    let k_cp0_b0 = make_pane_key("cp0", "s0", "b0");
    let k_moon_b1 = make_pane_key("moon", "s2", "b1");
    let k_m1_b0 = make_pane_key("m1", "s3", "b0");
    let k_mini_b2 = make_pane_key("mini", "s1", "b2");

    let mut drafts = BTreeMap::new();
    drafts.insert(k_mini_b2.clone(), "检查一下 tsnet SOCKS5 直连延迟".into());

    let panes = vec![
        PaneSummary {
            key: k_mini_b1.clone(),
            host_id: "mini".into(),
            host_label: "mini".into(),
            session_id: "s1".into(),
            session_label: "rex-zero · build".into(),
            window_id: "w1".into(),
            window_label: "RexZero原生构建 · m5stack".into(),
            block_id: "b1".into(),
            title: "rex-zero · 交叉编译".into(),
            program: "agy".into(),
            pwd: "~/fun/m5stack/rex-zero-native".into(),
            status: PaneActivityStatus::Blocked,
            status_kind: Some("permission".into()),
            status_msg: Some("等待授权: cargo zigbuild --release".into()),
            owned_by_us: false,
            released_by_us: false,
            has_draft: false,
            updated_at_ms: now_ms,
        },
        PaneSummary {
            key: k_m1_b0.clone(),
            host_id: "m1".into(),
            host_label: "m1".into(),
            session_id: "s3".into(),
            session_label: "ci · runner".into(),
            window_id: "w0".into(),
            window_label: "TLS握手单测 · rexrs".into(),
            block_id: "b0".into(),
            title: "rexrs · tls_handshake".into(),
            program: "cargo".into(),
            pwd: "~/work/rexrs".into(),
            status: PaneActivityStatus::Error,
            status_kind: Some("exit_code".into()),
            status_msg: Some("1 test failed (exit 101)".into()),
            owned_by_us: false,
            released_by_us: false,
            has_draft: false,
            updated_at_ms: now_ms.saturating_sub(2 * 60_000),
        },
        PaneSummary {
            key: k_moon_b1.clone(),
            host_id: "moon".into(),
            host_label: "moon".into(),
            session_id: "s2".into(),
            session_label: "codex · gate2".into(),
            window_id: "w1".into(),
            window_label: "Gate2代码终审 · rex-zero".into(),
            block_id: "b1".into(),
            title: "Gate 2 终审通过".into(),
            program: "codex".into(),
            pwd: "~/fun/m5stack/rex-zero-native".into(),
            status: PaneActivityStatus::UnseenDone,
            status_kind: Some("done".into()),
            status_msg: Some("0 P0 / 0 P1 · 契约一致".into()),
            owned_by_us: false,
            released_by_us: false,
            has_draft: false,
            updated_at_ms: now_ms.saturating_sub(5 * 60_000),
        },
        PaneSummary {
            key: k_cp0_b0.clone(),
            host_id: "cp0".into(),
            host_label: "cp0 本机".into(),
            session_id: "s0".into(),
            session_label: "ops · cardputer".into(),
            window_id: "w0".into(),
            window_label: "设备遥测巡检 · cardputer".into(),
            block_id: "b0".into(),
            title: "rex server status".into(),
            program: "rex".into(),
            pwd: "~".into(),
            status: PaneActivityStatus::Running,
            status_kind: Some("working".into()),
            status_msg: Some("采集本机 Rex 与网卡遥测".into()),
            owned_by_us: false,
            released_by_us: false,
            has_draft: false,
            updated_at_ms: now_ms.saturating_sub(40_000),
        },
        PaneSummary {
            key: k_mini_b2.clone(),
            host_id: "mini".into(),
            host_label: "mini".into(),
            session_id: "s1".into(),
            session_label: "rex-zero · build".into(),
            window_id: "w2".into(),
            window_label: "打包部署脚本 · m5stack".into(),
            block_id: "b2".into(),
            title: "zsh · scripts".into(),
            program: "zsh".into(),
            pwd: "~/fun/m5stack/rex-zero-native/scripts".into(),
            status: PaneActivityStatus::Idle,
            status_kind: None,
            status_msg: None,
            owned_by_us: false,
            released_by_us: false,
            has_draft: true,
            updated_at_ms: now_ms.saturating_sub(18 * 60_000),
        },
    ];

    // Feed REAL `libghostty-vt` terminals (`50×14`) with lines <= 50 cols so nothing clips at x=320.
    let cp0_ansi = concat!(
        "\x1b[1;36mzero@cardputer\x1b[0m:\x1b[1;33m~\x1b[0m$ rex server status\r\n",
        "\x1b[1;32m●\x1b[0m rex-server \x1b[38;5;117mv0.19.0\x1b[0m (rev 19) pid=1482 up=4h18m\r\n",
        "  socket:  \x1b[36m/run/user/1000/rex/server.sock\x1b[0m\r\n",
        "  tailnet: \x1b[32mrex-zero.ts.net\x1b[0m (direct 3ms)\r\n",
        "\x1b[1;35m┌─────────┬──────────┬───────────┬─────────────┐\x1b[0m\r\n",
        "\x1b[1;35m│\x1b[0m Metric  \x1b[1;35m│\x1b[0m Value    \x1b[1;35m│\x1b[0m Budget    \x1b[1;35m│\x1b[0m Status      \x1b[1;35m│\x1b[0m\r\n",
        "\x1b[1;35m├─────────┼──────────┼───────────┼─────────────┤\x1b[0m\r\n",
        "\x1b[1;35m│\x1b[0m RAM RSS \x1b[1;35m│\x1b[0m \x1b[32m18.4 MiB\x1b[0m \x1b[1;35m│\x1b[0m < 48 MiB  \x1b[1;35m│\x1b[0m \x1b[1;32mOK (352MiB)\x1b[0m \x1b[1;35m│\x1b[0m\r\n",
        "\x1b[1;35m│\x1b[0m CPU Tmp \x1b[1;35m│\x1b[0m \x1b[33m46.8 °C\x1b[0m  \x1b[1;35m│\x1b[0m < 75 °C   \x1b[1;35m│\x1b[0m \x1b[1;32mCOOL\x1b[0m        \x1b[1;35m│\x1b[0m\r\n",
        "\x1b[1;35m│\x1b[0m Battery \x1b[1;35m│\x1b[0m \x1b[36m86% 3.98V\x1b[0m\x1b[1;35m│\x1b[0m Dischrg   \x1b[1;35m│\x1b[0m \x1b[1;36mREADY\x1b[0m       \x1b[1;35m│\x1b[0m\r\n",
        "\x1b[1;35m└─────────┴──────────┴───────────┴─────────────┘\x1b[0m\r\n",
        "\x1b[1;36mzero@cardputer\x1b[0m:\x1b[1;33m~\x1b[0m$ "
    );
    vt.write_raw_sync(&k_cp0_b0, 50, 14, cp0_ansi.as_bytes().to_vec());

    let mini_ansi = concat!(
        "\x1b[1;36m❯\x1b[0m 构建 CardputerZero ARM64 固件并静态链接 VT\r\n",
        "\x1b[38;5;141m●\x1b[0m 已核对 types.ts 与 shim.c，准备交叉编译。\r\n",
        "\x1b[1;33m⚠ Permission:\x1b[0m Allow cargo zigbuild --release?\r\n",
        "  \x1b[1;32m[1]\x1b[0m Allow once    \x1b[1;31m[2]\x1b[0m Deny\r\n"
    );
    vt.write_raw_sync(&k_mini_b1, 50, 14, mini_ansi.as_bytes().to_vec());

    let moon_ansi = concat!(
        "\x1b[1;36m❯\x1b[0m 运行 Gate 2 独立代码终审\r\n",
        "\x1b[1;32m✓ Codex Review Pass (0 P0 / 0 P1)\x1b[0m\r\n",
        "  • Focus & ownership isolation verified (Peek).\r\n",
        "  • tsnet SOCKS5 & 0600 key perms verified.\r\n"
    );
    vt.write_raw_sync(&k_moon_b1, 50, 14, moon_ansi.as_bytes().to_vec());

    let m1_ansi = concat!(
        "\x1b[1;31merror:\x1b[0m test tls_expired_cert failed (tls.rs:88)\r\n",
        "note: run with RUST_BACKTRACE=1 for a backtrace\r\n"
    );
    vt.write_raw_sync(&k_m1_b0, 50, 14, m1_ansi.as_bytes().to_vec());

    let mut extras = HashMap::new();
    extras.insert(
        k_mini_b1.clone(),
        MockPaneExtra {
            live_activity: Some("等待授权: cargo zigbuild --release".into()),
            approval: Some(ApprovalCard {
                title: "Allow command cargo zigbuild --release?".into(),
                detail: "cargo zigbuild --release -p pocket-cardputer-zero --target aarch64-unknown-linux-gnu.2.36".into(),
                options: vec![
                    ApprovalOption {
                        key: "1".into(),
                        label: "[1] Allow once".into(),
                        send: "1".into(),
                    },
                    ApprovalOption {
                        key: "2".into(),
                        label: "[2] Deny".into(),
                        send: "2".into(),
                    },
                ],
            }),
            reader_messages: vec![
                ReaderMessage {
                    id: "m1".into(),
                    role: ReaderRole::User,
                    title: None,
                    body: "构建 CardputerZero ARM64 原生引擎并链接官方 libghostty-vt.a".into(),
                },
                ReaderMessage {
                    id: "m2".into(),
                    role: ReaderRole::Tool,
                    title: Some("Read(native/ghostty/shim.c)".into()),
                    body: "已核验 RpTerminal FFI、GHOSTSNP 快照解码与 rex1 APC 帧边界。".into(),
                },
                ReaderMessage {
                    id: "m3".into(),
                    role: ReaderRole::Assistant,
                    title: Some("Antigravity".into()),
                    body: "准备在目标 aarch64-unknown-linux-gnu.2.36 上执行 Release 交叉编译，请确认授权运行命令。".into(),
                },
            ],
        },
    );

    extras.insert(
        k_cp0_b0.clone(),
        MockPaneExtra {
            live_activity: Some("采集本机 Rex 与网卡遥测".into()),
            approval: None,
            reader_messages: vec![
                ReaderMessage {
                    id: "c1".into(),
                    role: ReaderRole::User,
                    title: None,
                    body: "rex server status".into(),
                },
                ReaderMessage {
                    id: "c2".into(),
                    role: ReaderRole::Assistant,
                    title: Some("cp0 telemetry".into()),
                    body: "rex-server v0.19.0 运行正常 · RAM 18.4 MiB / 352 MiB · CPU 46.8°C · Tailnet 直连 3ms（按 Ctrl+T 切换真实 libghostty-vt 终端视图）。".into(),
                },
            ],
        },
    );

    extras.insert(
        k_moon_b1.clone(),
        MockPaneExtra {
            live_activity: None,
            approval: None,
            reader_messages: vec![
                ReaderMessage {
                    id: "r1".into(),
                    role: ReaderRole::User,
                    title: None,
                    body: "对 Rex Zero 进行 Gate 2 架构与安全终审".into(),
                },
                ReaderMessage {
                    id: "r2".into(),
                    role: ReaderRole::Assistant,
                    title: Some("Codex Gate 2".into()),
                    body: "✓ 0 P0 / 0 P1：默认 Peek 只读不篡改桌面终端尺寸；tsnet 纯用户态 SOCKS5 零冲突；SSH/ASR 凭证 0600 落盘通过。".into(),
                },
            ],
        },
    );

    extras.insert(
        k_m1_b0.clone(),
        MockPaneExtra {
            live_activity: None,
            approval: None,
            reader_messages: vec![
                ReaderMessage {
                    id: "e1".into(),
                    role: ReaderRole::Tool,
                    title: Some("cargo test -p rexrs".into()),
                    body: "FAILED transport::tls_expired_cert — assertion failed at src/tls.rs:88".into(),
                },
            ],
        },
    );

    let auth_url = "https://login.tailscale.com/a/rexzero01".to_string();
    let tailnet = TailnetState {
        enabled: false,
        backend_state: "NeedsLogin".into(),
        qr_matrix: qr::encode_matrix(&auth_url),
        auth_url,
        tailnet_name: "example-tailnet.ts.net".into(),
        self_dns: "rex-zero.example-tailnet.ts.net".into(),
        proxy_port: 0,
        error: None,
        peers: vec![
            TailnetPeer {
                host_name: "mini-rex".into(),
                dns_name: "mini-rex.example-tailnet.ts.net".into(),
                ips: vec!["100.64.0.12".into()],
                online: true,
                path_kind: Some(PathKind::Direct),
                latency_ms: Some(3),
                rex_endpoint: Some("https://mini-rex.example-tailnet.ts.net".into()),
                already_added: true,
            },
            TailnetPeer {
                host_name: "moon-rex".into(),
                dns_name: "moon-rex.example-tailnet.ts.net".into(),
                ips: vec!["100.64.0.28".into()],
                online: true,
                path_kind: Some(PathKind::Direct),
                latency_ms: Some(18),
                rex_endpoint: Some("https://moon-rex.example-tailnet.ts.net".into()),
                already_added: true,
            },
            TailnetPeer {
                host_name: "nas-lab".into(),
                dns_name: "nas-lab.example-tailnet.ts.net".into(),
                ips: vec!["100.64.0.45".into()],
                online: true,
                path_kind: Some(PathKind::Relay),
                latency_ms: Some(29),
                rex_endpoint: Some("https://nas-lab.example-tailnet.ts.net".into()),
                already_added: false,
            },
        ],
    };

    let attention = AttentionSummary {
        blocked_count: 1,
        error_count: 1,
        unseen_done_count: 1,
        next_target_key: Some(k_mini_b1),
        chime_seq: 1,
        chime_kind: ChimeKind::Approval,
        muted: false,
    };

    MockSeed {
        hosts,
        panes,
        extras,
        drafts,
        tailnet,
        attention,
    }
}
