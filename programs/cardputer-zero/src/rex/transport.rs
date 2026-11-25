//! Native Rex transports (`Unix`, `SSH dial-stdio`, `HTTPS/WSS` via `rustls` + `tsnet` SOCKS5),
//! wakeup-pipe nonblocking `poll` multiplexer, env proxy (`HTTPS_PROXY` / `ALL_PROXY`) dialer,
//! and host configuration persistence (`~/.config/rex-zero/`).

use crate::rex::types::{AsrProvider, HostKind, PathKind};
use percent_encoding::percent_decode_str;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_pki_types::ServerName;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    io::{self, Read, Write},
    net::{Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};
use tungstenite::{client::IntoClientRequest, http::HeaderValue, WebSocket};

const HANDSHAKE_IO_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_POLL_TIMEOUT: Duration = Duration::from_secs(5);

// ============================================================================
// Persistent Config (`~/.config/rex-zero/`) + Read-Only Rex Host Discovery
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfiguredHost {
    pub id: String,
    pub label: String,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedSettings {
    #[serde(default = "default_asr_provider")]
    pub asr_provider: String,
    #[serde(default)]
    pub asr_provider_explicit: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asr_key_provider: Option<String>,
    #[serde(default)]
    pub asr_api_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asr_app_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asr_endpoint: Option<String>,
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub tailnet_enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tailnet_hostname: Option<String>,
    #[serde(default)]
    pub font_preset: u8,
    #[serde(default = "default_reader_mode")]
    pub reader_mode: String,
}

fn default_asr_provider() -> String {
    "doubao_free".into()
}

fn default_reader_mode() -> String {
    "chat".into()
}

impl Default for PersistedSettings {
    fn default() -> Self {
        Self {
            asr_provider: default_asr_provider(),
            asr_provider_explicit: false,
            asr_key_provider: None,
            asr_api_key: String::new(),
            asr_app_id: None,
            asr_endpoint: None,
            muted: false,
            tailnet_enabled: false,
            tailnet_hostname: None,
            font_preset: 0,
            reader_mode: default_reader_mode(),
        }
    }
}

impl PersistedSettings {
    pub fn provider_enum(&self) -> AsrProvider {
        let raw = AsrProvider::from_name(&self.asr_provider);
        if raw == AsrProvider::DoubaoFree
            && !self.asr_provider_explicit
            && !self.asr_api_key.trim().is_empty()
            && crate::rex::asr::resolve_plugin_path(AsrProvider::DoubaoFree).is_none()
        {
            return AsrProvider::Openai;
        }
        // Automatically upgrade legacy unconfigured `"openai"` defaults (from v0.1.0) to
        // built-in zero-key Doubao streaming plugin when not explicitly chosen by the user.
        if !self.asr_provider_explicit
            && self.asr_api_key.trim().is_empty()
            && raw == AsrProvider::Openai
            && crate::rex::asr::resolve_plugin_path(AsrProvider::DoubaoFree).is_some()
        {
            return AsrProvider::DoubaoFree;
        }
        raw
    }

    pub fn credentials_match_provider(&self, p: AsrProvider) -> bool {
        if let Some(owner) = self.asr_key_provider.as_deref() {
            return AsrProvider::from_name(owner) == p;
        }
        let raw = AsrProvider::from_name(&self.asr_provider);
        raw == p || (!self.asr_provider_explicit && raw == AsrProvider::DoubaoFree && p == AsrProvider::Openai)
    }

    pub fn effective_api_key(&self, p: AsrProvider) -> &str {
        if self.credentials_match_provider(p) {
            self.asr_api_key.trim()
        } else {
            ""
        }
    }

    pub fn effective_endpoint(&self, p: AsrProvider) -> Option<&str> {
        if self.credentials_match_provider(p) {
            self.asr_endpoint.as_deref().map(str::trim).filter(|s| !s.is_empty())
        } else {
            None
        }
    }

    pub fn effective_app_id(&self, p: AsrProvider) -> Option<&str> {
        if self.credentials_match_provider(p) {
            self.asr_app_id.as_deref().map(str::trim).filter(|s| !s.is_empty())
        } else {
            None
        }
    }

    pub fn is_asr_configured(&self) -> bool {
        let p = self.provider_enum();
        match p {
            AsrProvider::DoubaoFree | AsrProvider::Plugin => {
                crate::rex::asr::resolve_plugin_path(p).is_some()
            }
            AsrProvider::Openai
            | AsrProvider::Groq
            | AsrProvider::Elevenlabs
            | AsrProvider::Doubao => !self.effective_api_key(p).is_empty(),
        }
    }
}

pub fn config_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("REX_ZERO_CONFIG_DIR") {
        return PathBuf::from(dir);
    }
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("rex-zero")
}

pub fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("REX_ZERO_STATE_DIR") {
        return PathBuf::from(dir);
    }
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("rex-zero")
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let tmp = path.with_extension("tmp");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

pub fn load_settings(dir: &Path) -> PersistedSettings {
    std::fs::read_to_string(dir.join("settings.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_settings(dir: &Path, settings: &PersistedSettings) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(settings).map_err(io::Error::other)?;
    write_private_file(&dir.join("settings.json"), &json)
}

pub fn load_saved_hosts(dir: &Path) -> Vec<ConfiguredHost> {
    std::fs::read_to_string(dir.join("hosts.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_hosts(dir: &Path, hosts: &[ConfiguredHost]) -> io::Result<()> {
    let json = serde_json::to_vec_pretty(hosts).map_err(io::Error::other)?;
    write_private_file(&dir.join("hosts.json"), &json)
}

pub fn load_drafts(dir: &Path) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = std::fs::read_to_string(dir.join("drafts.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let mut budget = super::MAX_TOTAL_DRAFTS_BYTES - 2;
    map.retain(|key, value| {
        let overhead = super::entry_bytes(key, "");
        value.truncate(super::draft_prefix(value, budget.saturating_sub(overhead)).len());
        if key.is_empty() || value.is_empty() {
            return false;
        }
        budget -= super::entry_bytes(key, value);
        true
    });
    map
}

pub fn save_drafts(dir: &Path, drafts: &BTreeMap<String, String>) -> io::Result<()> {
    let json = serde_json::to_vec(drafts).map_err(io::Error::other)?;
    write_private_file(&dir.join("drafts.json"), &json)
}

/// Discovers local Unix socket + user's read-only Rex host definitions + saved Rex Zero hosts.
pub fn discover_initial_hosts(
    config_root: &Path,
    connect_local_macos: bool,
) -> Vec<ConfiguredHost> {
    let mut out: Vec<ConfiguredHost> = Vec::new();
    let mut seen_endpoints: HashSet<String> = HashSet::new();

    // 1. Local Rex server socket discovery.
    if let Some(sock) = discover_local_socket(connect_local_macos) {
        let ep = format!("unix://{}", sock.display());
        seen_endpoints.insert(ep.clone());
        out.push(ConfiguredHost {
            id: "local".into(),
            label: local_host_label(),
            endpoint: ep,
            ssh_key_path: None,
        });
    }

    // 2. Saved hosts in `~/.config/rex-zero/hosts.json`.
    for h in load_saved_hosts(config_root) {
        if seen_endpoints.insert(h.endpoint.clone()) {
            out.push(h);
        }
    }

    // 3. Read-only import from user's desktop/CLI Rex configs (`~/.config/rex/hosts.json`,
    // `~/.local/share/rex/host-endpoints.json`, `~/Library/Application Support/rex/host-endpoints.json`).
    if std::env::var_os("REX_ZERO_SKIP_SYSTEM_HOSTS").is_none() {
        for discovered in read_external_rex_hosts() {
            if !seen_endpoints.contains(&discovered.endpoint)
                && !out
                    .iter()
                    .any(|h| h.label.eq_ignore_ascii_case(&discovered.label))
            {
                seen_endpoints.insert(discovered.endpoint.clone());
                out.push(discovered);
            }
        }
    }

    out
}

fn local_host_label() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(name) = std::fs::read_to_string("/etc/hostname") {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                return format!("{trimmed} 本机");
            }
        }
        "cp0 本机".into()
    }
    #[cfg(not(target_os = "linux"))]
    {
        "本机 Rex".into()
    }
}

fn discover_local_socket(connect_local_macos: bool) -> Option<PathBuf> {
    if let Ok(env_ep) = std::env::var("REX_SERVER") {
        if cfg!(target_os = "linux") || connect_local_macos {
            if let Some(rest) = env_ep.strip_prefix("unix://") {
                if let Ok(decoded) = percent_decode_str(rest).decode_utf8() {
                    let p = PathBuf::from(decoded.as_ref());
                    if p.exists() {
                        return Some(p);
                    }
                }
            } else if env_ep.starts_with('/') {
                let p = PathBuf::from(env_ep);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
            let candidate = PathBuf::from(xdg).join("rex/server.sock");
            if candidate.exists() {
                return Some(candidate);
            }
        }
        let uid = unsafe { libc::getuid() };
        let run_sock = PathBuf::from(format!("/run/user/{uid}/rex/server.sock"));
        if run_sock.exists() {
            return Some(run_sock);
        }
    }

    #[cfg(target_os = "macos")]
    if connect_local_macos {
        if let Some(home) = std::env::var_os("HOME") {
            let sock = PathBuf::from(home).join("Library/Application Support/rex/server.sock");
            if sock.exists() {
                return Some(sock);
            }
        }
    }

    None
}

fn read_external_rex_hosts() -> Vec<ConfiguredHost> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let candidates = [
        home.join(".config/rex/hosts.json"),
        home.join(".local/share/rex/hosts.json"),
        home.join(".local/share/rex/host-endpoints.json"),
        home.join("Library/Application Support/rex/host-endpoints.json"),
    ];
    let mut out = Vec::new();
    for path in candidates {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(val) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        // Format A: Array or `{"hosts": [ {"id":..., "label":..., "endpoints":[...]} ]}`
        let array_opt = val
            .as_array()
            .or_else(|| val.get("hosts").and_then(Value::as_array));
        if let Some(items) = array_opt {
            for item in items {
                let label = item
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim();
                let endpoint = item
                    .get("endpoint")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        item.get("endpoints")
                            .and_then(Value::as_array)
                            .and_then(|a| a.first())
                            .and_then(Value::as_str)
                    })
                    .unwrap_or("")
                    .trim();
                if !endpoint.is_empty() {
                    let normalized = normalize_endpoint(endpoint);
                    let derived_label = if label.is_empty() {
                        derive_label_from_endpoint(&normalized)
                    } else {
                        label.to_string()
                    };
                    let id = slug_id(&derived_label, out.len());
                    out.push(ConfiguredHost {
                        id,
                        label: derived_label,
                        endpoint: normalized,
                        ssh_key_path: None,
                    });
                }
            }
        } else if let Some(map) = val.get("hosts").and_then(Value::as_object) {
            // Format B: `host-endpoints.json` (`{"hosts": {"host:uuid": "https://..."}}`)
            for (_host_key, ep_val) in map {
                if let Some(ep) = ep_val.as_str() {
                    let normalized = normalize_endpoint(ep);
                    let label = derive_label_from_endpoint(&normalized);
                    let id = slug_id(&label, out.len());
                    out.push(ConfiguredHost {
                        id,
                        label,
                        endpoint: normalized,
                        ssh_key_path: None,
                    });
                }
            }
        }
    }
    out
}

pub fn normalize_endpoint(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("unix://")
        || trimmed.starts_with("ssh://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("wss://")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("ws://")
        || trimmed.starts_with("tcp://")
    {
        return trimmed.trim_end_matches('/').to_string();
    }
    if trimmed.starts_with('/') {
        return format!("unix://{trimmed}");
    }
    if !trimmed.contains('@') && is_magic_dns(trimmed) {
        return format!(
            "https://{}",
            trimmed.trim_end_matches('.').to_ascii_lowercase()
        );
    }
    if trimmed.contains('@') {
        return format!("ssh://{trimmed}");
    }
    if trimmed.contains(':') {
        return format!("tcp://{trimmed}");
    }
    format!("ssh://{trimmed}")
}

pub fn classify_endpoint(endpoint: &str) -> (HostKind, PathKind) {
    if endpoint.starts_with("unix://") || endpoint.starts_with('/') {
        (HostKind::Local, PathKind::Local)
    } else if endpoint.starts_with("ssh://") {
        (HostKind::Ssh, PathKind::Ssh)
    } else if parse_endpoint(endpoint)
        .is_ok_and(|ep| matches!(ep, ParsedEndpoint::Network {host, ..} if is_magic_dns(&host)))
        || endpoint.starts_with("https://")
        || endpoint.starts_with("wss://")
    {
        (HostKind::Tailnet, PathKind::Direct)
    } else {
        (HostKind::Tcp, PathKind::Tcp)
    }
}

pub fn derive_label_from_endpoint(endpoint: &str) -> String {
    let rest = endpoint
        .split("://")
        .nth(1)
        .unwrap_or(endpoint)
        .trim_end_matches('/');
    let host_part = rest.rsplit('@').next().unwrap_or(rest);
    let host_no_port = host_part.split(':').next().unwrap_or(host_part);
    let first_label = host_no_port.split('.').next().unwrap_or(host_no_port);
    let clean = first_label.strip_suffix("-rex").unwrap_or(first_label);
    if clean.is_empty() {
        "rex-host".into()
    } else {
        clean.to_string()
    }
}

pub fn slug_id(label: &str, salt: usize) -> String {
    let mut s: String = label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    s = s.trim_matches('-').to_string();
    if s.is_empty() {
        format!("host-{salt}")
    } else {
        s
    }
}

// ============================================================================
// Parsed Endpoint & Three Native Transports (`Unix`, `SSH`, `TLS`/`TCP`)
// ============================================================================

#[derive(Debug, Clone)]
pub enum ParsedEndpoint {
    Unix(PathBuf),
    Ssh {
        user_host: String,
        host_only: String,
        port: Option<u16>,
    },
    Network {
        tls: bool,
        host: String,
        port: u16,
    },
}

pub fn validate_ssh_token(part: &str, role: &str) -> Result<(), String> {
    if part.is_empty() {
        return Err(format!("empty ssh {role}"));
    }
    if part.starts_with('-') {
        return Err(format!("ssh {role} must not start with '-' ({part})"));
    }
    if role == "host" && part.parse::<std::net::IpAddr>().is_err() {
        let dns = part.strip_suffix('.').unwrap_or(part);
        if dns.len() > 253
            || !dns.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err("invalid SSH hostname".into());
        }
    }
    if part
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '\0'))
    {
        return Err(format!("invalid characters in ssh {role}"));
    }
    Ok(())
}

pub fn validate_ssh_key_path(key_path: &str) -> Result<&str, String> {
    let trimmed = key_path.trim();
    if trimmed.is_empty() {
        return Err("empty ssh key path".into());
    }
    if trimmed.starts_with('-') {
        return Err("ssh key path must not start with '-'".into());
    }
    if trimmed.chars().any(|c| c.is_control() || c == '\0') {
        return Err("ssh key path contains control characters".into());
    }
    Ok(trimmed)
}

pub fn parse_endpoint(endpoint: &str) -> Result<ParsedEndpoint, String> {
    let ep = normalize_endpoint(endpoint);
    if let Some(rest) = ep.strip_prefix("unix://") {
        let decoded = percent_decode_str(rest)
            .decode_utf8()
            .map_err(|e| format!("bad unix socket path: {e}"))?;
        return Ok(ParsedEndpoint::Unix(PathBuf::from(decoded.as_ref())));
    }
    if let Some(rest) = ep.strip_prefix("ssh://") {
        let rest = rest.trim_end_matches('/');
        let (user_part, host_port) = match rest.rsplit_once('@') {
            Some((u, hp)) => {
                validate_ssh_token(u, "username")?;
                (Some(u), hp)
            }
            None => (None, rest),
        };
        let (host_only, port) = parse_host_optional_port(host_port, None)?;
        validate_ssh_token(&host_only, "host")?;
        let user_host = match user_part {
            Some(u) => format!("{u}@{host_only}"),
            None => host_only.clone(),
        };
        return Ok(ParsedEndpoint::Ssh {
            user_host,
            host_only,
            port,
        });
    }
    for (prefix, tls, default_port) in [
        ("https://", true, 443u16),
        ("wss://", true, 443u16),
        ("http://", false, 80u16),
        ("ws://", false, 80u16),
        ("tcp://", false, 7297u16),
    ] {
        if let Some(rest) = ep.strip_prefix(prefix) {
            let authority = rest.split('/').next().unwrap_or(rest);
            let (host, port_opt) = parse_host_optional_port(authority, Some(default_port))?;
            let port = port_opt.unwrap_or(default_port);
            format_validated_authority(&host, port).map_err(|e| e.to_string())?;
            return Ok(ParsedEndpoint::Network { tls, host, port });
        }
    }
    Err(format!("unsupported endpoint: {endpoint}"))
}

fn parse_host_optional_port(
    input: &str,
    default_port: Option<u16>,
) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = input.strip_prefix('[') {
        let (v6, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("unclosed IPv6 bracket in {input}"))?;
        if v6.parse::<Ipv6Addr>().is_err() || (!after.is_empty() && !after.starts_with(':')) {
            return Err("invalid bracketed IPv6 address".into());
        }
        let port = if let Some(p_str) = after.strip_prefix(':') {
            Some(
                p_str
                    .parse::<u16>()
                    .map_err(|_| format!("bad port in {input}"))?,
            )
        } else {
            default_port
        };
        return Ok((v6.to_string(), port));
    }
    if let Some((h, p_str)) = input.rsplit_once(':') {
        if !h.contains(':') {
            let p = p_str
                .parse::<u16>()
                .map_err(|_| format!("bad port in {input}"))?;
            return Ok((h.to_string(), Some(p)));
        }
    }
    if input.is_empty() {
        return Err("empty host".into());
    }
    Ok((input.to_string(), default_port))
}

pub(crate) fn is_magic_dns(host: &str) -> bool {
    host.trim_end_matches('.')
        .as_bytes()
        .last_chunk::<7>()
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case(b".ts.net"))
}

fn is_tailnet_target(host: &str) -> bool {
    is_magic_dns(host) || host.starts_with("100.") || host.starts_with("fd7a:115c:a1e0:")
}

fn has_system_tailscaled() -> bool {
    #[cfg(target_os = "macos")]
    {
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        Path::new("/var/run/tailscale/tailscaled.sock").exists()
            || Path::new("/run/tailscale/tailscaled.sock").exists()
    }
}

pub fn shared_tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                let _ = roots.add(cert);
            }
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let cfg = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("TLS versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone()
}

/// Validates `target_host` and formats a single RFC-compliant `host:port` or `[ipv6]:port`
/// authority, rejecting control characters, whitespace, header-injection bytes, and unbracketed IPv6.
pub fn format_validated_authority(target_host: &str, target_port: u16) -> io::Result<String> {
    if target_port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "port must be non-zero",
        ));
    }
    if target_host.is_empty() || target_host.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host length invalid",
        ));
    }
    if target_host.chars().any(|c| {
        c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '?' | '#' | '@' | '[' | ']')
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host contains invalid or control characters",
        ));
    }
    if target_host.contains(':') {
        let v6: Ipv6Addr = target_host.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid IPv6 literal host")
        })?;
        return Ok(format!("[{v6}]:{target_port}"));
    }
    if !target_host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "host contains invalid hostname characters",
        ));
    }
    Ok(format!("{target_host}:{target_port}"))
}

/// Pure-Rust SOCKS5 client handshake (`NO AUTH`, domain ATYP `0x03` or IPv6 `0x04` so MagicDNS
/// resolves inside `rex-zero-tsnet` without touching OS `/etc/resolv.conf`).
pub fn connect_socks5(
    proxy_addr: SocketAddr,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let tcp = dial_socks(
        proxy_addr,
        target_host,
        target_port,
        Instant::now() + timeout,
        &CancelWatch::default(),
    )?;
    blocking_tcp(tcp, timeout)
}

fn socks_handshake(
    stream: &mut (impl Read + Write),
    target_host: &str,
    target_port: u16,
) -> io::Result<()> {
    // Greeting: VER=5, NMETHODS=1, METHOD=0x00 (No Auth)
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut method_reply = [0u8; 2];
    stream.read_exact(&mut method_reply)?;
    if method_reply != [0x05, 0x00] {
        return Err(io::Error::other(format!(
            "SOCKS5 auth rejected: {method_reply:?}"
        )));
    }

    let mut req = Vec::with_capacity(7 + target_host.len());
    if let Ok(v6) = target_host.parse::<Ipv6Addr>() {
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x04]);
        req.extend_from_slice(&v6.octets());
    } else {
        let host_bytes = target_host.as_bytes();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8]);
        req.extend_from_slice(host_bytes);
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&req)?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 connect failed (code 0x{:02x}) for {target_host}:{target_port}",
            head[1]
        )));
    }
    // Consume BND.ADDR + BND.PORT
    let skip = match head[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len)?;
            len[0] as usize + 2
        }
        other => {
            return Err(io::Error::other(format!(
                "SOCKS5 unknown ATYP 0x{other:02x}"
            )));
        }
    };
    let mut discard = vec![0u8; skip];
    stream.read_exact(&mut discard)?;
    Ok(())
}

/// Connects to `target_host:target_port`, honoring `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`
/// (`http://host:port` HTTP CONNECT or `socks5://host:port`) when set!
pub fn connect_tcp_with_env_proxy(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let tcp = dial_with_env_proxy(
        host,
        port,
        Instant::now() + timeout,
        &CancelWatch::default(),
    )?;
    blocking_tcp(tcp, timeout)
}

fn blocking_tcp(tcp: TcpStream, timeout: Duration) -> io::Result<TcpStream> {
    tcp.set_nonblocking(false)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    Ok(tcp)
}

fn dial_with_env_proxy(
    target_host: &str,
    target_port: u16,
    deadline: Instant,
    cancel: &CancelWatch,
) -> io::Result<TcpStream> {
    let target_authority = format_validated_authority(target_host, target_port)?;
    let proxy_env = [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ]
    .into_iter()
    .find_map(|k| std::env::var(k).ok())
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty());

    if let Some(proxy_url) = proxy_env {
        if let Some(rest) = proxy_url
            .strip_prefix("socks5://")
            .or_else(|| proxy_url.strip_prefix("socks5h://"))
        {
            let authority = rest.split('/').next().unwrap_or(rest);
            let addr = resolve_watched(authority, 1080, deadline, cancel)?;
            return dial_socks(addr, target_host, target_port, deadline, cancel);
        }
        let http_rest = proxy_url
            .strip_prefix("http://")
            .unwrap_or(proxy_url.as_str());
        let proxy_authority = http_rest.split('/').next().unwrap_or(http_rest);
        let addr = resolve_watched(proxy_authority, 8080, deadline, cancel)?;
        let tcp = dial_tcp(addr, deadline, cancel)?;
        let mut stream = RexStream::new(RexInner::Tcp(tcp.try_clone()?), deadline, cancel.clone());
        let connect_req = format!(
            "CONNECT {target_authority} HTTP/1.1\r\nHost: {target_authority}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
        );
        stream.write_all(connect_req.as_bytes())?;
        read_connect_headers(&mut stream)?;
        return Ok(tcp);
    }
    dial_tcp(
        resolve_watched(&target_authority, target_port, deadline, cancel)?,
        deadline,
        cancel,
    )
}

fn read_connect_headers(stream: &mut impl Read) -> io::Result<()> {
    let mut headers = Vec::new();
    let mut byte = [0u8; 1];
    while headers.len() < 8192 {
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            let status = headers.split(|b| *b == b'\n').next().unwrap();
            if status.split(|b| *b == b' ').nth(1) == Some(b"200") {
                return Ok(());
            }
            return Err(io::Error::other("proxy refused CONNECT"));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "CONNECT headers exceed 8 KiB",
    ))
}

fn dial_socks(
    addr: SocketAddr,
    host: &str,
    port: u16,
    deadline: Instant,
    cancel: &CancelWatch,
) -> io::Result<TcpStream> {
    format_validated_authority(host, port)?;
    let tcp = dial_tcp(addr, deadline, cancel)?;
    let mut io = RexStream::new(RexInner::Tcp(tcp.try_clone()?), deadline, cancel.clone());
    socks_handshake(&mut io, host, port)?;
    Ok(tcp)
}

fn resolve_watched(
    authority: &str,
    port: u16,
    deadline: Instant,
    cancel: &CancelWatch,
) -> io::Result<SocketAddr> {
    cancel.remaining(deadline)?;
    if let Ok(addr) = authority.parse() {
        return Ok(addr);
    }
    // libc DNS can block. Bound outstanding lookups even if the resolver never returns.
    use std::sync::atomic::AtomicUsize;
    static LOOKUPS: AtomicUsize = AtomicUsize::new(0);
    LOOKUPS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < 8).then_some(n + 1)
        })
        .map_err(|_| io::Error::other("DNS resolver busy"))?;
    let authority = authority.to_owned();
    let (tx, rx) = std::sync::mpsc::channel();
    if let Err(e) = std::thread::Builder::new()
        .name("rex-dns".into())
        .spawn(move || {
            let result = resolve_first_addr(&authority, port);
            LOOKUPS.fetch_sub(1, Ordering::Release);
            let _ = tx.send(result);
        })
    {
        LOOKUPS.fetch_sub(1, Ordering::Release);
        return Err(e);
    }
    loop {
        let remaining = cancel.remaining(deadline)?;
        match rx.recv_timeout(remaining.min(Duration::from_millis(25))) {
            Ok(result) => return result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(_) => return Err(io::Error::other("resolver stopped")),
        }
    }
}

fn connect_fd<T>(
    family: i32,
    addr: &T,
    len: usize,
    deadline: Instant,
    cancel: &CancelWatch,
) -> io::Result<OwnedFd> {
    cancel.remaining(deadline)?;
    let raw = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    set_fd_cloexec(raw)?;
    set_fd_nonblocking(raw, true)?;
    loop {
        cancel.remaining(deadline)?;
        if unsafe { libc::connect(raw, std::ptr::from_ref(addr).cast(), len as libc::socklen_t) }
            == 0
        {
            return Ok(fd);
        }
        let err = io::Error::last_os_error();
        if family == libc::AF_UNIX && err.kind() == io::ErrorKind::WouldBlock {
            // Linux reports EAGAIN on a full Unix listen backlog without initiating a connection.
            std::thread::sleep(cancel.remaining(deadline)?.min(Duration::from_millis(10)));
            continue;
        }
        if !matches!(
            err.raw_os_error(),
            Some(libc::EINPROGRESS | libc::EINTR | libc::EALREADY)
        ) {
            return Err(err);
        }
        cancel.wait_io(raw, libc::POLLOUT, deadline)?;
        let mut error: libc::c_int = 0;
        let mut optlen = std::mem::size_of_val(&error) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                std::ptr::from_mut(&mut error).cast(),
                &mut optlen,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        return if error == 0 {
            Ok(fd)
        } else {
            Err(io::Error::from_raw_os_error(error))
        };
    }
}

fn dial_unix(path: &Path, deadline: Instant, cancel: &CancelWatch) -> io::Result<UnixStream> {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Unix socket path",
        ));
    }
    addr.sun_family = libc::AF_UNIX as _;
    for (dst, b) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *b as _;
    }
    let len = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    #[cfg(target_os = "macos")]
    {
        addr.sun_len = len as u8;
    }
    Ok(UnixStream::from(connect_fd(
        libc::AF_UNIX,
        &addr,
        len,
        deadline,
        cancel,
    )?))
}

fn dial_tcp(remote: SocketAddr, deadline: Instant, cancel: &CancelWatch) -> io::Result<TcpStream> {
    let fd = match remote {
        SocketAddr::V4(v4) => {
            let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            addr.sin_family = libc::AF_INET as _;
            addr.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            addr.sin_port = v4.port().to_be();
            connect_fd(
                libc::AF_INET,
                &addr,
                std::mem::size_of_val(&addr),
                deadline,
                cancel,
            )?
        }
        SocketAddr::V6(v6) => {
            let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            addr.sin6_family = libc::AF_INET6 as _;
            addr.sin6_addr.s6_addr = v6.ip().octets();
            addr.sin6_port = v6.port().to_be();
            addr.sin6_scope_id = v6.scope_id();
            connect_fd(
                libc::AF_INET6,
                &addr,
                std::mem::size_of_val(&addr),
                deadline,
                cancel,
            )?
        }
    };
    let tcp = TcpStream::from(fd);
    tcp.set_nodelay(true)?;
    Ok(tcp)
}

fn resolve_first_addr(authority: &str, default_port: u16) -> io::Result<SocketAddr> {
    let with_port = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:{default_port}")
    };
    with_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other(format!("DNS resolved no address for {authority}")))
}

/// Invoked when `pocket-cardputer-zero --rex-socks5-stdio <127.0.0.1:port> <host> <port>`
/// runs as `ssh -o ProxyCommand=...`, providing zero-external-dependency SOCKS5 tunneling for SSH!
pub fn run_socks5_stdio_bridge(
    proxy_spec: &str,
    target_host: &str,
    target_port: u16,
) -> io::Result<()> {
    let proxy_addr: SocketAddr = proxy_spec
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("bad proxy addr: {e}")))?;
    let tcp = connect_socks5(
        proxy_addr,
        target_host,
        target_port,
        Duration::from_secs(10),
    )?;
    bridge_nonblocking_fds(libc::STDIN_FILENO, libc::STDOUT_FILENO, tcp)
}

/// Single-threaded nonblocking bidirectional bridge between `(in_fd, out_fd)` and `tcp`.
/// Exits promptly on remote EOF (after flushing pending remote bytes to `out_fd`) without
/// waiting for `in_fd` to close first, and propagates any copy `io::Error`.
fn bridge_nonblocking_fds(in_fd: RawFd, out_fd: RawFd, mut tcp: TcpStream) -> io::Result<()> {
    tcp.set_read_timeout(None)?;
    tcp.set_write_timeout(None)?;
    tcp.set_nonblocking(true)?;
    set_fd_nonblocking(in_fd, true)?;
    set_fd_nonblocking(out_fd, true)?;
    let tcp_fd = tcp.as_raw_fd();

    let mut in_to_tcp: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut tcp_to_out: Vec<u8> = Vec::with_capacity(16 * 1024);
    let mut in_eof = false;
    let mut tcp_eof = false;
    let mut tcp_write_shut = false;
    let mut scratch = [0u8; 16 * 1024];

    loop {
        if tcp_eof && tcp_to_out.is_empty() {
            return Ok(());
        }
        if in_eof && in_to_tcp.is_empty() && !tcp_write_shut {
            let _ = tcp.shutdown(std::net::Shutdown::Write);
            tcp_write_shut = true;
        }
        if in_eof && tcp_eof && in_to_tcp.is_empty() && tcp_to_out.is_empty() {
            return Ok(());
        }

        let mut pfds: [libc::pollfd; 3] = [
            libc::pollfd {
                fd: if !in_eof && in_to_tcp.len() < 16 * 1024 {
                    in_fd
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if !tcp_to_out.is_empty() { out_fd } else { -1 },
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: tcp_fd,
                events: (if !tcp_eof && tcp_to_out.len() < 16 * 1024 {
                    libc::POLLIN
                } else {
                    0
                }) | (if !in_to_tcp.is_empty() {
                    libc::POLLOUT
                } else {
                    0
                }),
                revents: 0,
            },
        ];

        let rc = unsafe { libc::poll(pfds.as_mut_ptr(), 3, 15_000) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }

        // 1. Read from `in_fd` -> `in_to_tcp`.
        if !in_eof && in_to_tcp.len() < 16 * 1024 && pfds[0].revents != 0 {
            loop {
                let cap = (16 * 1024usize).saturating_sub(in_to_tcp.len());
                if cap == 0 {
                    break;
                }
                let n = unsafe {
                    libc::read(in_fd, scratch.as_mut_ptr().cast(), cap.min(scratch.len()))
                };
                if n > 0 {
                    in_to_tcp.extend_from_slice(&scratch[..n as usize]);
                } else if n == 0 {
                    in_eof = true;
                    break;
                } else {
                    let err = io::Error::last_os_error();
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) {
                        break;
                    }
                    if (pfds[0].revents & libc::POLLHUP) != 0 {
                        in_eof = true;
                        break;
                    }
                    return Err(err);
                }
            }
        }

        // 2. Write `in_to_tcp` -> `tcp`.
        if !in_to_tcp.is_empty()
            && (pfds[2].revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP)) != 0
        {
            match tcp.write(&in_to_tcp) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "remote write zero",
                    ));
                }
                Ok(n) => {
                    in_to_tcp.drain(..n);
                }
                Err(ref e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e),
            }
        }

        // 3. Read `tcp` -> `tcp_to_out`.
        if !tcp_eof
            && tcp_to_out.len() < 16 * 1024
            && (pfds[2].revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP)) != 0
        {
            loop {
                let cap = (16 * 1024usize).saturating_sub(tcp_to_out.len());
                if cap == 0 {
                    break;
                }
                let max_read = cap.min(scratch.len());
                match tcp.read(&mut scratch[..max_read]) {
                    Ok(0) => {
                        tcp_eof = true;
                        break;
                    }
                    Ok(n) => {
                        tcp_to_out.extend_from_slice(&scratch[..n]);
                    }
                    Err(ref e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // 4. Write `tcp_to_out` -> `out_fd`.
        if !tcp_to_out.is_empty() {
            let n = unsafe { libc::write(out_fd, tcp_to_out.as_ptr().cast(), tcp_to_out.len()) };
            if n > 0 {
                tcp_to_out.drain(..n as usize);
            } else if n < 0 {
                let err = io::Error::last_os_error();
                if !matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) {
                    return Err(err);
                }
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "stdout write zero",
                ));
            }
        }
    }
}

// ============================================================================
// Unified `RexStream` (`Unix`, `Tcp`, `Tls`, `SshChild`)
// ============================================================================

#[derive(Clone, Default)]
pub struct CancelWatch {
    stop: Arc<AtomicBool>,
    wake_read: Option<Arc<OwnedFdWrap>>,
}

impl CancelWatch {
    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn remaining(&self, deadline: Instant) -> io::Result<Duration> {
        if self.is_stopped() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "stream stopped",
            ));
        }
        deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "stream deadline expired"))
    }

    fn wait_io(&self, fd: RawFd, events: libc::c_short, deadline: Instant) -> io::Result<()> {
        let mut watch_wake = self.wake_fd() >= 0;
        loop {
            let rem = self.remaining(deadline)?;
            let slice_ms = if watch_wake {
                rem.as_millis().clamp(1, 250) as i32
            } else {
                rem.as_millis().clamp(1, 50) as i32
            };
            let mut pfds = [
                libc::pollfd {
                    fd,
                    events: events | libc::POLLERR | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if watch_wake { self.wake_fd() } else { -1 },
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let nfds = if watch_wake { 2 } else { 1 };
            let rc = unsafe { libc::poll(pfds.as_mut_ptr(), nfds, slice_ms) };
            if self.is_stopped() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream stopped",
                ));
            }
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            if pfds[0].revents != 0 {
                return Ok(());
            }
            if watch_wake && pfds[1].revents != 0 {
                // `wake_fd` has a pending command byte while `stop` is still false; leave the
                // byte intact for the supervisor loop and finish this single wait with 50ms slices.
                watch_wake = false;
            }
        }
    }

    fn wake_fd(&self) -> RawFd {
        self.wake_read.as_ref().map(|w| w.0).unwrap_or(-1)
    }
}

enum RexInner {
    Unix(UnixStream),
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    Ssh {
        child: Child,
        stdin: ChildStdin,
        stdout: ChildStdout,
    },
}

pub struct RexStream {
    inner: RexInner,
    /// When `Some(deadline)`, `read()` polls boundedly up to `deadline` (for WS upgrade,
    /// `hello`/`welcome`, and synchronous RPCs). When `None` (`enable_nonblocking_loop`),
    /// `read()` returns `WouldBlock` immediately for 0% CPU event-loop draining.
    read_deadline: Option<Instant>,
    cancel: CancelWatch,
}

impl RexStream {
    fn new(inner: RexInner, deadline: Instant, cancel: CancelWatch) -> Self {
        Self {
            inner,
            read_deadline: Some(deadline),
            cancel,
        }
    }

    pub fn read_fd(&self) -> RawFd {
        match &self.inner {
            RexInner::Unix(stream) => stream.as_raw_fd(),
            RexInner::Tcp(stream) => stream.as_raw_fd(),
            RexInner::Tls(stream) => stream.get_ref().as_raw_fd(),
            RexInner::Ssh { stdout, .. } => stdout.as_raw_fd(),
        }
    }

    fn write_fd(&self) -> RawFd {
        match &self.inner {
            RexInner::Unix(stream) => stream.as_raw_fd(),
            RexInner::Tcp(stream) => stream.as_raw_fd(),
            RexInner::Tls(stream) => stream.get_ref().as_raw_fd(),
            RexInner::Ssh { stdin, .. } => stdin.as_raw_fd(),
        }
    }

    pub fn begin_shutdown_writes(&mut self, deadline: Instant) {
        self.cancel = CancelWatch::default();
        self.read_deadline = Some(deadline);
    }

    pub fn set_read_deadline(&mut self, deadline: Option<Instant>) {
        self.read_deadline = deadline;
    }

    /// Switches steady-state read mode to immediate `WouldBlock` so `tungstenite` drains frames
    /// cleanly and parks in `poll([read_fd, wake_r])` with 0% idle CPU. Both pipe/socket directions
    /// are ALREADY `O_NONBLOCK` from construction, so writes remain deadline-bound and stop-interruptible!
    pub fn enable_nonblocking_loop(&mut self) -> io::Result<()> {
        self.read_deadline = None;
        Ok(())
    }
}

impl Read for RexStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(deadline) = self.read_deadline {
                self.cancel.remaining(deadline)?;
            }
            if self.cancel.is_stopped() {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "stream stopped",
                ));
            }
            let res = match &mut self.inner {
                RexInner::Unix(stream) => stream.read(buf),
                RexInner::Tcp(stream) => stream.read(buf),
                RexInner::Tls(stream) => stream.read(buf),
                RexInner::Ssh { stdout, .. } => stdout.read(buf),
            };
            match (res, self.read_deadline) {
                (Err(ref e), Some(deadline)) if e.kind() == io::ErrorKind::WouldBlock => {
                    // During TLS handshake, `StreamOwned::read` may need `POLLOUT` if `wants_write()`.
                    let events = match &self.inner {
                        RexInner::Tls(s) if s.conn.wants_write() => libc::POLLIN | libc::POLLOUT,
                        _ => libc::POLLIN,
                    };
                    self.cancel.wait_io(self.read_fd(), events, deadline)?;
                }
                (other, _) => return other,
            }
        }
    }
}

impl Write for RexStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let deadline = self
            .read_deadline
            .unwrap_or_else(|| Instant::now() + WRITE_POLL_TIMEOUT);
        loop {
            self.cancel.remaining(deadline)?;
            let res = match &mut self.inner {
                RexInner::Unix(stream) => stream.write(buf),
                RexInner::Tcp(stream) => stream.write(buf),
                RexInner::Tls(stream) => stream.write(buf),
                RexInner::Ssh { stdin, .. } => stdin.write(buf),
            };
            match res {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let events = match &self.inner {
                        RexInner::Tls(s) if s.conn.wants_read() => libc::POLLIN | libc::POLLOUT,
                        _ => libc::POLLOUT,
                    };
                    self.cancel.wait_io(self.write_fd(), events, deadline)?;
                }
                other => return other,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let deadline = self
            .read_deadline
            .unwrap_or_else(|| Instant::now() + WRITE_POLL_TIMEOUT);
        loop {
            self.cancel.remaining(deadline)?;
            let res = match &mut self.inner {
                RexInner::Unix(stream) => stream.flush(),
                RexInner::Tcp(stream) => stream.flush(),
                RexInner::Tls(stream) => stream.flush(),
                RexInner::Ssh { stdin, .. } => stdin.flush(),
            };
            match res {
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let events = match &self.inner {
                        RexInner::Tls(s) if s.conn.wants_read() => libc::POLLIN | libc::POLLOUT,
                        _ => libc::POLLOUT,
                    };
                    self.cancel.wait_io(self.write_fd(), events, deadline)?;
                }
                other => return other,
            }
        }
    }
}

impl Drop for RexStream {
    fn drop(&mut self) {
        if let RexInner::Ssh { child, .. } = &mut self.inner {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Opens a Rex WebSocket (`/api/control` or `/api/data`) over `Unix`, `SSH dial-stdio`, or `HTTPS/TCP`,
/// bounded by `HANDSHAKE_IO_TIMEOUT` and interruptible at any point via `cancel`.
pub fn open_rex_websocket(
    endpoint: &str,
    ssh_key_path: Option<&str>,
    tsnet_proxy_port: u16,
    ws_path: &str,
    subprotocol: &str,
    cancel: CancelWatch,
) -> Result<WebSocket<RexStream>, String> {
    if cancel.is_stopped() {
        return Err("cancelled".into());
    }
    let parsed = parse_endpoint(endpoint)?;
    let deadline = Instant::now() + HANDSHAKE_IO_TIMEOUT;
    let (stream, ws_url) = match parsed {
        ParsedEndpoint::Unix(path) => {
            let sock = dial_unix(&path, deadline, &cancel)
                .map_err(|e| format!("unix socket {}: {e}", path.display()))?;
            sock.set_nonblocking(true)
                .map_err(|e| format!("nonblocking unix socket: {e}"))?;
            (
                RexStream::new(RexInner::Unix(sock), deadline, cancel),
                format!("ws://localhost{ws_path}"),
            )
        }
        ParsedEndpoint::Ssh {
            user_host,
            host_only,
            port,
        } => {
            validate_ssh_token(&host_only, "host")?;
            if user_host.starts_with('-') {
                return Err("ssh destination must not start with '-'".into());
            }
            let validated_key = match ssh_key_path.filter(|k| !k.trim().is_empty()) {
                Some(k) => Some(validate_ssh_key_path(k)?),
                None => None,
            };

            let mut cmd = Command::new("ssh");
            cmd.args([
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=8",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "ServerAliveCountMax=2",
                "-o",
                "StrictHostKeyChecking=accept-new",
            ]);
            if let Some(p) = port {
                cmd.args(["-p", &p.to_string()]);
            }
            if let Some(key) = validated_key {
                cmd.args(["-i", key]);
            }
            if is_magic_dns(&host_only) && tsnet_proxy_port == 0 && !has_system_tailscaled() {
                return Err("正在等待内置 Tailscale 节点就绪".into());
            }
            if tsnet_proxy_port > 0 && is_tailnet_target(&host_only) {
                if let Ok(exe) = std::env::current_exe() {
                    let proxy_cmd = format!(
                        "'{}' --rex-socks5-stdio 127.0.0.1:{tsnet_proxy_port} '{host_only}' {}",
                        exe.display()
                            .to_string()
                            .replace('%', "%%")
                            .replace('\'', "'\\''"),
                        port.unwrap_or(22)
                    );
                    cmd.arg("-o").arg(format!("ProxyCommand={proxy_cmd}"));
                }
            }
            // Terminate SSH option parsing with `--` before destination and remote command!
            cmd.arg("--").arg(&user_host).arg(
                "PATH=\"$HOME/.local/bin:/opt/homebrew/bin:/usr/local/bin:$PATH\" rex __internal dial-stdio",
            );
            cmd.stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());

            let mut child = cmd
                .spawn()
                .map_err(|e| format!("spawn ssh {user_host}: {e}"))?;
            let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
                let _ = child.kill();
                let _ = child.wait();
                return Err("ssh missing stdio pipes".into());
            };
            if let Err(e) = set_fd_nonblocking(stdin.as_raw_fd(), true)
                .and_then(|()| set_fd_nonblocking(stdout.as_raw_fd(), true))
            {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("ssh nonblocking stdio failed: {e}"));
            }
            (
                RexStream::new(
                    RexInner::Ssh {
                        child,
                        stdin,
                        stdout,
                    },
                    deadline,
                    cancel,
                ),
                format!("ws://localhost{ws_path}"),
            )
        }
        ParsedEndpoint::Network { tls, host, port } => {
            let tcp = if tsnet_proxy_port > 0 && is_tailnet_target(&host) {
                let proxy = SocketAddr::from(([127, 0, 0, 1], tsnet_proxy_port));
                match dial_socks(proxy, &host, port, deadline, &cancel) {
                    Ok(s) => s,
                    Err(socks_err) if !is_magic_dns(&host) || has_system_tailscaled() => {
                        dial_with_env_proxy(&host, port, deadline, &cancel)
                            .map_err(|_| format!("tsnet SOCKS5 ({socks_err}) & direct failed"))?
                    }
                    Err(socks_err) => {
                        return Err(format!("Tailscale 连接失败 ({host}): {socks_err}"));
                    }
                }
            } else if is_magic_dns(&host) && !has_system_tailscaled() {
                return Err("正在等待内置 Tailscale 节点就绪".into());
            } else {
                dial_with_env_proxy(&host, port, deadline, &cancel)
                    .map_err(|e| format!("connect {host}:{port}: {e}"))?
            };
            tcp.set_nonblocking(true)
                .map_err(|e| format!("nonblocking tcp socket: {e}"))?;

            let host_authority = if host.contains(':') {
                format!("[{host}]:{port}")
            } else if (tls && port == 443) || (!tls && port == 80) {
                host.clone()
            } else {
                format!("{host}:{port}")
            };

            if tls {
                let server_name = ServerName::try_from(host.clone())
                    .map_err(|e| format!("invalid TLS server name {host}: {e}"))?;
                let tls_conn = ClientConnection::new(shared_tls_config(), server_name)
                    .map_err(|e| format!("TLS init failed: {e}"))?;
                let tls_stream = StreamOwned::new(tls_conn, tcp);
                (
                    RexStream::new(RexInner::Tls(Box::new(tls_stream)), deadline, cancel),
                    format!("wss://{host_authority}{ws_path}"),
                )
            } else {
                (
                    RexStream::new(RexInner::Tcp(tcp), deadline, cancel),
                    format!("ws://{host_authority}{ws_path}"),
                )
            }
        }
    };

    let mut req = ws_url
        .as_str()
        .into_client_request()
        .map_err(|e| format!("WS request build failed: {e}"))?;
    let header_val = HeaderValue::from_str(subprotocol)
        .map_err(|e| format!("invalid subprotocol {subprotocol}: {e}"))?;
    req.headers_mut()
        .insert("Sec-WebSocket-Protocol", header_val);

    let (ws, _resp) = tungstenite::client::client(req, stream)
        .map_err(|e| format!("WebSocket upgrade failed ({ws_url}): {e}"))?;
    Ok(ws)
}

// ============================================================================
// Unix Nonblocking `poll` + Close-on-Exec Wakeup Pipe
// ============================================================================

pub struct WakePipe {
    read_fd: Arc<OwnedFdWrap>,
    _write_keepalive: Arc<OwnedFdWrap>,
}

#[derive(Clone)]
pub struct Waker {
    write_fd: Arc<OwnedFdWrap>,
}

struct OwnedFdWrap(RawFd);
impl Drop for OwnedFdWrap {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

pub fn set_fd_cloexec(fd: RawFd) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

impl WakePipe {
    pub fn new() -> io::Result<(Self, Waker)> {
        let mut fds = [-1 as libc::c_int; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // Take RAII ownership immediately so any setup failure closes both descriptors cleanly!
        let read_fd = Arc::new(OwnedFdWrap(fds[0]));
        let write_fd = Arc::new(OwnedFdWrap(fds[1]));
        set_fd_cloexec(read_fd.0)?;
        set_fd_cloexec(write_fd.0)?;
        set_fd_nonblocking(read_fd.0, true)?;
        set_fd_nonblocking(write_fd.0, true)?;
        Ok((
            Self {
                read_fd,
                _write_keepalive: write_fd.clone(),
            },
            Waker { write_fd },
        ))
    }

    pub fn read_fd(&self) -> RawFd {
        self.read_fd.0
    }

    pub fn cancel_watch(&self, stop: Arc<AtomicBool>) -> CancelWatch {
        CancelWatch {
            stop,
            wake_read: Some(self.read_fd.clone()),
        }
    }

    pub fn drain(&self) {
        let mut buf = [0u8; 64];
        loop {
            let n = unsafe { libc::read(self.read_fd.0, buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
        }
    }
}

impl Waker {
    pub fn wake(&self) {
        let byte = [1u8];
        unsafe {
            let _ = libc::write(self.write_fd.0, byte.as_ptr().cast(), 1);
        }
    }
}

pub fn set_fd_nonblocking(fd: RawFd, nonblocking: bool) -> io::Result<()> {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let next = if nonblocking {
            flags | libc::O_NONBLOCK
        } else {
            flags & !libc::O_NONBLOCK
        };
        if libc::fcntl(fd, libc::F_SETFL, next) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Blocks in `libc::poll` until `stream_fd` or `wake_fd` is readable, or `timeout_ms` elapses.
pub fn wait_fd_readable(stream_fd: RawFd, wake_fd: RawFd, timeout_ms: i32) -> bool {
    let mut pfds = [
        libc::pollfd {
            fd: stream_fd,
            events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
            revents: 0,
        },
        libc::pollfd {
            fd: wake_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let nfds = if wake_fd >= 0 { 2 } else { 1 };
    let rc = unsafe { libc::poll(pfds.as_mut_ptr(), nfds, timeout_ms) };
    rc > 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn fully_qualified_magic_dns_names_use_the_tailnet_route() {
        for name in ["p.example.ts.net", "P.EXAMPLE.TS.NET.", "p.example.Ts.NeT"] {
            assert!(is_tailnet_target(name));
            assert_eq!(normalize_endpoint(name), "https://p.example.ts.net");
            assert_eq!(
                classify_endpoint(&format!("tcp://{name}:7297")).0,
                HostKind::Tailnet
            );
        }
        assert!(!is_tailnet_target("p.ts.net.example."));
    }

    #[test]
    fn ssh_accepts_only_ip_literals_and_dns_labels() {
        for host in ["example.ts.net", "node-1", "127.0.0.1", "[::1]:2222"] {
            assert!(parse_endpoint(&format!("ssh://user@{host}")).is_ok());
        }
        for host in [
            "a b",
            "a;b",
            "a|b",
            "a&b",
            "a$b",
            "a(b)",
            "a`b",
            "a'b",
            "a\"b",
            "a..b",
            "-node",
            "a.-b",
            "[::1]extra",
        ] {
            assert!(parse_endpoint(&format!("ssh://{host}")).is_err(), "{host}");
        }
    }

    #[test]
    fn partial_connect_response_obeys_deadline_and_cancel() {
        for cancelling in [true, false] {
            let (mut peer, client) = UnixStream::pair().unwrap();
            client.set_nonblocking(true).unwrap();
            peer.write_all(b"HTTP/1.1 200 OK\r\n").unwrap();
            let (pipe, waker) = WakePipe::new().unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let deadline = Instant::now()
                + if cancelling {
                    Duration::from_secs(2)
                } else {
                    Duration::from_millis(50)
                };
            let mut stream = RexStream::new(
                RexInner::Unix(client),
                deadline,
                pipe.cancel_watch(stop.clone()),
            );
            std::thread::scope(|scope| {
                if cancelling {
                    scope.spawn(move || {
                        thread::sleep(Duration::from_millis(20));
                        stop.store(true, Ordering::Release);
                        waker.wake();
                    });
                }
                let started = Instant::now();
                let error = read_connect_headers(&mut stream).unwrap_err();
                assert_eq!(
                    error.kind(),
                    if cancelling {
                        io::ErrorKind::ConnectionAborted
                    } else {
                        io::ErrorKind::TimedOut
                    }
                );
                assert!(started.elapsed() < Duration::from_secs(1));
            });
        }
    }

    #[test]
    fn connect_headers_require_complete_terminator_within_budget_and_preserve_payload() {
        let prefix = b"HTTP/1.1 200 OK\r\nX: ";
        let mut bytes = prefix.to_vec();
        bytes.resize(8192 - 4, b'a');
        bytes.extend_from_slice(b"\r\n\r\nlive");
        let mut input = bytes.as_slice();
        read_connect_headers(&mut input).unwrap();
        assert_eq!(input, b"live");
        bytes.insert(prefix.len(), b'a');
        assert!(read_connect_headers(&mut bytes.as_slice()).is_err());
        assert!(read_connect_headers(&mut prefix.as_slice()).is_err());
    }

    #[test]
    fn endpoint_normalization_and_ssh_option_injection_guard() {
        assert_eq!(
            normalize_endpoint("mini-rex.example-tailnet.ts.net"),
            "https://mini-rex.example-tailnet.ts.net"
        );
        assert_eq!(normalize_endpoint("zero@cp0"), "ssh://zero@cp0");
        assert_eq!(
            derive_label_from_endpoint("https://moon-rex.example-tailnet.ts.net"),
            "moon"
        );
        assert_eq!(derive_label_from_endpoint("ssh://dev@m1:2222"), "m1");

        match parse_endpoint("ssh://dev@100.64.0.42:2222").unwrap() {
            ParsedEndpoint::Ssh {
                user_host,
                host_only,
                port,
            } => {
                assert_eq!(user_host, "dev@100.64.0.42");
                assert_eq!(host_only, "100.64.0.42");
                assert_eq!(port, Some(2222));
            }
            other => panic!("unexpected {other:?}"),
        }

        // Option injection in destination or username MUST be rejected!
        assert!(parse_endpoint("ssh://-oProxyCommand=sh").is_err());
        assert!(parse_endpoint("ssh://-F/tmp/cfg@m1").is_err());
        assert!(parse_endpoint("ssh://root@-oLocalCommand=id").is_err());
        assert!(parse_endpoint("ssh://@m1").is_err());
        assert!(validate_ssh_key_path("-oProxyCommand=id").is_err());
        assert!(validate_ssh_key_path("/tmp/id_ed25519\nbad").is_err());
        assert_eq!(
            validate_ssh_key_path("/tmp/id_paired_01").unwrap(),
            "/tmp/id_paired_01"
        );

        // Authority validation & IPv6 bracketing for HTTP CONNECT / TCP dial:
        assert_eq!(
            format_validated_authority("2001:db8::1", 443).unwrap(),
            "[2001:db8::1]:443"
        );
        assert_eq!(
            format_validated_authority("mini-rex.ts.net", 443).unwrap(),
            "mini-rex.ts.net:443"
        );
        assert!(format_validated_authority("bad.host\r\nInjected: 1", 443).is_err());
        assert!(format_validated_authority("not:valid:ipv6:zzzz", 443).is_err());
    }

    #[test]
    fn wake_pipe_sets_close_on_exec_and_interrupts_stalled_stream() {
        let (pipe, waker) = WakePipe::new().unwrap();
        let r_flags = unsafe { libc::fcntl(pipe.read_fd(), libc::F_GETFD) };
        let w_flags = unsafe { libc::fcntl(waker.write_fd.0, libc::F_GETFD) };
        assert_ne!(r_flags & libc::FD_CLOEXEC, 0);
        assert_ne!(w_flags & libc::FD_CLOEXEC, 0);

        // Verify `RexStream` aborts a stalled handshake read immediately when `stop` signals!
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (_s, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(500));
        });

        let stop = Arc::new(AtomicBool::new(false));
        let cancel = pipe.cancel_watch(stop.clone());
        let stop_trigger = stop.clone();
        let waker_trigger = waker.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(35));
            stop_trigger.store(true, Ordering::SeqCst);
            waker_trigger.wake();
        });

        let t0 = Instant::now();
        let res = open_rex_websocket(
            &format!("ws://{addr}"),
            None,
            0,
            "/api/control",
            "rex.control.v1",
            cancel,
        );
        assert!(res.is_err());
        assert!(
            t0.elapsed() < Duration::from_millis(350),
            "cancel took {:?}",
            t0.elapsed()
        );
        let _ = server.join();
    }

    #[test]
    fn nonblocking_bridge_exits_promptly_on_remote_eof_with_open_stdin() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.write_all(b"hello-from-remote").unwrap();
            // Remote closes immediately while local `in_fd` stays open!
        });

        let tcp = TcpStream::connect(addr).unwrap();
        let mut in_pipe = [-1 as libc::c_int; 2];
        let mut out_pipe = [-1 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(in_pipe.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(out_pipe.as_mut_ptr()) }, 0);

        let t0 = Instant::now();
        bridge_nonblocking_fds(in_pipe[0], out_pipe[1], tcp).unwrap();
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "bridge hung on open stdin: {:?}",
            t0.elapsed()
        );

        unsafe {
            libc::close(out_pipe[1]);
        }
        let mut received = [0u8; 64];
        let n = unsafe { libc::read(out_pipe[0], received.as_mut_ptr().cast(), received.len()) };
        assert_eq!(&received[..n as usize], b"hello-from-remote");
        unsafe {
            libc::close(in_pipe[0]);
            libc::close(in_pipe[1]);
            libc::close(out_pipe[0]);
        }
        server.join().unwrap();
    }

    #[test]
    fn socks5_client_handshakes_domain_atyp_cleanly() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut g = [0u8; 3];
            s.read_exact(&mut g).unwrap();
            assert_eq!(g, [0x05, 0x01, 0x00]);
            s.write_all(&[0x05, 0x00]).unwrap();
            let mut h = [0u8; 5];
            s.read_exact(&mut h).unwrap();
            assert_eq!(&h[..4], &[0x05, 0x01, 0x00, 0x03]);
            let dlen = h[4] as usize;
            let mut domain_and_port = vec![0u8; dlen + 2];
            s.read_exact(&mut domain_and_port).unwrap();
            assert_eq!(&domain_and_port[..dlen], b"mini-rex.ts.net");
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb])
                .unwrap();
            s.write_all(b"pong").unwrap();
        });

        let mut client =
            connect_socks5(addr, "mini-rex.ts.net", 443, Duration::from_secs(2)).unwrap();
        let mut out = [0u8; 4];
        client.read_exact(&mut out).unwrap();
        assert_eq!(&out, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn persisted_settings_isolates_cloud_credentials_across_providers() {
        let mut s = PersistedSettings {
            asr_provider: "openai".into(),
            asr_api_key: "sk-openai-legacy".into(),
            asr_endpoint: Some("https://openai-proxy.example".into()),
            ..PersistedSettings::default()
        };
        assert_eq!(s.effective_api_key(AsrProvider::Openai), "sk-openai-legacy");
        assert_eq!(s.effective_api_key(AsrProvider::Groq), "");
        assert_eq!(s.effective_endpoint(AsrProvider::Groq), None);

        // Freeze legacy owner before switching to Groq without a Groq key
        s.asr_key_provider = Some("openai".into());
        s.asr_provider = "groq".into();
        s.asr_provider_explicit = true;
        assert_eq!(s.provider_enum(), AsrProvider::Groq);
        assert!(!s.is_asr_configured());
        assert_eq!(s.effective_api_key(AsrProvider::Groq), "");

        // Switching back to OpenAI restores the OpenAI key
        s.asr_provider = "openai".into();
        assert!(s.is_asr_configured());
        assert_eq!(s.effective_api_key(AsrProvider::Openai), "sk-openai-legacy");
    }
}
