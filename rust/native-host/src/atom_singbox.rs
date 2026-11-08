//! atom fork: the sing-box configuration (atom `docs/design.md` §6) and its
//! transactional application.
//!
//! atom generates the whole file; nobody edits it. Applying a new file:
//! generate → `sing-box check` → atomic write → the reload command (a
//! systemd unit reload, which sends SIGHUP) → confirm through the Clash API.
//! Every application writes a new random Clash API secret, so an answer with
//! the new secret proves the new configuration runs (the old instance does
//! not know it). Any failure after the write puts the old file back and
//! reloads again.
//!
//! The work is blocking (a child process, a local HTTP exchange) and runs on
//! the blocking pool with owned data; one application at a time in the whole
//! process ([`ApplyGuard`]).

use std::io::{Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::atom_proxy::{FINAL, GroupKind, ProxyState};
use crate::atom_rules::Action;

pub(crate) const CONFIG_FILE: &str = "config.json";
const NEXT_FILE: &str = "config.json.next";
pub(crate) const DNS_IN: &str = "dns-in";
pub(crate) const MIXED_IN: &str = "mixed-in";
const BLOCK: &str = "block";
const DIRECT: &str = "direct";
const CHECK_TIMEOUT: Duration = Duration::from_secs(60);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 3 } else { 20 });
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Where and how sing-box runs (the `singbox` section of the `atom_rules`
/// arguments; not user settings).
#[derive(Clone, Debug)]
pub(crate) struct Host {
    pub(crate) binary: PathBuf,
    /// The working directory: `config.json`, `cache.db`.
    pub(crate) dir: PathBuf,
    /// Run after writing the file: reload (or start) the service.
    pub(crate) reload: Vec<String>,
    pub(crate) clash_api: SocketAddr,
    /// The FakeIP DNS inbound AtomDNS forwards to (`nocnfake`).
    pub(crate) dns_in: SocketAddr,
    /// AtomDNS itself, for the mixed inbound's `resolve`.
    pub(crate) atomdns: SocketAddr,
    pub(crate) redirect_port: u16,
    pub(crate) tproxy_port: u16,
    /// The AtomDNS upstream group the default resolver comes from.
    pub(crate) resolver_group: String,
}

impl Host {
    /// The ports the mixed inbound may not take.
    pub(crate) fn reserved_ports(&self) -> Vec<u16> {
        vec![
            self.dns_in.port(),
            self.atomdns.port(),
            self.redirect_port,
            self.tproxy_port,
            self.clash_api.port(),
        ]
    }

    pub(crate) fn config_path(&self) -> PathBuf {
        self.dir.join(CONFIG_FILE)
    }
}

/// One IP rule (design §4.6), in table order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IpRule {
    pub(crate) cidrs: Vec<String>,
    pub(crate) action: Action,
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

fn members_or_block(members: &[String]) -> Vec<String> {
    if members.is_empty() {
        vec![BLOCK.to_owned()]
    } else {
        members.to_vec()
    }
}

fn listen(address: IpAddr) -> String {
    address.to_string()
}

/// The whole configuration. Deterministic: the same inputs give the same
/// bytes (`serde_json` maps are sorted), so a file can be compared with
/// what would be generated now.
pub(crate) fn generate(
    host: &Host,
    state: &ProxyState,
    ip_rules: &[IpRule],
    resolver: &str,
    secret: &str,
) -> Result<Vec<u8>, String> {
    let (resolver_kind, resolver_ip, resolver_port) = crate::atom_proxy::parse_resolver(resolver)?;
    let mut outbounds = Vec::new();
    for node in &state.nodes {
        let mut outbound = node.outbound.clone();
        outbound.insert("tag".into(), json!(node.id));
        outbounds.push(Value::Object(outbound));
    }
    for group in &state.groups {
        let mut outbound = Map::new();
        outbound.insert("tag".into(), json!(group.id));
        outbound.insert("outbounds".into(), json!(members_or_block(&group.members)));
        match group.kind {
            GroupKind::Selector => {
                outbound.insert("type".into(), json!("selector"));
                if !group.selected.is_empty() {
                    outbound.insert("default".into(), json!(group.selected));
                }
            }
            GroupKind::Urltest => {
                outbound.insert("type".into(), json!("urltest"));
                outbound.insert(
                    "url".into(),
                    json!(
                        group
                            .url
                            .as_deref()
                            .unwrap_or(crate::atom_proxy::DEFAULT_URL)
                    ),
                );
                outbound.insert(
                    "interval".into(),
                    json!(
                        group
                            .interval
                            .as_deref()
                            .unwrap_or(crate::atom_proxy::DEFAULT_INTERVAL)
                    ),
                );
                outbound.insert(
                    "tolerance".into(),
                    json!(
                        group
                            .tolerance
                            .unwrap_or(crate::atom_proxy::DEFAULT_TOLERANCE)
                    ),
                );
            }
        }
        outbounds.push(Value::Object(outbound));
    }
    let final_group = &state.final_group;
    let mut final_outbound = Map::new();
    final_outbound.insert("type".into(), json!("selector"));
    final_outbound.insert("tag".into(), json!(FINAL));
    final_outbound.insert(
        "outbounds".into(),
        json!(members_or_block(&final_group.members)),
    );
    if !final_group.selected.is_empty() {
        final_outbound.insert("default".into(), json!(final_group.selected));
    }
    outbounds.push(Value::Object(final_outbound));
    outbounds.push(json!({"type": "direct", "tag": DIRECT}));
    outbounds.push(json!({"type": "block", "tag": BLOCK}));

    let mut rules = vec![
        json!({"inbound": [DNS_IN], "action": "hijack-dns"}),
        // The mixed inbound asks AtomDNS; a FakeIP answer is decided by the
        // binding (the sing-box patch), the rest by the rules below.
        json!({
            "inbound": [MIXED_IN],
            "action": "resolve",
            "server": "atomdns",
            "disable_cache": true
        }),
    ];
    for rule in ip_rules {
        rules.push(match &rule.action {
            Action::Proxy { group_id } => {
                json!({"ip_cidr": rule.cidrs, "action": "route", "outbound": group_id})
            }
            Action::Direct => json!({"ip_cidr": rule.cidrs, "action": "route", "outbound": DIRECT}),
            Action::Block => json!({"ip_cidr": rule.cidrs, "action": "reject"}),
        });
    }
    // A name AtomDNS answered with a real address goes direct; an address
    // the client sent itself falls to Final.
    rules.push(json!({
        "inbound": [MIXED_IN],
        "domain_regex": ["."],
        "action": "route",
        "outbound": DIRECT
    }));

    let config = json!({
        "log": {"level": "info", "timestamp": true},
        "dns": {
            "servers": [
                {"type": "fakeip", "tag": "fakeip", "inet4_range": state.settings.fakeip_range},
                {"type": resolver_kind, "tag": "resolver", "server": resolver_ip.to_string(), "server_port": resolver_port},
                {"type": "udp", "tag": "atomdns", "server": host.atomdns.ip().to_string(), "server_port": host.atomdns.port()}
            ],
            "rules": [{"query_type": ["A", "AAAA"], "server": "fakeip"}],
            "final": "resolver"
        },
        "inbounds": [
            {"type": "direct", "tag": DNS_IN, "listen": listen(host.dns_in.ip()), "listen_port": host.dns_in.port()},
            {"type": "redirect", "tag": "redirect-in", "listen": "0.0.0.0", "listen_port": host.redirect_port},
            {"type": "tproxy", "tag": "tproxy-in", "listen": "0.0.0.0", "listen_port": host.tproxy_port, "network": "udp"},
            {"type": "mixed", "tag": MIXED_IN, "listen": "0.0.0.0", "listen_port": state.settings.mixed_port}
        ],
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": FINAL,
            // Node names never go through the FakeIP DNS rules.
            "default_domain_resolver": "resolver"
        },
        "experimental": {
            "cache_file": {"enabled": true, "path": "cache.db", "store_fakeip": true},
            "clash_api": {"external_controller": host.clash_api.to_string(), "secret": secret}
        }
    });
    let mut bytes = serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// The Clash API secret of a configuration file.
pub(crate) fn secret_of(bytes: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    value
        .pointer("/experimental/clash_api/secret")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

pub(crate) fn new_secret() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        bytes = nanos.to_be_bytes();
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The first plain (UDP/TCP to an address) entry of an AtomDNS upstream
/// group, else the dial address of the first entry that has one.
pub(crate) fn default_resolver(
    entries: &[crate::config::settings::UpstreamEntry],
) -> Option<String> {
    let enabled = || entries.iter().filter(|entry| entry.enabled);
    enabled()
        .find(|entry| crate::atom_proxy::parse_resolver(&entry.addr).is_ok())
        .map(|entry| entry.addr.clone())
        .or_else(|| {
            enabled()
                .find(|entry| entry.dial_addr.parse::<IpAddr>().is_ok())
                .map(|entry| format!("udp://{}", entry.dial_addr))
        })
}

/// The fallback when no domestic upstream has an address.
pub(crate) const FALLBACK_RESOLVER: &str = "udp://223.5.5.5";

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

static APPLYING: AtomicBool = AtomicBool::new(false);

/// Held while one application runs; there is only one sing-box.
pub(crate) struct ApplyGuard(());

impl ApplyGuard {
    pub(crate) fn try_begin() -> Option<Self> {
        APPLYING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(Self(()))
    }

    pub(crate) fn busy() -> bool {
        APPLYING.load(Ordering::Acquire)
    }
}

impl Drop for ApplyGuard {
    fn drop(&mut self) {
        APPLYING.store(false, Ordering::Release);
    }
}

/// Runs a command with a deadline; the error carries the end of its output.
fn run(command: &[String], timeout: Duration, what: &str) -> Result<(), String> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| format!("{what}: 没有配置命令"))?;
    let output_file = std::env::temp_dir().join(format!(
        "atom-singbox-{}-{}.out",
        std::process::id(),
        new_secret()
    ));
    let output = std::fs::File::create(&output_file).map_err(|error| format!("{what}: {error}"))?;
    let errors = output
        .try_clone()
        .map_err(|error| format!("{what}: {error}"))?;
    let result = (|| {
        let mut child = std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::null())
            .stdout(output)
            .stderr(errors)
            .spawn()
            .map_err(|error| format!("{what}: 启动 {program} 失败: {error}"))?;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|error| format!("{what}: {error}"))?
            {
                if status.success() {
                    return Ok(());
                }
                let text = std::fs::read(&output_file).unwrap_or_default();
                let text = String::from_utf8_lossy(&text);
                let tail: String = text
                    .trim()
                    .chars()
                    .rev()
                    .take(600)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                return Err(format!("{what}失败（{status}）: {tail}"));
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{what}超时（{} 秒）", timeout.as_secs()));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })();
    let _ = std::fs::remove_file(&output_file);
    result
}

/// `sing-box check` on the candidate (written next to the live file).
pub(crate) fn check(host: &Host, bytes: &[u8]) -> Result<(), String> {
    // Nothing is written where sing-box is not installed.
    if !host.binary.is_file() {
        return Err(format!("找不到 sing-box 程序 {}", host.binary.display()));
    }
    let next = host.dir.join(NEXT_FILE);
    crate::runtime_snapshot::write_durably(&next, bytes)
        .map_err(|error| format!("写入 {} 失败: {error}", next.display()))?;
    let command = vec![
        host.binary.display().to_string(),
        "check".to_owned(),
        "-D".to_owned(),
        host.dir.display().to_string(),
        "-c".to_owned(),
        next.display().to_string(),
    ];
    let result = run(&command, CHECK_TIMEOUT, "sing-box check ");
    if result.is_err() {
        let _ = std::fs::remove_file(&next);
    }
    result
}

/// Replaces the live file (the checked candidate is renamed over it, or the
/// given bytes written when restoring).
fn install(host: &Host, bytes: Option<&[u8]>) -> Result<(), String> {
    let live = host.config_path();
    match bytes {
        Some(bytes) => crate::runtime_snapshot::write_durably(&live, bytes),
        None => match std::fs::remove_file(&live) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        },
    }
    .map_err(|error| format!("写入 {} 失败: {error}", live.display()))
}

fn reload(host: &Host) -> Result<(), String> {
    run(&host.reload, RELOAD_TIMEOUT, "重载 sing-box ")
}

/// Waits until the Clash API answers `/proxies` with `secret` and lists
/// Final.
fn confirm(host: &Host, secret: &str) -> Result<(), String> {
    let deadline = Instant::now() + CONFIRM_TIMEOUT;
    let mut last;
    loop {
        match clash(host.clash_api, secret, "GET", "/proxies", None) {
            Ok((200, body)) => {
                let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                if value.pointer(&format!("/proxies/{FINAL}")).is_some() {
                    return Ok(());
                }
                last = "Clash API 里没有 Final".to_owned();
            }
            Ok((status, _)) => last = format!("Clash API 返回 {status}"),
            Err(error) => last = error,
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{} 秒内没有确认新配置生效: {last}",
                CONFIRM_TIMEOUT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Why an application failed: `sing-box check` refused the candidate
/// (nothing was touched), or a later step failed (the old file is back).
#[derive(Debug)]
pub(crate) enum ApplyError {
    Check(String),
    Runtime(String),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Check(message) | Self::Runtime(message) => f.write_str(message),
        }
    }
}

/// Applies `bytes` (secret `secret`): check, write, reload, confirm; on a
/// failure after the write, the old file (or none) is restored and reloaded.
pub(crate) fn apply_blocking(host: &Host, bytes: &[u8], secret: &str) -> Result<(), ApplyError> {
    check(host, bytes).map_err(ApplyError::Check)?;
    let live = host.config_path();
    let old = match std::fs::read(&live) {
        Ok(old) => Some(old),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            let _ = std::fs::remove_file(host.dir.join(NEXT_FILE));
            return Err(ApplyError::Runtime(format!(
                "读取 {} 失败: {error}",
                live.display()
            )));
        }
    };
    std::fs::rename(host.dir.join(NEXT_FILE), &live)
        .map_err(|error| ApplyError::Runtime(format!("替换 {} 失败: {error}", live.display())))?;
    let failure = match reload(host).and_then(|()| confirm(host, secret)) {
        Ok(()) => return Ok(()),
        Err(failure) => failure,
    };
    Err(ApplyError::Runtime(format!(
        "{failure}；{}",
        rollback(host, old.as_deref())
    )))
}

/// Puts `old` back after a failed application and says how that went.
pub(crate) fn rollback(host: &Host, old: Option<&[u8]>) -> String {
    if let Err(error) = install(host, old) {
        return format!("回滚失败: {error}");
    }
    let Some(old) = old else {
        // There was no configuration: nothing to bring back up.
        let _ = reload(host);
        return "已删除新配置（之前没有配置）".to_owned();
    };
    match reload(host).and_then(|()| match secret_of(old) {
        Some(secret) => confirm(host, &secret),
        None => Ok(()),
    }) {
        Ok(()) => "已回滚到旧配置".to_owned(),
        Err(error) => format!("已写回旧配置，但重载后没有确认: {error}"),
    }
}

// ---------------------------------------------------------------------------
// Clash API
// ---------------------------------------------------------------------------

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|pair| pair == b"\r\n")
            .ok_or("chunked 应答不完整")?;
        let size_text = std::str::from_utf8(&body[..line_end]).map_err(|_| "chunk 长度无效")?;
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| "chunk 长度无效")?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            return Err("chunked 应答不完整".into());
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

/// One HTTP/1.1 exchange with the Clash API; `(status, body)`.
pub(crate) fn clash(
    address: SocketAddr,
    secret: &str,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    let mut stream = TcpStream::connect_timeout(&address, HTTP_TIMEOUT)
        .map_err(|error| format!("连接 Clash API {address} 失败: {error}"))?;
    stream.set_read_timeout(Some(HTTP_TIMEOUT * 4)).ok();
    stream.set_write_timeout(Some(HTTP_TIMEOUT)).ok();
    let body = body.unwrap_or(b"");
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {secret}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.write_all(body))
        .map_err(|error| format!("Clash API 请求失败: {error}"))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("Clash API 应答失败: {error}"))?;
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("Clash API 应答无效")?;
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or("Clash API 应答无效")?;
    let payload = &response[split + 4..];
    let chunked = head.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        line.starts_with("transfer-encoding:") && line.contains("chunked")
    });
    let payload = if chunked {
        decode_chunked(payload)?
    } else {
        payload.to_vec()
    };
    Ok((status, payload))
}

fn query_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// Switches a selector (a group or Final) at runtime.
pub(crate) fn select(host: &Host, secret: &str, tag: &str, member: &str) -> Result<(), String> {
    let body = serde_json::to_vec(&json!({ "name": member })).unwrap_or_default();
    match clash(
        host.clash_api,
        secret,
        "PUT",
        &format!("/proxies/{}", query_encode(tag)),
        Some(&body),
    )? {
        (200..=299, _) => Ok(()),
        (status, body) => Err(format!(
            "Clash API 切换失败（{status}）: {}",
            String::from_utf8_lossy(&body).trim()
        )),
    }
}

/// Tests every member of a group: `{member: delay ms}` (failed members are
/// left out by sing-box).
pub(crate) fn delay(
    host: &Host,
    secret: &str,
    tag: &str,
    url: &str,
    timeout_ms: u32,
) -> Result<Value, String> {
    let path = format!(
        "/group/{}/delay?url={}&timeout={timeout_ms}",
        query_encode(tag),
        query_encode(url)
    );
    match clash(host.clash_api, secret, "GET", &path, None)? {
        (200, body) => serde_json::from_slice(&body).map_err(|error| error.to_string()),
        (status, body) => Err(format!(
            "Clash API 测速失败（{status}）: {}",
            String::from_utf8_lossy(&body).trim()
        )),
    }
}

/// Tests one node: `{"delay": ms}`. A node that fails the test is an
/// error (sing-box answers 503 or 504 with the reason).
pub(crate) fn node_delay(
    host: &Host,
    secret: &str,
    tag: &str,
    url: &str,
    timeout_ms: u32,
) -> Result<Value, String> {
    let path = format!(
        "/proxies/{}/delay?url={}&timeout={timeout_ms}",
        query_encode(tag),
        query_encode(url)
    );
    match clash(host.clash_api, secret, "GET", &path, None)? {
        (200, body) => serde_json::from_slice(&body).map_err(|error| error.to_string()),
        (status, body) => Err(format!(
            "测速失败（{status}）: {}",
            String::from_utf8_lossy(&body).trim()
        )),
    }
}

/// sing-box's version through the Clash API, if it answers.
pub(crate) fn version(host: &Host, secret: &str) -> Option<String> {
    let (status, body) = clash(host.clash_api, secret, "GET", "/version", None).ok()?;
    if status != 200 {
        return None;
    }
    let value: Value = serde_json::from_slice(&body).ok()?;
    value
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

pub(crate) fn read_live(host: &Host) -> Option<Vec<u8>> {
    std::fs::read(host.config_path()).ok()
}

#[cfg(test)]
#[path = "atom_singbox_tests.rs"]
pub(crate) mod tests;
