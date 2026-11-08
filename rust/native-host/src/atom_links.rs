//! atom fork: node import (design §5.1). Three inputs, one output, the
//! sing-box outbound (without `tag`) and a display name:
//!
//! - `json`: one sing-box outbound, an array of them, or a whole sing-box
//!   configuration (its proxy outbounds are taken, groups and the like
//!   skipped). The `tag` becomes the name.
//! - `yaml`: Clash/mihomo `proxies` (a whole configuration, the list, or one
//!   proxy).
//! - `link`: share links, one per line: `vless://`, `vmess://`, `trojan://`,
//!   `ss://`, `hysteria2://` (`hy2://`), `tuic://`, `anytls://`, `socks://`
//!   (`socks5://`, `socks5h://`).
//!
//! An import is all or nothing: the first entry that cannot be converted is
//! the error, with its position.

use serde_json::{Map, Value, json};

pub(crate) type Imported = (String, Map<String, Value>);

fn obj(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

// ---------------------------------------------------------------------------
// Small decoders
// ---------------------------------------------------------------------------

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Standard or URL-safe base64, padding optional.
fn base64_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let cleaned: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let trimmed = cleaned.trim_end_matches('=');
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(trimmed)
        .ok()
}

fn base64_text(value: &str) -> Option<String> {
    String::from_utf8(base64_decode(value)?).ok()
}

// ---------------------------------------------------------------------------
// Shared sing-box pieces
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Tls {
    enabled: bool,
    server_name: String,
    insecure: bool,
    alpn: Vec<String>,
    fingerprint: String,
    reality_key: String,
    reality_short_id: String,
    disable_sni: bool,
}

impl Tls {
    fn value(&self) -> Option<Value> {
        if !self.enabled {
            return None;
        }
        let mut tls = Map::new();
        tls.insert("enabled".into(), json!(true));
        if !self.server_name.is_empty() {
            tls.insert("server_name".into(), json!(self.server_name));
        }
        if self.insecure {
            tls.insert("insecure".into(), json!(true));
        }
        if self.disable_sni {
            tls.insert("disable_sni".into(), json!(true));
        }
        if !self.alpn.is_empty() {
            tls.insert("alpn".into(), json!(self.alpn));
        }
        // REALITY needs uTLS; sing-box refuses it without.
        let fingerprint = if self.fingerprint.is_empty() && !self.reality_key.is_empty() {
            "chrome"
        } else {
            self.fingerprint.as_str()
        };
        if !fingerprint.is_empty() {
            tls.insert(
                "utls".into(),
                json!({"enabled": true, "fingerprint": fingerprint}),
            );
        }
        if !self.reality_key.is_empty() {
            let mut reality = Map::new();
            reality.insert("enabled".into(), json!(true));
            reality.insert("public_key".into(), json!(self.reality_key));
            if !self.reality_short_id.is_empty() {
                reality.insert("short_id".into(), json!(self.reality_short_id));
            }
            tls.insert("reality".into(), Value::Object(reality));
        }
        Some(Value::Object(tls))
    }
}

fn alpn_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

/// A V2Ray transport: `ws`, `grpc`, `httpupgrade`, `http` (h2); plain TCP
/// has none.
fn transport(kind: &str, host: &str, path: &str, service: &str) -> Result<Option<Value>, String> {
    Ok(match kind {
        "" | "tcp" | "raw" | "none" => None,
        "ws" | "websocket" => {
            let mut ws = Map::new();
            ws.insert("type".into(), json!("ws"));
            if !path.is_empty() {
                ws.insert("path".into(), json!(path));
            }
            if !host.is_empty() {
                ws.insert("headers".into(), json!({"Host": host}));
            }
            Some(Value::Object(ws))
        }
        "grpc" => Some(json!({"type": "grpc", "service_name": service})),
        "httpupgrade" => {
            let mut upgrade = Map::new();
            upgrade.insert("type".into(), json!("httpupgrade"));
            if !host.is_empty() {
                upgrade.insert("host".into(), json!(host));
            }
            if !path.is_empty() {
                upgrade.insert("path".into(), json!(path));
            }
            Some(Value::Object(upgrade))
        }
        "h2" | "http" => {
            let mut http = Map::new();
            http.insert("type".into(), json!("http"));
            if !host.is_empty() {
                http.insert("host".into(), json!(alpn_list(host)));
            }
            if !path.is_empty() {
                http.insert("path".into(), json!(path));
            }
            Some(Value::Object(http))
        }
        other => return Err(format!("不支持的传输方式 `{other}`")),
    })
}

fn base(kind: &str, server: &str, port: u16) -> Result<Map<String, Value>, String> {
    let server = server.trim().trim_start_matches('[').trim_end_matches(']');
    if server.is_empty() {
        return Err("缺少服务器地址".into());
    }
    if port == 0 {
        return Err("缺少端口".into());
    }
    let mut outbound = Map::new();
    outbound.insert("type".into(), json!(kind));
    outbound.insert("server".into(), json!(server));
    outbound.insert("server_port".into(), json!(port));
    Ok(outbound)
}

fn put(outbound: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        outbound.insert(key.into(), value);
    }
}

fn default_name(outbound: &Map<String, Value>) -> String {
    let kind = outbound
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("node");
    let server = outbound.get("server").and_then(Value::as_str).unwrap_or("");
    let port = outbound
        .get("server_port")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if server.is_empty() {
        kind.to_owned()
    } else {
        format!("{kind} {server}:{port}")
    }
}

/// A display name: trimmed, control characters removed, at most 64 chars.
fn clean_name(name: &str, outbound: &Map<String, Value>) -> String {
    let name: String = name
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(64)
        .collect();
    let name = name.trim().to_owned();
    if name.is_empty() {
        default_name(outbound)
    } else {
        name
    }
}

// ---------------------------------------------------------------------------
// Share links
// ---------------------------------------------------------------------------

struct Link {
    user: String,
    password: String,
    host: String,
    port: u16,
    query: Vec<(String, String)>,
    name: String,
}

impl Link {
    fn get(&self, key: &str) -> &str {
        self.query
            .iter()
            .find(|(name, _)| name == key)
            .map_or("", |(_, value)| value.as_str())
    }

    fn any(&self, keys: &[&str]) -> &str {
        keys.iter()
            .map(|key| self.get(key))
            .find(|value| !value.is_empty())
            .unwrap_or("")
    }

    fn flag(&self, keys: &[&str]) -> bool {
        matches!(self.any(keys), "1" | "true" | "True" | "TRUE")
    }

    fn tls_common(&self, enabled: bool) -> Tls {
        Tls {
            enabled,
            server_name: self.any(&["sni", "peer", "servername"]).to_owned(),
            insecure: self.flag(&[
                "allowInsecure",
                "insecure",
                "allow_insecure",
                "skip-cert-verify",
            ]),
            alpn: alpn_list(self.get("alpn")),
            fingerprint: self.get("fp").to_owned(),
            ..Tls::default()
        }
    }
}

fn parse_link_url(link: &str) -> Result<Link, String> {
    let parsed = url::Url::parse(link).map_err(|error| format!("链接无法解析: {error}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "链接缺少服务器地址".to_owned())?
        .to_owned();
    let port = parsed.port().ok_or_else(|| "链接缺少端口".to_owned())?;
    Ok(Link {
        user: percent_decode(parsed.username()),
        password: percent_decode(parsed.password().unwrap_or("")),
        host,
        port,
        query: parsed
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
        name: percent_decode(parsed.fragment().unwrap_or("")),
    })
}

fn vless_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    if link.user.is_empty() {
        return Err("vless 链接缺少 uuid".into());
    }
    let mut outbound = base("vless", &link.host, link.port)?;
    outbound.insert("uuid".into(), json!(link.user));
    let flow = link.get("flow");
    if !flow.is_empty() {
        outbound.insert("flow".into(), json!(flow));
    }
    let security = link.get("security");
    let mut tls = link.tls_common(matches!(security, "tls" | "reality" | "xtls"));
    if security == "reality" {
        tls.reality_key = link.get("pbk").to_owned();
        tls.reality_short_id = link.get("sid").to_owned();
        if tls.reality_key.is_empty() {
            return Err("reality 链接缺少 pbk".into());
        }
    }
    put(&mut outbound, "tls", tls.value());
    let kind = link.get("type");
    let path = link.get("path");
    let service = link.any(&["serviceName", "service_name"]);
    put(
        &mut outbound,
        "transport",
        transport(
            kind,
            link.get("host"),
            path,
            if service.is_empty() { path } else { service },
        )?,
    );
    outbound.insert("packet_encoding".into(), json!("xudp"));
    Ok((clean_name(&link.name, &outbound), outbound))
}

fn trojan_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    if link.user.is_empty() {
        return Err("trojan 链接缺少密码".into());
    }
    let mut outbound = base("trojan", &link.host, link.port)?;
    outbound.insert("password".into(), json!(link.user));
    // TLS unless explicitly off.
    let security = link.get("security");
    let mut tls = link.tls_common(security != "none");
    if security == "reality" {
        tls.reality_key = link.get("pbk").to_owned();
        tls.reality_short_id = link.get("sid").to_owned();
    }
    put(&mut outbound, "tls", tls.value());
    let path = link.get("path");
    let service = link.any(&["serviceName", "service_name"]);
    put(
        &mut outbound,
        "transport",
        transport(
            link.get("type"),
            link.get("host"),
            path,
            if service.is_empty() { path } else { service },
        )?,
    );
    Ok((clean_name(&link.name, &outbound), outbound))
}

fn hysteria2_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    let password = if link.password.is_empty() {
        link.user.clone()
    } else {
        format!("{}:{}", link.user, link.password)
    };
    let mut outbound = base("hysteria2", &link.host, link.port)?;
    if !password.is_empty() {
        outbound.insert("password".into(), json!(password));
    }
    let obfs = link.get("obfs");
    if !obfs.is_empty() && obfs != "none" {
        outbound.insert(
            "obfs".into(),
            json!({"type": obfs, "password": link.get("obfs-password")}),
        );
    }
    put(&mut outbound, "tls", link.tls_common(true).value());
    Ok((clean_name(&link.name, &outbound), outbound))
}

fn tuic_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    if link.user.is_empty() {
        return Err("tuic 链接缺少 uuid".into());
    }
    let mut outbound = base("tuic", &link.host, link.port)?;
    outbound.insert("uuid".into(), json!(link.user));
    if !link.password.is_empty() {
        outbound.insert("password".into(), json!(link.password));
    }
    let congestion = link.any(&["congestion_control", "congestion-control"]);
    if !congestion.is_empty() {
        outbound.insert("congestion_control".into(), json!(congestion));
    }
    let relay = link.any(&["udp_relay_mode", "udp-relay-mode"]);
    if !relay.is_empty() {
        outbound.insert("udp_relay_mode".into(), json!(relay));
    }
    let mut tls = link.tls_common(true);
    tls.disable_sni = link.flag(&["disable_sni", "disable-sni"]);
    put(&mut outbound, "tls", tls.value());
    Ok((clean_name(&link.name, &outbound), outbound))
}

fn anytls_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    if link.user.is_empty() {
        return Err("anytls 链接缺少密码".into());
    }
    let mut outbound = base("anytls", &link.host, link.port)?;
    outbound.insert("password".into(), json!(link.user));
    put(&mut outbound, "tls", link.tls_common(true).value());
    Ok((clean_name(&link.name, &outbound), outbound))
}

/// `socks://`, `socks5://`, `socks5h://`: a SOCKS5 outbound (the name is
/// resolved by the server either way). The userinfo is `user:pass`, or
/// base64 of it (V2RayN).
fn socks_link(link: &str) -> Result<Imported, String> {
    let link = parse_link_url(link)?;
    let (username, password) = if link.password.is_empty() && !link.user.is_empty() {
        match base64_text(&link.user).and_then(|text| {
            text.split_once(':')
                .map(|(user, pass)| (user.to_owned(), pass.to_owned()))
        }) {
            Some(pair) => pair,
            None => (link.user.clone(), String::new()),
        }
    } else {
        (link.user.clone(), link.password.clone())
    };
    let mut outbound = base("socks", &link.host, link.port)?;
    outbound.insert("version".into(), json!("5"));
    if !username.is_empty() {
        outbound.insert("username".into(), json!(username));
    }
    if !password.is_empty() {
        outbound.insert("password".into(), json!(password));
    }
    Ok((clean_name(&link.name, &outbound), outbound))
}

/// `vmess://` + base64 of the V2RayN JSON (`add`, `port`, `id`, `aid`,
/// `scy`, `net`, `host`, `path`, `tls`, `sni`, `alpn`, `fp`, `ps`).
fn vmess_link(link: &str) -> Result<Imported, String> {
    let body = link.trim_start_matches("vmess://");
    let body = body.split('#').next().unwrap_or("");
    let text = base64_text(body).ok_or_else(|| "vmess 链接不是 base64".to_owned())?;
    let value: Value =
        serde_json::from_str(&text).map_err(|error| format!("vmess 链接的 JSON 无效: {error}"))?;
    let field = |key: &str| -> String {
        match value.get(key) {
            Some(Value::String(text)) => text.trim().to_owned(),
            Some(Value::Number(number)) => number.to_string(),
            _ => String::new(),
        }
    };
    let port: u16 = field("port")
        .parse()
        .map_err(|_| "vmess 端口无效".to_owned())?;
    let mut outbound = base("vmess", &field("add"), port)?;
    let uuid = field("id");
    if uuid.is_empty() {
        return Err("vmess 链接缺少 id".into());
    }
    outbound.insert("uuid".into(), json!(uuid));
    let security = field("scy");
    outbound.insert(
        "security".into(),
        json!(if security.is_empty() {
            "auto"
        } else {
            security.as_str()
        }),
    );
    let alter: u64 = field("aid").parse().unwrap_or(0);
    if alter != 0 {
        outbound.insert("alter_id".into(), json!(alter));
    }
    let tls = Tls {
        enabled: field("tls") == "tls",
        server_name: field("sni"),
        alpn: alpn_list(&field("alpn")),
        fingerprint: field("fp"),
        ..Tls::default()
    };
    put(&mut outbound, "tls", tls.value());
    let net = field("net");
    let path = field("path");
    put(
        &mut outbound,
        "transport",
        transport(&net, &field("host"), &path, &path)?,
    );
    outbound.insert("packet_encoding".into(), json!("xudp"));
    Ok((clean_name(&field("ps"), &outbound), outbound))
}

/// `ss://`: SIP002 (`ss://base64(method:password)@host:port/?plugin=#name`,
/// or the userinfo percent-encoded in clear for 2022 ciphers) and the
/// legacy `ss://base64(method:password@host:port)#name`.
fn ss_link(link: &str) -> Result<Imported, String> {
    let rest = &link["ss://".len()..];
    let (rest, name) = match rest.split_once('#') {
        Some((rest, name)) => (rest, percent_decode(name)),
        None => (rest, String::new()),
    };
    let sip002 = if rest.contains('@') {
        rest.to_owned()
    } else {
        let (encoded, tail) = match rest.find(['/', '?']) {
            Some(at) => rest.split_at(at),
            None => (rest, ""),
        };
        let decoded = base64_text(encoded).ok_or_else(|| "ss 链接不是 base64".to_owned())?;
        let (userinfo, server) = decoded
            .rsplit_once('@')
            .ok_or_else(|| "ss 链接缺少服务器地址".to_owned())?;
        // Re-encode the clear userinfo so the URL parser keeps it intact.
        let userinfo: String = userinfo
            .bytes()
            .map(|byte| {
                if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) || byte == b':' {
                    (byte as char).to_string()
                } else {
                    format!("%{byte:02X}")
                }
            })
            .collect();
        format!("{userinfo}@{server}{tail}")
    };
    let parsed = parse_link_url(&format!("ss://{sip002}"))?;
    let (method, password) = if parsed.password.is_empty() {
        // base64(method:password) in the user part.
        let decoded =
            base64_text(&parsed.user).ok_or_else(|| "ss 链接的用户信息无效".to_owned())?;
        let (method, password) = decoded
            .split_once(':')
            .ok_or_else(|| "ss 链接缺少加密方式或密码".to_owned())?;
        (method.to_owned(), password.to_owned())
    } else {
        (parsed.user.clone(), parsed.password.clone())
    };
    if method.is_empty() || password.is_empty() {
        return Err("ss 链接缺少加密方式或密码".into());
    }
    let mut outbound = base("shadowsocks", &parsed.host, parsed.port)?;
    outbound.insert("method".into(), json!(method));
    outbound.insert("password".into(), json!(password));
    let plugin = parsed.get("plugin");
    if !plugin.is_empty() {
        let (plugin, options) = plugin.split_once(';').unwrap_or((plugin, ""));
        let plugin = match plugin {
            "obfs-local" | "simple-obfs" => "obfs-local",
            "v2ray-plugin" => "v2ray-plugin",
            other => return Err(format!("不支持的 ss 插件 `{other}`")),
        };
        outbound.insert("plugin".into(), json!(plugin));
        if !options.is_empty() {
            outbound.insert("plugin_opts".into(), json!(options));
        }
    }
    let name = if name.is_empty() {
        parsed.name.clone()
    } else {
        name
    };
    Ok((clean_name(&name, &outbound), outbound))
}

pub(crate) fn parse_link(link: &str) -> Result<Imported, String> {
    let link = link.trim();
    let scheme = link
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase())
        .ok_or_else(|| "不是分享链接".to_owned())?;
    match scheme.as_str() {
        "vless" => vless_link(link),
        "vmess" => vmess_link(link),
        "trojan" => trojan_link(link),
        "ss" => ss_link(link),
        "hysteria2" | "hy2" => hysteria2_link(link),
        "tuic" => tuic_link(link),
        "anytls" => anytls_link(link),
        "socks" | "socks5" | "socks5h" => socks_link(link),
        other => Err(format!("不支持的链接协议 `{other}://`")),
    }
}

// ---------------------------------------------------------------------------
// Clash / mihomo proxies
// ---------------------------------------------------------------------------

fn text(proxy: &Map<String, Value>, key: &str) -> String {
    match proxy.get(key) {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn truthy(proxy: &Map<String, Value>, key: &str) -> bool {
    matches!(proxy.get(key), Some(Value::Bool(true)))
        || matches!(text(proxy, key).as_str(), "true" | "1")
}

fn strings(proxy: &Map<String, Value>, key: &str) -> Vec<String> {
    match proxy.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Some(Value::String(value)) => alpn_list(value),
        _ => Vec::new(),
    }
}

fn section(proxy: &Map<String, Value>, key: &str) -> Map<String, Value> {
    proxy
        .get(key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn clash_tls(proxy: &Map<String, Value>, enabled: bool) -> Tls {
    let reality = section(proxy, "reality-opts");
    let mut server_name = text(proxy, "servername");
    if server_name.is_empty() {
        server_name = text(proxy, "sni");
    }
    Tls {
        enabled,
        server_name,
        insecure: truthy(proxy, "skip-cert-verify"),
        alpn: strings(proxy, "alpn"),
        fingerprint: text(proxy, "client-fingerprint"),
        reality_key: text(&reality, "public-key"),
        reality_short_id: text(&reality, "short-id"),
        disable_sni: truthy(proxy, "disable-sni"),
    }
}

fn clash_transport(proxy: &Map<String, Value>) -> Result<Option<Value>, String> {
    let network = text(proxy, "network");
    match network.as_str() {
        "ws" => {
            let ws = section(proxy, "ws-opts");
            let headers = section(&ws, "headers");
            transport("ws", &text(&headers, "Host"), &text(&ws, "path"), "")
        }
        "grpc" => {
            let grpc = section(proxy, "grpc-opts");
            transport("grpc", "", "", &text(&grpc, "grpc-service-name"))
        }
        "h2" => {
            let h2 = section(proxy, "h2-opts");
            transport(
                "http",
                &strings(&h2, "host").join(","),
                &text(&h2, "path"),
                "",
            )
        }
        "http" => {
            let http = section(proxy, "http-opts");
            let path = strings(&http, "path")
                .into_iter()
                .next()
                .unwrap_or_default();
            let headers = section(&http, "headers");
            transport("http", &strings(&headers, "Host").join(","), &path, "")
        }
        other => transport(other, "", "", ""),
    }
}

fn clash_proxy(proxy: &Map<String, Value>) -> Result<Imported, String> {
    let kind = text(proxy, "type");
    let port: u16 = text(proxy, "port")
        .parse()
        .map_err(|_| "端口无效".to_owned())?;
    let server = text(proxy, "server");
    let outbound = match kind.as_str() {
        "ss" => {
            if text(proxy, "cipher").is_empty() {
                return Err("缺少 cipher".into());
            }
            let mut outbound = base("shadowsocks", &server, port)?;
            outbound.insert("method".into(), json!(text(proxy, "cipher")));
            outbound.insert("password".into(), json!(text(proxy, "password")));
            let plugin = text(proxy, "plugin");
            if !plugin.is_empty() {
                let opts = section(proxy, "plugin-opts");
                let (name, options) = match plugin.as_str() {
                    "obfs" => (
                        "obfs-local",
                        format!(
                            "obfs={};obfs-host={}",
                            text(&opts, "mode"),
                            text(&opts, "host")
                        ),
                    ),
                    "v2ray-plugin" => {
                        let mut options = format!("mode={}", text(&opts, "mode"));
                        if truthy(&opts, "tls") {
                            options.push_str(";tls");
                        }
                        for key in ["host", "path"] {
                            let value = text(&opts, key);
                            if !value.is_empty() {
                                options.push_str(&format!(";{key}={value}"));
                            }
                        }
                        ("v2ray-plugin", options)
                    }
                    other => return Err(format!("不支持的 ss 插件 `{other}`")),
                };
                outbound.insert("plugin".into(), json!(name));
                outbound.insert("plugin_opts".into(), json!(options));
            }
            outbound
        }
        "vmess" => {
            let mut outbound = base("vmess", &server, port)?;
            outbound.insert("uuid".into(), json!(text(proxy, "uuid")));
            let cipher = text(proxy, "cipher");
            outbound.insert(
                "security".into(),
                json!(if cipher.is_empty() {
                    "auto"
                } else {
                    cipher.as_str()
                }),
            );
            let alter: u64 = text(proxy, "alterId").parse().unwrap_or(0);
            if alter != 0 {
                outbound.insert("alter_id".into(), json!(alter));
            }
            put(
                &mut outbound,
                "tls",
                clash_tls(proxy, truthy(proxy, "tls")).value(),
            );
            put(&mut outbound, "transport", clash_transport(proxy)?);
            outbound.insert("packet_encoding".into(), json!("xudp"));
            outbound
        }
        "vless" => {
            let mut outbound = base("vless", &server, port)?;
            outbound.insert("uuid".into(), json!(text(proxy, "uuid")));
            let flow = text(proxy, "flow");
            if !flow.is_empty() {
                outbound.insert("flow".into(), json!(flow));
            }
            let reality = proxy.contains_key("reality-opts");
            put(
                &mut outbound,
                "tls",
                clash_tls(proxy, truthy(proxy, "tls") || reality).value(),
            );
            put(&mut outbound, "transport", clash_transport(proxy)?);
            outbound.insert("packet_encoding".into(), json!("xudp"));
            outbound
        }
        "trojan" => {
            let mut outbound = base("trojan", &server, port)?;
            outbound.insert("password".into(), json!(text(proxy, "password")));
            put(&mut outbound, "tls", clash_tls(proxy, true).value());
            put(&mut outbound, "transport", clash_transport(proxy)?);
            outbound
        }
        "hysteria2" => {
            let mut outbound = base("hysteria2", &server, port)?;
            let password = text(proxy, "password");
            if !password.is_empty() {
                outbound.insert("password".into(), json!(password));
            }
            let obfs = text(proxy, "obfs");
            if !obfs.is_empty() {
                outbound.insert(
                    "obfs".into(),
                    json!({"type": obfs, "password": text(proxy, "obfs-password")}),
                );
            }
            put(&mut outbound, "tls", clash_tls(proxy, true).value());
            outbound
        }
        "tuic" => {
            let mut outbound = base("tuic", &server, port)?;
            outbound.insert("uuid".into(), json!(text(proxy, "uuid")));
            let password = text(proxy, "password");
            if !password.is_empty() {
                outbound.insert("password".into(), json!(password));
            }
            let congestion = text(proxy, "congestion-controller");
            if !congestion.is_empty() {
                outbound.insert("congestion_control".into(), json!(congestion));
            }
            let relay = text(proxy, "udp-relay-mode");
            if !relay.is_empty() {
                outbound.insert("udp_relay_mode".into(), json!(relay));
            }
            put(&mut outbound, "tls", clash_tls(proxy, true).value());
            outbound
        }
        "anytls" => {
            let mut outbound = base("anytls", &server, port)?;
            outbound.insert("password".into(), json!(text(proxy, "password")));
            put(&mut outbound, "tls", clash_tls(proxy, true).value());
            outbound
        }
        "socks5" => {
            let mut outbound = base("socks", &server, port)?;
            outbound.insert("version".into(), json!("5"));
            for key in ["username", "password"] {
                let value = text(proxy, key);
                if !value.is_empty() {
                    outbound.insert(key.into(), json!(value));
                }
            }
            if truthy(proxy, "tls") {
                return Err("不支持带 TLS 的 socks5".into());
            }
            outbound
        }
        "" => return Err("缺少 type".into()),
        other => return Err(format!("不支持的 Clash 节点类型 `{other}`")),
    };
    for key in ["uuid", "password", "method"] {
        if outbound.get(key).and_then(Value::as_str) == Some("") {
            return Err(format!("缺少 {key}"));
        }
    }
    let name = text(proxy, "name");
    Ok((clean_name(&name, &outbound), outbound))
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

fn numbered<T>(index: usize, result: Result<T, String>) -> Result<T, String> {
    result.map_err(|error| format!("第 {} 项: {error}", index + 1))
}

/// Nodes from share links, one per line (blank lines and `#` comments
/// skipped).
pub(crate) fn from_links(content: &str) -> Result<Vec<Imported>, String> {
    let lines: Vec<&str> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    lines
        .iter()
        .enumerate()
        .map(|(index, line)| numbered(index, parse_link(line)))
        .collect()
}

/// Nodes from Clash/mihomo YAML: a configuration with `proxies`, a list of
/// proxies, or one proxy.
pub(crate) fn from_clash_yaml(content: &str) -> Result<Vec<Imported>, String> {
    let value: Value =
        yaml_serde::from_str(content).map_err(|error| format!("YAML 无法解析: {error}"))?;
    let proxies = match value {
        Value::Object(mut map) if map.contains_key("proxies") => match map.remove("proxies") {
            Some(Value::Array(items)) => items,
            _ => return Err("proxies 必须是列表".into()),
        },
        Value::Object(map) => vec![Value::Object(map)],
        Value::Array(items) => items,
        _ => return Err("YAML 里没有节点".into()),
    };
    proxies
        .iter()
        .enumerate()
        .map(|(index, proxy)| {
            numbered(
                index,
                proxy
                    .as_object()
                    .ok_or_else(|| "节点必须是映射".to_owned())
                    .and_then(clash_proxy),
            )
        })
        .collect()
}

/// Nodes from sing-box JSON: one outbound, a list, or a configuration with
/// `outbounds` (only its proxy outbounds).
pub(crate) fn from_singbox_json(value: Value) -> Result<Vec<Imported>, String> {
    let (items, whole) = match value {
        Value::Object(mut map) if map.contains_key("outbounds") && !map.contains_key("type") => {
            match map.remove("outbounds") {
                Some(Value::Array(items)) => (items, true),
                _ => return Err("outbounds 必须是数组".into()),
            }
        }
        Value::Object(map) => (vec![Value::Object(map)], false),
        Value::Array(items) => (items, false),
        _ => return Err("JSON 里没有 outbound".into()),
    };
    let mut nodes = Vec::new();
    for (index, item) in items.into_iter().enumerate() {
        let mut outbound = obj(item);
        if outbound.is_empty() {
            return Err(format!("第 {} 项不是对象", index + 1));
        }
        let kind = outbound.get("type").and_then(Value::as_str).unwrap_or("");
        if whole
            && matches!(
                kind,
                "direct" | "block" | "dns" | "selector" | "urltest" | "fallback" | "load_balance"
            )
        {
            continue;
        }
        let name = match outbound.remove("tag") {
            Some(Value::String(tag)) => tag,
            _ => String::new(),
        };
        let name = clean_name(&name, &outbound);
        numbered(
            index,
            crate::atom_proxy::check_outbound(&outbound).map_err(|refusal| refusal.message),
        )?;
        nodes.push((name, outbound));
    }
    if nodes.is_empty() {
        return Err("没有可导入的节点".into());
    }
    Ok(nodes)
}

#[cfg(test)]
#[path = "atom_links_tests.rs"]
mod tests;
