//! Generates the Mihomo configuration from Atom's saved nodes and rules.

use serde_json::{Map, Value, json};

use crate::atom_proxy::{self, FINAL, GroupKind, Node, ProxyState};
use crate::atom_rules::Action;
use crate::atom_singbox::{Host, IpRule};

/// Removes the subscription caches (`providers/p-*.yaml`) that the live
/// configuration no longer names, e.g. after a URL change or a removal.
/// `p-<8 hex>-<64 hex>.yaml`, the names `generate` gives the caches.
fn is_provider_cache(name: &str) -> bool {
    let hex = |part: &str, len: usize| {
        part.len() == len && part.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    name.strip_suffix(".yaml")
        .and_then(|stem| stem.strip_prefix("p-"))
        .and_then(|stem| stem.split_once('-'))
        .is_some_and(|(id, hash)| hex(id, 8) && hex(hash, 64))
}

pub(crate) fn prune_provider_caches(dir: &std::path::Path, live: &[u8]) {
    let Ok(config) = serde_json::from_slice::<Value>(live) else {
        return;
    };
    let keep: std::collections::HashSet<String> = config["proxy-providers"]
        .as_object()
        .into_iter()
        .flatten()
        .filter_map(|(_, provider)| provider["path"].as_str())
        .filter_map(|path| path.strip_prefix("providers/").map(str::to_owned))
        .collect();
    let Ok(entries) = std::fs::read_dir(dir.join("providers")) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_provider_cache(&name)
            && !keep.contains(&name)
            && entry.file_type().is_ok_and(|kind| kind.is_file())
        {
            if let Err(error) = std::fs::remove_file(entry.path()) {
                eprintln!("清理订阅缓存 {name} 失败: {error}");
            }
        }
    }
}

pub(crate) fn generate(
    host: &Host,
    state: &ProxyState,
    ip_rules: &[IpRule],
    resolver: &str,
    secret: &str,
) -> Result<Vec<u8>, String> {
    let (transport, ip, port) = atom_proxy::parse_resolver(resolver)?;
    let resolver = format!("{transport}://{}", std::net::SocketAddr::new(ip, port));
    let proxies = state
        .nodes
        .iter()
        .map(proxy)
        .collect::<Result<Vec<_>, _>>()?;
    let mut groups = Vec::new();
    for group in &state.groups {
        let mut members = state.members_of(group);
        if group.providers.is_empty() || !members.is_empty() {
            members = ordered_members(members, &group.selected);
        }
        let kind = match group.kind {
            GroupKind::Selector => "select",
            GroupKind::Urltest => "url-test",
            _ => group.kind.name(),
        };
        let mut value = json!({"name":group.id, "type":kind, "empty-fallback":"REJECT"});
        if !members.is_empty() {
            value["proxies"] = json!(members);
        }
        if !group.providers.is_empty() {
            value["use"] = json!(group.providers);
        }
        if group.kind != GroupKind::Selector {
            let duration = group
                .interval
                .as_deref()
                .unwrap_or(atom_proxy::DEFAULT_INTERVAL);
            value["url"] = json!(group.url.as_deref().unwrap_or(atom_proxy::DEFAULT_URL));
            value["interval"] =
                json!(atom_proxy::duration_secs(duration).map_err(|error| error.message)?);
        }
        if group.kind == GroupKind::Urltest {
            value["tolerance"] = json!(group.tolerance.unwrap_or(atom_proxy::DEFAULT_TOLERANCE));
        } else if group.kind == GroupKind::LoadBalance {
            value["strategy"] = json!(group.strategy.unwrap_or_default());
        }
        groups.push(value);
    }
    groups.push(json!({
        "name":FINAL, "type":"select",
        "proxies":ordered_members(state.final_group.members.clone(), &state.final_group.selected)
    }));
    let mut rules: Vec<String> = ip_rules.iter().map(ip_rule).collect();
    rules.push("AND,((IN-NAME,DEFAULT-MIXED),(DOMAIN-REGEX,.)),DIRECT".to_owned());
    rules.push(format!("MATCH,{FINAL}"));
    let providers = state.providers.iter().map(|provider| {
        let input = &provider.settings;
        let digest = ring::digest::digest(&ring::digest::SHA256, input.url.as_bytes());
        let hash = digest.as_ref().iter().map(|byte| format!("{byte:02x}")).collect::<String>();
        let mut entry = json!({
            "type":"http", "url":input.url, "interval":input.interval, "proxy":input.download_via.as_deref().unwrap_or("DIRECT"),
            "path":format!("providers/{}-{hash}.yaml", provider.id),
            "override":{"additional-prefix":format!("{}/", provider.id)},
            "health-check":{"enable":true, "url":atom_proxy::DEFAULT_URL, "interval":300, "lazy":true},
            "size-limit": 16 * 1024 * 1024,
        });
        if !input.filter.is_empty() {
            entry["filter"] = json!(input.filter);
        }
        (provider.id.clone(), entry)
    }).collect::<Map<String, Value>>();
    let mut config = json!({
        "mode":"rule", "log-level":"info", "allow-lan":true, "bind-address":"0.0.0.0",
        "mixed-port":state.settings.mixed_port,
        "redir-port":host.redirect_port,
        "tproxy-port":host.tproxy_port,
        "ipv6": true,
        "external-controller":host.clash_api.to_string(), "secret":secret,
        "profile":{"store-selected":true,"store-fake-ip":true},
        "dns":{
            "enable":true,
            "listen":host.dns_in.to_string(),
            "ipv6":false,
            "enhanced-mode":"fake-ip",
            "fake-ip-range":state.settings.fakeip_range,
            "fake-ip-range6":"",
            "fake-ip-filter":[],
            "use-hosts":false, "use-system-hosts":false,
            "default-nameserver":[resolver],
            "nameserver":[resolver],
            "proxy-server-nameserver":[resolver],
            "atom-fake-ip-final":FINAL,
            "atom-mixed-dns":host.atomdns.to_string(),
        },
        "proxies":proxies, "proxy-groups":groups, "rules":rules,
    });
    if !providers.is_empty() {
        config["proxy-providers"] = Value::Object(providers);
    }
    // JSON is valid YAML and lets the installer's nft hook read the same
    // generated file with its standard-library JSON decoder.
    let mut bytes = serde_json::to_vec_pretty(&config).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn ordered_members(mut members: Vec<String>, selected: &str) -> Vec<String> {
    if members.is_empty() {
        members.push("REJECT".to_owned());
    } else if let Some(index) = members.iter().position(|member| member == selected) {
        members.rotate_left(index);
    }
    members
}

fn alternatives(mut values: Vec<String>) -> Option<String> {
    match values.len() {
        0 => None,
        1 => values.pop(),
        _ => Some(format!("(OR,({}))", values.join(","))),
    }
}

fn ip_rule(rule: &IpRule) -> String {
    let mut conditions = Vec::new();
    conditions.extend(alternatives(
        rule.cidrs
            .iter()
            .map(|cidr| {
                let kind = if cidr.contains(':') {
                    "IP-CIDR6"
                } else {
                    "IP-CIDR"
                };
                format!("({kind},{cidr},no-resolve)")
            })
            .collect(),
    ));
    let mut ports: Vec<_> = rule.ports.iter().map(u16::to_string).collect();
    ports.extend(rule.port_ranges.iter().filter_map(|range| {
        let (start, end) = range.split_once(':')?;
        let start = if start.is_empty() { "0" } else { start };
        let end = if end.is_empty() { "65535" } else { end };
        Some(format!("{start}-{end}"))
    }));
    conditions.extend(alternatives(
        ports
            .into_iter()
            .map(|port| format!("(DST-PORT,{port})"))
            .collect(),
    ));
    conditions.extend(alternatives(
        rule.networks
            .iter()
            .map(|network| format!("(NETWORK,{network})"))
            .collect(),
    ));
    let target = match &rule.action {
        Action::Proxy { group_id } => group_id,
        Action::Direct => "DIRECT",
        Action::Block => "REJECT",
    };
    format!("AND,({}),{target}", conditions.join(","))
}

fn copy(from: &mut Map<String, Value>, to: &mut Map<String, Value>, keys: &[(&str, &str)]) {
    for (source, target) in keys {
        if let Some(value) = from.remove(*source) {
            to.insert((*target).to_owned(), value);
        }
    }
}

fn object(value: Value, section: &str) -> Result<Map<String, Value>, String> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(format!("{section} 必须是对象")),
    }
}

fn no_extra(fields: &Map<String, Value>) -> Result<(), String> {
    if let Some(key) = fields.keys().next() {
        return Err(format!("mihomo 尚不支持此节点选项 {key}"));
    }
    Ok(())
}

fn proxy(node: &Node) -> Result<Value, String> {
    convert_proxy(node).map_err(|error| format!("节点 {} ({})：{error}", node.name, node.id))
}

pub(crate) fn convert_proxy(node: &Node) -> Result<Value, String> {
    let mut options = node.outbound.clone();
    let kind = options.remove("type").unwrap_or_default();
    let ty = match kind.as_str() {
        Some("shadowsocks") => "ss",
        Some("socks") if options.remove("version").is_none_or(|v| v == "5") => "socks5",
        Some(ty @ ("vless" | "vmess" | "trojan" | "hysteria2" | "tuic" | "anytls" | "http")) => ty,
        _ => return Err("mihomo 未支持转换此节点协议".to_owned()),
    };
    let mut out = Map::from_iter([
        ("name".to_owned(), json!(node.id)),
        ("type".to_owned(), json!(ty)),
    ]);
    copy(
        &mut options,
        &mut out,
        &[
            ("server", "server"),
            ("server_port", "port"),
            ("password", "password"),
            ("username", "username"),
            ("uuid", "uuid"),
            ("flow", "flow"),
            ("security", "cipher"),
            ("method", "cipher"),
            ("alter_id", "alterId"),
            ("packet_encoding", "packet-encoding"),
            ("congestion_control", "congestion-controller"),
            ("udp_relay_mode", "udp-relay-mode"),
        ],
    );
    if matches!(ty, "ss" | "socks5" | "vless" | "vmess" | "trojan" | "anytls") {
        out.insert("udp".into(), json!(true));
    }
    if ty == "hysteria2" {
        for (source, target) in [("up_mbps", "up"), ("down_mbps", "down")] {
            if let Some(value) = options.remove(source) {
                let mbps = value
                    .as_u64()
                    .ok_or_else(|| format!("{source} 必须是整数"))?;
                out.insert(target.into(), json!(format!("{mbps} Mbps")));
            }
        }
    }
    if ty == "ss" {
        if let Some(plugin) = options.remove("plugin") {
            let plugin = match plugin.as_str() {
                Some("obfs-local") => "obfs",
                Some("v2ray-plugin") => "v2ray-plugin",
                _ => return Err("mihomo 未支持转换此 Shadowsocks 插件".into()),
            };
            let raw = options.remove("plugin_opts").unwrap_or_default();
            let mut values = Map::new();
            for pair in raw
                .as_str()
                .unwrap_or_default()
                .split(';')
                .filter(|pair| !pair.is_empty())
            {
                match pair.split_once('=') {
                    Some(("obfs" | "mode", value)) => {
                        values.insert("mode".into(), json!(value));
                    }
                    Some(("obfs-host" | "host", value)) => {
                        values.insert("host".into(), json!(value));
                    }
                    Some(("path", value)) => {
                        values.insert("path".into(), json!(value));
                    }
                    None if pair == "tls" => {
                        values.insert("tls".into(), json!(true));
                    }
                    _ => return Err("mihomo 未支持转换此 Shadowsocks 插件选项".into()),
                }
            }
            out.insert("plugin".into(), json!(plugin));
            out.insert("plugin-opts".into(), Value::Object(values));
        }
    }
    if let Some(obfs) = options.remove("obfs") {
        let mut obfs = object(obfs, "obfs")?;
        copy(
            &mut obfs,
            &mut out,
            &[("type", "obfs"), ("password", "obfs-password")],
        );
        no_extra(&obfs)?;
    }
    let tls_enabled = options
        .get("tls")
        .and_then(|tls| tls.get("enabled"))
        .is_some_and(|value| *value == true);
    if let Some(tls) = options.remove("tls") {
        convert_tls(object(tls, "tls")?, &mut out, ty)?;
    }
    if let Some(transport) = options.remove("transport") {
        convert_transport(object(transport, "transport")?, &mut out, tls_enabled)?;
    }
    no_extra(&options)?;
    Ok(Value::Object(out))
}

fn convert_tls(
    mut tls: Map<String, Value>,
    out: &mut Map<String, Value>,
    ty: &str,
) -> Result<(), String> {
    let enabled = tls.remove("enabled").is_some_and(|value| value == true);
    if !enabled {
        if matches!(ty, "trojan" | "hysteria2" | "tuic" | "anytls") {
            return Err("此协议在 mihomo 中必须启用 TLS".into());
        }
        return Ok(());
    }
    if matches!(ty, "vmess" | "vless" | "socks5" | "http") {
        out.insert("tls".into(), json!(true));
    }
    let sni = match ty {
        "vmess" | "vless" => "servername",
        "http" | "trojan" | "hysteria2" | "tuic" | "anytls" => "sni",
        _ => return Err("mihomo 未支持转换此节点的 TLS 选项".into()),
    };
    copy(
        &mut tls,
        out,
        &[
            ("server_name", sni),
            ("insecure", "skip-cert-verify"),
            ("alpn", "alpn"),
        ],
    );
    if ty == "tuic" {
        copy(&mut tls, out, &[("disable_sni", "disable-sni")]);
    }
    if let Some(utls) = tls.remove("utls") {
        let mut utls = object(utls, "utls")?;
        if utls.remove("enabled").is_some_and(|value| value == true) {
            copy(&mut utls, out, &[("fingerprint", "client-fingerprint")]);
            no_extra(&utls)?;
        }
    }
    if let Some(reality) = tls.remove("reality") {
        let mut reality = object(reality, "reality")?;
        if reality.remove("enabled").is_some_and(|value| value == true) {
            let mut opts = Map::new();
            copy(
                &mut reality,
                &mut opts,
                &[("public_key", "public-key"), ("short_id", "short-id")],
            );
            no_extra(&reality)?;
            out.insert("reality-opts".into(), Value::Object(opts));
        }
    }
    no_extra(&tls)
}

fn convert_transport(
    mut transport: Map<String, Value>,
    out: &mut Map<String, Value>,
    tls: bool,
) -> Result<(), String> {
    let kind = transport.remove("type").unwrap_or_default();
    let mut opts = Map::new();
    let network = match kind.as_str() {
        Some("ws") => {
            copy(
                &mut transport,
                &mut opts,
                &[
                    ("path", "path"),
                    ("headers", "headers"),
                    ("max_early_data", "max-early-data"),
                    ("early_data_header_name", "early-data-header-name"),
                ],
            );
            "ws"
        }
        Some("httpupgrade") => {
            opts.insert("v2ray-http-upgrade".into(), json!(true));
            copy(&mut transport, &mut opts, &[("path", "path")]);
            if let Some(host) = transport.remove("host") {
                opts.insert("headers".into(), json!({"Host":host}));
            }
            "ws"
        }
        Some("grpc") => {
            copy(
                &mut transport,
                &mut opts,
                &[("service_name", "grpc-service-name")],
            );
            "grpc"
        }
        // Mihomo's h2 needs TLS; a plain HTTP transport is its http network.
        Some("http") if tls => {
            copy(
                &mut transport,
                &mut opts,
                &[("host", "host"), ("path", "path")],
            );
            "h2"
        }
        Some("http") => {
            // sing-box sends PUT unless told otherwise, Mihomo GET.
            let method = match transport.remove("method") {
                Some(Value::String(method)) if !method.is_empty() => json!(method),
                _ => json!("PUT"),
            };
            opts.insert("method".into(), method);
            if let Some(path) = transport.remove("path") {
                opts.insert("path".into(), json!([path]));
            }
            let mut headers = Map::new();
            if let Some(Value::Object(values)) = transport.remove("headers") {
                for (name, value) in values {
                    let list = match value {
                        Value::Array(list) => list,
                        value => vec![value],
                    };
                    headers.insert(name, Value::Array(list));
                }
            }
            if let Some(host) = transport.remove("host") {
                let list = match host {
                    Value::Array(list) => list,
                    host => vec![host],
                };
                headers.insert("Host".into(), Value::Array(list));
            }
            if !headers.is_empty() {
                opts.insert("headers".into(), Value::Object(headers));
            }
            "http"
        }
        _ => return Err("mihomo 未支持转换此传输协议".into()),
    };
    no_extra(&transport)?;
    out.insert("network".into(), json!(network));
    out.insert(format!("{network}-opts"), Value::Object(opts));
    Ok(())
}
