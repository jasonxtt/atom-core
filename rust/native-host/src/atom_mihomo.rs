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
    // Nodes mihomo cannot run stay in Atom's state but are not configured;
    // the groups and Final lose them as members.
    let state = &state.effective();
    for provider in &state.providers {
        if let Some(via) = provider.settings.download_via.as_deref() {
            if state.node(via).is_none() {
                return Err(format!(
                    "订阅 {} 的下载节点在 mihomo 下不生效，请改用其他节点或直连",
                    provider.settings.name
                ));
            }
        }
    }
    let proxies = state
        .nodes
        .iter()
        .map(proxy)
        .collect::<Result<Vec<_>, _>>()?;
    let mut groups = Vec::new();
    for group in &state.groups {
        let mut members = state.members_of(group);
        let uses_providers = state.uses_providers(group);
        if !uses_providers || !members.is_empty() {
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
        if group.all_providers && uses_providers {
            value["include-all-providers"] = json!(true);
        } else if !group.providers.is_empty() {
            value["use"] = json!(group.providers);
        }
        if uses_providers && !group.filter.is_empty() {
            // mihomo applies a group's filter to the subscription nodes only.
            value["filter"] = json!(mihomo_filter(&group.filter));
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

/// Atom's group filter (case-insensitive, over the node name) as a mihomo
/// group `filter` (regexp2, case-sensitive, over the full name
/// `p-xxxxxxxx/<name>`): `(?i)`, a match that must start behind the
/// subscription prefix, a start anchor (`^`, `\A`) written as "right behind
/// the prefix", and the backtick (mihomo's separator of several filters)
/// written as `\x60`.
pub(crate) fn mihomo_filter(filter: &str) -> String {
    const BEHIND: &str = "(?<=^p-[0-9a-f]{8}/)";
    let mut out = String::from("(?i)(?<=^p-[0-9a-f]{8}/.*)(?:");
    let mut chars = filter.chars();
    let mut class = false;
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some('A') if !class => out.push_str(BEHIND),
                Some(next) => {
                    out.push('\\');
                    out.push(next);
                }
                None => out.push_str("\\\\"),
            },
            '[' if !class => {
                class = true;
                out.push(c);
            }
            ']' if class => {
                class = false;
                out.push(c);
            }
            '^' if !class => out.push_str(BEHIND),
            '`' => out.push_str("\\x60"),
            _ => out.push(c),
        }
    }
    out.push(')');
    out
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
        Some(
            ty @ ("vless" | "vmess" | "trojan" | "hysteria2" | "tuic" | "anytls" | "http"
            | "hysteria" | "ssh" | "snell"),
        ) => ty,
        Some("wireguard") => return convert_wireguard(node, options),
        Some("naive") => return Err("mihomo 没有 naive 协议".to_owned()),
        Some("shadowtls") => {
            return Err("mihomo 的 shadowtls 只能作为其他协议的插件，不能做独立节点".to_owned());
        }
        Some("socks") => return Err("mihomo 只支持 SOCKS5".to_owned()),
        Some(other) => return Err(format!("mihomo 未支持转换 {other} 节点")),
        None => return Err("节点缺少 type".to_owned()),
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
            ("user", "username"),
            ("psk", "psk"),
            ("auth_str", "auth-str"),
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
    if matches!(ty, "ss" | "socks5" | "vless" | "vmess" | "trojan" | "anytls" | "snell") {
        out.insert("udp".into(), json!(true));
    }
    match ty {
        "hysteria" => convert_hysteria(&mut options, &mut out)?,
        "ssh" => convert_ssh(&mut options, &mut out)?,
        "snell" => convert_snell(&mut options, &mut out)?,
        _ => {}
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
        if ty == "hysteria" {
            out.insert("obfs".into(), obfs);
        } else {
            convert_obfs(obfs, &mut out)?;
        }
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

fn convert_obfs(obfs: Value, out: &mut Map<String, Value>) -> Result<(), String> {
    let mut obfs = object(obfs, "obfs")?;
    copy(
        &mut obfs,
        out,
        &[("type", "obfs"), ("password", "obfs-password")],
    );
    no_extra(&obfs)
}

fn take_strings(value: Value, what: &str) -> Result<Vec<String>, String> {
    match value {
        Value::String(text) => Ok(vec![text]),
        Value::Array(items) => items
            .into_iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| format!("{what} 必须是字符串"))
            })
            .collect(),
        _ => Err(format!("{what} 必须是字符串或字符串数组")),
    }
}

/// A sing-box duration such as `10s` or `1m` as whole seconds.
fn seconds(value: &Value, what: &str) -> Result<u64, String> {
    match value {
        Value::Number(number) => number
            .as_u64()
            .ok_or_else(|| format!("{what} 必须是整数秒")),
        Value::String(text) => atom_proxy::duration_secs(text)
            .map_err(|_| format!("{what} `{text}` 无效：写成 30s、3m 这样的形式")),
        _ => Err(format!("{what} 必须是时长")),
    }
}

/// hysteria (v1): the rate fields are `up`/`down` text ("100 Mbps") or
/// `up_mbps`/`down_mbps`; `auth` is base64 in both kernels.
fn convert_hysteria(
    options: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Result<(), String> {
    for (text, mbps, target) in [("up", "up_mbps", "up"), ("down", "down_mbps", "down")] {
        let value = options.remove(text).or_else(|| {
            options
                .remove(mbps)
                .and_then(|value| value.as_u64().map(|mbps| json!(format!("{mbps} Mbps"))))
        });
        // The other spelling may be present as well; the text one wins.
        options.remove(mbps);
        match value {
            Some(value) => {
                out.insert(target.into(), value);
            }
            None => return Err(format!("hysteria 节点需要 {text} 或 {mbps}")),
        }
    }
    // sing-box takes `auth_str` over `auth`; mihomo the other way round.
    if out.get("auth-str").and_then(Value::as_str).is_some_and(|text| !text.is_empty()) {
        options.remove("auth");
    } else {
        copy(options, out, &[("auth", "auth")]);
    }
    if let Some(ports) = options.remove("server_ports") {
        let ports: Vec<String> = take_strings(ports, "server_ports")?
            .into_iter()
            .map(|range| range.replace(':', "-"))
            .collect();
        out.insert("ports".into(), json!(ports.join(",")));
    }
    if let Some(interval) = options.remove("hop_interval") {
        out.insert("hop-interval".into(), json!(seconds(&interval, "hop_interval")?));
    }
    Ok(())
}

fn convert_ssh(
    options: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Result<(), String> {
    if options.contains_key("private_key_path") {
        return Err("mihomo 的 ssh 不读取 private_key_path，请把私钥内容写进 private_key".to_owned());
    }
    // sing-box joins a list of lines into one key; defaults: root, port 22.
    if let Some(keys) = options.remove("private_key") {
        out.insert("private-key".into(), json!(take_strings(keys, "private_key")?.join("\n")));
    }
    out.entry("username").or_insert_with(|| json!("root"));
    out.entry("port").or_insert_with(|| json!(22));
    if let Some(value) = options.remove("private_key_passphrase") {
        out.insert("private-key-passphrase".into(), value);
    }
    for (source, target) in [("host_key", "host-key"), ("host_key_algorithms", "host-key-algorithms")] {
        if let Some(value) = options.remove(source) {
            out.insert(target.into(), json!(take_strings(value, source)?));
        }
    }
    Ok(())
}

fn convert_snell(
    options: &mut Map<String, Value>,
    out: &mut Map<String, Value>,
) -> Result<(), String> {
    if options.contains_key("userkey") {
        return Err("mihomo 的 snell 不支持 userkey".to_owned());
    }
    if options.contains_key("network") {
        return Err("mihomo 的 snell 不支持限定 network".to_owned());
    }
    copy(options, out, &[("version", "version"), ("reuse", "reuse"), ("mode", "mode")]);
    let mut obfs = Map::new();
    copy(options, &mut obfs, &[("obfs_mode", "mode"), ("obfs_host", "host")]);
    // "none" is mihomo's empty mode.
    if obfs.get("mode").and_then(Value::as_str) == Some("none") {
        obfs.remove("mode");
    }
    if !obfs.is_empty() {
        out.insert("obfs-opts".into(), Value::Object(obfs));
    }
    Ok(())
}

/// WireGuard is an endpoint in sing-box (`address`, `peers`); mihomo takes
/// it as a proxy with `ip`/`ipv6` and `peers`.
fn convert_wireguard(node: &Node, mut options: Map<String, Value>) -> Result<Value, String> {
    let mut out = Map::from_iter([
        ("name".to_owned(), json!(node.id)),
        ("type".to_owned(), json!("wireguard")),
        ("udp".to_owned(), json!(true)),
    ]);
    copy(
        &mut options,
        &mut out,
        &[("private_key", "private-key"), ("mtu", "mtu"), ("workers", "workers")],
    );
    let Some(address) = options.remove("address") else {
        return Err("wireguard 节点需要 address".to_owned());
    };
    for prefix in take_strings(address, "address")? {
        let target = if prefix.contains(':') { "ipv6" } else { "ip" };
        if out.insert(target.into(), json!(prefix)).is_some() {
            return Err("mihomo 的 wireguard 每种 IP 版本只能有一个 address".to_owned());
        }
    }
    let mut peers = Vec::new();
    let mut keepalive = None;
    for peer in match options.remove("peers") {
        Some(Value::Array(peers)) => peers,
        Some(_) => return Err("peers 必须是数组".to_owned()),
        None => Vec::new(),
    } {
        let mut peer = object(peer, "peers")?;
        let mut view = Map::new();
        copy(
            &mut peer,
            &mut view,
            &[
                ("address", "server"),
                ("port", "port"),
                ("public_key", "public-key"),
                ("pre_shared_key", "pre-shared-key"),
                ("allowed_ips", "allowed-ips"),
                ("reserved", "reserved"),
            ],
        );
        let interval = peer.remove("persistent_keepalive_interval").unwrap_or(json!(0));
        if keepalive.get_or_insert_with(|| interval.clone()) != &interval {
            return Err("mihomo 的 wireguard 所有 peer 共用一个 persistent-keepalive".to_owned());
        }
        no_extra(&peer)?;
        peers.push(Value::Object(view));
    }
    if peers.is_empty() {
        return Err("wireguard 节点需要 peers".to_owned());
    }
    out.insert("peers".into(), Value::Array(peers));
    if let Some(interval) = keepalive.filter(|interval| *interval != json!(0)) {
        out.insert("persistent-keepalive".into(), interval);
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
        if matches!(ty, "trojan" | "hysteria" | "hysteria2" | "tuic" | "anytls") {
            return Err("此协议在 mihomo 中必须启用 TLS".into());
        }
        return Ok(());
    }
    if matches!(ty, "vmess" | "vless" | "socks5" | "http") {
        out.insert("tls".into(), json!(true));
    }
    let sni = match ty {
        "vmess" | "vless" => "servername",
        "http" | "trojan" | "hysteria" | "hysteria2" | "tuic" | "anytls" => "sni",
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
