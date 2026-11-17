//! Generates the Mihomo configuration from Atom's saved nodes and rules.

use serde_json::{Map, Value, json};

use crate::atom_proxy::{self, FINAL, GroupKind, Node, ProxyState};
use crate::atom_rules::Action;
use crate::atom_singbox::{Host, IpRule};

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
        let members = ordered_members(state.members_of(group), &group.selected);
        let value = match group.kind {
            GroupKind::Selector => json!({"name":group.id, "type":"select", "proxies":members}),
            GroupKind::Urltest => {
                let duration = group
                    .interval
                    .as_deref()
                    .unwrap_or(atom_proxy::DEFAULT_INTERVAL);
                json!({
                    "name": group.id, "type":"url-test", "proxies":members,
                    "url":group.url.as_deref().unwrap_or(atom_proxy::DEFAULT_URL),
                    "interval":atom_proxy::duration_secs(duration).map_err(|error| error.message)?,
                    "tolerance":group.tolerance.unwrap_or(atom_proxy::DEFAULT_TOLERANCE),
                })
            }
        };
        groups.push(value);
    }
    groups.push(json!({
        "name":FINAL, "type":"select",
        "proxies":ordered_members(state.final_group.members.clone(), &state.final_group.selected)
    }));
    let mut rules: Vec<String> = ip_rules.iter().map(ip_rule).collect();
    rules.push("AND,((IN-NAME,DEFAULT-MIXED),(DOMAIN-REGEX,.)),DIRECT".to_owned());
    rules.push(format!("MATCH,{FINAL}"));
    let config = json!({
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

fn convert_proxy(node: &Node) -> Result<Value, String> {
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
    if matches!(ty, "ss" | "socks5" | "vless" | "vmess" | "trojan") {
        out.insert("udp".into(), json!(true));
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
    if let Some(tls) = options.remove("tls") {
        convert_tls(object(tls, "tls")?, &mut out, ty)?;
    }
    if let Some(transport) = options.remove("transport") {
        convert_transport(object(transport, "transport")?, &mut out)?;
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
        Some("http") => {
            copy(
                &mut transport,
                &mut opts,
                &[("host", "host"), ("path", "path")],
            );
            "h2"
        }
        _ => return Err("mihomo 未支持转换此传输协议".into()),
    };
    no_extra(&transport)?;
    out.insert("network".into(), json!(network));
    out.insert(format!("{network}-opts"), Value::Object(opts));
    Ok(())
}
