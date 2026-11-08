//! atom fork: nodes, node groups, Final and the sing-box settings (atom
//! `docs/design.md` §5, §6, §7.2).
//!
//! The whole proxy side is one document, `webinfo/atom_proxy.json`
//! (`{version, nodes, groups, final, settings}`), with one version like the
//! rule table. Everything here is pure: a change builds the next state, the
//! owner ([`crate::atom_rules::AtomRules`]) validates it, generates and
//! applies the sing-box configuration ([`crate::atom_singbox`]), and only
//! then writes and publishes it.
//!
//! sing-box tags are immutable internal IDs: `n-xxxxxxxx` for nodes,
//! `g-xxxxxxxx` for groups (the builtin "默认代理" is `g-default`), `final`
//! for Final. Names are only shown. An empty group (or an empty Final) is
//! generated with a hidden `block` member, so its traffic is refused rather
//! than sent direct.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::atom_rules::Refusal;

pub(crate) const PROXY_FILE: &str = "webinfo/atom_proxy.json";
/// The builtin group "默认代理": it cannot be deleted.
pub(crate) const DEFAULT_GROUP: &str = "g-default";
const DEFAULT_GROUP_NAME: &str = "默认代理";
/// The tag of Final (`route.final`). Rules may proxy to it too: a rule whose
/// group is deleted is moved to Final.
pub(crate) const FINAL: &str = "final";
pub(crate) const DEFAULT_URL: &str = "https://www.gstatic.com/generate_204";
pub(crate) const DEFAULT_INTERVAL: &str = "3m";
pub(crate) const DEFAULT_TOLERANCE: u16 = 50;
pub(crate) const DEFAULT_FAKEIP_RANGE: &str = "28.0.0.0/8";
pub(crate) const DEFAULT_MIXED_PORT: u16 = 7890;
const MAX_NAME_CHARS: usize = 64;
/// The most nodes one state holds (an import is refused beyond it).
const MAX_NODES: usize = 4096;
const MAX_GROUPS: usize = 512;

/// The sing-box outbound types a node may be: the proxy protocols. Groups,
/// `direct`, `block` and `dns` are atom's own.
const NODE_TYPES: &[&str] = &[
    "socks",
    "http",
    "shadowsocks",
    "vmess",
    "trojan",
    "naive",
    "wireguard",
    "hysteria",
    "shadowtls",
    "vless",
    "tuic",
    "hysteria2",
    "anytls",
    "ssh",
    "tor",
];

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Node {
    pub(crate) id: String,
    pub(crate) name: String,
    /// The sing-box outbound without its `tag` (the tag is `id`).
    pub(crate) outbound: Map<String, Value>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum GroupKind {
    Selector,
    Urltest,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Group {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) kind: GroupKind,
    /// Node and group IDs, in order.
    pub(crate) members: Vec<String>,
    /// selector: the chosen member ("" = the first).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) selected: String,
    /// urltest: the test URL, interval and tolerance (ms).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) interval: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) tolerance: Option<u16>,
}

/// Final: a selector over groups and nodes (by default every group; a new
/// group joins it), never `direct`. One member is selected.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Final {
    pub(crate) members: Vec<String>,
    pub(crate) selected: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    /// sing-box's FakeIP `inet4_range`.
    pub(crate) fakeip_range: String,
    /// The DNS sing-box resolves node names with; "" = the first plain
    /// domestic upstream of AtomDNS.
    #[serde(default)]
    pub(crate) resolver: String,
    /// The mixed inbound; AtomDNS's `main_proxy` follows it.
    pub(crate) mixed_port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            fakeip_range: DEFAULT_FAKEIP_RANGE.to_owned(),
            resolver: String::new(),
            mixed_port: DEFAULT_MIXED_PORT,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProxyState {
    pub(crate) version: u64,
    pub(crate) nodes: Vec<Node>,
    pub(crate) groups: Vec<Group>,
    #[serde(rename = "final")]
    pub(crate) final_group: Final,
    pub(crate) settings: Settings,
}

impl Default for ProxyState {
    /// A new installation: no nodes, the empty "默认代理", Final on it.
    fn default() -> Self {
        Self {
            version: 0,
            nodes: Vec::new(),
            groups: vec![Group {
                id: DEFAULT_GROUP.to_owned(),
                name: DEFAULT_GROUP_NAME.to_owned(),
                kind: GroupKind::Selector,
                members: Vec::new(),
                selected: String::new(),
                url: None,
                interval: None,
                tolerance: None,
            }],
            final_group: Final {
                members: vec![DEFAULT_GROUP.to_owned()],
                selected: DEFAULT_GROUP.to_owned(),
            },
            settings: Settings::default(),
        }
    }
}

/// The editable part of a group (create and replace).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupInput {
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) kind: GroupKind,
    #[serde(default)]
    pub(crate) members: Vec<String>,
    #[serde(default)]
    pub(crate) selected: String,
    #[serde(default)]
    pub(crate) url: Option<String>,
    #[serde(default)]
    pub(crate) interval: Option<String>,
    #[serde(default)]
    pub(crate) tolerance: Option<u16>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(400, message)
}

fn is_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|rest| {
        rest.len() == 8
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn check_name(what: &str, name: &str) -> Result<(), Refusal> {
    if name.trim().is_empty() {
        return Err(invalid(format!("{what}需要名称")));
    }
    if name != name.trim()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "{what}名称 `{name}` 无效：不能有首尾空白或控制字符，最长 {MAX_NAME_CHARS} 个字符"
        )));
    }
    Ok(())
}

/// A node's outbound: a proxy type, no `tag` (atom sets it) and no
/// `detour` (chains are not offered yet). The protocol fields are left to
/// `sing-box check`.
pub(crate) fn check_outbound(outbound: &Map<String, Value>) -> Result<(), Refusal> {
    let kind = outbound
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("outbound 需要 type"))?;
    if !NODE_TYPES.contains(&kind) {
        return Err(invalid(format!("不支持的节点类型 `{kind}`")));
    }
    for key in ["tag", "detour"] {
        if outbound.contains_key(key) {
            return Err(invalid(format!("节点的 outbound 不能带 `{key}`")));
        }
    }
    if !matches!(kind, "wireguard" | "tor") {
        let server = outbound.get("server").and_then(Value::as_str).unwrap_or("");
        if server.trim().is_empty() {
            return Err(invalid(format!("{kind} 节点需要 server")));
        }
    }
    Ok(())
}

/// Outbound fields that are credentials: never shown by the API. Checked
/// against the sing-box v1.14.4 outbound options of the node types:
/// passwords and user names (socks, http, shadowsocks, trojan, naive,
/// hysteria2, tuic, anytls, shadowtls, ssh, `obfs.password`), `uuid`
/// (vmess, vless, tuic), hysteria's `auth` and `auth_str`, ssh and
/// wireguard keys, TLS `client_key` and REALITY's `short_id` (the server
/// admits only its listed IDs; `public_key` is public). The generic
/// `key`, `psk`, `token`, `secret` cover what other types may add.
const CREDENTIAL_KEYS: &[&str] = &[
    "password",
    "username",
    "user",
    "uuid",
    "auth",
    "auth_str",
    "private_key",
    "private_key_passphrase",
    "pre_shared_key",
    "client_key",
    "short_id",
    "key",
    "psk",
    "token",
    "secret",
];

/// HTTP header names that carry credentials (`headers` of http, ws and h2
/// transports, naive's `extra_headers`).
const CREDENTIAL_HEADERS: &[&str] = &["authorization", "proxy-authorization", "cookie"];

/// A node's outbound for the API: every credential field removed, at any
/// depth (`obfs.password`, wireguard `peers[].pre_shared_key`, ...), plus
/// hysteria's string `obfs` (its obfuscation password) and credential
/// headers.
pub(crate) fn public_outbound(outbound: &Map<String, Value>) -> Map<String, Value> {
    fn clean(key: &str, value: &Value) -> Value {
        match value {
            Value::Object(map) if key == "headers" || key == "extra_headers" => Value::Object(
                map.iter()
                    .filter(|(name, _)| {
                        !CREDENTIAL_HEADERS.contains(&name.to_ascii_lowercase().as_str())
                    })
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect(),
            ),
            Value::Object(map) => Value::Object(public_outbound(map)),
            Value::Array(items) => Value::Array(items.iter().map(|item| clean("", item)).collect()),
            other => other.clone(),
        }
    }
    outbound
        .iter()
        .filter(|(key, value)| {
            let hidden = CREDENTIAL_KEYS.contains(&key.as_str())
                || (key.as_str() == "obfs" && value.is_string());
            !hidden
        })
        .map(|(key, value)| (key.clone(), clean(key, value)))
        .collect()
}

/// A sing-box duration of whole seconds, minutes or hours (`30s`, `3m`,
/// `1h30m`), at least one second.
fn check_interval(value: &str) -> Result<(), Refusal> {
    let bad = || {
        invalid(format!(
            "interval `{value}` 无效：写成 30s、3m、1h 这样的形式"
        ))
    };
    let mut rest = value;
    let mut total: u64 = 0;
    if rest.is_empty() {
        return Err(bad());
    }
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 || digits > 6 {
            return Err(bad());
        }
        let number: u64 = rest[..digits].parse().map_err(|_| bad())?;
        let unit = rest[digits..].chars().next().ok_or_else(bad)?;
        total += number
            * match unit {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                _ => return Err(bad()),
            };
        rest = &rest[digits + 1..];
    }
    if total == 0 {
        return Err(bad());
    }
    Ok(())
}

/// `[udp|tcp]://IP[:port]` or a bare IP: the resolver must be an address
/// (a name would itself need resolving).
pub(crate) fn parse_resolver(value: &str) -> Result<(&'static str, std::net::IpAddr, u16), String> {
    let value = value.trim();
    let (kind, rest) = if let Some(rest) = value.strip_prefix("udp://") {
        ("udp", rest)
    } else if let Some(rest) = value.strip_prefix("tcp://") {
        ("tcp", rest)
    } else {
        ("udp", value)
    };
    if let Ok(ip) = rest.parse::<std::net::IpAddr>() {
        return Ok((kind, ip, 53));
    }
    if let Ok(socket) = rest.parse::<std::net::SocketAddr>() {
        if socket.port() != 0 {
            return Ok((kind, socket.ip(), socket.port()));
        }
    }
    Err(format!(
        "resolver `{value}` 无效：写成 IP、udp://IP[:端口] 或 tcp://IP[:端口]"
    ))
}

pub(crate) fn check_settings(settings: &Settings, reserved: &[u16]) -> Result<(), Refusal> {
    let range: Option<(std::net::IpAddr, u8)> =
        crate::rule_formats::parse_prefix(&settings.fakeip_range);
    match range {
        Some((std::net::IpAddr::V4(address), bits)) if (8..=24).contains(&bits) => {
            let masked = u32::from(address) & (u32::MAX << (32 - bits));
            if masked != u32::from(address) {
                return Err(invalid(format!(
                    "fakeip_range `{}` 的主机位不为 0",
                    settings.fakeip_range
                )));
            }
            if address.is_loopback() || address.octets()[0] == 0 {
                return Err(invalid("fakeip_range 不能是 0.0.0.0/8 或回环网段"));
            }
        }
        _ => {
            return Err(invalid(format!(
                "fakeip_range `{}` 无效：要 IPv4 网段，前缀长度 8 到 24",
                settings.fakeip_range
            )));
        }
    }
    if !settings.resolver.trim().is_empty() {
        parse_resolver(&settings.resolver).map_err(invalid)?;
    }
    if settings.mixed_port == 0 || reserved.contains(&settings.mixed_port) {
        return Err(invalid(format!(
            "mixed_port {} 不可用（0 或已被 atom 的其他端口占用）",
            settings.mixed_port
        )));
    }
    Ok(())
}

/// Every member of `members` exists (a node or a group), once, and is not
/// `owner` itself.
fn check_members(
    owner: &str,
    members: &[String],
    nodes: &BTreeSet<&str>,
    groups: &BTreeSet<&str>,
) -> Result<(), Refusal> {
    let mut seen = BTreeSet::new();
    for member in members {
        if member == owner {
            return Err(invalid(format!("{owner} 不能包含自己")));
        }
        if !nodes.contains(member.as_str()) && !groups.contains(member.as_str()) {
            return Err(invalid(format!(
                "{owner} 的成员 `{member}` 不存在（直连不能做成员）"
            )));
        }
        if !seen.insert(member.as_str()) {
            return Err(invalid(format!("{owner} 的成员 `{member}` 重复")));
        }
    }
    Ok(())
}

impl ProxyState {
    pub(crate) fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|node| node.id == id)
    }

    pub(crate) fn group(&self, id: &str) -> Option<&Group> {
        self.groups.iter().find(|group| group.id == id)
    }

    /// Whether a rule may proxy to `id`: a group or Final.
    pub(crate) fn is_target(&self, id: &str) -> bool {
        id == FINAL || self.group(id).is_some()
    }

    fn taken(&self, id: &str) -> bool {
        self.node(id).is_some() || self.group(id).is_some()
    }

    /// The whole state is consistent. `reserved` are the ports atom's other
    /// listeners use.
    pub(crate) fn validate(&self, reserved: &[u16]) -> Result<(), Refusal> {
        if self.nodes.len() > MAX_NODES {
            return Err(invalid(format!("节点数超过 {MAX_NODES}")));
        }
        if self.groups.len() > MAX_GROUPS {
            return Err(invalid(format!("节点组数超过 {MAX_GROUPS}")));
        }
        let mut nodes = BTreeSet::new();
        for node in &self.nodes {
            if !is_id(&node.id, "n-") {
                return Err(invalid(format!("节点 ID `{}` 无效", node.id)));
            }
            if !nodes.insert(node.id.as_str()) {
                return Err(invalid(format!("节点 ID `{}` 重复", node.id)));
            }
            check_name("节点", &node.name)?;
            check_outbound(&node.outbound)
                .map_err(|refusal| invalid(format!("节点 {}: {}", node.id, refusal.message)))?;
        }
        let mut groups = BTreeSet::new();
        for group in &self.groups {
            if group.id != DEFAULT_GROUP && !is_id(&group.id, "g-") {
                return Err(invalid(format!("节点组 ID `{}` 无效", group.id)));
            }
            if !groups.insert(group.id.as_str()) {
                return Err(invalid(format!("节点组 ID `{}` 重复", group.id)));
            }
        }
        if !groups.contains(DEFAULT_GROUP) {
            return Err(invalid("内置组“默认代理”不能删除"));
        }
        for group in &self.groups {
            check_name("节点组", &group.name)?;
            check_members(&group.id, &group.members, &nodes, &groups)?;
            match group.kind {
                GroupKind::Selector => {
                    if group.url.is_some() || group.interval.is_some() || group.tolerance.is_some()
                    {
                        return Err(invalid(format!(
                            "{}: selector 没有 url、interval、tolerance",
                            group.id
                        )));
                    }
                    if !group.selected.is_empty() && !group.members.contains(&group.selected) {
                        return Err(invalid(format!(
                            "{}: 选中的 `{}` 不是成员",
                            group.id, group.selected
                        )));
                    }
                }
                GroupKind::Urltest => {
                    if !group.selected.is_empty() {
                        return Err(invalid(format!(
                            "{}: urltest 自动选择，不能指定选中",
                            group.id
                        )));
                    }
                    let url = group.url.as_deref().unwrap_or(DEFAULT_URL);
                    let parsed = url::Url::parse(url)
                        .map_err(|error| invalid(format!("{}: url 无效: {error}", group.id)))?;
                    if !matches!(parsed.scheme(), "http" | "https") {
                        return Err(invalid(format!("{}: url 只支持 http 和 https", group.id)));
                    }
                    check_interval(group.interval.as_deref().unwrap_or(DEFAULT_INTERVAL))
                        .map_err(|refusal| invalid(format!("{}: {}", group.id, refusal.message)))?;
                }
            }
        }
        self.check_cycles()?;
        let final_group = &self.final_group;
        check_members(FINAL, &final_group.members, &nodes, &groups)?;
        if final_group.members.is_empty() {
            if !final_group.selected.is_empty() {
                return Err(invalid("Final 没有成员，不能有选中项"));
            }
        } else if !final_group.members.contains(&final_group.selected) {
            return Err(invalid(format!(
                "Final 选中的 `{}` 不是 Final 的成员",
                final_group.selected
            )));
        }
        check_settings(&self.settings, reserved)
    }

    /// Groups may contain groups, but never themselves through others.
    fn check_cycles(&self) -> Result<(), Refusal> {
        let edges: BTreeMap<&str, Vec<&str>> = self
            .groups
            .iter()
            .map(|group| {
                let inner = group
                    .members
                    .iter()
                    .map(String::as_str)
                    .filter(|member| self.group(member).is_some())
                    .collect();
                (group.id.as_str(), inner)
            })
            .collect();
        // 0 unvisited, 1 on the path, 2 done.
        let mut mark: BTreeMap<&str, u8> = BTreeMap::new();
        fn visit<'a>(
            id: &'a str,
            edges: &BTreeMap<&'a str, Vec<&'a str>>,
            mark: &mut BTreeMap<&'a str, u8>,
            path: &mut Vec<&'a str>,
        ) -> Result<(), Vec<&'a str>> {
            match mark.get(id) {
                Some(2) => return Ok(()),
                Some(1) => {
                    let start = path.iter().position(|step| *step == id).unwrap_or(0);
                    let mut cycle = path[start..].to_vec();
                    cycle.push(id);
                    return Err(cycle);
                }
                _ => {}
            }
            mark.insert(id, 1);
            path.push(id);
            for next in edges.get(id).into_iter().flatten() {
                visit(next, edges, mark, path)?;
            }
            path.pop();
            mark.insert(id, 2);
            Ok(())
        }
        for id in edges.keys() {
            let mut path = Vec::new();
            visit(id, &edges, &mut mark, &mut path)
                .map_err(|cycle| invalid(format!("节点组成环：{}", cycle.join(" → "))))?;
        }
        Ok(())
    }

    /// Groups (and Final) with no member: their traffic is refused.
    pub(crate) fn empty_groups(&self) -> Vec<String> {
        let mut empty: Vec<String> = self
            .groups
            .iter()
            .filter(|group| group.members.is_empty())
            .map(|group| group.id.clone())
            .collect();
        if self.final_group.members.is_empty() {
            empty.push(FINAL.to_owned());
        }
        empty
    }

    /// The groups whose members include `id`.
    pub(crate) fn groups_containing(&self, id: &str) -> Vec<String> {
        self.groups
            .iter()
            .filter(|group| group.members.iter().any(|member| member == id))
            .map(|group| group.id.clone())
            .collect()
    }

    /// Drops `id` from every group and from Final; a selection that pointed
    /// at it falls back (a selector to its first member, Final to
    /// "默认代理" when it is a member, else its first member).
    fn forget(&mut self, id: &str) {
        for group in &mut self.groups {
            group.members.retain(|member| member != id);
            if group.selected == id {
                group.selected.clear();
            }
        }
        let final_group = &mut self.final_group;
        final_group.members.retain(|member| member != id);
        if final_group.selected == id || !final_group.members.contains(&final_group.selected) {
            final_group.selected = if final_group.members.iter().any(|m| m == DEFAULT_GROUP) {
                DEFAULT_GROUP.to_owned()
            } else {
                final_group.members.first().cloned().unwrap_or_default()
            };
        }
    }

    // ---- changes (each returns the next state's new pieces) --------------

    pub(crate) fn add_nodes(&mut self, imported: Vec<(String, Map<String, Value>)>) -> Vec<Node> {
        let mut added = Vec::new();
        for (name, outbound) in imported {
            let id = crate::atom_rules::new_id("n-", &|id| self.taken(id));
            let node = Node { id, name, outbound };
            self.nodes.push(node.clone());
            added.push(node);
        }
        added
    }

    pub(crate) fn update_node(
        &mut self,
        id: &str,
        name: Option<String>,
        outbound: Option<Map<String, Value>>,
    ) -> Result<Node, Refusal> {
        let node = self
            .nodes
            .iter_mut()
            .find(|node| node.id == id)
            .ok_or_else(|| Refusal::new(404, format!("节点 `{id}` 不存在")))?;
        if let Some(name) = name {
            node.name = name;
        }
        if let Some(outbound) = outbound {
            node.outbound = outbound;
        }
        Ok(node.clone())
    }

    /// Removes a node; groups and Final drop it from their members.
    pub(crate) fn remove_node(&mut self, id: &str) -> Result<(), Refusal> {
        let before = self.nodes.len();
        self.nodes.retain(|node| node.id != id);
        if self.nodes.len() == before {
            return Err(Refusal::new(404, format!("节点 `{id}` 不存在")));
        }
        self.forget(id);
        Ok(())
    }

    fn group_from(id: String, input: GroupInput) -> Group {
        let urltest = input.kind == GroupKind::Urltest;
        Group {
            id,
            name: input.name,
            kind: input.kind,
            members: input.members,
            selected: input.selected,
            url: if urltest {
                Some(input.url.unwrap_or_else(|| DEFAULT_URL.to_owned()))
            } else {
                input.url
            },
            interval: if urltest {
                Some(
                    input
                        .interval
                        .unwrap_or_else(|| DEFAULT_INTERVAL.to_owned()),
                )
            } else {
                input.interval
            },
            tolerance: if urltest {
                Some(input.tolerance.unwrap_or(DEFAULT_TOLERANCE))
            } else {
                input.tolerance
            },
        }
    }

    /// Adds a group; it joins Final too.
    pub(crate) fn add_group(&mut self, input: GroupInput) -> Group {
        let id = crate::atom_rules::new_id("g-", &|id| self.taken(id));
        let group = Self::group_from(id, input);
        self.groups.push(group.clone());
        self.final_group.members.push(group.id.clone());
        group
    }

    pub(crate) fn update_group(&mut self, id: &str, input: GroupInput) -> Result<Group, Refusal> {
        let at = self
            .groups
            .iter()
            .position(|group| group.id == id)
            .ok_or_else(|| Refusal::new(404, format!("节点组 `{id}` 不存在")))?;
        let group = Self::group_from(id.to_owned(), input);
        self.groups[at] = group.clone();
        Ok(group)
    }

    /// Removes a group: other groups and Final drop it. The rules that
    /// proxy to it are the owner's business.
    pub(crate) fn remove_group(&mut self, id: &str) -> Result<(), Refusal> {
        if id == DEFAULT_GROUP {
            return Err(invalid("内置组“默认代理”不能删除"));
        }
        let before = self.groups.len();
        self.groups.retain(|group| group.id != id);
        if self.groups.len() == before {
            return Err(Refusal::new(404, format!("节点组 `{id}` 不存在")));
        }
        self.forget(id);
        Ok(())
    }

    /// Records the selection of a selector group or Final.
    pub(crate) fn select(&mut self, id: &str, member: &str) -> Result<(), Refusal> {
        if id == FINAL {
            if !self.final_group.members.iter().any(|m| m == member) {
                return Err(invalid(format!("`{member}` 不是 Final 的成员")));
            }
            self.final_group.selected = member.to_owned();
            return Ok(());
        }
        let group = self
            .groups
            .iter_mut()
            .find(|group| group.id == id)
            .ok_or_else(|| Refusal::new(404, format!("节点组 `{id}` 不存在")))?;
        if group.kind != GroupKind::Selector {
            return Err(invalid(format!("{id} 是 urltest，自动选择，不能手动切换")));
        }
        if !group.members.iter().any(|m| m == member) {
            return Err(invalid(format!("`{member}` 不是 {id} 的成员")));
        }
        group.selected = member.to_owned();
        Ok(())
    }

    /// The member a selector group (or Final) currently has selected.
    pub(crate) fn selection(&self, id: &str) -> Option<String> {
        if id == FINAL {
            return Some(self.final_group.selected.clone());
        }
        let group = self.group(id)?;
        (group.kind == GroupKind::Selector).then(|| {
            if group.selected.is_empty() {
                group.members.first().cloned().unwrap_or_default()
            } else {
                group.selected.clone()
            }
        })
    }
}

/// Loads the state; a missing file is a new installation (not written until
/// the first change). A file that cannot be read or does not validate stops
/// the configuration, like the rule table.
pub(crate) fn load(root: &Path, reserved: &[u16]) -> Result<ProxyState, String> {
    let path = root.join(PROXY_FILE);
    let state = match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice::<ProxyState>(&bytes)
            .map_err(|error| format!("{}: {error}", path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ProxyState::default(),
        Err(error) => return Err(format!("{}: {error}", path.display())),
    };
    state
        .validate(reserved)
        .map_err(|refusal| format!("{}: {}", path.display(), refusal.message))?;
    Ok(state)
}

#[cfg(test)]
thread_local! {
    /// Tests: make the next [`save`] on this thread fail.
    pub(crate) static FAIL_NEXT_SAVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Writes the state; the file holds node credentials, so it is owner-only
/// (0600).
pub(crate) fn save(root: &Path, state: &ProxyState) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_NEXT_SAVE.with(|fail| fail.replace(false)) {
        return Err(std::io::Error::other("injected save failure"));
    }
    let mut bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    crate::runtime_snapshot::write_durably_private(&root.join(PROXY_FILE), &bytes)
}

#[cfg(test)]
#[path = "atom_proxy_tests.rs"]
mod tests;
