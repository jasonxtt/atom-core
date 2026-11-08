//! atom fork: the user rule table (atom `docs/design.md` §3.1, §4).
//!
//! An ordered list of rules. The first enabled rule whose conditions hold
//! decides the query: proxy through a group (a FakeIP from sing-box, the
//! group sent as EDNS0 65001 SET), direct (the domestic DNS, real addresses)
//! or block (an empty answer). A query no rule decides falls through to the
//! original domestic/foreign judgment.
//!
//! Conditions: the name conditions (`domain`, `suffix`, `keyword`, `regex`,
//! `ruleset`) are one class and the `client` addresses another. Within a
//! class any entry may match; every class a rule uses must match. A rule
//! with a `client` condition can only be direct or block. `ip_cidr` rules
//! are matched by sing-box (design §4.6): they stand alone (no name or
//! client condition), take no part in the DNS table, and are compiled into
//! the generated sing-box route rules in table order ([`singbox`]).
//!
//! With a `singbox` section in the plugin arguments the table also owns the
//! proxy side (nodes, groups, Final, settings: [`crate::atom_proxy`]): a
//! proxy rule's group must exist, and a change that alters the generated
//! sing-box configuration is applied to sing-box before it is saved.
//!
//! The `atom_rules` plugin is a fixture: it only marks the query (one fast
//! mark per action) and, for proxy, records the group in
//! `ExecutionState::outbound`; the configuration dispatches on the marks.
//! The table lives in `webinfo/atom_rules.json` and the custom rulesets in
//! `webinfo/atom_rulesets.json` (lists in
//! `webinfo/atom_rulesets/<id>-<revision>.txt`; a new list is a new file,
//! switched to by the metadata write).
//! Every change is validated and compiled first, written to disk second, and
//! published last, as one whole table ([`Live`]): a query sees either the old
//! or the new table, never a mix, and DNS is not interrupted.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use atomdns_matcher_core::{IpPrefixList, MixSet, MixSetBuilder};
use atomdns_sequence_core::{
    ExecutionState, Executor, ExecutorError, ExecutorOutcome, RoutingField, StateMutation,
};
use serde::{Deserialize, Serialize};

use crate::atom_proxy::ProxyState;
use crate::managed::DomainSetHandle;
use crate::rule_sources::Live;

mod singbox;
pub(crate) use singbox::last_apply;

pub(crate) const RULES_FILE: &str = "webinfo/atom_rules.json";
pub(crate) const RULESETS_FILE: &str = "webinfo/atom_rulesets.json";
pub(crate) const RULESET_DIR: &str = "webinfo/atom_rulesets";
/// The most entries one rule's inline conditions or one local list may hold.
const MAX_LIST_RULES: usize = crate::rule_formats::MAX_RULES;
/// sing-box trims the tag; a short, printable tag keeps the option small.
const MAX_GROUP_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// Model (the JSON of the API and of the files)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Match {
    /// Exact names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) domain: Vec<String>,
    /// The name and its subdomains.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) suffix: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) keyword: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) regex: Vec<String>,
    /// Builtin set names or custom ruleset IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ruleset: Vec<String>,
    /// Client addresses or prefixes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) client: Vec<String>,
    /// Target IP prefixes (matched by sing-box; a rule with them has no
    /// other condition).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ip_cidr: Vec<String>,
}

impl Match {
    fn has_name(&self) -> bool {
        !(self.domain.is_empty()
            && self.suffix.is_empty()
            && self.keyword.is_empty()
            && self.regex.is_empty()
            && self.ruleset.is_empty())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Action {
    /// `group_id` is a sing-box outbound tag: a node group (`g-*`) or
    /// Final (`final`). Without a proxy side (no `singbox` section) only its
    /// form is checked.
    Proxy {
        group_id: String,
    },
    Direct,
    Block,
}

impl Action {
    fn name(&self) -> &'static str {
        match self {
            Self::Proxy { .. } => "proxy",
            Self::Direct => "direct",
            Self::Block => "block",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub(crate) id: String,
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) remark: String,
    #[serde(rename = "match")]
    pub(crate) matches: Match,
    pub(crate) action: Action,
}

/// The editable part of a rule (create and replace).
#[derive(Clone, Debug)]
pub(crate) struct RuleInput {
    pub(crate) enabled: bool,
    pub(crate) remark: String,
    pub(crate) matches: Match,
    pub(crate) action: Action,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    version: u64,
    rules: Vec<Rule>,
}

/// Where a custom ruleset's names come from.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub(crate) enum Source {
    /// A downloaded list (text, YAML, JSON, SRS, `.dat` with a category,
    /// `.mrs`), converted once to the local list form.
    Remote {
        url: String,
        #[serde(default = "format_default")]
        format: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        category: String,
    },
    /// A list edited through the API.
    Local,
}

fn format_default() -> String {
    "auto".to_owned()
}

// No `deny_unknown_fields`: serde does not support it beside `flatten`
// (`Source` itself refuses unknown fields).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct Ruleset {
    pub(crate) id: String,
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) source: Source,
    #[serde(default)]
    pub(crate) rule_count: usize,
    /// Unix seconds of the last successful download or edit; 0: never.
    #[serde(default)]
    pub(crate) updated_at: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) last_error: String,
    /// The list's revision, its file `<id>-<revision>.txt`. Every new list
    /// is a new revision; 0: no list yet (a remote set never downloaded),
    /// the list is empty and there is no file.
    #[serde(default)]
    pub(crate) revision: u64,
}

/// A builtin set the configuration offers to rules by name.
#[derive(Clone)]
pub(crate) enum BuiltinSet {
    /// A `domain_mapper` provider: the fast mark the mapper sets for it.
    Mark(u64),
    /// A set the host matches directly (`adguard_rule`, `domain_set`).
    Handle(DomainSetHandle),
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) status: u16,
    pub(crate) message: String,
    /// The current table version (stale-version conflicts).
    pub(crate) version: Option<u64>,
    /// The rules that block a deletion.
    pub(crate) rules: Vec<String>,
}

impl Refusal {
    pub(crate) fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            version: None,
            rules: Vec::new(),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self::new(400, message)
    }
}

// ---------------------------------------------------------------------------
// Compiled table
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum SetRef {
    Mark(u64),
    Handle(DomainSetHandle),
    List(Rc<MixSet>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Proxy(Arc<str>),
    Direct,
    Block,
}

struct Compiled {
    index: usize,
    inline: Option<MixSet>,
    sets: Vec<SetRef>,
    clients: Option<IpPrefixList>,
    verdict: Verdict,
    /// The audit label (`domain_set`) and the matched-rule source.
    label: String,
    source: String,
}

/// One query as the rules see it.
pub(crate) struct Query<'a> {
    /// The hostname-grammar name (what `domain_set`s match), if it is one.
    hostname: Option<&'a str>,
    /// The presentation-form name (lists, `adguard_rule`).
    presentation: Option<&'a str>,
    fast_flags: u64,
    client: Option<IpAddr>,
}

impl Compiled {
    fn matches(&self, query: &Query<'_>) -> bool {
        if self.inline.is_some() || !self.sets.is_empty() {
            let name = query.presentation;
            let inline = self
                .inline
                .as_ref()
                .is_some_and(|set| name.is_some_and(|name| set.is_match(name)));
            let hit = inline
                || self.sets.iter().any(|set| match set {
                    SetRef::Mark(mask) => query.fast_flags & mask != 0,
                    SetRef::List(list) => name.is_some_and(|name| list.is_match(name)),
                    SetRef::Handle(handle) => {
                        let name = if handle.uses_presentation_name() {
                            query.presentation
                        } else {
                            query.hostname
                        };
                        name.is_some_and(|name| handle.matches(name))
                    }
                });
            if !hit {
                return false;
            }
        }
        match &self.clients {
            Some(clients) => query.client.is_some_and(|ip| clients.contains(ip)),
            None => true,
        }
    }
}

#[derive(Default)]
struct Table {
    rules: Vec<Compiled>,
}

impl Table {
    fn first(&self, query: &Query<'_>) -> Option<&Compiled> {
        self.rules.iter().find(|rule| rule.matches(query))
    }
}

// ---------------------------------------------------------------------------
// The rule table owner
// ---------------------------------------------------------------------------

/// The fast marks the plugin sets, one per action (`args.marks`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Marks {
    pub(crate) proxy: u8,
    pub(crate) direct: u8,
    pub(crate) block: u8,
}

impl Marks {
    fn mask(self, verdict: &Verdict) -> u64 {
        1u64 << match verdict {
            Verdict::Proxy(_) => self.proxy,
            Verdict::Direct => self.direct,
            Verdict::Block => self.block,
        }
    }
}

#[derive(Clone)]
pub(crate) struct State {
    version: u64,
    rules: Vec<Rule>,
    rulesets: Vec<Ruleset>,
    lists: BTreeMap<String, Rc<MixSet>>,
}

/// The rule table of one compiled configuration.
pub(crate) struct AtomRules {
    /// The configuration root; empty for an in-memory compile (nothing is
    /// read or written).
    root: PathBuf,
    marks: Marks,
    /// The `domain_mapper` whose marks the [`BuiltinSet::Mark`] sets are.
    pub(crate) mapper: Option<String>,
    /// SOCKS5 proxy for ruleset downloads (`proxy: $main_proxy`).
    pub(crate) socks5: String,
    builtin: Vec<(String, BuiltinSet)>,
    state: RefCell<State>,
    table: Live<Table>,
    /// The newest download started per ruleset (in memory): only that one
    /// may install its result, so overlapping refreshes cannot publish an
    /// older snapshot over a newer one.
    downloads: RefCell<BTreeMap<String, u64>>,
    next_download: std::cell::Cell<u64>,
    /// The proxy side (`singbox` section); `None`: rules only.
    proxy: Option<singbox::Proxy>,
    /// A change is being applied to sing-box: other changes are refused
    /// until it is saved or rolled back.
    busy: std::cell::Cell<bool>,
}

/// The default table of a new installation (design §4.4). The ads rule
/// needs the `adguard` builtin set; a configuration without it gets the LAN
/// rule alone.
fn default_rules(adguard: bool) -> Vec<Rule> {
    let mut rules = vec![Rule {
        id: "r-lan".to_owned(),
        enabled: true,
        remark: "局域网和私有域名".to_owned(),
        matches: Match {
            suffix: [
                "lan",
                "local",
                "localhost",
                "localdomain",
                "home.arpa",
                "internal",
            ]
            .map(str::to_owned)
            .to_vec(),
            ..Match::default()
        },
        action: Action::Direct,
    }];
    if adguard {
        rules.push(Rule {
            id: "r-ads".to_owned(),
            enabled: true,
            remark: "广告".to_owned(),
            matches: Match {
                ruleset: vec!["adguard".to_owned()],
                ..Match::default()
            },
            action: Action::Block,
        });
    }
    rules
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

pub(crate) fn new_id(prefix: &str, taken: &dyn Fn(&str) -> bool) -> String {
    loop {
        let mut bytes = [0u8; 4];
        if getrandom::fill(&mut bytes).is_err() {
            // Fall back to the clock; the loop still rejects a collision.
            bytes = u32::try_from(now() % i64::from(u32::MAX))
                .unwrap_or(0)
                .to_be_bytes();
        }
        let id = format!(
            "{prefix}{:02x}{:02x}{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        );
        if !taken(&id) {
            return id;
        }
    }
}

/// Reads a local list file: one rule per line in the provider text form
/// (`domain:`, `full:`, `keyword:`, `regexp:`; a bare name is `domain:`).
/// A missing file is an error: a ruleset with a revision has a file.
fn read_list(path: &Path) -> Result<Vec<String>, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

fn list_path(root: &Path, id: &str, revision: u64) -> PathBuf {
    root.join(RULESET_DIR).join(format!("{id}-{revision}.txt"))
}

/// Builds the matcher of a list; the first bad entry is the error.
pub(crate) fn build_list(rules: &[String]) -> Result<MixSet, String> {
    if rules.len() > MAX_LIST_RULES {
        return Err(format!("规则数超过 {MAX_LIST_RULES}"));
    }
    let mut builder = MixSetBuilder::new();
    builder.set_default("domain");
    for rule in rules {
        builder
            .add(rule)
            .map_err(|error| format!("无效的规则 `{rule}`: {error}"))?;
    }
    Ok(builder.finish())
}

/// One name entry of a rule: non-empty, no whitespace, no type prefix.
fn name_entry(kind: &str, value: &str) -> Result<String, Refusal> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Refusal::invalid(format!("{kind} 条目不能为空")));
    }
    if value.chars().any(char::is_whitespace) {
        return Err(Refusal::invalid(format!("{kind} 条目 `{value}` 含有空白")));
    }
    if kind != "regex" && !value.is_ascii() {
        return Err(Refusal::invalid(format!(
            "{kind} 条目 `{value}` 不是 ASCII（国际化域名请写成 punycode）"
        )));
    }
    // A trailing dot is the root of a name, not part of it (but is part of
    // a regex or keyword).
    Ok(if matches!(kind, "domain" | "suffix") {
        value.trim_end_matches('.').to_owned()
    } else {
        value.to_owned()
    })
}

fn parse_client(value: &str) -> Result<(IpAddr, u8), Refusal> {
    crate::rule_formats::parse_prefix(value.trim())
        .ok_or_else(|| Refusal::invalid(format!("client 条目 `{value}` 不是 IP 地址或网段")))
}

/// A proxy rule's group: a group of `proxy` or Final; without a proxy
/// side, any well-formed tag.
fn validate_group(group: &str, proxy: Option<&ProxyState>) -> Result<(), Refusal> {
    if group.trim().is_empty() {
        return Err(Refusal::invalid("代理动作需要 group_id"));
    }
    if group != group.trim() || group.len() > MAX_GROUP_BYTES || group.chars().any(char::is_control)
    {
        return Err(Refusal::invalid(format!(
            "group_id `{group}` 无效：不能有首尾空白或控制字符，最长 {MAX_GROUP_BYTES} 字节"
        )));
    }
    if let Some(proxy) = proxy {
        if !proxy.is_target(group) {
            return Err(Refusal::invalid(format!("节点组 `{group}` 不存在")));
        }
    }
    Ok(())
}

/// An `ip_cidr` entry in its canonical `address/bits` form.
fn ip_entry(value: &str) -> Result<String, Refusal> {
    let (address, bits) = crate::rule_formats::parse_prefix(value.trim())
        .ok_or_else(|| Refusal::invalid(format!("ip_cidr 条目 `{value}` 不是 IP 地址或网段")))?;
    Ok(match address {
        IpAddr::V4(v4) => {
            let masked = if bits == 0 {
                0
            } else {
                u32::from(v4) & (u32::MAX << (32 - u32::from(bits)))
            };
            format!("{}/{bits}", std::net::Ipv4Addr::from(masked))
        }
        IpAddr::V6(v6) => {
            let masked = if bits == 0 {
                0
            } else {
                u128::from(v6) & (u128::MAX << (128 - u32::from(bits)))
            };
            format!("{}/{bits}", std::net::Ipv6Addr::from(masked))
        }
    })
}

/// The enabled `ip_cidr` rules of `rules`, in order: what sing-box matches.
pub(crate) fn ip_rules(rules: &[Rule]) -> Vec<crate::atom_singbox::IpRule> {
    rules
        .iter()
        .filter(|rule| rule.enabled && !rule.matches.ip_cidr.is_empty())
        .map(|rule| crate::atom_singbox::IpRule {
            cidrs: rule
                .matches
                .ip_cidr
                .iter()
                .filter_map(|value| ip_entry(value).ok())
                .collect(),
            action: rule.action.clone(),
        })
        .collect()
}

impl AtomRules {
    /// Loads the table and the custom rulesets from `root` (in memory with
    /// the default table when `root` is empty). Nothing is written: a missing
    /// table file is the default table until the first change saves it.
    pub(crate) fn load(
        root: &Path,
        marks: Marks,
        mapper: Option<String>,
        socks5: String,
        builtin: Vec<(String, BuiltinSet)>,
        singbox: Option<crate::atom_singbox::Host>,
    ) -> Result<Self, String> {
        let adguard = builtin.iter().any(|(name, _)| name == "adguard");
        let (version, rules) = if root.as_os_str().is_empty() {
            (0, default_rules(adguard))
        } else {
            let path = root.join(RULES_FILE);
            match std::fs::read(&path) {
                Ok(bytes) => {
                    let file: RulesFile = serde_json::from_slice(&bytes)
                        .map_err(|error| format!("{}: {error}", path.display()))?;
                    (file.version, file.rules)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    (0, default_rules(adguard))
                }
                Err(error) => return Err(format!("{}: {error}", path.display())),
            }
        };
        let mut rulesets = Vec::new();
        let mut lists = BTreeMap::new();
        if !root.as_os_str().is_empty() {
            let path = root.join(RULESETS_FILE);
            match std::fs::read(&path) {
                Ok(bytes) => {
                    rulesets = serde_json::from_slice(&bytes)
                        .map_err(|error| format!("{}: {error}", path.display()))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("{}: {error}", path.display())),
            }
            for set in &rulesets {
                let set: &Ruleset = set;
                // Revision 0 is only a remote set that never downloaded a
                // list; anything else claiming no list is not trusted (it
                // would load as an empty set and match nothing).
                if set.revision == 0 {
                    let why = if matches!(set.source, Source::Local) {
                        "本地规则集一定有列表".to_owned()
                    } else if set.rule_count != 0 {
                        format!("rule_count 为 {}", set.rule_count)
                    } else {
                        String::new()
                    };
                    if !why.is_empty() {
                        return Err(format!(
                            "{}: 规则集 `{}` 的状态不一致：revision 为 0（没有列表文件），但{why}",
                            path.display(),
                            set.id
                        ));
                    }
                }
                let list = if set.revision == 0 {
                    MixSetBuilder::new().finish()
                } else {
                    let file = list_path(root, &set.id, set.revision);
                    build_list(&read_list(&file)?)
                        .map_err(|error| format!("{}: {error}", file.display()))?
                };
                lists.insert(set.id.clone(), Rc::new(list));
            }
        }
        let rules_owner = Self {
            root: root.to_path_buf(),
            marks,
            mapper,
            socks5,
            builtin,
            state: RefCell::new(State {
                version,
                rules,
                rulesets,
                lists,
            }),
            table: Live::new(Table::default()),
            downloads: RefCell::new(BTreeMap::new()),
            next_download: std::cell::Cell::new(0),
            proxy: match singbox {
                Some(host) => Some(singbox::Proxy::load(root, host)?),
                None => None,
            },
            busy: std::cell::Cell::new(false),
        };
        let table = {
            let state = rules_owner.state.borrow();
            let proxy = rules_owner.proxy_state();
            rules_owner
                .compile(&state, proxy.as_ref())
                .map_err(|refusal| {
                    format!("{}: {}", root.join(RULES_FILE).display(), refusal.message)
                })?
        };
        rules_owner.table.replace(Rc::new(table));
        Ok(rules_owner)
    }

    pub(crate) fn executor(self: &Rc<Self>) -> Box<dyn Executor> {
        Box::new(RulesExecutor {
            rules: Rc::clone(self),
        })
    }

    fn builtin(&self, name: &str) -> Option<&BuiltinSet> {
        self.builtin
            .iter()
            .find(|(builtin, _)| builtin == name)
            .map(|(_, set)| set)
    }

    /// Validates one rule against `state` (and the groups of `proxy`) and
    /// compiles it; an `ip_cidr` rule is validated only (sing-box matches
    /// it).
    fn compile_rule(
        &self,
        state: &State,
        proxy: Option<&ProxyState>,
        index: usize,
        rule: &Rule,
    ) -> Result<Option<Compiled>, Refusal> {
        let at = |refusal: Refusal| Refusal {
            message: format!("规则 {}: {}", rule.id, refusal.message),
            ..refusal
        };
        let m = &rule.matches;
        if !m.ip_cidr.is_empty() {
            if self.proxy.is_none() {
                return Err(at(Refusal::invalid(
                    "ip_cidr 条件由 sing-box 匹配，需要配置里的 singbox 段",
                )));
            }
            if m.has_name() || !m.client.is_empty() {
                return Err(at(Refusal::invalid(
                    "ip_cidr 规则只能单独使用，不能再带域名或 client 条件",
                )));
            }
            if m.ip_cidr.len() > MAX_LIST_RULES {
                return Err(at(Refusal::invalid(format!(
                    "ip_cidr 条目超过 {MAX_LIST_RULES}"
                ))));
            }
            for value in &m.ip_cidr {
                ip_entry(value).map_err(at)?;
            }
            if let Action::Proxy { group_id } = &rule.action {
                validate_group(group_id, proxy).map_err(at)?;
            }
            return Ok(None);
        }
        if !m.has_name() && m.client.is_empty() {
            return Err(at(Refusal::invalid("规则至少要有一个匹配条件")));
        }
        let mut inline = Vec::new();
        for (kind, prefix, values) in [
            ("domain", "full:", &m.domain),
            ("suffix", "domain:", &m.suffix),
            ("keyword", "keyword:", &m.keyword),
            ("regex", "regexp:", &m.regex),
        ] {
            for value in values {
                inline.push(format!("{prefix}{}", name_entry(kind, value).map_err(at)?));
            }
        }
        let inline = if inline.is_empty() {
            None
        } else {
            Some(build_list(&inline).map_err(|message| at(Refusal::invalid(message)))?)
        };
        let mut sets = Vec::new();
        for name in &m.ruleset {
            let set = if let Some(builtin) = self.builtin(name) {
                match builtin {
                    BuiltinSet::Mark(mask) => SetRef::Mark(*mask),
                    BuiltinSet::Handle(handle) => SetRef::Handle(handle.clone()),
                }
            } else if let Some(list) = state.lists.get(name) {
                SetRef::List(Rc::clone(list))
            } else {
                return Err(at(Refusal::invalid(format!("规则集 `{name}` 不存在"))));
            };
            sets.push(set);
        }
        let clients = if m.client.is_empty() {
            None
        } else {
            let mut list = IpPrefixList::new();
            for value in &m.client {
                let (address, bits) = parse_client(value).map_err(at)?;
                list.append(address, bits);
            }
            list.rebuild();
            Some(list)
        };
        let verdict = match &rule.action {
            Action::Proxy { group_id } => {
                // sing-box binds a group per name, not per client: a client
                // rule could only bind the group for every client (a cached
                // FakeIP sends no CLEAR), so proxy is the same for everyone.
                if !m.client.is_empty() {
                    return Err(at(Refusal::invalid(
                        "带 client 条件的规则只能直连或屏蔽：sing-box 只按域名绑定出站组、不区分客户端，代理规则对所有客户端必须一样",
                    )));
                }
                validate_group(group_id, proxy).map_err(at)?;
                Verdict::Proxy(Arc::from(group_id.as_str()))
            }
            Action::Direct => Verdict::Direct,
            Action::Block => Verdict::Block,
        };
        let shown = if rule.remark.trim().is_empty() {
            rule.id.as_str()
        } else {
            rule.remark.trim()
        };
        Ok(Some(Compiled {
            index,
            inline,
            sets,
            clients,
            verdict,
            label: format!("规则:{}", shown.replace('|', "/")),
            source: format!("atom_rule:{}", rule.id),
        }))
    }

    /// Compiles every enabled rule of `state`. A disabled rule is still
    /// validated, so it can be enabled later without surprises.
    fn compile(&self, state: &State, proxy: Option<&ProxyState>) -> Result<Table, Refusal> {
        let mut ids = std::collections::BTreeSet::new();
        let mut rules = Vec::new();
        for (index, rule) in state.rules.iter().enumerate() {
            if !ids.insert(rule.id.as_str()) {
                return Err(Refusal::invalid(format!("规则 ID `{}` 重复", rule.id)));
            }
            let compiled = self.compile_rule(state, proxy, index, rule)?;
            if let (true, Some(compiled)) = (rule.enabled, compiled) {
                rules.push(compiled);
            }
        }
        Ok(Table { rules })
    }

    /// Validates `next`, writes what changed, and publishes it. A change of
    /// the IP rules goes through [`Self::commit_rules`] instead (sing-box
    /// first).
    fn commit(&self, next: State, rules: bool, rulesets: bool) -> Result<(), Refusal> {
        if self.busy.get() {
            return Err(singbox::busy());
        }
        if self.proxy.is_some() && ip_rules(&next.rules) != ip_rules(&self.state.borrow().rules) {
            return Err(Refusal::new(
                500,
                "内部错误：改动 IP 规则需要先应用 sing-box 配置",
            ));
        }
        let proxy = self.proxy_state();
        let table = self.compile(&next, proxy.as_ref())?;
        if !self.root.as_os_str().is_empty() {
            let failed = |error: std::io::Error| Refusal::new(500, format!("保存失败: {error}"));
            if rules {
                self.write_rules_file(&next).map_err(failed)?;
            }
            if rulesets {
                let mut bytes = serde_json::to_vec_pretty(&next.rulesets)
                    .map_err(|error| Refusal::new(500, error.to_string()))?;
                bytes.push(b'\n');
                crate::runtime_snapshot::write_durably(&self.root.join(RULESETS_FILE), &bytes)
                    .map_err(failed)?;
            }
        }
        *self.state.borrow_mut() = next;
        self.table.replace(Rc::new(table));
        Ok(())
    }

    fn write_rules_file(&self, state: &State) -> std::io::Result<()> {
        let file = RulesFile {
            version: state.version,
            rules: state.rules.clone(),
        };
        let mut bytes = serde_json::to_vec_pretty(&file).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        crate::runtime_snapshot::write_durably(&self.root.join(RULES_FILE), &bytes)
    }

    fn check_version(state: &State, version: Option<u64>) -> Result<(), Refusal> {
        match version {
            Some(version) if version != state.version => Err(Refusal {
                version: Some(state.version),
                ..Refusal::new(
                    409,
                    format!(
                        "规则表已被修改（当前版本 {}，请求的版本 {version}），请刷新后重试",
                        state.version
                    ),
                )
            }),
            _ => Ok(()),
        }
    }

    fn position(state: &State, id: &str) -> Result<usize, Refusal> {
        state
            .rules
            .iter()
            .position(|rule| rule.id == id)
            .ok_or_else(|| Refusal::new(404, format!("规则 `{id}` 不存在")))
    }

    /// Where a rule placed `before`/`after` another goes (`None`: the end).
    fn anchor(
        state: &State,
        before: Option<&str>,
        after: Option<&str>,
    ) -> Result<Option<usize>, Refusal> {
        match (before, after) {
            (Some(_), Some(_)) => Err(Refusal::invalid("before_id 和 after_id 只能给一个")),
            (Some(id), None) => Self::position(state, id).map(Some),
            (None, Some(id)) => Self::position(state, id).map(|at| Some(at + 1)),
            (None, None) => Ok(None),
        }
    }

    // ---- rules ----------------------------------------------------------

    pub(crate) fn rules(&self) -> (u64, Vec<Rule>) {
        let state = self.state.borrow();
        (state.version, state.rules.clone())
    }

    #[cfg(test)]
    pub(crate) fn create(
        &self,
        input: RuleInput,
        version: Option<u64>,
        before: Option<&str>,
        after: Option<&str>,
    ) -> Result<(u64, Rule), Refusal> {
        let (next, done) = self.plan_create(input, version, before, after)?;
        self.commit(next, true, false)?;
        Ok(done)
    }

    #[cfg(test)]
    pub(crate) fn update(
        &self,
        id: &str,
        input: RuleInput,
        version: Option<u64>,
    ) -> Result<(u64, Rule), Refusal> {
        let (next, done) = self.plan_update(id, input, version)?;
        self.commit(next, true, false)?;
        Ok(done)
    }

    #[cfg(test)]
    pub(crate) fn delete(&self, id: &str, version: Option<u64>) -> Result<u64, Refusal> {
        let (next, done) = self.plan_delete(id, version)?;
        self.commit(next, true, false)?;
        Ok(done)
    }

    #[cfg(test)]
    pub(crate) fn move_rule(
        &self,
        id: &str,
        before: Option<&str>,
        after: Option<&str>,
        version: u64,
    ) -> Result<u64, Refusal> {
        let (next, done) = self.plan_move(id, before, after, version)?;
        self.commit(next, true, false)?;
        Ok(done)
    }

    // The four methods above are the synchronous form the tests use; the
    // plans build the next state, and the API commits it with
    // `commit_rules` (sing-box first when the IP rules change).

    pub(crate) fn plan_create(
        &self,
        input: RuleInput,
        version: Option<u64>,
        before: Option<&str>,
        after: Option<&str>,
    ) -> Result<(State, (u64, Rule)), Refusal> {
        let mut next = self.state.borrow().clone();
        Self::check_version(&next, version)?;
        let at = Self::anchor(&next, before, after)?;
        let id = new_id("r-", &|id| next.rules.iter().any(|rule| rule.id == id));
        let rule = Rule {
            id,
            enabled: input.enabled,
            remark: input.remark,
            matches: input.matches,
            action: input.action,
        };
        next.rules
            .insert(at.unwrap_or(next.rules.len()), rule.clone());
        next.version += 1;
        let version = next.version;
        Ok((next, (version, rule)))
    }

    pub(crate) fn plan_update(
        &self,
        id: &str,
        input: RuleInput,
        version: Option<u64>,
    ) -> Result<(State, (u64, Rule)), Refusal> {
        let mut next = self.state.borrow().clone();
        Self::check_version(&next, version)?;
        let at = Self::position(&next, id)?;
        let rule = Rule {
            id: id.to_owned(),
            enabled: input.enabled,
            remark: input.remark,
            matches: input.matches,
            action: input.action,
        };
        next.rules[at] = rule.clone();
        next.version += 1;
        let version = next.version;
        Ok((next, (version, rule)))
    }

    pub(crate) fn plan_delete(
        &self,
        id: &str,
        version: Option<u64>,
    ) -> Result<(State, u64), Refusal> {
        let mut next = self.state.borrow().clone();
        Self::check_version(&next, version)?;
        let at = Self::position(&next, id)?;
        next.rules.remove(at);
        next.version += 1;
        let version = next.version;
        Ok((next, version))
    }

    /// Moves `id` right before `before` or right after `after`. The version
    /// is required: a reorder from a stale view would undo someone else's.
    pub(crate) fn plan_move(
        &self,
        id: &str,
        before: Option<&str>,
        after: Option<&str>,
        version: u64,
    ) -> Result<(State, u64), Refusal> {
        let mut next = self.state.borrow().clone();
        Self::check_version(&next, Some(version))?;
        if before.is_none() && after.is_none() {
            return Err(Refusal::invalid("需要 before_id 或 after_id"));
        }
        if before == Some(id) || after == Some(id) {
            return Err(Refusal::invalid("不能相对自己移动"));
        }
        let from = Self::position(&next, id)?;
        Self::anchor(&next, before, after)?;
        let rule = next.rules.remove(from);
        let to = Self::anchor(&next, before, after)?.unwrap_or(next.rules.len());
        next.rules.insert(to, rule);
        next.version += 1;
        let version = next.version;
        Ok((next, version))
    }

    /// The rule a query for `name` from `client` hits, with its position.
    /// `fast_flags` are the marks the mapper would set for the name.
    pub(crate) fn test(
        &self,
        name: &str,
        client: Option<IpAddr>,
        fast_flags: u64,
    ) -> Option<(usize, Rule)> {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        let query = Query {
            hostname: Some(&name),
            presentation: Some(&name),
            fast_flags,
            client,
        };
        let table = self.table.get();
        let hit = table.first(&query)?;
        let state = self.state.borrow();
        Some((hit.index, state.rules.get(hit.index)?.clone()))
    }

    // ---- rulesets -------------------------------------------------------

    pub(crate) fn builtin_names(&self) -> Vec<String> {
        self.builtin.iter().map(|(name, _)| name.clone()).collect()
    }

    pub(crate) fn rulesets(&self) -> Vec<Ruleset> {
        self.state.borrow().rulesets.clone()
    }

    pub(crate) fn ruleset(&self, id: &str) -> Option<Ruleset> {
        self.state
            .borrow()
            .rulesets
            .iter()
            .find(|set| set.id == id)
            .cloned()
    }

    /// The local list of a ruleset as stored.
    pub(crate) fn ruleset_entries(&self, id: &str) -> Result<Vec<String>, Refusal> {
        let Some(set) = self.ruleset(id) else {
            return Err(Refusal::new(404, format!("规则集 `{id}` 不存在")));
        };
        if self.root.as_os_str().is_empty() || set.revision == 0 {
            return Ok(Vec::new());
        }
        read_list(&list_path(&self.root, id, set.revision))
            .map_err(|error| Refusal::new(500, error))
    }

    fn remove_list(&self, id: &str, revision: u64) {
        if !self.root.as_os_str().is_empty() && revision != 0 {
            let _ = std::fs::remove_file(list_path(&self.root, id, revision));
        }
    }

    /// Publishes `next`, in which ruleset `id` moved from revision `old` to
    /// `new` with the list `entries`. The list goes to the new revision's
    /// file first; the metadata write in [`Self::commit`] is the one point
    /// that switches to it, so a failure anywhere leaves the old list and
    /// the old metadata together. The file left behind is removed (the new
    /// one on failure, the old one on success).
    fn commit_list(
        &self,
        next: State,
        id: &str,
        old: u64,
        new: u64,
        entries: &[String],
    ) -> Result<(), Refusal> {
        if !self.root.as_os_str().is_empty() {
            let mut text = entries.join("\n");
            text.push('\n');
            crate::runtime_snapshot::write_durably(
                &list_path(&self.root, id, new),
                text.as_bytes(),
            )
            .map_err(|error| Refusal::new(500, format!("保存失败: {error}")))?;
        }
        if let Err(refusal) = self.commit(next, false, true) {
            self.remove_list(id, new);
            return Err(refusal);
        }
        self.remove_list(id, old);
        Ok(())
    }

    fn check_source(source: &Source) -> Result<(), Refusal> {
        if let Source::Remote {
            url,
            format,
            category,
        } = source
        {
            let parsed = url::Url::parse(url)
                .map_err(|error| Refusal::invalid(format!("url 无效: {error}")))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(Refusal::invalid("url 只支持 http 和 https"));
            }
            let format = crate::rule_formats::Format::parse(format)
                .ok_or_else(|| Refusal::invalid(format!("不支持的 format `{format}`")))?;
            if format == crate::rule_formats::Format::Dat && category.trim().is_empty() {
                return Err(Refusal::invalid(".dat 格式需要 category"));
            }
        }
        Ok(())
    }

    /// Adds a custom ruleset. A local one starts with `entries`; a remote one
    /// starts empty until [`Self::store_download`].
    pub(crate) fn create_ruleset(
        &self,
        name: &str,
        source: Source,
        entries: Vec<String>,
    ) -> Result<Ruleset, Refusal> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Refusal::invalid("规则集需要 name"));
        }
        Self::check_source(&source)?;
        if matches!(source, Source::Remote { .. }) && !entries.is_empty() {
            return Err(Refusal::invalid(
                "远程规则集的内容来自下载，不能直接给 rules",
            ));
        }
        let list = build_list(&entries).map_err(Refusal::invalid)?;
        let mut next = self.state.borrow().clone();
        let id = new_id("rs-", &|id| next.rulesets.iter().any(|set| set.id == id));
        // A local set has its list from the start; a remote one has none
        // until its first download (revision 0).
        let local = matches!(source, Source::Local);
        let set = Ruleset {
            id: id.clone(),
            name: name.to_owned(),
            source,
            rule_count: entries.len(),
            updated_at: if entries.is_empty() { 0 } else { now() },
            last_error: String::new(),
            revision: u64::from(local),
        };
        next.rulesets.push(set.clone());
        next.lists.insert(id.clone(), Rc::new(list));
        if local {
            self.commit_list(next, &id, 0, 1, &entries)?;
        } else {
            self.commit(next, false, true)?;
        }
        Ok(set)
    }

    /// Renames a ruleset, replaces its source, and (local only) its entries.
    pub(crate) fn update_ruleset(
        &self,
        id: &str,
        name: Option<&str>,
        source: Option<Source>,
        entries: Option<Vec<String>>,
    ) -> Result<Ruleset, Refusal> {
        let mut next = self.state.borrow().clone();
        let at = next
            .rulesets
            .iter()
            .position(|set| set.id == id)
            .ok_or_else(|| Refusal::new(404, format!("规则集 `{id}` 不存在")))?;
        let mut set = next.rulesets[at].clone();
        if let Some(name) = name {
            if name.trim().is_empty() {
                return Err(Refusal::invalid("规则集需要 name"));
            }
            name.trim().clone_into(&mut set.name);
        }
        if let Some(source) = source {
            Self::check_source(&source)?;
            if std::mem::discriminant(&source) != std::mem::discriminant(&set.source) {
                return Err(Refusal::invalid("不能改变规则集的类型（remote/local）"));
            }
            set.source = source;
        }
        if let Some(entries) = entries {
            if matches!(set.source, Source::Remote { .. }) {
                return Err(Refusal::invalid(
                    "远程规则集的内容来自下载，不能直接给 rules",
                ));
            }
            let list = build_list(&entries).map_err(Refusal::invalid)?;
            let old = set.revision;
            set.revision = old + 1;
            set.rule_count = entries.len();
            set.updated_at = now();
            next.lists.insert(id.to_owned(), Rc::new(list));
            next.rulesets[at] = set.clone();
            self.commit_list(next, id, old, set.revision, &entries)?;
            return Ok(set);
        }
        next.rulesets[at] = set.clone();
        self.commit(next, false, true)?;
        Ok(set)
    }

    /// Removes a ruleset no rule references (409 lists the rules that do).
    pub(crate) fn delete_ruleset(&self, id: &str) -> Result<(), Refusal> {
        let mut next = self.state.borrow().clone();
        let at = next
            .rulesets
            .iter()
            .position(|set| set.id == id)
            .ok_or_else(|| Refusal::new(404, format!("规则集 `{id}` 不存在")))?;
        let users: Vec<String> = next
            .rules
            .iter()
            .filter(|rule| rule.matches.ruleset.iter().any(|name| name == id))
            .map(|rule| rule.id.clone())
            .collect();
        if !users.is_empty() {
            return Err(Refusal {
                rules: users,
                ..Refusal::new(409, format!("规则集 `{id}` 还被规则引用，请先修改这些规则"))
            });
        }
        let revision = next.rulesets.remove(at).revision;
        next.lists.remove(id);
        self.commit(next, false, true)?;
        self.downloads.borrow_mut().remove(id);
        self.remove_list(id, revision);
        Ok(())
    }

    /// Starts a download of ruleset `id`: the ticket [`Self::store_download`]
    /// needs. A later start makes every earlier ticket stale.
    pub(crate) fn begin_download(&self, id: &str) -> u64 {
        let ticket = self.next_download.get() + 1;
        self.next_download.set(ticket);
        self.downloads.borrow_mut().insert(id.to_owned(), ticket);
        ticket
    }

    /// Installs a converted download (`Ok`) or records why it failed.
    /// Only the newest download started ([`Self::begin_download`]) of a set
    /// that still has the downloaded `source` is installed; any other is
    /// discarded with 409, so neither a slow download of a replaced URL nor
    /// an older overlapping refresh (or its late failure) replaces a newer
    /// result.
    pub(crate) fn store_download(
        &self,
        id: &str,
        source: &Source,
        ticket: u64,
        result: Result<(Vec<String>, MixSet), String>,
    ) -> Result<Ruleset, Refusal> {
        if self.downloads.borrow().get(id) != Some(&ticket) {
            return Err(Refusal::new(
                409,
                format!("规则集 `{id}` 有更新的一次下载，这次下载的结果已丢弃"),
            ));
        }
        let mut next = self.state.borrow().clone();
        let at = next
            .rulesets
            .iter()
            .position(|set| set.id == id)
            .ok_or_else(|| Refusal::new(404, format!("规则集 `{id}` 不存在")))?;
        let mut set = next.rulesets[at].clone();
        if set.source != *source {
            return Err(Refusal::new(
                409,
                format!("规则集 `{id}` 的来源在下载期间被修改，这次下载的结果已丢弃"),
            ));
        }
        match result {
            Ok((entries, list)) => {
                let old = set.revision;
                set.revision = old + 1;
                set.rule_count = entries.len();
                set.updated_at = now();
                set.last_error.clear();
                next.lists.insert(id.to_owned(), Rc::new(list));
                next.rulesets[at] = set.clone();
                self.commit_list(next, id, old, set.revision, &entries)?;
            }
            Err(error) => {
                set.last_error = error;
                next.rulesets[at] = set.clone();
                self.commit(next, false, true)?;
            }
        }
        Ok(set)
    }
}

/// Converts a downloaded list to local list entries (blocking work).
pub(crate) fn convert_download(
    bytes: &[u8],
    format: &str,
    category: &str,
    url: &str,
) -> Result<(Vec<String>, MixSet), String> {
    use crate::rule_formats::Format;
    let format =
        crate::rule_formats::resolve(Format::parse(format).unwrap_or(Format::Auto), bytes, url);
    let entries = match format {
        Format::Srs => {
            atomdns_matcher_core::decode_domain_srs(bytes, true)
                .map_err(|error| format!("无效的 SRS 数据: {error}"))?
                .rules
        }
        Format::Dat | Format::Mrs => {
            crate::rule_binary::parse(
                bytes,
                format == Format::Dat,
                category,
                crate::rule_binary::Want::Domains,
                true,
            )
            .map_err(|error| format!("无效的 {} 数据: {error}", format.as_str()))?
            .domains
        }
        _ => {
            crate::rule_formats::parse(bytes, format, true)
                .map_err(|error| format!("无效的 {} 数据: {error}", format.as_str()))?
                .domains
        }
    };
    if entries.is_empty() {
        return Err("下载内容里没有可用的域名规则".to_owned());
    }
    let list = build_list(&entries)?;
    Ok((entries, list))
}

struct RulesExecutor {
    rules: Rc<AtomRules>,
}

impl Executor for RulesExecutor {
    fn execute(&self, state: &mut ExecutionState) -> Result<ExecutorOutcome, ExecutorError> {
        let table = self.rules.table.get();
        if table.rules.is_empty() {
            return Ok(ExecutorOutcome::Continue);
        }
        let wire = &state.query.question.qname_wire;
        let hostname = crate::matchers::wire_name_to_ascii_domain(wire);
        let presentation = crate::config::presentation_name(wire);
        let query = Query {
            hostname: hostname.as_deref(),
            presentation: presentation.as_deref(),
            fast_flags: state.fast_flags,
            client: state.query.client.peer_ip(),
        };
        let Some(rule) = table.first(&query) else {
            return Ok(ExecutorOutcome::Continue);
        };
        state.apply_mutation(StateMutation::SetFastFlags(
            state.fast_flags | self.rules.marks.mask(&rule.verdict),
        ));
        if let Verdict::Proxy(group) = &rule.verdict {
            state.outbound = Some(Arc::clone(group));
        }
        state.apply_mutation(StateMutation::SetRouting {
            field: RoutingField::DomainSet,
            value: Some(rule.label.clone()),
        });
        state.apply_mutation(StateMutation::SetRouting {
            field: RoutingField::MatchedRuleSource,
            value: Some(rule.source.clone()),
        });
        Ok(ExecutorOutcome::Continue)
    }
}

/// The API view of an action, for `rules/test`.
pub(crate) fn action_name(action: &Action) -> &'static str {
    action.name()
}

#[cfg(test)]
mod tests;
