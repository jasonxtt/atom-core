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
//! class any entry may match; every class a rule uses must match. `ip_cidr`
//! is matched by sing-box (design §4.6) and refused here until the sing-box
//! configuration is generated.
//!
//! The `atom_rules` plugin is a fixture: it only marks the query (one fast
//! mark per action) and, for proxy, records the group in
//! `ExecutionState::outbound`; the configuration dispatches on the marks.
//! The table lives in `webinfo/atom_rules.json` and the custom rulesets in
//! `webinfo/atom_rulesets.json` (lists in `webinfo/atom_rulesets/<id>.txt`).
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

use crate::managed::DomainSetHandle;
use crate::rule_sources::Live;

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
    /// Target IP prefixes (matched by sing-box; not accepted yet).
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
    /// `group_id` is a sing-box outbound tag. Groups arrive with the sing-box
    /// configuration (atom step 3); until then any well-formed tag is kept.
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
struct State {
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

fn new_id(prefix: &str, taken: &dyn Fn(&str) -> bool) -> String {
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
fn read_list(path: &Path) -> Result<Vec<String>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(String::from_utf8_lossy(&bytes)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned)
            .collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(format!("read {}: {error}", path.display())),
    }
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

/// Reserved for the group check of atom step 3 (the group must exist).
fn validate_group(group: &str) -> Result<(), Refusal> {
    if group.trim().is_empty() {
        return Err(Refusal::invalid("代理动作需要 group_id"));
    }
    if group != group.trim() || group.len() > MAX_GROUP_BYTES || group.chars().any(char::is_control)
    {
        return Err(Refusal::invalid(format!(
            "group_id `{group}` 无效：不能有首尾空白或控制字符，最长 {MAX_GROUP_BYTES} 字节"
        )));
    }
    Ok(())
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
                let file = root.join(RULESET_DIR).join(format!("{}.txt", set.id));
                let list = build_list(&read_list(&file)?)
                    .map_err(|error| format!("{}: {error}", file.display()))?;
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
        };
        let table = {
            let state = rules_owner.state.borrow();
            rules_owner.compile(&state).map_err(|refusal| {
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

    /// Validates one rule against `state` and compiles it.
    fn compile_rule(&self, state: &State, index: usize, rule: &Rule) -> Result<Compiled, Refusal> {
        let at = |refusal: Refusal| Refusal {
            message: format!("规则 {}: {}", rule.id, refusal.message),
            ..refusal
        };
        let m = &rule.matches;
        if !m.ip_cidr.is_empty() {
            return Err(at(Refusal::invalid(
                "ip_cidr 条件由 sing-box 匹配，要等 sing-box 配置生成（atom 第 3 步）后才能使用",
            )));
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
                validate_group(group_id).map_err(at)?;
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
        Ok(Compiled {
            index,
            inline,
            sets,
            clients,
            verdict,
            label: format!("规则:{}", shown.replace('|', "/")),
            source: format!("atom_rule:{}", rule.id),
        })
    }

    /// Compiles every enabled rule of `state`. A disabled rule is still
    /// validated, so it can be enabled later without surprises.
    fn compile(&self, state: &State) -> Result<Table, Refusal> {
        let mut ids = std::collections::BTreeSet::new();
        let mut rules = Vec::new();
        for (index, rule) in state.rules.iter().enumerate() {
            if !ids.insert(rule.id.as_str()) {
                return Err(Refusal::invalid(format!("规则 ID `{}` 重复", rule.id)));
            }
            let compiled = self.compile_rule(state, index, rule)?;
            if rule.enabled {
                rules.push(compiled);
            }
        }
        Ok(Table { rules })
    }

    /// Validates `next`, writes what changed, and publishes it.
    fn commit(&self, next: State, rules: bool, rulesets: bool) -> Result<(), Refusal> {
        let table = self.compile(&next)?;
        if !self.root.as_os_str().is_empty() {
            let failed = |error: std::io::Error| Refusal::new(500, format!("保存失败: {error}"));
            if rules {
                let file = RulesFile {
                    version: next.version,
                    rules: next.rules.clone(),
                };
                let mut bytes = serde_json::to_vec_pretty(&file)
                    .map_err(|error| Refusal::new(500, error.to_string()))?;
                bytes.push(b'\n');
                crate::runtime_snapshot::write_durably(&self.root.join(RULES_FILE), &bytes)
                    .map_err(failed)?;
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

    pub(crate) fn create(
        &self,
        input: RuleInput,
        version: Option<u64>,
        before: Option<&str>,
        after: Option<&str>,
    ) -> Result<(u64, Rule), Refusal> {
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
        self.commit(next, true, false)?;
        Ok((version, rule))
    }

    pub(crate) fn update(
        &self,
        id: &str,
        input: RuleInput,
        version: Option<u64>,
    ) -> Result<(u64, Rule), Refusal> {
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
        self.commit(next, true, false)?;
        Ok((version, rule))
    }

    pub(crate) fn delete(&self, id: &str, version: Option<u64>) -> Result<u64, Refusal> {
        let mut next = self.state.borrow().clone();
        Self::check_version(&next, version)?;
        let at = Self::position(&next, id)?;
        next.rules.remove(at);
        next.version += 1;
        let version = next.version;
        self.commit(next, true, false)?;
        Ok(version)
    }

    /// Moves `id` right before `before` or right after `after`. The version
    /// is required: a reorder from a stale view would undo someone else's.
    pub(crate) fn move_rule(
        &self,
        id: &str,
        before: Option<&str>,
        after: Option<&str>,
        version: u64,
    ) -> Result<u64, Refusal> {
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
        self.commit(next, true, false)?;
        Ok(version)
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
        if self.ruleset(id).is_none() {
            return Err(Refusal::new(404, format!("规则集 `{id}` 不存在")));
        }
        if self.root.as_os_str().is_empty() {
            return Ok(Vec::new());
        }
        read_list(&self.list_file(id)).map_err(|error| Refusal::new(500, error))
    }

    fn list_file(&self, id: &str) -> PathBuf {
        self.root.join(RULESET_DIR).join(format!("{id}.txt"))
    }

    fn write_list(&self, id: &str, rules: &[String]) -> Result<(), Refusal> {
        if self.root.as_os_str().is_empty() {
            return Ok(());
        }
        let mut text = rules.join("\n");
        text.push('\n');
        crate::runtime_snapshot::write_durably(&self.list_file(id), text.as_bytes())
            .map_err(|error| Refusal::new(500, format!("保存失败: {error}")))
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
        let set = Ruleset {
            id: id.clone(),
            name: name.to_owned(),
            source,
            rule_count: entries.len(),
            updated_at: if entries.is_empty() { 0 } else { now() },
            last_error: String::new(),
        };
        self.write_list(&id, &entries)?;
        next.rulesets.push(set.clone());
        next.lists.insert(id, Rc::new(list));
        self.commit(next, false, true)?;
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
            self.write_list(id, &entries)?;
            set.rule_count = entries.len();
            set.updated_at = now();
            next.lists.insert(id.to_owned(), Rc::new(list));
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
        next.rulesets.remove(at);
        next.lists.remove(id);
        self.commit(next, false, true)?;
        if !self.root.as_os_str().is_empty() {
            let _ = std::fs::remove_file(self.list_file(id));
        }
        Ok(())
    }

    /// Installs a converted download (`Ok`) or records why it failed.
    pub(crate) fn store_download(
        &self,
        id: &str,
        result: Result<(Vec<String>, MixSet), String>,
    ) -> Result<Ruleset, Refusal> {
        let mut next = self.state.borrow().clone();
        let at = next
            .rulesets
            .iter()
            .position(|set| set.id == id)
            .ok_or_else(|| Refusal::new(404, format!("规则集 `{id}` 不存在")))?;
        let mut set = next.rulesets[at].clone();
        match result {
            Ok((entries, list)) => {
                self.write_list(id, &entries)?;
                set.rule_count = entries.len();
                set.updated_at = now();
                set.last_error.clear();
                next.lists.insert(id.to_owned(), Rc::new(list));
            }
            Err(error) => set.last_error = error,
        }
        next.rulesets[at] = set.clone();
        self.commit(next, false, true)?;
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
