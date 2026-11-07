//! The typed settings layer: `webinfo/settings.json` and the one function that
//! combines it with the YAML definitions.
//!
//! WebUI-adjustable values live in named configuration objects (`socks5_proxy`,
//! `ecs_address`, the upstream lists of `aliapi`, the `domain_output` switch,
//! the `feature_flag` values).
//! [`apply`] validates the settings against the collected definitions,
//! resolves `$tag` references to the literal forms the plugin compilers already
//! accept and overlays the settings values, then reports every settable item
//! with its effective value and source. `start`, `check` and hot apply all go
//! through it. See `docs/rust/contracts/native-settings.md`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{ConfigError, RawMap, RawPlugin, RawValue};

/// The settings file, relative to the configuration root.
pub(crate) const SETTINGS_FILE: &str = "webinfo/settings.json";
const VERSION: u32 = 1;

/// The `domain_output` tags the WebUI's four named switches address.
pub(crate) const REMEMBER_DIRECT: &str = "my_realiplist";
pub(crate) const REMEMBER_PROXY: &str = "my_fakeiplist";
pub(crate) const NO_V4: &str = "my_nov4list";
pub(crate) const NO_V6: &str = "my_nov6list";

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Addr {
    pub(crate) addr: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PluginSwitch {
    pub(crate) enabled: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DomainGeneration {
    /// The master switch; absent means on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) plugins: BTreeMap<String, PluginSwitch>,
}

impl DomainGeneration {
    fn is_empty(&self) -> bool {
        self.enabled.is_none() && self.plugins.is_empty()
    }
}

/// The accepted ranges of the tunable numbers (see `native-settings.md`).
pub(crate) const CACHE_SIZE_RANGE: (u64, u64) = (1_000, 100_000_000);
pub(crate) const CACHE_LAZY_TTL_RANGE: (u64, u64) = (0, u32::MAX as u64);
pub(crate) const CACHE_DUMP_INTERVAL_RANGE: (u64, u64) = (60, 31_536_000);
pub(crate) const LEARNER_TTL_RANGE: (u64, u64) = (60, 315_360_000);
pub(crate) const LEARNER_WRITE_INTERVAL_RANGE: (u64, u64) = (60, 31_536_000);

/// The stored differences of one `cache`: capacity in entries, the seconds an
/// expired answer may still be served, and the seconds between dumps.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CacheTuning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) lazy_cache_ttl: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) dump_interval: Option<u64>,
}

impl CacheTuning {
    pub(crate) fn is_empty(&self) -> bool {
        self.size.is_none() && self.lazy_cache_ttl.is_none() && self.dump_interval.is_none()
    }
}

/// The stored differences of one `route_learner` category.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CategoryTuning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) ttl: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) max_entries: Option<u64>,
}

impl CategoryTuning {
    pub(crate) fn is_empty(&self) -> bool {
        self.ttl.is_none() && self.max_entries.is_none()
    }
}

/// The stored differences of the learners: the write interval (every
/// `route_learner`) and the numbers of single categories.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Learning {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) write_interval: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) categories: BTreeMap<String, CategoryTuning>,
}

impl Learning {
    fn is_empty(&self) -> bool {
        self.write_interval.is_none() && self.categories.is_empty()
    }
}

/// One upstream as the WebUI sends and shows it (the reference
/// `UpstreamOverrideConfig` with `use_proxy` for `use_socks_proxy`).
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpstreamEntry {
    #[serde(default)]
    pub(crate) tag: String,
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) protocol: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) addr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) dial_addr: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) idle_timeout: i64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) upstream_query_timeout: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) enable_pipeline: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) enable_http3: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) insecure_skip_verify: bool,
    /// Rejected: a literal proxy address has no place in an entry; use `use_proxy`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) socks5: String,
    /// The reference name of `use_proxy`; accepted on input only.
    #[serde(default, skip_serializing)]
    pub(crate) use_socks_proxy: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) use_proxy: Option<bool>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) so_mark: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) bind_to_device: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) bootstrap: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) bootstrap_version: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) account_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) access_key_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) access_key_secret: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) server_addr: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub(crate) ecs_client_ip: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) ecs_client_mask: i64,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

impl UpstreamEntry {
    /// The protocol as the compiler names it (`dot` is `tls`, `doh` is `https`).
    pub(crate) fn protocol_name(&self) -> String {
        match self.protocol.trim().to_lowercase().as_str() {
            "dot" => "tls".to_owned(),
            "doh" => "https".to_owned(),
            "doq" => "quic".to_owned(),
            other => other.to_owned(),
        }
    }

    /// The effective proxy switch.
    pub(crate) fn proxy_switch(&self) -> bool {
        self.use_proxy.or(self.use_socks_proxy).unwrap_or(false)
    }

    /// The address with the scheme the protocol implies (the reference
    /// `normalizeRuntimeUpstreamAddr`).
    pub(crate) fn runtime_addr(&self) -> String {
        let raw = self.addr.trim();
        if raw.is_empty() || raw.contains("://") {
            return raw.to_owned();
        }
        let scheme = match self.protocol_name().as_str() {
            scheme @ ("udp" | "tcp" | "tls" | "https" | "quic") => scheme.to_owned(),
            _ => return raw.to_owned(),
        };
        if scheme == "https" && !raw.contains('/') {
            format!("https://{raw}/dns-query")
        } else {
            format!("{scheme}://{raw}")
        }
    }

    /// The reference UI rules plus the options this host cannot honor, each
    /// refused with its reason instead of being ignored.
    pub(crate) fn validate(&self, index: usize) -> Result<(), String> {
        let at = |reason: String| format!("Item #{} ({}): {reason}", index + 1, self.tag);
        if self.tag.is_empty() {
            return Err(format!("Item #{}: tag (name) is required", index + 1));
        }
        let protocol = self.protocol_name();
        if protocol == "aliapi"
            || !self.account_id.is_empty()
            || !self.access_key_id.is_empty()
            || !self.access_key_secret.is_empty()
            || !self.server_addr.is_empty()
            || !self.ecs_client_ip.is_empty()
            || self.ecs_client_mask != 0
        {
            return Err(at(
                "the signed AliDNS API is not supported; use a standard DNS upstream".to_owned(),
            ));
        }
        if self.addr.trim().is_empty() {
            return Err(at("addr is required for DNS types".to_owned()));
        }
        if let Some((scheme, _)) = self.addr.trim().split_once("://") {
            if !matches!(protocol.as_str(), "udp" | "tcp" | "tls" | "https" | "quic")
                || !scheme.eq_ignore_ascii_case(&protocol)
            {
                return Err(at(format!(
                    "protocol {protocol} does not match the scheme {scheme} of the address"
                )));
            }
        } else if !matches!(protocol.as_str(), "udp" | "tcp" | "tls" | "https") {
            return Err(at(format!("protocol `{protocol}` is not supported")));
        }
        if protocol == "quic" {
            return Err(at("protocol quic is not supported".to_owned()));
        }
        if !self.socks5.trim().is_empty() {
            return Err(at(
                "a literal socks5 address is not supported; set use_proxy and a proxy object"
                    .to_owned(),
            ));
        }
        for (name, set) in [
            ("so_mark", self.so_mark != 0),
            ("bind_to_device", !self.bind_to_device.is_empty()),
            ("enable_pipeline", self.enable_pipeline),
            ("enable_http3", self.enable_http3),
            ("idle_timeout", self.idle_timeout > 0),
        ] {
            if set {
                return Err(at(format!("{name} is not supported")));
            }
        }
        Ok(())
    }
}

/// The parsed `webinfo/settings.json`: value overrides and managed upstream lists.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Settings {
    #[serde(default)]
    version: u32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) proxies: BTreeMap<String, Addr>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) ecs: BTreeMap<String, Addr>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) upstreams: BTreeMap<String, Vec<UpstreamEntry>>,
    #[serde(default, skip_serializing_if = "DomainGeneration::is_empty")]
    pub(crate) domain_generation: DomainGeneration,
    /// Tuned `cache` numbers by cache tag; only differences from the YAML.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) caches: BTreeMap<String, CacheTuning>,
    /// Tuned `route_learner` numbers; only differences from the YAML.
    #[serde(default, skip_serializing_if = "Learning::is_empty")]
    pub(crate) learning: Learning,
    /// The `feature_flag` values that differ from the YAML defaults. Unlike the
    /// other sections it is kept when empty: its presence records that the
    /// schema-2 switch files were migrated (see `config::flags`).
    #[serde(
        default,
        deserialize_with = "present_flags",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) flags: Option<BTreeMap<String, super::flags::FlagValue>>,
}

/// A present `flags` key must be an object (`null` is not "absent": absent
/// means "not migrated yet").
fn present_flags<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, super::flags::FlagValue>>, D::Error> {
    BTreeMap::deserialize(deserializer).map(Some)
}

impl Settings {
    /// The settings file under `root`.
    pub(crate) fn path(root: &Path) -> PathBuf {
        root.join(SETTINGS_FILE)
    }

    /// Reads the file: absent is empty, anything unusable is an error.
    pub(crate) fn load(root: &Path) -> Result<Self, ConfigError> {
        let path = Self::path(root);
        let display = SETTINGS_FILE.to_owned();
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => {
                return Err(ConfigError::new(display, format!("cannot read: {error}")));
            }
        };
        Self::parse(&bytes)
    }

    /// Decodes settings bytes; an empty file is empty settings.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, ConfigError> {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
        }
        let mut settings: Self = serde_json::from_slice(bytes).map_err(|error| {
            ConfigError::new(SETTINGS_FILE, format!("invalid settings: {error}"))
        })?;
        if settings.version != VERSION {
            return Err(ConfigError::new(
                SETTINGS_FILE,
                format!(
                    "unsupported settings version {} (expected {VERSION})",
                    settings.version
                ),
            ));
        }
        for entries in settings.upstreams.values_mut() {
            for entry in entries {
                entry.use_proxy = Some(entry.proxy_switch());
                entry.use_socks_proxy = None;
            }
        }
        Ok(settings)
    }

    /// The file's bytes: sorted keys, two-space indent, trailing newline.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut value = self.clone();
        value.version = VERSION;
        let mut text = serde_json::to_string_pretty(&value).unwrap_or_default();
        text.push('\n');
        text.into_bytes()
    }
}

/// One settable item: its effective value and where it came from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectiveItem {
    pub object: String,
    pub kind: &'static str,
    pub field: &'static str,
    pub value: String,
    /// `yaml` or `settings` (a `feature_flag` may also say `legacy`).
    pub source: &'static str,
}

/// The values the YAML itself gives, before any settings: what a stored
/// setting is compared with. Upstream lists also retain explicit management
/// intent when their entries equal these defaults.
#[derive(Clone, Debug, Default)]
pub(crate) struct YamlDefaults {
    pub(crate) proxies: BTreeMap<String, String>,
    pub(crate) ecs: BTreeMap<String, String>,
    pub(crate) upstreams: BTreeMap<String, Vec<UpstreamEntry>>,
    /// The `enabled` of every `domain_output`.
    pub(crate) generation: BTreeMap<String, bool>,
    /// The `aliapi` groups that name a plugin-level `proxy`: only their
    /// entries can say `use_proxy`.
    pub(crate) proxy_groups: std::collections::BTreeSet<String>,
    /// The `show_when` conditions of every `aliapi` that declares one (all
    /// must hold for the group to be shown as in use; display only).
    pub(crate) show_when: BTreeMap<String, Vec<String>>,
    /// The YAML numbers of every `cache`.
    pub(crate) caches: BTreeMap<String, CacheDefaults>,
    /// The YAML `ttl` and `max_entries` of every learner category, in
    /// declaration order of the learners and their categories.
    pub(crate) categories: Vec<(String, CategoryDefaults)>,
    /// The YAML `write_interval` of the first `route_learner`.
    pub(crate) write_interval: Option<u64>,
}

/// The YAML numbers of one `cache`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CacheDefaults {
    pub(crate) size: u64,
    pub(crate) lazy_cache_ttl: u64,
    pub(crate) dump_interval: u64,
}

/// The YAML numbers of one learner category.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CategoryDefaults {
    pub(crate) ttl: u64,
    pub(crate) max_entries: u64,
}

/// What [`apply`] found: the report, the effective upstream lists in the UI
/// shape (settings entries as stored, YAML entries converted) and the YAML
/// defaults.
pub(crate) struct Applied {
    pub(crate) items: Vec<EffectiveItem>,
    pub(crate) upstreams: BTreeMap<String, Vec<UpstreamEntry>>,
    pub(crate) defaults: YamlDefaults,
    /// Every `feature_flag` in declaration order, with its effective value.
    pub(crate) flags: Vec<super::flags::Flag>,
    /// Legacy switch files that could not be migrated (startup log).
    pub(crate) legacy_notes: super::flags::LegacyNotes,
}

const YAML: &str = "yaml";
const SETTINGS: &str = "settings";

fn settings_error(path: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::new(format!("{SETTINGS_FILE}:{path}"), reason)
}

fn string_arg(args: &RawMap, key: &str) -> Option<String> {
    match args.get(key) {
        Some(RawValue::String(value)) => Some(value.clone()),
        _ => None,
    }
}

fn args_mut(plugin: &mut RawPlugin) -> Option<&mut RawMap> {
    match &mut plugin.args {
        RawValue::Map(map) => Some(map),
        _ => None,
    }
}

fn set_arg(map: &mut RawMap, key: &str, value: RawValue) {
    map.entries.retain(|(name, _)| name != key);
    map.entries.push((key.to_owned(), value));
}

fn take_arg(map: &mut RawMap, key: &str) -> Option<RawValue> {
    let position = map.entries.iter().position(|(name, _)| name == key)?;
    Some(map.entries.remove(position).1)
}

/// `host:port` with a nonzero port (an IPv6 literal in brackets).
fn validate_proxy_addr(addr: &str) -> Result<(), String> {
    if let Ok(socket) = addr.parse::<std::net::SocketAddr>() {
        return if socket.port() == 0 {
            Err("the proxy port must not be 0".to_owned())
        } else {
            Ok(())
        };
    }
    let Some((host, port)) = addr.rsplit_once(':') else {
        return Err("expected host:port".to_owned());
    };
    let port_ok = port.parse::<u16>().is_ok_and(|port| port != 0);
    if host.is_empty() || host.contains(char::is_whitespace) || !port_ok {
        return Err("expected host:port with a nonzero port".to_owned());
    }
    Ok(())
}

/// An IP, optionally with `/mask` (the mask is ignored, as in quick `ecs`).
fn validate_ecs_addr(addr: &str) -> Result<(), String> {
    let first = addr.split_whitespace().next().unwrap_or_default();
    let ip = first.split_once('/').map_or(first, |(ip, _)| ip);
    ip.parse::<std::net::IpAddr>()
        .map(|_| ())
        .map_err(|_| "expected an IP address".to_owned())
}

type Validator = fn(&str) -> Result<(), String>;

/// What an object resolves to.
struct Objects {
    proxies: BTreeMap<String, String>,
    ecs: BTreeMap<String, String>,
}

/// Overlays `settings` on `definitions` and resolves references, in place.
///
/// # Errors
///
/// A [`ConfigError`] naming the YAML path (or the settings file and key) of
/// the first problem: a settings key that names nothing or the wrong kind, an
/// invalid value, an unknown or missing reference, conflicting spellings.
pub(super) fn apply(
    definitions: &mut [RawPlugin],
    settings: &Settings,
    legacy_root: Option<&Path>,
) -> Result<Applied, ConfigError> {
    let kind_of = |tag: &str| {
        definitions
            .iter()
            .find(|plugin| plugin.tag == tag)
            .map(|plugin| plugin.kind.clone())
    };
    // The WebUI's domain-generation switches address learner categories too.
    let category_tags: Vec<String> = definitions
        .iter()
        .filter(|plugin| plugin.kind == "route_learner")
        .flat_map(learner_category_tags)
        .collect();
    for (section, tags, wanted) in [
        (
            "proxies",
            settings.proxies.keys().collect::<Vec<_>>(),
            "socks5_proxy",
        ),
        ("ecs", settings.ecs.keys().collect(), "ecs_address"),
        ("upstreams", settings.upstreams.keys().collect(), "aliapi"),
        (
            "domain_generation.plugins",
            settings.domain_generation.plugins.keys().collect(),
            "domain_output",
        ),
        ("caches", settings.caches.keys().collect(), "cache"),
    ] {
        for tag in tags {
            match kind_of(tag) {
                Some(kind) if kind == wanted => {}
                None if wanted == "domain_output" && category_tags.contains(tag) => {}
                // The caches of the special groups exist only once the generated
                // YAML is added, after this check; a group that is gone leaves its
                // values unused rather than failing the load.
                None if wanted == "cache" && tag.starts_with("cache_special_") => {}
                Some(kind) => {
                    return Err(settings_error(
                        &format!("{section}.{tag}"),
                        format!("`{tag}` is a {kind}, not a {wanted}"),
                    ));
                }
                None => {
                    return Err(settings_error(
                        &format!("{section}.{tag}"),
                        format!("no {wanted} `{tag}` in the configuration"),
                    ));
                }
            }
        }
    }
    for (tag, entries) in &settings.upstreams {
        for (index, entry) in entries.iter().enumerate() {
            entry
                .validate(index)
                .map_err(|reason| settings_error(&format!("upstreams.{tag}"), reason))?;
        }
    }

    validate_tuning(settings, &category_tags)?;

    let mut report = Vec::new();
    let mut upstreams = BTreeMap::new();
    let mut defaults = YamlDefaults::default();
    let mut show_when_paths = Vec::new();
    let mut objects = Objects {
        proxies: BTreeMap::new(),
        ecs: BTreeMap::new(),
    };
    for plugin in definitions.iter_mut() {
        let (map, section, kind, validate): (_, _, &'static str, Validator) =
            match plugin.kind.as_str() {
                "socks5_proxy" => (
                    &settings.proxies,
                    &mut objects.proxies,
                    "socks5_proxy",
                    validate_proxy_addr,
                ),
                "ecs_address" => (
                    &settings.ecs,
                    &mut objects.ecs,
                    "ecs_address",
                    validate_ecs_addr,
                ),
                _ => continue,
            };
        let path = format!("{}.args", plugin.source_path);
        let tag = plugin.tag.clone();
        let args =
            args_mut(plugin).ok_or_else(|| ConfigError::new(&path, "args must be a mapping"))?;
        args.reject_unknown(&["addr"], &path)?;
        let yaml = match args.get("addr") {
            Some(RawValue::String(value)) => value.clone(),
            None | Some(RawValue::Null) => String::new(),
            Some(_) => {
                return Err(ConfigError::new(
                    format!("{path}.addr"),
                    "expected a string",
                ));
            }
        };
        let yaml_addr = yaml.clone();
        let (addr, source) = match map.get(&tag) {
            Some(value) => (value.addr.clone(), SETTINGS),
            None => (yaml, YAML),
        };
        // An empty proxy address means "no proxy": the reference's empty global
        // `socks5` (the shipped default) is the same state.
        if addr.is_empty() && kind != "socks5_proxy" {
            return Err(ConfigError::new(
                format!("{path}.addr"),
                "addr must be specified",
            ));
        }
        let checked = if addr.is_empty() {
            Ok(())
        } else {
            validate(&addr)
        };
        checked.map_err(|reason| {
            if source == SETTINGS {
                settings_error(&format!("{}.{tag}", section_name(kind)), reason.clone())
            } else {
                ConfigError::new(format!("{path}.addr"), reason)
            }
        })?;
        set_arg(args, "addr", RawValue::String(addr.clone()));
        let yaml_defaults = if kind == "socks5_proxy" {
            &mut defaults.proxies
        } else {
            &mut defaults.ecs
        };
        yaml_defaults.insert(tag.clone(), yaml_addr);
        section.insert(tag.clone(), addr.clone());
        report.push(EffectiveItem {
            object: tag,
            kind,
            field: "addr",
            value: addr,
            source,
        });
    }

    for plugin in definitions.iter_mut() {
        match plugin.kind.as_str() {
            "aliapi" => {
                if args_mut(plugin).is_some_and(|args| args.get("proxy").is_some()) {
                    defaults.proxy_groups.insert(plugin.tag.clone());
                }
                let conditions = aliapi(
                    plugin,
                    settings,
                    &objects,
                    &mut report,
                    &mut upstreams,
                    &mut defaults.upstreams,
                )?;
                if !conditions.is_empty() {
                    show_when_paths.push((plugin.tag.clone(), plugin.source_path.clone()));
                    defaults.show_when.insert(plugin.tag.clone(), conditions);
                }
            }
            "sd_set_light" | "si_set" | "adguard_rule" => {
                let path = format!("{}.args", plugin.source_path);
                if let Some(args) = args_mut(plugin) {
                    resolve_proxy_key(args, &path, &objects, "socks5", None)?;
                }
            }
            "ecs_handler" => {
                let path = format!("{}.args", plugin.source_path);
                if let Some(args) = args_mut(plugin) {
                    if let Some(RawValue::String(value)) = args.get("preset").cloned() {
                        if let Some(tag) = value.trim().strip_prefix('$') {
                            let addr = lookup(
                                &objects.ecs,
                                tag,
                                &format!("{path}.preset"),
                                "ecs_address",
                            )?;
                            let first = addr.split_whitespace().next().unwrap_or_default();
                            let ip = first.split_once('/').map_or(first, |(ip, _)| ip);
                            set_arg(args, "preset", RawValue::String(ip.to_owned()));
                        }
                    }
                }
            }
            "sequence" => {
                let path = format!("{}.args", plugin.source_path);
                resolve_ecs_strings(&mut plugin.args, &path, &objects)?;
            }
            "cache" => tune_cache(plugin, settings, &mut report, &mut defaults)?,
            "domain_output" => domain_output(plugin, settings, &mut report, &mut defaults)?,
            "route_learner" => route_learner(plugin, settings, &mut report, &mut defaults)?,
            _ => {}
        }
    }
    let mut flags = definitions
        .iter()
        .filter(|plugin| plugin.kind == "feature_flag")
        .map(super::flags::declaration)
        .collect::<Result<Vec<_>, _>>()?;
    let legacy_notes = super::flags::resolve(&mut flags, settings.flags.as_ref(), legacy_root)?;
    for (tag, source_path) in &show_when_paths {
        for (index, text) in defaults.show_when[tag].iter().enumerate() {
            super::flags::condition(
                text,
                &format!("{source_path}.args.show_when[{index}]"),
                &flags,
            )?;
        }
    }
    for flag in &flags {
        report.push(EffectiveItem {
            object: flag.key.clone(),
            kind: "feature_flag",
            field: "value",
            value: flag.value.to_string(),
            source: flag.source,
        });
    }
    Ok(Applied {
        items: report,
        upstreams,
        defaults,
        flags,
        legacy_notes,
    })
}

fn section_name(kind: &str) -> &'static str {
    if kind == "socks5_proxy" {
        "proxies"
    } else {
        "ecs"
    }
}

fn lookup(
    map: &BTreeMap<String, String>,
    tag: &str,
    path: &str,
    wanted: &str,
) -> Result<String, ConfigError> {
    map.get(tag)
        .cloned()
        .ok_or_else(|| ConfigError::new(path, format!("unknown {wanted} `${tag}`")))
}

/// Replaces `proxy: $tag` by the literal `target` key; a literal `target`
/// beside it is a conflict. Returns the resolved address.
fn resolve_proxy_key(
    args: &mut RawMap,
    path: &str,
    objects: &Objects,
    target: &str,
    forbidden_with: Option<&str>,
) -> Result<Option<String>, ConfigError> {
    let Some(value) = take_arg(args, "proxy") else {
        return Ok(None);
    };
    let RawValue::String(reference) = value else {
        return Err(ConfigError::new(
            format!("{path}.proxy"),
            "expected a `$tag` reference",
        ));
    };
    let tag = reference.trim().strip_prefix('$').ok_or_else(|| {
        ConfigError::new(
            format!("{path}.proxy"),
            "a proxy must be a `$tag` reference to a socks5_proxy",
        )
    })?;
    let addr = lookup(
        &objects.proxies,
        tag,
        &format!("{path}.proxy"),
        "socks5_proxy",
    )?;
    let literal = match args.get(target) {
        Some(RawValue::String(value)) => !value.is_empty(),
        _ => false,
    };
    if literal || forbidden_with.is_some_and(|key| args.get(key).is_some()) {
        return Err(ConfigError::new(
            format!("{path}.proxy"),
            "proxy cannot be combined with a literal socks5 address",
        ));
    }
    set_arg(args, target, RawValue::String(addr.clone()));
    Ok(Some(addr))
}

/// The `aliapi` transformation (see the module docs). Returns the group's
/// `show_when` conditions (empty without one), taken out of the arguments.
fn aliapi(
    plugin: &mut RawPlugin,
    settings: &Settings,
    objects: &Objects,
    report: &mut Vec<EffectiveItem>,
    effective: &mut BTreeMap<String, Vec<UpstreamEntry>>,
    yaml_defaults: &mut BTreeMap<String, Vec<UpstreamEntry>>,
) -> Result<Vec<String>, ConfigError> {
    let path = format!("{}.args", plugin.source_path);
    let tag = plugin.tag.clone();
    let args =
        args_mut(plugin).ok_or_else(|| ConfigError::new(&path, "aliapi args must be a mapping"))?;
    let show_when_path = format!("{path}.show_when");
    let show_when = match take_arg(args, "show_when") {
        None => Vec::new(),
        Some(RawValue::String(text)) => vec![text],
        Some(RawValue::Sequence(items)) if !items.is_empty() => items
            .iter()
            .enumerate()
            .map(|(index, item)| match item {
                RawValue::String(text) => Ok(text.clone()),
                _ => Err(ConfigError::new(
                    format!("{show_when_path}[{index}]"),
                    "expected a string",
                )),
            })
            .collect::<Result<_, _>>()?,
        Some(_) => {
            return Err(ConfigError::new(
                show_when_path,
                "expected a condition or a non-empty list of conditions",
            ));
        }
    };
    let plugin_socks5 = string_arg(args, "socks5").unwrap_or_default();
    // The plugin-level default proxy of entries that opt in.
    let mut plugin_proxy: Option<String> = None;
    if let Some(value) = args.get("proxy").cloned() {
        if !plugin_socks5.is_empty() {
            return Err(ConfigError::new(
                format!("{path}.proxy"),
                "proxy cannot be combined with a literal socks5 address",
            ));
        }
        take_arg(args, "proxy");
        let RawValue::String(reference) = value else {
            return Err(ConfigError::new(
                format!("{path}.proxy"),
                "expected a `$tag` reference",
            ));
        };
        let name = reference.trim().strip_prefix('$').ok_or_else(|| {
            ConfigError::new(
                format!("{path}.proxy"),
                "a proxy must be a `$tag` reference to a socks5_proxy",
            )
        })?;
        plugin_proxy = Some(lookup(
            &objects.proxies,
            name,
            &format!("{path}.proxy"),
            "socks5_proxy",
        )?);
    }
    let upstreams_path = format!("{path}.upstreams");
    let proxies = Proxies {
        plugin_proxy: plugin_proxy.as_deref(),
        plugin_socks5: &plugin_socks5,
        objects,
    };

    // The list the YAML gives, resolved to literal proxies.
    let mut summary = Vec::new();
    let mut yaml_entries = Vec::new();
    if let Some(RawValue::Sequence(items)) = args
        .entries
        .iter_mut()
        .find(|(key, _)| key == "upstreams")
        .map(|(_, value)| value)
    {
        (summary, yaml_entries) = resolve_items(items, &proxies, false, &upstreams_path)?;
    }
    yaml_defaults.insert(tag.clone(), yaml_entries.clone());

    // A settings list replaces it (enabled entries only). atom: the FakeIP
    // upstream is fixed to sing-box's `dns-in` and never taken from settings.
    let from_settings = settings
        .upstreams
        .get(&tag)
        .filter(|_| tag != crate::edns_directive::FAKEIP_UPSTREAM);
    if let Some(entries) = from_settings {
        let mut items: Vec<RawValue> = entries
            .iter()
            .filter(|entry| entry.enabled)
            .map(upstream_to_raw)
            .collect();
        (summary, _) = resolve_items(&mut items, &proxies, true, &upstreams_path)?;
        // A stored list is managed by the UI/API; YAML-only groups retain
        // their explicit concurrency. Use the resolved enabled population.
        let concurrent = items.len().min(super::aliapi::MAX_CONCURRENT);
        set_arg(
            args,
            "concurrent",
            RawValue::Number(super::RawNumber::Unsigned(concurrent as u64)),
        );
        set_arg(args, "upstreams", RawValue::Sequence(items));
    }
    effective.insert(
        tag.clone(),
        match from_settings {
            Some(entries) => entries.clone(),
            None => yaml_entries,
        },
    );
    report.push(EffectiveItem {
        object: tag,
        kind: "aliapi",
        field: "upstreams",
        value: summary.join(", "),
        source: if from_settings.is_some() {
            SETTINGS
        } else {
            YAML
        },
    });
    Ok(show_when)
}

/// The proxy inputs every upstream entry of one `aliapi` is resolved against.
struct Proxies<'a> {
    plugin_proxy: Option<&'a str>,
    plugin_socks5: &'a str,
    objects: &'a Objects,
}

/// Resolves `proxy`/`use_proxy` of each entry to the literal `socks5` the
/// compiler knows, refusing every ambiguous combination, and returns the
/// entries' summary and UI form.
fn resolve_items(
    items: &mut [RawValue],
    proxies: &Proxies<'_>,
    from_settings: bool,
    list_path: &str,
) -> Result<(Vec<String>, Vec<UpstreamEntry>), ConfigError> {
    let mut summary = Vec::new();
    let mut entries = Vec::new();
    for (index, item) in items.iter_mut().enumerate() {
        let item_path = format!("{list_path}[{index}]");
        let RawValue::Map(item) = item else { continue };
        let has_proxy = item.get("proxy").is_some();
        let has_switch = item.get("use_proxy").is_some();
        let literal = !string_arg(item, "socks5").unwrap_or_default().is_empty();
        let refuse =
            |key: &str, reason: &str| Err(ConfigError::new(format!("{item_path}.{key}"), reason));
        if has_proxy && has_switch {
            return refuse("proxy", "proxy and use_proxy cannot both be given");
        }
        if (has_proxy || has_switch) && literal {
            return refuse(
                "socks5",
                "a literal socks5 address cannot be combined with proxy/use_proxy",
            );
        }
        if (has_proxy || has_switch || from_settings) && !proxies.plugin_socks5.is_empty() {
            return refuse(
                "socks5",
                "a literal plugin socks5 address cannot be combined with proxy/use_proxy or upstream settings; use `proxy: $socks5_proxy`",
            );
        }
        let own_proxy = resolve_proxy_key(item, &item_path, proxies.objects, "socks5", None)?;
        let uses = match take_arg(item, "use_proxy") {
            None | Some(RawValue::Null) => false,
            Some(RawValue::Bool(value)) => value,
            Some(_) => return refuse("use_proxy", "expected a boolean"),
        };
        if own_proxy.is_none() && uses {
            let Some(addr) = proxies.plugin_proxy else {
                return refuse(
                    "use_proxy",
                    "use_proxy needs a plugin-level `proxy: $socks5_proxy`",
                );
            };
            set_arg(item, "socks5", RawValue::String(addr.to_owned()));
        }
        let name = string_arg(item, "tag").unwrap_or_default();
        let addr = string_arg(item, "addr").unwrap_or_default();
        // `[proxy]` marks an entry that really connects through a proxy
        // address (UDP never does).
        let through = (!string_arg(item, "socks5").unwrap_or_default().is_empty()
            || !proxies.plugin_socks5.is_empty())
            && !addr.starts_with("udp://")
            && addr.contains("://");
        let mark = if through { " [proxy]" } else { "" };
        let dial = string_arg(item, "dial_addr").unwrap_or_default();
        let dial = if dial.is_empty() {
            String::new()
        } else {
            format!(" dial={dial}")
        };
        summary.push(if name.is_empty() {
            format!("{addr}{dial}{mark}")
        } else {
            format!("{name}={addr}{dial}{mark}")
        });
        let proxied = own_proxy.is_some() || uses || literal || !proxies.plugin_socks5.is_empty();
        entries.push(raw_to_entry(item, proxied));
    }
    Ok((summary, entries))
}

/// A YAML upstream as a UI entry (enabled, with the effective proxy switch).
fn raw_to_entry(item: &RawMap, proxied: bool) -> UpstreamEntry {
    let text = |key: &str| string_arg(item, key).unwrap_or_default();
    let number = |key: &str| match item.get(key) {
        Some(RawValue::Number(super::RawNumber::Signed(value))) => *value,
        Some(RawValue::Number(super::RawNumber::Unsigned(value))) => {
            i64::try_from(*value).unwrap_or(0)
        }
        _ => 0,
    };
    let addr = text("addr");
    let protocol = addr
        .split_once("://")
        .map_or("udp", |(scheme, _)| scheme)
        .to_lowercase();
    UpstreamEntry {
        tag: text("tag"),
        enabled: true,
        protocol,
        addr,
        dial_addr: text("dial_addr"),
        upstream_query_timeout: number("upstream_query_timeout"),
        insecure_skip_verify: matches!(
            item.get("insecure_skip_verify"),
            Some(RawValue::Bool(true))
        ),
        use_proxy: Some(proxied),
        bootstrap: text("bootstrap"),
        bootstrap_version: number("bootstrap_version"),
        ..UpstreamEntry::default()
    }
}

/// One enabled UI entry as the YAML mapping `aliapi` decodes.
pub(super) fn upstream_to_raw(entry: &UpstreamEntry) -> RawValue {
    let string = |value: &str| RawValue::String(value.to_owned());
    let number = |value: i64| RawValue::Number(super::RawNumber::Signed(value));
    let mut map = RawMap {
        entries: Vec::new(),
    };
    map.entries.push(("tag".to_owned(), string(&entry.tag)));
    map.entries
        .push(("addr".to_owned(), string(&entry.runtime_addr())));
    if !entry.dial_addr.is_empty() {
        map.entries
            .push(("dial_addr".to_owned(), string(&entry.dial_addr)));
    }
    if entry.upstream_query_timeout != 0 {
        map.entries.push((
            "upstream_query_timeout".to_owned(),
            number(entry.upstream_query_timeout),
        ));
    }
    if entry.insecure_skip_verify {
        map.entries
            .push(("insecure_skip_verify".to_owned(), RawValue::Bool(true)));
    }
    if !entry.bootstrap.is_empty() {
        map.entries
            .push(("bootstrap".to_owned(), string(&entry.bootstrap)));
    }
    if entry.bootstrap_version != 0 {
        map.entries.push((
            "bootstrap_version".to_owned(),
            number(entry.bootstrap_version),
        ));
    }
    if entry.proxy_switch() {
        map.entries
            .push(("use_proxy".to_owned(), RawValue::Bool(true)));
    }
    RawValue::Map(map)
}

/// Rewrites the strings `ecs $tag` inside a sequence's arguments.
fn resolve_ecs_strings(
    value: &mut RawValue,
    path: &str,
    objects: &Objects,
) -> Result<(), ConfigError> {
    match value {
        RawValue::String(text) => {
            let trimmed = text.trim();
            if let Some(rest) = trimmed.strip_prefix("ecs ") {
                if let Some(tag) = rest.trim().strip_prefix('$') {
                    let addr = lookup(&objects.ecs, tag, path, "ecs_address")?;
                    *text = format!("ecs {addr}");
                }
            }
            Ok(())
        }
        RawValue::Sequence(items) => {
            for (index, item) in items.iter_mut().enumerate() {
                resolve_ecs_strings(item, &format!("{path}[{index}]"), objects)?;
            }
            Ok(())
        }
        RawValue::Map(map) => {
            for (key, item) in &mut map.entries {
                resolve_ecs_strings(item, &format!("{path}.{key}"), objects)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// The category tags of a `route_learner` definition (what is readable of an
/// unvalidated definition; the compiler reports malformed ones).
/// `value` inside `(low, high)`, or the settings error that names the key.
fn check_range(path: &str, value: u64, (low, high): (u64, u64)) -> Result<(), ConfigError> {
    if (low..=high).contains(&value) {
        Ok(())
    } else {
        Err(settings_error(
            path,
            format!("must be between {low} and {high}, got {value}"),
        ))
    }
}

/// The ranges of the tunable numbers, and the categories they name.
fn validate_tuning(settings: &Settings, category_tags: &[String]) -> Result<(), ConfigError> {
    for (tag, tuning) in &settings.caches {
        let at = |field: &str| format!("caches.{tag}.{field}");
        if let Some(value) = tuning.size {
            check_range(&at("size"), value, CACHE_SIZE_RANGE)?;
        }
        if let Some(value) = tuning.lazy_cache_ttl {
            check_range(&at("lazy_cache_ttl"), value, CACHE_LAZY_TTL_RANGE)?;
        }
        if let Some(value) = tuning.dump_interval {
            check_range(&at("dump_interval"), value, CACHE_DUMP_INTERVAL_RANGE)?;
        }
    }
    if let Some(value) = settings.learning.write_interval {
        check_range(
            "learning.write_interval",
            value,
            LEARNER_WRITE_INTERVAL_RANGE,
        )?;
    }
    let cap = u64::try_from(crate::route_learner::MAX_ENTRIES_CAP).unwrap_or(u64::MAX);
    for (tag, tuning) in &settings.learning.categories {
        if !category_tags.contains(tag) {
            return Err(settings_error(
                &format!("learning.categories.{tag}"),
                format!("no route_learner category `{tag}` in the configuration"),
            ));
        }
        if let Some(value) = tuning.ttl {
            check_range(
                &format!("learning.categories.{tag}.ttl"),
                value,
                LEARNER_TTL_RANGE,
            )?;
        }
        if let Some(value) = tuning.max_entries {
            check_range(
                &format!("learning.categories.{tag}.max_entries"),
                value,
                (1, cap),
            )?;
        }
    }
    Ok(())
}

/// An integer argument; `None` when absent, null or not an integer (the
/// plugin compiler reports the latter).
fn integer_arg(args: &RawMap, key: &str) -> Option<i64> {
    match args.get(key) {
        Some(RawValue::Number(super::RawNumber::Signed(value))) => Some(*value),
        Some(RawValue::Number(super::RawNumber::Unsigned(value))) => i64::try_from(*value).ok(),
        _ => None,
    }
}

/// Reports one tunable number and, when the settings tune it, writes it into
/// the arguments in place of the YAML value.
fn tuned(
    args: &mut RawMap,
    report: &mut Vec<EffectiveItem>,
    (object, kind, field): (&str, &'static str, &'static str),
    yaml: u64,
    own: Option<u64>,
) {
    let value = own.unwrap_or(yaml);
    if own.is_some() {
        set_arg(
            args,
            field,
            RawValue::Number(super::RawNumber::Unsigned(value)),
        );
    }
    report.push(EffectiveItem {
        object: object.to_owned(),
        kind,
        field,
        value: value.to_string(),
        source: if own.is_some() { SETTINGS } else { YAML },
    });
}

/// The effective `size`, `lazy_cache_ttl` and `dump_interval` of a `cache`:
/// the settings value, else the YAML one (else the plugin default).
pub(super) fn tune_cache(
    plugin: &mut RawPlugin,
    settings: &Settings,
    report: &mut Vec<EffectiveItem>,
    defaults: &mut YamlDefaults,
) -> Result<(), ConfigError> {
    let tag = plugin.tag.clone();
    let own = settings.caches.get(&tag).cloned().unwrap_or_default();
    let Some(args) = args_mut(plugin) else {
        return Ok(());
    };
    let positive = |key: &str, fallback: u64| {
        integer_arg(args, key)
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value > 0)
            .unwrap_or(fallback)
    };
    let yaml = CacheDefaults {
        size: positive("size", super::DEFAULT_CACHE_SIZE),
        lazy_cache_ttl: integer_arg(args, "lazy_cache_ttl")
            .and_then(|value| u64::try_from(value).ok())
            .unwrap_or(0),
        dump_interval: positive("dump_interval", super::DEFAULT_CACHE_DUMP_INTERVAL_SECS),
    };
    defaults.caches.insert(tag.clone(), yaml);
    for (field, yaml, own) in [
        ("size", yaml.size, own.size),
        ("lazy_cache_ttl", yaml.lazy_cache_ttl, own.lazy_cache_ttl),
        ("dump_interval", yaml.dump_interval, own.dump_interval),
    ] {
        tuned(args, report, (&tag, "cache", field), yaml, own);
    }
    Ok(())
}

fn learner_category_tags(plugin: &RawPlugin) -> Vec<String> {
    let RawValue::Map(args) = &plugin.args else {
        return Vec::new();
    };
    let Some(RawValue::Sequence(list)) = args.get("categories") else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|item| match item {
            RawValue::Map(map) => match map.get("tag") {
                Some(RawValue::String(tag)) => Some(tag.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// The effective `enabled` of every category of a `route_learner`: the
/// category's setting (else the YAML value) while the master switch is on.
fn route_learner(
    plugin: &mut RawPlugin,
    settings: &Settings,
    report: &mut Vec<EffectiveItem>,
    defaults: &mut YamlDefaults,
) -> Result<(), ConfigError> {
    let path = format!("{}.args.categories", plugin.source_path);
    let learner = plugin.tag.clone();
    let master = settings.domain_generation.enabled.unwrap_or(true);
    let RawValue::Map(args) = &mut plugin.args else {
        return Ok(());
    };
    let yaml_interval = integer_arg(args, "write_interval")
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(21_600);
    let default_max = integer_arg(args, "max_entries")
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(20_000);
    defaults.write_interval.get_or_insert(yaml_interval);
    tuned(
        args,
        report,
        (&learner, "route_learner", "write_interval"),
        yaml_interval,
        settings.learning.write_interval,
    );
    let Some((_, RawValue::Sequence(list))) = args
        .entries
        .iter_mut()
        .find(|(name, _)| name == "categories")
    else {
        return Ok(());
    };
    for (index, item) in list.iter_mut().enumerate() {
        let RawValue::Map(map) = item else { continue };
        let Some(RawValue::String(tag)) = map.get("tag").cloned() else {
            continue;
        };
        let yaml = match map.get("enabled") {
            None | Some(RawValue::Null) => true,
            Some(RawValue::Bool(value)) => *value,
            Some(_) => {
                return Err(ConfigError::new(
                    format!("{path}[{index}].enabled"),
                    "expected a boolean",
                ));
            }
        };
        defaults.generation.insert(tag.clone(), yaml);
        let tuning = settings
            .learning
            .categories
            .get(&tag)
            .cloned()
            .unwrap_or_default();
        let category = CategoryDefaults {
            ttl: integer_arg(map, "ttl")
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(0),
            max_entries: integer_arg(map, "max_entries")
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or(default_max),
        };
        defaults.categories.push((tag.clone(), category));
        // A category without a `ttl` is the compiler's error to report.
        if map.get("ttl").is_some() {
            tuned(
                map,
                report,
                (&tag, "route_learner", "ttl"),
                category.ttl,
                tuning.ttl,
            );
        }
        tuned(
            map,
            report,
            (&tag, "route_learner", "max_entries"),
            category.max_entries,
            tuning.max_entries,
        );
        let own = settings
            .domain_generation
            .plugins
            .get(&tag)
            .map(|switch| switch.enabled);
        let effective = master && own.unwrap_or(yaml);
        set_arg(map, "enabled", RawValue::Bool(effective));
        report.push(EffectiveItem {
            object: tag,
            kind: "domain_output",
            field: "enabled",
            value: effective.to_string(),
            source: if own.is_some() || !master {
                SETTINGS
            } else {
                YAML
            },
        });
    }
    Ok(())
}

/// The effective `enabled` of a `domain_output`: the plugin's setting (else
/// the YAML value) while the master switch is on.
fn domain_output(
    plugin: &mut RawPlugin,
    settings: &Settings,
    report: &mut Vec<EffectiveItem>,
    defaults: &mut YamlDefaults,
) -> Result<(), ConfigError> {
    let path = format!("{}.args", plugin.source_path);
    let tag = plugin.tag.clone();
    let master = settings.domain_generation.enabled.unwrap_or(true);
    let own = settings
        .domain_generation
        .plugins
        .get(&tag)
        .map(|switch| switch.enabled);
    let args = match &mut plugin.args {
        RawValue::Map(map) => map,
        RawValue::Null => {
            plugin.args = RawValue::Map(RawMap {
                entries: Vec::new(),
            });
            match &mut plugin.args {
                RawValue::Map(map) => map,
                _ => return Ok(()),
            }
        }
        _ => {
            return Err(ConfigError::new(
                &path,
                "domain_output args must be a mapping",
            ));
        }
    };
    let yaml = match args.get("enabled") {
        None | Some(RawValue::Null) => true,
        Some(RawValue::Bool(value)) => *value,
        Some(_) => {
            return Err(ConfigError::new(
                format!("{path}.enabled"),
                "expected a boolean",
            ));
        }
    };
    defaults.generation.insert(tag.clone(), yaml);
    // The plugin's setting replaces the YAML value; the master switch gates both.
    let effective = master && own.unwrap_or(yaml);
    set_arg(args, "enabled", RawValue::Bool(effective));
    report.push(EffectiveItem {
        object: tag,
        kind: "domain_output",
        field: "enabled",
        value: effective.to_string(),
        source: if own.is_some() || !master {
            SETTINGS
        } else {
            YAML
        },
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_round_trip_and_reject_what_they_do_not_know() {
        let text = br#"{"version":1,"proxies":{"p":{"addr":"10.0.0.1:1080"}},"domain_generation":{"enabled":false}}"#;
        let settings = Settings::parse(text).unwrap();
        assert_eq!(settings.proxies["p"].addr, "10.0.0.1:1080");
        assert_eq!(settings.domain_generation.enabled, Some(false));
        assert_eq!(Settings::parse(&settings.to_bytes()).unwrap(), settings);
        assert_eq!(Settings::parse(b"").unwrap(), Settings::default());
        for bad in [
            &br#"{"version":2}"#[..],
            br#"{"version":1,"extra":{}}"#,
            br#"{"version":1,"proxies":{"p":{"addr":"x","more":1}}}"#,
            br#"{"proxies":{}}"#,
            b"{not json",
        ] {
            assert!(
                Settings::parse(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn tuning_sections_round_trip_omit_empty_parts_and_refuse_unknown_fields() {
        let text = br#"{"version":1,"caches":{"c":{"size":5000,"lazy_cache_ttl":0}},"learning":{"write_interval":600,"categories":{"k":{"ttl":60}}}}"#;
        let settings = Settings::parse(text).unwrap();
        assert_eq!(settings.caches["c"].size, Some(5000));
        assert_eq!(settings.caches["c"].lazy_cache_ttl, Some(0));
        assert_eq!(settings.learning.categories["k"].ttl, Some(60));
        assert_eq!(Settings::parse(&settings.to_bytes()).unwrap(), settings);
        let empty = Settings::parse(br#"{"version":1,"caches":{},"learning":{}}"#).unwrap();
        assert_eq!(empty.to_bytes(), b"{\n  \"version\": 1\n}\n");
        for bad in [
            &br#"{"version":1,"caches":{"c":{"more":1}}}"#[..],
            br#"{"version":1,"caches":{"c":{"size":-1}}}"#,
            br#"{"version":1,"caches":{"c":{"size":"big"}}}"#,
            br#"{"version":1,"learning":{"more":1}}"#,
            br#"{"version":1,"learning":{"categories":{"k":{"mark":3}}}}"#,
        ] {
            assert!(
                Settings::parse(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn tuning_ranges_are_checked_and_name_the_key() {
        let check = |json: &str| {
            let settings = Settings::parse(json.as_bytes()).unwrap();
            validate_tuning(&settings, &["k".to_owned()])
        };
        assert!(check(r#"{"version":1,"caches":{"c":{"size":1000,"lazy_cache_ttl":4294967295,"dump_interval":60}}}"#).is_ok());
        assert!(check(r#"{"version":1,"learning":{"write_interval":31536000,"categories":{"k":{"ttl":60,"max_entries":262144}}}}"#).is_ok());
        for (json, key) in [
            (
                r#"{"version":1,"caches":{"c":{"size":999}}}"#,
                "caches.c.size",
            ),
            (
                r#"{"version":1,"caches":{"c":{"size":100000001}}}"#,
                "caches.c.size",
            ),
            (
                r#"{"version":1,"caches":{"c":{"lazy_cache_ttl":4294967296}}}"#,
                "caches.c.lazy_cache_ttl",
            ),
            (
                r#"{"version":1,"caches":{"c":{"dump_interval":59}}}"#,
                "caches.c.dump_interval",
            ),
            (
                r#"{"version":1,"learning":{"write_interval":59}}"#,
                "learning.write_interval",
            ),
            (
                r#"{"version":1,"learning":{"categories":{"k":{"ttl":59}}}}"#,
                "learning.categories.k.ttl",
            ),
            (
                r#"{"version":1,"learning":{"categories":{"k":{"max_entries":0}}}}"#,
                "learning.categories.k.max_entries",
            ),
            (
                r#"{"version":1,"learning":{"categories":{"other":{"ttl":60}}}}"#,
                "learning.categories.other",
            ),
        ] {
            let error = check(json).unwrap_err().to_string();
            assert!(error.contains(key), "{json}: {error}");
        }
    }

    #[test]
    fn entries_are_validated_like_the_ui_and_refuse_unsupported_options() {
        let entry = |json: &str| -> UpstreamEntry { serde_json::from_str(json).unwrap() };
        let ok = entry(
            r#"{"tag":"a","enabled":true,"protocol":"doh","addr":"dns.example","use_socks_proxy":true}"#,
        );
        assert!(ok.validate(0).is_ok());
        assert_eq!(ok.protocol_name(), "https");
        assert_eq!(ok.runtime_addr(), "https://dns.example/dns-query");
        assert!(ok.proxy_switch());
        assert_eq!(
            entry(r#"{"tag":"a","protocol":"udp","addr":"1.1.1.1"}"#).runtime_addr(),
            "udp://1.1.1.1"
        );
        for (json, reason) in [
            (r#"{"protocol":"udp","addr":"1.1.1.1"}"#, "tag"),
            (r#"{"tag":"a","protocol":"udp"}"#, "addr is required"),
            (
                r#"{"tag":"a","protocol":"udp","addr":"tcp://1.1.1.1"}"#,
                "does not match",
            ),
            (r#"{"tag":"a","protocol":"aliapi"}"#, "signed AliDNS"),
            (
                r#"{"tag":"a","protocol":"udp","addr":"1.1.1.1","account_id":"x"}"#,
                "signed AliDNS",
            ),
            (
                r#"{"tag":"a","protocol":"udp","addr":"1.1.1.1","socks5":"1.2.3.4:1"}"#,
                "literal socks5",
            ),
            (
                r#"{"tag":"a","protocol":"udp","addr":"1.1.1.1","so_mark":3}"#,
                "so_mark",
            ),
            (r#"{"tag":"a","protocol":"quic","addr":"1.1.1.1"}"#, "quic"),
        ] {
            let error = entry(json).validate(0).unwrap_err();
            assert!(error.contains(reason), "{json}: {error}");
        }
        assert!(serde_json::from_str::<UpstreamEntry>(r#"{"tag":"a","bogus":1}"#).is_err());
    }

    #[test]
    fn addresses_are_checked() {
        assert!(validate_proxy_addr("192.0.2.1:7890").is_ok());
        assert!(validate_proxy_addr("proxy.example:1080").is_ok());
        assert!(validate_proxy_addr("[::1]:1080").is_ok());
        for bad in ["192.0.2.1", "192.0.2.1:0", ":1080", "a b:1", "host:99999"] {
            assert!(validate_proxy_addr(bad).is_err(), "{bad}");
        }
        assert!(validate_ecs_addr("2001:db8:ec5::1").is_ok());
        assert!(validate_ecs_addr("192.0.2.0/24").is_ok());
        assert!(validate_ecs_addr("not-an-ip").is_err());
    }
}
