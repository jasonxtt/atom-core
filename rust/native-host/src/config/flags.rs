//! Named feature flags (`feature_flag`), which replaced `switch1`..`switch17`
//! in configuration schema 3.
//!
//! A flag is a non-executable configuration object: a label, a description,
//! a UI section, a kind (`bool` or `choice` with options) and a default. Its
//! value lives in the `flags` section of `webinfo/settings.json` (differences
//! only) and is fixed into each compiled generation, so the quick matcher
//! `flag key` / `flag key=option` is a constant of the generation a query was
//! admitted to. See `docs/rust/contracts/native-feature-flags.md`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{ConfigError, RawPlugin, RawValue, expect_map, expect_sequence, expect_string};

/// The UI sections a flag may belong to.
pub(crate) const SECTIONS: &[&str] = &[
    "mode",
    "upstream",
    "routing",
    "blocking",
    "rewrite",
    "learning",
    "cache",
    "client",
    "special_groups",
];

/// A flag value as stored in `settings.json`: a boolean for `bool` flags, an
/// option value for `choice` flags.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum FlagValue {
    Bool(bool),
    Choice(String),
}

impl std::fmt::Display for FlagValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool(value) => write!(formatter, "{value}"),
            Self::Choice(value) => formatter.write_str(value),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FlagOption {
    pub(crate) value: String,
    pub(crate) label: String,
}

/// One declared flag with the value this generation was compiled with.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Flag {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) description: String,
    pub(crate) section: String,
    /// `None` for a `bool` flag.
    pub(crate) options: Option<Vec<FlagOption>>,
    pub(crate) default: FlagValue,
    pub(crate) value: FlagValue,
    /// Whether a changed value makes the host start a `requery` task.
    pub(crate) requery_on_change: bool,
    /// `yaml`, `settings` or `legacy` (taken from `rule/switchN.txt` while the
    /// settings file has no `flags` section yet).
    pub(crate) source: &'static str,
}

impl Flag {
    pub(crate) fn kind(&self) -> &'static str {
        if self.options.is_some() {
            "choice"
        } else {
            "bool"
        }
    }

    /// Whether `value` has this flag's type (and names one of its options).
    pub(crate) fn accepts(&self, value: &FlagValue) -> bool {
        match (&self.options, value) {
            (None, FlagValue::Bool(_)) => true,
            (Some(options), FlagValue::Choice(choice)) => {
                options.iter().any(|option| &option.value == choice)
            }
            _ => false,
        }
    }
}

fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && name.len() <= 32
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn nonempty(map: &super::RawMap, key: &str, path: &str) -> Result<String, ConfigError> {
    let value = expect_string(map.required(key, path)?, &format!("{path}.{key}"))?;
    if value.trim().is_empty() {
        return Err(ConfigError::new(
            format!("{path}.{key}"),
            "must not be empty",
        ));
    }
    Ok(value)
}

/// Decodes and validates one `feature_flag` declaration. The value is the
/// default until [`resolve`] overlays settings or legacy values.
pub(super) fn declaration(plugin: &RawPlugin) -> Result<Flag, ConfigError> {
    if !valid_name(&plugin.tag) {
        return Err(ConfigError::new(
            format!("{}.tag", plugin.source_path),
            "a feature_flag tag must match ^[a-z][a-z0-9_]{0,31}$",
        ));
    }
    let path = format!("{}.args", plugin.source_path);
    let args = expect_map(&plugin.args, &path, "feature_flag args must be a mapping")?;
    args.reject_unknown(
        &[
            "label",
            "description",
            "section",
            "kind",
            "options",
            "default",
            "requery_on_change",
        ],
        &path,
    )?;
    let label = nonempty(args, "label", &path)?;
    let description = nonempty(args, "description", &path)?;
    let section = expect_string(args.required("section", &path)?, &format!("{path}.section"))?;
    if !SECTIONS.contains(&section.as_str()) {
        return Err(ConfigError::new(
            format!("{path}.section"),
            format!(
                "unknown section `{section}`; expected one of {}",
                SECTIONS.join(", ")
            ),
        ));
    }
    let kind = expect_string(args.required("kind", &path)?, &format!("{path}.kind"))?;
    let default_path = format!("{path}.default");
    let default = args.required("default", &path)?;
    let (options, default) = match kind.as_str() {
        "bool" => {
            if args.get("options").is_some() {
                return Err(ConfigError::new(
                    format!("{path}.options"),
                    "a bool flag has no options",
                ));
            }
            let RawValue::Bool(default) = default else {
                return Err(ConfigError::new(default_path, "expected true or false"));
            };
            (None, FlagValue::Bool(*default))
        }
        "choice" => {
            let options_path = format!("{path}.options");
            let raw = expect_sequence(args.required("options", &path)?, &options_path)?;
            if raw.len() < 2 {
                return Err(ConfigError::new(
                    options_path,
                    "a choice flag needs at least two options",
                ));
            }
            let mut options: Vec<FlagOption> = Vec::new();
            for (index, option) in raw.iter().enumerate() {
                let at = format!("{options_path}[{index}]");
                let map = expect_map(option, &at, "an option must be a mapping")?;
                map.reject_unknown(&["value", "label"], &at)?;
                let value = expect_string(map.required("value", &at)?, &format!("{at}.value"))?;
                if !valid_name(&value) {
                    return Err(ConfigError::new(
                        format!("{at}.value"),
                        "an option value must match ^[a-z][a-z0-9_]{0,31}$",
                    ));
                }
                if options.iter().any(|option| option.value == value) {
                    return Err(ConfigError::new(
                        format!("{at}.value"),
                        format!("duplicate option `{value}`"),
                    ));
                }
                let label = nonempty(map, "label", &at)?;
                options.push(FlagOption { value, label });
            }
            let RawValue::String(default) = default else {
                return Err(ConfigError::new(default_path, "expected an option value"));
            };
            if !options.iter().any(|option| &option.value == default) {
                return Err(ConfigError::new(
                    default_path,
                    format!("`{default}` is not one of the options"),
                ));
            }
            (Some(options), FlagValue::Choice(default.clone()))
        }
        other => {
            return Err(ConfigError::new(
                format!("{path}.kind"),
                format!("unknown kind `{other}`; expected bool or choice"),
            ));
        }
    };
    let requery_on_change = match args.get("requery_on_change") {
        None => false,
        Some(RawValue::Bool(value)) => *value,
        Some(_) => {
            return Err(ConfigError::new(
                format!("{path}.requery_on_change"),
                "expected true or false",
            ));
        }
    };
    Ok(Flag {
        key: plugin.tag.clone(),
        label,
        description,
        section,
        options,
        value: default.clone(),
        default,
        requery_on_change,
        source: "yaml",
    })
}

/// What [`resolve`] found besides the flags: notes for the startup log about
/// legacy values that could not be used.
pub(crate) type LegacyNotes = Vec<String>;

/// Flags atom removed from its configuration: a stored value of one is
/// ignored (and dropped by the next settings write), not a load error.
/// `ddns_foreign`: atom step 6b made DDNS a rule.
const RETIRED: &[&str] = &["ddns_foreign"];

/// Overlays the settings (or, before the first migration, the legacy
/// `rule/switchN.txt` values under `legacy_root`) on the declarations.
pub(super) fn resolve(
    flags: &mut [Flag],
    stored: Option<&BTreeMap<String, FlagValue>>,
    legacy_root: Option<&Path>,
) -> Result<LegacyNotes, ConfigError> {
    let mut notes = Vec::new();
    match stored {
        Some(stored) => {
            for (key, value) in stored {
                let at = format!("{}:flags.{key}", super::settings::SETTINGS_FILE);
                let Some(flag) = flags.iter_mut().find(|flag| &flag.key == key) else {
                    if RETIRED.contains(&key.as_str()) {
                        continue;
                    }
                    return Err(ConfigError::new(
                        at,
                        format!("no feature_flag `{key}` in the configuration"),
                    ));
                };
                if !flag.accepts(value) {
                    return Err(ConfigError::new(
                        at,
                        format!("`{value}` is not a valid {} value", flag.kind()),
                    ));
                }
                flag.value = value.clone();
                flag.source = "settings";
            }
        }
        None => {
            if let Some(root) = legacy_root {
                let values = legacy_values(root, flags, &mut notes);
                for flag in flags.iter_mut() {
                    if let Some(value) = values.get(&flag.key) {
                        if *value != flag.default {
                            flag.value = value.clone();
                            flag.source = "legacy";
                        }
                    }
                }
            }
        }
    }
    Ok(notes)
}

/// The `flags` section that stores `flags`' current values: every value that
/// differs from its default.
pub(crate) fn differences(flags: &[Flag]) -> BTreeMap<String, FlagValue> {
    flags
        .iter()
        .filter(|flag| flag.value != flag.default)
        .map(|flag| (flag.key.clone(), flag.value.clone()))
        .collect()
}

/// The one-time migration table from the schema-2 switch files.
#[derive(Clone, Copy)]
enum Legacy {
    /// `Bool(switch, on_b)`: `A` is on, or `B` when `on_b`.
    Bool(u8, bool),
    /// `Choice(switch, a, b)`: `A`/`B` map to two options.
    Choice(u8, &'static str, &'static str),
    /// switch2 + switch12.
    Client,
}

const LEGACY: &[(&str, Legacy)] = &[
    ("core_mode", Legacy::Choice(3, "compat", "safe")),
    ("dns_mode", Legacy::Choice(17, "fakeip", "realip")),
    ("cn_fakeip", Legacy::Bool(9, true)),
    ("prefer_v4", Legacy::Bool(8, false)),
    ("ddns_foreign", Legacy::Bool(16, false)),
    ("block_empty", Legacy::Bool(1, false)),
    ("block_blocklist", Legacy::Bool(1, false)),
    ("block_qtypes", Legacy::Bool(5, false)),
    ("block_ads", Legacy::Bool(7, false)),
    ("block_aaaa", Legacy::Bool(6, false)),
    ("lazy_cache", Legacy::Bool(4, false)),
    ("full_cache", Legacy::Bool(13, false)),
    ("client_routing", Legacy::Client),
];

const CLIENT_OPTIONS: &[&str] = &["none", "only_listed_proxy", "listed_direct"];

/// The schema-2 state files were bounded to 1 MiB.
const MAX_LEGACY_BYTES: u64 = 1024 * 1024;

/// One legacy switch file: `Some("A" | "B")`, or `None` (with a note) when it
/// is missing, unreadable, too large or holds anything else.
fn read_switch(root: &Path, switch: u8, notes: &mut LegacyNotes) -> Option<&'static str> {
    use std::io::Read as _;
    let path = root.join(format!("rule/switch{switch}.txt"));
    let mut text = String::new();
    let read = std::fs::File::open(&path)
        .and_then(|file| file.take(MAX_LEGACY_BYTES + 1).read_to_string(&mut text));
    match read {
        Ok(_) if text.len() as u64 > MAX_LEGACY_BYTES => {
            notes.push(format!("rule/switch{switch}.txt is larger than 1 MiB"));
            None
        }
        Ok(_) => match text.trim() {
            "A" => Some("A"),
            "B" => Some("B"),
            _ => {
                notes.push(format!("rule/switch{switch}.txt does not hold A or B"));
                None
            }
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            notes.push(format!("rule/switch{switch}.txt is missing"));
            None
        }
        Err(error) => {
            notes.push(format!("rule/switch{switch}.txt: {error}"));
            None
        }
    }
}

/// The values the schema-2 switch files give the declared flags of the
/// table. A flag that is not declared, or whose kind or options differ from
/// the table, is left alone; a file that gives no `A`/`B` keeps the default.
fn legacy_values(
    root: &Path,
    flags: &[Flag],
    notes: &mut LegacyNotes,
) -> BTreeMap<String, FlagValue> {
    let mut values = BTreeMap::new();
    let mut cache: BTreeMap<u8, Option<&'static str>> = BTreeMap::new();
    let mut switch = |number: u8, notes: &mut LegacyNotes| {
        *cache
            .entry(number)
            .or_insert_with(|| read_switch(root, number, notes))
    };
    for (key, legacy) in LEGACY {
        let Some(flag) = flags.iter().find(|flag| flag.key == *key) else {
            continue;
        };
        let value = match *legacy {
            Legacy::Bool(number, on_b) => {
                if flag.options.is_some() {
                    continue;
                }
                match switch(number, notes) {
                    Some(letter) => FlagValue::Bool((letter == "B") == on_b),
                    None => continue,
                }
            }
            Legacy::Choice(number, a, b) => {
                let value_a = FlagValue::Choice(a.to_owned());
                let value_b = FlagValue::Choice(b.to_owned());
                if !flag.accepts(&value_a) || !flag.accepts(&value_b) {
                    continue;
                }
                match switch(number, notes) {
                    Some("A") => value_a,
                    Some(_) => value_b,
                    None => continue,
                }
            }
            Legacy::Client => {
                if !CLIENT_OPTIONS
                    .iter()
                    .all(|option| flag.accepts(&FlagValue::Choice((*option).to_owned())))
                {
                    continue;
                }
                // Only (A, B) and (B, A) ever matched a rule; everything else,
                // missing and invalid files included, was "no distinction".
                let option = match (switch(2, notes), switch(12, notes)) {
                    (Some("A"), Some("B")) => "only_listed_proxy",
                    (Some("B"), Some("A")) => "listed_direct",
                    _ => "none",
                };
                FlagValue::Choice(option.to_owned())
            }
        };
        values.insert((*key).to_owned(), value);
    }
    values
}

/// Compiles the quick matcher `flag key` (bool) / `flag key=option` (choice)
/// to its constant answer for this generation.
pub(super) fn matches(args: &str, path: &str, flags: &[Flag]) -> Result<bool, ConfigError> {
    let (key, option) = match args.split_once('=') {
        Some((key, option)) => (key.trim(), Some(option.trim())),
        None => (args.trim(), None),
    };
    if key.is_empty() || key.contains(char::is_whitespace) {
        return Err(ConfigError::new(
            path,
            "flag requires `flag <key>` or `flag <key>=<option>`",
        ));
    }
    let Some(flag) = flags.iter().find(|flag| flag.key == key) else {
        return Err(ConfigError::new(
            path,
            format!("unknown feature_flag `{key}`"),
        ));
    };
    match (&flag.options, option) {
        (None, None) => Ok(flag.value == FlagValue::Bool(true)),
        (None, Some(_)) => Err(ConfigError::new(
            path,
            format!("`{key}` is a bool flag: use `flag {key}` or `!flag {key}`"),
        )),
        (Some(_), None) => Err(ConfigError::new(
            path,
            format!("`{key}` is a choice flag: use `flag {key}=<option>`"),
        )),
        (Some(options), Some(option)) => {
            if !options.iter().any(|candidate| candidate.value == option) {
                return Err(ConfigError::new(
                    path,
                    format!("`{option}` is not an option of `{key}`"),
                ));
            }
            Ok(flag.value == FlagValue::Choice(option.to_owned()))
        }
    }
}

/// One condition of an `aliapi` `show_when`: `flag <key>[=<option>]`, or the
/// same after `!`. Validated like the matcher; the answer is this
/// generation's.
pub(crate) fn condition(text: &str, path: &str, flags: &[Flag]) -> Result<bool, ConfigError> {
    let trimmed = text.trim();
    let (negated, rest) = match trimmed.strip_prefix('!') {
        Some(rest) => (true, rest.trim_start()),
        None => (false, trimmed),
    };
    let Some(args) = rest.strip_prefix("flag ") else {
        return Err(ConfigError::new(
            path,
            "show_when takes `flag <key>`, `flag <key>=<option>` or the same after `!`",
        ));
    };
    Ok(matches(args, path, flags)? != negated)
}

/// Whether `name` is one of the schema-2 `switch1`..`switch17` names, which
/// are refused with a pointer to `feature_flag`.
pub(super) fn legacy_switch(name: &str) -> bool {
    name.strip_prefix("switch")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Startup's one-time migration: when the settings file has no `flags`
/// section yet, the values the compile took from `rule/switchN.txt` are
/// written into it (differences only, `{}` when there are none), so the switch
/// files are never read again. Nothing is written when the file changed
/// since the compile; a failed write is logged and
/// retried at the next start. The live configuration is updated in place: the
/// values are the same, only their source becomes `settings`.
pub(crate) fn persist_migration(config: &mut super::CompiledConfig) {
    for note in &config.flag_legacy_notes {
        crate::diag::warn_line!("feature_flag migration: {note}; the YAML default applies");
    }
    if config.flags.is_empty() || config.settings.flags.is_some() {
        return;
    }
    let Some(root) = config.reload.as_ref().map(|reload| reload.root_dir.clone()) else {
        return;
    };
    let path = super::settings::Settings::path(&root);
    let current = match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            crate::diag::warn_line!("feature_flag migration not written: {error}");
            return;
        }
    };
    let unchanged = match &current {
        Some(bytes) => {
            super::settings::Settings::parse(bytes).ok() == Some(config.settings.clone())
        }
        None => config.settings == super::settings::Settings::default(),
    };
    if !unchanged {
        crate::diag::warn_line!(
            "feature_flag migration not written: {} changed since it was read",
            super::settings::SETTINGS_FILE
        );
        return;
    }
    let mut settings = config.settings.clone();
    settings.flags = Some(differences(&config.flags));
    let bytes = settings.to_bytes();
    if let Err(error) = crate::runtime_snapshot::write_durably(&path, &bytes) {
        crate::diag::warn_line!("feature_flag migration not written: {error}");
        return;
    }
    config.compile_inputs.files.insert(
        crate::special_groups::lexical_path(&path),
        Some(crate::special_groups::sha256(&bytes)),
    );
    config.settings = settings;
    for flag in &mut config.flags {
        if flag.source == "legacy" {
            flag.source = "settings";
        }
    }
    for item in &mut config.settings_report {
        if item.kind == "feature_flag" && item.source == "legacy" {
            item.source = "settings";
        }
    }
    crate::diag::info_line!(
        "feature_flag values migrated from rule/switchN.txt into {}",
        super::settings::SETTINGS_FILE
    );
}
