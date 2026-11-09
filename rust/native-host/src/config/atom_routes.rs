//! atom fork: the upstream groups a direct rule may name (atom step 6b).
//!
//! A direct rule may name an upstream group for its query (`dns`) and turn
//! caching off (`cache: false`). The groups are the configuration's forward
//! (`aliapi`) plugins other than the FakeIP one (`domestic`, `foreign`,
//! `foreignecs`) plus the custom groups of `settings.json`
//! (`atom_groups`), which are compiled here as forward plugins of their own.
//!
//! When the `atom_rules` plugin declares `marks.route`, this module also
//! generates the sequence [`SEQUENCE`]: every group has two numeric marks
//! (`mark N`: with the rule cache [`CACHE`], `mark N+1`: without), and the
//! `atom_rules` plugin receives the group → `N` table as its `routes`
//! argument. A rule that sends its query to a group sets the fast mark
//! `marks.route` and that numeric mark; the configuration runs
//! `$atom_direct` on the fast mark. Nothing here is written to disk: the
//! plugins exist only in the compiled configuration, so adding or removing
//! a group is a settings change (a new configuration generation).

use std::collections::BTreeSet;

use super::settings::Settings;
use super::{ConfigError, RawMap, RawNumber, RawPlugin, RawValue};

/// The generated sequence a routed direct rule runs.
pub(crate) const SEQUENCE: &str = "atom_direct";
/// The template of the routed direct rules' caches (declared in the YAML,
/// optional): each group gets a copy, `cache_atom_<group>`, with its own
/// dump file; the template itself is not compiled.
pub(crate) const CACHE: &str = "cache_atom";
/// The first group's numeric mark; group `i` has `BASE + 2i` (cached) and
/// `BASE + 2i + 1` (uncached).
const MARK_BASE: u32 = 70_000;
const MAX_NAME_CHARS: usize = 32;

fn error(path: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::new(format!("settings.json: {path}"), reason)
}

/// `u-` and eight lowercase hexadecimal digits.
pub(crate) fn valid_tag(tag: &str) -> bool {
    tag.strip_prefix("u-").is_some_and(|hex| {
        hex.len() == 8 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// A group name the UI shows: not blank, no control characters, at most 32
/// characters.
pub(crate) fn check_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("上游组名称不能为空".to_owned());
    }
    if name.chars().any(char::is_control) || name.trim() != name {
        return Err("上游组名称不能有首尾空白或控制字符".to_owned());
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(format!("上游组名称最长 {MAX_NAME_CHARS} 个字符"));
    }
    Ok(())
}

fn string(value: &str) -> RawValue {
    RawValue::String(value.to_owned())
}

fn map(entries: Vec<(&str, RawValue)>) -> RawValue {
    RawValue::Map(RawMap {
        entries: entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    })
}

/// A copy of the `cache_atom` template for one group: its own tag and dump
/// file (`<stem>_<group>.dump` beside the template's).
fn cache_for(template: &RawPlugin, tag: &str, group: &str) -> RawPlugin {
    let mut plugin = template.clone();
    plugin.tag = tag.to_owned();
    plugin.source_path = format!("{} (for {group})", template.source_path);
    if let RawValue::Map(args) = &mut plugin.args {
        for (key, value) in &mut args.entries {
            if key == "dump_file" {
                if let RawValue::String(path) = value {
                    *path = match path.strip_suffix(".dump") {
                        Some(stem) => format!("{stem}_{group}.dump"),
                        None => format!("{path}_{group}"),
                    };
                }
            }
        }
    }
    plugin
}

/// Adds the custom groups' forward plugins and, when `atom_rules` declares
/// `marks.route`, the [`SEQUENCE`] and the plugin's `routes` argument.
pub(super) fn synthesize(
    definitions: &mut Vec<RawPlugin>,
    settings: &Settings,
) -> Result<(), ConfigError> {
    let mut seen = BTreeSet::new();
    for (index, group) in settings.atom_groups.iter().enumerate() {
        let path = format!("atom_groups[{index}]");
        if !valid_tag(&group.tag) {
            return Err(error(&path, "tag 必须是 u- 加 8 位十六进制数字"));
        }
        if !seen.insert(group.tag.as_str()) || definitions.iter().any(|p| p.tag == group.tag) {
            return Err(error(&path, format!("tag `{}` 重复", group.tag)));
        }
        check_name(&group.name).map_err(|reason| error(&path, reason))?;
        let enabled = settings
            .upstreams
            .get(&group.tag)
            .is_some_and(|list| list.iter().any(|entry| entry.enabled));
        if !enabled {
            return Err(error(
                &path,
                format!("上游组 `{}` 在 upstreams 里没有启用的上游", group.tag),
            ));
        }
    }
    let Some(template) = definitions.iter().find(|p| p.kind == "aliapi").cloned() else {
        if settings.atom_groups.is_empty() {
            return Ok(());
        }
        return Err(error("atom_groups", "配置里没有 forward（aliapi）插件可参照"));
    };
    // The custom groups reach the outside like the foreign group: through
    // the forward plugins' `proxy` (`$main_proxy`) where an entry asks for it.
    let proxy = definitions
        .iter()
        .filter(|p| p.kind == "aliapi")
        .find_map(|p| match &p.args {
            RawValue::Map(args) => args.get("proxy").cloned(),
            _ => None,
        });
    for (index, group) in settings.atom_groups.iter().enumerate() {
        let mut args = vec![
            ("concurrent", RawValue::Number(RawNumber::Unsigned(1))),
            ("upstreams", RawValue::Sequence(Vec::new())),
        ];
        if let Some(proxy) = &proxy {
            args.push(("proxy", proxy.clone()));
        }
        definitions.push(RawPlugin {
            tag: group.tag.clone(),
            kind: "aliapi".to_owned(),
            args: map(args),
            source_path: format!("settings.json: atom_groups[{index}]"),
            root_dir: template.root_dir.clone(),
        });
    }

    let Some(rules_at) = definitions.iter().position(|p| p.kind == "atom_rules") else {
        return Ok(());
    };
    let declares_route = match &definitions[rules_at].args {
        RawValue::Map(args) => {
            if args.get("routes").is_some() {
                return Err(ConfigError::new(
                    format!("{}.args.routes", definitions[rules_at].source_path),
                    "routes is generated from the upstream groups; do not write it",
                ));
            }
            matches!(args.get("marks"), Some(RawValue::Map(marks)) if marks.get("route").is_some())
        }
        _ => false,
    };
    if !declares_route {
        return Ok(());
    }
    let groups: Vec<String> = definitions
        .iter()
        .filter(|p| p.kind == "aliapi" && p.tag != crate::edns_directive::FAKEIP_UPSTREAM)
        .map(|p| p.tag.clone())
        .collect();
    // One rule cache per group, cloned from `cache_atom`: a cached answer
    // never crosses groups (client rules can send one name to two groups).
    let template = definitions
        .iter()
        .position(|p| p.tag == CACHE && p.kind == "cache")
        .map(|at| definitions.remove(at));
    let mut steps = Vec::new();
    let mut routes = Vec::new();
    let mut caches = Vec::new();
    for (index, tag) in groups.iter().enumerate() {
        let cached = MARK_BASE + 2 * u32::try_from(index).unwrap_or(u32::MAX / 4);
        let label = map(vec![
            ("matches", string(&format!("mark {cached} {}", cached + 1))),
            (
                "exec",
                string(&format!("flow_setter sequence={SEQUENCE} upstream={tag}")),
            ),
        ]);
        steps.push(label);
        if let Some(template) = &template {
            let cache_tag = format!("{CACHE}_{tag}");
            caches.push(cache_for(template, &cache_tag, tag));
            steps.push(map(vec![
                ("matches", string(&format!("mark {cached}"))),
                ("exec", string(&format!("${cache_tag}"))),
            ]));
        }
        steps.push(map(vec![
            ("matches", string(&format!("mark {cached} {}", cached + 1))),
            (
                "exec",
                RawValue::Sequence(vec![string(&format!("${tag}")), string("cname_remover")]),
            ),
        ]));
        routes.push((tag.clone(), RawValue::Number(RawNumber::Unsigned(u64::from(cached)))));
    }
    definitions.extend(caches);
    // Removing the template moved the plugins after it.
    let rules_at = definitions
        .iter()
        .position(|p| p.kind == "atom_rules")
        .unwrap_or(rules_at);
    let root_dir = definitions[rules_at].root_dir.clone();
    if let RawValue::Map(args) = &mut definitions[rules_at].args {
        args.entries.push((
            "routes".to_owned(),
            RawValue::Map(RawMap { entries: routes }),
        ));
    }
    definitions.push(RawPlugin {
        tag: SEQUENCE.to_owned(),
        kind: "sequence".to_owned(),
        args: RawValue::Sequence(steps),
        source_path: format!("generated {SEQUENCE}"),
        root_dir,
    });
    Ok(())
}
