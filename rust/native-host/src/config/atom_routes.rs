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
/// The same for the refresh flow (`sequence_requery`): no rule cache, so a
/// refresh always asks the group (requery's flush list cannot name the
/// generated caches).
pub(crate) const REQUERY_SEQUENCE: &str = "atom_direct_requery";
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
/// file (`<stem>_<group>.dump` beside the template's); keyed by ECS too for
/// a group whose route adds one.
fn cache_for(template: &RawPlugin, tag: &str, group: &str, ecs: bool) -> RawPlugin {
    let mut plugin = template.clone();
    plugin.tag = tag.to_owned();
    plugin.source_path = format!("{} (for {group})", template.source_path);
    if let RawValue::Map(args) = &mut plugin.args {
        if ecs {
            args.entries.retain(|(key, _)| key != "enable_ecs");
            args.entries.push(("enable_ecs".to_owned(), RawValue::Bool(true)));
        }
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
    // `route_ecs`: group → `ecs_address` reference (`$client_ecs`); the
    // group's route adds that ECS before its cache and upstream, as the
    // YAML's own sequence for the group does (`sequence_google_node`).
    let mut ecs = Vec::new();
    if let RawValue::Map(args) = &definitions[rules_at].args {
        if let Some(value) = args.get("route_ecs") {
            let path = format!("{}.args.route_ecs", definitions[rules_at].source_path);
            let RawValue::Map(entries) = value else {
                return Err(ConfigError::new(path, "route_ecs must be a mapping"));
            };
            for (group, reference) in &entries.entries {
                let RawValue::String(reference) = reference else {
                    return Err(ConfigError::new(format!("{path}.{group}"), "expected `$tag`"));
                };
                ecs.push((group.clone(), reference.clone()));
            }
        }
    }
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
    let mut requery_steps = Vec::new();
    let mut routes = Vec::new();
    let mut caches = Vec::new();
    for (index, tag) in groups.iter().enumerate() {
        let cached = MARK_BASE + 2 * u32::try_from(index).unwrap_or(u32::MAX / 4);
        let both = format!("mark {cached} {}", cached + 1);
        let group_ecs = ecs.iter().find(|(group, _)| group == tag).map(|(_, r)| r);
        let mut prelude = vec![string(&format!(
            "flow_setter sequence={SEQUENCE} upstream={tag}"
        ))];
        if let Some(reference) = group_ecs {
            prelude.push(string(&format!("ecs {reference}")));
        }
        let forward = map(vec![
            ("matches", string(&both)),
            (
                "exec",
                RawValue::Sequence(vec![string(&format!("${tag}")), string("cname_remover")]),
            ),
        ]);
        let label = map(vec![
            ("matches", string(&both)),
            ("exec", RawValue::Sequence(prelude)),
        ]);
        requery_steps.push(label.clone());
        requery_steps.push(forward.clone());
        steps.push(label);
        if let Some(template) = &template {
            let cache_tag = format!("{CACHE}_{tag}");
            caches.push(cache_for(template, &cache_tag, tag, group_ecs.is_some()));
            steps.push(map(vec![
                ("matches", string(&format!("mark {cached}"))),
                ("exec", string(&format!("${cache_tag}"))),
            ]));
        }
        steps.push(forward);
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
        root_dir: root_dir.clone(),
    });
    definitions.push(RawPlugin {
        tag: REQUERY_SEQUENCE.to_owned(),
        kind: "sequence".to_owned(),
        args: RawValue::Sequence(requery_steps),
        source_path: format!("generated {REQUERY_SEQUENCE}"),
        root_dir,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plugin(tag: &str, kind: &str, args: RawValue) -> RawPlugin {
        RawPlugin {
            tag: tag.to_owned(),
            kind: kind.to_owned(),
            args,
            source_path: format!("$.plugins.{tag}"),
            root_dir: std::path::PathBuf::from("/tmp"),
        }
    }

    fn text(value: &RawValue) -> String {
        match value {
            RawValue::String(text) => text.clone(),
            RawValue::Sequence(items) => items.iter().map(text).collect::<Vec<_>>().join(" | "),
            RawValue::Map(map) => map
                .entries
                .iter()
                .map(|(key, value)| format!("{key}={}", text(value)))
                .collect::<Vec<_>>()
                .join(", "),
            RawValue::Bool(value) => value.to_string(),
            RawValue::Number(RawNumber::Unsigned(value)) => value.to_string(),
            _ => String::new(),
        }
    }

    #[test]
    fn routes_add_ecs_per_group_caches_and_a_cacheless_refresh_sequence() {
        let empty = || RawValue::Map(RawMap { entries: Vec::new() });
        let mut definitions = vec![
            plugin("cache_atom", "cache", map(vec![("dump_file", string("cache/cache_atom.dump"))])),
            plugin("domestic", "aliapi", empty()),
            plugin("foreignecs", "aliapi", empty()),
            plugin("nocnfake", "aliapi", empty()),
            plugin(
                "atom_rules",
                "atom_rules",
                map(vec![
                    ("marks", map(vec![("route", RawValue::Number(RawNumber::Unsigned(43)))])),
                    ("route_ecs", map(vec![("foreignecs", string("$client_ecs"))])),
                ]),
            ),
        ];
        synthesize(&mut definitions, &Settings::default()).unwrap();
        let find = |tag: &str| definitions.iter().find(|p| p.tag == tag);
        assert!(find("cache_atom").is_none(), "the template is not compiled");
        let ecs_cache = text(&find("cache_atom_foreignecs").unwrap().args);
        assert!(ecs_cache.contains("dump_file=cache/cache_atom_foreignecs.dump"), "{ecs_cache}");
        assert!(ecs_cache.contains("enable_ecs=true"), "{ecs_cache}");
        assert!(!text(&find("cache_atom_domestic").unwrap().args).contains("enable_ecs"));
        let rules = text(&find("atom_rules").unwrap().args);
        assert!(rules.contains("routes=domestic=70000, foreignecs=70002"), "{rules}");

        let direct = text(&find(SEQUENCE).unwrap().args);
        assert!(direct.contains("matches=mark 70002 70003, exec=flow_setter sequence=atom_direct upstream=foreignecs | ecs $client_ecs"), "{direct}");
        assert!(direct.contains("matches=mark 70002, exec=$cache_atom_foreignecs"), "{direct}");
        assert!(!direct.contains("mark 70000 70001, exec=flow_setter sequence=atom_direct upstream=domestic | ecs"), "{direct}");
        let refresh = text(&find(REQUERY_SEQUENCE).unwrap().args);
        assert!(!refresh.contains("$cache_atom"), "no rule cache when refreshing: {refresh}");
        assert!(refresh.contains("exec=$foreignecs | cname_remover"), "{refresh}");
        assert!(!refresh.contains("nocnfake") && !direct.contains("nocnfake"));
    }
}
