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
/// The cache of routed direct rules (declared in the YAML, optional).
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
    let cache = definitions.iter().any(|p| p.tag == CACHE && p.kind == "cache");
    let mut steps = Vec::new();
    let mut routes = Vec::new();
    for (index, tag) in groups.iter().enumerate() {
        let cached = MARK_BASE + 2 * u32::try_from(index).unwrap_or(u32::MAX / 4);
        let forward = RawValue::Sequence(vec![
            string(&format!("flow_setter sequence={SEQUENCE} upstream={tag}")),
            string(&format!("${tag}")),
            string("cname_remover"),
        ]);
        if cache {
            steps.push(map(vec![
                ("matches", string(&format!("mark {cached}"))),
                ("exec", string(&format!("${CACHE}"))),
            ]));
        }
        steps.push(map(vec![
            ("matches", string(&format!("mark {cached}"))),
            ("exec", forward.clone()),
        ]));
        steps.push(map(vec![
            ("matches", string(&format!("mark {}", cached + 1))),
            ("exec", forward),
        ]));
        routes.push((tag.clone(), RawValue::Number(RawNumber::Unsigned(u64::from(cached)))));
    }
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
