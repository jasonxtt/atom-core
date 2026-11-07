//! HTTP routes of the typed settings layer: the WebUI's `/api/v1/overrides`,
//! `/api/v1/domain-generation`, `/api/v1/flags`, the effective-settings report
//! and the settings-backed `POST /api/v1/upstream/config`. Every change builds new
//! settings and goes through `RuntimeControl::apply_settings` (a whole
//! generation, or nothing). See `docs/rust/contracts/native-settings.md`.

use serde::Deserialize;

use crate::config::CompiledConfig;
use crate::config::flags::{Flag, FlagValue};
use crate::config::settings::{
    CACHE_DUMP_INTERVAL_RANGE, CACHE_LAZY_TTL_RANGE, CACHE_SIZE_RANGE, CacheDefaults,
    LEARNER_TTL_RANGE, LEARNER_WRITE_INTERVAL_RANGE, Learning, NO_V4, NO_V6, PluginSwitch,
    REMEMBER_DIRECT, REMEMBER_PROXY, UpstreamEntry,
};
use crate::rule_sources::Reply;
use crate::runtime_snapshot::{ApplyFailure, RuntimeControl};

const JSON: &str = "application/json; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";

fn text(status: u16, message: &str) -> Reply {
    Reply {
        status,
        content_type: Some(TEXT),
        body: format!("{message}\n").into_bytes(),
        headers: Vec::new(),
    }
}

fn json(status: u16, value: &serde_json::Value) -> Reply {
    let mut body = serde_json::to_vec(value).unwrap_or_default();
    body.push(b'\n');
    Reply {
        status,
        content_type: Some(JSON),
        body,
        headers: Vec::new(),
    }
}

fn not_allowed() -> Reply {
    Reply {
        status: 405,
        content_type: Some(TEXT),
        body: b"method not allowed\n".to_vec(),
        headers: Vec::new(),
    }
}

/// An apply failure as the HTTP answer.
fn failure(error: ApplyFailure) -> Reply {
    match error {
        ApplyFailure::Invalid(reason) => text(400, &reason),
        ApplyFailure::Busy(reason) => text(409, &format!("settings are being applied: {reason}")),
        ApplyFailure::Conflict(path) => text(
            409,
            &format!("{} changed while applying; retry", path.display()),
        ),
        ApplyFailure::ResourceConflict(reason) => text(409, &reason),
        ApplyFailure::Failed(reason) => text(500, &reason),
        ApplyFailure::Shutdown => text(503, "host is stopping"),
        ApplyFailure::RecoveryRequired(reason) => {
            text(503, &format!("recovery required: {reason}"))
        }
        ApplyFailure::CommittedCleanup { generation, reason } => text(
            500,
            &format!("settings applied as generation {generation}, but cleanup failed: {reason}"),
        ),
    }
}

/// The UI shape of one upstream entry: `use_socks_proxy` is the effective
/// proxy switch (the reference field name).
fn entry_json(entry: &UpstreamEntry) -> serde_json::Value {
    let mut value = serde_json::to_value(entry).unwrap_or_default();
    if let Some(map) = value.as_object_mut() {
        // The page's field is the reference name, `use_socks_proxy`.
        map.remove("use_proxy");
        map.insert(
            "use_socks_proxy".to_owned(),
            serde_json::Value::Bool(entry.proxy_switch()),
        );
    }
    value
}

/// `GET /api/v1/upstream/config`: every `aliapi` tag with its effective list.
pub(crate) fn upstream_config(config: &CompiledConfig) -> serde_json::Value {
    serde_json::Value::Object(
        config
            .effective_upstreams
            .iter()
            .map(|(tag, entries)| {
                (
                    tag.clone(),
                    serde_json::Value::Array(entries.iter().map(entry_json).collect()),
                )
            })
            .collect(),
    )
}

/// `GET /api/v1/upstream/groups`: every `aliapi` group, whether its
/// `show_when` holds in this generation, the conditions, when they are met
/// (`used_when`, in words; only with conditions) and, when they are not, why the
/// group is not in use.
pub(crate) fn upstream_groups(config: &CompiledConfig) -> serde_json::Value {
    serde_json::Value::Array(
        config
            .effective_upstreams
            .keys()
            .map(|tag| {
                let conditions = show_when(config, tag);
                let active = group_active(config, tag);
                let mut value = serde_json::json!({
                    "tag": tag,
                    "active": active,
                    "show_when": conditions,
                });
                if !conditions.is_empty() {
                    value["used_when"] = usage(config, tag).into();
                }
                if !active {
                    value["inactive_reason"] = format!("仅在{}时使用", usage(config, tag)).into();
                }
                value
            })
            .collect(),
    )
}

fn show_when<'a>(config: &'a CompiledConfig, tag: &str) -> &'a [String] {
    config
        .yaml_defaults
        .show_when
        .get(tag)
        .map_or(&[], Vec::as_slice)
}

/// Whether every `show_when` condition of `tag` holds (validated at load).
fn group_active(config: &CompiledConfig, tag: &str) -> bool {
    show_when(config, tag).iter().all(|text| {
        crate::config::flags::condition(text, "show_when", &config.flags).unwrap_or(true)
    })
}

/// `「国内域名 FakeIP」开启` (conditions joined by `且`).
fn usage(config: &CompiledConfig, tag: &str) -> String {
    show_when(config, tag)
        .iter()
        .map(|text| crate::config::flags::describe(text, &config.flags))
        .collect::<Vec<_>>()
        .join("且")
}

/// The settings entries of `tag`, for `GET /runtime/{tag}`.
pub(crate) fn override_config(config: &CompiledConfig, tag: &str) -> Vec<serde_json::Value> {
    config
        .settings
        .upstreams
        .get(tag)
        .map(|entries| entries.iter().map(entry_json).collect())
        .unwrap_or_default()
}

/// `POST /api/v1/upstream/config {plugin_tag, upstreams}`.
pub(crate) async fn post_upstream(control: &RuntimeControl, body: &[u8]) -> Reply {
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        plugin_tag: String,
        #[serde(default)]
        upstreams: Vec<UpstreamEntry>,
    }
    let payload: Payload = match serde_json::from_slice(body) {
        Ok(payload) => payload,
        Err(error) => {
            return text(
                400,
                &format!("invalid upstream configuration JSON: {error}"),
            );
        }
    };
    let tag = payload.plugin_tag.trim().to_owned();
    if tag.is_empty() {
        return text(400, "plugin_tag is required");
    }
    let current = control.view();
    if !current.config.effective_upstreams.contains_key(&tag) {
        return text(404, "upstream tag not found");
    }
    for (index, entry) in payload.upstreams.iter().enumerate() {
        if let Err(reason) = entry.validate(index) {
            return text(400, &reason);
        }
    }
    // An empty list restores the YAML list; a list must keep one enabled
    // upstream (an `aliapi` without one does not load).
    if !payload.upstreams.is_empty() && !payload.upstreams.iter().any(|entry| entry.enabled) {
        let mut reason = format!("上游组「{tag}」至少要保留一个启用的上游。");
        if !show_when(&current.config, &tag).is_empty() {
            reason.push_str(&format!(
                "这个组只在{}时使用；不想用它，关闭该开关即可。",
                usage(&current.config, &tag)
            ));
        }
        return text(400, &reason);
    }
    if let Some(profile) = &current.config.standard_groups {
        if profile
            .groups
            .iter()
            .any(|group| format!("special_upstream_{}", group.slot) == tag)
        {
            return text(400, "专属分流组上游只能在专属分流组设置中维护");
        }
    }
    let mut settings = current.config.settings.clone();
    let mut entries = payload.upstreams;
    for entry in &mut entries {
        entry.use_proxy = Some(entry.proxy_switch());
        entry.use_socks_proxy = None;
    }
    // Presence records UI/API management, including when the list equals
    // YAML: managed groups derive concurrency from their enabled entries.
    // Only an explicit empty list restores YAML list/concurrency semantics.
    if entries.is_empty() {
        settings.upstreams.remove(&tag);
    } else {
        settings.upstreams.insert(tag, entries);
    }
    drop(current);
    match control.apply_settings(settings).await {
        Ok(_) => json(
            200,
            &serde_json::json!({ "message": "Upstream configuration saved." }),
        ),
        Err(error) => failure(error),
    }
}

/// The overrides page exists when a `socks5_proxy` or `ecs_address` does.
pub(crate) fn overrides_available(config: &CompiledConfig) -> bool {
    config.reload.is_some()
        && config
            .settings_report
            .iter()
            .any(|item| matches!(item.kind, "socks5_proxy" | "ecs_address"))
}

/// The domain-generation switches exist when a `domain_output` does.
pub(crate) fn generation_available(config: &CompiledConfig) -> bool {
    config.reload.is_some()
        && (!config.local.domain_outputs.is_empty() || !config.local.learners.is_empty())
}

/// The flag routes exist when a file-backed configuration declares a flag.
pub(crate) fn flags_available(config: &CompiledConfig) -> bool {
    config.reload.is_some() && !config.flags.is_empty()
}

/// The cache numbers are tunable when a file-backed configuration has a `cache`.
pub(crate) fn cache_settings_available(config: &CompiledConfig) -> bool {
    config.reload.is_some() && !config.yaml_defaults.caches.is_empty()
}

/// The learner numbers are tunable when a file-backed configuration has a
/// `route_learner`.
pub(crate) fn learning_settings_available(config: &CompiledConfig) -> bool {
    config.reload.is_some() && !config.yaml_defaults.categories.is_empty()
}

/// The tags of one plugin kind in the effective report, in order.
fn objects<'a>(config: &'a CompiledConfig, kind: &str) -> Vec<&'a crate::config::EffectiveItem> {
    config
        .settings_report
        .iter()
        .filter(|item| item.kind == kind)
        .collect()
}

/// `/api/v1/overrides`, `/api/v1/domain-generation`, `/api/v1/flags[/{key}]`,
/// `/api/v1/settings/effective`; `None` for any other path.
pub(crate) async fn handle(
    control: Option<&RuntimeControl>,
    config: &CompiledConfig,
    method: &str,
    path: &str,
    body: &[u8],
) -> Option<Reply> {
    let reply = match path.trim_end_matches('/') {
        "/api/v1/settings/effective" => match method {
            "GET" => effective(config),
            _ => not_allowed(),
        },
        "/api/v1/flags" if !flags_available(config) => return None,
        "/api/v1/flags" => match method {
            "GET" => flags_get(config),
            _ => not_allowed(),
        },
        other if other.starts_with("/api/v1/flags/") => {
            if !flags_available(config) {
                return None;
            }
            let key = &other["/api/v1/flags/".len()..];
            match method {
                "POST" | "DELETE" => match control {
                    Some(control) => flag_change(control, method, key, body).await,
                    None => text(503, "runtime control is unavailable"),
                },
                _ => not_allowed(),
            }
        }
        "/api/v1/cache/settings" if !cache_settings_available(config) => return None,
        "/api/v1/cache/settings" => match method {
            "GET" => cache_settings_get(config),
            _ => not_allowed(),
        },
        other if other.starts_with("/api/v1/cache/settings/") => {
            if !cache_settings_available(config) {
                return None;
            }
            let tag = &other["/api/v1/cache/settings/".len()..];
            match method {
                "POST" | "DELETE" => match control {
                    Some(control) => cache_settings_change(control, method, tag, body).await,
                    None => text(503, "runtime control is unavailable"),
                },
                _ => not_allowed(),
            }
        }
        "/api/v1/learning/settings" if !learning_settings_available(config) => return None,
        "/api/v1/learning/settings" => match method {
            "GET" => learning_settings_get(config),
            "POST" | "DELETE" => match control {
                Some(control) => learning_settings_change(control, method, body).await,
                None => text(503, "runtime control is unavailable"),
            },
            _ => not_allowed(),
        },
        "/api/v1/overrides" if !overrides_available(config) => return None,
        "/api/v1/domain-generation" if !generation_available(config) => return None,
        "/api/v1/overrides" => match method {
            "GET" => overrides_get(config),
            "POST" => match control {
                Some(control) => overrides_post(control, body).await,
                None => text(503, "runtime control is unavailable"),
            },
            _ => not_allowed(),
        },
        "/api/v1/domain-generation" => match method {
            "GET" => generation_get(config),
            "POST" => match control {
                Some(control) => generation_post(control, body).await,
                None => text(503, "runtime control is unavailable"),
            },
            _ => not_allowed(),
        },
        _ => return None,
    };
    Some(reply)
}

/// One tunable number: the effective value, the YAML one and whether they
/// differ.
fn number_json(value: u64, default: u64) -> serde_json::Value {
    serde_json::json!({"value": value, "default": default, "modified": value != default})
}

/// The effective numbers of a cache (the settings value, else the YAML one).
fn cache_numbers(config: &CompiledConfig, tag: &str, yaml: CacheDefaults) -> [u64; 3] {
    let own = config.settings.caches.get(tag).cloned().unwrap_or_default();
    [
        own.size.unwrap_or(yaml.size),
        own.lazy_cache_ttl.unwrap_or(yaml.lazy_cache_ttl),
        own.dump_interval.unwrap_or(yaml.dump_interval),
    ]
}

fn cache_json(config: &CompiledConfig, tag: &str, yaml: CacheDefaults) -> serde_json::Value {
    let [size, lazy, dump] = cache_numbers(config, tag, yaml);
    let label = config
        .caches
        .iter()
        .find(|cache| cache.tag == tag)
        .map_or("", |cache| cache.label.as_str());
    serde_json::json!({
        "tag": tag,
        "label": label,
        "size": number_json(size, yaml.size),
        "lazy_cache_ttl": number_json(lazy, yaml.lazy_cache_ttl),
        "dump_interval": number_json(dump, yaml.dump_interval),
    })
}

/// `GET /api/v1/cache/settings`: every `cache` in configuration order.
fn cache_settings_get(config: &CompiledConfig) -> Reply {
    let caches: Vec<_> = config
        .settings_report
        .iter()
        .filter(|item| item.kind == "cache" && item.field == "size")
        .filter_map(|item| {
            let yaml = *config.yaml_defaults.caches.get(&item.object)?;
            Some(cache_json(config, &item.object, yaml))
        })
        .collect();
    json(
        200,
        &serde_json::json!({
            "settings_file": crate::config::settings::SETTINGS_FILE,
            "caches": caches,
        }),
    )
}

/// A body field: a whole number inside `range`, or `null` (back to the YAML
/// value).
fn tuned_number(
    name: &str,
    value: &serde_json::Value,
    (low, high): (u64, u64),
) -> Result<Option<u64>, String> {
    match value {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::Number(number) => match number.as_u64() {
            Some(value) if (low..=high).contains(&value) => Ok(Some(value)),
            Some(value) => Err(format!(
                "{name} must be between {low} and {high}, got {value}"
            )),
            None => Err(format!("{name} must be a whole number or null")),
        },
        _ => Err(format!("{name} must be a whole number or null")),
    }
}

/// `POST /api/v1/cache/settings/{tag}` (`{"size"?, "lazy_cache_ttl"?,
/// "dump_interval"?}`, `null` restores a field) and `DELETE` (restores all).
/// Every one of the three is part of the cache's identity: a changed value
/// replaces the cache by an empty one (`reset` names it).
async fn cache_settings_change(
    control: &RuntimeControl,
    method: &str,
    tag: &str,
    body: &[u8],
) -> Reply {
    let current = control.view();
    let Some(yaml) = current.config.yaml_defaults.caches.get(tag).copied() else {
        return text(404, &format!("no cache `{tag}`"));
    };
    let mut patch: Vec<(&str, Option<u64>)> = Vec::new();
    if method == "DELETE" {
        patch.extend([
            ("size", None),
            ("lazy_cache_ttl", None),
            ("dump_interval", None),
        ]);
    } else {
        let Ok(serde_json::Value::Object(object)) = serde_json::from_slice(body) else {
            return text(400, "expected a JSON object");
        };
        if object.is_empty() {
            return text(
                400,
                "expected at least one of: size, lazy_cache_ttl, dump_interval",
            );
        }
        for (name, value) in &object {
            let (name, range) = match name.as_str() {
                "size" => ("size", CACHE_SIZE_RANGE),
                "lazy_cache_ttl" => ("lazy_cache_ttl", CACHE_LAZY_TTL_RANGE),
                "dump_interval" => ("dump_interval", CACHE_DUMP_INTERVAL_RANGE),
                other => return text(400, &format!("unsupported field `{other}`")),
            };
            match tuned_number(name, value, range) {
                Ok(value) => patch.push((name, value)),
                Err(reason) => return text(400, &reason),
            }
        }
    }
    let before = cache_numbers(&current.config, tag, yaml);
    let mut settings = current.config.settings.clone();
    let mut tuning = settings.caches.remove(tag).unwrap_or_default();
    for (name, value) in patch {
        let (slot, default) = match name {
            "size" => (&mut tuning.size, yaml.size),
            "lazy_cache_ttl" => (&mut tuning.lazy_cache_ttl, yaml.lazy_cache_ttl),
            _ => (&mut tuning.dump_interval, yaml.dump_interval),
        };
        // Only differences from the YAML are stored.
        *slot = value.filter(|value| *value != default);
    }
    if !tuning.is_empty() {
        settings.caches.insert(tag.to_owned(), tuning);
    }
    let unchanged = settings == current.config.settings;
    drop(current);
    if !unchanged {
        if let Err(error) = control.apply_settings(settings).await {
            return failure(error);
        }
    }
    let view = control.view();
    let reset = !unchanged && cache_numbers(&view.config, tag, yaml) != before;
    json(
        200,
        &serde_json::json!({
            "cache": cache_json(&view.config, tag, yaml),
            "reset": if reset { vec![tag] } else { Vec::new() },
        }),
    )
}

fn learning_json(config: &CompiledConfig) -> serde_json::Value {
    let learning = &config.settings.learning;
    let yaml_interval = config.yaml_defaults.write_interval.unwrap_or(21_600);
    serde_json::json!({
        "settings_file": crate::config::settings::SETTINGS_FILE,
        "write_interval": number_json(learning.write_interval.unwrap_or(yaml_interval), yaml_interval),
        "categories": config
            .yaml_defaults
            .categories
            .iter()
            .map(|(tag, yaml)| {
                let own = learning.categories.get(tag).cloned().unwrap_or_default();
                serde_json::json!({
                    "tag": tag,
                    "ttl": number_json(own.ttl.unwrap_or(yaml.ttl), yaml.ttl),
                    "max_entries": number_json(own.max_entries.unwrap_or(yaml.max_entries), yaml.max_entries),
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn learning_settings_get(config: &CompiledConfig) -> Reply {
    json(200, &learning_json(config))
}

/// `POST /api/v1/learning/settings` (`{"write_interval"?, "categories"?:
/// {"<tag>": {"ttl"?, "max_entries"?}}}`, `null` restores a value) and
/// `DELETE` (restores everything). One request is one published generation.
/// The learned names stay: a lowered `max_entries` keeps the most recently
/// confirmed ones.
async fn learning_settings_change(control: &RuntimeControl, method: &str, body: &[u8]) -> Reply {
    let current = control.view();
    let mut settings = current.config.settings.clone();
    if method == "DELETE" {
        settings.learning = Learning::default();
    } else if let Err(reply) = patch_learning(&current.config, &mut settings, body) {
        return reply;
    }
    let unchanged = settings == current.config.settings;
    drop(current);
    if !unchanged {
        if let Err(error) = control.apply_settings(settings).await {
            return failure(error);
        }
    }
    json(200, &learning_json(&control.view().config))
}

/// Applies a learning request body to `settings`; the error is the HTTP answer.
fn patch_learning(
    config: &CompiledConfig,
    settings: &mut crate::config::settings::Settings,
    body: &[u8],
) -> Result<(), Reply> {
    let Ok(serde_json::Value::Object(object)) = serde_json::from_slice(body) else {
        return Err(text(400, "expected a JSON object"));
    };
    if object.is_empty() {
        return Err(text(
            400,
            "expected at least one of: write_interval, categories",
        ));
    }
    let cap = u64::try_from(crate::route_learner::MAX_ENTRIES_CAP).unwrap_or(u64::MAX);
    for (name, value) in &object {
        match name.as_str() {
            "write_interval" => {
                let value = tuned_number(name, value, LEARNER_WRITE_INTERVAL_RANGE)
                    .map_err(|reason| text(400, &reason))?;
                let yaml = config.yaml_defaults.write_interval;
                settings.learning.write_interval = value.filter(|value| Some(*value) != yaml);
            }
            "categories" => {
                let Some(map) = value.as_object() else {
                    return Err(text(
                        400,
                        "categories must be an object keyed by category tag",
                    ));
                };
                for (tag, fields) in map {
                    let Some((_, yaml)) = config
                        .yaml_defaults
                        .categories
                        .iter()
                        .find(|(name, _)| name == tag)
                    else {
                        return Err(text(404, &format!("no route_learner category `{tag}`")));
                    };
                    let Some(fields) = fields.as_object() else {
                        return Err(text(400, &format!("categories.{tag} must be an object")));
                    };
                    let mut tuning = settings.learning.categories.remove(tag).unwrap_or_default();
                    for (field, value) in fields {
                        let at = format!("categories.{tag}.{field}");
                        match field.as_str() {
                            "ttl" => {
                                let value = tuned_number(&at, value, LEARNER_TTL_RANGE)
                                    .map_err(|reason| text(400, &reason))?;
                                tuning.ttl = value.filter(|value| *value != yaml.ttl);
                            }
                            "max_entries" => {
                                let value = tuned_number(&at, value, (1, cap))
                                    .map_err(|reason| text(400, &reason))?;
                                tuning.max_entries =
                                    value.filter(|value| *value != yaml.max_entries);
                            }
                            other => {
                                return Err(text(
                                    400,
                                    &format!("unsupported field `{other}` in categories.{tag}"),
                                ));
                            }
                        }
                    }
                    if !tuning.is_empty() {
                        settings.learning.categories.insert(tag.clone(), tuning);
                    }
                }
            }
            other => return Err(text(400, &format!("unsupported field `{other}`"))),
        }
    }
    Ok(())
}

fn flag_json(flag: &Flag) -> serde_json::Value {
    let mut value = serde_json::json!({
        "key": flag.key,
        "label": flag.label,
        "description": flag.description,
        "section": flag.section,
        "kind": flag.kind(),
        "default": flag.default,
        "value": flag.value,
        "modified": flag.value != flag.default,
        "source": flag.source,
        "requery_on_change": flag.requery_on_change,
    });
    if let Some(options) = &flag.options {
        value["options"] = options
            .iter()
            .map(|option| serde_json::json!({"value": option.value, "label": option.label}))
            .collect();
    }
    value
}

fn flags_get(config: &CompiledConfig) -> Reply {
    json(
        200,
        &serde_json::json!({
            "settings_file": crate::config::settings::SETTINGS_FILE,
            "migrated": config.settings.flags.is_some(),
            "flags": config.flags.iter().map(flag_json).collect::<Vec<_>>(),
        }),
    )
}

/// `POST /api/v1/flags/{key}` (`{"value": …}`) and `DELETE` (back to the
/// default). Only the differences from the defaults are stored; a flag set to
/// its default leaves the `flags` section (which stays, possibly empty).
async fn flag_change(control: &RuntimeControl, method: &str, key: &str, body: &[u8]) -> Reply {
    let current = control.view();
    let Some(flag) = current.config.flags.iter().find(|flag| flag.key == key) else {
        return text(404, &format!("no feature_flag `{key}`"));
    };
    let value = if method == "DELETE" {
        flag.default.clone()
    } else {
        let Ok(serde_json::Value::Object(object)) = serde_json::from_slice(body) else {
            return text(400, "expected a JSON object {\"value\": ...}");
        };
        if object.len() != 1 {
            return text(400, "expected exactly one field: value");
        }
        let value = match object.get("value") {
            Some(serde_json::Value::Bool(value)) => FlagValue::Bool(*value),
            Some(serde_json::Value::String(value)) => FlagValue::Choice(value.clone()),
            _ => return text(400, "value must be a boolean or an option string"),
        };
        if !flag.accepts(&value) {
            return text(
                400,
                &format!(
                    "`{value}` is not a valid value of the {} flag `{key}`",
                    flag.kind()
                ),
            );
        }
        value
    };
    if value == flag.value {
        return flag_reply(flag, false);
    }
    let requery_on_change = flag.requery_on_change;
    let mut settings = current.config.settings.clone();
    // Before the first migration the values may come from the legacy switch
    // files; the first change stores all of them.
    let mut stored = settings
        .flags
        .take()
        .unwrap_or_else(|| crate::config::flags::differences(&current.config.flags));
    if value == flag.default {
        stored.remove(key);
    } else {
        stored.insert(key.to_owned(), value);
    }
    settings.flags = Some(stored);
    drop(current);
    if let Err(error) = control.apply_settings(settings).await {
        return failure(error);
    }
    let view = control.view();
    let triggered = requery_on_change && trigger_requery(&view.config).await;
    match view.config.flags.iter().find(|flag| flag.key == key) {
        Some(flag) => flag_reply(flag, triggered),
        None => text(500, "the flag is gone after the change"),
    }
}

/// The answer of a flag change: the flag and whether the change started a
/// `requery` task (`requery_triggered`).
fn flag_reply(flag: &Flag, triggered: bool) -> Reply {
    let mut value = flag_json(flag);
    value["requery_triggered"] = triggered.into();
    json(200, &value)
}

/// Starts a `requery` task on the generation that was just published. False
/// when the configuration has no `requery` plugin or the task did not start
/// (the change itself stays applied either way).
async fn trigger_requery(config: &CompiledConfig) -> bool {
    let Some(requery) = config.local.requeries.first() else {
        return false;
    };
    let reply = requery.runtime.handle("POST", "trigger", &[]).await;
    if reply.status != 200 {
        crate::diag::warn_line!(
            "{}: the flag change did not start a task (HTTP {})",
            requery.tag,
            reply.status
        );
    }
    reply.status == 200
}

fn effective(config: &CompiledConfig) -> Reply {
    json(
        200,
        &serde_json::json!({
            "settings_file": crate::config::settings::SETTINGS_FILE,
            "items": config.settings_report,
        }),
    )
}

/// The one object of a kind, or why there is not exactly one.
fn unique<'a>(
    config: &'a CompiledConfig,
    kind: &str,
) -> Result<Option<&'a crate::config::EffectiveItem>, String> {
    let all = objects(config, kind);
    match all.len() {
        0 => Ok(None),
        1 => Ok(Some(all[0])),
        _ => Err(format!(
            "ambiguous: several {kind} objects ({}); the WebUI field maps to exactly one",
            all.iter()
                .map(|item| item.object.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn overrides_get(config: &CompiledConfig) -> Reply {
    let value = |kind: &str| -> Result<String, String> {
        Ok(unique(config, kind)?
            .map(|item| item.value.clone())
            .unwrap_or_default())
    };
    match (value("socks5_proxy"), value("ecs_address")) {
        (Ok(socks5), Ok(ecs)) => json(
            200,
            &serde_json::json!({ "socks5": socks5, "ecs": ecs, "replacements": [] }),
        ),
        (Err(reason), _) | (_, Err(reason)) => text(409, &reason),
    }
}

async fn overrides_post(control: &RuntimeControl, body: &[u8]) -> Reply {
    #[derive(Deserialize)]
    struct Replacement {
        #[serde(default)]
        original: String,
    }
    #[derive(Deserialize)]
    struct Payload {
        #[serde(default)]
        socks5: String,
        #[serde(default)]
        ecs: String,
        #[serde(default)]
        replacements: Option<Vec<Replacement>>,
    }
    let payload: Payload = match serde_json::from_slice(body) {
        Ok(payload) => payload,
        Err(error) => return text(400, &format!("Invalid request body: {error}")),
    };
    if payload
        .replacements
        .as_ref()
        .is_some_and(|rules| rules.iter().any(|rule| !rule.original.trim().is_empty()))
    {
        return text(
            400,
            "replacements are not supported; use socks5_proxy / ecs_address objects",
        );
    }
    let current = control.view();
    let mut settings = current.config.settings.clone();
    for (kind, wanted, section) in [
        ("socks5_proxy", payload.socks5.trim(), "proxies"),
        ("ecs_address", payload.ecs.trim(), "ecs"),
    ] {
        let object = match unique(&current.config, kind) {
            Ok(object) => object,
            Err(reason) => return text(409, &reason),
        };
        let Some(object) = object else {
            if wanted.is_empty() {
                continue;
            }
            return text(400, &format!("no {kind} object is configured"));
        };
        let map = if section == "proxies" {
            &mut settings.proxies
        } else {
            &mut settings.ecs
        };
        let yaml = if section == "proxies" {
            &current.config.yaml_defaults.proxies
        } else {
            &current.config.yaml_defaults.ecs
        };
        if wanted.is_empty()
            || yaml
                .get(&object.object)
                .is_some_and(|value| value == wanted)
        {
            // Back to the YAML value.
            map.remove(&object.object);
        } else {
            map.insert(
                object.object.clone(),
                crate::config::settings::Addr {
                    addr: wanted.to_owned(),
                },
            );
        }
    }
    let unchanged = settings == current.config.settings;
    drop(current);
    if !unchanged {
        if let Err(error) = control.apply_settings(settings).await {
            return failure(error);
        }
    }
    json(
        200,
        &serde_json::json!({ "message": "Global overrides saved and applied." }),
    )
}

/// The five WebUI switches from the effective report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Generation {
    enabled: bool,
    remember_direct: bool,
    remember_proxy: bool,
    no_v4: bool,
    no_v6: bool,
}

impl Generation {
    fn of(config: &CompiledConfig) -> Self {
        let settings = &config.settings;
        // A plugin's own setting, else what the YAML says, else on.
        let plugin = |tag: &str| {
            settings
                .domain_generation
                .plugins
                .get(tag)
                .map(|switch| switch.enabled)
                .or_else(|| config.yaml_defaults.generation.get(tag).copied())
                .unwrap_or(true)
        };
        Self {
            enabled: settings.domain_generation.enabled.unwrap_or(true),
            remember_direct: plugin(REMEMBER_DIRECT),
            remember_proxy: plugin(REMEMBER_PROXY),
            no_v4: plugin(NO_V4),
            no_v6: plugin(NO_V6),
        }
    }

    fn json(self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "remember_direct": self.remember_direct,
            "remember_proxy": self.remember_proxy,
            "no_v4": self.no_v4,
            "no_v6": self.no_v6,
        })
    }
}

fn generation_get(config: &CompiledConfig) -> Reply {
    json(200, &Generation::of(config).json())
}

async fn generation_post(control: &RuntimeControl, body: &[u8]) -> Reply {
    #[derive(Deserialize)]
    struct Patch {
        enabled: Option<bool>,
        remember_direct: Option<bool>,
        remember_proxy: Option<bool>,
        no_v4: Option<bool>,
        no_v6: Option<bool>,
    }
    let patch: Patch = match serde_json::from_slice(body) {
        Ok(patch) => patch,
        Err(error) => return text(400, &error.to_string()),
    };
    let current = control.view();
    let before = Generation::of(&current.config);
    let mut after = before;
    if let Some(value) = patch.enabled {
        after.enabled = value;
    }
    if let Some(value) = patch.remember_direct {
        after.remember_direct = value;
    }
    if let Some(value) = patch.remember_proxy {
        after.remember_proxy = value;
    }
    if let Some(value) = patch.no_v4 {
        after.no_v4 = value;
    }
    if let Some(value) = patch.no_v6 {
        after.no_v6 = value;
    }
    let present: Vec<String> = current
        .config
        .local
        .domain_outputs
        .iter()
        .map(|output| output.tag.clone())
        .chain(
            current
                .config
                .local
                .learners
                .iter()
                .flat_map(|learner| learner.runtime.category_tags().map(str::to_owned)),
        )
        .collect();
    // The reference flushes a list whose switch went from on to off; the master
    // switch going off flushes every list.
    let mut flush: Vec<String> = Vec::new();
    if before.enabled && !after.enabled {
        flush.extend(present.iter().cloned());
    }
    for (tag, was, now) in [
        (
            REMEMBER_DIRECT,
            before.remember_direct,
            after.remember_direct,
        ),
        (REMEMBER_PROXY, before.remember_proxy, after.remember_proxy),
        (NO_V4, before.no_v4, after.no_v4),
        (NO_V6, before.no_v6, after.no_v6),
    ] {
        if was && !now && present.iter().any(|name| name == tag) {
            flush.push(tag.to_owned());
        }
    }
    flush.sort();
    flush.dedup();
    let mut settings = current.config.settings.clone();
    settings.domain_generation.enabled = (!after.enabled).then_some(false);
    for (tag, value) in [
        (REMEMBER_DIRECT, after.remember_direct),
        (REMEMBER_PROXY, after.remember_proxy),
        (NO_V4, after.no_v4),
        (NO_V6, after.no_v6),
    ] {
        let yaml = current.config.yaml_defaults.generation.get(tag).copied();
        if yaml.unwrap_or(true) == value {
            settings.domain_generation.plugins.remove(tag);
        } else {
            settings
                .domain_generation
                .plugins
                .insert(tag.to_owned(), PluginSwitch { enabled: value });
        }
    }
    let unchanged = settings == current.config.settings;
    drop(current);
    if !unchanged {
        if let Err(error) = control.apply_settings(settings).await {
            return failure(error);
        }
    }
    let mut failed = Vec::new();
    for tag in &flush {
        let path = format!("/plugins/{tag}/flush");
        match crate::api::local_plugin_request(control, "GET", &path, b"").await {
            Some((200..=299, _)) => {}
            Some((status, body)) => failed.push(format!(
                "{tag}: {status} {}",
                String::from_utf8_lossy(&body).trim()
            )),
            None => failed.push(format!("{tag}: no such plugin route")),
        }
    }
    if !failed.is_empty() {
        return text(
            500,
            &format!(
                "settings were applied, but flushing failed: {}",
                failed.join("; ")
            ),
        );
    }
    json(
        200,
        &serde_json::json!({ "settings": after.json(), "flush_targets": flush }),
    )
}
