//! atom fork: the AtomDNS side of the management API, under `/api/v1/atom/`
//! (atom `docs/design.md` §7.2, §8). It replaces AtomDNS's own settings routes
//! (`/api/v1/flags`, `/api/v1/overrides`, `/api/v1/domain-generation`,
//! `/api/v1/upstream/config`) and the plugin route of the rewrite rules, which
//! atom step 6 removed with the old WebUI. The DDNS list went in step 6b: a
//! DDNS name is a direct rule with an upstream group and no cache.
//!
//! | path | methods |
//! |---|---|
//! | `dns` | GET, PUT (any of the fields) |
//! | `upstreams` | GET, POST `{name, upstreams}` (a custom group) |
//! | `upstreams/{tag}` | PUT `{upstreams, name?}` (empty: back to the YAML list), DELETE (custom groups) |
//! | `rewrite` | GET, PUT `{entries}` |
//!
//! `dns` and `upstreams` are stored in `webinfo/settings.json` and published
//! as a new generation (`RuntimeControl::apply_settings`); they carry no
//! version (the last write wins). Custom groups (`settings.atom_groups`)
//! become forward plugins of the generation (`config::atom_routes`).
//! `rewrite` replaces its rule file; every successful change of it empties
//! all caches.

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::atom_rules_api::{error, flush_caches, json as reply_json};
use crate::cache::CacheCatalog;
use crate::config::CompiledConfig;
use crate::config::flags::FlagValue;
use crate::config::settings::{NO_V4, NO_V6, PluginSwitch, REMEMBER_DIRECT, REMEMBER_PROXY};
use crate::config::settings::{Settings, UpstreamEntry};
use crate::rule_sources::Reply;
use crate::runtime_snapshot::{ApplyFailure, RuntimeControl};

/// The rewrite plugin (`sub_config/rule_set.yaml`).
const REWRITE: &str = "rewrite";
/// The feature flags `dns` exposes (`sub_config/flags.yaml`).
const FLAGS: &[&str] = &[
    "core_mode",
    "block_qtypes",
    "block_aaaa",
    "prefer_v4",
    "full_cache",
    "lazy_cache",
];

/// Whether a request publishes settings itself: it takes no management
/// lease, because a published generation waits for every lease.
pub(crate) fn applies_settings(method: &str, segments: &[&str]) -> bool {
    matches!(
        (method, segments),
        ("PUT", ["dns"]) | ("POST", ["upstreams"]) | ("PUT" | "DELETE", ["upstreams", _])
    )
}

pub(crate) async fn handle(
    control: Option<&RuntimeControl>,
    config: &CompiledConfig,
    cache: &CacheCatalog,
    method: &str,
    segments: &[&str],
    body: &[u8],
) -> Option<Reply> {
    Some(match (method, segments) {
        ("GET", ["dns"]) => {
            dns_view(config).map_or_else(|e| error(500, e), |v| reply_json(200, &v))
        }
        ("PUT", ["dns"]) => match control {
            Some(control) => put_dns(control, body).await,
            None => error(503, "runtime control is unavailable"),
        },
        ("GET", ["upstreams"]) => reply_json(200, &upstreams_view(config)),
        ("POST", ["upstreams"]) => match control {
            Some(control) => create_group(control, body).await,
            None => error(503, "runtime control is unavailable"),
        },
        ("PUT", ["upstreams", tag]) => match control {
            Some(control) => put_upstreams(control, tag, body).await,
            None => error(503, "runtime control is unavailable"),
        },
        ("DELETE", ["upstreams", tag]) => match control {
            Some(control) => delete_group(control, tag).await,
            None => error(503, "runtime control is unavailable"),
        },
        ("GET", ["rewrite"]) => match rewrite_runtime(config) {
            Ok(runtime) => reply_json(200, &json!({ "entries": runtime.lines() })),
            Err(reply) => reply,
        },
        ("PUT", ["rewrite"]) => put_rewrite(config, cache, body).await,
        (_, ["dns" | "upstreams" | "rewrite", ..]) => error(405, "method not allowed"),
        _ => return None,
    })
}

/// An apply failure as the HTTP answer.
fn failure(failure: ApplyFailure) -> Reply {
    let status = match &failure {
        ApplyFailure::Invalid(_) => 400,
        ApplyFailure::Busy(_) | ApplyFailure::Conflict(_) | ApplyFailure::ResourceConflict(_) => {
            409
        }
        ApplyFailure::Shutdown | ApplyFailure::RecoveryRequired(_) => 503,
        ApplyFailure::Failed(_) | ApplyFailure::CommittedCleanup { .. } => 500,
    };
    error(status, failure)
}

fn object(body: &[u8]) -> Result<Map<String, Value>, Reply> {
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(error(400, "invalid request body: expected a JSON object")),
        Err(e) => Err(error(400, format!("invalid request body: {e}"))),
    }
}

// ----- dns ------------------------------------------------------------------

/// The one `ecs_address` object, or why there is not exactly one.
fn ecs_object(config: &CompiledConfig) -> Result<Option<&crate::config::EffectiveItem>, String> {
    let all: Vec<_> = config
        .settings_report
        .iter()
        .filter(|item| item.kind == "ecs_address")
        .collect();
    match all.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one)),
        _ => Err("配置里有多个 ecs_address 对象".to_owned()),
    }
}

/// The five learning switches (`domain_output` and the learner categories).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Learning {
    enabled: bool,
    remember_direct: bool,
    remember_proxy: bool,
    no_v4: bool,
    no_v6: bool,
}

impl Learning {
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

    fn json(self) -> Value {
        json!({
            "enabled": self.enabled,
            "remember_direct": self.remember_direct,
            "remember_proxy": self.remember_proxy,
            "no_v4": self.no_v4,
            "no_v6": self.no_v6,
        })
    }

    fn switches(self) -> [(&'static str, bool); 4] {
        [
            (REMEMBER_DIRECT, self.remember_direct),
            (REMEMBER_PROXY, self.remember_proxy),
            (NO_V4, self.no_v4),
            (NO_V6, self.no_v6),
        ]
    }
}

fn dns_view(config: &CompiledConfig) -> Result<Value, String> {
    let mut map = Map::new();
    for key in FLAGS {
        let flag = config
            .flags
            .iter()
            .find(|flag| flag.key == *key)
            .ok_or_else(|| format!("配置里没有功能开关 `{key}`"))?;
        let value = match &flag.value {
            FlagValue::Bool(value) => json!(value),
            FlagValue::Choice(value) => json!(value),
        };
        map.insert((*key).to_owned(), value);
    }
    map.insert(
        "ecs".to_owned(),
        json!(ecs_object(config)?.map_or("", |item| item.value.as_str())),
    );
    map.insert("learning".to_owned(), Learning::of(config).json());
    Ok(Value::Object(map))
}

/// Builds the settings a `PUT dns` asks for; also returns the learning lists
/// to empty (switched off) and whether a flag that wants a `requery` changed.
fn dns_settings(
    config: &CompiledConfig,
    mut patch: Map<String, Value>,
) -> Result<(Settings, Vec<String>, bool), String> {
    let mut settings = config.settings.clone();
    let mut requery = false;
    // Before the first migration the values may come from the legacy switch
    // files; the first change stores all of them.
    let mut stored = settings
        .flags
        .take()
        .unwrap_or_else(|| crate::config::flags::differences(&config.flags));
    for key in FLAGS {
        let Some(raw) = patch.remove(*key) else {
            continue;
        };
        let flag = config
            .flags
            .iter()
            .find(|flag| flag.key == *key)
            .ok_or_else(|| format!("配置里没有功能开关 `{key}`"))?;
        let value = match raw {
            Value::Bool(value) => FlagValue::Bool(value),
            Value::String(value) => FlagValue::Choice(value),
            _ => return Err(format!("{key} 必须是布尔值或选项字符串")),
        };
        if !flag.accepts(&value) {
            return Err(format!("`{value}` 不是 {key} 的有效值"));
        }
        requery |= flag.requery_on_change && value != flag.value;
        if value == flag.default {
            stored.remove(*key);
        } else {
            stored.insert((*key).to_owned(), value);
        }
    }
    settings.flags = Some(stored);
    if let Some(raw) = patch.remove("ecs") {
        let Value::String(wanted) = raw else {
            return Err("ecs 必须是字符串".to_owned());
        };
        let wanted = wanted.trim();
        match ecs_object(config)? {
            None if wanted.is_empty() => {}
            None => return Err("配置里没有 ecs_address 对象".to_owned()),
            Some(object) => {
                if wanted.is_empty()
                    || config
                        .yaml_defaults
                        .ecs
                        .get(&object.object)
                        .is_some_and(|value| value == wanted)
                {
                    // Back to the YAML value.
                    settings.ecs.remove(&object.object);
                } else {
                    settings.ecs.insert(
                        object.object.clone(),
                        crate::config::settings::Addr {
                            addr: wanted.to_owned(),
                        },
                    );
                }
            }
        }
    }
    let mut flush = Vec::new();
    if let Some(raw) = patch.remove("learning") {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Patch {
            enabled: Option<bool>,
            remember_direct: Option<bool>,
            remember_proxy: Option<bool>,
            no_v4: Option<bool>,
            no_v6: Option<bool>,
        }
        let patch: Patch =
            serde_json::from_value(raw).map_err(|e| format!("learning 无效: {e}"))?;
        let before = Learning::of(config);
        let after = Learning {
            enabled: patch.enabled.unwrap_or(before.enabled),
            remember_direct: patch.remember_direct.unwrap_or(before.remember_direct),
            remember_proxy: patch.remember_proxy.unwrap_or(before.remember_proxy),
            no_v4: patch.no_v4.unwrap_or(before.no_v4),
            no_v6: patch.no_v6.unwrap_or(before.no_v6),
        };
        let present: Vec<String> = config
            .local
            .domain_outputs
            .iter()
            .map(|output| output.tag.clone())
            .chain(
                config
                    .local
                    .learners
                    .iter()
                    .flat_map(|learner| learner.runtime.category_tags().map(str::to_owned)),
            )
            .collect();
        // A list whose switch goes from on to off is emptied; the master
        // switch going off empties every list.
        if before.enabled && !after.enabled {
            flush.extend(present.iter().cloned());
        }
        for ((tag, was), (_, now)) in before.switches().into_iter().zip(after.switches()) {
            if was && !now && present.iter().any(|name| name == tag) {
                flush.push(tag.to_owned());
            }
        }
        flush.sort();
        flush.dedup();
        settings.domain_generation.enabled = (!after.enabled).then_some(false);
        for (tag, value) in after.switches() {
            let yaml = config.yaml_defaults.generation.get(tag).copied();
            if yaml.unwrap_or(true) == value {
                settings.domain_generation.plugins.remove(tag);
            } else {
                settings
                    .domain_generation
                    .plugins
                    .insert(tag.to_owned(), PluginSwitch { enabled: value });
            }
        }
    }
    if let Some(key) = patch.keys().next() {
        return Err(format!("invalid request body: unknown field `{key}`"));
    }
    Ok((settings, flush, requery))
}

async fn put_dns(control: &RuntimeControl, body: &[u8]) -> Reply {
    let patch = match object(body) {
        Ok(patch) => patch,
        Err(reply) => return reply,
    };
    let current = control.view();
    let (settings, flush, requery) = match dns_settings(&current.config, patch) {
        Ok(built) => built,
        Err(reason) => return error(400, reason),
    };
    let unchanged = settings == current.config.settings;
    drop(current);
    if !unchanged {
        if let Err(e) = control.apply_settings(settings).await {
            return failure(e);
        }
    }
    let view = control.view();
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
        return error(
            500,
            format!("设置已应用，但清空学习名单失败: {}", failed.join("; ")),
        );
    }
    if requery {
        trigger_requery(&view.config).await;
    }
    match dns_view(&view.config) {
        Ok(value) => reply_json(200, &value),
        Err(e) => error(500, e),
    }
}

/// Starts a `requery` task on the generation that was just published (a
/// `requery_on_change` flag changed). The change stays applied either way.
async fn trigger_requery(config: &CompiledConfig) {
    let Some(requery) = config.local.requeries.first() else {
        return;
    };
    let reply = requery.runtime.handle("POST", "trigger", &[]).await;
    if reply.status != 200 {
        crate::diag::warn_line!(
            "{}: the flag change did not start a task (HTTP {})",
            requery.tag,
            reply.status
        );
    }
}

// ----- upstreams ------------------------------------------------------------

/// The display names of the YAML upstream groups.
fn builtin_name(tag: &str) -> &str {
    match tag {
        "domestic" => "国内",
        "foreign" => "国外",
        "foreignecs" => "国外（带 ECS）",
        other => other,
    }
}

fn upstreams_view(config: &CompiledConfig) -> Value {
    let custom = &config.settings.atom_groups;
    let groups: Vec<Value> = config
        .effective_upstreams
        .iter()
        .filter(|(tag, _)| tag.as_str() != crate::edns_directive::FAKEIP_UPSTREAM)
        .map(|(tag, entries)| {
            let mine = custom.iter().find(|group| &group.tag == tag);
            json!({
                "tag": tag,
                "name": mine.map_or_else(|| builtin_name(tag), |group| group.name.as_str()),
                "builtin": mine.is_none(),
                "customized": config.settings.upstreams.contains_key(tag),
                "upstreams": entries,
            })
        })
        .collect();
    json!({ "groups": groups })
}

/// A list a group may take: each entry valid, one of them enabled, proxy
/// switches in their stored form.
fn checked_entries(tag: &str, mut entries: Vec<UpstreamEntry>) -> Result<Vec<UpstreamEntry>, Reply> {
    for (index, entry) in entries.iter().enumerate() {
        entry.validate(index).map_err(|reason| error(400, reason))?;
    }
    // A list must keep one enabled upstream (an `aliapi` without one does not
    // load); an empty list restores the YAML list.
    if !entries.is_empty() && !entries.iter().any(|entry| entry.enabled) {
        return Err(error(400, format!("上游组 `{tag}` 至少要保留一个启用的上游")));
    }
    for entry in &mut entries {
        entry.use_proxy = Some(entry.proxy_switch());
        entry.use_socks_proxy = None;
    }
    Ok(entries)
}

async fn publish(control: &RuntimeControl, settings: Settings, created: Option<&str>) -> Reply {
    if let Err(e) = control.apply_settings(settings).await {
        return failure(e);
    }
    let mut view = upstreams_view(&control.view().config);
    match created {
        Some(tag) => {
            view["tag"] = json!(tag);
            reply_json(201, &view)
        }
        None => reply_json(200, &view),
    }
}

async fn put_upstreams(control: &RuntimeControl, tag: &str, body: &[u8]) -> Reply {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        upstreams: Vec<UpstreamEntry>,
        name: Option<String>,
    }
    let payload: Payload = match serde_json::from_slice(body) {
        Ok(payload) => payload,
        Err(e) => return error(400, format!("invalid request body: {e}")),
    };
    let current = control.view();
    if tag == crate::edns_directive::FAKEIP_UPSTREAM {
        return error(400, "FakeIP 上游固定为本机 sing-box，不能修改");
    }
    if !current.config.effective_upstreams.contains_key(tag) {
        return error(404, format!("上游组 `{tag}` 不存在"));
    }
    let mut settings = current.config.settings.clone();
    let custom = settings.atom_groups.iter().position(|group| group.tag == tag);
    if let Some(name) = payload.name {
        let Some(at) = custom else {
            return error(400, "内置上游组不能改名");
        };
        if let Err(reason) = crate::config::atom_routes::check_name(&name) {
            return error(400, reason);
        }
        settings.atom_groups[at].name = name;
    }
    if custom.is_some() && payload.upstreams.is_empty() {
        return error(400, format!("自定义上游组 `{tag}` 至少要有一个上游"));
    }
    let entries = match checked_entries(tag, payload.upstreams) {
        Ok(entries) => entries,
        Err(reply) => return reply,
    };
    if entries.is_empty() {
        settings.upstreams.remove(tag);
    } else {
        settings.upstreams.insert(tag.to_owned(), entries);
    }
    drop(current);
    publish(control, settings, None).await
}

/// `POST upstreams`: a custom group (`u-` and eight hexadecimal digits).
async fn create_group(control: &RuntimeControl, body: &[u8]) -> Reply {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Payload {
        name: String,
        upstreams: Vec<UpstreamEntry>,
    }
    let payload: Payload = match serde_json::from_slice(body) {
        Ok(payload) => payload,
        Err(e) => return error(400, format!("invalid request body: {e}")),
    };
    if let Err(reason) = crate::config::atom_routes::check_name(&payload.name) {
        return error(400, reason);
    }
    if payload.upstreams.is_empty() {
        return error(400, "上游组至少要有一个上游");
    }
    let current = control.view();
    let mut settings = current.config.settings.clone();
    let taken = |id: &str| {
        current.config.effective_upstreams.contains_key(id)
            || settings.atom_groups.iter().any(|group| group.tag == id)
    };
    let tag = crate::atom_rules::new_id("u-", &taken);
    let entries = match checked_entries(&tag, payload.upstreams) {
        Ok(entries) => entries,
        Err(reply) => return reply,
    };
    settings.atom_groups.push(crate::config::settings::AtomGroup {
        tag: tag.clone(),
        name: payload.name,
    });
    settings.upstreams.insert(tag.clone(), entries);
    drop(current);
    publish(control, settings, Some(&tag)).await
}

/// `DELETE upstreams/{tag}`: a custom group no rule names.
async fn delete_group(control: &RuntimeControl, tag: &str) -> Reply {
    let current = control.view();
    let mut settings = current.config.settings.clone();
    let Some(at) = settings.atom_groups.iter().position(|group| group.tag == tag) else {
        return if current.config.effective_upstreams.contains_key(tag) {
            error(400, format!("内置上游组 `{tag}` 不能删除"))
        } else {
            error(404, format!("上游组 `{tag}` 不存在"))
        };
    };
    if let Some(rules) = current.config.local.atom_rules.as_deref() {
        let using = rules.rules_using_group(tag);
        if !using.is_empty() {
            return reply_json(
                409,
                &json!({
                    "error": format!("上游组 `{tag}` 被 {} 条规则使用，先改掉这些规则", using.len()),
                    "rules": using,
                }),
            );
        }
    }
    settings.atom_groups.remove(at);
    settings.upstreams.remove(tag);
    drop(current);
    publish(control, settings, None).await
}

// ----- rewrite --------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entries {
    entries: Vec<String>,
}

fn entries(body: &[u8]) -> Result<Vec<String>, Reply> {
    serde_json::from_slice::<Entries>(body)
        .map(|payload| payload.entries)
        .map_err(|e| error(400, format!("invalid request body: {e}")))
}

fn rewrite_runtime(
    config: &CompiledConfig,
) -> Result<&std::rc::Rc<crate::rewrite::Rewrite>, Reply> {
    config
        .local
        .rewrites
        .iter()
        .find(|rewrite| rewrite.tag == REWRITE)
        .map(|rewrite| &rewrite.runtime)
        .ok_or_else(|| error(404, format!("配置里没有重写插件 `{REWRITE}`")))
}

/// The answer after a fixed list changed: caches are emptied, so no cached
/// answer of the old list outlives it.
async fn after_change(config: &CompiledConfig, cache: &CacheCatalog, value: &Value) -> Reply {
    match flush_caches(config, cache).await {
        Ok(()) => reply_json(200, value),
        Err(e) => error(
            500,
            format!("修改已保存并生效，但清空缓存失败，旧的缓存应答可能还会被使用: {e}"),
        ),
    }
}

async fn put_rewrite(config: &CompiledConfig, cache: &CacheCatalog, body: &[u8]) -> Reply {
    let runtime = match rewrite_runtime(config) {
        Ok(runtime) => runtime,
        Err(reply) => return reply,
    };
    let values = match entries(body) {
        Ok(values) => values,
        Err(reply) => return reply,
    };
    match runtime.replace(&values).await {
        Ok(()) => after_change(config, cache, &json!({ "entries": runtime.lines() })).await,
        Err((status, reason)) => error(status, reason),
    }
}

#[cfg(test)]
#[path = "atom_dns_api_tests.rs"]
mod tests;
