//! atom fork: the management API of the rule table, under `/api/v1/atom/`
//! (atom `docs/design.md` §8). Errors use the host's JSON form
//! `{"error": "..."}`; a stale-version conflict adds `version`, a blocked
//! ruleset deletion adds `rules`.
//!
//! | path | methods |
//! |---|---|
//! | `rules` | GET (`{version, rules}`), POST (create) |
//! | `rules/{id}` | PUT (replace), DELETE (`?version=`) |
//! | `rules/move` | POST `{id, before_id \| after_id, version}` |
//! | `rules/test` | POST `{domain, client?}` |
//! | `rulesets` | GET, POST (remote or local) |
//! | `rulesets/{id}` | GET (with `rules`), PUT, DELETE |
//! | `rulesets/{id}/refresh` | POST (download a remote ruleset again) |
//!
//! Every successful change empties all caches (design §4.5, v0: clear
//! everything), so no cached answer outlives the rule that produced it.

use std::net::IpAddr;
use std::time::Duration;

use atomdns_upstream_core::TransportCancellation;
use serde::Deserialize;

use crate::atom_rules::{AtomRules, Refusal, RuleInput, Ruleset, Source};
use crate::cache::CacheCatalog;
use crate::config::CompiledConfig;
use crate::rule_sources::Reply;

pub(crate) const PREFIX: &str = "/api/v1/atom/";
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const DOWNLOAD_LIMIT: usize = 64 * 1024 * 1024;

fn json(status: u16, value: &serde_json::Value) -> Reply {
    let mut body = serde_json::to_vec(value).unwrap_or_default();
    body.push(b'\n');
    Reply {
        status,
        content_type: Some("application/json"),
        body,
        headers: Vec::new(),
    }
}

fn error(status: u16, message: impl std::fmt::Display) -> Reply {
    json(status, &serde_json::json!({ "error": message.to_string() }))
}

fn refusal(refusal: &Refusal) -> Reply {
    let mut value = serde_json::json!({ "error": refusal.message });
    if let Some(version) = refusal.version {
        value["version"] = version.into();
    }
    if !refusal.rules.is_empty() {
        value["rules"] = refusal.rules.clone().into();
    }
    json(refusal.status, &value)
}

fn body<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, Reply> {
    serde_json::from_slice(bytes).map_err(|e| error(400, format!("invalid request body: {e}")))
}

/// Whether a request changes the rule table or the rulesets (it then takes
/// the management lease). `rules/test` only reads.
pub(crate) fn mutates(method: &str, path: &str) -> bool {
    path.strip_prefix(PREFIX).is_some_and(|rest| {
        matches!(method, "POST" | "PUT" | "DELETE") && rest.trim_end_matches('/') != "rules/test"
    })
}

fn query_version(query: Option<&str>) -> Result<Option<u64>, Reply> {
    let Some(query) = query else {
        return Ok(None);
    };
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("version=") {
            return value
                .parse()
                .map(Some)
                .map_err(|_| error(400, "version must be an integer"));
        }
    }
    Ok(None)
}

/// Empties every cache after a change. A cached answer of the old rules
/// (a FakeIP that sends no CLEAR) must not outlive them: when a flush cannot
/// persist its empty dump, the cache is discarded instead (memory cleared,
/// dump file removed). What still fails is returned, and the change is
/// reported as applied but not fully flushed.
async fn flush_caches(config: &CompiledConfig, cache: &CacheCatalog) -> Result<(), String> {
    let mut failed = Vec::new();
    for item in &config.caches {
        let Some(store) = cache.get(item.id) else {
            continue;
        };
        let Err(e) = store.flush().await else {
            continue;
        };
        crate::diag::warn_line!(
            "atom rules: flushing cache {} failed: {e}; discarding it instead",
            item.tag
        );
        if let Err(e) = store.discard().await {
            failed.push(format!("{}: {e}", item.tag));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

pub(crate) async fn handle(
    config: &CompiledConfig,
    cache: &CacheCatalog,
    method: &str,
    target: &str,
    request_body: &[u8],
    shutdown: &TransportCancellation,
) -> Option<Reply> {
    let (path, query) = target
        .split_once('?')
        .map_or((target, None), |(path, query)| (path, Some(query)));
    let rest = path.strip_prefix(PREFIX)?.trim_end_matches('/');
    let Some(rules) = config.local.atom_rules.as_deref() else {
        return Some(error(
            404,
            "atom 规则表未启用（配置里没有 atom_rules 插件）",
        ));
    };
    let segments: Vec<&str> = rest.split('/').collect();
    let reply = match (method, segments.as_slice()) {
        ("GET", ["rules"]) => return Some(list_rules(rules)),
        ("POST", ["rules"]) => create_rule(rules, request_body),
        ("POST", ["rules", "move"]) => move_rule(rules, request_body),
        ("POST", ["rules", "test"]) => return Some(test_rule(config, rules, request_body)),
        ("PUT", ["rules", id]) => update_rule(rules, id, request_body),
        ("DELETE", ["rules", id]) => match query_version(query) {
            Ok(version) => match rules.delete(id, version) {
                Ok(version) => Ok(json(200, &serde_json::json!({ "version": version }))),
                Err(e) => Err(refusal(&e)),
            },
            Err(reply) => Err(reply),
        },
        ("GET", ["rulesets"]) => return Some(list_rulesets(rules)),
        ("GET", ["rulesets", id]) => return Some(show_ruleset(rules, id)),
        ("POST", ["rulesets"]) => create_ruleset(rules, request_body, shutdown).await,
        ("PUT", ["rulesets", id]) => update_ruleset(rules, id, request_body),
        ("DELETE", ["rulesets", id]) => match rules.delete_ruleset(id) {
            Ok(()) => Ok(json(200, &serde_json::json!({ "deleted": id }))),
            Err(e) => Err(refusal(&e)),
        },
        ("POST", ["rulesets", id, "refresh"]) => refresh_ruleset(rules, id, shutdown).await,
        (_, ["rules" | "rulesets", ..]) => return Some(error(405, "method not allowed")),
        _ => return Some(error(404, "not found")),
    };
    Some(match reply {
        Ok(reply) => match flush_caches(config, cache).await {
            Ok(()) => reply,
            Err(e) => error(
                500,
                format!("修改已保存并生效，但清空缓存失败，旧的缓存应答可能还会被使用: {e}"),
            ),
        },
        Err(reply) => reply,
    })
}

fn list_rules(rules: &AtomRules) -> Reply {
    let (version, list) = rules.rules();
    json(
        200,
        &serde_json::json!({ "version": version, "rules": list }),
    )
}

#[derive(Deserialize)]
struct Create {
    #[serde(flatten)]
    rule: RuleInputFields,
    version: Option<u64>,
    before_id: Option<String>,
    after_id: Option<String>,
}

/// The editable fields of a rule, flattened beside the request-only ones.
#[derive(Deserialize)]
struct RuleInputFields {
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default)]
    remark: String,
    #[serde(rename = "match")]
    matches: crate::atom_rules::Match,
    action: crate::atom_rules::Action,
}

fn yes() -> bool {
    true
}

impl From<RuleInputFields> for RuleInput {
    fn from(fields: RuleInputFields) -> Self {
        Self {
            enabled: fields.enabled,
            remark: fields.remark,
            matches: fields.matches,
            action: fields.action,
        }
    }
}

#[derive(Deserialize)]
struct Replace {
    #[serde(flatten)]
    rule: RuleInputFields,
    version: Option<u64>,
}

fn create_rule(rules: &AtomRules, bytes: &[u8]) -> Result<Reply, Reply> {
    let create: Create = body(bytes)?;
    let (version, rule) = rules
        .create(
            create.rule.into(),
            create.version,
            create.before_id.as_deref(),
            create.after_id.as_deref(),
        )
        .map_err(|e| refusal(&e))?;
    Ok(json(
        201,
        &serde_json::json!({ "version": version, "rule": rule }),
    ))
}

fn update_rule(rules: &AtomRules, id: &str, bytes: &[u8]) -> Result<Reply, Reply> {
    let replace: Replace = body(bytes)?;
    let (version, rule) = rules
        .update(id, replace.rule.into(), replace.version)
        .map_err(|e| refusal(&e))?;
    Ok(json(
        200,
        &serde_json::json!({ "version": version, "rule": rule }),
    ))
}

fn move_rule(rules: &AtomRules, bytes: &[u8]) -> Result<Reply, Reply> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Move {
        id: String,
        before_id: Option<String>,
        after_id: Option<String>,
        version: Option<u64>,
    }
    let request: Move = body(bytes)?;
    let Some(version) = request.version else {
        return Err(error(400, "move 需要 version"));
    };
    let version = rules
        .move_rule(
            &request.id,
            request.before_id.as_deref(),
            request.after_id.as_deref(),
            version,
        )
        .map_err(|e| refusal(&e))?;
    let (_, list) = rules.rules();
    Ok(json(
        200,
        &serde_json::json!({ "version": version, "rules": list }),
    ))
}

fn test_rule(config: &CompiledConfig, rules: &AtomRules, bytes: &[u8]) -> Reply {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Test {
        domain: String,
        client: Option<String>,
    }
    let request: Test = match body(bytes) {
        Ok(request) => request,
        Err(reply) => return reply,
    };
    let domain = request
        .domain
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if domain.is_empty() {
        return error(400, "需要 domain");
    }
    let client = match request.client.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(text) => match text.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => return error(400, format!("client `{text}` 不是 IP 地址")),
        },
    };
    // The builtin sets a mapper marks: what the mapper would set for the name.
    let fast_flags = rules
        .mapper
        .as_deref()
        .and_then(|tag| config.domain_mappers.iter().find(|m| m.tag == tag))
        .map_or(0, |mapper| mapper.evaluate(Some(&domain)).fast_flags);
    match rules.test(&domain, client, fast_flags) {
        Some((index, rule)) => {
            let mut value = serde_json::json!({
                "domain": domain,
                "matched": true,
                "index": index,
                "action": crate::atom_rules::action_name(&rule.action),
                "rule": rule,
            });
            if let crate::atom_rules::Action::Proxy { group_id } = &rule.action {
                value["group_id"] = group_id.clone().into();
            }
            json(200, &value)
        }
        None => json(
            200,
            &serde_json::json!({
                "domain": domain,
                "matched": false,
                "fallthrough": "original",
            }),
        ),
    }
}

fn ruleset_view(set: &Ruleset) -> serde_json::Value {
    serde_json::to_value(set).unwrap_or_default()
}

fn list_rulesets(rules: &AtomRules) -> Reply {
    let mut list: Vec<serde_json::Value> = rules
        .builtin_names()
        .into_iter()
        .map(|name| serde_json::json!({ "id": name, "name": name, "type": "builtin" }))
        .collect();
    list.extend(rules.rulesets().iter().map(ruleset_view));
    json(200, &serde_json::Value::Array(list))
}

fn show_ruleset(rules: &AtomRules, id: &str) -> Reply {
    let Some(set) = rules.ruleset(id) else {
        return if rules.builtin_names().iter().any(|name| name == id) {
            json(
                200,
                &serde_json::json!({ "id": id, "name": id, "type": "builtin" }),
            )
        } else {
            error(404, format!("规则集 `{id}` 不存在"))
        };
    };
    match rules.ruleset_entries(id) {
        Ok(entries) => {
            let mut value = ruleset_view(&set);
            value["rules"] = entries.into();
            json(200, &value)
        }
        Err(e) => refusal(&e),
    }
}

struct RulesetBody {
    name: Option<String>,
    /// `None` when the body has no `type`.
    source: Option<Source>,
    rules: Option<Vec<String>>,
}

fn ruleset_body(bytes: &[u8]) -> Result<RulesetBody, Reply> {
    let serde_json::Value::Object(mut map) = body::<serde_json::Value>(bytes)? else {
        return Err(error(400, "invalid request body: expected an object"));
    };
    let name = match map.remove("name") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(name)) => Some(name),
        Some(_) => return Err(error(400, "name must be a string")),
    };
    let rules = match map.remove("rules") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            serde_json::from_value(value)
                .map_err(|e| error(400, format!("rules must be a list of strings: {e}")))?,
        ),
    };
    let source = if map.contains_key("type") {
        Some(
            serde_json::from_value(serde_json::Value::Object(map))
                .map_err(|e| error(400, format!("invalid request body: {e}")))?,
        )
    } else if let Some(key) = map.keys().next() {
        return Err(error(
            400,
            format!("invalid request body: unknown field `{key}`"),
        ));
    } else {
        None
    };
    Ok(RulesetBody {
        name,
        source,
        rules,
    })
}

async fn download(rules: &AtomRules, set: &Ruleset, shutdown: &TransportCancellation) -> Reply {
    let Source::Remote {
        url,
        format,
        category,
    } = set.source.clone()
    else {
        return error(400, "本地规则集不需要刷新");
    };
    let ticket = rules.begin_download(&set.id);
    let fetched = crate::rule_download::fetch(
        crate::rule_download::Fetch {
            url: &url,
            socks5: &rules.socks5,
            timeout: DOWNLOAD_TIMEOUT,
            max_bytes: DOWNLOAD_LIMIT,
            roots: None,
        },
        shutdown,
    )
    .await;
    let converted = match fetched {
        Ok(bytes) => tokio::task::spawn_blocking(move || {
            crate::atom_rules::convert_download(&bytes, &format, &category, &url)
        })
        .await
        .unwrap_or_else(|e| Err(format!("conversion failed: {e}"))),
        Err(e) => Err(format!("下载失败: {e}")),
    };
    let failed = converted.as_ref().err().cloned();
    match rules.store_download(&set.id, &set.source, ticket, converted) {
        // The set is kept with `last_error`; the caller sees the failure.
        Ok(set) => match failed {
            None => json(200, &ruleset_view(&set)),
            Some(message) => {
                let mut value = ruleset_view(&set);
                value["error"] = message.into();
                json(502, &value)
            }
        },
        Err(e) => refusal(&e),
    }
}

async fn create_ruleset(
    rules: &AtomRules,
    bytes: &[u8],
    shutdown: &TransportCancellation,
) -> Result<Reply, Reply> {
    let request = ruleset_body(bytes)?;
    let Some(source) = request.source else {
        return Err(error(400, "规则集需要 type（remote 或 local）"));
    };
    let remote = matches!(source, Source::Remote { .. });
    let set = rules
        .create_ruleset(
            request.name.as_deref().unwrap_or(""),
            source,
            request.rules.unwrap_or_default(),
        )
        .map_err(|e| refusal(&e))?;
    if !remote {
        return Ok(json(201, &ruleset_view(&set)));
    }
    // A remote set is created even when its first download fails; the
    // reply then carries the reason (`error`, status 502) and `last_error`.
    let reply = download(rules, &set, shutdown).await;
    Ok(if reply.status == 200 {
        Reply {
            status: 201,
            ..reply
        }
    } else {
        reply
    })
}

fn update_ruleset(rules: &AtomRules, id: &str, bytes: &[u8]) -> Result<Reply, Reply> {
    let request = ruleset_body(bytes)?;
    let set = rules
        .update_ruleset(id, request.name.as_deref(), request.source, request.rules)
        .map_err(|e| refusal(&e))?;
    Ok(json(200, &ruleset_view(&set)))
}

async fn refresh_ruleset(
    rules: &AtomRules,
    id: &str,
    shutdown: &TransportCancellation,
) -> Result<Reply, Reply> {
    let Some(set) = rules.ruleset(id) else {
        return Err(error(404, format!("规则集 `{id}` 不存在")));
    };
    let reply = download(rules, &set, shutdown).await;
    if reply.status == 200 {
        Ok(reply)
    } else {
        Err(reply)
    }
}

#[cfg(test)]
#[path = "atom_rules_api_tests.rs"]
mod tests;
