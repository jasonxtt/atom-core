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
//! | `rulesets/{id}/refresh` | POST (download a remote or builtin ruleset again) |
//!
//! Nodes, groups, Final, the sing-box settings, `status` and `apply` are in
//! [`crate::atom_proxy_api`]; the AtomDNS settings (`dns`, `upstreams`) and
//! the rewrite rules (`rewrite`) in [`crate::atom_dns_api`]. Every
//! route is listed in [`ROUTES`], which `docs/api/openapi.yaml` must match.
//!
//! Every successful change empties the global caches (design §4.5.1), so no
//! cached answer outlives the rule that produced it; the daily update of the
//! rulesets empties none.

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

pub(crate) fn json(status: u16, value: &serde_json::Value) -> Reply {
    let mut body = serde_json::to_vec(value).unwrap_or_default();
    body.push(b'\n');
    Reply {
        status,
        content_type: Some("application/json"),
        body,
        headers: Vec::new(),
    }
}

pub(crate) fn error(status: u16, message: impl std::fmt::Display) -> Reply {
    json(status, &serde_json::json!({ "error": message.to_string() }))
}

pub(crate) fn refusal(refusal: &Refusal) -> Reply {
    let mut value = serde_json::json!({ "error": refusal.message });
    if let Some(version) = refusal.version {
        value["version"] = version.into();
    }
    if !refusal.rules.is_empty() {
        value["rules"] = refusal.rules.clone().into();
    }
    json(refusal.status, &value)
}

pub(crate) fn body<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, Reply> {
    serde_json::from_slice(bytes).map_err(|e| error(400, format!("invalid request body: {e}")))
}

/// Whether a request changes the rule table or the rulesets (it then takes
/// the management lease). `rules/test` only reads.
/// `PUT settings` takes the lease itself: a mixed port change reloads the
/// AtomDNS configuration afterwards, which waits for every lease.
/// `PUT dns` and the upstream group writes (`POST upstreams`, `PUT` and
/// `DELETE upstreams/{tag}`) publish settings themselves, for the same
/// reason.
pub(crate) fn mutates(method: &str, path: &str) -> bool {
    path.strip_prefix(PREFIX).is_some_and(|rest| {
        let rest = rest.trim_end_matches('/');
        let segments: Vec<&str> = rest.split('/').collect();
        matches!(method, "POST" | "PUT" | "DELETE")
            && rest != "rules/test"
            && rest != "rules/dryrun"
            && !(method == "PUT" && rest == "settings")
            && !crate::atom_dns_api::applies_settings(method, &segments)
    })
}

/// Every route under [`PREFIX`]: `(method, path template)`. The OpenAPI
/// document (`docs/api/openapi.yaml`) lists exactly these, and a test checks
/// that each one reaches its handler (the dispatch itself is the `match` in
/// each module's `handle`).
#[cfg(test)]
pub(crate) const ROUTES: &[(&str, &str)] = &[
    ("GET", "rules"),
    ("POST", "rules"),
    ("PUT", "rules/{id}"),
    ("DELETE", "rules/{id}"),
    ("POST", "rules/move"),
    ("POST", "rules/test"),
    ("POST", "rules/dryrun"),
    ("GET", "rulesets"),
    ("POST", "rulesets"),
    ("GET", "rulesets/{id}"),
    ("PUT", "rulesets/{id}"),
    ("DELETE", "rulesets/{id}"),
    ("POST", "rulesets/{id}/refresh"),
    ("GET", "nodes"),
    ("POST", "nodes"),
    ("GET", "nodes/{id}"),
    ("PUT", "nodes/{id}"),
    ("DELETE", "nodes/{id}"),
    ("POST", "nodes/{id}/delay"),
    ("GET", "groups"),
    ("POST", "groups"),
    ("GET", "groups/{id}"),
    ("PUT", "groups/{id}"),
    ("DELETE", "groups/{id}"),
    ("POST", "groups/{id}/select"),
    ("POST", "groups/{id}/delay"),
    ("GET", "final"),
    ("PUT", "final"),
    ("GET", "settings"),
    ("PUT", "settings"),
    ("GET", "status"),
    ("GET", "apply"),
    ("POST", "apply"),
    ("GET", "dns"),
    ("PUT", "dns"),
    ("GET", "upstreams"),
    ("PUT", "upstreams/{tag}"),
    ("GET", "catalog"),
    ("POST", "catalog/sync"),
    ("POST", "upstreams"),
    ("DELETE", "upstreams/{tag}"),
    ("GET", "rewrite"),
    ("PUT", "rewrite"),
    ("POST", "groups/move"),
    ("GET", "runtime"),
    ("GET", "connections"),
    ("DELETE", "connections"),
    ("DELETE", "connections/{id}"),
    ("GET", "system"),
    ("GET", "caches"),
    ("POST", "caches/{tag}/flush"),
    ("GET", "stats/upstreams"),
    ("GET", "learning"),
    ("POST", "learning/{key}/flush"),
    ("GET", "requery"),
    ("PUT", "requery"),
    ("POST", "requery/trigger"),
    ("GET", "audit/status"),
    ("POST", "audit/start"),
    ("POST", "audit/stop"),
    ("POST", "audit/clear"),
    ("GET", "audit/capacity"),
    ("POST", "audit/capacity"),
    ("GET", "audit/stats"),
    ("GET", "audit/stats/windows"),
    ("GET", "audit/logs"),
    ("GET", "audit/logs/domain"),
    ("GET", "audit/rank/domain"),
    ("GET", "audit/rank/client"),
    ("GET", "audit/rank/domain_set"),
    ("GET", "audit/rank/effective"),
    ("GET", "audit/rank/slowest"),
];

/// Display names of the builtin sets atom's configuration offers (an
/// unknown one is shown by its name).
fn builtin_label(name: &str) -> &str {
    match name {
        "adguard" => "广告（AdGuard 规则）",
        "geosite_cn" => "中国域名（geosite-cn）",
        "geosite_no_cn" => "非中国域名（geolocation-!cn）",
        "cuscn" => "国内修正（geolocation-!cn 里的国内域名）",
        "cusnocn" => "国外修正（geosite-cn 里的国外域名）",
        "geoip_cn" => "中国 IP（geoip-cn）",
        other => other,
    }
}

/// A builtin set: `refreshable`, its download address (`url`, a set with one
/// source) and last update (`updated`, RFC 3339), whether the original
/// judgement needs it (`required`: no deletion) and whether rules may name
/// it (`usable`: not for the IP sets).
fn builtin_view(config: &CompiledConfig, rules: &AtomRules, name: &str) -> serde_json::Value {
    let provider = config.rule_sources.provider(name);
    let mut value = serde_json::json!({
        "id": name,
        "name": builtin_label(name),
        "type": "builtin",
        "refreshable": provider.as_ref().is_some_and(|provider| {
            !matches!(provider.kind, crate::rule_sources::Kind::Light)
        }),
        "required": crate::atom_rules::REQUIRED_BUILTIN.contains(&name),
        "usable": rules.builtin_names().iter().any(|n| n == name),
    });
    if let Some((url, updated)) = provider
        .as_ref()
        .and_then(|provider| config.rule_sources.source_url(provider))
    {
        value["url"] = url.into();
        if let Some(updated) = updated {
            value["updated"] = updated.into();
        }
    }
    value
}

/// `PUT rulesets/{id}` of a builtin set: `{url}`, the download address of
/// its one source; downloaded at once (like `refresh`).
async fn set_builtin_url(
    config: &CompiledConfig,
    rules: &AtomRules,
    id: &str,
    bytes: &[u8],
) -> Result<Reply, Reply> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Put {
        url: String,
    }
    let put: Put = body(bytes)?;
    let provider = config
        .rule_sources
        .provider(id)
        .filter(|provider| !matches!(provider.kind, crate::rule_sources::Kind::Light))
        .ok_or_else(|| error(400, format!("内置规则集 `{id}` 没有可改的下载地址")))?;
    match config.rule_sources.set_url(&provider, put.url.trim()).await {
        Ok((sources, updated)) if sources > 0 && updated == 0 => Err(error(
            502,
            format!("地址已保存，但没有下载成功（见日志），`{id}` 的列表保持不变"),
        )),
        Ok(_) => Ok(json(200, &builtin_view(config, rules, id))),
        Err((status, e)) => Err(error(status, e)),
    }
}

/// `DELETE rulesets/{id}[?confirm=true]`: a custom set, or a builtin one the
/// original judgement does not need. While rules name it: 409 with their
/// IDs; with `confirm=true` it leaves those rules first (a rule left
/// without a name or IP condition goes).
async fn delete_any_ruleset(
    rules: &AtomRules,
    id: &str,
    query: Option<&str>,
) -> Result<Reply, Reply> {
    let builtin = rules.listed_builtins().iter().any(|name| name == id);
    if !builtin && rules.ruleset(id).is_none() {
        return Err(error(404, format!("规则集 `{id}` 不存在")));
    }
    if builtin && crate::atom_rules::REQUIRED_BUILTIN.contains(&id) {
        return Err(error(400, format!("内置规则集 `{id}` 是分流必需的，不能删除")));
    }
    let confirm = query.is_some_and(|query| {
        query
            .split('&')
            .any(|pair| matches!(pair, "confirm" | "confirm=true" | "confirm=1"))
    });
    let mut edited = false;
    if confirm {
        if let Some(next) = rules.plan_without_ruleset(id) {
            rules.commit_rules(next).await.map_err(|e| refusal(&e))?;
            edited = true;
        }
    }
    let removed = if builtin {
        rules.remove_builtin(id)
    } else {
        rules.delete_ruleset(id)
    };
    if let Err(e) = removed {
        // The rules changed already: the success path (caches, ledger)
        // still runs, with the failure as the reply (codex review of step
        // 6b-2b, round 2).
        return if edited { Ok(refusal(&e)) } else { Err(refusal(&e)) };
    }
    drop_unused_catalog(rules);
    Ok(json(200, &serde_json::json!({ "deleted": id, "rules_version": rules.rules().0 })))
}

pub(crate) fn query_version(query: Option<&str>) -> Result<Option<u64>, Reply> {
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

/// The global caches (`cache_all`, `cache_all_noleak`): ahead of the
/// original judgement, behind the rule table, so only queries no rule
/// matched reach them; they also hold FakeIP answers.
pub(crate) fn is_global_cache(tag: &str) -> bool {
    tag.starts_with("cache_all")
}

/// Empties the named caches `wanted` picks (atom design 4.5). A cached answer
/// the change made wrong must not outlive it: when a flush cannot persist its
/// empty dump, the cache is discarded instead (memory cleared, dump file
/// removed). What still fails is returned, and the change is reported as
/// applied but not fully flushed.
pub(crate) async fn flush_caches_where(
    config: &CompiledConfig,
    cache: &CacheCatalog,
    wanted: impl Fn(&str) -> bool,
) -> Result<(), String> {
    let mut failed = Vec::new();
    for item in &config.caches {
        if item.kind != crate::config::CacheKind::Named || !wanted(&item.tag) {
            continue;
        }
        let Some(store) = cache.get(item.id) else {
            continue;
        };
        let Err(e) = store.flush().await else {
            continue;
        };
        crate::diag::warn_line!(
            "atom: flushing cache {} failed: {e}; discarding it instead",
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

/// Empties the global caches after a change of the rules, the rulesets or
/// the rewrite rules. Both sit ahead of the global cache, so a query they
/// answer never reaches it; what it may still hold is an answer from before
/// a rule was added or changed. The upstream answer caches hold what an
/// upstream said, whatever rule sent the query there, and are kept.
pub(crate) async fn flush_global_caches(
    config: &CompiledConfig,
    cache: &CacheCatalog,
) -> Result<(), String> {
    flush_caches_where(config, cache, is_global_cache).await
}

pub(crate) async fn handle(
    control: Option<&crate::runtime_snapshot::RuntimeControl>,
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
    // The query audit (DNS logs and statistics) is AtomDNS's own API, also
    // served under this prefix; `api.rs` routes it.
    if rest.starts_with("audit/") {
        return None;
    }
    let Some(rules) = config.local.atom_rules.as_deref() else {
        return Some(error(
            404,
            "atom 规则表未启用（配置里没有 atom_rules 插件）",
        ));
    };
    let segments: Vec<&str> = rest.split('/').collect();
    if let Some(reply) =
        crate::atom_dns_api::handle(control, config, cache, method, &segments, request_body).await
    {
        return Some(reply);
    }
    let reply = match (method, segments.as_slice()) {
        ("GET", ["rules"]) => return Some(list_rules(rules)),
        ("POST", ["rules"]) => create_rule(rules, request_body, shutdown).await,
        ("POST", ["rules", "move"]) => move_rule(rules, request_body).await,
        ("POST", ["rules", "test"]) => return Some(test_rule(config, rules, request_body)),
        ("POST", ["rules", "dryrun"]) => {
            return Some(dry_run(control, config, rules, request_body).await);
        }
        ("PUT", ["rules", id]) => update_rule(rules, id, request_body, shutdown).await,
        ("GET", ["catalog"]) => return Some(list_catalog(rules, query)),
        // Not a rule change: no cache flush, no ledger pass.
        ("POST", ["catalog", "sync"]) => return Some(sync_catalog(rules).await),
        ("DELETE", ["rules", id]) => delete_rule(rules, id, query).await,
        ("GET", ["rulesets"]) => return Some(list_rulesets(config, rules)),
        ("GET", ["rulesets", id]) => return Some(show_ruleset(config, rules, id)),
        ("POST", ["rulesets"]) => create_ruleset(rules, request_body, shutdown).await,
        ("PUT", ["rulesets", id]) if rules.listed_builtins().iter().any(|n| n == id) => {
            set_builtin_url(config, rules, id, request_body).await
        }
        ("PUT", ["rulesets", id]) => update_ruleset(rules, id, request_body),
        ("DELETE", ["rulesets", id]) => delete_any_ruleset(rules, id, query).await,
        ("POST", ["rulesets", id, "refresh"]) if rules.listed_builtins().iter().any(|n| n == id) => {
            refresh_builtin(config, id).await
        }
        ("POST", ["rulesets", id, "refresh"]) => refresh_ruleset(rules, id, shutdown).await,
        (_, ["rules" | "rulesets" | "catalog", ..]) => {
            return Some(error(405, "method not allowed"));
        }
        _ => {
            return Some(
                crate::atom_proxy_api::handle(
                    control,
                    config,
                    cache,
                    rules,
                    method,
                    &segments,
                    query,
                    request_body,
                )
                .await,
            );
        }
    };
    Some(match reply {
        Ok(reply) => {
            let flushed = flush_global_caches(config, cache).await;
            // Names clients already hold follow the new rules at once.
            crate::atom_ledger::resync(config, rules, segments[0]).await;
            match flushed {
                Ok(()) => reply,
                Err(e) => error(
                    500,
                    format!("修改已保存并生效，但清空缓存失败，旧的缓存应答可能还会被使用: {e}"),
                ),
            }
        }
        Err(reply) => reply,
    })
}

/// `GET catalog?q=&limit=`: the catalog entries whose name contains `q`
/// (case-insensitive), at most `limit` (default 50, at most 500).
fn list_catalog(rules: &AtomRules, query: Option<&str>) -> Reply {
    let mut q = String::new();
    let mut limit = 50usize;
    for pair in query.unwrap_or("").split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value);
        match key {
            "q" => q = value.trim().to_lowercase(),
            "limit" => match value.parse::<usize>() {
                Ok(n) if (1..=500).contains(&n) => limit = n,
                _ => return error(400, "limit 是 1 到 500"),
            },
            _ => return error(400, format!("不认识的参数 `{key}`")),
        }
    }
    let catalog = rules.catalog();
    let matching: Vec<_> = catalog
        .entries()
        .into_iter()
        .filter(|entry| q.is_empty() || entry.name.to_lowercase().contains(&q))
        .collect();
    let total = matching.len();
    let entries: Vec<serde_json::Value> = matching
        .into_iter()
        .take(limit)
        .map(|entry| {
            let mut value = serde_json::to_value(&entry).unwrap_or_default();
            // In use: a rule names it, so its set (counts, update time) exists.
            if let Some(set) = rules.ruleset(&entry.id) {
                value["ruleset"] = ruleset_view(&set);
            }
            value
        })
        .collect();
    json(
        200,
        &serde_json::json!({
            "updated_at": catalog.updated_at,
            "size": catalog.len(),
            "total": total,
            "entries": entries,
        }),
    )
}

/// A query value: `+` is a space, `%XX` a byte.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |at: usize| {
            bytes
                .get(at)
                .and_then(|b| char::from(*b).to_digit(16))
                .and_then(|d| u8::try_from(d).ok())
        };
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                if let (Some(high), Some(low)) = (hex(i + 1), hex(i + 2)) {
                    out.push(high * 16 + low);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `POST catalog/sync`: reads the index from GitHub now.
async fn sync_catalog(rules: &AtomRules) -> Reply {
    match crate::atom_catalog::sync(rules.root(), &rules.socks5, crate::atom_rules::now()).await {
        Ok(catalog) => {
            let view =
                serde_json::json!({ "updated_at": catalog.updated_at, "size": catalog.len() });
            rules.set_catalog(catalog);
            json(200, &view)
        }
        Err(e) => error(502, e),
    }
}

const UPDATE_AGE: i64 = 24 * 3600;
const UPDATE_FIRST: Duration = Duration::from_secs(300);
const UPDATE_CHECK: Duration = Duration::from_secs(3600);

/// Starts the daily refresh of this configuration's remote and catalog
/// rulesets and of the catalog index (atom step 6b): five minutes after it
/// starts serving, then every hour, whatever is a day old is downloaded
/// again. Each download holds the management lease, like an API write, so it
/// never runs into a configuration publication; it stops when a newer
/// configuration takes over (`AtomRules::stop_updates`).
pub(crate) fn spawn_updates(rules: &std::rc::Rc<AtomRules>, api: &crate::local_url::LocalApi) {
    if rules.root().as_os_str().is_empty() {
        return;
    }
    let cancel = TransportCancellation::new();
    rules.set_updates(cancel.clone());
    let rules = std::rc::Rc::clone(rules);
    let control = api.control.clone();
    tokio::task::spawn_local(async move {
        let mut wait = UPDATE_FIRST;
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
            wait = UPDATE_CHECK;
            update_round(&rules, &control, &cancel).await;
        }
    });
}

async fn update_round(
    rules: &AtomRules,
    control: &crate::runtime_snapshot::RuntimeControlWeak,
    cancel: &TransportCancellation,
) {
    let now = crate::atom_rules::now();
    // Catalog sets a cleanup could not remove (a sing-box application was
    // running then) go now; the unused ones are not downloaded.
    if let Some(control) = control.upgrade() {
        if let Ok(lease) = control.begin_management_mutation() {
            if !cancel.is_cancelled() {
                drop_unused_catalog(rules);
            }
            drop(lease);
        }
    }
    let unused = rules.unused_catalog_rulesets();
    let due: Vec<Ruleset> = rules
        .rulesets()
        .into_iter()
        .filter(|set| !matches!(set.source, Source::Local) && now - set.updated_at >= UPDATE_AGE)
        .filter(|set| !unused.contains(&set.id))
        .collect();
    let catalog_due = now - rules.catalog().updated_at >= UPDATE_AGE;
    for set in due {
        let Some(control) = control.upgrade() else {
            return;
        };
        // A publication is running: this set waits for the next round.
        let Ok(lease) = control.begin_management_mutation() else {
            continue;
        };
        if cancel.is_cancelled() {
            return;
        }
        let (reply, installed) = download(rules, &set, cancel).await;
        // No cache is emptied: a stale global cache entry answered lazily
        // runs the whole flow again in the background and corrects itself.
        if installed {
            let view = control.view();
            crate::atom_ledger::resync(&view.config, rules, "rulesets").await;
        }
        if reply.status != 200 {
            crate::diag::warn_line!(
                "atom_rules: daily update of {} failed: {}",
                set.id,
                String::from_utf8_lossy(&reply.body).trim()
            );
        }
        drop(lease);
    }
    if catalog_due && !cancel.is_cancelled() {
        let Some(control) = control.upgrade() else {
            return;
        };
        let Ok(lease) = control.begin_management_mutation() else {
            return;
        };
        match crate::atom_catalog::sync(rules.root(), &rules.socks5, now).await {
            Ok(catalog) => rules.set_catalog(catalog),
            Err(e) => crate::diag::warn_line!("atom_rules: daily catalog sync failed: {e}"),
        }
        drop(lease);
    }
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
    /// Direct only: the upstream group (atom step 6b).
    #[serde(default)]
    dns: Option<String>,
    /// Direct only: false bypasses every cache.
    #[serde(default = "yes")]
    cache: bool,
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
            dns: fields.dns,
            cache: fields.cache,
        }
    }
}

#[derive(Deserialize)]
struct Replace {
    #[serde(flatten)]
    rule: RuleInputFields,
    version: Option<u64>,
}

async fn create_rule(
    rules: &AtomRules,
    bytes: &[u8],
    shutdown: &TransportCancellation,
) -> Result<Reply, Reply> {
    let create: Create = body(bytes)?;
    let pins = match ensure_catalog(rules, &create.rule.matches, shutdown).await {
        Ok(pins) => pins,
        Err(reply) => {
            drop_unused_catalog(rules);
            return Err(reply);
        }
    };
    let planned = rules
        .plan_create(
            create.rule.into(),
            create.version,
            create.before_id.as_deref(),
            create.after_id.as_deref(),
        )
        .map_err(|e| refusal(&e));
    let committed = match planned {
        Ok((next, done)) => rules
            .commit_rules(next)
            .await
            .map(|()| done)
            .map_err(|e| refusal(&e)),
        Err(reply) => Err(reply),
    };
    // A refused rule leaves no catalog set it created behind.
    drop(pins);
    drop_unused_catalog(rules);
    let (version, rule) = committed?;
    Ok(json(
        201,
        &serde_json::json!({ "version": version, "rule": rule }),
    ))
}

/// The catalog sets a request names, pinned (not removed as unused) until
/// it ends.
struct CatalogPins<'a> {
    rules: &'a AtomRules,
    ids: Vec<String>,
}

impl Drop for CatalogPins<'_> {
    fn drop(&mut self) {
        self.rules.unpin_catalog(&self.ids);
    }
}

/// Every catalog entry `matches` names gets a set whose first download
/// succeeded before the rule is saved: one initialization per ID at a time
/// (a second request waits for the first and uses its result), and the sets
/// stay pinned until the caller drops the result. A failed download fails
/// the request (502); the caller then removes what no rule names.
async fn ensure_catalog<'a>(
    rules: &'a AtomRules,
    matches: &crate::atom_rules::Match,
    shutdown: &TransportCancellation,
) -> Result<CatalogPins<'a>, Reply> {
    let ids: Vec<String> = matches
        .ruleset
        .iter()
        .chain(&matches.ip_ruleset)
        .filter(|id| crate::atom_catalog::is_catalog_id(id))
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    rules.pin_catalog(&ids);
    let pins = CatalogPins { rules, ids };
    for id in &pins.ids {
        let lock = rules.catalog_lock(id);
        let _initializing = lock.lock().await;
        if rules.ruleset(id).is_some_and(|set| set.revision > 0) {
            continue;
        }
        let set = match rules.ruleset(id) {
            Some(set) => set,
            None => rules.create_catalog_ruleset(id).map_err(|e| refusal(&e))?,
        };
        let (reply, installed) = download(rules, &set, shutdown).await;
        if !installed {
            return Err(reply);
        }
    }
    Ok(pins)
}

/// After a rule change: the catalog rulesets no rule names any more go.
fn drop_unused_catalog(rules: &AtomRules) {
    for id in rules.unused_catalog_rulesets() {
        if let Err(e) = rules.delete_ruleset(&id) {
            crate::diag::error_line!("atom_rules: removing unused catalog ruleset {id}: {}", e.message);
        }
    }
}

async fn update_rule(
    rules: &AtomRules,
    id: &str,
    bytes: &[u8],
    shutdown: &TransportCancellation,
) -> Result<Reply, Reply> {
    let replace: Replace = body(bytes)?;
    let pins = match ensure_catalog(rules, &replace.rule.matches, shutdown).await {
        Ok(pins) => pins,
        Err(reply) => {
            drop_unused_catalog(rules);
            return Err(reply);
        }
    };
    let planned = rules
        .plan_update(id, replace.rule.into(), replace.version)
        .map_err(|e| refusal(&e));
    let committed = match planned {
        Ok((next, done)) => rules
            .commit_rules(next)
            .await
            .map(|()| done)
            .map_err(|e| refusal(&e)),
        Err(reply) => Err(reply),
    };
    drop(pins);
    drop_unused_catalog(rules);
    let (version, rule) = committed?;
    Ok(json(
        200,
        &serde_json::json!({ "version": version, "rule": rule }),
    ))
}

async fn delete_rule(rules: &AtomRules, id: &str, query: Option<&str>) -> Result<Reply, Reply> {
    let version = query_version(query)?;
    let (next, version) = rules.plan_delete(id, version).map_err(|e| refusal(&e))?;
    rules.commit_rules(next).await.map_err(|e| refusal(&e))?;
    drop_unused_catalog(rules);
    Ok(json(200, &serde_json::json!({ "version": version })))
}

async fn move_rule(rules: &AtomRules, bytes: &[u8]) -> Result<Reply, Reply> {
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
    let (next, version) = rules
        .plan_move(
            &request.id,
            request.before_id.as_deref(),
            request.after_id.as_deref(),
            version,
        )
        .map_err(|e| refusal(&e))?;
    rules.commit_rules(next).await.map_err(|e| refusal(&e))?;
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

/// `POST rules/dryrun {domain, client?, qtype?}`: what the main flow would
/// do with the query now, step by step, leaving no trace
/// ([`crate::atom_dryrun`]). It runs on the live generation's upstreams.
pub(crate) async fn dry_run(
    control: Option<&crate::runtime_snapshot::RuntimeControl>,
    config: &CompiledConfig,
    rules: &AtomRules,
    bytes: &[u8],
) -> Reply {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct DryRun {
        domain: String,
        client: Option<String>,
        qtype: Option<String>,
    }
    let request: DryRun = match body(bytes) {
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
    let qtype = match request.qtype.as_deref().map(str::trim) {
        None | Some("" | "A" | "a") => 1,
        Some("AAAA" | "aaaa") => 28,
        Some(other) => return error(400, format!("qtype 只能是 A 或 AAAA（`{other}`）")),
    };
    let Some(view) = control.map(crate::runtime_snapshot::RuntimeControl::view) else {
        return error(503, "DNS 没有在运行");
    };
    if view.config.generation != config.generation {
        return error(503, "配置正在切换，请重试");
    }
    let request = crate::atom_dryrun::Request {
        domain,
        client,
        qtype,
    };
    match crate::atom_dryrun::run(
        &view.config,
        &view.forwards,
        rules,
        &request,
        view.options.request_deadline,
    )
    .await {
        Ok(value) => json(200, &value),
        Err(message) => error(400, message),
    }
}

fn ruleset_view(set: &Ruleset) -> serde_json::Value {
    serde_json::to_value(set).unwrap_or_default()
}

fn list_rulesets(config: &CompiledConfig, rules: &AtomRules) -> Reply {
    let mut list: Vec<serde_json::Value> = rules
        .listed_builtins()
        .iter()
        .map(|name| builtin_view(config, rules, name))
        .collect();
    list.extend(rules.rulesets().iter().map(ruleset_view));
    json(200, &serde_json::Value::Array(list))
}

fn show_ruleset(config: &CompiledConfig, rules: &AtomRules, id: &str) -> Reply {
    let Some(set) = rules.ruleset(id) else {
        return if rules.listed_builtins().iter().any(|name| name == id) {
            json(200, &builtin_view(config, rules, id))
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

/// Downloads and converts one file (the conversion on the blocking pool).
async fn fetch_converted(
    rules: &AtomRules,
    url: String,
    format: String,
    category: String,
    shutdown: &TransportCancellation,
) -> Result<crate::atom_rules::Converted, String> {
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
    match fetched {
        Ok(bytes) => tokio::task::spawn_blocking(move || {
            crate::atom_rules::convert_download(&bytes, &format, &category, &url)
        })
        .await
        .unwrap_or_else(|e| Err(format!("conversion failed: {e}"))),
        Err(e) => Err(format!("下载失败: {e}")),
    }
}

/// A catalog entry's files, merged: MetaCubeX's names and prefixes come in
/// two files, blackmatrix7's in one. Any file failing fails the whole set.
async fn fetch_catalog(
    rules: &AtomRules,
    id: &str,
    shutdown: &TransportCancellation,
) -> Result<crate::atom_rules::Converted, String> {
    let entry = rules
        .catalog()
        .find(id)
        .ok_or_else(|| format!("规则源 `{id}` 不在目录里"))?;
    let mut merged: Option<crate::atom_rules::Converted> = None;
    for (url, format) in crate::atom_catalog::urls(&entry) {
        let part = fetch_converted(rules, url, format.to_owned(), String::new(), shutdown).await?;
        merged = Some(match merged {
            None => part,
            Some(mut all) => {
                all.entries.extend(part.entries);
                all.ips.extend(part.ips);
                for (kind, count) in part.skipped {
                    *all.skipped.entry(kind).or_default() += count;
                }
                all.list = crate::atom_rules::build_list(&all.entries)?;
                all
            }
        });
    }
    merged.ok_or_else(|| format!("规则源 `{id}` 没有文件"))
}

/// Downloads a remote or catalog set again. `.1`: a new list was saved (and
/// so the caches and the ledger must follow), even when sing-box then failed
/// to take its IP prefixes (the reply is 502 then).
async fn download(
    rules: &AtomRules,
    set: &Ruleset,
    shutdown: &TransportCancellation,
) -> (Reply, bool) {
    let ticket;
    let converted = match set.source.clone() {
        Source::Remote {
            url,
            format,
            category,
        } => {
            ticket = rules.begin_download(&set.id);
            fetch_converted(rules, url, format, category, shutdown).await
        }
        Source::Catalog => {
            ticket = rules.begin_download(&set.id);
            fetch_catalog(rules, &set.id, shutdown).await
        }
        Source::Local => return (error(400, "本地规则集不需要刷新"), false),
    };
    let failed = converted.as_ref().err().cloned();
    let before = rules.current_ip_rules();
    match rules.store_download(&set.id, &set.source, ticket, converted) {
        // New IP prefixes of a set a rule's `ip_ruleset` takes: sing-box
        // follows (atom step 6b). The download is saved either way.
        Ok(set) if failed.is_none() => match rules.follow_ip_rules(&before).await {
            Ok(()) => (json(200, &ruleset_view(&set)), true),
            Err(e) => {
                let mut value = ruleset_view(&set);
                value["error"] = format!(
                    "规则集已更新，但 sing-box 没能换上新的 IP 网段（仍用旧的，下次应用时补上）: {}",
                    e.message
                )
                .into();
                (json(502, &value), true)
            }
        },
        // The set is kept with `last_error`; the caller sees the failure.
        Ok(set) => {
            let mut value = ruleset_view(&set);
            value["error"] = failed.unwrap_or_default().into();
            (json(502, &value), false)
        }
        Err(e) => (refusal(&e), false),
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
    let (reply, _) = download(rules, &set, shutdown).await;
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
    // A saved list goes the success way (caches, ledger) whatever sing-box
    // said; the reply keeps its status.
    match download(rules, &set, shutdown).await {
        (reply, true) => Ok(reply),
        (reply, false) => Err(reply),
    }
}

/// Downloads a builtin set's sources again (`sd_set_light`, `si_set`,
/// `adguard_rule` of the configuration) and waits until the new lists are in
/// use; the caller then empties the caches and brings sing-box's bindings up
/// to date, as after any other ruleset change. Fails (keeping the old lists)
/// when no download succeeded.
async fn refresh_builtin(config: &CompiledConfig, id: &str) -> Result<Reply, Reply> {
    let provider = config
        .rule_sources
        .provider(id)
        .filter(|provider| !matches!(provider.kind, crate::rule_sources::Kind::Light))
        .ok_or_else(|| error(400, format!("内置规则集 `{id}` 不能刷新")))?;
    match config.rule_sources.refresh(&provider).await {
        Ok((sources, updated)) if sources > 0 && updated == 0 => Err(error(
            502,
            format!("内置规则集 `{id}` 的 {sources} 个来源都没有下载成功（见日志），列表保持不变"),
        )),
        Ok((sources, updated)) => Ok(json(
            200,
            &serde_json::json!({ "id": id, "sources": sources, "updated": updated }),
        )),
        Err((status, e)) => Err(error(status, e)),
    }
}

#[cfg(test)]
#[path = "atom_rules_api_tests.rs"]
mod tests;
