//! atom fork: the management API of nodes, groups, Final and the sing-box
//! settings, under `/api/v1/atom/` (atom `docs/design.md` §5, §6, §8).
//! Errors are `{"error": "..."}` like the rules API; a stale version adds
//! `version`, a blocked group deletion adds `rules`.
//!
//! | path | methods |
//! |---|---|
//! | `nodes` | GET, POST `{format: json\|yaml\|link, content}` (import) |
//! | `nodes/{id}` | GET, PUT `{name?, format?, content?}`, DELETE |
//! | `nodes/{id}/delay` | POST `{url?, timeout?}` (Clash API) |
//! | `groups` | GET, POST `{name, type, members, ...}` |
//! | `groups/{id}` | GET, PUT, DELETE (`?confirm=true`) |
//! | `groups/{id}/select` | POST `{name}` (Clash API, no reload) |
//! | `groups/{id}/delay` | POST `{url?, timeout?}` (Clash API) |
//! | `final` | GET, PUT `{members?, selected?}` |
//! | `settings` | GET, PUT `{fakeip_range?, resolver?, mixed_port?}` |
//! | `status` | GET |
//! | `apply` | GET (the latest application), POST (apply again) |
//!
//! Every write takes an optional `version` (body, or `?version=` for
//! DELETE) checked against the proxy state's version. Node views never
//! carry credentials ([`crate::atom_proxy::public_outbound`]): a node's
//! connection is replaced whole, by new import content. A write that changes
//! the generated sing-box configuration is applied to sing-box first
//! ([`AtomRules::transact`]); a failure there leaves everything unchanged.

use serde_json::{Map, Value, json};

use crate::atom_proxy::{FINAL, GroupInput, ProxyState};
use crate::atom_rules::{AtomRules, Refusal};
use crate::atom_rules_api::{error, flush_caches, json as reply_json, query_version, refusal};
use crate::cache::CacheCatalog;
use crate::config::CompiledConfig;
use crate::rule_sources::Reply;

type Answer = Result<Reply, Reply>;

fn fail(refusal_value: &Refusal) -> Reply {
    refusal(refusal_value)
}

/// The body as an object, with its `version` taken out.
fn object(bytes: &[u8]) -> Result<(Option<u64>, Map<String, Value>), Reply> {
    let value: Value = if bytes.iter().all(u8::is_ascii_whitespace) {
        Value::Object(Map::new())
    } else {
        serde_json::from_slice(bytes)
            .map_err(|e| error(400, format!("invalid request body: {e}")))?
    };
    let Value::Object(mut map) = value else {
        return Err(error(400, "invalid request body: expected an object"));
    };
    let version = match map.remove("version") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .ok_or_else(|| error(400, "version must be an integer"))?,
        ),
    };
    Ok((version, map))
}

fn from_map<T: serde::de::DeserializeOwned>(map: Map<String, Value>) -> Result<T, Reply> {
    serde_json::from_value(Value::Object(map))
        .map_err(|e| error(400, format!("invalid request body: {e}")))
}

fn query_flag(query: Option<&str>, key: &str) -> bool {
    query.is_some_and(|query| {
        query
            .split('&')
            .any(|pair| pair == key || pair == format!("{key}=true") || pair == format!("{key}=1"))
    })
}

fn state(rules: &AtomRules) -> ProxyState {
    rules.proxy_state().unwrap_or_default()
}

fn node_view(state: &ProxyState, node: &crate::atom_proxy::Node) -> Value {
    json!({
        "id": node.id,
        "name": node.name,
        "type": node.outbound.get("type"),
        "server": node.outbound.get("server"),
        "server_port": node.outbound.get("server_port"),
        "outbound": crate::atom_proxy::public_outbound(&node.outbound),
        "groups": state.groups_containing(&node.id),
    })
}

fn group_view(state: &ProxyState, group: &crate::atom_proxy::Group) -> Value {
    let mut value = serde_json::to_value(group).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        map.insert("empty".into(), json!(group.members.is_empty()));
        map.insert(
            "builtin".into(),
            json!(group.id == crate::atom_proxy::DEFAULT_GROUP),
        );
        if let Some(now) = state.selection(&group.id) {
            map.insert("now".into(), json!(now));
        }
    }
    value
}

fn final_view(state: &ProxyState) -> Value {
    json!({
        "version": state.version,
        "members": state.final_group.members,
        "selected": state.final_group.selected,
        "empty": state.final_group.members.is_empty(),
    })
}

fn settings_view(rules: &AtomRules, state: &ProxyState) -> Value {
    json!({
        "version": state.version,
        "fakeip_range": state.settings.fakeip_range,
        "resolver": state.settings.resolver,
        "resolver_effective": rules.resolver_for(state),
        "mixed_port": state.settings.mixed_port,
    })
}

// ---- nodes ----------------------------------------------------------------

async fn import_nodes(rules: &AtomRules, bytes: &[u8]) -> Answer {
    let (version, mut map) = object(bytes)?;
    rules.check_proxy_version(version).map_err(|e| fail(&e))?;
    let format = map
        .remove("format")
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| error(400, "导入需要 format：json、yaml 或 link"))?;
    let content = map
        .remove("content")
        .ok_or_else(|| error(400, "导入需要 content"))?;
    if let Some(key) = map.keys().next() {
        return Err(error(
            400,
            format!("invalid request body: unknown field `{key}`"),
        ));
    }
    let imported = parse_import(&format, content)?;
    let mut next = state(rules);
    let added = next.add_nodes(imported);
    next.version += 1;
    let version = next.version;
    rules
        .transact(None, Some(next.clone()), "nodes")
        .await
        .map_err(|e| fail(&e))?;
    let nodes: Vec<Value> = added.iter().map(|node| node_view(&next, node)).collect();
    Ok(reply_json(
        201,
        &json!({ "version": version, "nodes": nodes }),
    ))
}

/// Converts import content (`format`: json, yaml or link) to nodes.
fn parse_import(format: &str, content: Value) -> Result<Vec<crate::atom_links::Imported>, Reply> {
    let text = content.as_str().map(str::to_owned);
    let imported = match (format, text) {
        ("json", Some(text)) => serde_json::from_str::<Value>(&text)
            .map_err(|e| format!("JSON 无法解析: {e}"))
            .and_then(crate::atom_links::from_singbox_json),
        ("json", None) => crate::atom_links::from_singbox_json(content),
        ("yaml", Some(text)) => crate::atom_links::from_clash_yaml(&text),
        ("link", Some(text)) => crate::atom_links::from_links(&text),
        ("yaml" | "link", None) => Err("content 必须是字符串".to_owned()),
        (other, _) => Err(format!("不支持的 format `{other}`：json、yaml 或 link")),
    }
    .map_err(|message| error(400, message))?;
    if imported.is_empty() {
        return Err(error(400, "没有可导入的节点"));
    }
    Ok(imported)
}

async fn update_node(rules: &AtomRules, id: &str, bytes: &[u8]) -> Answer {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Update {
        name: Option<String>,
        format: Option<String>,
        content: Option<Value>,
    }
    let (version, map) = object(bytes)?;
    let update: Update = from_map(map)?;
    rules.check_proxy_version(version).map_err(|e| fail(&e))?;
    // No content: the connection stays as it is (the API never shows its
    // credentials, so it cannot be edited field by field).
    let outbound = match (update.format, update.content) {
        (Some(format), Some(content)) => {
            let mut imported = parse_import(&format, content)?;
            if imported.len() != 1 {
                return Err(error(400, "修改节点时 content 只能是一个节点"));
            }
            Some(imported.remove(0).1)
        }
        (None, None) => None,
        _ => return Err(error(400, "format 和 content 要一起给")),
    };
    let mut next = state(rules);
    let node = next
        .update_node(id, update.name, outbound)
        .map_err(|e| fail(&e))?;
    next.version += 1;
    let version = next.version;
    rules
        .transact(None, Some(next.clone()), "nodes")
        .await
        .map_err(|e| fail(&e))?;
    Ok(reply_json(
        200,
        &json!({ "version": version, "node": node_view(&next, &node) }),
    ))
}

async fn delete_node(rules: &AtomRules, id: &str, query: Option<&str>) -> Answer {
    rules
        .check_proxy_version(query_version(query)?)
        .map_err(|e| fail(&e))?;
    let mut next = state(rules);
    next.remove_node(id).map_err(|e| fail(&e))?;
    next.version += 1;
    let version = next.version;
    rules
        .transact(None, Some(next), "nodes")
        .await
        .map_err(|e| fail(&e))?;
    Ok(reply_json(
        200,
        &json!({ "version": version, "deleted": id }),
    ))
}

// ---- groups ---------------------------------------------------------------

async fn create_group(rules: &AtomRules, bytes: &[u8]) -> Answer {
    let (version, map) = object(bytes)?;
    let input: GroupInput = from_map(map)?;
    rules.check_proxy_version(version).map_err(|e| fail(&e))?;
    let mut next = state(rules);
    let group = next.add_group(input);
    next.version += 1;
    let version = next.version;
    rules
        .transact(None, Some(next.clone()), "groups")
        .await
        .map_err(|e| fail(&e))?;
    Ok(reply_json(
        201,
        &json!({ "version": version, "group": group_view(&next, &group) }),
    ))
}

async fn update_group(rules: &AtomRules, id: &str, bytes: &[u8]) -> Answer {
    let (version, map) = object(bytes)?;
    let input: GroupInput = from_map(map)?;
    rules.check_proxy_version(version).map_err(|e| fail(&e))?;
    let mut next = state(rules);
    let group = next.update_group(id, input).map_err(|e| fail(&e))?;
    next.version += 1;
    let version = next.version;
    rules
        .transact(None, Some(next.clone()), "groups")
        .await
        .map_err(|e| fail(&e))?;
    Ok(reply_json(
        200,
        &json!({ "version": version, "group": group_view(&next, &group) }),
    ))
}

/// `(reply, rules changed)`: a confirmed deletion moves rules to Final.
async fn delete_group(
    rules: &AtomRules,
    id: &str,
    query: Option<&str>,
) -> Result<(Reply, bool), Reply> {
    rules
        .check_proxy_version(query_version(query)?)
        .map_err(|e| fail(&e))?;
    let before = rules.rules().0;
    let version = rules
        .delete_group(id, query_flag(query, "confirm"))
        .await
        .map_err(|e| fail(&e))?;
    let (after, list) = rules.rules();
    let moved = after != before;
    Ok((
        reply_json(
            200,
            &json!({
                "version": version,
                "deleted": id,
                "rules_version": after,
                "rules": if moved { json!(list) } else { Value::Null },
            }),
        ),
        moved,
    ))
}

async fn select(rules: &AtomRules, id: &str, bytes: &[u8]) -> Answer {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Select {
        name: String,
    }
    let (version, map) = object(bytes)?;
    let request: Select = from_map(map)?;
    let version = rules
        .select(id, &request.name, version)
        .await
        .map_err(|e| fail(&e))?;
    Ok(reply_json(
        200,
        &json!({ "version": version, "id": id, "selected": request.name }),
    ))
}

async fn delay(rules: &AtomRules, id: &str, node: bool, bytes: &[u8]) -> Answer {
    if node != id.starts_with("n-") {
        let what = if node { "节点" } else { "节点组" };
        return Err(error(404, format!("{what} `{id}` 不存在")));
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Delay {
        url: Option<String>,
        timeout: Option<u32>,
    }
    let (_, map) = object(bytes)?;
    let request: Delay = from_map(map)?;
    let timeout = request.timeout.unwrap_or(5000).clamp(100, 30_000);
    let result = rules
        .delay(id, request.url, timeout)
        .await
        .map_err(|e| fail(&e))?;
    // A node: `{id, delay}`; a group: `{id, delays: {member: ms}}`.
    Ok(reply_json(
        200,
        &if node {
            json!({ "id": id, "delay": result.get("delay") })
        } else {
            json!({ "id": id, "delays": result })
        },
    ))
}

// ---- final ----------------------------------------------------------------

async fn put_final(rules: &AtomRules, bytes: &[u8]) -> Answer {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Put {
        members: Option<Vec<String>>,
        selected: Option<String>,
    }
    let (version, map) = object(bytes)?;
    let request: Put = from_map(map)?;
    rules.check_proxy_version(version).map_err(|e| fail(&e))?;
    let current = state(rules);
    match request.members {
        Some(members) if members != current.final_group.members => {
            let mut next = current;
            next.final_group.members = members;
            next.final_group.selected = request.selected.unwrap_or(next.final_group.selected);
            if !next
                .final_group
                .members
                .contains(&next.final_group.selected)
            {
                // The old choice left: "默认代理" if present, else the first.
                next.final_group.selected = if next
                    .final_group
                    .members
                    .iter()
                    .any(|member| member == crate::atom_proxy::DEFAULT_GROUP)
                {
                    crate::atom_proxy::DEFAULT_GROUP.to_owned()
                } else {
                    next.final_group
                        .members
                        .first()
                        .cloned()
                        .unwrap_or_default()
                };
            }
            next.version += 1;
            rules
                .transact(None, Some(next), "final")
                .await
                .map_err(|e| fail(&e))?;
        }
        _ => {
            if let Some(selected) = request.selected {
                if selected != current.final_group.selected {
                    rules
                        .select(FINAL, &selected, None)
                        .await
                        .map_err(|e| fail(&e))?;
                }
            }
        }
    }
    Ok(reply_json(200, &final_view(&state(rules))))
}

// ---- settings -------------------------------------------------------------

/// Moves AtomDNS's `main_proxy` with the mixed port, when it pointed at the
/// old one (an address set by hand elsewhere is left alone).
async fn follow_mixed_port(
    control: &crate::runtime_snapshot::RuntimeControl,
    old: u16,
    new: u16,
) -> Result<bool, String> {
    let current = control.view();
    let objects: Vec<&crate::config::EffectiveItem> = current
        .config
        .settings_report
        .iter()
        .filter(|item| item.kind == "socks5_proxy")
        .collect();
    let [object] = objects.as_slice() else {
        return Ok(false);
    };
    if object.value != format!("127.0.0.1:{old}") {
        return Ok(false);
    }
    let wanted = format!("127.0.0.1:{new}");
    let mut settings = current.config.settings.clone();
    if current.config.yaml_defaults.proxies.get(&object.object) == Some(&wanted) {
        settings.proxies.remove(&object.object);
    } else {
        settings.proxies.insert(
            object.object.clone(),
            crate::config::settings::Addr { addr: wanted },
        );
    }
    drop(current);
    control
        .apply_settings(settings)
        .await
        .map(|_| true)
        .map_err(|error| error.to_string())
}

async fn put_settings(
    control: Option<&crate::runtime_snapshot::RuntimeControl>,
    config: &CompiledConfig,
    cache: &CacheCatalog,
    rules: &AtomRules,
    bytes: &[u8],
) -> Reply {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Put {
        fakeip_range: Option<String>,
        resolver: Option<String>,
        mixed_port: Option<u16>,
    }
    let parsed = object(bytes).and_then(|(version, map)| Ok((version, from_map::<Put>(map)?)));
    let (version, request) = match parsed {
        Ok(parsed) => parsed,
        Err(reply) => return reply,
    };
    // `mutates` leaves this route out: the lease is held for the sing-box
    // part only, since moving `main_proxy` reloads AtomDNS, which waits
    // for every lease.
    let lease =
        match control.map(crate::runtime_snapshot::RuntimeControl::begin_management_mutation) {
            Some(Ok(lease)) => Some(lease),
            Some(Err(_)) => return error(503, "host is applying configuration"),
            None => None,
        };
    if let Err(e) = rules.check_proxy_version(version) {
        return fail(&e);
    }
    let current = state(rules);
    let mut next = current.clone();
    if let Some(range) = request.fakeip_range {
        next.settings.fakeip_range = range.trim().to_owned();
    }
    if let Some(resolver) = request.resolver {
        next.settings.resolver = resolver.trim().to_owned();
    }
    if let Some(port) = request.mixed_port {
        next.settings.mixed_port = port;
    }
    if next.settings == current.settings {
        return reply_json(200, &settings_view(rules, &current));
    }
    next.version += 1;
    if let Err(e) = rules.transact(None, Some(next.clone()), "settings").await {
        return fail(&e);
    }
    // Cached answers hold FakeIPs of the old range.
    if next.settings.fakeip_range != current.settings.fakeip_range {
        if let Err(e) = flush_caches(config, cache).await {
            return error(
                500,
                format!("设置已应用，但清空缓存失败，旧网段的 FakeIP 应答可能还会被使用: {e}"),
            );
        }
    }
    let view = settings_view(rules, &next);
    drop(lease);
    let (old, new) = (current.settings.mixed_port, next.settings.mixed_port);
    if old != new {
        if let Some(control) = control {
            if let Err(e) = follow_mixed_port(control, old, new).await {
                return error(
                    500,
                    format!(
                        "sing-box 已改用 mixed 端口 {new}，但 AtomDNS 的 main_proxy 没能跟着改: {e}"
                    ),
                );
            }
        }
    }
    reply_json(200, &view)
}

// ---- status / apply -------------------------------------------------------

async fn status(rules: &AtomRules) -> Reply {
    let current = state(rules);
    let host = rules.proxy_host().cloned();
    let secret = rules.live_secret();
    let singbox_version = match (host.clone(), secret) {
        (Some(host), Some(secret)) => {
            tokio::task::spawn_blocking(move || crate::atom_singbox::version(&host, &secret))
                .await
                .ok()
                .flatten()
        }
        _ => None,
    };
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for rule in crate::atom_rules::ip_rules(&rules.rules().1) {
        for cidr in rule.cidrs {
            let list = if cidr.contains(':') { &mut v6 } else { &mut v4 };
            if !list.contains(&cidr) {
                list.push(cidr);
            }
        }
    }
    let host_view = host.as_ref().map(|host| {
        json!({
            "config": host.config_path().display().to_string(),
            "clash_api": host.clash_api.to_string(),
            "dns_in": host.dns_in.to_string(),
            "redirect_port": host.redirect_port,
            "tproxy_port": host.tproxy_port,
        })
    });
    reply_json(
        200,
        &json!({
            "atomdns": {"version": env!("CARGO_PKG_VERSION")},
            "singbox": {
                "running": singbox_version.is_some(),
                "version": singbox_version,
                "in_sync": rules.in_sync(),
                "host": host_view,
            },
            "last_apply": crate::atom_rules::last_apply(),
            "warnings": {"empty_groups": current.empty_groups()},
            // For the nft rules (atom steps 4 and 7): what must reach sing-box.
            "nft": {
                "fakeip_range": current.settings.fakeip_range,
                "ip_cidr": {"inet4": v4, "inet6": v6},
            },
        }),
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle(
    control: Option<&crate::runtime_snapshot::RuntimeControl>,
    config: &CompiledConfig,
    cache: &CacheCatalog,
    rules: &AtomRules,
    method: &str,
    segments: &[&str],
    query: Option<&str>,
    body: &[u8],
) -> Reply {
    let known = matches!(
        segments.first(),
        Some(&("nodes" | "groups" | "final" | "settings" | "status" | "apply"))
    );
    if !known {
        return error(404, "not found");
    }
    if rules.proxy_host().is_none() {
        return error(404, "没有配置 sing-box（atom_rules 的 singbox 段）");
    }
    let current = || state(rules);
    let answer: Answer = match (method, segments) {
        ("GET", ["nodes"]) => {
            let state = current();
            let nodes: Vec<Value> = state
                .nodes
                .iter()
                .map(|node| node_view(&state, node))
                .collect();
            Ok(reply_json(
                200,
                &json!({ "version": state.version, "nodes": nodes }),
            ))
        }
        ("POST", ["nodes"]) => import_nodes(rules, body).await,
        ("GET", ["nodes", id]) => {
            let state = current();
            match state.node(id) {
                Some(node) => Ok(reply_json(200, &node_view(&state, node))),
                None => Err(error(404, format!("节点 `{id}` 不存在"))),
            }
        }
        ("PUT", ["nodes", id]) => update_node(rules, id, body).await,
        ("DELETE", ["nodes", id]) => delete_node(rules, id, query).await,
        ("POST", ["nodes", id, "delay"]) => delay(rules, id, true, body).await,
        ("GET", ["groups"]) => {
            let state = current();
            let groups: Vec<Value> = state
                .groups
                .iter()
                .map(|group| group_view(&state, group))
                .collect();
            Ok(reply_json(
                200,
                &json!({ "version": state.version, "groups": groups }),
            ))
        }
        ("POST", ["groups"]) => create_group(rules, body).await,
        ("GET", ["groups", id]) => {
            let state = current();
            match state.group(id) {
                Some(group) => Ok(reply_json(200, &group_view(&state, group))),
                None => Err(error(404, format!("节点组 `{id}` 不存在"))),
            }
        }
        ("PUT", ["groups", id]) => update_group(rules, id, body).await,
        ("DELETE", ["groups", id]) => match delete_group(rules, id, query).await {
            // Rules moved to Final: cached answers carry the old SET.
            Ok((reply, true)) => match flush_caches(config, cache).await {
                Ok(()) => Ok(reply),
                Err(e) => Err(error(
                    500,
                    format!("修改已保存并生效，但清空缓存失败，旧的缓存应答可能还会被使用: {e}"),
                )),
            },
            Ok((reply, false)) => Ok(reply),
            Err(reply) => Err(reply),
        },
        ("POST", ["groups", id, "select"]) => select(rules, id, body).await,
        ("POST", ["groups", id, "delay"]) => delay(rules, id, false, body).await,
        ("GET", ["final"]) => Ok(reply_json(200, &final_view(&current()))),
        ("PUT", ["final"]) => put_final(rules, body).await,
        ("GET", ["settings"]) => Ok(reply_json(200, &settings_view(rules, &current()))),
        ("PUT", ["settings"]) => return put_settings(control, config, cache, rules, body).await,
        ("GET", ["status"]) => return status(rules).await,
        ("GET", ["apply"]) => Ok(reply_json(
            200,
            &json!({ "last_apply": crate::atom_rules::last_apply(), "in_sync": rules.in_sync() }),
        )),
        ("POST", ["apply"]) => rules
            .reapply()
            .await
            .map(|()| {
                reply_json(
                    200,
                    &json!({ "last_apply": crate::atom_rules::last_apply() }),
                )
            })
            .map_err(|e| fail(&e)),
        _ => Err(error(405, "method not allowed")),
    };
    answer.unwrap_or_else(|reply| reply)
}

#[cfg(test)]
#[path = "atom_proxy_api_tests.rs"]
mod tests;
