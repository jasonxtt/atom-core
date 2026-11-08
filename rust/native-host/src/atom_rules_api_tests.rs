use atomdns_upstream_core::TransportCancellation;

use super::{handle, mutates};
use crate::assembly::{HostAssembly, HostOptions};

const YAML: &str = r"log: {level: error}
plugins:
  - tag: cache_all
    type: cache
    args: {size: 64}
  - tag: blocked
    type: domain_set
    args: {exps: ['full:blocked.example']}
  - tag: domestic
    type: forward
    args: {upstreams: [{addr: 'udp://127.0.0.1:15000'}]}
  - tag: atom_rules
    type: atom_rules
    args:
      marks: {proxy: 41, direct: 42, block: 40}
      builtin: [blocked]
  - tag: main
    type: sequence
    args:
      - exec: $atom_rules
      - exec: $cache_all
      - exec: $domestic
  - tag: listener
    type: udp_server
    args: {entry: main, listen: '127.0.0.1:3099'}
";

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("atom-rules-api-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Api {
    assembly: HostAssembly,
    root: std::path::PathBuf,
}

impl Api {
    fn new(name: &str) -> Self {
        Self::with_yaml(name, YAML)
    }

    fn with_yaml(name: &str, yaml: &str) -> Self {
        let root = scratch(name);
        let config = crate::config::compile_yaml_with_base(yaml, &root).expect("config");
        let assembly = HostAssembly::with_options(config, HostOptions::default()).unwrap();
        Self { assembly, root }
    }

    fn call(&self, method: &str, target: &str, body: &str) -> (u16, serde_json::Value) {
        let reply = self
            .assembly
            .block_on(handle(
                self.assembly.config(),
                self.assembly.cache(),
                method,
                target,
                body.as_bytes(),
                &TransportCancellation::new(),
            ))
            .expect("an atom route");
        let value = serde_json::from_slice(&reply.body).unwrap_or(serde_json::Value::Null);
        (reply.status, value)
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn only_writes_take_the_management_lease() {
    assert!(mutates("POST", "/api/v1/atom/rules"));
    assert!(mutates("POST", "/api/v1/atom/rules/move"));
    assert!(mutates("PUT", "/api/v1/atom/rules/r-1"));
    assert!(mutates("DELETE", "/api/v1/atom/rulesets/rs-1"));
    assert!(!mutates("POST", "/api/v1/atom/rules/test"));
    assert!(!mutates("GET", "/api/v1/atom/rules"));
    assert!(!mutates("POST", "/api/v1/upstream/config"));
}

#[test]
fn crud_move_and_test_over_http_shapes() {
    let api = Api::new("crud");
    let (status, list) = api.call("GET", "/api/v1/atom/rules", "");
    assert_eq!(status, 200);
    assert_eq!(list["version"], 0);
    assert_eq!(
        list["rules"].as_array().unwrap().len(),
        1,
        "LAN only: no adguard"
    );

    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"remark": "视频", "match": {"suffix": ["video.example"]},
            "action": {"type": "proxy", "group_id": "g-v"}, "version": 0}"#,
    );
    assert_eq!(status, 201, "{created}");
    assert_eq!(created["version"], 1);
    let proxied = created["rule"]["id"].as_str().unwrap().to_owned();
    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"domain": ["www.video.example"], "ruleset": ["blocked"]},
            "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 201, "{created}");
    let direct = created["rule"]["id"].as_str().unwrap().to_owned();

    let test = |name: &str| {
        api.call(
            "POST",
            "/api/v1/atom/rules/test",
            &format!(r#"{{"domain": "{name}"}}"#),
        )
        .1
    };
    let hit = test("www.video.example");
    assert_eq!(
        (hit["action"].clone(), hit["group_id"].clone()),
        ("proxy".into(), "g-v".into())
    );
    assert_eq!(
        test("blocked.example")["action"],
        "direct",
        "builtin domain_set"
    );
    assert_eq!(test("nothing.example")["matched"], false);

    // A stale move is refused in the host error form, with the version.
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules/move",
        &format!(r#"{{"id": "{direct}", "before_id": "{proxied}", "version": 1}}"#),
    );
    assert_eq!(status, 409);
    assert!(refused["error"].is_string());
    assert_eq!(refused["version"], 2);
    let (status, moved) = api.call(
        "POST",
        "/api/v1/atom/rules/move",
        &format!(r#"{{"id": "{direct}", "before_id": "{proxied}", "version": 2}}"#),
    );
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["version"], 3);
    assert_eq!(moved["rules"][1]["id"], direct.as_str());
    assert_eq!(test("www.video.example")["action"], "direct");
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/rules/move",
        &format!(r#"{{"id": "{direct}", "before_id": "{proxied}"}}"#),
    );
    assert_eq!(status, 400, "move needs a version");

    let (status, replaced) = api.call(
        "PUT",
        &format!("/api/v1/atom/rules/{proxied}"),
        r#"{"enabled": false, "match": {"suffix": ["video.example"]}, "action": {"type": "block"}}"#,
    );
    assert_eq!(status, 200, "{replaced}");
    assert_eq!(test("a.video.example")["matched"], false, "disabled");
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"ip_cidr": ["1.2.3.0/24"]}, "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 400);
    assert!(refused["error"].as_str().unwrap().contains("ip_cidr"));
    let (status, _) = api.call(
        "DELETE",
        &format!("/api/v1/atom/rules/{proxied}?version=1"),
        "",
    );
    assert_eq!(status, 409);
    let (status, deleted) = api.call(
        "DELETE",
        &format!("/api/v1/atom/rules/{proxied}?version=4"),
        "",
    );
    assert_eq!((status, deleted["version"].clone()), (200, 5.into()));
    let (status, _) = api.call("PATCH", "/api/v1/atom/rules", "");
    assert_eq!(status, 405);
    assert!(api.root.join(crate::atom_rules::RULES_FILE).exists());
}

#[test]
fn a_proxy_rule_with_a_client_is_refused_in_chinese() {
    let api = Api::new("client-proxy");
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["video.example"], "client": ["192.168.1.0/24"]},
            "action": {"type": "proxy", "group_id": "g-v"}}"#,
    );
    assert_eq!(status, 400);
    let message = refused["error"].as_str().unwrap();
    assert!(
        message.contains("client") && message.contains("直连或屏蔽"),
        "{message}"
    );
    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["video.example"], "client": ["192.168.1.0/24"]},
            "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 201, "{created}");
    let id = created["rule"]["id"].as_str().unwrap().to_owned();
    let (status, _) = api.call(
        "PUT",
        &format!("/api/v1/atom/rules/{id}"),
        r#"{"match": {"client": ["192.168.1.0/24"]}, "action": {"type": "proxy", "group_id": "g-v"}}"#,
    );
    assert_eq!(status, 400);
}

/// A cache with a dump file, so a flush has to persist.
const DUMP_YAML: &str = r"log: {level: error}
plugins:
  - tag: cache_all
    type: cache
    args: {size: 64, dump_file: cache/all.dump}
  - tag: domestic
    type: forward
    args: {upstreams: [{addr: 'udp://127.0.0.1:15000'}]}
  - tag: atom_rules
    type: atom_rules
    args:
      marks: {proxy: 41, direct: 42, block: 40}
  - tag: main
    type: sequence
    args:
      - exec: $atom_rules
      - exec: $cache_all
      - exec: $domestic
  - tag: listener
    type: udp_server
    args: {entry: main, listen: '127.0.0.1:3098'}
";

fn query_and_answer() -> (Vec<u8>, Vec<u8>) {
    let mut raw = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    raw.extend_from_slice(b"\x01a\x07example\x00\x00\x01\x00\x01");
    let mut wire = raw.clone();
    wire[2] = 0x81;
    wire[3] = 0x80;
    wire[7] = 1;
    wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4]);
    (raw, wire)
}

#[test]
fn a_flush_that_cannot_persist_still_drops_the_old_entries() {
    let api = Api::with_yaml("flush-fallback", DUMP_YAML);
    let dump = api.assembly.config().caches[0].dump_file.clone().unwrap();
    std::fs::create_dir_all(dump.parent().unwrap()).unwrap();
    let store = api.assembly.cache().get(crate::config::CacheId(0)).unwrap();
    let (raw, response) = query_and_answer();
    if let Some(token) = store.begin_store(&raw).unwrap() {
        token.publish(&response).unwrap();
    }
    api.assembly.block_on(store.save()).unwrap();
    assert!(dump.exists(), "the old entry is on disk too");
    // The flush fails to write its empty dump; the change still succeeds,
    // with the cache discarded in memory and on disk.
    store.inject_persist_fault(crate::managed::PersistFault::Rename);
    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["example"]}, "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 201, "{created}");
    assert!(
        store.lookup_entry(&raw).unwrap().is_none(),
        "memory cleared"
    );
    assert!(!dump.exists(), "a restart cannot load the old entry");

    // When even the discard cannot remove the dump (here a directory), the
    // caller is told: the change is in force, the cache is not fully gone.
    if let Some(token) = store.begin_store(&raw).unwrap() {
        token.publish(&response).unwrap();
    }
    std::fs::create_dir_all(dump.join("blocker")).unwrap();
    let (status, failed) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["other.example"]}, "action": {"type": "block"}}"#,
    );
    assert_eq!(status, 500, "{failed}");
    assert!(
        failed["error"].as_str().unwrap().contains("清空缓存失败"),
        "{failed}"
    );
    assert!(
        store.lookup_entry(&raw).unwrap().is_none(),
        "memory still cleared"
    );
    assert_eq!(api.call("GET", "/api/v1/atom/rules", "").1["version"], 2);
}

#[test]
fn rulesets_and_cache_flush() {
    let api = Api::new("rulesets");
    let (status, set) = api.call(
        "POST",
        "/api/v1/atom/rulesets",
        r#"{"name": "mine", "type": "local", "rules": ["mine.example"]}"#,
    );
    assert_eq!(status, 201, "{set}");
    let id = set["id"].as_str().unwrap().to_owned();
    let (_, list) = api.call("GET", "/api/v1/atom/rulesets", "");
    let types: Vec<_> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["type"].clone())
        .collect();
    assert_eq!(types, vec!["builtin", "local"]);
    let (_, shown) = api.call("GET", &format!("/api/v1/atom/rulesets/{id}"), "");
    assert_eq!(shown["rules"], serde_json::json!(["mine.example"]));

    // Fill the cache, then a change must empty it.
    let raw = {
        let mut raw = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        raw.extend_from_slice(b"\x01a\x07example\x00\x00\x01\x00\x01");
        raw
    };
    let response = {
        let mut wire = raw.clone();
        wire[2] = 0x81;
        wire[3] = 0x80;
        wire[7] = 1;
        wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 1, 2, 3, 4]);
        wire
    };
    let store = api.assembly.cache().get(crate::config::CacheId(0)).unwrap();
    if let Some(token) = store.begin_store(&raw).unwrap() {
        token.publish(&response).unwrap();
    }
    assert!(store.lookup_entry(&raw).unwrap().is_some(), "cached");
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/rules",
        &format!(r#"{{"match": {{"ruleset": ["{id}"]}}, "action": {{"type": "block"}}}}"#),
    );
    assert_eq!(status, 201);
    assert!(
        store.lookup_entry(&raw).unwrap().is_none(),
        "flushed by the change"
    );
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/atom/rules/test",
            r#"{"domain": "x.mine.example"}"#
        )
        .1["action"],
        "block"
    );

    let (status, refused) = api.call("DELETE", &format!("/api/v1/atom/rulesets/{id}"), "");
    assert_eq!(status, 409);
    assert_eq!(refused["rules"].as_array().unwrap().len(), 1);
    let (status, _) = api.call(
        "PUT",
        &format!("/api/v1/atom/rulesets/{id}"),
        r#"{"rules": ["other.example"]}"#,
    );
    assert_eq!(status, 200);
    assert_eq!(
        api.call(
            "POST",
            "/api/v1/atom/rules/test",
            r#"{"domain": "x.mine.example"}"#
        )
        .1["matched"],
        false
    );
    let (status, _) = api.call("POST", &format!("/api/v1/atom/rulesets/{id}/refresh"), "");
    assert_eq!(status, 400, "a local set has nothing to download");
    let (status, _) = api.call("POST", "/api/v1/atom/rulesets", r#"{"name": "x"}"#);
    assert_eq!(status, 400, "type is required");
}
