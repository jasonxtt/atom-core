use atomdns_upstream_core::TransportCancellation;
use serde_json::Value;

use crate::assembly::{HostAssembly, HostOptions};
use crate::atom_singbox::tests::FakeSingbox;

struct Api {
    assembly: HostAssembly,
    root: std::path::PathBuf,
    fake: FakeSingbox,
    yaml: String,
}

impl Api {
    fn new(name: &str) -> Self {
        let fake = FakeSingbox::start(&format!("api-{name}"));
        let yaml = format!(
            r"log: {{level: error}}
plugins:
  - tag: cache_all
    type: cache
    args: {{size: 64}}
  - tag: cache_all_noleak
    type: cache
    args: {{size: 64}}
  - tag: cache_upstream
    type: cache
    args: {{size: 64}}
  - tag: domestic
    type: forward
    args: {{upstreams: [{{addr: 'udp://127.0.0.1:15000'}}]}}
  - tag: atom_rules
    type: atom_rules
    args:
      marks: {{proxy: 41, direct: 42, block: 40}}
      {}
  - tag: main
    type: sequence
    args:
      - exec: $atom_rules
      - exec: $cache_all
      - exec: $domestic
  - tag: listener
    type: udp_server
    args: {{entry: main, listen: '127.0.0.1:3098'}}
",
            fake.yaml()
        );
        let root =
            std::env::temp_dir().join(format!("atom-proxy-api-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let config = crate::config::compile_yaml_with_base(&yaml, &root).expect("config");
        let assembly = HostAssembly::with_options(config, HostOptions::default()).unwrap();
        Self {
            assembly,
            root,
            fake,
            yaml,
        }
    }

    /// Loads the configuration and the state files again, as a restart does.
    fn restart(&mut self) {
        let config = crate::config::compile_yaml_with_base(&self.yaml, &self.root).expect("config");
        self.assembly = HostAssembly::with_options(config, HostOptions::default()).unwrap();
    }

    /// A request as a future, to run two at once.
    async fn request(&self, method: &str, target: &str, body: &str) -> (u16, Value) {
        let reply = crate::atom_rules_api::handle(
            None,
            self.assembly.config(),
            self.assembly.cache(),
            method,
            target,
            body.as_bytes(),
            &TransportCancellation::new(),
        )
        .await
        .expect("an atom route");
        let value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        (reply.status, value)
    }

    /// Whether the files on disk make a configuration that loads.
    fn reloads_from_disk(&self) -> Result<(), String> {
        crate::config::compile_yaml_with_base(&self.yaml, &self.root)
            .map(|_| ())
            .map_err(|error| format!("{error:?}"))
    }

    fn reply(&self, method: &str, target: &str) -> crate::rule_sources::Reply {
        self.assembly
            .block_on(crate::atom_rules_api::handle(
                None,
                self.assembly.config(),
                self.assembly.cache(),
                method,
                target,
                b"",
                &TransportCancellation::new(),
            ))
            .expect("an atom route")
    }

    fn call(&self, method: &str, target: &str, body: &str) -> (u16, Value) {
        let reply = self
            .assembly
            .block_on(crate::atom_rules_api::handle(
                None,
                self.assembly.config(),
                self.assembly.cache(),
                method,
                target,
                body.as_bytes(),
                &TransportCancellation::new(),
            ))
            .expect("an atom route");
        let value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        (reply.status, value)
    }

    fn live(&self) -> Value {
        serde_json::from_slice(&self.fake.live().expect("a live config")).unwrap()
    }

    fn outbound(&self, tag: &str) -> Value {
        self.live()["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["tag"] == tag)
            .cloned()
            .unwrap_or(Value::Null)
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

const TWO_LINKS: &str = r#"{"format": "link", "content": "trojan://pw@hk.example:443#香港\nhy2://pw@jp.example:443#日本"}"#;

#[test]
fn import_groups_rules_and_ip_rules_reach_sing_box() {
    let api = Api::new("flow");
    let (status, groups) = api.call("GET", "/api/v1/atom/groups", "");
    assert_eq!(status, 200);
    assert_eq!(groups["groups"][0]["id"], "g-default");
    assert_eq!(groups["groups"][0]["empty"], true);

    let (status, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    assert_eq!(status, 201, "{imported}");
    assert_eq!(imported["version"], 1);
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    let jp = imported["nodes"][1]["id"].as_str().unwrap().to_owned();
    assert_eq!(imported["nodes"][0]["name"], "香港");
    // Applied: the running instance has the file, under the new secret.
    assert_eq!(api.fake.running(), api.fake.live());
    assert_eq!(api.outbound(&hk)["type"], "trojan");
    assert_eq!(
        api.outbound("g-default")["outbounds"],
        serde_json::json!(["block"])
    );

    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/groups",
        &format!(
            r#"{{"name": "流媒体", "type": "urltest", "members": ["{hk}", "{jp}"], "version": 1}}"#
        ),
    );
    assert_eq!(status, 201, "{created}");
    let media = created["group"]["id"].as_str().unwrap().to_owned();
    assert_eq!(created["group"]["interval"], "3m");
    assert_eq!(
        api.outbound(&media)["outbounds"],
        serde_json::json!([hk, jp])
    );
    assert_eq!(
        api.outbound("final")["outbounds"],
        serde_json::json!(["g-default", media])
    );

    // validate_group now checks the group exists.
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["netflix.com"]}, "action": {"type": "proxy", "group_id": "g-00000000"}}"#,
    );
    assert_eq!(status, 400);
    assert!(
        refused["error"].as_str().unwrap().contains("不存在"),
        "{refused}"
    );
    let reloads = api.fake.reload_count();
    let (status, rule) = api.call(
        "POST",
        "/api/v1/atom/rules",
        &format!(r#"{{"match": {{"suffix": ["netflix.com"]}}, "action": {{"type": "proxy", "group_id": "{media}"}}}}"#),
    );
    assert_eq!(status, 201, "{rule}");
    let netflix = rule["rule"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        api.fake.reload_count(),
        reloads,
        "a DNS-only rule does not touch sing-box"
    );

    // An IP rule becomes a sing-box route rule; with a client condition it
    // is 400 (the client list is AtomDNS's; names beside it are fine since
    // step 6b).
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"ip_cidr": ["91.108.4.0/22"], "client": ["192.168.1.0/24"]}, "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 400);
    assert!(
        refused["error"].as_str().unwrap().contains("client"),
        "{refused}"
    );
    let (status, rule) = api.call(
        "POST",
        "/api/v1/atom/rules",
        &format!(r#"{{"remark": "Telegram", "match": {{"ip_cidr": ["91.108.4.1/22", "2001:b28:f23d::/48"]}}, "action": {{"type": "proxy", "group_id": "{media}"}}}}"#),
    );
    assert_eq!(status, 201, "{rule}");
    let telegram = rule["rule"]["id"].as_str().unwrap().to_owned();
    let routes = api.live()["route"]["rules"].clone();
    assert_eq!(
        routes[2]["rules"][1],
        serde_json::json!({"ip_cidr": ["91.108.4.0/22", "2001:b28:f23d::/48"]})
    );
    assert_eq!(routes[2]["outbound"], media.as_str());
    let (_, status_view) = api.call("GET", "/api/v1/atom/status", "");
    assert_eq!(status_view["singbox"]["in_sync"], true, "{status_view}");
    assert_eq!(status_view["singbox"]["version"], "sing-box 1.14.4-atom");
    assert!(status_view.get("nft").is_none(), "{status_view}");
    // The IP rule takes no part in the DNS table.
    let (_, test) = api.call(
        "POST",
        "/api/v1/atom/rules/test",
        r#"{"domain": "91.108.4.1"}"#,
    );
    assert_eq!(test["matched"], false);

    // Deleting a group rules use: 409 with them, then confirm moves them to Final.
    let (status, blocked) = api.call("DELETE", &format!("/api/v1/atom/groups/{media}"), "");
    assert_eq!(status, 409);
    let mut users: Vec<String> = blocked["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    users.sort();
    let mut expected = vec![netflix.clone(), telegram.clone()];
    expected.sort();
    assert_eq!(users, expected);
    let (status, deleted) = api.call(
        "DELETE",
        &format!("/api/v1/atom/groups/{media}?confirm=true"),
        "",
    );
    assert_eq!(status, 200, "{deleted}");
    let (_, rules) = api.call("GET", "/api/v1/atom/rules", "");
    for rule in rules["rules"].as_array().unwrap() {
        if rule["id"] == netflix.as_str() || rule["id"] == telegram.as_str() {
            assert_eq!(rule["action"]["group_id"], "final");
        }
    }
    assert_eq!(api.outbound(&media), Value::Null);
    assert_eq!(
        api.outbound("final")["outbounds"],
        serde_json::json!(["g-default"])
    );
    assert_eq!(api.live()["route"]["rules"][2]["outbound"], "final");
    let (_, final_view) = api.call("GET", "/api/v1/atom/final", "");
    assert_eq!(final_view["members"], serde_json::json!(["g-default"]));
    let (status, _) = api.call("DELETE", "/api/v1/atom/groups/g-default?confirm=true", "");
    assert_eq!(status, 400, "the builtin group stays");

    // Files survive a reload of the configuration.
    let saved: Value =
        serde_json::from_slice(&std::fs::read(api.root.join("webinfo/atom_proxy.json")).unwrap())
            .unwrap();
    assert_eq!(saved["nodes"].as_array().unwrap().len(), 2);
}

#[test]
fn a_refused_check_or_reload_changes_nothing() {
    let api = Api::new("rollback");
    let (status, _) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    assert_eq!(status, 201);
    let before = api.fake.live().unwrap();
    let (_, nodes_before) = api.call("GET", "/api/v1/atom/nodes", "");

    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/nodes",
        r#"{"format": "json", "content": {"type": "trojan", "server": "BADCHECK.example", "server_port": 443, "password": "p"}}"#,
    );
    assert_eq!(status, 400, "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("sing-box check"),
        "{refused}"
    );
    assert_eq!(api.fake.live().unwrap(), before);

    let (status, failed) = api.call(
        "POST",
        "/api/v1/atom/nodes",
        r#"{"format": "yaml", "content": "{name: x, type: trojan, server: BADRELOAD.example, port: 443, password: p}"}"#,
    );
    assert_eq!(status, 502, "{failed}");
    assert!(
        failed["error"].as_str().unwrap().contains("已回滚到旧配置"),
        "{failed}"
    );
    assert_eq!(api.fake.live().unwrap(), before);
    assert_eq!(api.fake.running().unwrap(), before);
    let (_, nodes_after) = api.call("GET", "/api/v1/atom/nodes", "");
    assert_eq!(nodes_after, nodes_before, "state unchanged");
    let (_, apply) = api.call("GET", "/api/v1/atom/apply", "");
    assert_eq!(apply["last_apply"]["ok"], false);
    assert_eq!(apply["in_sync"], true);
}

#[test]
fn renames_skip_sing_box_and_select_goes_through_the_clash_api() {
    let api = Api::new("select");
    let (_, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    let jp = imported["nodes"][1]["id"].as_str().unwrap().to_owned();
    let (status, _) = api.call(
        "PUT",
        "/api/v1/atom/groups/g-default",
        &format!(r#"{{"name": "默认代理", "type": "selector", "members": ["{hk}", "{jp}"]}}"#),
    );
    assert_eq!(status, 200);
    let reloads = api.fake.reload_count();
    let (status, renamed) = api.call(
        "PUT",
        &format!("/api/v1/atom/nodes/{hk}"),
        r#"{"name": "香港 IPLC"}"#,
    );
    assert_eq!(status, 200, "{renamed}");
    assert_eq!(renamed["node"]["name"], "香港 IPLC");
    assert_eq!(
        api.fake.reload_count(),
        reloads,
        "names are not in the sing-box file"
    );

    let (status, selected) = api.call(
        "POST",
        "/api/v1/atom/groups/g-default/select",
        &format!(r#"{{"name": "{jp}"}}"#),
    );
    assert_eq!(status, 200, "{selected}");
    assert_eq!(
        api.fake.selects.lock().unwrap().last().unwrap().0,
        "g-default"
    );
    assert_eq!(api.fake.reload_count(), reloads, "select does not reload");
    assert_eq!(api.outbound("g-default")["default"], jp.as_str());
    let (_, status_view) = api.call("GET", "/api/v1/atom/status", "");
    assert_eq!(status_view["singbox"]["in_sync"], true);
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/groups/g-default/select",
        r#"{"name": "direct"}"#,
    );
    assert_eq!(status, 400);

    // Final: switching is a select, editing members an application.
    let (status, _) = api.call(
        "PUT",
        "/api/v1/atom/final",
        &format!(r#"{{"selected": "{hk}"}}"#),
    );
    assert_eq!(status, 400, "not a member yet");
    let (status, final_view) = api.call(
        "PUT",
        "/api/v1/atom/final",
        &format!(r#"{{"members": ["g-default", "{hk}"], "selected": "{hk}"}}"#),
    );
    assert_eq!(status, 200, "{final_view}");
    assert_eq!(api.outbound("final")["default"], hk.as_str());
    let (status, _) = api.call("PUT", "/api/v1/atom/final", r#"{"members": ["direct"]}"#);
    assert_eq!(status, 400, "Final cannot be direct");
    let (status, final_view) =
        api.call("PUT", "/api/v1/atom/final", r#"{"selected": "g-default"}"#);
    assert_eq!(status, 200);
    assert_eq!(final_view["selected"], "g-default");
    assert_eq!(api.fake.selects.lock().unwrap().last().unwrap().0, "final");

    let (status, delays) = api.call("POST", "/api/v1/atom/groups/g-default/delay", "{}");
    assert_eq!(status, 200, "{delays}");
    assert_eq!(delays["delays"]["n-00000001"], 120);

    // Version conflicts.
    let (status, conflict) = api.call(
        "POST",
        "/api/v1/atom/groups",
        r#"{"name": "x", "type": "selector", "version": 1}"#,
    );
    assert_eq!(status, 409);
    assert!(conflict["version"].as_u64().unwrap() > 1);
    // Deleting a node empties the group it was in rather than failing.
    let (status, _) = api.call("DELETE", &format!("/api/v1/atom/nodes/{jp}"), "");
    assert_eq!(status, 200);
    assert_eq!(
        api.outbound("g-default")["outbounds"],
        serde_json::json!([hk])
    );
}

#[test]
fn settings_are_validated_and_applied() {
    let api = Api::new("settings");
    let (status, settings) = api.call("GET", "/api/v1/atom/settings", "");
    assert_eq!(status, 200);
    assert_eq!(settings["mixed_port"], 7890);
    assert_eq!(settings["resolver_effective"], "udp://223.5.5.5");
    assert_eq!(settings["direct_ttl_max"], 300);
    assert_eq!(settings["fakeip_ttl_max"], 1);
    let (status, refused) = api.call("PUT", "/api/v1/atom/settings", r#"{"mixed_port": 6666}"#);
    assert_eq!(status, 400, "{refused}");
    let (status, applied) = api.call(
        "PUT",
        "/api/v1/atom/settings",
        r#"{"fakeip_range": "198.18.0.0/15", "resolver": "tcp://119.29.29.29"}"#,
    );
    assert_eq!(status, 200, "{applied}");
    assert_eq!(applied["resolver_effective"], "tcp://119.29.29.29");
    let live = api.live();
    assert_eq!(live["dns"]["servers"][0]["inet4_range"], "198.18.0.0/15");
    assert_eq!(live["dns"]["servers"][1]["type"], "tcp");
    let (status, refused) = api.call("PUT", "/api/v1/atom/settings", r#"{"fakeip_ttl_max": 0}"#);
    assert_eq!(status, 400, "{refused}");
    let before = api.fake.live();
    let (status, applied) = api.call(
        "PUT",
        "/api/v1/atom/settings",
        r#"{"direct_ttl_max": 60, "fakeip_ttl_max": 5}"#,
    );
    assert_eq!(status, 200, "{applied}");
    assert_eq!(
        (&applied["direct_ttl_max"], &applied["fakeip_ttl_max"]),
        (&Value::from(60), &Value::from(5))
    );
    // Not part of the sing-box configuration: nothing was applied.
    assert_eq!(api.fake.live(), before);
    let (status, applied) = api.call("PUT", "/api/v1/atom/settings", r#"{"mixed_port": 17890}"#);
    assert_eq!(status, 200, "{applied}");
    assert_eq!(api.live()["inbounds"][3]["listen_port"], 17890);
    let (status, reapplied) = api.call("POST", "/api/v1/atom/apply", "");
    assert_eq!(status, 200, "{reapplied}");
    assert_eq!(reapplied["last_apply"]["trigger"], "apply");
}

#[test]
fn global_caches_exclude_current_fakeip_and_filter_old_dumps() {
    let api = Api::new("fakeip-cache");
    let cache = |tag: &str| {
        let item = api
            .assembly
            .config()
            .named_caches()
            .find(|item| item.tag == tag)
            .unwrap();
        api.assembly.cache().get(item.id).unwrap()
    };
    let wire = |name: u8, address: [u8; 4]| {
        let query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, name, 0, 0, 1, 0, 1];
        let mut response = query.clone();
        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 1;
        response.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        response.extend_from_slice(&address);
        (query, response)
    };
    let (fake_query, fake) = wire(b'a', [28, 0, 0, 2]);
    let (real_query, real) = wire(b'b', [192, 0, 2, 1]);
    let (previous_query, previous_fake) = wire(b'c', [198, 18, 0, 2]);
    let fakeip_host = api
        .assembly
        .config()
        .local
        .atom_rules
        .as_ref()
        .unwrap()
        .proxy_host()
        .unwrap();
    let origin = atomdns_sequence_core::ResponseOrigin {
        identity: "nocnfake".into(),
        peer: Some(fakeip_host.dns_in),
        transport: Some("udp"),
    };
    let source = cache("cache_upstream");
    for (query, response, origin) in [
        (&fake_query, &fake, None),
        (&real_query, &real, None),
        (&previous_query, &previous_fake, Some(origin.clone())),
    ] {
        assert!(
            source
                .begin_store(query)
                .unwrap()
                .unwrap()
                .publish_with_origin(response, "", origin)
                .unwrap()
        );
    }
    let legacy_dump = source.dump().unwrap();

    for tag in ["cache_all", "cache_all_noleak"] {
        let store = cache(tag);
        assert!(
            !store
                .begin_store(&fake_query)
                .unwrap()
                .unwrap()
                .publish(&fake)
                .unwrap()
        );
        assert!(
            !store
                .begin_store(&previous_query)
                .unwrap()
                .unwrap()
                .publish_with_origin(&previous_fake, "", Some(origin.clone()))
                .unwrap()
        );
        if tag == "cache_all" {
            let path = api.root.join("legacy.dump");
            std::fs::write(&path, &legacy_dump).unwrap();
            let startup = store.clone().with_persistence(Some(path), 600).catalog();
            api.assembly.block_on(startup.load_startup());
        } else {
            api.assembly
                .block_on(store.import_dump(legacy_dump.clone()))
                .unwrap();
        }
        assert!(store.lookup(&fake_query).unwrap().is_none());
        assert!(store.lookup(&previous_query).unwrap().is_none());
        assert!(store.lookup(&real_query).unwrap().is_some());
    }

    let (status, result) = api.call(
        "PUT",
        "/api/v1/atom/settings",
        r#"{"fakeip_range":"198.18.0.0/15"}"#,
    );
    assert_eq!(status, 200, "{result}");
    for tag in ["cache_all", "cache_all_noleak"] {
        let store = cache(tag);
        assert!(
            !store
                .begin_store(&previous_query)
                .unwrap()
                .unwrap()
                .publish(&previous_fake)
                .unwrap()
        );
        assert!(
            store
                .begin_store(&real_query)
                .unwrap()
                .unwrap()
                .publish(&real)
                .unwrap()
        );
    }
    assert!(source.lookup(&previous_query).unwrap().is_some());
}

#[test]
fn without_a_singbox_section_the_proxy_routes_are_absent() {
    let root = std::env::temp_dir().join(format!("atom-proxy-api-none-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let yaml = r"log: {level: error}
plugins:
  - tag: domestic
    type: forward
    args: {upstreams: [{addr: 'udp://127.0.0.1:15000'}]}
  - tag: atom_rules
    type: atom_rules
    args: {marks: {proxy: 41, direct: 42, block: 40}}
  - tag: main
    type: sequence
    args:
      - exec: $atom_rules
      - exec: $domestic
  - tag: listener
    type: udp_server
    args: {entry: main, listen: '127.0.0.1:3097'}
";
    let config = crate::config::compile_yaml_with_base(yaml, &root).expect("config");
    let assembly = HostAssembly::with_options(config, HostOptions::default()).unwrap();
    let reply = assembly
        .block_on(crate::atom_rules_api::handle(
            None,
            assembly.config(),
            assembly.cache(),
            "GET",
            "/api/v1/atom/nodes",
            b"",
            &TransportCancellation::new(),
        ))
        .unwrap();
    assert_eq!(reply.status, 404);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn settings_put_takes_its_own_lease() {
    assert!(!crate::atom_rules_api::mutates(
        "PUT",
        "/api/v1/atom/settings"
    ));
    assert!(crate::atom_rules_api::mutates("POST", "/api/v1/atom/nodes"));
    assert!(crate::atom_rules_api::mutates(
        "DELETE",
        "/api/v1/atom/groups/g-1"
    ));
    assert!(!crate::atom_rules_api::mutates(
        "GET",
        "/api/v1/atom/status"
    ));
}

#[test]
fn node_views_carry_credentials_and_edits_replace_the_connection() {
    let api = Api::new("credentials");
    let (status, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    assert_eq!(status, 201);
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(imported["nodes"][0]["outbound"]["password"], "pw", "{imported}");
    let (_, one) = api.call("GET", &format!("/api/v1/atom/nodes/{hk}"), "");
    assert_eq!(one["outbound"]["server"], "hk.example");
    assert_eq!(one["outbound"]["password"], "pw");
    assert_eq!(api.outbound(&hk)["password"], "pw");

    let (status, _) = api.call(
        "PUT",
        &format!("/api/v1/atom/nodes/{hk}"),
        r#"{"format": "link"}"#,
    );
    assert_eq!(status, 400, "format and content go together");
    let (status, _) = api.call(
        "PUT",
        &format!("/api/v1/atom/nodes/{hk}"),
        r#"{"format": "link", "content": "trojan://a@x.example:1\ntrojan://b@y.example:2"}"#,
    );
    assert_eq!(status, 400, "one node only");
    let (status, replaced) = api.call(
        "PUT",
        &format!("/api/v1/atom/nodes/{hk}"),
        r#"{"format": "link", "content": "trojan://newpw@hk2.example:8443#ignored"}"#,
    );
    assert_eq!(status, 200, "{replaced}");
    assert_eq!(
        replaced["node"]["name"], "香港",
        "the name stays unless given"
    );
    assert_eq!(replaced["node"]["server"], "hk2.example");
    assert_eq!(api.outbound(&hk)["password"], "newpw");
    assert_eq!(api.outbound(&hk)["server_port"], 8443);

    let (status, tested) = api.call(
        "POST",
        &format!("/api/v1/atom/nodes/{hk}/delay"),
        r#"{"timeout": 2000}"#,
    );
    assert_eq!(status, 200, "{tested}");
    assert_eq!(tested, serde_json::json!({"id": hk, "delay": 88}));
    let (status, _) = api.call("POST", "/api/v1/atom/nodes/g-default/delay", "{}");
    assert_eq!(status, 404);
    let (status, _) = api.call("POST", &format!("/api/v1/atom/groups/{hk}/delay"), "{}");
    assert_eq!(status, 404);
}

/// `nodes/{id}/export` gives the text `PUT nodes/{id}` takes back: saving it
/// unchanged leaves the connection as it is, in either format.
#[test]
fn an_exported_node_saves_back_unchanged() {
    let api = Api::new("export");
    let (_, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    let before = api.outbound(&hk);

    let reply = api.reply("GET", &format!("/api/v1/atom/nodes/{hk}/export"));
    assert!(reply.headers.contains(&("Cache-Control", "no-store".to_owned())));
    let (status, json_text) = api.call("GET", &format!("/api/v1/atom/nodes/{hk}/export"), "");
    assert_eq!(status, 200, "{json_text}");
    assert_eq!(json_text["format"], "json", "sing-box is the default kernel");
    let content = json_text["content"].as_str().unwrap();
    assert!(content.trim_start().starts_with("{\n  \"tag\": \"香港\""), "{content}");
    assert!(content.contains("\"password\": \"pw\""), "{content}");

    let (status, yaml_text) = api.call("GET", &format!("/api/v1/atom/nodes/{hk}/export?format=yaml"), "");
    assert_eq!(status, 200, "{yaml_text}");
    let yaml = yaml_text["content"].as_str().unwrap();
    assert!(yaml.starts_with("name: 香港\ntype: trojan\n"), "{yaml}");
    assert!(yaml.contains("password: pw"), "{yaml}");

    for text in [&json_text, &yaml_text] {
        let body = serde_json::json!({"format": text["format"], "content": text["content"]});
        let (status, saved) = api.call("PUT", &format!("/api/v1/atom/nodes/{hk}"), &body.to_string());
        assert_eq!(status, 200, "{saved}");
        assert_eq!(saved["node"]["name"], "香港");
        assert_eq!(api.outbound(&hk), before, "{}", text["format"]);
    }

    // A TCP-only Mihomo proxy becomes a TCP-only sing-box outbound.
    assert!(yaml.contains("udp: true"), "{yaml}");
    let body = serde_json::json!({"format": "yaml", "content": yaml.replace("udp: true", "udp: false")});
    let (status, saved) = api.call("PUT", &format!("/api/v1/atom/nodes/{hk}"), &body.to_string());
    assert_eq!(status, 200, "{saved}");
    let tcp_only = api.outbound(&hk);
    assert_eq!(tcp_only["network"], "tcp");
    // References to other proxies must still be configured through groups.
    let body = serde_json::json!({"format": "yaml", "content": format!("{yaml}dialer-proxy: another-node\n")});
    let (status, refused) = api.call("PUT", &format!("/api/v1/atom/nodes/{hk}"), &body.to_string());
    assert_eq!(status, 400, "{refused}");
    assert!(refused["error"].as_str().unwrap().contains("dialer-proxy"), "{refused}");
    assert_eq!(api.outbound(&hk), tcp_only);

    // Hysteria2 bandwidth and a VLESS packet encoding come back from YAML; a
    // node the YAML cannot carry whole is offered only as JSON.
    let nodes = serde_json::json!([
        {"tag": "hy", "type": "hysteria2", "server": "h.example", "server_port": 443,
         "password": "p", "up_mbps": 50, "down_mbps": 200,
         "tls": {"enabled": true, "server_name": "h.example"}},
        {"tag": "vl", "type": "vless", "server": "v.example", "server_port": 443,
         "uuid": "9b1c2e4a-0000-4000-8000-000000000001", "packet_encoding": "packetaddr"},
        {"tag": "bare", "type": "vless", "server": "b.example", "server_port": 443,
         "uuid": "9b1c2e4a-0000-4000-8000-000000000002"}
    ]);
    let body = serde_json::json!({"format": "json", "content": nodes.to_string()});
    let (status, imported) = api.call("POST", "/api/v1/atom/nodes", &body.to_string());
    assert_eq!(status, 201, "{imported}");
    for (index, round_trips) in [(0, true), (1, true), (2, false)] {
        let id = imported["nodes"][index]["id"].as_str().unwrap().to_owned();
        let before = api.outbound(&id);
        let (status, text) = api.call("GET", &format!("/api/v1/atom/nodes/{id}/export?format=yaml"), "");
        if !round_trips {
            assert_eq!(status, 422, "{text}");
            continue;
        }
        assert_eq!(status, 200, "{text}");
        let body = serde_json::json!({"format": "yaml", "content": text["content"]});
        let (status, saved) = api.call("PUT", &format!("/api/v1/atom/nodes/{id}"), &body.to_string());
        assert_eq!(status, 200, "{saved}");
        assert_eq!(api.outbound(&id), before, "{}", text["content"]);
    }

    let (status, _) = api.call("GET", &format!("/api/v1/atom/nodes/{hk}/export?format=link"), "");
    assert_eq!(status, 400);
    let (status, _) = api.call("GET", "/api/v1/atom/nodes/n-missing/export", "");
    assert_eq!(status, 404);
}

/// Port and network conditions (sing-box, real addresses only): never with
/// name or client conditions; compiled beside IP prefixes, FakeIP left out.
#[test]
fn port_and_network_rules_go_to_sing_box() {
    let mut api = Api::new("ports");
    let refused = |body: &str| {
        let (status, view) = api.call("POST", "/api/v1/atom/rules", body);
        assert_eq!(status, 400, "{body}: {view}");
        view["error"].as_str().unwrap().to_owned()
    };
    for body in [
        r#"{"match": {"port": [443], "suffix": ["a.example"]}, "action": {"type": "direct"}}"#,
        r#"{"match": {"network": ["udp"], "ruleset": ["cuscn"]}, "action": {"type": "block"}}"#,
        r#"{"match": {"port_range": ["1:2"], "client": ["192.168.1.0/24"]}, "action": {"type": "block"}}"#,
    ] {
        assert!(refused(body).contains("DNS 查询时不知道端口"), "{body}");
    }
    assert!(refused(r#"{"match": {"port": [0]}, "action": {"type": "block"}}"#).contains("1 到 65535"));
    for range in ["2000:1000", "1000", ":", "a:b", "0:10"] {
        let body = format!(r#"{{"match": {{"port_range": ["{range}"]}}, "action": {{"type": "block"}}}}"#);
        assert!(refused(&body).contains("port_range"), "{range}");
    }
    assert!(refused(r#"{"match": {"network": ["icmp"]}, "action": {"type": "block"}}"#).contains("tcp 或 udp"));
    // An IP rule over the FakeIP range is refused (FakeIP destinations go by
    // binding or Final); so is a range change over an IP rule.
    for cidr in ["28.1.0.0/16", "0.0.0.0/0", "28.9.9.9"] {
        let body = format!(r#"{{"match": {{"ip_cidr": ["{cidr}"]}}, "action": {{"type": "block"}}}}"#);
        assert!(refused(&body).contains("FakeIP 网段"), "{cidr}");
    }

    let (status, rule) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"port": [5201, 22, 5201], "port_range": [" 6000:6010 ", "7000:"], "network": ["udp", "tcp"]}, "action": {"type": "proxy", "group_id": "g-default"}}"#,
    );
    assert_eq!(status, 201, "{rule}");
    let (status, rule) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"ip_cidr": ["1.1.1.1"], "network": ["udp"]}, "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 201, "{rule}");
    let routes = api.live()["route"]["rules"].clone();
    let not_fakeip = serde_json::json!({"ip_cidr": ["28.0.0.0/8"], "invert": true});
    assert_eq!(
        routes[2],
        serde_json::json!({"type": "logical", "mode": "and", "rules": [not_fakeip, {"port": [22, 5201], "port_range": ["6000:6010", "7000:"], "network": ["tcp", "udp"]}], "action": "route", "outbound": "g-default"})
    );
    assert_eq!(
        routes[3],
        serde_json::json!({"type": "logical", "mode": "and", "rules": [not_fakeip, {"ip_cidr": ["1.1.1.1/32"], "network": ["udp"]}], "action": "route", "outbound": "direct"})
    );
    let (_, status_view) = api.call("GET", "/api/v1/atom/status", "");
    assert_eq!(status_view["singbox"]["in_sync"], true, "{status_view}");
    let (status, refused) = api.call(
        "PUT",
        "/api/v1/atom/settings",
        r#"{"fakeip_range": "1.0.0.0/8"}"#,
    );
    assert_eq!(status, 400, "{refused}");
    assert!(refused["error"].as_str().unwrap().contains("FakeIP 网段"), "{refused}");
    // A table saved before the check (an ip_cidr over the range) still
    // loads; other rules stay editable, the overlapping entry is refused
    // when that rule is written again.
    let file = api.root.join("webinfo/atom_rules.json");
    let mut saved: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    let legacy = saved["rules"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|rule| rule["match"]["ip_cidr"].is_array())
        .unwrap();
    legacy["match"]["ip_cidr"] = serde_json::json!(["28.0.0.0/8"]);
    let legacy_id = legacy["id"].as_str().unwrap().to_owned();
    std::fs::write(&file, serde_json::to_vec(&saved).unwrap()).unwrap();
    api.reloads_from_disk().unwrap();
    api.restart();
    let version = || api.call("GET", "/api/v1/atom/rules", "").1["version"].as_u64().unwrap();
    // The legacy rule can still be edited (its entry stays), not given a
    // new overlapping entry; a range change still checks every entry.
    let (status, body) = api.call(
        "PUT",
        &format!("/api/v1/atom/rules/{legacy_id}"),
        &format!(r#"{{"remark": "旧规则", "match": {{"ip_cidr": [" 28.0.0.1/8", "1.1.1.1"], "network": ["udp"]}}, "action": {{"type": "direct"}}, "version": {}}}"#, version()),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = api.call(
        "PUT",
        &format!("/api/v1/atom/rules/{legacy_id}"),
        &format!(r#"{{"match": {{"ip_cidr": ["28.0.0.0/8", "28.1.0.0/16"]}}, "action": {{"type": "direct"}}, "version": {}}}"#, version()),
    );
    assert_eq!(status, 400, "{body}");
    assert!(body["error"].as_str().unwrap().contains("28.1.0.0/16"), "{body}");
    let (status, body) = api.call("PUT", "/api/v1/atom/settings", r#"{"fakeip_range": "28.0.0.0/16"}"#);
    assert_eq!(status, 400, "{body}");
    let (status, body) = api.call(
        "PUT",
        &format!("/api/v1/atom/rules/{legacy_id}"),
        &format!(r#"{{"match": {{"ip_cidr": ["1.1.1.1"], "network": ["udp"]}}, "action": {{"type": "direct"}}, "version": {}}}"#, version()),
    );
    assert_eq!(status, 200, "{body}");
    // The FakeIP exclusion follows the range.
    let (status, changed) = api.call(
        "PUT",
        "/api/v1/atom/settings",
        r#"{"fakeip_range": "29.0.0.0/8"}"#,
    );
    assert_eq!(status, 200, "{changed}");
    assert_eq!(
        api.live()["route"]["rules"][2]["rules"][0],
        serde_json::json!({"ip_cidr": ["29.0.0.0/8"], "invert": true})
    );
}

fn fail_next_save() {
    crate::atom_proxy::FAIL_NEXT_SAVE.with(|fail| fail.set(true));
}

/// A failed save whose compensation fails too leaves sing-box on the new
/// configuration, and says so.
#[test]
fn a_failed_compensation_is_reported() {
    let api = Api::new("compensate-fails");
    let (status, _) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    assert_eq!(status, 201);
    // The compensation writes config.json through `<file>.tmp-<pid>`: a
    // directory there makes that write fail.
    let blocker = api
        .fake
        .host
        .dir
        .join(format!("config.json.tmp-{}", std::process::id()));
    std::fs::create_dir_all(&blocker).unwrap();
    fail_next_save();
    let (status, body) = api.call(
        "PUT",
        "/api/v1/atom/settings",
        r#"{"fakeip_range": "29.0.0.0/8"}"#,
    );
    std::fs::remove_dir_all(&blocker).unwrap();
    assert_eq!(status, 500, "{body}");
    assert!(
        body["error"].as_str().unwrap().contains("回滚失败"),
        "{body}"
    );
    assert_eq!(api.live()["dns"]["servers"][0]["inet4_range"], "29.0.0.0/8");
}

#[test]
fn a_failed_save_keeps_other_changes_out_until_sing_box_is_compensated() {
    let api = Api::new("compensate");
    let (status, _) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    assert_eq!(status, 201);
    let before = api.fake.live().unwrap();
    let reloads = api.fake.reload_count();
    let slow = api.fake.host.dir.join("slow");
    std::fs::write(&slow, b"").unwrap();
    fail_next_save();
    let (first, second) = api.assembly.block_on(async {
        let first = api.request(
            "POST",
            "/api/v1/atom/groups",
            r#"{"name": "g", "type": "selector"}"#,
        );
        let second = async {
            // The second reload of the first change is its compensation.
            while api.fake.reload_count() < reloads + 2 {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            api.request(
                "POST",
                "/api/v1/atom/nodes",
                r#"{"format": "link", "content": "trojan://x@z.example:1"}"#,
            )
            .await
        };
        tokio::join!(first, second)
    });
    std::fs::remove_file(&slow).unwrap();
    assert_eq!(first.0, 500, "{}", first.1);
    let message = first.1["error"].as_str().unwrap();
    assert!(
        message.contains("injected save failure") && message.contains("已回滚到旧配置"),
        "{message}"
    );
    assert_eq!(
        second.0, 409,
        "a change during the compensation is refused: {}",
        second.1
    );
    assert_eq!(api.fake.live().unwrap(), before);
    assert_eq!(api.fake.running().unwrap(), before);
    let (_, nodes) = api.call("GET", "/api/v1/atom/nodes", "");
    assert_eq!(nodes["nodes"].as_array().unwrap().len(), 2);
}

#[test]
fn a_confirmed_group_deletion_writes_rules_first_and_undoes_them_on_failure() {
    let mut api = Api::new("delete-order");
    let (_, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    let (_, created) = api.call(
        "POST",
        "/api/v1/atom/groups",
        &format!(r#"{{"name": "G", "type": "selector", "members": ["{hk}"]}}"#),
    );
    let group = created["group"]["id"].as_str().unwrap().to_owned();
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/rules",
        &format!(r#"{{"match": {{"suffix": ["a.example"]}}, "action": {{"type": "proxy", "group_id": "{group}"}}}}"#),
    );
    assert_eq!(status, 201);
    let rules_file = api.root.join(crate::atom_rules::RULES_FILE);
    let proxy_file = api.root.join(crate::atom_proxy::PROXY_FILE);
    let (old_rules, old_proxy) = (
        std::fs::read(&rules_file).unwrap(),
        std::fs::read(&proxy_file).unwrap(),
    );

    // The group file write fails after the rules were written: they are put back.
    fail_next_save();
    let (status, failed) = api.call(
        "DELETE",
        &format!("/api/v1/atom/groups/{group}?confirm=true"),
        "",
    );
    assert_eq!(status, 500, "{failed}");
    assert!(
        failed["error"].as_str().unwrap().contains("规则文件已恢复"),
        "{failed}"
    );
    assert_eq!(std::fs::read(&rules_file).unwrap(), old_rules);
    assert_eq!(std::fs::read(&proxy_file).unwrap(), old_proxy);
    let (_, rules) = api.call("GET", "/api/v1/atom/rules", "");
    assert_eq!(
        rules["rules"].as_array().unwrap().last().unwrap()["action"]["group_id"],
        group.as_str()
    );
    api.reloads_from_disk().unwrap();
    let marker = api.root.join("webinfo/atom_removed_groups").join(&group);
    assert!(marker.exists());
    let rules = api.assembly.config().local.atom_rules.as_ref().unwrap();
    api.assembly
        .block_on(rules.rebind_removed_groups())
        .unwrap();
    let last_rebind = api.fake.host.dir.join("last-rebind");
    assert!(
        !last_rebind.exists(),
        "the rolled-back group is still active"
    );

    // A crash between the two writes leaves new rules beside the old groups:
    // that loads. The other order (old rules, new groups) would not.
    let (status, _) = api.call(
        "DELETE",
        &format!("/api/v1/atom/groups/{group}?confirm=true"),
        "",
    );
    assert_eq!(status, 200);
    let (new_rules, new_proxy) = (
        std::fs::read(&rules_file).unwrap(),
        std::fs::read(&proxy_file).unwrap(),
    );
    std::fs::write(&proxy_file, &old_proxy).unwrap();
    api.reloads_from_disk()
        .expect("new rules with the old groups load");
    std::fs::write(&rules_file, &old_rules).unwrap();
    std::fs::write(&proxy_file, &new_proxy).unwrap();
    let refused = api.reloads_from_disk().unwrap_err();
    assert!(refused.contains("不存在"), "{refused}");
    std::fs::write(&rules_file, &new_rules).unwrap();

    let fail = api.fake.host.dir.join("fail-rebind");
    std::fs::write(&fail, b"").unwrap();
    let rules = api.assembly.config().local.atom_rules.as_ref().unwrap();
    let (_, status) = api.call("GET", "/api/v1/atom/status", "");
    assert_eq!(status["bindings"]["pending"], true);
    assert!(!last_rebind.exists(), "deleting did not wait for migration");
    assert!(
        api.assembly
            .block_on(rules.rebind_removed_groups())
            .is_err()
    );
    assert!(marker.exists(), "a failed migration must survive a restart");
    std::fs::remove_file(&last_rebind).unwrap();
    std::fs::remove_file(fail).unwrap();
    api.restart();
    let rules = api.assembly.config().local.atom_rules.clone().unwrap();
    let control = api.assembly.control();
    api.assembly.block_on(async {
        let cancel = TransportCancellation::new();
        crate::atom_ledger::spawn_worker(
            rules,
            crate::runtime_snapshot::RuntimeControlWeak::from_control(&control),
            cancel.clone(),
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while marker.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        cancel.cancel();
    });
    assert_eq!(
        std::fs::read_to_string(last_rebind).unwrap(),
        format!("/cache/fakeip/group/{group}/final")
    );
}

#[test]
fn a_reload_brings_the_running_selection_to_the_saved_one() {
    let api = Api::new("cached-selection");
    let (_, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    let jp = imported["nodes"][1]["id"].as_str().unwrap().to_owned();
    let members = format!(r#""members": ["{hk}", "{jp}"]"#);
    let (status, _) = api.call(
        "PUT",
        "/api/v1/atom/groups/g-default",
        &format!(r#"{{"name": "默认代理", "type": "selector", {members}}}"#),
    );
    assert_eq!(status, 200);
    // jp through the Clash API: sing-box's cache.db now remembers jp.
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/groups/g-default/select",
        &format!(r#"{{"name": "{jp}"}}"#),
    );
    assert_eq!(status, 200);
    // Back to hk by editing the group: a reload, after which the cached jp
    // would win over `default` unless the selection is pushed again.
    let (status, _) = api.call(
        "PUT",
        "/api/v1/atom/groups/g-default",
        &format!(r#"{{"name": "默认代理", "type": "selector", {members}, "selected": "{hk}"}}"#),
    );
    assert_eq!(status, 200);
    let last = api
        .fake
        .selects
        .lock()
        .unwrap()
        .iter()
        .rev()
        .find(|(tag, _)| tag == "g-default")
        .cloned()
        .unwrap();
    assert_eq!(last.1, format!(r#"{{"name":"{hk}"}}"#));
}

#[test]
fn a_select_that_cannot_be_saved_is_switched_back() {
    let api = Api::new("select-undo");
    let (_, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    let jp = imported["nodes"][1]["id"].as_str().unwrap().to_owned();
    let (status, _) = api.call(
        "PUT",
        "/api/v1/atom/groups/g-default",
        &format!(r#"{{"name": "默认代理", "type": "selector", "members": ["{hk}", "{jp}"]}}"#),
    );
    assert_eq!(status, 200);
    let before = api.fake.live().unwrap();
    fail_next_save();
    let (status, failed) = api.call(
        "POST",
        "/api/v1/atom/groups/g-default/select",
        &format!(r#"{{"name": "{jp}"}}"#),
    );
    assert_eq!(status, 500, "{failed}");
    assert!(
        failed["error"]
            .as_str()
            .unwrap()
            .contains("已恢复原来的选择"),
        "{failed}"
    );
    let selects = api.fake.selects.lock().unwrap().clone();
    let tail: Vec<&str> = selects
        .iter()
        .rev()
        .take(2)
        .map(|(_, body)| body.as_str())
        .collect();
    assert_eq!(
        tail,
        [
            format!(r#"{{"name":"{hk}"}}"#),
            format!(r#"{{"name":"{jp}"}}"#)
        ]
    );
    assert_eq!(api.fake.live().unwrap(), before, "the file is back");
    let (_, groups) = api.call("GET", "/api/v1/atom/groups/g-default", "");
    assert_eq!(groups["now"], hk.as_str());
}

/// The OpenAPI document of the atom API (`docs/api/openapi.yaml`).
const OPENAPI: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/api/openapi.yaml"
));

/// Whether a reply is a dispatcher's fallback (no handler owns the route)
/// rather than a handler's own answer.
fn fallback(status: u16, value: &Value) -> bool {
    matches!(
        (status, value["error"].as_str()),
        (404, Some("not found")) | (405, Some("method not allowed"))
    )
}

/// The document lists exactly the routes of `ROUTES`, each route reaches its
/// handler, every error is `{"error": string}`, a success status is one the
/// document gives, and a method a path does not list is 405.
#[test]
fn groups_and_final_move_in_the_display_order_without_a_reload() {
    let api = Api::new("group-move");
    let (_, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    let mut ids = Vec::new();
    for name in ["流媒体", "AI"] {
        let (status, created) = api.call(
            "POST",
            "/api/v1/atom/groups",
            &format!(r#"{{"name": "{name}", "type": "selector", "members": ["{hk}"]}}"#),
        );
        assert_eq!(status, 201, "{created}");
        ids.push(created["group"]["id"].as_str().unwrap().to_owned());
    }
    let (media, ai) = (ids[0].clone(), ids[1].clone());
    let (status, groups) = api.call("GET", "/api/v1/atom/groups", "");
    assert_eq!(status, 200);
    assert_eq!(groups["order"], serde_json::json!(["g-default", "final", media, ai]));

    let (file, reloads) = (api.fake.live(), api.fake.reload_count());
    let version = groups["version"].as_u64().unwrap();
    let (status, moved) = api.call(
        "POST",
        "/api/v1/atom/groups/move",
        &format!(r#"{{"id": "final", "after_id": "{ai}", "version": {version}}}"#),
    );
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["order"], serde_json::json!(["g-default", media, ai, "final"]));
    assert_eq!(moved["version"], version + 1);
    let names: Vec<&str> = moved["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["默认代理", "流媒体", "AI"]);
    assert_eq!(api.fake.live(), file, "the order is not in the sing-box file");
    assert_eq!(api.fake.reload_count(), reloads);

    let (status, moved) = api.call(
        "POST",
        "/api/v1/atom/groups/move",
        &format!(r#"{{"id": "{ai}", "before_id": "g-default"}}"#),
    );
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["order"], serde_json::json!([ai, "g-default", media, "final"]));
    api.reloads_from_disk().expect("the saved order loads");

    // Even when the running file is not the saved state's (a failed
    // compensation), a move applies nothing.
    let path = api.fake.host.config_path();
    let mut stale: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    stale["marker"] = "stale".into();
    std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
    let (file, reloads) = (api.fake.live(), api.fake.reload_count());
    let (status, moved) = api.call(
        "POST",
        "/api/v1/atom/groups/move",
        &format!(r#"{{"id": "final", "before_id": "{ai}"}}"#),
    );
    assert_eq!(status, 200, "{moved}");
    assert_eq!(moved["order"], serde_json::json!(["final", ai, "g-default", media]));
    assert_eq!((api.fake.live(), api.fake.reload_count()), (file, reloads));

    // A deleted group leaves the order; a new one goes last.
    let (status, _) = api.call("DELETE", &format!("/api/v1/atom/groups/{media}"), "");
    assert_eq!(status, 200);
    let (_, created) = api.call(
        "POST",
        "/api/v1/atom/groups",
        &format!(r#"{{"name": "新组", "type": "selector", "members": ["{hk}"]}}"#),
    );
    let new = created["group"]["id"].as_str().unwrap().to_owned();
    let (_, groups) = api.call("GET", "/api/v1/atom/groups", "");
    assert_eq!(groups["order"], serde_json::json!(["final", ai, "g-default", new]));

    for (body, want) in [
        (r#"{"id": "final"}"#.to_owned(), 400),
        (r#"{"id": "final", "before_id": "g-default", "after_id": "g-default"}"#.to_owned(), 400),
        (r#"{"id": "final", "before_id": "final"}"#.to_owned(), 400),
        (r#"{"id": "g-nope", "before_id": "final"}"#.to_owned(), 404),
        (r#"{"id": "final", "before_id": "g-default", "version": 1}"#.to_owned(), 409),
        (r#"{"id": "final", "before_id": "g-default", "extra": 1}"#.to_owned(), 400),
    ] {
        let (status, value) = api.call("POST", "/api/v1/atom/groups/move", &body);
        assert_eq!(status, want, "{body}: {value}");
        assert!(value["error"].is_string(), "{body}: {value}");
    }
}

#[test]
fn runtime_and_connections_come_from_the_clash_api() {
    let api = Api::new("runtime");
    let (status, value) = api.call("GET", "/api/v1/atom/runtime", "");
    assert_eq!(status, 409, "nothing applied yet: {value}");
    let (_, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    let jp = imported["nodes"][1]["id"].as_str().unwrap().to_owned();
    let (status, _) = api.call(
        "PUT",
        "/api/v1/atom/groups/g-default",
        &format!(r#"{{"name": "默认代理", "type": "selector", "members": ["{jp}", "{hk}"]}}"#),
    );
    assert_eq!(status, 200);

    let (status, runtime) = api.call("GET", "/api/v1/atom/runtime", "");
    assert_eq!(status, 200, "{runtime}");
    assert_eq!(runtime["groups"]["g-default"]["now"], jp.as_str());
    assert_eq!(runtime["groups"]["final"]["now"], "g-default");
    assert_eq!(runtime["nodes"][&hk]["delay"], 88);
    assert_eq!(runtime["nodes"][&hk]["time"], "2026-11-10T00:00:00Z");

    let (status, connections) = api.call("GET", "/api/v1/atom/connections", "");
    assert_eq!(status, 200, "{connections}");
    assert_eq!(connections["memory"], 30);
    assert_eq!(connections["connections"][0]["id"], "c-1");
    let (status, closed) = api.call("DELETE", "/api/v1/atom/connections/c-1", "");
    assert_eq!((status, &closed["closed"]), (200, &serde_json::json!("c-1")));
    let (status, closed) = api.call("DELETE", "/api/v1/atom/connections", "");
    assert_eq!((status, &closed["closed"]), (200, &Value::Null));
    let (status, _) = api.call("PUT", "/api/v1/atom/connections", "");
    assert_eq!(status, 405);
}

#[test]
fn system_reports_the_machine_and_both_programs() {
    let api = Api::new("system");
    let (status, system) = api.call("GET", "/api/v1/atom/system", "");
    assert_eq!(status, 200, "{system}");
    for key in ["cpu", "memory", "load", "uptime_seconds", "atomdns", "singbox"] {
        assert!(system.get(key).is_some(), "{key}: {system}");
    }
    if cfg!(target_os = "linux") {
        assert!(system["cpu"]["cores"].as_u64().unwrap() >= 1);
        assert!(system["cpu"]["total_seconds"].as_f64().unwrap() >= system["cpu"]["busy_seconds"].as_f64().unwrap());
        assert!(system["memory"]["total_bytes"].as_u64().unwrap() > 0);
        assert_eq!(system["atomdns"]["pid"], std::process::id());
        assert!(system["atomdns"]["resident_bytes"].as_u64().unwrap() > 0);
    }
    let (status, _) = api.call("POST", "/api/v1/atom/system", "");
    assert_eq!(status, 405);

    let (status, with_history) = api.call("GET", "/api/v1/atom/system?history=1&window=15m", "");
    assert_eq!(status, 200, "{with_history}");
    assert!(with_history.get("rates").is_some(), "{with_history}");
    assert!(with_history.get("traffic").is_some(), "{with_history}");
    assert!(with_history["history"]["system"].is_array(), "{with_history}");
    assert_eq!(with_history["history"]["traffic"]["window"], "15m");
    assert_eq!(with_history["history"]["traffic"]["step_seconds"], 15);
    assert!(with_history["history"]["traffic"]["points"].is_array());

    let (status, bad_window) = api.call("GET", "/api/v1/atom/system?history=1&window=2h", "");
    assert_eq!(status, 400, "{bad_window}");
}

#[test]
fn the_openapi_document_matches_the_routes() {
    let spec: Value = yaml_serde::from_str(OPENAPI).expect("openapi.yaml parses");
    assert!(spec["openapi"].as_str().unwrap().starts_with("3."));
    assert_eq!(spec["servers"][0]["url"], "/api/v1/atom");
    let paths = spec["paths"].as_object().expect("paths");
    let mut documented = std::collections::BTreeSet::new();
    for (path, item) in paths {
        for method in ["get", "post", "put", "delete", "patch"] {
            if item.get(method).is_some() {
                let path = path.strip_prefix('/').expect("a path starts with /");
                documented.insert((method.to_ascii_uppercase(), path.to_owned()));
            }
        }
    }
    let routes: std::collections::BTreeSet<(String, String)> = crate::atom_rules_api::ROUTES
        .iter()
        .map(|(method, path)| ((*method).to_owned(), (*path).to_owned()))
        .collect();
    assert_eq!(documented, routes, "openapi.yaml and ROUTES differ");

    let api = Api::new("openapi");
    let concrete = |path: &str| {
        path.replace("{id}", "x-none")
            .replace("{tag}", "domestic")
            .replace("{key}", "no_v6")
    };
    for (method, path) in &routes {
        if path.starts_with("audit/") {
            // AtomDNS's audit API: `api.rs` serves it (tested there).
            assert!(
                crate::api::routes_to_audit(&format!("/api/v1/atom/{path}")),
                "{method} {path} reaches no audit handler"
            );
            continue;
        }
        if path == "auth" || path.starts_with("auth/") {
            // The panel login: `api.rs` serves it before dispatch (`panel_auth`, tested there).
            continue;
        }
        if path == "maintenance" || path.starts_with("maintenance/") {
            assert!(
                crate::atom_maintenance::route(method, &format!("/api/v1/atom/{path}")).is_some(),
                "{method} {path} reaches no maintenance handler"
            );
            continue;
        }
        let (status, value) = api.call(method, &format!("/api/v1/atom/{}", concrete(path)), "{}");
        assert!(
            !fallback(status, &value),
            "{method} {path} has no handler: {status} {value}"
        );
        if status >= 400 {
            assert!(
                value["error"].is_string(),
                "{method} {path}: an error body is {{\"error\": string}}: {value}"
            );
        } else {
            let responses = &paths[&format!("/{path}")][method.to_ascii_lowercase()]["responses"];
            assert!(
                responses.get(status.to_string()).is_some(),
                "{method} {path}: {status} is not documented"
            );
        }
    }
    for path in paths.keys() {
        let path = path.strip_prefix('/').unwrap();
        if path.starts_with("audit/")
            || path == "auth"
            || path.starts_with("auth/")
            || path == "maintenance"
            || path.starts_with("maintenance/")
        {
            continue;
        }
        let (status, value) = api.call("PATCH", &format!("/api/v1/atom/{}", concrete(path)), "{}");
        assert_eq!(
            (status, value["error"].as_str()),
            (405, Some("method not allowed")),
            "PATCH {path}"
        );
    }
    let (status, value) = api.call("GET", "/api/v1/atom/nothing-here", "");
    assert_eq!((status, value["error"].is_string()), (404, true));
    // The audit root itself is no audit route: the atom API's JSON 404.
    let (status, value) = api.call("GET", "/api/v1/atom/audit", "");
    assert_eq!((status, value["error"].is_string()), (404, true));
}

/// A rule takes a ruleset's names (`ruleset`) and its IP prefixes
/// (`ip_ruleset`) in one rule (atom step 6b). A download that brings new
/// prefixes is saved and sing-box follows it (trigger `rulesets`); a set
/// that `ip_ruleset` names cannot be deleted.
#[test]
fn a_ruleset_ip_part_reaches_sing_box_when_downloaded() {
    let api = Api::new("ip-ruleset");
    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/rulesets",
        r#"{"name": "Telegram", "type": "remote", "url": "http://127.0.0.1:9/Telegram.list"}"#,
    );
    assert_eq!(status, 502, "created, first download failed: {created}");
    let id = created["id"].as_str().unwrap().to_owned();
    let (status, rule) = api.call(
        "POST",
        "/api/v1/atom/rules",
        &format!(r#"{{"match": {{"ruleset": ["{id}"], "ip_ruleset": ["{id}"]}}, "action": {{"type": "proxy", "group_id": "final"}}}}"#),
    );
    assert_eq!(status, 201, "{rule}");
    let reloads = api.fake.reload_count();

    let rules = api.assembly.config().local.atom_rules.clone().unwrap();
    let before = rules.current_ip_rules();
    let set = rules.ruleset(&id).unwrap();
    let converted = crate::atom_rules::convert_download(
        b"DOMAIN-SUFFIX,t.me\nIP-CIDR,91.108.4.1/22,no-resolve\nIP-CIDR6,2001:b28:f23d::/48\nIP-ASN,62041\nPROCESS-NAME,Telegram\n",
        "auto",
        "",
        "Telegram.list",
    );
    let stored = rules
        .store_download(&id, &set.source, rules.begin_download(&id), converted)
        .unwrap();
    assert_eq!((stored.rule_count, stored.ip_count), (1, 2));
    assert_eq!(stored.skipped.values().sum::<u64>(), 2, "{:?}", stored.skipped);
    api.assembly
        .block_on(rules.follow_ip_rules(&before))
        .unwrap();
    assert_eq!(api.fake.reload_count(), reloads + 1, "sing-box followed the prefixes");
    let routes = api.live()["route"]["rules"].clone();
    assert!(
        routes.as_array().unwrap().iter().any(|rule| rule["rules"][1]
            == serde_json::json!({"ip_cidr": ["91.108.4.0/22", "2001:b28:f23d::/48"]})
            && rule["outbound"] == "final"),
        "{routes}"
    );
    let (_, apply) = api.call("GET", "/api/v1/atom/apply", "");
    assert_eq!(apply["last_apply"]["trigger"], "rulesets", "{apply}");
    // The same prefixes again: nothing to apply.
    api.assembly
        .block_on(rules.follow_ip_rules(&rules.current_ip_rules()))
        .unwrap();
    assert_eq!(api.fake.reload_count(), reloads + 1);

    let (status, refused) = api.call("DELETE", &format!("/api/v1/atom/rulesets/{id}"), "");
    assert_eq!(status, 409, "{refused}");
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules",
        &format!(r#"{{"match": {{"ip_ruleset": ["{id}"], "client": ["192.168.1.2"]}}, "action": {{"type": "direct"}}}}"#),
    );
    assert_eq!(status, 400, "{refused}");
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"ip_ruleset": ["rs-nope"]}, "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 400, "{refused}");
}

/// The catalog: listing and search; a rule that names an entry uses its
/// managed ruleset; such a set cannot be edited or created by hand, and it
/// goes with the last rule naming it (atom step 6b).
#[test]
fn catalog_entries_become_managed_rulesets_while_rules_name_them() {
    let api = Api::new("catalog");
    let rules = api.assembly.config().local.atom_rules.clone().unwrap();
    rules.set_catalog(crate::atom_catalog::Catalog {
        updated_at: 7,
        meta: crate::atom_catalog::Meta {
            geosite: vec!["netflix".into()],
            geoip: vec!["netflix".into(), "telegram".into()],
        },
        bm7: vec!["Telegram".into()],
    });
    let (status, listed) = api.call("GET", "/api/v1/atom/catalog?q=TELE", "");
    assert_eq!(status, 200, "{listed}");
    assert_eq!((&listed["size"], &listed["total"]), (&serde_json::json!(3), &serde_json::json!(2)));
    let ids: Vec<&str> = listed["entries"].as_array().unwrap().iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["meta:telegram", "bm7:Telegram"]);
    assert_eq!(listed["entries"][0]["names"], false);
    assert_eq!(api.call("GET", "/api/v1/atom/catalog?limit=0", "").0, 400);
    assert_eq!(api.call("GET", "/api/v1/atom/catalog?nope=1", "").0, 400);

    // Not in the catalog: 400, nothing created.
    let (status, value) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"ruleset": ["bm7:Nope"]}, "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 400, "{value}");
    assert!(rules.ruleset("bm7:Nope").is_none());

    // An entry already downloaded is used as it is.
    let set = rules.create_catalog_ruleset("bm7:Telegram").unwrap();
    assert_eq!(set.name, "blackmatrix7 · Telegram");
    let converted = crate::atom_rules::convert_download(b"DOMAIN-SUFFIX,t.me\n", "text", "", "x.list");
    rules
        .store_download(&set.id, &set.source, rules.begin_download(&set.id), converted)
        .unwrap();
    let (status, created) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"ruleset": ["bm7:Telegram"]}, "action": {"type": "block"}}"#,
    );
    assert_eq!(status, 201, "{created}");
    let rule = created["rule"]["id"].as_str().unwrap().to_owned();
    let (_, listed) = api.call("GET", "/api/v1/atom/catalog?q=Telegram", "");
    assert_eq!(listed["entries"][1]["ruleset"]["rule_count"], 1, "{listed}");
    assert_eq!(
        api.call("PUT", "/api/v1/atom/rulesets/bm7:Telegram", r#"{"name": "x"}"#).0,
        400
    );
    assert_eq!(
        api.call("POST", "/api/v1/atom/rulesets", r#"{"name": "x", "type": "catalog"}"#).0,
        400
    );
    assert_eq!(
        api.call("DELETE", "/api/v1/atom/rulesets/bm7:Telegram", "").0,
        409,
        "in use"
    );
    // The UI sends the ID percent-encoded (`encodeURIComponent`).
    let (status, shown) = api.call("GET", "/api/v1/atom/rulesets/bm7%3ATelegram", "");
    assert_eq!((status, &shown["id"]), (200, &serde_json::json!("bm7:Telegram")), "{shown}");
    assert_eq!(
        api.call("PUT", "/api/v1/atom/rulesets/bm7%3ATelegram", r#"{"name": "x"}"#).0,
        400
    );
    assert_eq!(api.call("DELETE", "/api/v1/atom/rulesets/bm7%3ATelegram", "").0, 409);
    assert_eq!(api.call("GET", "/api/v1/atom/rulesets/bm7%3ANope", "").0, 404);
    let (status, _) = api.call("DELETE", &format!("/api/v1/atom/rules/{rule}"), "");
    assert_eq!(status, 200);
    assert!(rules.ruleset("bm7:Telegram").is_none(), "the last rule took its set along");

    // A set another request is initializing (pinned) survives the cleanup
    // after an unrelated rule write (codex review of step 6b-2b, round 1).
    let pinned = vec!["meta:netflix".to_owned()];
    rules.create_catalog_ruleset("meta:netflix").unwrap();
    rules.pin_catalog(&pinned);
    let (status, other) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["x.example"]}, "action": {"type": "block"}}"#,
    );
    assert_eq!(status, 201, "{other}");
    assert!(rules.ruleset("meta:netflix").is_some(), "pinned: kept");
    rules.unpin_catalog(&pinned);
    let other = other["rule"]["id"].as_str().unwrap().to_owned();
    assert_eq!(api.call("DELETE", &format!("/api/v1/atom/rules/{other}"), "").0, 200);
    assert!(rules.ruleset("meta:netflix").is_none(), "unpinned and unused: gone");
}

#[test]
fn provider_definitions_remain_private_and_singbox_refuses_mihomo_groups() {
    let mut api = Api::new("providers");
    let (status, provider) = api.call(
        "POST",
        "/api/v1/atom/providers",
        r#"{"name":"机场","url":"https://example.test/sub?token=private-token","interval":600}"#,
    );
    assert_eq!(status, 201, "{provider}");
    let id = provider["provider"]["id"].as_str().unwrap();
    assert!(id.starts_with("p-"));
    assert!(!provider.to_string().contains("private-token"));
    let (status, _) = api.call(
        "POST", "/api/v1/atom/providers",
        &format!(r#"{{"name":"Loop","url":"https://example.test/sub","download_via":"{id}"}}"#),
    );
    assert_eq!(status, 400);
    let path = format!("/api/v1/atom/providers/{id}");
    let (status, changed) = api.call("PUT", &path, r#"{"name":"改名","interval":900}"#);
    assert_eq!(status, 200, "{changed}");
    assert!(crate::atom_proxy::load(&api.root, &[], None).unwrap().providers[0].settings.url.contains("private-token"));
    assert_eq!(api.call("POST", &format!("{path}/refresh"), "{}").0, 409);
    // sing-box has no fallback or load-balance group: refused, not degraded.
    for kind in ["fallback", "load-balance"] {
        let (status, refused) = api.call(
            "POST",
            "/api/v1/atom/groups",
            &format!(r#"{{"name":"Failover","type":"{kind}","providers":["{id}"]}}"#),
        );
        assert_eq!(status, 400, "{refused}");
    }
    let (status, group) = api.call(
        "POST",
        "/api/v1/atom/groups",
        &format!(r#"{{"name":"Auto","type":"urltest","providers":["{id}"],"all_providers":false}}"#),
    );
    assert_eq!(status, 201, "{group}");
    let group_id = group["group"]["id"].as_str().unwrap();
    assert_eq!(group["group"]["empty"], true);
    assert_eq!(api.outbound(group_id)["type"], "urltest");
    assert_eq!(api.outbound(group_id)["outbounds"], serde_json::json!(["block"]));
    assert_eq!(api.call("DELETE", &path, "").0, 409);
    api.restart();
    let (_, settings) = api.call("GET", "/api/v1/atom/settings", "");
    assert_eq!(settings["warnings"]["inactive_providers"][0], id);
    assert_eq!(api.call("DELETE", &format!("/api/v1/atom/groups/{group_id}"), "").0, 200);
    assert_eq!(api.call("DELETE", &path, "").0, 200);
}

#[test]
fn backend_check_lists_nodes_mihomo_cannot_run_and_the_switch_needs_confirmation() {
    let api = Api::new("backend-check");
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/nodes",
        r#"{"format":"json","content":[{"type":"naive","tag":"N","server":"n.example","server_port":443,"username":"u","password":"p"},{"type":"trojan","tag":"T","server":"t.example","server_port":443,"password":"p","tls":{"enabled":true}}]}"#,
    );
    assert_eq!(status, 201);
    let (_, nodes) = api.call("GET", "/api/v1/atom/nodes", "");
    assert_eq!(nodes["nodes"][0]["active"], true);
    let (status, check) = api.call("GET", "/api/v1/atom/settings/backend-check?target=mihomo", "");
    assert_eq!(status, 200, "{check}");
    assert_eq!(check["inactive_nodes"].as_array().unwrap().len(), 1);
    assert_eq!(check["inactive_nodes"][0]["name"], "N");
    assert!(check["inactive_nodes"][0]["reason"].as_str().unwrap().contains("naive"));
    assert_eq!(check["provider_count"], 0);
    let (_, check) = api.call("GET", "/api/v1/atom/settings/backend-check?target=sing-box", "");
    assert_eq!(check["inactive_nodes"], serde_json::json!([]));
    assert_eq!(api.call("GET", "/api/v1/atom/settings/backend-check?target=x", "").0, 400);

    // Without the confirmation nothing changes and the nodes come back.
    let (status, refused) = api.call("PUT", "/api/v1/atom/settings", r#"{"backend":"mihomo"}"#);
    assert_eq!(status, 409, "{refused}");
    assert_eq!(refused["nodes"][0]["name"], "N");
    // group_actions belong to the switch to sing-box.
    let (status, _) = api.call(
        "PUT",
        "/api/v1/atom/settings",
        r#"{"backend":"mihomo","group_actions":{}}"#,
    );
    assert_eq!(status, 400);
    let (_, settings) = api.call("GET", "/api/v1/atom/settings", "");
    assert_eq!(settings["backend"], "sing-box");
}

#[test]
fn backend_check_allows_ss_interface_and_keeps_native_mihomo_nodes() {
    let mut api = Api::new("native-proxies");
    let (status, imported) = api.call("POST", "/api/v1/atom/nodes", r#"{
        "format":"json", "content":{"tag":"Bound SS","type":"shadowsocks","server":"ss.example",
        "server_port":443,"method":"aes-128-gcm","password":"dummy","bind_interface":"lo"}
    }"#);
    assert_eq!(status, 201, "{imported}");
    let id = imported["nodes"][0]["id"].as_str().unwrap();
    let (status, yaml) = api.call("GET", &format!("/api/v1/atom/nodes/{id}/export?format=yaml"), "");
    assert_eq!(status, 200, "{yaml}");
    assert!(yaml["content"].as_str().unwrap().contains("interface-name: lo"));
    let body = serde_json::json!({"format":"yaml", "content":yaml["content"]});
    let (status, saved) = api.call("PUT", &format!("/api/v1/atom/nodes/{id}"), &body.to_string());
    assert_eq!(status, 200, "{saved}");
    assert_eq!(api.outbound(id)["bind_interface"], "lo");

    let (status, native) = api.call("POST", "/api/v1/atom/nodes", r#"{
        "format":"yaml", "content":"{name: TLS SOCKS, type: socks5, server: socks.example, port: 443, tls: true}"
    }"#);
    assert_eq!(status, 201, "{native}");
    let native_id = native["nodes"][0]["id"].as_str().unwrap();
    assert_eq!(native["nodes"][0]["active"], false);
    assert_eq!(native["nodes"][0]["server_port"], 443);
    api.restart();
    let (status, yaml) = api.call("GET", &format!("/api/v1/atom/nodes/{native_id}/export"), "");
    assert_eq!(status, 200, "{yaml}");
    assert_eq!(yaml["format"], "yaml");
    assert!(yaml["content"].as_str().unwrap().contains("tls: true"));

    let (_, check) = api.call("GET", "/api/v1/atom/settings/backend-check?target=mihomo", "");
    assert_eq!(check["inactive_nodes"], serde_json::json!([]));
    let (_, check) = api.call("GET", "/api/v1/atom/settings/backend-check?target=sing-box", "");
    assert_eq!(check["inactive_nodes"].as_array().unwrap().len(), 1);
    assert_eq!(check["inactive_nodes"][0]["id"], native_id);
    assert!(check["inactive_nodes"][0]["reason"].as_str().unwrap().contains("TLS"));
}

#[test]
fn a_shadowtls_pair_is_saved_edited_and_exported_as_one_node() {
    use serde_json::json;
    let mut api = Api::new("shadowtls-pair");
    let pair = crate::atom_singbox::tests::shadowtls_pair();
    let body = |content: Value| json!({"format":"json","content":content}).to_string();
    let (status, missing) = api.call("POST", "/api/v1/atom/nodes", &body(pair[0].clone()));
    assert_eq!(status, 400, "{missing}");
    assert!(missing["error"].as_str().unwrap().contains("一起导入"));
    let duplicated = json!([pair[0], pair[1], pair[1]]);
    assert_eq!(api.call("POST", "/api/v1/atom/nodes", &body(duplicated)).0, 400);

    let (status, added) = api.call("POST", "/api/v1/atom/nodes", &body(pair));
    assert_eq!(status, 201, "{added}");
    assert_eq!(added["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(added["nodes"][0]["server"], "127.0.0.1");
    let id = added["nodes"][0]["id"].as_str().unwrap();
    let shadowtls_tag = format!("{id}-shadowtls");
    assert_eq!(api.outbound(id)["detour"], shadowtls_tag);
    assert_eq!(api.outbound(&shadowtls_tag)["type"], "shadowtls");
    assert_eq!(api.call("GET", "/api/v1/atom/settings/backend-check?target=mihomo", "").1["inactive_nodes"], json!([]));

    api.restart();
    for format in ["json", "yaml"] {
        let (status, exported) = api.call("GET", &format!("/api/v1/atom/nodes/{id}/export?format={format}"), "");
        assert_eq!(status, 200, "{exported}");
        if format == "json" {
            let entries: Value = serde_json::from_str(exported["content"].as_str().unwrap()).unwrap();
            assert_eq!(entries[0]["detour"], entries[1]["tag"]);
        }
        let (status, edited) = api.call("PUT", &format!("/api/v1/atom/nodes/{id}"), &exported.to_string());
        assert_eq!(status, 200, "{edited}");
        assert_eq!(api.outbound(id)["detour"], shadowtls_tag);
        assert_eq!(api.outbound(&shadowtls_tag)["tls"]["utls"]["fingerprint"], "chrome");
    }
    let (status, _) = api.call("DELETE", &format!("/api/v1/atom/nodes/{id}"), "");
    assert_eq!(status, 200);
    assert!(api.outbound(&shadowtls_tag).is_null());
}

#[test]
fn imports_pasted_inline_clash_nodes_with_misaligned_dashes() {
    use serde_json::json;
    let api = Api::new("inline-clash-paste");
    let pasted = r#"  - {name: first, type: ss, server: ss.test, port: 443, cipher: aes-128-gcm, password: '  first:#  '}
  - {name: second, type: trojan, server: trojan.test, port: 443, password: 'second:#', sni: tls.test}
"#;
    // The previous import form trimmed the clipboard text before submitting it.
    let misaligned = pasted.trim();
    assert!(yaml_serde::from_str::<Value>(misaligned).is_err());
    let body = |content: &str| json!({"format":"yaml","content":content}).to_string();
    let malformed = format!("{misaligned}\n - {{name: broken");
    let (status, refused) = api.call("POST", "/api/v1/atom/nodes", &body(&malformed));
    assert_eq!(status, 400, "{refused}");
    assert_eq!(api.call("GET", "/api/v1/atom/nodes", "").1["nodes"], json!([]));

    let (status, imported) = api.call("POST", "/api/v1/atom/nodes", &body(misaligned));
    assert_eq!(status, 201, "{imported}");
    let nodes = imported["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0]["name"], "first");
    assert_eq!(nodes[0]["outbound"]["password"], "  first:#  ");
    assert_eq!(nodes[1]["name"], "second");
    assert_eq!(nodes[1]["outbound"]["tls"]["server_name"], "tls.test");
}

#[test]
fn mihomo_statistics_warn_without_disabling_nodes_and_keep_native_yaml() {
    use serde_json::json;
    let api = Api::new("mihomo-statistics");
    let fingerprint = "01:".repeat(31) + "01";
    let content = json!({"name":"Stats", "type":"trojan", "server":"trojan.test", "port":443, "password":"test",
        "fingerprint":fingerprint, "smux":{"enabled":true,"protocol":"h2mux","statistic":true}});
    let body = json!({"format":"yaml", "content":content.to_string()});
    let (status, added) = api.call("POST", "/api/v1/atom/nodes", &body.to_string());
    assert_eq!(status, 201, "{added}");
    assert_eq!(added["nodes"][0]["active"], true);
    let id = added["nodes"][0]["id"].as_str().unwrap();
    let outbound = api.outbound(id);
    assert_eq!(outbound["tls"]["certificate_fingerprint"], fingerprint);
    assert_eq!(outbound["multiplex"]["enabled"], true);
    let (status, exported) = api.call("GET", &format!("/api/v1/atom/nodes/{id}/export?format=yaml"), "");
    assert_eq!(status, 200, "{exported}");
    assert!(exported["content"].as_str().unwrap().contains("statistic: true"));
    let (_, to_sb) = api.call("GET", "/api/v1/atom/settings/backend-check?target=sing-box", "");
    assert_eq!(to_sb["inactive_nodes"], json!([]));
    assert_eq!(to_sb["statistics_warnings"][0]["id"], id);
    let (_, to_mihomo) = api.call("GET", "/api/v1/atom/settings/backend-check?target=mihomo", "");
    assert_eq!(to_mihomo["inactive_nodes"], json!([]));
    assert_eq!(to_mihomo["statistics_warnings"], json!([]));
}

/// `POST nodes/delete` deletes several nodes with one sing-box reload; when
/// any ID is refused nothing changes and every refused ID is listed.
#[test]
fn a_batch_deletion_is_all_or_none() {
    let api = Api::new("batch-delete");
    let (status, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    assert_eq!(status, 201, "{imported}");
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    let jp = imported["nodes"][1]["id"].as_str().unwrap().to_owned();
    let (status, provider) = api.call(
        "POST",
        "/api/v1/atom/providers",
        &format!(r#"{{"name":"机场","url":"https://example.test/sub","download_via":"{hk}"}}"#),
    );
    assert_eq!(status, 201, "{provider}");
    let provider_id = provider["provider"]["id"].as_str().unwrap().to_owned();

    for body in [r#"{"ids": []}"#.to_owned(), format!(r#"{{"ids": ["{jp}", "{jp}"]}}"#), "{}".to_owned()] {
        let (status, refused) = api.call("POST", "/api/v1/atom/nodes/delete", &body);
        assert_eq!(status, 400, "{body}: {refused}");
    }
    let (_, before) = api.call("GET", "/api/v1/atom/nodes", "");
    let (file, reloads) = (api.fake.live(), api.fake.reload_count());
    // A node still used to download a subscription: nothing is deleted.
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/nodes/delete",
        &format!(r#"{{"ids": ["{jp}", "{hk}", "n-missing"]}}"#),
    );
    assert_eq!(status, 409, "{refused}");
    let failed: Vec<&str> = refused["failed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert_eq!(failed, [hk.as_str(), "n-missing"]);
    assert!(refused["error"].as_str().unwrap().contains(&hk));
    let (status, missing) = api.call(
        "POST",
        "/api/v1/atom/nodes/delete",
        &format!(r#"{{"ids": ["{jp}", "n-missing"]}}"#),
    );
    assert_eq!(status, 404, "{missing}");
    let (_, after) = api.call("GET", "/api/v1/atom/nodes", "");
    assert_eq!(after, before, "state unchanged");
    assert_eq!((api.fake.live(), api.fake.reload_count()), (file, reloads));
    // A stale version is refused like every write.
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/nodes/delete",
        &format!(r#"{{"ids": ["{jp}"], "version": 0}}"#),
    );
    assert_eq!(status, 409);

    let (status, _) = api.call("DELETE", &format!("/api/v1/atom/providers/{provider_id}"), "");
    assert_eq!(status, 200);
    let (_, listed) = api.call("GET", "/api/v1/atom/nodes", "");
    let version = listed["version"].as_u64().unwrap();
    let reloads = api.fake.reload_count();
    let (status, deleted) = api.call(
        "POST",
        "/api/v1/atom/nodes/delete",
        &format!(r#"{{"ids": ["{hk}", "{jp}"], "version": {version}}}"#),
    );
    assert_eq!(status, 200, "{deleted}");
    assert_eq!(deleted["version"], version + 1);
    assert_eq!(deleted["deleted"], serde_json::json!([hk, jp]));
    assert_eq!(api.fake.reload_count(), reloads + 1, "one reload");
    let (_, listed) = api.call("GET", "/api/v1/atom/nodes", "");
    assert_eq!(listed["nodes"], serde_json::json!([]));
}
