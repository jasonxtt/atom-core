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

    // An IP rule becomes a sing-box route rule; mixing it with names is 400.
    let (status, refused) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"ip_cidr": ["91.108.4.0/22"], "suffix": ["t.me"]}, "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 400);
    assert!(
        refused["error"].as_str().unwrap().contains("单独"),
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
        routes[2],
        serde_json::json!({"ip_cidr": ["91.108.4.0/22", "2001:b28:f23d::/48"], "action": "route", "outbound": media})
    );
    let (_, status_view) = api.call("GET", "/api/v1/atom/status", "");
    assert_eq!(status_view["singbox"]["in_sync"], true, "{status_view}");
    assert_eq!(status_view["singbox"]["version"], "sing-box 1.14.4-atom");
    assert_eq!(
        status_view["nft"]["ip_cidr"]["inet4"],
        serde_json::json!(["91.108.4.0/22"])
    );
    assert_eq!(status_view["nft"]["fakeip_range"], "28.0.0.0/8");
    // The nft sets follow the IP rules (IPv4 only), in one script.
    let scripts = api.fake.nft_scripts();
    assert!(
        scripts
            .last()
            .unwrap()
            .contains("add element inet atom iprule4 { 91.108.4.0/22 }\n"),
        "{scripts:?}"
    );
    assert_eq!(status_view["nft"]["table"], "atom");
    assert_eq!(status_view["nft"]["sync"]["ok"], true, "{status_view}");
    assert_eq!(
        status_view["nft"]["sync"]["sets"]["iprule4"],
        serde_json::json!(["91.108.4.0/22"])
    );
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
fn a_failed_nft_update_keeps_the_change_and_is_reported() {
    let api = Api::new("nft");
    let before = api.fake.nft_scripts().len();
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"suffix": ["example.com"]}, "action": {"type": "direct"}}"#,
    );
    assert_eq!(status, 201);
    assert_eq!(
        api.fake.nft_scripts().len(),
        before,
        "domain rules leave nft alone"
    );
    std::fs::write(api.fake.host.dir.join("nftfail"), "").unwrap();
    let (status, rule) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"ip_cidr": ["1.1.1.1/32"]}, "action": {"type": "block"}}"#,
    );
    assert_eq!(status, 201, "{rule}");
    let (_, view) = api.call("GET", "/api/v1/atom/status", "");
    assert_eq!(view["nft"]["sync"]["ok"], false, "{view}");
    assert!(
        view["nft"]["sync"]["error"]
            .as_str()
            .unwrap()
            .contains("No such file")
    );
    assert_eq!(
        api.live()["route"]["rules"][2]["ip_cidr"],
        serde_json::json!(["1.1.1.1/32"])
    );
    std::fs::remove_file(api.fake.host.dir.join("nftfail")).unwrap();
    let (status, _) = api.call("POST", "/api/v1/atom/apply", "");
    assert_eq!(status, 200);
    let (_, view) = api.call("GET", "/api/v1/atom/status", "");
    assert_eq!(view["nft"]["sync"]["ok"], true, "{view}");
    assert!(
        api.fake
            .nft_scripts()
            .last()
            .unwrap()
            .contains("add element inet atom iprule4 { 1.1.1.1/32 }")
    );
}

/// A start whose application fails (rolled back) fills nft from what
/// sing-box runs, not from the atom state it could not apply.
#[test]
fn a_failed_startup_application_keeps_nft_on_the_running_configuration() {
    let api = Api::new("nft-startup");
    let (status, _) = api.call(
        "POST",
        "/api/v1/atom/rules",
        r#"{"match": {"ip_cidr": ["1.1.1.1/32"]}, "action": {"type": "block"}}"#,
    );
    assert_eq!(status, 201);
    // sing-box runs something else (an older range and IP rule) than the state.
    let mut running = api.live();
    running["dns"]["servers"][0]["inet4_range"] = "29.0.0.0/8".into();
    running["route"]["rules"][2]["ip_cidr"] = serde_json::json!(["9.9.9.9/32"]);
    let bytes = serde_json::to_vec(&running).unwrap();
    std::fs::write(api.fake.host.config_path(), &bytes).unwrap();
    std::fs::write(api.fake.host.dir.join("running.json"), &bytes).unwrap();
    std::fs::write(api.fake.host.dir.join("failreload"), "").unwrap();
    let rules = api.assembly.config().local.atom_rules.clone().unwrap();
    api.assembly.block_on(rules.ensure());
    let last = crate::atom_rules::last_apply().unwrap();
    assert!(!last.ok, "{last:?}");
    let script = api.fake.nft_scripts().pop().unwrap();
    assert!(
        script.contains("fakeip4 { 29.0.0.0/8 }") && script.contains("iprule4 { 9.9.9.9/32 }"),
        "{script}"
    );
    // Once sing-box takes the state, nft follows.
    std::fs::remove_file(api.fake.host.dir.join("failreload")).unwrap();
    let (status, _) = api.call("POST", "/api/v1/atom/apply", "");
    assert_eq!(status, 200);
    let script = api.fake.nft_scripts().pop().unwrap();
    assert!(
        script.contains("fakeip4 { 28.0.0.0/8 }") && script.contains("iprule4 { 1.1.1.1/32 }"),
        "{script}"
    );
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
    let (status, applied) = api.call("PUT", "/api/v1/atom/settings", r#"{"mixed_port": 17890}"#);
    assert_eq!(status, 200, "{applied}");
    assert_eq!(api.live()["inbounds"][3]["listen_port"], 17890);
    let (status, reapplied) = api.call("POST", "/api/v1/atom/apply", "");
    assert_eq!(status, 200, "{reapplied}");
    assert_eq!(reapplied["last_apply"]["trigger"], "apply");
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
fn node_views_hide_credentials_and_edits_replace_the_connection() {
    let api = Api::new("credentials");
    let (status, imported) = api.call("POST", "/api/v1/atom/nodes", TWO_LINKS);
    assert_eq!(status, 201);
    let hk = imported["nodes"][0]["id"].as_str().unwrap().to_owned();
    assert!(
        imported["nodes"][0]["outbound"].get("password").is_none(),
        "{imported}"
    );
    let (_, listed) = api.call("GET", "/api/v1/atom/nodes", "");
    assert!(!listed.to_string().contains("\"password\""), "{listed}");
    let (_, one) = api.call("GET", &format!("/api/v1/atom/nodes/{hk}"), "");
    assert_eq!(one["outbound"]["server"], "hk.example");
    assert!(one["outbound"].get("password").is_none());
    // The file sing-box runs still has the credentials.
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

fn fail_next_save() {
    crate::atom_proxy::FAIL_NEXT_SAVE.with(|fail| fail.set(true));
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
    let api = Api::new("delete-order");
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
