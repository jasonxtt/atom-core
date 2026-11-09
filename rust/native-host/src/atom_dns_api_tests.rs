//! Tests of `atom_dns_api`: `dns`, `upstreams` (custom groups included), `rewrite`.

use atomdns_upstream_core::TransportCancellation;
use serde_json::{Value, json};

struct Host {
    root: std::path::PathBuf,
    host: crate::HostAssembly,
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Host {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("atom-dns-api-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("webinfo")).unwrap();
        std::fs::create_dir_all(root.join("rule")).unwrap();
        std::fs::write(
            root.join("rule/rewrite.txt"),
            "full:nas.example 192.0.2.9\n",
        )
        .unwrap();
        let (dns, api) = (free_port(), free_port());
        let flag = |tag: &str, default: bool| {
            format!(
                "  - tag: {tag}\n    type: feature_flag\n    args: {{label: {tag}, description: test, section: mode, kind: bool, default: {default}}}\n"
            )
        };
        let mut yaml = format!(
            "log: {{level: error}}\napi: {{http: '127.0.0.1:{api}'}}\nplugins:\n  - tag: core_mode\n    type: feature_flag\n    args:\n      label: core\n      description: test\n      section: mode\n      kind: choice\n      options: [{{value: compat, label: c}}, {{value: safe, label: s}}]\n      default: compat\n"
        );
        for (tag, default) in [
            ("block_qtypes", true),
            ("block_aaaa", false),
            ("prefer_v4", false),
            ("full_cache", true),
            ("lazy_cache", true),
        ] {
            yaml.push_str(&flag(tag, default));
        }
        yaml.push_str(
            "  - tag: client_ecs\n    type: ecs_address\n    args: {addr: '2408:8888::8'}\n  - tag: domestic\n    type: aliapi\n    args: {upstreams: [{tag: one, addr: 'udp://127.0.0.1:15998'}]}\n  - tag: nocnfake\n    type: aliapi\n    args: {upstreams: [{tag: fake, addr: 'udp://127.0.0.1:6666'}]}\n  - tag: cache_atom\n    type: cache\n    args: {size: 64}\n  - tag: rewrite\n    type: rewrite\n    args: {files: [rule/rewrite.txt], dns: 'udp://127.0.0.1:15998'}\n  - tag: atom_rules\n    type: atom_rules\n    args: {marks: {proxy: 41, direct: 42, block: 40, route: 43}}\n  - tag: entry\n    type: sequence\n    args: [{exec: $rewrite}, {exec: $atom_rules}, {matches: fast_mark 43, exec: [$atom_direct, exit]}, {exec: $domestic}]\n",
        );
        yaml.push_str(&format!(
            "  - tag: main\n    type: udp_server\n    args: {{entry: entry, listen: '127.0.0.1:{dns}'}}\n"
        ));
        let path = root.join("config.yaml");
        std::fs::write(&path, yaml).unwrap();
        let host = crate::HostAssembly::from_config_file_in(&path, None).expect("config");
        Self { root, host }
    }

    fn call(&self, method: &str, path: &str, body: &Value) -> (u16, Value) {
        let control = self.host.control();
        let body = body.to_string();
        self.host.block_on(async {
            let view = control.view();
            let reply = crate::atom_rules_api::handle(
                Some(&control),
                &view.config,
                &view.cache,
                method,
                &format!("/api/v1/atom/{path}"),
                body.as_bytes(),
                &TransportCancellation::new(),
            )
            .await
            .expect("an atom route");
            (
                reply.status,
                serde_json::from_slice(&reply.body).unwrap_or(Value::Null),
            )
        })
    }

    fn settings(&self) -> Value {
        serde_json::from_slice(&std::fs::read(self.root.join("webinfo/settings.json")).unwrap())
            .unwrap()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn dns_shows_and_changes_the_open_settings() {
    let host = Host::new("dns");
    let (status, view) = host.call("GET", "dns", &Value::Null);
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["core_mode"], "compat");
    assert_eq!(view["block_qtypes"], true);
    assert_eq!(view["prefer_v4"], false);
    assert_eq!(view["ecs"], "2408:8888::8");
    assert_eq!(view["learning"]["enabled"], true);

    let (status, view) = host.call(
        "PUT",
        "dns",
        &json!({"core_mode": "safe", "prefer_v4": true, "ecs": "203.0.113.1"}),
    );
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["core_mode"], "safe");
    assert_eq!(view["prefer_v4"], true);
    assert_eq!(view["ecs"], "203.0.113.1");
    assert_eq!(
        view["block_qtypes"], true,
        "fields left out keep their value"
    );
    let saved = host.settings();
    assert_eq!(saved["flags"]["core_mode"], "safe");
    assert_eq!(saved["flags"]["prefer_v4"], true);
    assert_eq!(host.host.control().generation(), 1, "one new generation");

    // Back to the defaults: nothing but the (empty) flags section is stored.
    let (status, _) = host.call(
        "PUT",
        "dns",
        &json!({"core_mode": "compat", "prefer_v4": false, "ecs": ""}),
    );
    assert_eq!(status, 200);
    assert_eq!(host.settings()["flags"], json!({}));
    assert_eq!(
        host.call("GET", "dns", &Value::Null).1["ecs"],
        "2408:8888::8"
    );

    for bad in [
        json!({"core_mode": "fast"}),
        json!({"prefer_v4": "yes"}),
        json!({"nope": 1}),
        json!({"learning": {"nope": true}}),
        json!([1]),
    ] {
        let (status, value) = host.call("PUT", "dns", &bad);
        assert_eq!(status, 400, "{bad}: {value}");
        assert!(value["error"].is_string());
    }
    let (status, _) = host.call("POST", "dns", &json!({}));
    assert_eq!(status, 405);
}

#[test]
fn upstreams_list_every_group_but_fakeip_and_replace_one() {
    let host = Host::new("upstreams");
    let (status, view) = host.call("GET", "upstreams", &Value::Null);
    assert_eq!(status, 200, "{view}");
    let groups = view["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1, "nocnfake is left out: {view}");
    assert_eq!(groups[0]["tag"], "domestic");
    assert_eq!(groups[0]["customized"], false);
    assert_eq!(groups[0]["upstreams"][0]["addr"], "udp://127.0.0.1:15998");

    let entry =
        json!({"tag": "two", "enabled": true, "protocol": "udp", "addr": "127.0.0.1:15997"});
    let (status, view) = host.call("PUT", "upstreams/domestic", &json!({"upstreams": [entry]}));
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["groups"][0]["customized"], true);
    assert_eq!(view["groups"][0]["upstreams"][0]["tag"], "two");
    assert_eq!(host.settings()["upstreams"]["domestic"][0]["tag"], "two");
    // A restart reads the saved list back.
    let again = crate::HostAssembly::from_config_file_in(&host.root.join("config.yaml"), None)
        .expect("restarts");
    assert_eq!(
        again.config().effective_upstreams["domestic"][0].tag,
        "two",
        "the saved list survives a restart"
    );
    drop(again);

    // An empty list restores the configuration's list.
    let (status, view) = host.call("PUT", "upstreams/domestic", &json!({"upstreams": []}));
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["groups"][0]["customized"], false);
    assert_eq!(view["groups"][0]["upstreams"][0]["tag"], "one");

    let disabled =
        json!({"upstreams": [{"tag": "x", "enabled": false, "addr": "udp://127.0.0.1:1"}]});
    assert_eq!(host.call("PUT", "upstreams/domestic", &disabled).0, 400);
    assert_eq!(
        host.call("PUT", "upstreams/nocnfake", &json!({"upstreams": []}))
            .0,
        400
    );
    assert_eq!(
        host.call("PUT", "upstreams/elsewhere", &json!({"upstreams": []}))
            .0,
        404
    );
    assert_eq!(
        host.call("PUT", "upstreams/domestic", &json!({"nope": []}))
            .0,
        400
    );
    assert_eq!(host.call("PUT", "upstreams", &json!({})).0, 405);
}

#[test]
fn rewrite_replaces_its_file() {
    let host = Host::new("fixed");
    assert_eq!(host.call("GET", "ddns", &Value::Null).0, 404, "DDNS is a rule now");
    let (status, view) = host.call("GET", "rewrite", &Value::Null);
    assert_eq!(
        (status, view),
        (200, json!({"entries": ["full:nas.example 192.0.2.9"]}))
    );
    let (status, view) = host.call(
        "PUT",
        "rewrite",
        &json!({"entries": ["full:nas.example 192.0.2.10", "domain:tv.example tv.target.example"]}),
    );
    assert_eq!(status, 200, "{view}");
    assert_eq!(view["entries"].as_array().unwrap().len(), 2);
    assert_eq!(
        std::fs::read_to_string(host.root.join("rule/rewrite.txt")).unwrap(),
        "full:nas.example 192.0.2.10\ndomain:tv.example tv.target.example\n"
    );
    // An invalid line changes nothing.
    let (status, value) = host.call("PUT", "rewrite", &json!({"entries": ["full:only-a-name"]}));
    assert_eq!(status, 400, "{value}");
    assert_eq!(host.call("GET", "rewrite", &Value::Null).1, view);
    assert_eq!(host.call("DELETE", "rewrite", &Value::Null).0, 405);
}

/// What the configuration reads from the rewrite file is part of a hot
/// apply's fingerprints, so a candidate compiled from an older list is
/// refused at its commit point (codex review of step 6a, round 1).
#[test]
fn the_rewrite_file_is_a_fingerprinted_input() {
    let host = Host::new("rewrite-input");
    let file = host.root.join("rule/rewrite.txt");
    let control = host.host.control();
    let view = control.view();
    let inputs = &view.config.compile_inputs.files;
    assert!(
        inputs
            .iter()
            .any(|(path, digest)| path.ends_with("rule/rewrite.txt") && digest.is_some()),
        "{inputs:?} lacks {}",
        file.display()
    );
}

/// A rewrite plugin reading several files cannot be replaced whole: the
/// other files would bring their rules back at the next load (codex review
/// of step 6a, round 2).
#[test]
fn a_rewrite_with_several_files_is_not_replaced() {
    let host = Host::new("rewrite-two");
    let path = host.root.join("config.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap().replace(
        "files: [rule/rewrite.txt]",
        "files: [rule/rewrite.txt, rule/more.txt]",
    );
    std::fs::write(
        host.root.join("rule/more.txt"),
        "full:tv.example 192.0.2.8\n",
    )
    .unwrap();
    std::fs::write(&path, yaml).unwrap();
    let two = Host {
        root: host.root.clone(),
        host: crate::HostAssembly::from_config_file_in(&path, None).expect("config"),
    };
    let (status, value) = two.call("PUT", "rewrite", &json!({"entries": []}));
    assert_eq!(status, 409, "{value}");
    assert_eq!(
        two.call("GET", "rewrite", &Value::Null).1["entries"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        std::fs::read_to_string(two.root.join("rule/rewrite.txt")).unwrap(),
        "full:nas.example 192.0.2.9\n"
    );
}

/// atom's own configuration keeps the rewrite rules in one file, so `PUT
/// rewrite` can replace them; the DDNS list is gone (step 6b: a rule).
#[test]
fn the_shipped_rewrite_plugin_reads_one_file_and_ddns_is_gone() {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/sub_config/rule_set.yaml"
    ))
    .unwrap();
    let yaml: Value = yaml_serde::from_str(&text).unwrap();
    let plugin = |tag: &str| {
        yaml["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .find(|plugin| plugin["tag"] == tag)
            .cloned()
            .unwrap_or_else(|| panic!("no {tag}"))
    };
    assert!(
        yaml["plugins"].as_array().unwrap().iter().all(|p| p["tag"] != "ddnslist"),
        "the DDNS list is a rule now"
    );
    let rewrite = plugin("rewrite");
    assert_eq!(rewrite["args"]["files"].as_array().unwrap().len(), 1);
}

/// The required fields of an upstream entry in `openapi.yaml` are what the
/// handler needs: an entry of exactly them is accepted, one without any of
/// them is refused.
#[test]
fn an_upstream_entry_needs_what_the_document_requires() {
    let spec: Value = yaml_serde::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/api/openapi.yaml"
    )))
    .unwrap();
    let required: Vec<String> = spec["components"]["schemas"]["Upstream"]["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field.as_str().unwrap().to_owned())
        .collect();
    let sample = |field: &str| match field {
        "tag" => json!("sample"),
        "protocol" => json!("udp"),
        "addr" => json!("127.0.0.1:15996"),
        other => panic!("no sample value for the required field {other}"),
    };
    let host = Host::new("upstream-schema");
    let entry = |skip: Option<&str>| {
        let mut entry = serde_json::Map::new();
        entry.insert("enabled".into(), json!(true));
        for field in required.iter().filter(|field| Some(field.as_str()) != skip) {
            entry.insert(field.clone(), sample(field));
        }
        json!({"upstreams": [Value::Object(entry)]})
    };
    let (status, value) = host.call("PUT", "upstreams/domestic", &entry(None));
    assert_eq!(status, 200, "{value}");
    for field in &required {
        let (status, value) = host.call("PUT", "upstreams/domestic", &entry(Some(field)));
        assert_eq!(status, 400, "without {field}: {value}");
    }
}

/// A DNS query for `name` A, RD set.
fn query(name: &str) -> Vec<u8> {
    let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        packet.push(u8::try_from(label.len()).unwrap());
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

/// An in-process query (what `requery` sends through `LocalApi::resolve`, and
/// a rewrite's domain target) has no client: it meets no client rule, plain
/// or inverted (codex review of step 6a, round 4: it used to carry 127.0.0.1,
/// which met `client: [127.0.0.1]` and every inverted rule without it).
#[test]
fn in_process_queries_meet_no_client_rule() {
    let host = Host::new("in-process");
    let path = host.root.join("config.yaml");
    let yaml = std::fs::read_to_string(&path).unwrap().replace(
        "  - tag: entry\n",
        "  - tag: probe\n    type: sequence\n    args: [{exec: $atom_rules}, {matches: fast_mark 40, exec: reject 3}, {exec: reject 5}]\n  - tag: entry\n",
    );
    std::fs::write(&path, yaml).unwrap();
    let probe = Host {
        root: host.root.clone(),
        host: crate::HostAssembly::from_config_file_in(&path, None).expect("config"),
    };
    for rule in [
        json!({"match": {"suffix": ["plain.example"], "client": ["127.0.0.1"]}, "action": {"type": "block"}}),
        json!({"match": {"suffix": ["outside.example"], "client": ["192.168.1.0/24"], "client_invert": true}, "action": {"type": "block"}}),
        json!({"match": {"suffix": ["named.example"]}, "action": {"type": "block"}}),
    ] {
        let (status, value) = probe.call("POST", "rules", &rule);
        assert_eq!(status, 201, "{value}");
    }
    let control = probe.host.control();
    let local = crate::local_url::LocalApi {
        control: crate::runtime_snapshot::RuntimeControlWeak::from_control(&control),
        api: None,
        roots: None,
    };
    let rcode = |name: &'static str| {
        let local = local.clone();
        probe.host.block_on(async move {
            let reply = local
                .resolve("probe", &query(name), std::time::Duration::from_secs(2))
                .await
                .expect("an in-process answer");
            reply[3] & 0x0f
        })
    };
    assert_eq!(rcode("a.named.example"), 3, "a name rule still blocks");
    assert_eq!(rcode("a.plain.example"), 5, "a client rule does not match");
    assert_eq!(
        rcode("a.outside.example"),
        5,
        "an inverted client rule does not match"
    );
}

/// A UDP DNS server answering every A query with `address`, counting the
/// queries it saw.
fn fake_upstream(address: [u8; 4]) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&seen);
    std::thread::spawn(move || {
        let mut buffer = [0u8; 1500];
        while let Ok((size, peer)) = socket.recv_from(&mut buffer) {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let query = &buffer[..size];
            // Header with QR, RD, RA; one question, one answer, no OPT.
            let question_end = 12 + query[12..].iter().position(|b| *b == 0).unwrap() + 5;
            let mut reply = query[..2].to_vec();
            reply.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
            reply.extend_from_slice(&query[12..question_end]);
            reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0x01, 0x2c, 0, 4]);
            reply.extend_from_slice(&address);
            let _ = socket.send_to(&reply, peer);
        }
    });
    (port, seen)
}

/// The address of an answer with one A record (the fake's), if any.
fn first_a(reply: &[u8]) -> Option<[u8; 4]> {
    let answers = u16::from_be_bytes([reply[6], reply[7]]);
    (answers > 0).then(|| reply[reply.len() - 4..].try_into().unwrap())
}

#[test]
fn custom_upstream_groups_are_created_named_used_and_deleted() {
    let host = Host::new("groups");
    let entry = |port: u16| json!({"tag": format!("u{port}"), "enabled": true, "protocol": "udp", "addr": format!("127.0.0.1:{port}")});
    let (status, created) = host.call(
        "POST",
        "upstreams",
        &json!({"name": "公司 DNS", "upstreams": [entry(15990)]}),
    );
    assert_eq!(status, 201, "{created}");
    let tag = created["tag"].as_str().unwrap().to_owned();
    assert!(crate::config::atom_routes::valid_tag(&tag), "{tag}");
    let group = created["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["tag"] == tag.as_str())
        .cloned()
        .unwrap();
    assert_eq!((&group["name"], &group["builtin"]), (&json!("公司 DNS"), &json!(false)));
    let domestic = &created["groups"][0];
    assert_eq!((&domestic["name"], &domestic["builtin"]), (&json!("国内"), &json!(true)));
    assert_eq!(host.settings()["atom_groups"], json!([{"tag": tag, "name": "公司 DNS"}]));

    // Rename; a custom group keeps at least one upstream.
    let (status, view) = host.call(
        "PUT",
        &format!("upstreams/{tag}"),
        &json!({"name": "内网 DNS", "upstreams": [entry(15991)]}),
    );
    assert_eq!(status, 200, "{view}");
    assert_eq!(host.settings()["atom_groups"][0]["name"], "内网 DNS");
    assert_eq!(host.settings()["upstreams"][&tag][0]["addr"], "127.0.0.1:15991");
    assert_eq!(
        host.call("PUT", &format!("upstreams/{tag}"), &json!({"upstreams": []})).0,
        400
    );
    assert_eq!(
        host.call("PUT", "upstreams/domestic", &json!({"name": "x", "upstreams": []})).0,
        400,
        "builtin groups keep their names"
    );
    for bad in [json!({"name": " ", "upstreams": [entry(1)]}), json!({"name": "x", "upstreams": []})] {
        assert_eq!(host.call("POST", "upstreams", &bad).0, 400, "{bad}");
    }

    // A rule names it; then the group cannot go.
    let rule = json!({"match": {"suffix": ["corp.example"]}, "action": {"type": "direct"}, "dns": tag});
    let (status, created_rule) = host.call("POST", "rules", &rule);
    assert_eq!(status, 201, "{created_rule}");
    let rule_id = created_rule["rule"]["id"].as_str().unwrap().to_owned();
    let (status, refused) = host.call("DELETE", &format!("upstreams/{tag}"), &Value::Null);
    assert_eq!(status, 409, "{refused}");
    assert_eq!(refused["rules"], json!([rule_id]));
    assert_eq!(host.call("DELETE", "upstreams/domestic", &Value::Null).0, 400);
    assert_eq!(host.call("DELETE", "upstreams/u-00000000", &Value::Null).0, 404);

    // Rule checks: an unknown group, dns or cache on a non-direct rule.
    for bad in [
        json!({"match": {"suffix": ["a.example"]}, "action": {"type": "direct"}, "dns": "u-ffffffff"}),
        json!({"match": {"suffix": ["a.example"]}, "action": {"type": "block"}, "dns": "domestic"}),
        json!({"match": {"suffix": ["a.example"]}, "action": {"type": "block"}, "cache": false}),
    ] {
        let (status, value) = host.call("POST", "rules", &bad);
        assert_eq!(status, 400, "{bad}: {value}");
    }

    let (status, _) = host.call("DELETE", &format!("rules/{rule_id}"), &Value::Null);
    assert_eq!(status, 200);
    let (status, view) = host.call("DELETE", &format!("upstreams/{tag}"), &Value::Null);
    assert_eq!(status, 200, "{view}");
    assert!(host.settings().get("atom_groups").is_none());
    assert!(host.settings()["upstreams"].get(&tag).is_none());
}

/// A direct rule with `dns` asks that group (through the generated
/// `atom_direct`), with the rule cache; `cache: false` asks every time.
#[test]
fn a_direct_rule_asks_its_group_with_or_without_the_cache() {
    let host = Host::new("routed");
    let (port, seen) = fake_upstream([192, 0, 2, 77]);
    let upstream = json!({"tag": "corp", "enabled": true, "protocol": "udp", "addr": format!("127.0.0.1:{port}")});
    let (status, created) = host.call(
        "POST",
        "upstreams",
        &json!({"name": "公司", "upstreams": [upstream]}),
    );
    assert_eq!(status, 201, "{created}");
    let tag = created["tag"].as_str().unwrap().to_owned();
    for rule in [
        json!({"match": {"suffix": ["cached.example"]}, "action": {"type": "direct"}, "dns": tag}),
        json!({"match": {"suffix": ["fresh.example"]}, "action": {"type": "direct"}, "dns": tag, "cache": false}),
    ] {
        let (status, value) = host.call("POST", "rules", &rule);
        assert_eq!(status, 201, "{value}");
    }
    let (_, rules) = host.call("GET", "rules", &Value::Null);
    // After the default LAN rule.
    assert_eq!(rules["rules"][2]["cache"], false, "{rules}");
    assert!(rules["rules"][1].get("cache").is_none(), "the default is left out: {rules}");

    let control = host.host.control();
    let local = crate::local_url::LocalApi {
        control: crate::runtime_snapshot::RuntimeControlWeak::from_control(&control),
        api: None,
        roots: None,
    };
    let ask = |name: &'static str| {
        let local = local.clone();
        host.host.block_on(async move {
            local
                .resolve("entry", &query(name), std::time::Duration::from_secs(2))
                .await
                .expect("an answer")
        })
    };
    let count = || seen.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(first_a(&ask("a.cached.example")), Some([192, 0, 2, 77]));
    assert_eq!(count(), 1);
    assert_eq!(first_a(&ask("a.cached.example")), Some([192, 0, 2, 77]));
    assert_eq!(count(), 1, "the rule cache answered");
    assert_eq!(first_a(&ask("a.fresh.example")), Some([192, 0, 2, 77]));
    assert_eq!(first_a(&ask("a.fresh.example")), Some([192, 0, 2, 77]));
    assert_eq!(count(), 3, "no cache: asked both times");

    // The routes survive a restart (the group is in settings.json).
    let again = crate::HostAssembly::from_config_file_in(&host.root.join("config.yaml"), None)
        .expect("restarts");
    assert!(again.config().effective_upstreams.contains_key(&tag));
}
