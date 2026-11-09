//! Tests of `atom_dns_api`: `dns`, `upstreams`, `ddns`, `rewrite`.

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
        std::fs::write(root.join("rule/ddnslist.txt"), "full:home.example\n").unwrap();
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
            ("ddns_foreign", false),
            ("full_cache", true),
            ("lazy_cache", true),
        ] {
            yaml.push_str(&flag(tag, default));
        }
        yaml.push_str(
            "  - tag: client_ecs\n    type: ecs_address\n    args: {addr: '2408:8888::8'}\n  - tag: domestic\n    type: aliapi\n    args: {upstreams: [{tag: one, addr: 'udp://127.0.0.1:15998'}]}\n  - tag: nocnfake\n    type: aliapi\n    args: {upstreams: [{tag: fake, addr: 'udp://127.0.0.1:6666'}]}\n  - tag: ddnslist\n    type: domain_set_light\n    args: {files: [rule/ddnslist.txt]}\n  - tag: mapper\n    type: domain_mapper\n    args: {default_mark: 17, default_tag: none, rules: [{tag: ddnslist, mark: 6, output_tag: DDNS}]}\n  - tag: rewrite\n    type: rewrite\n    args: {files: [rule/rewrite.txt], dns: 'udp://127.0.0.1:15998'}\n  - tag: atom_rules\n    type: atom_rules\n    args: {marks: {proxy: 41, direct: 42, block: 40}}\n  - tag: entry\n    type: sequence\n    args: [{exec: $rewrite}, {exec: $atom_rules}, {exec: $domestic}]\n",
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
fn ddns_and_rewrite_replace_their_files() {
    let host = Host::new("fixed");
    let (status, view) = host.call("GET", "ddns", &Value::Null);
    assert_eq!(
        (status, view),
        (200, json!({"entries": ["full:home.example"]}))
    );
    let (status, view) = host.call(
        "PUT",
        "ddns",
        &json!({"entries": ["  domain:dyn.example ", "", "# note", "full:b.example"]}),
    );
    assert_eq!(status, 200, "{view}");
    assert_eq!(
        view,
        json!({"entries": ["domain:dyn.example", "full:b.example"]})
    );
    assert_eq!(
        std::fs::read_to_string(host.root.join("rule/ddnslist.txt")).unwrap(),
        "domain:dyn.example\nfull:b.example\n"
    );
    assert_eq!(host.call("GET", "ddns", &Value::Null).1, view);
    assert_eq!(host.call("PUT", "ddns", &json!({"values": []})).0, 400);

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

/// Two overlapping DDNS replacements: each answers only once its own list
/// (or a later one) is the one the mapper uses. A rebuild already running
/// when the second one wrote is waited for (codex review of step 6a, round
/// 1); the other replacement may write again after a reply settled, while
/// that reply still empties the caches.
#[test]
fn overlapping_ddns_replacements_answer_once_their_list_is_in_use() {
    let host = Host::new("ddns-overlap");
    let control = host.host.control();
    let file = host.root.join("rule/ddnslist.txt");
    host.host.block_on(async {
        let put = |name: &'static str, other: &'static str| {
            let control = control.clone();
            let file = file.clone();
            async move {
                let view = control.view();
                let body = json!({"entries": [format!("full:{name}")]}).to_string();
                let reply = crate::atom_rules_api::handle(
                    Some(&control),
                    &view.config,
                    &view.cache,
                    "PUT",
                    "/api/v1/atom/ddns",
                    body.as_bytes(),
                    &TransportCancellation::new(),
                )
                .await
                .expect("an atom route");
                assert_eq!(reply.status, 200);
                let on_disk = std::fs::read_to_string(&file).unwrap();
                let mapper = view
                    .config
                    .domain_mappers
                    .iter()
                    .find(|mapper| mapper.tag == "mapper")
                    .unwrap();
                let own = mapper.evaluate(Some(name)).fast_flags & (1 << 6) != 0;
                assert!(
                    own || on_disk.trim() == format!("full:{other}"),
                    "{name} is answered before its list is in use (on disk: {on_disk:?})"
                );
            }
        };
        let first = tokio::task::spawn_local(put("first.example", "second.example"));
        let second = tokio::task::spawn_local(put("second.example", "first.example"));
        first.await.unwrap();
        second.await.unwrap();
    });
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

/// A DDNS entry the file loader would refuse (one line of 64 KiB or more
/// fails the whole file at the next start) is refused before anything is
/// written (codex review of step 6a, round 3).
#[test]
fn an_overlong_ddns_entry_is_refused_and_nothing_is_written() {
    let host = Host::new("ddns-long");
    let long = format!("keyword:{}", "a".repeat(64 * 1024));
    let (status, value) = host.call("PUT", "ddns", &json!({"entries": [long]}));
    assert_eq!(status, 400, "{value}");
    assert_eq!(
        std::fs::read_to_string(host.root.join("rule/ddnslist.txt")).unwrap(),
        "full:home.example\n"
    );
}

/// A rebuild that keeps the previous rules is reported, not answered 200:
/// here the mapper also reads another list whose file became unloadable.
#[test]
fn a_ddns_list_the_mapper_cannot_build_is_reported() {
    let host = Host::new("ddns-bad");
    let path = host.root.join("config.yaml");
    let yaml = std::fs::read_to_string(&path)
        .unwrap()
        .replace(
            "rules: [{tag: ddnslist, mark: 6, output_tag: DDNS}]",
            "rules: [{tag: ddnslist, mark: 6, output_tag: DDNS}, {tag: other, mark: 7, output_tag: O}]",
        )
        .replace(
            "  - tag: mapper\n",
            "  - tag: other\n    type: domain_set_light\n    args: {files: [rule/other.txt]}\n  - tag: mapper\n",
        );
    std::fs::write(host.root.join("rule/other.txt"), "full:o.example\n").unwrap();
    std::fs::write(&path, yaml).unwrap();
    let bad = Host {
        root: host.root.clone(),
        host: crate::HostAssembly::from_config_file_in(&path, None).expect("config"),
    };
    std::fs::write(
        bad.root.join("rule/other.txt"),
        format!("keyword:{}\n", "a".repeat(64 * 1024)),
    )
    .unwrap();
    let (status, value) = bad.call("PUT", "ddns", &json!({"entries": ["full:new.example"]}));
    assert_eq!(status, 500, "{value}");
    assert!(
        value["error"].as_str().unwrap().contains("没有生效"),
        "{value}"
    );
}

/// A DDNS list with more than its one writable file (another file, or inline
/// `exps`) cannot be replaced whole (codex review of step 6a, round 3).
#[test]
fn a_ddns_list_with_other_sources_is_not_replaced() {
    for (from, to) in [
        (
            "files: [rule/ddnslist.txt]",
            "files: [rule/ddnslist.txt, rule/more.txt]",
        ),
        (
            "files: [rule/ddnslist.txt]",
            "files: [rule/ddnslist.txt], exps: ['full:inline.example']",
        ),
    ] {
        let host = Host::new("ddns-more");
        let path = host.root.join("config.yaml");
        let yaml = std::fs::read_to_string(&path).unwrap().replace(from, to);
        std::fs::write(host.root.join("rule/more.txt"), "full:more.example\n").unwrap();
        std::fs::write(&path, yaml).unwrap();
        let other = Host {
            root: host.root.clone(),
            host: crate::HostAssembly::from_config_file_in(&path, None).expect("config"),
        };
        let (status, value) = other.call("PUT", "ddns", &json!({"entries": []}));
        assert_eq!(status, 409, "{to}: {value}");
        assert_eq!(
            std::fs::read_to_string(other.root.join("rule/ddnslist.txt")).unwrap(),
            "full:home.example\n"
        );
    }
}

/// atom's own configuration keeps the DDNS list and the rewrite rules in one
/// file each, so `PUT ddns` and `PUT rewrite` can replace them.
#[test]
fn the_shipped_ddns_and_rewrite_plugins_read_one_file() {
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
    let ddns = plugin("ddnslist");
    assert_eq!(ddns["type"], "domain_set_light");
    assert_eq!(ddns["args"]["files"].as_array().unwrap().len(), 1);
    assert!(ddns["args"].get("exps").is_none());
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
