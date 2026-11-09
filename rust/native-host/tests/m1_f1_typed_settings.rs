//! M1-f1: the typed settings layer — configuration objects and `$tag`
//! references, `webinfo/settings.json`, the effective report, hot apply of a
//! settings change as a whole generation, and the settings routes of the web UI.
//! Local DNS stubs and a local SOCKS5 relay stand in for the network; no test
//! reaches the public network.

#![allow(clippy::too_many_lines)]

use std::net::UdpSocket as StdUdpSocket;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

// ----- fixtures -----------------------------------------------------------------

struct Tree(PathBuf);

impl Tree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("m1-f1-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn text(&self, relative: &str) -> String {
        std::fs::read_to_string(self.0.join(relative)).unwrap_or_default()
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.0.join(relative)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn answer_for(query: &[u8], marker: u8) -> Vec<u8> {
    let mut end = 12;
    while query[end] != 0 {
        end += 1 + usize::from(query[end]);
    }
    end += 5;
    let mut reply = vec![query[0], query[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    reply.extend_from_slice(&query[12..end]);
    reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, marker]);
    reply
}

/// A UDP DNS stub that answers every query with `192.0.2.<marker>` after
/// `delay`; it counts what it received.
struct Stub {
    port: u16,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Stub {
    fn start(marker: u8, delay: Duration) -> Self {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            let mut packet = vec![0_u8; 4096];
            while !stopped.load(Ordering::SeqCst) {
                let Ok((length, client)) = socket.recv_from(&mut packet) else {
                    continue;
                };
                let reply = answer_for(&packet[..length], marker);
                let socket = socket.try_clone().unwrap();
                if delay.is_zero() {
                    let _ = socket.send_to(&reply, client);
                } else {
                    thread::spawn(move || {
                        thread::sleep(delay);
                        let _ = socket.send_to(&reply, client);
                    });
                }
            }
        });
        Self {
            port,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Stub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

struct Ports {
    dns: u16,
    api: u16,
}

fn ports() -> Ports {
    Ports {
        dns: free_port(),
        api: free_port(),
    }
}

/// A configuration with the settable objects; `extra` adds plugins before the
/// entry sequence, `entry` is the sequence's exec list.
fn config(tree: &Tree, ports: &Ports, extra: &str) {
    let yaml = format!(
        r#"log: {{level: error}}
api: {{http: "127.0.0.1:{api}"}}
plugins:
{extra}  - tag: entry
    type: sequence
    args:
      - exec: $my_realiplist
      - exec: $foreign
  - tag: listener
    type: udp_server
    args: {{entry: entry, listen: "127.0.0.1:{dns}"}}
"#,
        api = ports.api,
        dns = ports.dns,
    );
    tree.write("config.yaml", &yaml);
}

/// The objects every host test needs: a proxy object, an ECS object, an
/// `aliapi` group whose entries are `upstreams`, and one `domain_output`.
fn objects(proxy_addr: &str, upstreams: &str) -> String {
    format!(
        r#"  - tag: main_proxy
    type: socks5_proxy
    args: {{addr: "{proxy_addr}"}}
  - tag: client_ecs
    type: ecs_address
    args: {{addr: "192.0.2.77"}}
  - tag: foreign
    type: aliapi
    args:
      proxy: $main_proxy
      upstreams:
{upstreams}
  - tag: my_realiplist
    type: domain_output
    args: {{file_stat: gen/real.txt, dump_interval: 3600}}
"#
    )
}

fn udp_entries(stub: &Stub) -> String {
    format!(
        "        - {{tag: a, addr: \"udp://127.0.0.1:{}\"}}",
        stub.port
    )
}

// ----- compile-level behavior -----------------------------------------------------

fn compile(tree: &Tree) -> Result<atomdns_native_host::CompiledConfig, String> {
    atomdns_native_host::load_and_compile(&tree.path("config.yaml"))
        .map_err(|error| error.to_string())
}

#[test]
fn references_overlay_and_sources_are_reported_and_resolved() {
    let tree = Tree::new("effective");
    let ports = ports();
    let stub = Stub::start(1, Duration::ZERO);
    config(
        &tree,
        &ports,
        &objects(
            "192.0.2.1:7890",
            &format!(
                "        - {{tag: a, addr: \"tcp://127.0.0.1:{}\", use_proxy: true}}\n        - {{tag: b, addr: \"udp://127.0.0.1:{}\"}}",
                stub.port, stub.port
            ),
        ),
    );
    let config = compile(&tree).unwrap();
    let item = |kind: &str, object: &str| {
        config
            .settings_report()
            .iter()
            .find(|item| item.kind == kind && item.object == object)
            .unwrap_or_else(|| panic!("{kind} {object} missing"))
            .clone()
    };
    assert_eq!(item("socks5_proxy", "main_proxy").value, "192.0.2.1:7890");
    assert_eq!(item("socks5_proxy", "main_proxy").source, "yaml");
    assert_eq!(item("ecs_address", "client_ecs").value, "192.0.2.77");
    assert_eq!(item("domain_output", "my_realiplist").value, "true");
    let upstreams = item("aliapi", "foreign");
    assert_eq!(upstreams.source, "yaml");
    assert!(upstreams.value.contains("a=tcp://"), "{}", upstreams.value);
    // The entry that opted in carries the plugin proxy; the other does not.
    let definition = config
        .forward_definitions
        .iter()
        .find(|definition| definition.tag == "foreign")
        .unwrap();
    assert_eq!(
        definition.entries[0].target.socks5.as_deref(),
        Some("192.0.2.1:7890")
    );
    assert_eq!(definition.entries[1].target.socks5, None);

    // Settings overlay: a proxy address, an ECS address, a replaced upstream
    // list and the generation switches.
    tree.write(
        "webinfo/settings.json",
        r#"{"version":1,
  "proxies":{"main_proxy":{"addr":"10.9.9.9:1080"}},
  "ecs":{"client_ecs":{"addr":"198.51.100.5"}},
  "upstreams":{"foreign":[
     {"tag":"x","enabled":true,"protocol":"tcp","addr":"127.0.0.1:5353","use_proxy":true},
     {"tag":"y","enabled":false,"protocol":"udp","addr":"127.0.0.1:5354"}]},
  "domain_generation":{"plugins":{"my_realiplist":{"enabled":false}}}}"#,
    );
    let config = compile(&tree).unwrap();
    let report = config.settings_report();
    let find = |kind: &str| {
        report
            .iter()
            .find(|item| item.kind == kind)
            .unwrap()
            .clone()
    };
    assert_eq!(
        (
            find("socks5_proxy").value.as_str(),
            find("socks5_proxy").source
        ),
        ("10.9.9.9:1080", "settings")
    );
    assert_eq!(
        (
            find("ecs_address").value.as_str(),
            find("ecs_address").source
        ),
        ("198.51.100.5", "settings")
    );
    assert_eq!(
        (
            find("domain_output").value.as_str(),
            find("domain_output").source
        ),
        ("false", "settings")
    );
    let aliapi = find("aliapi");
    assert_eq!(aliapi.source, "settings");
    assert_eq!(aliapi.value, "x=tcp://127.0.0.1:5353 [proxy]");
    let definition = config
        .forward_definitions
        .iter()
        .find(|definition| definition.tag == "foreign")
        .unwrap();
    assert_eq!(definition.entries.len(), 1, "disabled entries are not used");
    assert_eq!(
        definition.entries[0].target.socks5.as_deref(),
        Some("10.9.9.9:1080")
    );
}

#[test]
fn bad_references_and_bad_settings_are_errors_with_their_path() {
    let tree = Tree::new("errors");
    let ports = ports();
    let stub = Stub::start(1, Duration::ZERO);
    let good = udp_entries(&stub);
    let try_config = |extra: String| {
        config(&tree, &ports, &extra);
        compile(&tree)
            .err()
            .unwrap_or_else(|| panic!("must fail:\n{extra}"))
    };
    // use_proxy without a plugin proxy.
    let error = try_config(
        "  - tag: main_proxy\n    type: socks5_proxy\n    args: {addr: \"1.2.3.4:1\"}\n  - tag: foreign\n    type: aliapi\n    args:\n      upstreams:\n        - {tag: a, addr: \"tcp://127.0.0.1:1\", use_proxy: true}\n  - tag: my_realiplist\n    type: domain_output\n    args: {}\n"
            .to_owned(),
    );
    assert!(
        error.contains("use_proxy") && error.contains("proxy"),
        "{error}"
    );
    // Unknown and wrong-kind references.
    let error =
        try_config(objects("1.2.3.4:1", &good).replace("proxy: $main_proxy", "proxy: $nothing"));
    assert!(error.contains("unknown socks5_proxy `$nothing`"), "{error}");
    let error =
        try_config(objects("1.2.3.4:1", &good).replace("proxy: $main_proxy", "proxy: $client_ecs"));
    assert!(
        error.contains("unknown socks5_proxy `$client_ecs`"),
        "{error}"
    );
    // A literal proxy and a reference together.
    let error = try_config(objects("1.2.3.4:1", &good).replace(
        "proxy: $main_proxy",
        "proxy: $main_proxy\n      socks5: \"5.6.7.8:1\"",
    ));
    assert!(error.contains("literal socks5"), "{error}");
    // Invalid object values.
    let error = try_config(objects("not-an-address", &good));
    assert!(error.contains("host:port"), "{error}");
    // Quick ecs referencing nothing.
    let mut extra = objects("1.2.3.4:1", &good);
    extra.push_str("  - tag: other\n    type: sequence\n    args:\n      - exec: ecs $missing\n");
    let error = try_config(extra);
    assert!(error.contains("unknown ecs_address `$missing`"), "{error}");

    // Settings that name nothing, name the wrong kind, or are malformed.
    config(&tree, &ports, &objects("1.2.3.4:1", &good));
    for (settings, expected) in [
        (
            r#"{"version":1,"proxies":{"ghost":{"addr":"1.2.3.4:1"}}}"#,
            "no socks5_proxy `ghost`",
        ),
        (
            r#"{"version":1,"proxies":{"client_ecs":{"addr":"1.2.3.4:1"}}}"#,
            "not a socks5_proxy",
        ),
        (r#"{"version":2}"#, "unsupported settings version 2"),
        (r#"{"version":1,"surprise":true}"#, "invalid settings"),
        (
            r#"{"version":1,"proxies":{"main_proxy":{"addr":"x"}}}"#,
            "host:port",
        ),
        (
            r#"{"version":1,"upstreams":{"foreign":[{"tag":"a","enabled":true,"protocol":"aliapi"}]}}"#,
            "signed AliDNS",
        ),
        (
            r#"{"version":1,"upstreams":{"foreign":[{"tag":"a","enabled":true,"protocol":"udp","addr":"1.1.1.1","socks5":"1.2.3.4:1"}]}}"#,
            "literal socks5",
        ),
        (
            r#"{"version":1,"upstreams":{"foreign":[{"tag":"a","enabled":false,"protocol":"udp","addr":"1.1.1.1"}]}}"#,
            "must not be empty",
        ),
        (r"not json", "invalid settings"),
    ] {
        tree.write("webinfo/settings.json", settings);
        let error = compile(&tree)
            .err()
            .unwrap_or_else(|| panic!("must fail: {settings}"));
        assert!(error.contains(expected), "{settings}\n{error}");
    }
}

/// The fixed addresses of every compiled ECS policy.
fn ecs_presets(config: &atomdns_native_host::CompiledConfig) -> Vec<std::net::IpAddr> {
    config
        .response_policies
        .iter()
        .filter_map(|policy| match &policy.policy {
            atomdns_native_host::ResponsePolicy::Ecs(ecs) => ecs.preset,
            _ => None,
        })
        .collect()
}

#[test]
fn quick_ecs_references_resolve_and_follow_the_settings() {
    let tree = Tree::new("ecs");
    let ports = ports();
    let stub = Stub::start(1, Duration::ZERO);
    let mut extra = objects("1.2.3.4:1", &udp_entries(&stub));
    extra.push_str(
        "  - tag: cache_x\n    type: cache\n    args: {}\n  - tag: ecs_seq\n    type: sequence\n    args:\n      - exec: $cache_x\n      - exec: ecs $client_ecs\n      - exec: $foreign\n",
    );
    config(&tree, &ports, &extra);
    // A reference to a fixed address may follow a cache (M1-g), literal or not.
    let config = compile(&tree).unwrap();
    assert!(ecs_presets(&config).contains(&"192.0.2.77".parse().unwrap()));
    tree.write(
        "webinfo/settings.json",
        r#"{"version":1,"ecs":{"client_ecs":{"addr":"2001:db8:ec5::1"}}}"#,
    );
    let config = compile(&tree).unwrap();
    assert!(ecs_presets(&config).contains(&"2001:db8:ec5::1".parse().unwrap()));
}

#[test]
fn check_prints_the_effective_values_with_their_sources() {
    let tree = Tree::new("check");
    let ports = ports();
    let stub = Stub::start(1, Duration::ZERO);
    config(
        &tree,
        &ports,
        &objects("192.0.2.1:7890", &udp_entries(&stub)),
    );
    tree.write(
        "webinfo/settings.json",
        r#"{"version":1,"proxies":{"main_proxy":{"addr":"10.9.9.9:1080"}}}"#,
    );
    let before = tree.text("webinfo/settings.json");
    let report = atomdns_native_host::check_config(&tree.path("config.yaml")).unwrap();
    let text = report.to_string();
    assert!(
        text.contains("EFFECTIVE socks5_proxy main_proxy addr=10.9.9.9:1080 source=settings"),
        "{text}"
    );
    assert!(
        text.contains("EFFECTIVE ecs_address client_ecs addr=192.0.2.77 source=yaml"),
        "{text}"
    );
    assert!(
        text.contains("EFFECTIVE domain_output my_realiplist enabled=true source=yaml"),
        "{text}"
    );
    assert!(
        text.contains("SUMMARY gaps=0 cascades=0 globals=0"),
        "{text}"
    );
    // `check` never writes.
    assert_eq!(tree.text("webinfo/settings.json"), before);
    // A broken settings file is reported, not ignored.
    tree.write("webinfo/settings.json", r#"{"version":9}"#);
    let text = atomdns_native_host::check_config(&tree.path("config.yaml"))
        .unwrap()
        .to_string();
    assert!(
        text.contains("GLOBAL")
            && text.contains("webinfo/settings.json")
            && text.contains("unsupported settings version 9"),
        "{text}"
    );
}

// ----- the running host -----------------------------------------------------------

#[test]
fn the_fixture_in_the_new_syntax_checks_clean_with_effective_values_and_sources() {
    let config =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/settings/config.yaml");
    let report = atomdns_native_host::check_config(&config).unwrap();
    let text = report.to_string();
    assert!(
        text.contains("SUMMARY gaps=0 cascades=0 globals=0"),
        "{text}"
    );
    for line in [
        "EFFECTIVE socks5_proxy main_proxy addr=192.0.2.9:7890 source=settings",
        "EFFECTIVE ecs_address client_ecs addr=2001:db8:ec5::1 source=yaml",
        "EFFECTIVE aliapi domestic upstreams=ali=udp://223.6.6.6 source=settings",
        "EFFECTIVE aliapi foreign upstreams=cf=tcp://1.1.1.1 [proxy], g=tls://dns.google dial=8.8.8.8 [proxy], direct=udp://9.9.9.9 source=yaml",
        "EFFECTIVE domain_output my_realiplist enabled=false source=settings",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
}

#[test]
fn rule_sources_take_the_proxy_by_reference() {
    let tree = Tree::new("sources");
    let ports = ports();
    let stub = Stub::start(1, Duration::ZERO);
    let mut extra = objects("1.2.3.4:1", &udp_entries(&stub));
    extra.push_str("  - tag: geosite\n    type: sd_set_light\n    args: {proxy: $main_proxy, local_config: srs/geosite.json}\n");
    tree.write("srs/geosite.json", "[]");
    config(&tree, &ports, &extra);
    assert!(compile(&tree).is_ok());
    let conflict = extra.replace(
        "proxy: $main_proxy, local_config",
        "proxy: $main_proxy, socks5: \"5.6.7.8:1\", local_config",
    );
    config(&tree, &ports, &conflict);
    let error = compile(&tree).err().unwrap();
    assert!(error.contains("literal socks5"), "{error}");
    let unknown = extra.replace(
        "proxy: $main_proxy, local_config",
        "proxy: $nowhere, local_config",
    );
    config(&tree, &ports, &unknown);
    assert!(
        compile(&tree)
            .err()
            .unwrap()
            .contains("unknown socks5_proxy `$nowhere`")
    );
}

#[test]
fn a_literal_proxy_cannot_mix_with_proxy_references_or_settings() {
    let tree = Tree::new("mixing");
    let ports = ports();
    let stub = Stub::start(1, Duration::ZERO);
    let good = udp_entries(&stub);
    let group = |plugin_args: &str, entry: &str| {
        format!(
            "  - tag: main_proxy\n    type: socks5_proxy\n    args: {{addr: \"1.2.3.4:1\"}}\n  - tag: foreign\n    type: aliapi\n    args:\n{plugin_args}      upstreams:\n        - {entry}\n  - tag: my_realiplist\n    type: domain_output\n    args: {{}}\n"
        )
    };
    let try_config = |extra: String| {
        config(&tree, &ports, &extra);
        compile(&tree)
            .err()
            .unwrap_or_else(|| panic!("must fail:\n{extra}"))
    };
    // use_proxy: false next to a literal address is still a mix.
    let error = try_config(group(
        "      socks5: \"5.6.7.8:1\"\n",
        "{tag: a, addr: \"tcp://127.0.0.1:1\", use_proxy: false}",
    ));
    assert!(error.contains("literal"), "{error}");
    let error = try_config(group(
        "",
        "{tag: a, addr: \"tcp://127.0.0.1:1\", socks5: \"5.6.7.8:1\", use_proxy: false}",
    ));
    assert!(error.contains("literal"), "{error}");
    // An entry reference next to a plugin literal address.
    let error = try_config(group(
        "      socks5: \"5.6.7.8:1\"\n",
        "{tag: a, addr: \"tcp://127.0.0.1:1\", proxy: $main_proxy}",
    ));
    assert!(error.contains("literal"), "{error}");
    // Stored upstreams cannot inherit a literal plugin address.
    config(
        &tree,
        &ports,
        &group(
            "      socks5: \"5.6.7.8:1\"\n",
            "{tag: a, addr: \"tcp://127.0.0.1:1\"}",
        ),
    );
    assert!(compile(&tree).is_ok(), "a plain literal still compiles");
    tree.write(
        "webinfo/settings.json",
        r#"{"version":1,"upstreams":{"foreign":[{"tag":"b","enabled":true,"protocol":"tcp","addr":"127.0.0.1:2","use_proxy":false}]}}"#,
    );
    let error = compile(&tree).err().expect("must fail");
    assert!(error.contains("literal"), "{error}");
    drop(good);
}

#[test]
fn managed_upstreams_derive_concurrency_but_yaml_keeps_its_limit() {
    let tree = Tree::new("managed-concurrent");
    let ports = ports();
    let stub = Stub::start(1, Duration::ZERO);
    let extra = objects("127.0.0.1:9", &udp_entries(&stub)).replace(
        "      proxy: $main_proxy",
        "      concurrent: 2\n      proxy: $main_proxy",
    );
    config(&tree, &ports, &extra);
    let concurrent = || {
        atomdns_native_host::load_and_compile(&tree.path("config.yaml"))
            .unwrap()
            .forward_definitions
            .iter()
            .find(|group| group.tag == "foreign")
            .unwrap()
            .concurrent
    };
    assert_eq!(concurrent(), 2, "unmanaged YAML must retain concurrent");
    for (count, disabled) in [(3, 0), (4, 1), (21, 0), (1, 0)] {
        let entries = (0..count)
            .map(|i| {
                serde_json::json!({
                    "tag": format!("u{i}"), "enabled": i >= disabled,
                    "protocol": "udp", "addr": format!("127.0.0.1:{}", 19000 + i)
                })
            })
            .collect::<Vec<_>>();
        tree.write(
            "webinfo/settings.json",
            &serde_json::json!({
                "version": 1, "upstreams": {"foreign": entries}
            })
            .to_string(),
        );
        assert_eq!(
            concurrent(),
            (count - disabled).min(20),
            "{count}/{disabled}"
        );
    }
    tree.write("webinfo/settings.json", r#"{"version":1}"#);
    assert_eq!(concurrent(), 2, "restoring YAML restores its concurrent");
}

#[test]
fn an_empty_proxy_address_means_no_proxy() {
    let tree = Tree::new("empty-proxy");
    let ports = ports();
    let stub = Stub::start(1, Duration::ZERO);
    config(
        &tree,
        &ports,
        &objects(
            "",
            &format!(
                "        - {{tag: a, addr: \"tcp://127.0.0.1:{}\", use_proxy: true}}",
                stub.port
            ),
        ),
    );
    let compiled = compile(&tree).expect("an empty proxy address compiles");
    let proxy = compiled
        .settings_report()
        .iter()
        .find(|item| item.kind == "socks5_proxy")
        .unwrap()
        .clone();
    assert_eq!((proxy.value.as_str(), proxy.source), ("", "yaml"));
    let definition = compiled
        .forward_definitions
        .iter()
        .find(|definition| definition.tag == "foreign")
        .unwrap();
    assert_eq!(
        definition.entries[0].target.socks5.as_deref().unwrap_or(""),
        ""
    );
    // A settings entry may fill it in, and may go back to empty.
    tree.write(
        "webinfo/settings.json",
        r#"{"version":1,"proxies":{"main_proxy":{"addr":"127.0.0.1:9"}}}"#,
    );
    let compiled = compile(&tree).unwrap();
    let proxy = compiled
        .settings_report()
        .iter()
        .find(|item| item.kind == "socks5_proxy")
        .unwrap()
        .clone();
    assert_eq!(
        (proxy.value.as_str(), proxy.source),
        ("127.0.0.1:9", "settings")
    );
    tree.write(
        "webinfo/settings.json",
        r#"{"version":1,"proxies":{"main_proxy":{"addr":""}}}"#,
    );
    assert!(compile(&tree).is_ok());
    // A bad address is still refused; the other object kind still needs one.
    tree.write(
        "webinfo/settings.json",
        r#"{"version":1,"proxies":{"main_proxy":{"addr":"nope"}}}"#,
    );
    assert!(compile(&tree).err().unwrap().contains("host:port"));
}
