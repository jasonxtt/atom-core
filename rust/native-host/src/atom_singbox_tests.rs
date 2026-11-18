use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use super::*;
use crate::atom_proxy::{Group, GroupKind, Node, ProxyState};

/// A stand-in sing-box for the transaction: a `check` script that refuses a
/// candidate containing `BADCHECK`, a reload script that "loads" the live
/// file into `running.json` (and fails on `BADRELOAD`), and a Clash API that
/// answers with the secret of `running.json` (none for `NOCONFIRM`).
/// Applications are process-wide ([`ApplyGuard`]): tests that apply run
/// one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

pub(crate) struct FakeSingbox {
    _serial: std::sync::MutexGuard<'static, ()>,
    pub(crate) dir: PathBuf,
    pub(crate) host: Host,
    /// The `PUT /proxies/{tag}` requests seen: `(tag, body)`.
    pub(crate) selects: Arc<Mutex<Vec<(String, String)>>>,
}

impl FakeSingbox {
    pub(crate) fn start(name: &str) -> Self {
        let serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join(format!("atom-singbox-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sb")).unwrap();
        let binary = dir.join("sing-box");
        std::fs::write(
            &binary,
            "#!/bin/sh\n# check -D dir -c file\nfile=\"$5\"\nif grep -q BADCHECK \"$file\"; then echo 'FATAL bad outbound' >&2; exit 1; fi\nexit 0\n",
        )
        .unwrap();
        let reload = dir.join("reload.sh");
        std::fs::write(
            &reload,
            format!(
                "#!/bin/sh\nd={}\necho x >> $d/reloads\nif [ -f $d/slow ]; then sleep 1; fi\nif [ -f $d/failreload ]; then echo 'reload refused' >&2; exit 1; fi\nif [ -f $d/config.json ] && grep -q BADRELOAD $d/config.json; then echo 'reload failed' >&2; exit 1; fi\nif [ -f $d/config.json ]; then cp $d/config.json $d/running.json; else rm -f $d/running.json; fi\n",
                dir.join("sb").display()
            ),
        )
        .unwrap();
        for file in [&binary, &reload] {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let clash_api = listener.local_addr().unwrap();
        let selects = Arc::new(Mutex::new(Vec::new()));
        let running = dir.join("sb").join("running.json");
        {
            let selects = Arc::clone(&selects);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        continue;
                    }
                    let mut parts = line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_owned();
                    let path = parts.next().unwrap_or("").to_owned();
                    let mut auth = String::new();
                    let mut length = 0usize;
                    loop {
                        let mut header = String::new();
                        if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                            break;
                        }
                        let lower = header.to_ascii_lowercase();
                        if let Some(value) = lower.strip_prefix("authorization: bearer ") {
                            auth = value.trim().to_owned();
                        }
                        if let Some(value) = lower.strip_prefix("content-length: ") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                    }
                    let mut body = vec![0u8; length];
                    let _ = reader.read_exact(&mut body);
                    let live = std::fs::read(&running).unwrap_or_default();
                    let secret = secret_of(&live).unwrap_or_default();
                    let refused = live.windows(9).any(|w| w == b"NOCONFIRM");
                    let (status, reply) = if refused || secret.is_empty() || auth != secret {
                        ("401 Unauthorized", "{}".to_owned())
                    } else if method == "GET" && path == "/proxies" {
                        // Chunked, like Go's net/http for a large body. Every
                        // outbound of the running file: a group's `now` is its
                        // first member, a node has one delay test of 88 ms.
                        let config: Value = serde_json::from_slice(&live).unwrap_or(Value::Null);
                        let mut proxies = serde_json::Map::new();
                        proxies.insert(FINAL.to_owned(), json!({"type": "Selector"}));
                        for outbound in config["outbounds"].as_array().into_iter().flatten() {
                            let tag = outbound["tag"].as_str().unwrap_or("").to_owned();
                            let entry = match outbound["outbounds"].as_array() {
                                Some(members) => {
                                    json!({"type": "Selector", "now": members.first()})
                                }
                                None => json!({"type": "Trojan", "history":
                                    [{"time": "2026-11-10T00:00:00Z", "delay": 88}]}),
                            };
                            proxies.insert(tag, entry);
                        }
                        ("200 OK", json!({ "proxies": proxies }).to_string())
                    } else if path == "/configs" {
                        let config: Value = yaml_serde::from_slice(&live).unwrap();
                        ("200 OK", config.to_string())
                    } else if path == "/atom/ready" || path == "/cache/fakeip/flush" {
                        ("204 No Content", String::new())
                    } else if method == "GET" && path == "/connections" {
                        (
                            "200 OK",
                            r#"{"downloadTotal":10,"uploadTotal":20,"memory":30,"connections":[{"id":"c-1","chains":["n-00000001","final"],"rule":"final"}]}"#.to_owned(),
                        )
                    } else if method == "DELETE" && path.starts_with("/connections") {
                        ("204 No Content", String::new())
                    } else if method == "POST" && path.starts_with("/cache/fakeip/group/") {
                        let dir = running.parent().unwrap();
                        std::fs::write(dir.join("last-rebind"), &path).unwrap();
                        if dir.join("fail-rebind").exists() {
                            ("409 Conflict", "{}".to_owned())
                        } else {
                            ("204 No Content", String::new())
                        }
                    } else if method == "PUT" && path.starts_with("/proxies/") {
                        selects.lock().unwrap().push((
                            path["/proxies/".len()..].to_owned(),
                            String::from_utf8_lossy(&body).into_owned(),
                        ));
                        ("204 No Content", String::new())
                    } else if method == "GET"
                        && path.starts_with("/proxies/")
                        && path.contains("/delay?")
                    {
                        ("200 OK", r#"{"delay":88}"#.to_owned())
                    } else if method == "GET" && path.starts_with("/group/") {
                        ("200 OK", r#"{"n-00000001":120}"#.to_owned())
                    } else if path == "/version" {
                        ("200 OK", r#"{"version":"sing-box 1.14.4-atom"}"#.to_owned())
                    } else {
                        ("404 Not Found", "{}".to_owned())
                    };
                    let response = if status.starts_with("200") && path == "/proxies" {
                        format!(
                            "HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{reply}\r\n0\r\n\r\n",
                            reply.len()
                        )
                    } else {
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                            reply.len()
                        )
                    };
                    let _ = stream.write_all(response.as_bytes());
                }
            });
        }
        let host = Host {
            backend: crate::atom_proxy::Backend::SingBox,
            stop: vec![],
            mihomo: None,
            binary,
            dir: dir.join("sb"),
            reload: vec![reload.display().to_string()],
            clash_api,
            dns_in: "127.0.0.1:6666".parse().unwrap(),
            atomdns: "127.0.0.1:53".parse().unwrap(),
            redirect_port: 7892,
            tproxy_port: 7893,
            resolver_group: "domestic".to_owned(),
        };
        Self {
            _serial: serial,
            dir,
            host,
            selects,
        }
    }

    pub(crate) fn live(&self) -> Option<Vec<u8>> {
        std::fs::read(self.host.config_path()).ok()
    }

    pub(crate) fn running(&self) -> Option<Vec<u8>> {
        std::fs::read(self.host.dir.join("running.json")).ok()
    }

    pub(crate) fn reload_count(&self) -> usize {
        std::fs::read_to_string(self.host.dir.join("reloads"))
            .map(|text| text.lines().count())
            .unwrap_or(0)
    }

    /// The YAML `singbox` section for this stand-in.
    pub(crate) fn yaml(&self) -> String {
        format!(
            "singbox: {{binary: '{}', dir: '{}', reload: ['{}'], clash_api: '{}', dns_in: '127.0.0.1:6666', atomdns: '127.0.0.1:53', redirect_port: 7892, tproxy_port: 7893, resolver_group: domestic}}",
            self.host.binary.display(),
            self.host.dir.display(),
            self.host.reload[0],
            self.host.clash_api,
        )
    }
}

impl Drop for FakeSingbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn config(secret: &str, marker: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "marker": marker,
        "experimental": {"clash_api": {"secret": secret}}
    }))
    .unwrap()
}

#[test]
fn apply_writes_reloads_and_confirms_with_the_new_secret() {
    let fake = FakeSingbox::start("ok");
    let first = config("s1", "one");
    apply_blocking(&fake.host, &first, "s1", &[], &[]).unwrap();
    assert_eq!(fake.live().unwrap(), first);
    assert_eq!(fake.running().unwrap(), first);
    assert!(!fake.host.dir.join(NEXT_FILE).exists());
    let second = config("s2", "two");
    apply_blocking(&fake.host, &second, "s2", &[], &[]).unwrap();
    assert_eq!(fake.running().unwrap(), second);
    assert_eq!(fake.reload_count(), 2);
}

#[test]
fn a_refused_check_touches_nothing() {
    let fake = FakeSingbox::start("check");
    let first = config("s1", "one");
    apply_blocking(&fake.host, &first, "s1", &[], &[]).unwrap();
    let bad = config("s2", "BADCHECK");
    let error = apply_blocking(&fake.host, &bad, "s2", &[], &[]).unwrap_err();
    assert!(
        matches!(&error, ApplyError::Check(message) if message.contains("bad outbound")),
        "{error}"
    );
    assert_eq!(fake.live().unwrap(), first);
    assert!(!fake.host.dir.join(NEXT_FILE).exists());
    assert_eq!(fake.reload_count(), 1, "no reload after a refused check");
}

#[test]
fn a_failed_reload_rolls_back() {
    let fake = FakeSingbox::start("reload");
    let first = config("s1", "one");
    apply_blocking(&fake.host, &first, "s1", &[], &[]).unwrap();
    let error = apply_blocking(&fake.host, &config("s2", "BADRELOAD"), "s2", &[], &[]).unwrap_err();
    let message = error.to_string();
    assert!(matches!(error, ApplyError::Runtime(_)));
    assert!(
        message.contains("reload failed") && message.contains("已回滚到旧配置"),
        "{message}"
    );
    assert_eq!(fake.live().unwrap(), first);
    assert_eq!(fake.running().unwrap(), first);
}

#[test]
fn an_unconfirmed_reload_rolls_back() {
    let fake = FakeSingbox::start("confirm");
    let first = config("s1", "one");
    apply_blocking(&fake.host, &first, "s1", &[], &[]).unwrap();
    let error = apply_blocking(&fake.host, &config("s2", "NOCONFIRM"), "s2", &[], &[]).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("没有确认") && message.contains("已回滚到旧配置"),
        "{message}"
    );
    assert_eq!(fake.live().unwrap(), first);
    assert_eq!(fake.running().unwrap(), first);
}

#[test]
fn the_first_failed_apply_leaves_no_file() {
    let fake = FakeSingbox::start("first");
    let error = apply_blocking(&fake.host, &config("s1", "BADRELOAD"), "s1", &[], &[]).unwrap_err();
    assert!(error.to_string().contains("之前没有配置"), "{error}");
    assert!(fake.live().is_none());
}

#[test]
fn a_missing_binary_writes_nothing() {
    let mut fake = FakeSingbox::start("nobinary");
    fake.host.binary = fake.dir.join("absent");
    let error = apply_blocking(&fake.host, &config("s1", "one"), "s1", &[], &[]).unwrap_err();
    assert!(error.to_string().contains("找不到 sing-box"), "{error}");
    assert!(!fake.host.dir.join(NEXT_FILE).exists());
}

#[test]
fn clash_select_and_delay_go_through_the_api() {
    let fake = FakeSingbox::start("clash");
    apply_blocking(&fake.host, &config("s1", "one"), "s1", &[], &[]).unwrap();
    select(&fake.host, "s1", "g-12345678", "n-00000001").unwrap();
    assert_eq!(
        fake.selects.lock().unwrap().as_slice(),
        &[(
            "g-12345678".to_owned(),
            r#"{"name":"n-00000001"}"#.to_owned()
        )]
    );
    assert_eq!(
        node_delay(&fake.host, "s1", "n-00000001", "https://example.com/", 500).unwrap()["delay"],
        88
    );
    let delays = delay(&fake.host, "s1", "g-12345678", "https://example.com/", 500).unwrap();
    assert_eq!(delays["n-00000001"], 120);
    assert!(select(&fake.host, "wrong", "g-12345678", "n-00000001").is_err());
    assert_eq!(
        version(&fake.host, "s1").as_deref(),
        Some("sing-box 1.14.4-atom")
    );
}

#[test]
fn chunked_bodies_are_decoded() {
    assert_eq!(
        decode_chunked(b"3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n").unwrap(),
        b"abcde"
    );
    assert!(decode_chunked(b"5\r\nab").is_err());
}

fn sample_state() -> ProxyState {
    let mut state = ProxyState::default();
    let mut outbound = Map::new();
    outbound.insert("type".into(), json!("trojan"));
    outbound.insert("server".into(), json!("a.example"));
    outbound.insert("server_port".into(), json!(443));
    outbound.insert("password".into(), json!("pw"));
    state.nodes.push(Node {
        id: "n-00000001".into(),
        name: "香港".into(),
        outbound,
    });
    state.groups[0].members = vec!["n-00000001".into()];
    state.groups.push(Group {
        id: "g-00000002".into(),
        name: "自动".into(),
        kind: GroupKind::Urltest,
        members: Vec::new(),
        providers: vec![],
        all_providers: false,
        strategy: None,
        filter: String::new(),
        order: Vec::new(),
        selected: String::new(),
        url: Some("https://cp.cloudflare.com/".into()),
        interval: Some("5m".into()),
        tolerance: Some(80),
    });
    state.final_group.members.push("g-00000002".into());
    state
}

fn generated(state: &ProxyState, ip_rules: &[IpRule]) -> Value {
    let fake_host = Host {
        backend: crate::atom_proxy::Backend::SingBox,
        stop: vec![],
        mihomo: None,
        binary: "/bin/true".into(),
        dir: "/tmp/sb".into(),
        reload: vec!["true".into()],
        clash_api: "127.0.0.1:9090".parse().unwrap(),
        dns_in: "127.0.0.1:6666".parse().unwrap(),
        atomdns: "127.0.0.1:53".parse().unwrap(),
        redirect_port: 7892,
        tproxy_port: 7893,
        resolver_group: "domestic".into(),
    };
    let bytes = generate(&fake_host, state, ip_rules, "udp://223.5.5.5", "secret").unwrap();
    assert_eq!(
        bytes,
        generate(&fake_host, state, ip_rules, "udp://223.5.5.5", "secret").unwrap()
    );
    serde_json::from_slice(&bytes).unwrap()
}

fn outbound<'a>(config: &'a Value, tag: &str) -> &'a Value {
    config["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["tag"] == tag)
        .unwrap_or_else(|| panic!("no outbound {tag}"))
}

#[test]
fn generation_follows_the_design_table() {
    let ip_rules = vec![
        IpRule {
            cidrs: vec!["91.108.4.0/22".into()],
            ports: Vec::new(),
            port_ranges: Vec::new(),
            networks: Vec::new(),
            action: Action::Proxy {
                group_id: "g-default".into(),
            },
        },
        IpRule {
            cidrs: vec!["10.9.0.0/16".into()],
            ports: Vec::new(),
            port_ranges: Vec::new(),
            networks: Vec::new(),
            action: Action::Block,
        },
        IpRule {
            cidrs: Vec::new(),
            ports: vec![22, 5201],
            port_ranges: vec!["6000:6010".into()],
            networks: vec!["tcp".into()],
            action: Action::Direct,
        },
    ];
    let config = generated(&sample_state(), &ip_rules);
    // Nodes are tagged by ID; groups and Final are selectors / urltests.
    assert_eq!(outbound(&config, "n-00000001")["password"], "pw");
    assert_eq!(
        outbound(&config, "g-default")["outbounds"],
        json!(["n-00000001"])
    );
    let auto = outbound(&config, "g-00000002");
    assert_eq!(auto["type"], "urltest");
    assert_eq!(
        auto["outbounds"],
        json!(["block"]),
        "an empty group refuses"
    );
    assert_eq!(auto["interval"], "5m");
    assert_eq!(auto["tolerance"], 80);
    let final_outbound = outbound(&config, "final");
    assert_eq!(final_outbound["type"], "selector");
    assert_eq!(
        final_outbound["outbounds"],
        json!(["g-default", "g-00000002"])
    );
    assert_eq!(final_outbound["default"], "g-default");
    assert_eq!(config["route"]["final"], "final");
    assert_eq!(config["route"]["default_domain_resolver"], "resolver");
    let rules = config["route"]["rules"].as_array().unwrap();
    assert_eq!(
        rules[0],
        json!({"inbound": ["dns-in"], "action": "hijack-dns"})
    );
    assert_eq!(rules[1]["action"], "resolve");
    assert_eq!(rules[1]["server"], "atomdns");
    // Every sing-box rule leaves FakeIP destinations out (a safeguard: the
    // patch routes them by binding or Final before any rule).
    let not_fakeip = json!({"ip_cidr": ["28.0.0.0/8"], "invert": true});
    assert_eq!(
        rules[2],
        json!({"type": "logical", "mode": "and", "rules": [not_fakeip, {"ip_cidr": ["91.108.4.0/22"]}], "action": "route", "outbound": "g-default"})
    );
    assert_eq!(
        rules[3],
        json!({"type": "logical", "mode": "and", "rules": [not_fakeip, {"ip_cidr": ["10.9.0.0/16"]}], "action": "reject"})
    );
    assert_eq!(
        rules[4],
        json!({"type": "logical", "mode": "and", "rules": [not_fakeip, {"port": [22, 5201], "port_range": ["6000:6010"], "network": ["tcp"]}], "action": "route", "outbound": "direct"})
    );
    assert_eq!(rules[5]["domain_regex"], json!(["."]));
    assert_eq!(rules[5]["outbound"], "direct");
    assert_eq!(config["dns"]["servers"][0]["inet4_range"], "28.0.0.0/8");
    assert_eq!(config["dns"]["servers"][1]["server"], "223.5.5.5");
    assert_eq!(config["dns"]["servers"][2]["server_port"], 53);
    assert_eq!(config["inbounds"][3]["listen_port"], 7890);
    assert_eq!(config["experimental"]["cache_file"]["store_fakeip"], true);
    assert_eq!(
        config["experimental"]["clash_api"]["external_controller"],
        "127.0.0.1:9090"
    );
    assert_eq!(
        secret_of(&serde_json::to_vec(&config).unwrap()).as_deref(),
        Some("secret")
    );
}

#[test]
fn a_new_installation_generates_refusing_groups() {
    let config = generated(&ProxyState::default(), &[]);
    assert_eq!(
        outbound(&config, "g-default")["outbounds"],
        json!(["block"])
    );
    assert_eq!(
        outbound(&config, "final")["outbounds"],
        json!(["g-default"])
    );
    assert!(
        config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["type"] != "direct" || item["tag"] == "direct")
    );
}

#[test]
fn the_default_resolver_is_the_first_plain_domestic_upstream() {
    use crate::config::settings::UpstreamEntry;
    let entry = |addr: &str, dial: &str, enabled: bool| UpstreamEntry {
        addr: addr.into(),
        dial_addr: dial.into(),
        enabled,
        ..UpstreamEntry::default()
    };
    assert_eq!(
        default_resolver(&[
            entry("udp://1.1.1.1", "", false),
            entry("https://dns.alidns.com/dns-query", "223.5.5.5", true),
            entry("tcp://119.29.29.29", "", true),
        ])
        .as_deref(),
        Some("tcp://119.29.29.29")
    );
    assert_eq!(
        default_resolver(&[entry("https://dns.alidns.com/dns-query", "223.6.6.6", true)])
            .as_deref(),
        Some("udp://223.6.6.6")
    );
    assert_eq!(
        default_resolver(&[entry("https://dns.example/dns-query", "", true)]),
        None
    );
}

#[test]
fn selections_are_synced_after_the_reload_and_restored_on_rollback() {
    let fake = FakeSingbox::start("selections");
    let chosen = vec![
        ("g-default".to_owned(), "n-00000002".to_owned()),
        ("final".to_owned(), "g-default".to_owned()),
    ];
    apply_blocking(&fake.host, &config("s1", "one"), "s1", &chosen, &[]).unwrap();
    assert_eq!(
        fake.selects.lock().unwrap().as_slice(),
        &[
            (
                "g-default".to_owned(),
                r#"{"name":"n-00000002"}"#.to_owned()
            ),
            ("final".to_owned(), r#"{"name":"g-default"}"#.to_owned()),
        ]
    );
    fake.selects.lock().unwrap().clear();
    let old_chosen = vec![("g-default".to_owned(), "n-00000001".to_owned())];
    apply_blocking(
        &fake.host,
        &config("s2", "BADRELOAD"),
        "s2",
        &chosen,
        &old_chosen,
    )
    .unwrap_err();
    assert_eq!(
        fake.selects.lock().unwrap().as_slice(),
        &[(
            "g-default".to_owned(),
            r#"{"name":"n-00000001"}"#.to_owned()
        )],
        "the old instance gets the old choices back"
    );
}

#[cfg(unix)]
#[test]
fn the_configuration_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let fake = FakeSingbox::start("mode");
    std::fs::write(fake.host.config_path(), b"{}").unwrap();
    std::fs::set_permissions(
        fake.host.config_path(),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    apply_blocking(&fake.host, &config("s1", "one"), "s1", &[], &[]).unwrap();
    let mode = std::fs::metadata(fake.host.config_path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn mihomo_switch_checks_before_stopping_and_restores_singbox_on_failure() {
    use crate::atom_proxy::Backend;

    let fake = FakeSingbox::start("mihomo-switch");
    let running = fake.host.dir.join("running.json");
    let stop = vec![
        "rm".to_owned(),
        "-f".to_owned(),
        running.display().to_string(),
    ];
    let old = Host {
        stop: stop.clone(),
        ..fake.host.clone()
    };
    let mihomo = Host {
        backend: Backend::Mihomo,
        dir: fake.dir.join("mh"),
        stop,
        reload: vec![
            "cp".to_owned(),
            fake.dir.join("mh/config.yaml").display().to_string(),
            running.display().to_string(),
        ],
        ..fake.host.clone()
    };
    let state = ProxyState::default();
    let resolver = "udp://223.5.5.5";
    let first = generate(&old, &state, &[], resolver, "old").unwrap();
    apply_blocking(&old, &first, "old", &[], &[]).unwrap();

    assert!(matches!(
        switch_blocking(&old, &mihomo, b"BADCHECK", "new", &[], &[]),
        Err(ApplyError::Check(_))
    ));
    assert_eq!(std::fs::read(&running).unwrap(), first);

    let rule = IpRule {
        cidrs: vec!["192.0.2.0/24".into(), "2001:db8::/32".into()],
        ports: vec![53],
        port_ranges: vec!["1000:1010".into()],
        networks: vec!["udp".into()],
        action: crate::atom_rules::Action::Direct,
    };
    let next = generate(&mihomo, &state, &[rule], resolver, "new").unwrap();
    let value: Value = yaml_serde::from_slice(&next).unwrap();
    assert_eq!(value["dns"]["atom-fake-ip-final"], "final");
    assert_eq!(
        value["rules"][0],
        "AND,((OR,((IP-CIDR,192.0.2.0/24,no-resolve),(IP-CIDR6,2001:db8::/32,no-resolve))),(OR,((DST-PORT,53),(DST-PORT,1000-1010))),(NETWORK,udp)),DIRECT"
    );
    if let Some(path) = std::env::var_os("ATOM_TEST_MIHOMO") {
        let real = Host {
            binary: path.into(),
            ..mihomo.clone()
        };
        check(&real, &next).unwrap();
    }
    switch_blocking(&old, &mihomo, &next, "new", &[], &[]).unwrap();
    assert_eq!(std::fs::read(&running).unwrap(), next);
    assert!(switch_back(&old, &mihomo, &[]).contains("已回滚"));
    assert_eq!(std::fs::read(&running).unwrap(), first);

    let failed = Host {
        reload: vec!["false".to_owned()],
        ..mihomo
    };
    assert!(matches!(
        switch_blocking(&old, &failed, &next, "new", &[], &[]),
        Err(ApplyError::Runtime(_))
    ));
    assert_eq!(std::fs::read(&running).unwrap(), first);
}

#[test]
fn mihomo_generates_native_subscriptions_and_automatic_groups() {
    use crate::atom_proxy::{Backend, GroupInput, ProviderInput, ProxyProvider};

    let fake = FakeSingbox::start("mihomo-providers");
    let mut host = fake.host.clone();
    host.backend = Backend::Mihomo;
    host.binary = std::env::var_os("ATOM_TEST_MIHOMO").map_or(host.binary, Into::into);
    let mut state = ProxyState::default();
    let provider = "p-01234567";
    state.settings.backend = Backend::Mihomo;
    state.providers.push(ProxyProvider {
        id: provider.to_owned(),
        settings: ProviderInput {
            name: "sub".to_owned(),
            url: "https://example.test/sub".to_owned(),
            interval: 900,
            filter: "HK|JP".to_owned(),
            download_via: None,
        },
    });
    let group = |name: &str, kind: &str, strategy: &str| {
        serde_json::from_value::<GroupInput>(json!({
            "name":name, "type":kind, "providers":[provider], "strategy":strategy
        })).unwrap()
    };
    let fallback = state.add_group(serde_json::from_value(json!({
        "name":"fallback", "type":"fallback", "providers":[provider]
    })).unwrap());
    let load_balance = state.add_group(group("balance", "load-balance", "round-robin"));
    state.validate(&[]).unwrap();
    let bytes = generate(&host, &state, &[], "223.5.5.5", "secret").unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let config = &value["proxy-providers"][provider];
    assert_eq!(config["proxy"], "DIRECT");
    assert_eq!(config["override"]["additional-prefix"], format!("{provider}/"));
    assert_eq!(config["filter"], "HK|JP");
    assert_eq!(config["interval"], 900);
    assert!(!config["path"].as_str().unwrap().contains("example.test"));
    let groups = value["proxy-groups"].as_array().unwrap();
    let by_id = |id: &str| groups.iter().find(|group| group["name"] == id).unwrap();
    assert_eq!(by_id(&fallback.id)["type"], "fallback");
    assert_eq!(by_id(&fallback.id)["empty-fallback"], "REJECT");
    assert!(by_id(&fallback.id).get("proxies").is_none());
    assert_eq!(by_id(&load_balance.id)["strategy"], "round-robin");
    assert_eq!(by_id(&load_balance.id)["use"][0], provider);
    if std::env::var_os("ATOM_TEST_MIHOMO").is_some() {
        check(&host, &bytes).unwrap();
    }
}

fn mihomo_node(outbound: Value) -> Node {
    Node {
        id: "n-1".to_owned(),
        name: "n".to_owned(),
        outbound: outbound.as_object().unwrap().clone(),
    }
}

#[test]
fn mihomo_http_transport_follows_tls() {
    let outbound = |tls: bool| {
        json!({
            "type":"vmess", "server":"h.test", "server_port":80, "uuid":"u",
            "tls":{"enabled":tls},
            "transport":{"type":"http", "host":["a.test"], "path":"/x", "method":"POST",
                "headers":{"X-A":"1", "X-B":["2","3"]}}
        })
    };
    let plain = crate::atom_mihomo::convert_proxy(&mihomo_node(outbound(false))).unwrap();
    assert_eq!(plain["network"], "http");
    assert!(plain.get("h2-opts").is_none());
    let opts = &plain["http-opts"];
    assert_eq!(opts["method"], "POST");
    assert_eq!(opts["path"], json!(["/x"]));
    assert_eq!(
        opts["headers"],
        json!({"X-A":["1"], "X-B":["2","3"], "Host":["a.test"]})
    );
    let mut bare = outbound(false);
    bare["transport"] = json!({"type":"http", "path":"/x"});
    let bare = crate::atom_mihomo::convert_proxy(&mihomo_node(bare)).unwrap();
    assert_eq!(bare["http-opts"]["method"], "PUT", "sing-box's default method");
    let mut empty = outbound(false);
    empty["transport"] = json!({"type":"http", "method":""});
    let empty = crate::atom_mihomo::convert_proxy(&mihomo_node(empty)).unwrap();
    assert_eq!(empty["http-opts"]["method"], "PUT");
    let secure = crate::atom_mihomo::convert_proxy(&mihomo_node(outbound(true)));
    // headers and method have no h2 counterpart: still refused rather than dropped
    assert!(secure.is_err());
    let mut h2 = outbound(true);
    h2["transport"] = json!({"type":"http", "host":["a.test"], "path":"/x"});
    let secure = crate::atom_mihomo::convert_proxy(&mihomo_node(h2)).unwrap();
    assert_eq!(secure["network"], "h2");
    assert_eq!(secure["h2-opts"], json!({"host":["a.test"], "path":"/x"}));
}

#[test]
fn mihomo_anytls_has_udp_and_hysteria2_maps_bandwidth() {
    let anytls = crate::atom_mihomo::convert_proxy(&mihomo_node(json!({
        "type":"anytls", "server":"a.test", "server_port":443, "password":"p",
        "tls":{"enabled":true, "server_name":"a.test"}
    })))
    .unwrap();
    assert_eq!(anytls["udp"], true);
    let hysteria2 = crate::atom_mihomo::convert_proxy(&mihomo_node(json!({
        "type":"hysteria2", "server":"h.test", "server_port":443, "password":"p",
        "up_mbps":50, "down_mbps":200,
        "tls":{"enabled":true, "server_name":"h.test"}
    })))
    .unwrap();
    assert_eq!(hysteria2["up"], "50 Mbps");
    assert_eq!(hysteria2["down"], "200 Mbps");
    assert!(hysteria2.get("up_mbps").is_none());
}

#[test]
fn mihomo_prunes_only_stale_subscription_caches() {
    let dir = std::env::temp_dir().join(format!("atom-prune-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let cache = dir.join("providers");
    std::fs::create_dir_all(&cache).unwrap();
    let hash = "a".repeat(64);
    let current = format!("p-00000001-{hash}.yaml");
    let stale = [format!("p-00000001-{}.yaml", "b".repeat(64)), format!("p-00000002-{hash}.yaml")];
    for name in stale.iter().chain([&current].into_iter()).chain(["other.yaml".to_owned(), "p-manual.yaml".to_owned()].iter()) {
        std::fs::write(cache.join(name), "x").unwrap();
    }
    let live = format!(r#"{{"proxy-providers":{{"p-00000001":{{"path":"providers/{current}"}}}}}}"#);
    crate::atom_mihomo::prune_provider_caches(&dir, live.as_bytes());
    let mut left: Vec<_> = std::fs::read_dir(&cache)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left, ["other.yaml".to_owned(), current, "p-manual.yaml".to_owned()]);
    // an unreadable live file prunes nothing
    crate::atom_mihomo::prune_provider_caches(&dir, b"not json");
    assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 3);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn convert(outbound: Value) -> Result<Value, String> {
    crate::atom_mihomo::convert_proxy(&mihomo_node(outbound))
}

fn wireguard_node() -> Value {
    json!({
        "type":"wireguard", "address":["10.0.0.2/32", "fd00::2/128"], "private_key":"cHJpdmF0ZS1rZXktMzItYnl0ZXMtbG9uZy1hYmM9",
        "mtu":1280,
        "peers":[{"address":"wg.example", "port":51820, "public_key":"cHVibGljLWtleS0zMi1ieXRlcy1sb25nLWFiYzEyMz0=",
            "allowed_ips":["0.0.0.0/0"], "persistent_keepalive_interval":25, "reserved":[1,2,3]}]
    })
}

#[test]
fn wireguard_is_an_endpoint_in_singbox_and_a_proxy_in_mihomo() {
    let mut state = ProxyState::default();
    state.nodes.push(Node {
        id: "n-00000001".into(),
        name: "wg".into(),
        outbound: wireguard_node().as_object().unwrap().clone(),
    });
    state.groups[0].members = vec!["n-00000001".into()];
    state.validate(&[]).unwrap();
    let config = generated(&state, &[]);
    assert_eq!(config["endpoints"][0]["type"], "wireguard");
    assert_eq!(config["endpoints"][0]["tag"], "n-00000001");
    assert!(
        config["outbounds"].as_array().unwrap().iter().all(|o| o["tag"] != "n-00000001"),
        "not an outbound"
    );
    let group = config["outbounds"].as_array().unwrap().iter().find(|o| o["tag"] == "g-default").unwrap();
    assert_eq!(group["outbounds"], json!(["n-00000001"]));
    // Nodes without WireGuard leave no `endpoints` key (the file of an upgrade stays the same).
    assert!(generated(&sample_state(), &[]).get("endpoints").is_none());

    let proxy = convert(wireguard_node()).unwrap();
    assert_eq!(proxy["ip"], "10.0.0.2/32");
    assert_eq!(proxy["ipv6"], "fd00::2/128");
    assert_eq!(proxy["peers"][0]["server"], "wg.example");
    assert_eq!(proxy["peers"][0]["public-key"], "cHVibGljLWtleS0zMi1ieXRlcy1sb25nLWFiYzEyMz0=");
    assert_eq!(proxy["peers"][0]["reserved"], json!([1, 2, 3]));
    assert_eq!(proxy["persistent-keepalive"], 25);
    assert_eq!(proxy["mtu"], 1280);
    let mut system = wireguard_node();
    system["system"] = json!(true);
    assert!(convert(system).unwrap_err().contains("system"));
}

#[test]
fn mihomo_converts_hysteria_ssh_and_snell() {
    let hysteria = convert(json!({
        "type":"hysteria", "server":"h.test", "server_port":443, "up_mbps":50, "down":"200 Mbps",
        "auth_str":"secret", "obfs":"o", "server_ports":["20000:30000"], "hop_interval":"30s",
        "tls":{"enabled":true, "server_name":"h.test", "insecure":true, "alpn":["hysteria"]}
    }))
    .unwrap();
    assert_eq!(hysteria["type"], "hysteria");
    assert_eq!(hysteria["up"], "50 Mbps");
    assert_eq!(hysteria["down"], "200 Mbps");
    assert_eq!(hysteria["auth-str"], "secret");
    assert_eq!(hysteria["obfs"], "o");
    assert_eq!(hysteria["ports"], "20000-30000");
    assert_eq!(hysteria["hop-interval"], 30);
    assert_eq!(hysteria["sni"], "h.test");
    assert_eq!(hysteria["skip-cert-verify"], true);
    assert!(convert(json!({"type":"hysteria", "server":"h", "server_port":1, "tls":{"enabled":true}})).is_err());

    let ssh = convert(json!({
        "type":"ssh", "server":"s.test", "server_port":22, "user":"root", "password":"p",
        "private_key":["-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"],
        "host_key":["ssh-ed25519 AAAA"]
    }))
    .unwrap();
    assert_eq!(ssh["username"], "root");
    assert!(ssh["private-key"].as_str().unwrap().contains("PRIVATE KEY"));
    assert_eq!(ssh["host-key"], json!(["ssh-ed25519 AAAA"]));
    for extra in [json!({"private_key_path":"/k"}), json!({"client_version":"x"})] {
        let mut node = json!({"type":"ssh", "server":"s.test", "server_port":22, "user":"root"});
        node.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        assert!(convert(node).is_err());
    }

    let snell = convert(json!({
        "type":"snell", "server":"n.test", "server_port":443, "psk":"k", "version":4, "reuse":true,
        "obfs_mode":"tls", "obfs_host":"bing.com"
    }))
    .unwrap();
    assert_eq!(snell["psk"], "k");
    assert_eq!(snell["version"], 4);
    assert_eq!(snell["obfs-opts"], json!({"mode":"tls", "host":"bing.com"}));
    assert_eq!(snell["udp"], true);
    let v6 = convert(json!({"type":"snell", "server":"n.test", "server_port":443, "psk":"k", "version":6, "mode":"unshaped"})).unwrap();
    assert_eq!(v6["mode"], "unshaped");
    assert!(convert(json!({"type":"snell", "server":"n", "server_port":1, "psk":"k", "version":6, "userkey":"u"})).is_err());
}

#[test]
fn mihomo_explains_the_nodes_it_cannot_run() {
    assert_eq!(convert(json!({"type":"naive", "server":"n", "server_port":443})).unwrap_err(), "mihomo 没有 naive 协议");
    assert!(convert(json!({"type":"shadowtls", "server":"n", "server_port":443})).unwrap_err().contains("插件"));
    let multiplex = convert(json!({
        "type":"vmess", "server":"v", "server_port":443, "uuid":"u", "multiplex":{"enabled":true}
    }))
    .unwrap_err();
    assert!(multiplex.contains("multiplex"), "{multiplex}");
}

#[test]
fn mihomo_group_filter_follows_the_subscription_prefix_and_case() {
    use crate::atom_mihomo::mihomo_filter;
    const HEAD: &str = "(?i)(?<=^p-[0-9a-f]{8}/.*)(?:";
    const BEHIND: &str = "(?<=^p-[0-9a-f]{8}/)";
    assert_eq!(mihomo_filter("HK|JP"), format!("{HEAD}HK|JP)"));
    assert_eq!(mihomo_filter("^HK|^日本$"), format!("{HEAD}{BEHIND}HK|{BEHIND}日本$)"));
    assert_eq!(mihomo_filter("\\Ax"), format!("{HEAD}{BEHIND}x)"));
    assert_eq!(mihomo_filter("[^a]x\\^"), format!("{HEAD}[^a]x\\^)"));
    assert_eq!(mihomo_filter("a`b"), format!("{HEAD}a\\x60b)"));
}

#[test]
fn mihomo_groups_take_all_providers_filter_and_skip_inactive_nodes() {
    use crate::atom_proxy::{Backend, ProviderInput, ProxyProvider};

    let fake = FakeSingbox::start("mihomo-all-providers");
    let mut host = fake.host.clone();
    host.backend = Backend::Mihomo;
    host.binary = std::env::var_os("ATOM_TEST_MIHOMO").map_or(host.binary, Into::into);
    let mut state = ProxyState::default();
    state.settings.backend = Backend::Mihomo;
    state.providers.push(ProxyProvider {
        id: "p-01234567".to_owned(),
        settings: ProviderInput {
            name: "sub".to_owned(),
            url: "https://example.test/sub".to_owned(),
            interval: 900,
            filter: String::new(),
            download_via: None,
        },
    });
    state.nodes.push(Node {
        id: "n-00000001".into(),
        name: "HK trojan".into(),
        outbound: json!({"type":"trojan", "server":"t.test", "server_port":443, "password":"p", "tls":{"enabled":true}})
            .as_object().unwrap().clone(),
    });
    state.nodes.push(Node {
        id: "n-00000002".into(),
        name: "HK naive".into(),
        outbound: json!({"type":"naive", "server":"n.test", "server_port":443, "username":"u", "password":"p"})
            .as_object().unwrap().clone(),
    });
    state.nodes.push(Node {
        id: "n-00000003".into(),
        name: "wg".into(),
        outbound: wireguard_node().as_object().unwrap().clone(),
    });
    state.nodes.push(Node {
        id: "n-00000004".into(),
        name: "snell".into(),
        outbound: json!({"type":"snell", "server":"s.test", "server_port":443, "psk":"k", "version":4}).as_object().unwrap().clone(),
    });
    state.nodes.push(Node {
        id: "n-00000005".into(),
        name: "hy1".into(),
        outbound: json!({"type":"hysteria", "server":"h.test", "server_port":443, "up_mbps":10, "down_mbps":10, "auth_str":"a",
            "tls":{"enabled":true, "server_name":"h.test"}}).as_object().unwrap().clone(),
    });
    state.nodes.push(Node {
        id: "n-00000006".into(),
        name: "ssh".into(),
        outbound: json!({"type":"ssh", "server":"s.test", "server_port":22, "user":"root", "password":"p"}).as_object().unwrap().clone(),
    });
    state.groups[0].members = state.nodes.iter().map(|node| node.id.clone()).collect();
    state.groups[0].selected = "n-00000002".to_owned();
    let all = state.add_group(serde_json::from_value(json!({
        "name":"all", "type":"urltest", "all_providers":true, "filter":"^HK"
    })).unwrap());
    let single = state.add_group(serde_json::from_value(json!({
        "name":"one", "type":"selector", "providers":["p-01234567"]
    })).unwrap());
    state.validate(&[]).unwrap();
    let bytes = generate(&host, &state, &[], "223.5.5.5", "secret").unwrap();
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    let proxies: Vec<&str> = value["proxies"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
    assert_eq!(proxies, ["n-00000001", "n-00000003", "n-00000004", "n-00000005", "n-00000006"], "naive is skipped");
    let groups = value["proxy-groups"].as_array().unwrap();
    let by_id = |id: &str| groups.iter().find(|group| group["name"] == id).unwrap();
    let default = by_id("g-default");
    assert!(!default["proxies"].as_array().unwrap().iter().any(|m| m == "n-00000002"));
    assert_eq!(default["proxies"][0], "n-00000001", "the selection that left falls back to the first");
    assert_eq!(by_id(&all.id)["include-all-providers"], true);
    assert!(by_id(&all.id).get("use").is_none());
    assert_eq!(
        by_id(&all.id)["filter"],
        "(?i)(?<=^p-[0-9a-f]{8}/.*)(?:(?<=^p-[0-9a-f]{8}/)HK)"
    );
    // The manual node matched by the filter is a plain member, the naive one is not.
    assert_eq!(by_id(&all.id)["proxies"], json!(["n-00000001"]));
    assert_eq!(by_id(&single.id)["use"], json!(["p-01234567"]));
    assert!(by_id(&single.id).get("filter").is_none(), "no filter: none written");
    if std::env::var_os("ATOM_TEST_MIHOMO").is_some() {
        check(&host, &bytes).unwrap();
    }

    // A subscription downloaded through a node mihomo cannot run has no way to download.
    state.providers[0].settings.download_via = Some("n-00000002".to_owned());
    assert!(generate(&host, &state, &[], "223.5.5.5", "secret").unwrap_err().contains("下载节点"));
}

#[test]
fn real_singbox_accepts_wireguard_endpoint_snell_ssh_and_hysteria() {
    let Some(binary) = std::env::var_os("ATOM_TEST_SINGBOX") else {
        return;
    };
    let fake = FakeSingbox::start("real-singbox-nodes");
    let mut host = fake.host.clone();
    host.binary = binary.into();
    let mut state = ProxyState::default();
    for (index, outbound) in [
        wireguard_node(),
        json!({"type":"snell", "server":"s.test", "server_port":443, "psk":"k", "version":4, "obfs_mode":"tls", "obfs_host":"bing.com"}),
        json!({"type":"snell", "server":"s.test", "server_port":443, "psk":"k", "version":6, "mode":"unshaped"}),
        json!({"type":"hysteria", "server":"h.test", "server_port":443, "up_mbps":10, "down_mbps":10, "auth_str":"a",
            "tls":{"enabled":true, "server_name":"h.test"}}),
        json!({"type":"ssh", "server":"s.test", "server_port":22, "user":"root", "password":"p"}),
    ]
    .into_iter()
    .enumerate()
    {
        state.nodes.push(Node {
            id: format!("n-0000000{index}"),
            name: format!("node{index}"),
            outbound: outbound.as_object().unwrap().clone(),
        });
    }
    state.groups[0].members = state.nodes.iter().map(|node| node.id.clone()).collect();
    state.validate(&[]).unwrap();
    let bytes = generate(&host, &state, &[], "223.5.5.5", "secret").unwrap();
    check(&host, &bytes).unwrap();
}

#[test]
fn mihomo_conversion_keeps_the_singbox_meaning_of_defaults_and_conflicts() {
    // ssh: root and port 22 by default; a key in lines is one key.
    let ssh = convert(json!({
        "type":"ssh", "server":"s.test",
        "private_key":["-----BEGIN OPENSSH PRIVATE KEY-----", "abc", "-----END OPENSSH PRIVATE KEY-----"]
    }))
    .unwrap();
    assert_eq!((ssh["username"].as_str(), ssh["port"].as_u64()), (Some("root"), Some(22)));
    assert_eq!(ssh["private-key"].as_str().unwrap().lines().count(), 3);
    // snell: obfs "none" is mihomo's empty mode.
    let snell = convert(json!({"type":"snell", "server":"n", "server_port":1, "psk":"k", "version":4, "obfs_mode":"none"})).unwrap();
    assert!(snell.get("obfs-opts").is_none());
    // hysteria: auth_str wins in sing-box, auth in mihomo: only the winner is written.
    let hy = convert(json!({
        "type":"hysteria", "server":"h", "server_port":1, "up_mbps":1, "down_mbps":1,
        "auth":"d3Jvbmc=", "auth_str":"correct", "tls":{"enabled":true}
    }))
    .unwrap();
    assert_eq!(hy["auth-str"], "correct");
    assert!(hy.get("auth").is_none());
    // wireguard: one keepalive for all peers in mihomo.
    let mut wg = wireguard_node();
    let mut second = wg["peers"][0].clone();
    second["persistent_keepalive_interval"] = json!(0);
    wg["peers"].as_array_mut().unwrap().push(second);
    assert!(convert(wg).unwrap_err().contains("persistent-keepalive"));
}
