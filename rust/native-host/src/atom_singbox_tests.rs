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
                "#!/bin/sh\nd={}\necho x >> $d/reloads\nif [ -f $d/config.json ] && grep -q BADRELOAD $d/config.json; then echo 'reload failed' >&2; exit 1; fi\nif [ -f $d/config.json ]; then cp $d/config.json $d/running.json; else rm -f $d/running.json; fi\n",
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
                        // Chunked, like Go's net/http for a large body.
                        (
                            "200 OK",
                            r#"{"proxies":{"final":{"type":"Selector"}}}"#.to_owned(),
                        )
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
            self.host.clash_api
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
    apply_blocking(&fake.host, &first, "s1").unwrap();
    assert_eq!(fake.live().unwrap(), first);
    assert_eq!(fake.running().unwrap(), first);
    assert!(!fake.host.dir.join(NEXT_FILE).exists());
    let second = config("s2", "two");
    apply_blocking(&fake.host, &second, "s2").unwrap();
    assert_eq!(fake.running().unwrap(), second);
    assert_eq!(fake.reload_count(), 2);
}

#[test]
fn a_refused_check_touches_nothing() {
    let fake = FakeSingbox::start("check");
    let first = config("s1", "one");
    apply_blocking(&fake.host, &first, "s1").unwrap();
    let bad = config("s2", "BADCHECK");
    let error = apply_blocking(&fake.host, &bad, "s2").unwrap_err();
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
    apply_blocking(&fake.host, &first, "s1").unwrap();
    let error = apply_blocking(&fake.host, &config("s2", "BADRELOAD"), "s2").unwrap_err();
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
    apply_blocking(&fake.host, &first, "s1").unwrap();
    let error = apply_blocking(&fake.host, &config("s2", "NOCONFIRM"), "s2").unwrap_err();
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
    let error = apply_blocking(&fake.host, &config("s1", "BADRELOAD"), "s1").unwrap_err();
    assert!(error.to_string().contains("之前没有配置"), "{error}");
    assert!(fake.live().is_none());
}

#[test]
fn a_missing_binary_writes_nothing() {
    let mut fake = FakeSingbox::start("nobinary");
    fake.host.binary = fake.dir.join("absent");
    let error = apply_blocking(&fake.host, &config("s1", "one"), "s1").unwrap_err();
    assert!(error.to_string().contains("找不到 sing-box"), "{error}");
    assert!(!fake.host.dir.join(NEXT_FILE).exists());
}

#[test]
fn clash_select_and_delay_go_through_the_api() {
    let fake = FakeSingbox::start("clash");
    apply_blocking(&fake.host, &config("s1", "one"), "s1").unwrap();
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
            action: Action::Proxy {
                group_id: "g-default".into(),
            },
        },
        IpRule {
            cidrs: vec!["10.9.0.0/16".into()],
            action: Action::Block,
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
    assert_eq!(
        rules[2],
        json!({"ip_cidr": ["91.108.4.0/22"], "action": "route", "outbound": "g-default"})
    );
    assert_eq!(
        rules[3],
        json!({"ip_cidr": ["10.9.0.0/16"], "action": "reject"})
    );
    assert_eq!(rules[4]["domain_regex"], json!(["."]));
    assert_eq!(rules[4]["outbound"], "direct");
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
