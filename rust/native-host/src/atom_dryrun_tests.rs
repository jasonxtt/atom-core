//! The dry run against the real flow: the shipped YAML (`config/`:
//! `config_custom.yaml`, the process, result-sequence, learner, flag and
//! cache files) with loopback fakes for the upstreams, sing-box and the
//! data sets. Every name is dry-run first, then queried for real; the two
//! must agree, and the dry run must leave caches, learned entries (their hit
//! counts too), the top domains, the binding ledger and sing-box untouched.

use std::net::{IpAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use crate::assembly::{HostAssembly, HostOptions};

/// Copied as they ship.
const SHIPPED: &[&str] = &[
    "sub_config/flags.yaml",
    "sub_config/cache.yaml",
    "sub_config/route_learner.yaml",
    "sub_config/domain_output.yaml",
    "sub_config/process_listed.yaml",
    "sub_config/process_ot.yaml",
    "sub_config/process_v4.yaml",
    "sub_config/process_v6.yaml",
];

/// A fake DNS server answering by the first label: `cn*` A 223.5.5.5,
/// `apple*` A 17.1.1.1 (`direct_ip`), `far*` A 8.8.8.8 and AAAA
/// 2001:db8::1, `none*` nothing; other A 223.6.6.6, other AAAA nothing.
/// `fakeip`: answers every A with 28.0.0.1 and records the EDNS0 65001
/// option payload (sing-box).
struct Fake {
    port: u16,
    seen: Arc<Mutex<Vec<(String, u16, Option<Vec<u8>>)>>>,
}

fn question(packet: &[u8]) -> (String, u16, usize) {
    let mut position = 12;
    let mut labels = Vec::new();
    while packet[position] != 0 {
        let length = usize::from(packet[position]);
        labels.push(String::from_utf8_lossy(&packet[position + 1..position + 1 + length]).into_owned());
        position += 1 + length;
    }
    let end = position + 5;
    (labels.join("."), u16::from_be_bytes([packet[end - 4], packet[end - 3]]), end)
}

/// The payload of option 65001 in the query's OPT record, if any.
fn directive(packet: &[u8], end: usize) -> Option<Vec<u8>> {
    let rest = packet.get(end..)?;
    // One additional record: root name, TYPE 41, CLASS, TTL, RDLEN.
    if rest.len() < 11 || rest[0] != 0 || rest[1..3] != [0, 41] {
        return None;
    }
    let mut options = &rest[11..];
    while options.len() >= 4 {
        let code = u16::from_be_bytes([options[0], options[1]]);
        let length = usize::from(u16::from_be_bytes([options[2], options[3]]));
        let data = options.get(4..4 + length)?;
        if code == 65001 {
            return Some(data.to_vec());
        }
        options = &options[4 + length..];
    }
    None
}

impl Fake {
    fn start(fakeip: bool) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut packet = [0u8; 1500];
            while let Ok((length, peer)) = socket.recv_from(&mut packet) {
                let query = &packet[..length];
                let (name, qtype, end) = question(query);
                record
                    .lock()
                    .unwrap()
                    .push((name.clone(), qtype, directive(query, end)));
                let first = name.split('.').next().unwrap_or("");
                let answer: Option<Vec<u8>> = if fakeip {
                    (qtype == 1).then(|| vec![28, 0, 0, 1])
                } else if first.starts_with("none") {
                    None
                } else if qtype == 1 {
                    Some(if first.starts_with("cn") {
                        vec![223, 5, 5, 5]
                    } else if first.starts_with("apple") {
                        vec![17, 1, 1, 1]
                    } else if first.starts_with("far") {
                        vec![8, 8, 8, 8]
                    } else {
                        vec![223, 6, 6, 6]
                    })
                } else if qtype == 28 && first.starts_with("far") {
                    let mut data = vec![0x20, 0x01, 0x0d, 0xb8];
                    data.extend([0; 11]);
                    data.push(1);
                    Some(data)
                } else {
                    None
                };
                let mut reply = vec![
                    query[0], query[1], 0x81, 0x80, 0, 1, 0, u8::from(answer.is_some()), 0, 0, 0, 0,
                ];
                reply.extend_from_slice(&query[12..end]);
                if let Some(data) = answer {
                    reply.extend_from_slice(&[0xc0, 0x0c]);
                    reply.extend_from_slice(&qtype.to_be_bytes());
                    reply.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                    reply.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
                    reply.extend_from_slice(&data);
                }
                let _ = socket.send_to(&reply, peer);
            }
        });
        Self { port, seen }
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }

    fn last(&self, name: &str) -> Option<(u16, Option<Vec<u8>>)> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(seen, _, _)| seen == name)
            .map(|(_, qtype, option)| (*qtype, option.clone()))
    }
}

fn shipped() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config")
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Tree(PathBuf);

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The configuration tree: the shipped flow, fake data and upstreams.
fn tree(name: &str, upstream: &Fake, singbox: &Fake, flags: &str) -> Tree {
    let root = std::env::temp_dir().join(format!("atom-dryrun-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for dir in ["sub_config", "rule", "cache", "gen", "webinfo"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    let source = shipped();
    for file in SHIPPED {
        std::fs::copy(source.join(file), root.join(file)).unwrap();
    }
    // The flow file as it ships; only the listeners, the API, the log and the
    // included files the fakes replace or leave out differ.
    let main = std::fs::read_to_string(source.join("config_custom.yaml")).unwrap();
    let mut out = String::new();
    for line in main.lines() {
        let dropped = ["adguard.yaml", "webinfo.yaml", "requery.yaml"]
            .iter()
            .any(|file| line.contains(&format!("\"sub_config/{file}\"")));
        if dropped || line.trim_start().starts_with("http: ") || line.trim_start().starts_with("api:") {
            continue;
        }
        if line.trim_start().starts_with("file: ") {
            out.push_str(&line.replace("/tmp/mosdns.log", &root.join("log.txt").display().to_string()));
        } else {
            out.push_str(&line.replace("\":53\"", &format!("\"127.0.0.1:{}\"", free_port())));
        }
        out.push('\n');
    }
    std::fs::write(root.join("config_custom.yaml"), out).unwrap();
    // The result sequences as they ship, sing-box at the fake.
    let forward = std::fs::read_to_string(source.join("sub_config/forward_1.yaml"))
        .unwrap()
        .replace("udp://127.0.0.1:6666", &format!("udp://127.0.0.1:{}", singbox.port));
    std::fs::write(root.join("sub_config/forward_1.yaml"), forward).unwrap();
    let up = format!("udp://127.0.0.1:{}", upstream.port);
    std::fs::write(
        root.join("sub_config/settings.yaml"),
        "plugins:\n  - {tag: main_proxy, type: socks5_proxy, args: {addr: '127.0.0.1:1'}}\n  - {tag: client_ecs, type: ecs_address, args: {addr: '2408:8888::8'}}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("sub_config/forward_local.yaml"),
        format!("plugins:\n  - {{tag: domestic, type: aliapi, args: {{upstreams: [{{tag: d1, addr: '{up}'}}]}}}}\n"),
    )
    .unwrap();
    std::fs::write(
        root.join("sub_config/forward_nocn.yaml"),
        format!("plugins:\n  - {{tag: foreign, type: aliapi, args: {{upstreams: [{{tag: f1, addr: '{up}'}}]}}}}\n"),
    )
    .unwrap();
    // `sequence_google_node` as it ships.
    std::fs::write(
        root.join("sub_config/forward_nocn_ecs.yaml"),
        format!(
            "plugins:\n  - {{tag: foreignecs, type: aliapi, args: {{upstreams: [{{tag: e1, addr: '{up}'}}]}}}}\n  - tag: sequence_google_node\n    type: sequence\n    args:\n      - exec: ecs $client_ecs\n      - exec: $cache_google_node\n      - exec: flow_setter sequence=sequence_google_node upstream=foreignecs\n      - exec: $foreignecs\n      - exec: cname_remover\n"
        ),
    )
    .unwrap();
    std::fs::write(
        root.join("sub_config/rule_set.yaml"),
        "plugins:\n  - {tag: direct_ip, type: ip_set, args: {files: [rule/direct_ip.txt]}}\n  - {tag: rewrite, type: rewrite, args: {files: [rule/rewrite.txt], dns: $sequence_local_in}}\n  - {tag: geosite_cn, type: domain_set_light, args: {files: [rule/cn.txt]}}\n  - {tag: geosite_no_cn, type: domain_set_light, args: {files: [rule/nocn.txt]}}\n  - {tag: geoip_cn, type: ip_set, args: {files: [rule/geoip.txt]}}\n  - tag: unified_matcher1\n    type: domain_mapper\n    args:\n      default_mark: 17\n      default_tag: x\n      rules:\n        - {tag: geosite_no_cn, mark: 14, output_tag: nocn}\n        - {tag: geosite_cn, mark: 16, output_tag: cn}\n",
    )
    .unwrap();
    std::fs::write(
        root.join("sub_config/atom_rules.yaml"),
        "plugins:\n  - tag: atom_rules\n    type: atom_rules\n    args:\n      route_ecs: {foreignecs: $client_ecs}\n      marks: {proxy: 41, direct: 42, block: 40, route: 43}\n      mapper: unified_matcher1\n      builtin: [geosite_cn, geosite_no_cn]\n",
    )
    .unwrap();
    std::fs::write(root.join("rule/direct_ip.txt"), "17.0.0.0/8\n").unwrap();
    std::fs::write(root.join("rule/geoip.txt"), "223.0.0.0/8\n").unwrap();
    std::fs::write(root.join("rule/cn.txt"), "domain:cnsite.test\n").unwrap();
    std::fs::write(root.join("rule/nocn.txt"), "domain:global.test\n").unwrap();
    std::fs::write(root.join("rule/rewrite.txt"), "full:nas.test 192.0.2.9\nfull:alias.test cnalias.test\n").unwrap();
    std::fs::write(root.join("webinfo/settings.json"), flags).unwrap();
    std::fs::write(
        root.join("webinfo/atom_rules.json"),
        r#"{"version": 1, "rules": [
          {"id": "r-ai", "enabled": true, "remark": "AI", "match": {"suffix": ["ai.test"]}, "action": {"type": "proxy", "group_id": "g-ai"}},
          {"id": "r-off", "enabled": false, "remark": "off", "match": {"suffix": ["cnsite.test"]}, "action": {"type": "block"}},
          {"id": "r-dr", "enabled": true, "remark": "直连", "match": {"suffix": ["dr.test"]}, "action": {"type": "direct"}},
          {"id": "r-kid", "enabled": true, "remark": "kid", "match": {"suffix": ["games.test"], "client": ["10.0.0.5"]}, "action": {"type": "block"}},
          {"id": "r-dns", "enabled": true, "remark": "nocache", "match": {"suffix": ["ddns.test"]}, "action": {"type": "direct"}, "dns": "foreign", "cache": false}
        ]}"#,
    )
    .unwrap();
    Tree(root)
}

struct Snapshot {
    caches: Vec<u64>,
    learned: Vec<Vec<(String, u32)>>,
    top: usize,
    upstream: usize,
    singbox: usize,
    ledger: Option<String>,
    rotation: u64,
}

fn snapshot(host: &HostAssembly, upstream: &Fake, singbox: &Fake, name: &str) -> Snapshot {
    let config = host.config();
    let learner = &config.local.learners[0].runtime;
    Snapshot {
        caches: config
            .caches
            .iter()
            .map(|cache| host.cache().get(cache.id).map_or(0, |store| store.len()))
            .collect(),
        learned: learner
            .category_tags()
            .map(str::to_owned)
            .collect::<Vec<_>>()
            .iter()
            .map(|tag| learner.names(tag))
            .collect(),
        top: config.local.domain_outputs.iter().map(|o| o.runtime.key_count()).sum(),
        upstream: upstream.count(),
        singbox: singbox.count(),
        ledger: crate::atom_ledger::binding_of(name).map(|binding| format!("{binding:?}")),
        rotation: host.forwards_handle().rotation_now(),
    }
}

fn dry(host: &HostAssembly, name: &str, qtype: u16, client: Option<&str>) -> Value {
    let config = host.config();
    let forwards = host.forwards_handle();
    let rules = config.local.atom_rules.clone().unwrap();
    let request = super::Request {
        domain: name.to_owned(),
        client: client.map(|ip| ip.parse::<IpAddr>().unwrap()),
        qtype,
    };
    host.block_on(super::run(config, &forwards, &rules, &request, host.options().request_deadline)).expect("dry run")
}

/// The real query: its answer addresses and rcode.
fn real(host: &HostAssembly, name: &str, qtype: u16, client: &str) -> (Vec<IpAddr>, u8) {
    let raw = super::query_wire(name, qtype).unwrap();
    let (header, question) = atomdns_dns_core::parse_query(&raw).unwrap();
    let forwards = host.forwards_handle();
    let mut checkpoint = crate::observer::ExecutionCheckpoint::new(false);
    let result = host.block_on(crate::execution::execute_request(
        crate::execution::ExecutionRequest {
            client: atomdns_sequence_core::ClientContext::from_peer(
                client.parse().unwrap(),
                atomdns_sequence_core::ClientTransport::Udp,
            ),
            config: host.config(),
            cache: host.cache(),
            options: host.options(),
            raw: &raw,
            header,
            question,
        },
        &forwards,
        atomdns_upstream_core::TransportCancellation::new(),
        &mut checkpoint,
    ));
    let wire = result.response_wire;
    (
        atomdns_dns_core::observe_answer_addresses(&wire).unwrap_or_default(),
        wire[3] & 0x0f,
    )
}

/// The dry run's conclusion matches the real answer, and sing-box got the
/// directive the dry run named (and only from the real query).
fn agree(host: &HostAssembly, upstream: &Fake, singbox: &Fake, name: &str, qtype: u16, client: Option<&str>) -> Value {
    let before = snapshot(host, upstream, singbox, name);
    let view = dry(host, name, qtype, client);
    let after = snapshot(host, upstream, singbox, name);
    assert_eq!(before.caches, after.caches, "{name}: caches");
    assert_eq!(before.learned, after.learned, "{name}: learned entries and hits");
    assert_eq!(before.top, after.top, "{name}: top domains");
    assert_eq!(before.singbox, after.singbox, "{name}: sing-box asked");
    assert_eq!(before.ledger, after.ledger, "{name}: ledger");
    assert_eq!(before.rotation, after.rotation, "{name}: upstream rotation");
    let asked = after.upstream - before.upstream;

    let (ips, rcode) = real(host, name, qtype, client.unwrap_or("192.168.1.9"));
    let conclusion = &view["conclusion"];
    let kind = conclusion["kind"].as_str().unwrap();
    let fakeip = ips.iter().any(|ip| ip.to_string() == "28.0.0.1");
    match kind {
        "proxy" => {
            if qtype == 1 {
                assert!(fakeip, "{name}: {view} vs {ips:?}");
            }
            let (_, option) = singbox.last(name).expect("sing-box asked");
            let expected = match conclusion["directive"].as_str().unwrap() {
                "CLEAR" => vec![1, 2],
                set => {
                    let tag = set.strip_prefix("SET ").unwrap();
                    let mut payload = vec![1, 1];
                    payload.extend_from_slice(tag.as_bytes());
                    payload
                }
            };
            assert_eq!(option.as_deref(), Some(&expected[..]), "{name}: directive");
        }
        "direct" => {
            assert!(!ips.is_empty() && !fakeip, "{name}: {view} vs {ips:?}");
            if let Some(dry_ips) = conclusion["ips"].as_array() {
                let dry_ips: Vec<String> = dry_ips.iter().map(|ip| ip.as_str().unwrap().to_owned()).collect();
                let real_ips: Vec<String> = ips.iter().map(ToString::to_string).collect();
                assert_eq!(dry_ips, real_ips, "{name}");
            }
        }
        "block" | "empty" => assert!(ips.is_empty() && rcode == 0, "{name}: {view} vs {ips:?} {rcode}"),
        other => panic!("{name}: {other} {view}"),
    }
    let mut view = view;
    view["asked"] = asked.into();
    view
}

#[test]
fn dry_runs_match_the_real_flow_and_leave_no_trace() {
    let upstream = Fake::start(false);
    let singbox = Fake::start(true);
    let tree = tree("compat", &upstream, &singbox, r#"{"version": 1}"#);
    let config = crate::config::load_and_compile(&tree.0.join("config_custom.yaml")).expect("compiles");
    let host = HostAssembly::with_options(config, HostOptions::default()).unwrap();
    let check = |name: &str, qtype: u16, client: Option<&str>| agree(&host, &upstream, &singbox, name, qtype, client);

    // A proxy rule: SET its group, no upstream asked.
    let view = check("api.ai.test", 1, None);
    assert_eq!(view["conclusion"]["kind"], "proxy", "{view}");
    assert_eq!(view["conclusion"]["directive"], "SET g-ai");
    assert_eq!(view["asked"], 0);
    let rules = view["steps"].as_array().unwrap().iter().find(|s| s["key"] == "rules").unwrap();
    assert_eq!(rules["result"], "hit");
    assert_eq!(rules["rules"][0]["status"], "hit");
    assert_eq!(view["branch"], Value::Null);

    // A direct rule: the domestic group, its cache, the real address.
    let view = check("www.dr.test", 1, None);
    assert_eq!(view["conclusion"]["kind"], "direct", "{view}");
    assert_eq!(view["conclusion"]["upstream"], "domestic");
    assert_eq!(view["conclusion"]["caches"], serde_json::json!(["国内查询缓存"]));
    assert_eq!(view["conclusion"]["ips"], serde_json::json!(["223.6.6.6"]));
    // The rules before it: hit at 3, one disabled, one miss.
    let rules = view["steps"].as_array().unwrap().iter().find(|s| s["key"] == "rules").unwrap();
    let statuses: Vec<&str> = rules["rules"].as_array().unwrap().iter().map(|r| r["status"].as_str().unwrap()).collect();
    assert_eq!(statuses, ["miss", "off", "hit"]);

    // A direct rule with an upstream group and no cache.
    let view = check("x.ddns.test", 1, None);
    assert_eq!(view["conclusion"]["upstream"], "foreign", "{view}");
    assert_eq!(view["conclusion"]["caches"], serde_json::json!([]));

    // A client rule: only for that client.
    let view = check("www.games.test", 1, Some("10.0.0.5"));
    assert_eq!(view["conclusion"]["kind"], "block", "{view}");
    let view = check("www.games.test", 1, Some("10.0.0.6"));
    assert_ne!(view["conclusion"]["kind"], "block", "{view}");

    // geosite: cn direct, non-cn FakeIP with CLEAR (Final).
    let view = check("www.cnsite.test", 1, None);
    assert_eq!((&view["conclusion"]["kind"], &view["branch"]), (&"direct".into(), &"geosite_cn".into()), "{view}");
    let view = check("www.global.test", 1, None);
    assert_eq!(view["conclusion"]["directive"], "CLEAR", "{view}");
    assert_eq!(view["conclusion"]["outbound"], "final");
    assert_eq!(view["branch"], "geosite_no_cn");
    assert_eq!(view["asked"], 0);

    // The probe: a Chinese address, direct_ip, a foreign one, none.
    let view = check("cnprobe.test", 1, None);
    assert_eq!((&view["conclusion"]["kind"], &view["branch"]), (&"direct".into(), &"rest".into()), "{view}");
    assert_eq!(view["asked"], 1);
    let rest = view["steps"].as_array().unwrap().iter().find(|s| s["key"] == "rest").unwrap();
    assert_eq!(rest["would_learn"], serde_json::json!(["记忆直连"]), "{rest}");
    let view = check("apple.test", 1, None);
    assert_eq!(view["conclusion"]["kind"], "direct", "{view}");
    let view = check("faraway.test", 1, None);
    assert_eq!(view["conclusion"]["kind"], "proxy", "{view}");
    assert_eq!(view["conclusion"]["directive"], "CLEAR");
    let view = check("nonehere.test", 1, None);
    assert_eq!(view["conclusion"]["kind"], "empty", "{view}");

    // Learned by the real queries: now remembered, and the dry run says so
    // (without counting a hit: `agree` compares the hit counts).
    let view = check("faraway.test", 1, None);
    assert_eq!(view["branch"], "remember_proxy", "{view}");
    assert_eq!(view["asked"], 0);
    let view = check("cnprobe.test", 1, None);
    assert_eq!(view["branch"], "remember_direct", "{view}");

    // AAAA: a foreign IPv6 → proxy; none → learned no-V6, then empty.
    let view = check("faraway6.test", 28, None);
    assert_eq!(view["conclusion"]["kind"], "proxy", "{view}");
    let view = check("cn6.test", 28, None);
    assert_eq!(view["conclusion"]["kind"], "empty", "{view}");
    let view = check("cn6.test", 28, None);
    assert_eq!(view["branch"], "empty", "{view}");
    let step = view["steps"].as_array().unwrap().iter().find(|s| s["key"] == "no_v6").unwrap();
    assert_eq!(step["result"], "hit", "{view}");

    // A rewrite answers first.
    let view = check("nas.test", 1, None);
    assert_eq!(view["conclusion"]["via"], "rewrite", "{view}");
    assert_eq!(view["steps"][0]["result"], "hit");
    assert_eq!(view["conclusion"]["ips"], serde_json::json!(["192.0.2.9"]));
    // An IPv4 target answers AAAA empty; a domain target is resolved.
    let view = check("nas.test", 28, None);
    assert_eq!((&view["conclusion"]["kind"], &view["conclusion"]["via"]), (&"empty".into(), &"rewrite".into()), "{view}");
    let view = check("alias.test", 1, None);
    assert_eq!(view["conclusion"]["ips"], serde_json::json!(["223.5.5.5"]), "{view}");

    // The order of the steps is the flow's.
    let view = dry(&host, "unlisted-two.test", 1, None);
    let keys: Vec<&str> = view["steps"].as_array().unwrap().iter().map(|s| s["key"].as_str().unwrap()).collect();
    assert_eq!(
        keys,
        ["rewrite", "block_qtypes", "block_aaaa", "rules", "no_v4", "geosite_no_cn", "geosite_cn", "remember_proxy", "remember_direct", "rest"],
        "{view}"
    );
}

#[test]
fn safe_mode_probes_the_foreign_group_with_ecs_and_block_aaaa_answers_empty() {
    let upstream = Fake::start(false);
    let singbox = Fake::start(true);
    let tree = tree(
        "safe",
        &upstream,
        &singbox,
        r#"{"version": 1, "flags": {"core_mode": "safe", "block_aaaa": true}}"#,
    );
    let config = crate::config::load_and_compile(&tree.0.join("config_custom.yaml")).expect("compiles");
    let host = HostAssembly::with_options(config, HostOptions::default()).unwrap();
    let view = agree(&host, &upstream, &singbox, "cnsafe.test", 1, None);
    assert_eq!(view["conclusion"]["upstream"], "foreignecs", "{view}");
    assert_eq!(view["conclusion"]["ecs"], "2408:8888::/48", "{view}");
    assert!(view["conclusion"]["caches"].as_array().unwrap().iter().any(|c| c == "全局缓存·安全模式"), "{view}");
    let view = agree(&host, &upstream, &singbox, "faraway.test", 28, None);
    assert_eq!(view["conclusion"]["kind"], "empty", "{view}");
    assert_eq!(view["conclusion"]["via"], "block_aaaa", "{view}");
    let _ = Duration::ZERO;
}

#[test]
fn prefer_ipv4_answers_aaaa_empty_when_a_has_an_answer() {
    let upstream = Fake::start(false);
    let singbox = Fake::start(true);
    let tree = tree("prefer", &upstream, &singbox, r#"{"version": 1, "flags": {"prefer_v4": true}}"#);
    let config = crate::config::load_and_compile(&tree.0.join("config_custom.yaml")).expect("compiles");
    let host = HostAssembly::with_options(config, HostOptions::default()).unwrap();
    // A has 8.8.8.8, AAAA 2001:db8::1: AAAA is answered empty.
    let view = agree(&host, &upstream, &singbox, "farv6.test", 28, None);
    assert_eq!((&view["conclusion"]["kind"], &view["conclusion"]["via"]), (&"empty".into(), &"prefer_v4".into()), "{view}");
    // Nothing remembered: the next dry run asks the reference again.
    let view = dry(&host, "farv6.test", 28, None);
    assert_eq!(view["conclusion"]["via"], "prefer_v4", "{view}");
    // No A answer: AAAA goes on (none either here: empty by the probe).
    let view = agree(&host, &upstream, &singbox, "nonev6.test", 28, None);
    assert_ne!(view["conclusion"]["via"], "prefer_v4", "{view}");
}
