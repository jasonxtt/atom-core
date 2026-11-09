use std::collections::BTreeSet;
use std::net::UdpSocket;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::*;
use crate::atom_rules::{Action, Marks, Match, RuleInput};

fn wire(name: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in name.split('.') {
        wire.push(u8::try_from(label.len()).unwrap());
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire
}

fn set(tag: &str) -> Binding {
    Binding::Set(Arc::from(tag))
}

/// The question name and the 65001 payload of a query (`None`: none).
fn directive_of(query: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut at = 12;
    while query[at] != 0 {
        at += 1 + usize::from(query[at]);
    }
    let name = query[12..=at].to_vec();
    at += 5; // root, qtype, qclass
    if u16::from_be_bytes([query[10], query[11]]) == 0 {
        return (name, None);
    }
    at += 1 + 2 + 2 + 4; // OPT owner, type, class, ttl
    let len = usize::from(u16::from_be_bytes([query[at], query[at + 1]]));
    let mut options = &query[at + 2..at + 2 + len];
    while options.len() >= 4 {
        let code = u16::from_be_bytes([options[0], options[1]]);
        let size = usize::from(u16::from_be_bytes([options[2], options[3]]));
        if code == crate::edns_directive::OPTION_CODE {
            return (name, Some(options[4..4 + size].to_vec()));
        }
        options = &options[4 + size..];
    }
    (name, None)
}

#[test]
fn the_lru_drops_the_least_recently_recorded_name() {
    let mut lru = Lru::new(2);
    lru.record(&wire("a.com"), set("g-1"));
    lru.record(&wire("b.com"), Binding::Clear);
    // Recording a again makes b the oldest.
    lru.record(&wire("a.com"), set("g-2"));
    lru.record(&wire("c.com"), set("g-3"));
    assert_eq!(lru.len(), 2);
    assert_eq!(lru.get(&wire("a.com")), Some(&set("g-2")));
    assert_eq!(lru.get(&wire("b.com")), None);
    assert_eq!(
        lru.snapshot(),
        [(wire("a.com"), set("g-2")), (wire("c.com"), set("g-3"))]
    );
    lru.clear();
    assert_eq!(lru.len(), 0);
    assert!(lru.snapshot().is_empty());
}

#[test]
fn a_recomputation_sends_only_what_changes() {
    let entries = [
        (wire("x.com"), set("g-x")),         // proxy X → Y: SET Y
        (wire("same.com"), set("g-x")),      // still X: nothing
        (wire("d.com"), set("g-x")),         // → direct: SET direct
        (wire("b.com"), Binding::Clear),     // → block: SET block
        (wire("gone.com"), set("g-x")),      // no rule: CLEAR
        (wire("final.com"), Binding::Clear), // still no rule: nothing
    ];
    let decide = |name: &[u8]| match crate::config::presentation_name(name)
        .as_deref()
        .map(|name| name.trim_end_matches('.'))
    {
        Some("x.com") => Some(Verdict::Proxy(Arc::from("g-y"))),
        Some("same.com") => Some(Verdict::Proxy(Arc::from("g-x"))),
        Some("d.com") => Some(Verdict::Direct),
        Some("b.com") => Some(Verdict::Block),
        _ => None,
    };
    assert_eq!(
        plan(&entries, decide),
        [
            (wire("x.com"), set("g-y")),
            (wire("d.com"), set("direct")),
            (wire("b.com"), set("block")),
            (wire("gone.com"), Binding::Clear),
        ]
    );
}

#[test]
fn a_directive_query_carries_set_or_clear() {
    let name = wire("Mixed.Example.com");
    let query = directive_query(0x1234, &name, &set("g-y")).unwrap();
    assert_eq!(&query[..2], &[0x12, 0x34]);
    assert_eq!(
        directive_of(&query),
        (name.clone(), Some(b"\x01\x01g-y".to_vec()))
    );
    let query = directive_query(1, &name, &Binding::Clear).unwrap();
    assert_eq!(directive_of(&query), (name, Some(vec![1, 2])));
}

fn rules_without_proxy() -> AtomRules {
    AtomRules::load(
        Path::new(""),
        Marks {
            proxy: 41,
            direct: 42,
            block: 40,
        },
        None,
        String::new(),
        Vec::new(),
        None,
    )
    .unwrap()
}

fn rule(matches: Match, action: Action) -> RuleInput {
    RuleInput {
        enabled: true,
        remark: String::new(),
        matches,
        action,
    }
}

fn suffix(name: &str) -> Match {
    Match {
        suffix: vec![name.to_owned()],
        ..Match::default()
    }
}

fn proxy(group: &str) -> Action {
    Action::Proxy {
        group_id: group.to_owned(),
    }
}

#[test]
fn a_recomputation_skips_rules_with_a_client_condition() {
    let rules = rules_without_proxy();
    rules
        .create(
            rule(
                Match {
                    client: vec!["10.0.0.1".to_owned()],
                    ..suffix("a.com")
                },
                Action::Direct,
            ),
            None,
            Some("r-lan"),
            None,
        )
        .unwrap();
    rules
        .create(
            rule(
                Match {
                    client: vec!["10.0.0.2".to_owned()],
                    ..Match::default()
                },
                Action::Block,
            ),
            None,
            Some("r-lan"),
            None,
        )
        .unwrap();
    rules
        .create(rule(suffix("a.com"), proxy("g-x")), None, None, None)
        .unwrap();
    // The client rules decide their clients' queries, which never reach
    // sing-box; the binding is everyone else's.
    assert_eq!(
        rules.decide(&wire("www.a.com"), 0),
        Some(Verdict::Proxy(Arc::from("g-x")))
    );
    assert_eq!(rules.decide(&wire("nas.lan"), 0), Some(Verdict::Direct));
    assert_eq!(rules.decide(&wire("b.com"), 0), None);
    assert_eq!(
        rules
            .test("www.a.com", "10.0.0.1".parse().ok(), 0)
            .unwrap()
            .1
            .action,
        Action::Direct
    );
}

/// The question names and 65001 payloads a fake `dns-in` received.
type Received = Arc<Mutex<Vec<(Vec<u8>, Option<Vec<u8>>)>>>;

/// A stand-in for sing-box's `dns-in`: answers every query except those for
/// `silent` names and records the directives it got.
struct FakeDnsIn {
    address: SocketAddr,
    got: Received,
}

impl FakeDnsIn {
    fn start(silent: BTreeSet<Vec<u8>>) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = socket.local_addr().unwrap();
        let got: Received = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&got);
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buffer) {
                let query = &buffer[..len];
                let (name, directive) = directive_of(query);
                seen.lock().unwrap().push((name.clone(), directive));
                if silent.contains(&name) {
                    continue;
                }
                let mut reply = query.to_vec();
                reply[2] |= 0x80;
                let _ = socket.send_to(&reply, peer);
            }
        });
        Self { address, got }
    }

    fn got(&self, name: &str) -> Vec<Option<Vec<u8>>> {
        let name = wire(name);
        self.got
            .lock()
            .unwrap()
            .iter()
            .filter(|(seen, _)| *seen == name)
            .map(|(_, directive)| directive.clone())
            .collect()
    }
}

fn host(dns_in: SocketAddr) -> crate::atom_singbox::Host {
    crate::atom_singbox::Host {
        binary: "/bin/true".into(),
        dir: "/nonexistent".into(),
        reload: vec!["true".into()],
        clash_api: "127.0.0.1:9".parse().unwrap(),
        dns_in,
        atomdns: "127.0.0.1:53".parse().unwrap(),
        redirect_port: 7892,
        tproxy_port: 7893,
        resolver_group: "domestic".into(),
        nft_table: None,
        nft: vec!["nft".into()],
    }
}

#[test]
fn a_resync_sends_the_changes_and_keeps_what_failed() {
    let silent = wire("www.ledger-e.test");
    let fake = FakeDnsIn::start([silent.clone()].into());
    let rules = AtomRules::load(
        Path::new(""),
        Marks {
            proxy: 41,
            direct: 42,
            block: 40,
        },
        None,
        String::new(),
        Vec::new(),
        Some(host(fake.address)),
    )
    .unwrap();
    for (name, action) in [
        ("ledger-a.test", proxy("final")),
        ("ledger-d.test", Action::Direct),
        ("ledger-e.test", Action::Block),
        ("ledger-f.test", proxy("g-default")),
    ] {
        rules
            .create(rule(suffix(name), action), None, None, None)
            .unwrap();
    }
    // What sing-box was told before.
    let ledger = Mutex::new(Lru::new(16));
    for (name, binding) in [
        ("www.ledger-a.test", set("g-default")),
        ("www.ledger-b.test", set("g-default")),
        ("www.ledger-c.test", Binding::Clear),
        ("www.ledger-d.test", set("g-default")),
        ("www.ledger-e.test", set("g-default")),
        ("www.ledger-f.test", set("g-default")),
    ] {
        ledger.lock().unwrap().record(&wire(name), binding);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let done = runtime
        .block_on(resync_with(&ledger, &rules, |_| 0, "rules"))
        .unwrap();
    assert_eq!(
        fake.got("www.ledger-a.test"),
        [Some(b"\x01\x01final".to_vec())]
    );
    assert_eq!(fake.got("www.ledger-b.test"), [Some(vec![1, 2])]);
    assert!(fake.got("www.ledger-c.test").is_empty());
    assert_eq!(
        fake.got("www.ledger-d.test"),
        [Some(b"\x01\x01direct".to_vec())]
    );
    // Unanswered: tried twice, then kept as it was.
    assert_eq!(
        fake.got("www.ledger-e.test"),
        [
            Some(b"\x01\x01block".to_vec()),
            Some(b"\x01\x01block".to_vec())
        ]
    );
    assert!(fake.got("www.ledger-f.test").is_empty());
    {
        let ledger = ledger.lock().unwrap();
        assert_eq!(ledger.get(&wire("www.ledger-a.test")), Some(&set("final")));
        assert_eq!(
            ledger.get(&wire("www.ledger-b.test")),
            Some(&Binding::Clear)
        );
        assert_eq!(ledger.get(&wire("www.ledger-d.test")), Some(&set("direct")));
        assert_eq!(ledger.get(&silent), Some(&set("g-default")));
        assert_eq!(
            ledger.get(&wire("www.ledger-f.test")),
            Some(&set("g-default"))
        );
    }
    assert_eq!(done.trigger, "rules");
    assert_eq!(done.changed, 4, "{done:?}");
    assert_eq!(done.failed, 1, "{done:?}");
    assert!(done.error.contains("no answer"), "{done:?}");
    // The next recomputation tries the failed one again, and only it.
    let again = runtime
        .block_on(resync_with(&ledger, &rules, |_| 0, "rules"))
        .unwrap();
    assert_eq!((again.changed, again.failed), (1, 1));
    assert_eq!(fake.got("www.ledger-e.test").len(), 4);
    assert_eq!(fake.got("www.ledger-a.test").len(), 1);
}
