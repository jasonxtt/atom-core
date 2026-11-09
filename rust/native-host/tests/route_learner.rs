//! `route_learner` / `route_learn`: learning by condition, the merge with a
//! `domain_mapper`, per-entry expiry, the state file, the management routes,
//! the hand-over to a new generation and the `requery` flush rule. Real UDP
//! queries and the real management listener; the upstream is a loopback mock.
//! No test reaches the public network.

#![allow(clippy::too_many_lines)]

use std::net::UdpSocket as StdUdpSocket;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use atomdns_native_host::{BoundHost, CompiledConfig, HostAssembly, HostOptions};
use atomdns_upstream_core::TransportCancellation;

// ----- fixtures -------------------------------------------------------------

struct Tree(PathBuf);

impl Tree {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("route-learner-{name}-{}", std::process::id()));
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

/// A loopback upstream that answers by the first label of the name:
/// `direct*` A -> 192.0.2.7, `proxy*` A -> 198.51.100.7, `servfail*` -> rcode 2,
/// `nx*` -> rcode 3, `v6yes*` AAAA -> `2001:db8::1`, anything else A ->
/// 203.0.113.9 and AAAA -> an empty NOERROR.
struct Upstream {
    address: String,
    seen: Arc<Mutex<Vec<(String, u16)>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

fn question(packet: &[u8]) -> (String, u16, usize) {
    let mut position = 12;
    let mut labels = Vec::new();
    while packet[position] != 0 {
        let length = usize::from(packet[position]);
        labels.push(
            String::from_utf8_lossy(&packet[position + 1..position + 1 + length]).into_owned(),
        );
        position += 1 + length;
    }
    let end = position + 5;
    let qtype = u16::from_be_bytes([packet[end - 4], packet[end - 3]]);
    (labels.join("."), qtype, end)
}

impl Upstream {
    fn start() -> Self {
        let socket = StdUdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let address = socket.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (record, stopped) = (Arc::clone(&seen), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            let mut packet = vec![0_u8; 4096];
            while !stopped.load(Ordering::SeqCst) {
                let Ok((length, client)) = socket.recv_from(&mut packet) else {
                    continue;
                };
                let query = &packet[..length];
                let (name, qtype, end) = question(query);
                record.lock().unwrap().push((name.clone(), qtype));
                let answer: Option<Vec<u8>> = if name.starts_with("direct") && qtype == 1 {
                    Some(vec![192, 0, 2, 7])
                } else if name.starts_with("proxy") && qtype == 1 {
                    Some(vec![198, 51, 100, 7])
                } else if name.starts_with("v6yes") && qtype == 28 {
                    let mut data = vec![0x20, 0x01, 0x0d, 0xb8];
                    data.extend([0; 11]);
                    data.push(1);
                    Some(data)
                } else if qtype == 1 {
                    Some(vec![203, 0, 113, 9])
                } else {
                    None
                };
                let rcode: u8 = if name.starts_with("servfail") {
                    2
                } else if name.starts_with("nx") {
                    3
                } else {
                    0
                };
                let answer = answer.filter(|_| rcode == 0);
                let mut reply = vec![
                    query[0],
                    query[1],
                    0x81,
                    0x80 | rcode,
                    0,
                    1,
                    0,
                    u8::from(answer.is_some()),
                    0,
                    0,
                    0,
                    0,
                ];
                reply.extend_from_slice(&query[12..end]);
                if let Some(data) = answer {
                    reply.extend_from_slice(&[0xc0, 0x0c]);
                    reply.extend_from_slice(&qtype.to_be_bytes());
                    reply.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
                    reply.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
                    reply.extend_from_slice(&data);
                }
                let _ = socket.send_to(&reply, client);
            }
        });
        Self {
            address,
            seen,
            stop,
            thread: Some(thread),
        }
    }

    fn count(&self, name: &str, qtype: u16) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|(n, t)| n == name && *t == qtype)
            .count()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

const CATEGORIES: &str = r#"      categories:
        - {tag: my_sv4list, mark: 4, label: "SPECIAL", source: "r_special", ttl: 1000}
        - {tag: my_realiplist, mark: 11, label: "DIRECT", source: "r_direct", ttl: 100}
        - {tag: my_fakeiplist, mark: 12, label: "PROXY", source: "r_proxy", ttl: 100}
        - {tag: my_nov6list, mark: 3, label: "NOV6", ttl: 60}
        - {tag: my_nov4list, mark: 2, label: "NOV4", ttl: 60}
"#;

/// The host. Learned marks answer: proxy (12) -> rcode 12, direct (11) ->
/// rcode 11, special (4) -> rcode 4, no-V6 (3) on AAAA -> rcode 6; otherwise
/// the upstream is asked and the rules learn from its answer.
fn config(tree: &Tree, ports: &Ports, upstream: &Upstream, extra: &str, learner_args: &str) {
    let yaml = format!(
        r#"log: {{level: error}}
api: {{http: "127.0.0.1:{api}"}}
plugins:
  - tag: fwd
    type: forward
    args: {{upstreams: [{{addr: "udp://{upstream}"}}]}}
  - tag: cache
    type: cache
    args: {{dump_file: "cache/c.gz"}}
  - {{tag: wl, type: domain_set_light, args: {{files: ["rule/wl.txt"]}}}}
  - tag: unified
    type: domain_mapper
    args:
      default_mark: 17
      default_tag: "UNMATCHED"
      rules:
        - {{tag: wl, mark: 8, output_tag: "STATIC"}}
  - tag: route_learner
    type: route_learner
    args:
      target_mapper: unified
      file: gen/route_learner.json
      write_interval: 3600
{learner_args}{CATEGORIES}
  - {{tag: learn_direct, type: route_learn, args: {{learner: route_learner, learn: [my_realiplist], when: ["qtype 1", "resp_ip 192.0.2.0/24"]}}}}
  - {{tag: learn_proxy, type: route_learn, args: {{learner: route_learner, learn: [my_fakeiplist, my_sv4list], when: ["qtype 1", "resp_ip 198.51.100.0/24"]}}}}
  - {{tag: learn_nov6, type: route_learn, args: {{learner: route_learner, learn: my_nov6list, when: ["qtype 28", "rcode 0 3", "!resp_ip 2000::/3"]}}}}
{extra}  - tag: entry
    type: sequence
    args:
      - exec: $unified
      - matches: fast_mark 12
        exec: reject 12
      - matches: fast_mark 11
        exec: reject 11
      - matches: fast_mark 4
        exec: reject 4
      - matches: [fast_mark 3, "qtype 28"]
        exec: reject 6
      - exec: $cache
      - exec: $fwd
      - exec: $learn_direct
      - exec: $learn_proxy
      - exec: $learn_nov6
  - tag: listener
    type: udp_server
    args: {{entry: entry, listen: "127.0.0.1:{dns}"}}
"#,
        api = ports.api,
        dns = ports.dns,
        upstream = upstream.address,
    );
    tree.write("config.yaml", &yaml);
    tree.write("rule/wl.txt", "domain:static.test\n");
    std::fs::create_dir_all(tree.path("cache")).unwrap();
}

fn compile(tree: &Tree) -> CompiledConfig {
    atomdns_native_host::load_and_compile(&tree.path("config.yaml")).expect("compiles")
}

fn assemble(config: CompiledConfig) -> HostAssembly {
    HostAssembly::with_options(config, HostOptions::default()).expect("assembles")
}

async fn serve(host: &HostAssembly) -> (TransportCancellation, tokio::task::JoinHandle<()>) {
    let bound: BoundHost = host.bind_host().await.expect("binds");
    let shutdown = TransportCancellation::new();
    let scope = shutdown.clone();
    let task = tokio::task::spawn_local(async move {
        bound.serve(scope).await.expect("clean shutdown");
    });
    (shutdown, task)
}

struct Http {
    status: u16,
    body: String,
}

/// A plugin route (`/plugins/...`), served in process: atom step 6 removed
/// them from HTTP.
async fn api(host: &HostAssembly, method: &str, path: &str, body: &str) -> Http {
    assert!(
        path.starts_with("/plugins/"),
        "{path} is not a plugin route"
    );
    let (status, body) = host
        .plugin_request(method, path, body.as_bytes())
        .await
        .unwrap_or((404, b"404 page not found\n".to_vec()));
    Http {
        status,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

fn wire(name: &str, qtype: u16) -> Vec<u8> {
    let mut out = vec![0, 7, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        out.push(u8::try_from(label.len()).unwrap());
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend(qtype.to_be_bytes());
    out.extend([0, 1]);
    out
}

async fn rcode_of(port: u16, name: &str, qtype: u16) -> u8 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket
        .send_to(&wire(name, qtype), ("127.0.0.1", port))
        .await
        .unwrap();
    let mut packet = vec![0; 1500];
    let (length, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut packet))
        .await
        .expect("response in time")
        .unwrap();
    assert!(length >= 12);
    packet[3] & 15
}

async fn a(port: u16, name: &str) -> u8 {
    rcode_of(port, name, 1).await
}

async fn aaaa(port: u16, name: &str) -> u8 {
    rcode_of(port, name, 28).await
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|error| panic!("{error}: {text}"))
}

// ----- tests ------------------------------------------------------------------

#[test]
fn rules_learn_by_condition_and_the_next_query_follows_the_learned_route() {
    let tree = Tree::new("rules");
    let ports = ports();
    let upstream = Upstream::start();
    config(&tree, &ports, &upstream, "", "");
    let host = assemble(compile(&tree));
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        // direct: learned from a 192.0.2.0/24 answer; the next query is routed
        // by the learned mark and never reaches the upstream again.
        assert_eq!(a(ports.dns, "direct1.test").await, 0);
        assert_eq!(a(ports.dns, "Direct1.Test").await, 11);
        assert_eq!(upstream.count("direct1.test", 1), 1);
        // A name whose answer matches no rule is not learned.
        assert_eq!(a(ports.dns, "plain.test").await, 0);
        assert_eq!(a(ports.dns, "plain.test").await, 0);
        // One rule can learn into several categories; the proxy mark wins in
        // the sequence.
        assert_eq!(a(ports.dns, "proxy1.test").await, 0);
        assert_eq!(a(ports.dns, "proxy1.test").await, 12);
        let special = api(&host, "GET", "/plugins/my_sv4list/show", "").await;
        assert!(special.body.contains("proxy1.test"), "{}", special.body);
        // no-V6: an empty NOERROR and an NXDOMAIN answer to AAAA are learned,
        // a SERVFAIL one is not (the rule asks for rcode 0 or 3), and an
        // answer with a global IPv6 address is not.
        assert_eq!(aaaa(ports.dns, "v6none.test").await, 0);
        assert_eq!(aaaa(ports.dns, "v6none.test").await, 6);
        assert_eq!(aaaa(ports.dns, "nx1.test").await, 3);
        assert_eq!(aaaa(ports.dns, "nx1.test").await, 6);
        assert_eq!(aaaa(ports.dns, "servfail1.test").await, 2);
        assert_eq!(aaaa(ports.dns, "servfail1.test").await, 2);
        assert_eq!(aaaa(ports.dns, "v6yes1.test").await, 0);
        assert_eq!(aaaa(ports.dns, "v6yes1.test").await, 0);
        // The learned no-V6 mark does not affect an A query for the same name.
        assert_eq!(a(ports.dns, "v6none.test").await, 0);
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn a_warm_response_keeps_the_current_learned_label_in_the_same_generation() {
    let tree = Tree::new("warm-label");
    let ports = ports();
    let upstream = Upstream::start();
    config(
        &tree,
        &ports,
        &upstream,
        "  - tag: empty_mapper\n    type: domain_mapper\n    args: {rules: []}\n",
        "",
    );
    let yaml = tree
        .text("config.yaml")
        .replace(
            "      - matches: fast_mark 11\n        exec: reject 11\n",
            "",
        )
        .replace(
            "entry: entry, listen:",
            "enable_audit: true, entry: entry, listen:",
        )
        .replace(
            "      - exec: $unified\n",
            "      - exec: $unified\n      - exec: $empty_mapper\n",
        );
    tree.write("config.yaml", &yaml);
    let compiled = compile(&tree);
    let mapper = compiled.domain_mappers[0].clone();
    let host = assemble(compiled);
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        assert_eq!(a(ports.dns, "direct.static.test").await, 0);
        assert_eq!(
            mapper
                .evaluate(Some("direct.static.test."))
                .domain_set
                .as_deref(),
            Some("DIRECT|STATIC")
        );
        assert_eq!(a(ports.dns, "direct.static.test").await, 0);
        assert_eq!(upstream.count("direct.static.test", 1), 1);
        let audit = host.audit_snapshot();
        let warm = audit
            .records
            .iter()
            .find(|row| row.cache_status == atomdns_native_host::CacheStatus::Hit)
            .expect("warm audit row");
        assert_eq!(warm.matched_rule_source.as_deref(), Some("r_direct|wl"));
        assert_eq!(warm.domain_set.as_deref(), Some("DIRECT|STATIC"));
        assert_eq!(warm.effective_tag.as_deref(), Some("STATIC"));
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn cached_learning_labels_follow_expiry_and_flush_in_every_execution_path() {
    for mode in ["ordinary", "branch", "direct", "nested", "empty"] {
        let tree = Tree::new(&format!("labels-{mode}"));
        let ports = ports();
        let upstream = Upstream::start();
        config(&tree, &ports, &upstream, "", "");
        let yaml = tree.text("config.yaml");
        let yaml = if mode == "direct" {
            yaml.replace("label: \"DIRECT\"", "label: \" DIRECT \"")
                .replace(
                    "default_tag: \"UNMATCHED\"",
                    "default_tag: \"UNMATCHED|FALLBACK\"",
                )
        } else if mode == "empty" {
            yaml.replace("default_tag: \"UNMATCHED\"", "default_tag: \"\"")
        } else {
            yaml
        };
        let prefix = yaml.split("  - tag: entry\n").next().unwrap();
        let successor =
            "      - exec: $fwd\n      - exec: $learn_direct\n      - exec: $learn_proxy\n";
        let (extra, entry) = match mode {
            "ordinary" | "empty" => (String::new(), format!("      - exec: $cache\n{successor}")),
            "nested" => (
                "  - tag: outer\n    type: cache\n    args: {size: 16}\n".to_owned(),
                format!("      - exec: $outer\n      - exec: $cache\n{successor}"),
            ),
            "branch" => (
                format!(
                    "  - tag: cached\n    type: sequence\n    args:\n      - exec: $cache\n{successor}  - tag: fb\n    type: fallback\n    args: {{primary: $cached, secondary: $fwd}}\n"
                ),
                "      - exec: $fb\n".to_owned(),
            ),
            _ => (
                "  - tag: fb\n    type: fallback\n    args: {primary: $cache, secondary: $fwd}\n"
                    .to_owned(),
                format!("      - exec: $fb\n{successor}"),
            ),
        };
        tree.write("config.yaml", &format!("{prefix}{extra}  - tag: entry\n    type: sequence\n    args:\n      - exec: $unified\n{entry}  - tag: listener\n    type: udp_server\n    args: {{enable_audit: true, entry: entry, listen: '127.0.0.1:{dns}'}}\n", dns=ports.dns));
        let compiled = compile(&tree);
        let learner = Rc::clone(&compiled.local.learners[0].runtime);
        let host = assemble(compiled);
        host.block_on(async {
            let (shutdown, task) = serve(&host).await;
            let default_label = if mode == "direct" {
                Some("UNMATCHED|FALLBACK")
            } else if mode == "empty" {
                None
            } else {
                Some("UNMATCHED")
            };
            for (name, learned, cold, source, category, seconds) in [
                (
                    "direct.static.test",
                    "DIRECT|STATIC",
                    Some("STATIC"),
                    Some("wl"),
                    "my_realiplist",
                    101,
                ),
                (
                    "direct.example",
                    "DIRECT",
                    default_label,
                    None,
                    "my_realiplist",
                    101,
                ),
                (
                    "proxy.static.test",
                    "SPECIAL|PROXY|STATIC",
                    Some("STATIC"),
                    Some("wl"),
                    "my_fakeiplist",
                    1001,
                ),
            ] {
                // Cold query learns; the next query is a real warm hit.
                assert_eq!(a(ports.dns, name).await, 0);
                let original_effective = host
                    .audit_snapshot()
                    .records
                    .last()
                    .unwrap()
                    .effective_tag
                    .clone();
                assert_eq!(a(ports.dns, name).await, 0);
                assert_eq!(
                    host.audit_snapshot()
                        .records
                        .last()
                        .unwrap()
                        .domain_set
                        .as_deref(),
                    Some(learned),
                    "{mode} {name}"
                );
                let entries = json(
                    &api(
                        &host,
                        "GET",
                        &format!("/plugins/route_learner/entries?category={category}"),
                        "",
                    )
                    .await
                    .body,
                );
                let row = entries["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["name"] == name)
                    .unwrap();
                assert_eq!(
                    row["hits"], 1,
                    "cache restoration must not look up the learner twice"
                );
                if mode == "nested" {
                    // An outer miss around an inner hit must not persist the
                    // query-local annotation as a new effective route.
                    api(&host, "GET", "/plugins/outer/flush", "").await;
                    assert_eq!(a(ports.dns, name).await, 0);
                    assert_eq!(a(ports.dns, name).await, 0);
                    assert_eq!(
                        host.audit_snapshot().records.last().unwrap().effective_tag,
                        original_effective
                    );
                }
                // Refill the cache while the learning label is already live,
                // so expiry must remove a label actually stored in the cache.
                flush_label_caches(&host, mode == "nested").await;
                assert_eq!(a(ports.dns, name).await, 0);
                let cached_effective = host
                    .audit_snapshot()
                    .records
                    .last()
                    .unwrap()
                    .effective_tag
                    .clone();
                let count = upstream.count(name, 1);
                learner.advance_clock(seconds);
                assert_eq!(a(ports.dns, name).await, 0);
                let audit = host.audit_snapshot();
                let expired = audit.records.last().unwrap();
                assert_eq!(expired.domain_set.as_deref(), cold, "expired {mode} {name}");
                assert_eq!(expired.matched_rule_source.as_deref(), source);
                assert_eq!(expired.effective_tag, cached_effective);
                assert_eq!(
                    upstream.count(name, 1),
                    count,
                    "expiry retained the cached response"
                );
                // Learn again, refill with the learned prefix, then flush the
                // category without flushing the response cache.
                flush_label_caches(&host, mode == "nested").await;
                assert_eq!(a(ports.dns, name).await, 0);
                flush_label_caches(&host, mode == "nested").await;
                assert_eq!(a(ports.dns, name).await, 0);
                for tag in [category, "my_sv4list"] {
                    assert_eq!(
                        api(&host, "GET", &format!("/plugins/{tag}/flush"), "")
                            .await
                            .status,
                        200
                    );
                }
                let count = upstream.count(name, 1);
                assert_eq!(a(ports.dns, name).await, 0);
                let audit = host.audit_snapshot();
                let flushed = audit.records.last().unwrap();
                assert_eq!(flushed.domain_set.as_deref(), cold, "flushed {mode} {name}");
                assert_eq!(flushed.matched_rule_source.as_deref(), source);
                assert_eq!(upstream.count(name, 1), count);
            }
            shutdown.cancel();
            task.await.unwrap();
        });
    }
}

async fn flush_label_caches(host: &HostAssembly, nested: bool) {
    api(host, "GET", "/plugins/cache/flush", "").await;
    if nested {
        api(host, "GET", "/plugins/outer/flush", "").await;
    }
}

#[test]
fn the_mapper_merges_learned_facts_first_and_never_applies_its_default() {
    let tree = Tree::new("merge");
    let ports = ports();
    let upstream = Upstream::start();
    config(&tree, &ports, &upstream, "", "");
    let compiled = compile(&tree);
    let mapper = compiled.domain_mappers[0].clone();
    let learner = Rc::clone(&compiled.local.learners[0].runtime);
    let host = assemble(compiled);
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        // Learned only.
        a(ports.dns, "direct2.test").await;
        let only = mapper.evaluate(Some("Direct2.Test."));
        assert!(only.matched);
        assert_eq!(only.fast_flags, 1 << 11);
        assert_eq!(only.domain_set.as_deref(), Some("DIRECT"));
        assert_eq!(only.matched_rule_source.as_deref(), Some("r_direct"));
        // Learned in two categories: the order of the categories, not of the
        // learning, decides the order of the labels.
        a(ports.dns, "proxy2.test").await;
        let two = mapper.evaluate(Some("proxy2.test."));
        assert_eq!(two.fast_flags, (1 << 4) | (1 << 12));
        assert_eq!(two.domain_set.as_deref(), Some("SPECIAL|PROXY"));
        // Learned and in a static list: the learned label comes first, the
        // marks are or-ed.
        a(ports.dns, "direct3.static.test").await;
        let both = mapper.evaluate(Some("direct3.static.test."));
        assert_eq!(both.fast_flags, (1 << 11) | (1 << 8));
        assert_eq!(both.domain_set.as_deref(), Some("DIRECT|STATIC"));
        assert_eq!(both.matched_rule_source.as_deref(), Some("r_direct|wl"));
        // Static only, and nothing at all.
        let fixed = mapper.evaluate(Some("other.static.test."));
        assert_eq!(fixed.domain_set.as_deref(), Some("STATIC"));
        let none = mapper.evaluate(Some("nothing.test."));
        assert!(!none.matched);
        assert_eq!(none.fast_flags, 1 << 17);
        assert_eq!(none.domain_set.as_deref(), Some("UNMATCHED"));
        // Expiry is per entry and per category: direct (ttl 100) is gone after
        // 101 s, special (ttl 1000) is still there.
        learner.advance_clock(101);
        let later = mapper.evaluate(Some("proxy2.test."));
        assert_eq!(later.fast_flags, 1 << 4);
        assert_eq!(later.domain_set.as_deref(), Some("SPECIAL"));
        let gone = mapper.evaluate(Some("direct2.test."));
        assert!(!gone.matched);
        // An expired name is learned afresh by the next query's rule (once
        // the cached answer is out of the way: a cache hit ends the flow
        // before the rules).
        api(&host, "GET", "/plugins/cache/flush", "").await;
        assert_eq!(a(ports.dns, "direct2.test").await, 0);
        assert_eq!(a(ports.dns, "direct2.test").await, 11);
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn show_save_flush_entries_and_status() {
    let tree = Tree::new("api");
    let ports = ports();
    let upstream = Upstream::start();
    config(&tree, &ports, &upstream, "", "");
    let compiled = compile(&tree);
    let learner = Rc::clone(&compiled.local.learners[0].runtime);
    let host = assemble(compiled);
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        for name in ["direct-a.test", "direct-b.test", "direct-c.test"] {
            a(ports.dns, name).await;
        }
        // Hits count the queries the learned route answered.
        for _ in 0..3 {
            a(ports.dns, "direct-b.test").await;
        }
        a(ports.dns, "direct-c.test").await;

        let shown = api(&host, "GET", "/plugins/my_realiplist/show", "").await;
        assert_eq!(shown.status, 200);
        let lines: Vec<&str> = shown.body.lines().collect();
        assert_eq!(lines.len(), 3, "{}", shown.body);
        // By hits, then name; the layout of a statistics line.
        let parsed: Vec<(String, String, String)> = lines
            .iter()
            .map(|line| {
                let fields: Vec<&str> = line.split(' ').collect();
                assert_eq!(fields.len(), 3, "{line}");
                assert_eq!(fields[0].len(), 10, "{line}");
                (
                    fields[0].to_owned(),
                    fields[1].to_owned(),
                    fields[2].to_owned(),
                )
            })
            .collect();
        assert_eq!(parsed[0].0, "0000000003");
        assert_eq!(parsed[0].2, "direct-b.test");
        assert_eq!(parsed[1].0, "0000000001");
        assert_eq!(parsed[1].2, "direct-c.test");
        assert_eq!(parsed[2].2, "direct-a.test");
        assert_eq!(parsed[0].1.len(), 10);
        let window = api(
            &host,
            "GET",
            "/plugins/my_realiplist/show?q=DIRECT-&limit=1&offset=1",
            "",
        )
        .await;
        assert_eq!(window.body.lines().count(), 1);
        assert!(window.body.contains("direct-c.test"));
        assert_eq!(
            api(&host, "GET", "/plugins/my_realiplist/show?q=zzz", "")
                .await
                .body,
            ""
        );

        // The detail route.
        let detail = api(
            &host,
            "GET",
            "/plugins/route_learner/entries?category=my_realiplist&sort=hits&limit=2",
            "",
        )
        .await;
        assert_eq!(detail.status, 200);
        let detail = json(&detail.body);
        assert_eq!(detail["total"], 3);
        let first = &detail["entries"][0];
        assert_eq!(first["name"], "direct-b.test");
        assert_eq!(first["category"], "my_realiplist");
        assert_eq!(first["conclusion"], "DIRECT");
        assert_eq!(first["mark"], 11);
        assert_eq!(first["reason"], "learn_direct");
        assert_eq!(first["hits"], 3);
        assert!(first["first_confirmed"].as_str().unwrap().ends_with('Z'));
        assert!(first["expires_at"].as_str().unwrap() > first["last_confirmed"].as_str().unwrap());
        assert_eq!(detail["entries"].as_array().unwrap().len(), 2);
        assert_eq!(
            api(
                &host,
                "GET",
                "/plugins/route_learner/entries?category=nope",
                ""
            )
            .await
            .status,
            404
        );
        let status = json(
            &api(&host, "GET", "/plugins/route_learner/status", "")
                .await
                .body,
        );
        let direct = status["categories"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["tag"] == "my_realiplist")
            .unwrap();
        assert_eq!(direct["entries"], 3);
        assert_eq!(direct["ttl_seconds"], 100);
        assert_eq!(status["counters"]["learned"], 3);

        // Methods and actions.
        assert_eq!(
            api(&host, "POST", "/plugins/my_realiplist/show", "")
                .await
                .status,
            405
        );
        assert_eq!(
            api(&host, "POST", "/plugins/route_learner/entries", "")
                .await
                .status,
            405
        );
        assert_eq!(
            api(&host, "GET", "/plugins/my_realiplist/nosuch", "")
                .await
                .status,
            404
        );
        assert_eq!(
            api(&host, "GET", "/plugins/my_realiplist/restartall", "")
                .await
                .status,
            501
        );

        // `save` writes the file once; a second save with nothing new changes
        // nothing.
        let saved = api(&host, "GET", "/plugins/my_realiplist/save", "").await;
        assert_eq!(
            (saved.status, saved.body.as_str()),
            (200, "domain_output saved")
        );
        let file = json(&tree.text("gen/route_learner.json"));
        assert_eq!(file["format"], 1);
        let rows = file["categories"]["my_realiplist"].as_array().unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0][0], "direct-a.test");
        assert_eq!(rows[1][3], 3, "the hit count is written");
        assert_eq!(rows[1][4], "learn_direct");
        let before = tree.text("gen/route_learner.json");
        assert_eq!(
            api(&host, "GET", "/plugins/my_realiplist/save", "")
                .await
                .status,
            200
        );
        assert_eq!(tree.text("gen/route_learner.json"), before);

        // Expired names are neither listed nor counted.
        learner.advance_clock(101);
        assert_eq!(
            api(&host, "GET", "/plugins/my_realiplist/show", "")
                .await
                .body,
            ""
        );
        // `flush` clears one category only and writes at once.
        a(ports.dns, "direct-d.test").await;
        a(ports.dns, "proxy-d.test").await;
        let flushed = api(&host, "GET", "/plugins/my_realiplist/flush", "").await;
        assert_eq!(
            (flushed.status, flushed.body.as_str()),
            (200, "domain_output flushed")
        );
        let file = json(&tree.text("gen/route_learner.json"));
        assert_eq!(
            file["categories"]["my_realiplist"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            file["categories"]["my_fakeiplist"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            a(ports.dns, "direct-d.test").await,
            0,
            "forgotten, asked again"
        );
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn closing_the_host_writes_the_state_and_a_restart_routes_by_it_at_once() {
    let tree = Tree::new("restart");
    let ports = ports();
    let upstream = Upstream::start();
    config(&tree, &ports, &upstream, "", "");
    let host = assemble(compile(&tree));
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        assert_eq!(a(ports.dns, "direct9.test").await, 0);
        assert_eq!(aaaa(ports.dns, "v6none9.test").await, 0);
        // Nothing was written yet: the interval is an hour and nothing asked.
        assert_eq!(tree.text("gen/route_learner.json"), "");
        shutdown.cancel();
        task.await.unwrap();
    });
    let file = json(&tree.text("gen/route_learner.json"));
    assert_eq!(file["categories"]["my_realiplist"][0][0], "direct9.test");
    assert_eq!(file["categories"]["my_nov6list"][0][0], "v6none9.test");

    let host = assemble(compile(&tree));
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        let before = upstream.count("direct9.test", 1);
        assert_eq!(a(ports.dns, "direct9.test").await, 11);
        assert_eq!(aaaa(ports.dns, "v6none9.test").await, 6);
        assert_eq!(upstream.count("direct9.test", 1), before);
        shutdown.cancel();
        task.await.unwrap();
    });
    // A damaged file starts empty instead of failing the start.
    tree.write("gen/route_learner.json", "{broken");
    let host = assemble(compile(&tree));
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        assert_eq!(a(ports.dns, "direct9.test").await, 0);
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn bad_configurations_are_refused_with_the_path() {
    for (what, patch, expected) in [
        (
            "unknown mapper",
            ("target_mapper: unified", "target_mapper: nosuch"),
            "target_mapper",
        ),
        ("ttl too small", ("ttl: 1000}", "ttl: 5}"), "ttl"),
        ("mark too big", ("mark: 4,", "mark: 64,"), "mark"),
        (
            "duplicate category",
            ("tag: my_nov4list", "tag: my_nov6list"),
            "duplicate category tag",
        ),
        (
            "category clashes with a plugin",
            ("tag: my_nov4list", "tag: wl"),
            "already a plugin",
        ),
        (
            "unknown category in a rule",
            ("learn: [my_realiplist]", "learn: [nosuch]"),
            "not a category",
        ),
        (
            "unknown learner in a rule",
            (
                "learner: route_learner, learn: [my_realiplist]",
                "learner: nosuch, learn: [my_realiplist]",
            ),
            "not a route_learner",
        ),
        (
            "bad condition",
            (
                "\"qtype 1\", \"resp_ip 192.0.2.0/24\"",
                "\"nosuchmatcher 1\"",
            ),
            "nosuchmatcher",
        ),
        (
            "unknown argument",
            (
                "write_interval: 3600",
                "write_interval: 3600\n      bogus: 1",
            ),
            "bogus",
        ),
        (
            "pipe in a label",
            ("label: \"SPECIAL\"", "label: \"A|B\""),
            "label",
        ),
    ] {
        let tree = Tree::new("bad");
        let ports = ports();
        let upstream = Upstream::start();
        config(&tree, &ports, &upstream, "", "");
        let yaml = tree.text("config.yaml");
        assert!(
            yaml.contains(patch.0),
            "{what}: fixture lacks {:?}",
            patch.0
        );
        tree.write("config.yaml", &yaml.replacen(patch.0, patch.1, 1));
        let error = atomdns_native_host::load_and_compile(&tree.path("config.yaml"))
            .err()
            .unwrap_or_else(|| panic!("{what} must fail"))
            .to_string();
        assert!(error.contains(expected), "{what}: {error}");
    }
    // A mapper takes one learner.
    let tree = Tree::new("two");
    let ports = ports();
    let upstream = Upstream::start();
    config(
        &tree,
        &ports,
        &upstream,
        "  - tag: second\n    type: route_learner\n    args:\n      target_mapper: unified\n      categories:\n        - {tag: other, mark: 20, label: OTHER, ttl: 100}\n",
        "",
    );
    let error = atomdns_native_host::load_and_compile(&tree.path("config.yaml"))
        .err()
        .expect("second learner")
        .to_string();
    assert!(error.contains("already has a route_learner"), "{error}");
}

// ----- tunable numbers (cache and learner settings) ----------------------------------
