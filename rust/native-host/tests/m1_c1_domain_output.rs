//! M1-c1: the native `domain_output` plugin — recording, the reference file
//! formats, periodic / early / final writes, in-process and HTTP rule
//! publication, the removed `target_mapper` arguments and the management API,
//! through real UDP queries and the real management listener. No test reaches
//! the public network.

#![allow(clippy::too_many_lines)]

use std::fmt::Write as _;
use std::io::{Read, Write as _};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use atomdns_native_host::{BoundHost, HostAssembly, HostOptions};
use atomdns_upstream_core::TransportCancellation;

// ----- fixtures -------------------------------------------------------------

struct Tree(PathBuf);

impl Tree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("m1-c1-{name}-{}", std::process::id()));
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

/// A host whose entry runs the mapper, then the outputs listed in `outputs`
/// (their definitions in `definitions`), then answers by fast mark:
/// 9 -> rcode 9, 4 -> rcode 4, 17 (the mapper default) -> rcode 7.
fn config(tree: &Tree, ports: &Ports, definitions: &str, outputs: &[&str]) {
    let mut execs = String::new();
    for tag in outputs {
        let _ = writeln!(execs, "      - exec: ${tag}");
    }
    let yaml = format!(
        r#"log: {{level: error}}
api: {{http: "127.0.0.1:{api}"}}
plugins:
  - tag: fwd
    type: forward
    args: {{upstreams: [{{addr: "udp://127.0.0.1:9"}}]}}
  - tag: sv4rule
    type: domain_set_light
    args: {{files: ["gen/sv4rule.txt"]}}
  - tag: unified
    type: domain_mapper
    args:
      default_mark: 17
      rules:
        - {{tag: sv4rule, mark: 9}}
{definitions}  - tag: entry
    type: sequence
    args:
      - exec: $unified
{execs}      - matches: fast_mark 9
        exec: reject 9
      - matches: fast_mark 4
        exec: reject 4
      - matches: fast_mark 17
        exec: reject 7
      - exec: reject 0
  - tag: listener
    type: udp_server
    args: {{entry: entry, listen: "127.0.0.1:{dns}"}}
"#,
        api = ports.api,
        dns = ports.dns,
    );
    tree.write("config.yaml", &yaml);
}

fn host(tree: &Tree) -> HostAssembly {
    let config =
        atomdns_native_host::load_and_compile(&tree.path("config.yaml")).expect("compiles");
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

fn wire(name: &str, flags: u8, dnssec: bool) -> Vec<u8> {
    let mut out = vec![0, 7, 1, flags, 0, 1, 0, 0, 0, 0, 0, u8::from(dnssec)];
    for label in name.trim_end_matches('.').split('.') {
        out.push(u8::try_from(label.len()).unwrap());
        out.extend_from_slice(label.as_bytes());
    }
    out.extend([0, 0, 1, 0, 1]);
    if dnssec {
        out.extend([0, 0, 41, 16, 0, 0, 0, 0x80, 0, 0, 0]);
    }
    out
}

async fn ask(port: u16, query: &[u8]) -> u8 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(query, ("127.0.0.1", port)).await.unwrap();
    let mut packet = vec![0; 1500];
    let (length, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut packet))
        .await
        .expect("response in time")
        .unwrap();
    assert!(length >= 12);
    packet[3] & 15
}

async fn rcode(port: u16, name: &str) -> u8 {
    ask(port, &wire(name, 0, false)).await
}

async fn eventually_text(tree: &Tree, relative: &str, predicate: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = tree.text(relative);
        if predicate(&text) {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "{relative} never matched; now {text:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// `(count, date, key)` of a statistics line.
fn parse_line(line: &str) -> (u64, String, String) {
    let fields: Vec<&str> = line.split(' ').collect();
    assert_eq!(fields.len(), 3, "{line:?}");
    assert_eq!(fields[0].len(), 10, "{line:?}");
    (
        fields[0].parse().unwrap(),
        fields[1].to_owned(),
        fields[2].to_owned(),
    )
}

// ----- tests ------------------------------------------------------------------

#[test]
fn closing_the_host_saves_and_a_restart_reads_the_file_back() {
    let tree = Tree::new("restart");
    let ports = ports();
    config(
        &tree,
        &ports,
        "  - tag: top_domains\n    type: domain_output\n    args:\n      file_stat: gen/top.txt\n      file_rule: gen/toprule.txt\n      dump_interval: 3600\n",
        &["top_domains"],
    );
    for round in 1..=2_u64 {
        let host = host(&tree);
        host.block_on(async {
            let (shutdown, task) = serve(&host).await;
            for _ in 0..3 {
                rcode(ports.dns, "again.example").await;
            }
            rcode(ports.dns, "once.example").await;
            shutdown.cancel();
            task.await.unwrap();
        });
        // The final save wrote the file before the host returned.
        let lines: Vec<(u64, String, String)> =
            tree.text("gen/top.txt").lines().map(parse_line).collect();
        assert_eq!(lines[0].0, 3 * round);
        assert_eq!(lines[0].2, "again.example");
        assert_eq!(lines[1].0, round);
        assert_eq!(lines[1].2, "once.example");
        assert_eq!(
            tree.text("gen/toprule.txt"),
            "full:again.example\nfull:once.example\n"
        );
    }
}

#[test]
fn max_entries_triggers_an_early_write() {
    let tree = Tree::new("early");
    let ports = ports();
    config(
        &tree,
        &ports,
        "  - tag: top_domains\n    type: domain_output\n    args:\n      max_entries: 3\n      file_stat: gen/top.txt\n      dump_interval: 3600\n",
        &["top_domains"],
    );
    let host = host(&tree);
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        rcode(ports.dns, "a.example").await;
        rcode(ports.dns, "a.example").await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            tree.text("gen/top.txt"),
            "",
            "two records are below the trigger"
        );
        rcode(ports.dns, "b.example").await;
        let stat = eventually_text(&tree, "gen/top.txt", |text| text.contains("b.example")).await;
        assert_eq!(stat.lines().count(), 2);
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn a_foreign_domain_set_url_gets_an_http_post_with_the_reference_body() {
    let tree = Tree::new("http");
    let ports = ports();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let push_port = listener.local_addr().unwrap().port();
    let (sender, received) = std::sync::mpsc::channel::<String>();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 4096];
        while let Ok(length) = stream.read(&mut chunk) {
            if length == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..length]);
            let text = String::from_utf8_lossy(&bytes);
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let expected: usize = head
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse().ok())
                    })
                    .unwrap_or(0);
                if body.len() >= expected {
                    break;
                }
            }
        }
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        sender
            .send(String::from_utf8_lossy(&bytes).into_owned())
            .unwrap();
    });
    config(
        &tree,
        &ports,
        &format!(
            "  - tag: top_domains\n    type: domain_output\n    args:\n      file_stat: gen/top.txt\n      dump_interval: 1\n      domain_set_url: \"http://127.0.0.1:{push_port}/somewhere/post\"\n"
        ),
        &["top_domains"],
    );
    let host = host(&tree);
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        rcode(ports.dns, "Push.Test").await;
        let request = tokio::task::spawn_blocking(move || {
            received.recv_timeout(Duration::from_secs(10)).unwrap()
        })
        .await
        .unwrap();
        assert!(
            request.starts_with("POST /somewhere/post HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("content-type: application/json"),
            "{request}"
        );
        let body = request.split_once("\r\n\r\n").unwrap().1;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(body).unwrap(),
            serde_json::json!({"values": ["full:push.test"]})
        );
        shutdown.cancel();
        task.await.unwrap();
    });
    server.join().unwrap();
}

#[test]
fn bad_arguments_fail_the_configuration() {
    for (arguments, expected) in [
        (
            "      target_mapper: unified\n",
            "removed in config schema 2",
        ),
        ("      target_mark: 4\n", "route_learner"),
        ("      target_tag: x\n", "target_tag"),
        ("      unknown_field: 1\n", "unknown_field"),
        ("      max_entries: x\n", "max_entries"),
    ] {
        let tree = Tree::new("bad");
        let ports = ports();
        config(
            &tree,
            &ports,
            &format!("  - tag: top_domains\n    type: domain_output\n    args:\n{arguments}"),
            &["top_domains"],
        );
        let error = atomdns_native_host::load_and_compile(&tree.path("config.yaml"))
            .err()
            .unwrap_or_else(|| panic!("{arguments} must fail"))
            .to_string();
        assert!(error.contains(expected), "{arguments}: {error}");
    }
}
