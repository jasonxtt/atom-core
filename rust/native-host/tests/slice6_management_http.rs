//! Slice 1 of the local-rule editing workflow: the scoped management HTTP
//! surface and the top-level host supervisor that owns DNS and HTTP together.
//!
//! These tests drive a real HTTP client against the host-owned listener and a
//! real DNS client against the host-owned UDP listener. No router, handler or
//! response object is mocked.

mod common;

use std::fs;
use std::net::{SocketAddr, TcpListener as StdTcpListener, UdpSocket as StdUdpSocket};
use std::path::PathBuf;
use std::time::Duration;

use atomdns_native_host::{HostAssembly, HostOptions, load_and_compile};
use atomdns_upstream_core::TransportCancellation;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One owned fixture directory holding a config and its real rule files.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir()
            .canonicalize()
            .expect("canonical temporary directory")
            .join(format!("atomdns-http-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("rules")).expect("fixture directory");
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) -> PathBuf {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture parent");
        }
        fs::write(&path, contents).expect("fixture file");
        path
    }

    fn config(&self) -> PathBuf {
        self.root.join("config.yaml")
    }

    fn read(&self, relative: &str) -> String {
        fs::read_to_string(self.root.join(relative)).expect("fixture read")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A fixture with a managed `blocklist`, a query-only `exps_only` set and a
/// management listener on a probed free port. The native config rejects port
/// 0, so the harness probes a concrete port first.
fn fixture(name: &str, dns_port: u16, api_port: u16) -> Fixture {
    let fixture = Fixture::new(name);
    fixture.write("rules/blocklist.txt", "a.example\nb.example\n");
    let dns_listen = format!("127.0.0.1:{dns_port}");
    let api_listen = format!("127.0.0.1:{api_port}");
    let yaml = format!(
        r#"log:
  level: error
api:
  http: "{api_listen}"
plugins:
  - tag: sequence_main
    type: sequence
    args:
      - matches: qname $blocklist
        exec: reject 3
      - exec: $forward_main
  - tag: blocklist
    type: domain_set
    args:
      files:
        - rules/blocklist.txt
  - tag: exps_only
    type: domain_set
    args:
      exps:
        - exps.example
  - tag: forward_main
    type: forward
    args:
      upstreams:
        - addr: "udp://127.0.0.1:25999"
  - tag: listener
    type: udp_server
    args:
      entry: sequence_main
      listen: "{dns_listen}"
      enable_audit: false
"#
    );
    fixture.write("config.yaml", &yaml);
    fixture
}

fn assembly_for(fixture: &Fixture) -> HostAssembly {
    HostAssembly::from_config(load_and_compile(&fixture.config()).expect("fixture config"))
        .expect("fixture assembly")
}

fn audit_assembly_for(fixture: &Fixture) -> HostAssembly {
    let yaml = fixture
        .read("config.yaml")
        .replace("enable_audit: false", "enable_audit: true");
    fixture.write("config.yaml", &yaml);
    HostAssembly::with_options_and_state_root(
        load_and_compile(&fixture.config()).expect("audit fixture config"),
        HostOptions::default(),
        &fixture.root,
    )
    .expect("audit fixture assembly")
}

/// A minimal DNS query for one name.
fn dns_query(id: u16, labels: &[&str]) -> Vec<u8> {
    let mut packet = Vec::from([
        u8::try_from(id >> 8).expect("high ID byte"),
        u8::try_from(id & 0x00ff).expect("low ID byte"),
        0x01,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]);
    for label in labels {
        packet.push(u8::try_from(label.len()).expect("DNS label length"));
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    packet
}

fn udp_query(listener: SocketAddr, request: &[u8]) -> Vec<u8> {
    let socket = StdUdpSocket::bind("127.0.0.1:0").expect("client bind");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("client timeout");
    socket.send_to(request, listener).expect("client send");
    let mut response = vec![0_u8; 65535];
    let (length, _) = socket.recv_from(&mut response).expect("client response");
    response[..length].to_vec()
}

fn rcode(response: &[u8]) -> u16 {
    u16::from_be_bytes([response[2], response[3]]) & 0x000f
}

/// One parsed HTTP response.
#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Sends one complete HTTP/1.1 request and reads the response until the server
/// closes the connection.
async fn http_request(address: SocketAddr, request: &str) -> HttpResponse {
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("http connect");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("http write");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("http read");
    parse_http_response(&bytes)
}

fn parse_http_response(bytes: &[u8]) -> HttpResponse {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("malformed HTTP response: {text:?}"));
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("status line");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect();
    HttpResponse {
        status,
        headers,
        body: body.to_owned(),
    }
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: native\r\nConnection: close\r\n\r\n")
}

fn raw(method: &str, path: &str) -> String {
    format!("{method} {path} HTTP/1.1\r\nHost: native\r\nConnection: close\r\n\r\n")
}

fn post(path: &str, body: &str) -> String {
    format!(
        "POST {path} HTTP/1.1\r\nHost: native\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A port that was just free; used to prove a failed bind released the other
/// listener.
fn free_tcp_port() -> u16 {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("probe bind");
    let port = listener.local_addr().expect("probe address").port();
    drop(listener);
    port
}

fn free_udp_port() -> u16 {
    let socket = StdUdpSocket::bind("127.0.0.1:0").expect("probe bind");
    let port = socket.local_addr().expect("probe address").port();
    drop(socket);
    port
}

#[test]
fn audit_v1_controls_use_real_http_and_dns_and_persist_capacity() {
    let fixture = fixture("audit-v1", free_udp_port(), free_tcp_port());
    let assembly = audit_assembly_for(&fixture);
    let bound = assembly
        .block_on(assembly.bind_host())
        .expect("bound host listeners");
    let dns = bound.dns_addr();
    let api = bound.api_addr().expect("management listener address");
    let shutdown = TransportCancellation::new();

    let result = assembly.block_on(async {
        let task = tokio::task::spawn_local(bound.serve(shutdown.clone()));
        let status = http_request(api, &get("/api/v1/audit/status")).await;
        assert_eq!(status.status, 200);
        assert_eq!(status.header("content-type"), Some("application/json"));
        assert_eq!(status.body, "{\"capturing\":true}\n");

        let stopped = http_request(api, &raw("POST", "/api/v1/audit/stop")).await;
        assert_eq!(stopped.status, 200);
        assert_eq!(stopped.header("content-type"), None);
        assert_eq!(stopped.body, "Audit log collection stopped.");
        let stopped_status = http_request(api, &get("/api/v1/audit/status")).await;
        assert_eq!(stopped_status.body, "{\"capturing\":false}\n");

        let first_dns = tokio::task::spawn_blocking(move || {
            udp_query(dns, &dns_query(0x7101, &["a", "example"]))
        })
        .await
        .expect("stopped DNS client");
        assert_eq!(rcode(&first_dns), 3);
        assert!(assembly.audit_snapshot().records.is_empty());

        let started = http_request(api, &raw("POST", "/api/v1/audit/start")).await;
        assert_eq!(started.status, 200);
        assert_eq!(started.body, "Audit log collection started.");
        let second_dns = tokio::task::spawn_blocking(move || {
            udp_query(dns, &dns_query(0x7102, &["a", "example"]))
        })
        .await
        .expect("started DNS client");
        assert_eq!(rcode(&second_dns), 3);
        assert_eq!(assembly.audit_snapshot().records.len(), 1);

        let capacity = http_request(api, &get("/api/v1/audit/capacity")).await;
        assert_eq!(capacity.body, "{\"capacity\":100000}\n");
        let resized = http_request(api, &post("/api/v1/audit/capacity", r#"{"capacity":2}"#)).await;
        assert_eq!(resized.status, 200, "{resized:?}");
        assert_eq!(resized.header("content-type"), None);
        assert_eq!(
            resized.body,
            "Audit log capacity set to 2. Existing logs have been cleared."
        );
        assert_eq!(assembly.audit_capacity(), 2);
        assert!(assembly.audit_snapshot().records.is_empty());
        assert!(fixture.root.join("webinfo/audit_settings.json").is_file());

        for (capacity, expected) in [(0, 0), (400_000, 400_000), (2, 2)] {
            let response = http_request(
                api,
                &post(
                    "/api/v1/audit/capacity",
                    &format!(r#"{{"capacity":{capacity}}}"#),
                ),
            )
            .await;
            assert_eq!(response.status, 200, "{capacity}: {response:?}");
            assert_eq!(assembly.audit_capacity(), expected);
            assert!(assembly.audit_snapshot().records.is_empty());
        }

        for body in [
            "{}",
            r#"{"capacity":1.5}"#,
            r#"{"capacity":"1"}"#,
            r#"{"capacity":1,"extra":true}"#,
            r#"{"capacity":400001}"#,
        ] {
            let invalid = http_request(api, &post("/api/v1/audit/capacity", body)).await;
            assert_eq!(invalid.status, 400, "{body}: {invalid:?}");
            assert_eq!(
                invalid.header("content-type"),
                Some("text/plain; charset=utf-8")
            );
            assert_eq!(invalid.body, "invalid audit capacity request\n");
            assert_eq!(assembly.audit_capacity(), 2);
        }

        exercise_atom_audit(api, &assembly).await;

        let clear = http_request(api, &raw("POST", "/api/v1/audit/clear")).await;
        assert_eq!(clear.status, 200);
        assert_eq!(clear.body, "In-memory audit logs cleared.");
        let wrong_method = http_request(api, &raw("POST", "/api/v1/audit/status")).await;
        assert_eq!(wrong_method.status, 405);
        assert_eq!(wrong_method.body, "method not allowed\n");

        shutdown.cancel();
        task.await.expect("supervisor task")
    });
    result.expect("supervisor shutdown is clean");

    let restarted = HostAssembly::with_options_and_state_root(
        load_and_compile(&fixture.config()).expect("restart config"),
        HostOptions::default(),
        &fixture.root,
    )
    .expect("restart assembly");
    assert_eq!(restarted.audit_capacity(), 2);
}

/// atom fork: the audit handlers under the management API's prefix answer
/// in its conventions (JSON errors and confirmations).
async fn exercise_atom_audit(api: SocketAddr, assembly: &HostAssembly) {
    let state = http_request(api, &get("/api/v1/atom/audit/status")).await;
    assert_eq!(state.status, 200);
    assert_eq!(state.body, "{\"capturing\":true}\n");
    let totals = http_request(api, &get("/api/v1/atom/audit/stats")).await;
    assert_eq!(totals.status, 200, "{totals:?}");
    assert!(totals.body.contains("\"total_queries\""), "{totals:?}");
    let invalid = http_request(api, &post("/api/v1/atom/audit/capacity", "{}")).await;
    assert_eq!(invalid.status, 400);
    assert_eq!(invalid.header("content-type"), Some("application/json"));
    assert_eq!(invalid.body, "{\"error\":\"invalid audit capacity request\"}\n");
    assert_eq!(assembly.audit_capacity(), 2);
    let wrong = http_request(api, &raw("POST", "/api/v1/atom/audit/status")).await;
    assert_eq!(wrong.status, 405);
    assert_eq!(wrong.body, "{\"error\":\"method not allowed\"}\n");
    let unknown = http_request(api, &get("/api/v1/atom/audit/nope")).await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.body, "{\"error\":\"404 page not found\"}\n");
    let cleared = http_request(api, &raw("POST", "/api/v1/atom/audit/clear")).await;
    assert_eq!(cleared.status, 200);
    assert_eq!(cleared.header("content-type"), Some("application/json"));
    assert_eq!(cleared.body, "{\"message\":\"In-memory audit logs cleared.\"}\n");
}

#[test]
fn audit_capacity_without_state_root_and_failed_replace_keep_old_runtime_state() {
    let audit_fixture = fixture("audit-no-root", free_udp_port(), free_tcp_port());
    let _ = audit_assembly_for(&audit_fixture);
    let no_root = HostAssembly::from_config(
        load_and_compile(&audit_fixture.config()).expect("no-root config"),
    )
    .expect("no-root assembly");
    let no_root_bound = no_root
        .block_on(no_root.bind_host())
        .expect("no-root host bind");
    let no_root_api = no_root_bound.api_addr().expect("no-root API");
    let no_root_shutdown = TransportCancellation::new();
    let result = no_root.block_on(async {
        let task = tokio::task::spawn_local(no_root_bound.serve(no_root_shutdown.clone()));
        let response = http_request(
            no_root_api,
            &post("/api/v1/audit/capacity", r#"{"capacity":2}"#),
        )
        .await;
        assert_eq!(response.status, 500);
        assert_eq!(response.body, "audit settings state root is unavailable\n");
        no_root_shutdown.cancel();
        task.await.expect("no-root fixture task")
    });
    result.expect("fixture shutdown");

    let failure_fixture = fixture("audit-write-failure", free_udp_port(), free_tcp_port());
    let canonical = failure_fixture.root.join("webinfo/audit_settings.json");
    let old_bytes = b"{\"capacity\":100000}\n";
    fs::create_dir_all(canonical.parent().expect("canonical parent")).expect("webinfo directory");
    fs::write(&canonical, old_bytes).expect("old settings");
    let failure = audit_assembly_for(&failure_fixture);
    failure.inject_audit_temp_write_failure();
    let bound = failure
        .block_on(failure.bind_host())
        .expect("failure host bind");
    let dns = bound.dns_addr();
    let api = bound.api_addr().expect("failure API");
    let shutdown = TransportCancellation::new();
    let result = failure.block_on(async {
        let task = tokio::task::spawn_local(bound.serve(shutdown.clone()));
        let dns_response = tokio::task::spawn_blocking(move || {
            udp_query(dns, &dns_query(0x7201, &["a", "example"]))
        })
        .await
        .expect("failure fixture DNS client");
        assert_eq!(rcode(&dns_response), 3);
        assert_eq!(failure.audit_snapshot().records.len(), 1);
        let response =
            http_request(api, &post("/api/v1/audit/capacity", r#"{"capacity":2}"#)).await;
        assert_eq!(response.status, 500);
        assert_eq!(response.body, "audit settings persistence failed\n");
        assert_eq!(failure.audit_capacity(), 100_000);
        assert_eq!(failure.audit_snapshot().records.len(), 1);

        failure.inject_audit_final_replace_failure();
        let response =
            http_request(api, &post("/api/v1/audit/capacity", r#"{"capacity":2}"#)).await;
        assert_eq!(response.status, 500);
        assert_eq!(response.body, "audit settings persistence failed\n");
        assert_eq!(failure.audit_capacity(), 100_000);
        assert_eq!(failure.audit_snapshot().records.len(), 1);
        shutdown.cancel();
        task.await.expect("failure fixture task")
    });
    result.expect("failure fixture shutdown");
    assert!(
        failure_fixture
            .root
            .join("webinfo/audit_settings.json")
            .is_file()
    );
    assert_eq!(
        fs::read(&canonical).expect("old settings remains"),
        old_bytes
    );
    assert_eq!(
        fs::read_dir(failure_fixture.root.join("webinfo"))
            .expect("webinfo entries")
            .count(),
        1,
        "failed writes must clean temporary settings files"
    );
}

#[test]
fn a_dns_only_configuration_has_no_management_listener() {
    let fixture = Fixture::new("dns-only");
    fixture.write("rules/unused.txt", "unused.example\n");
    let yaml = format!(
        r#"log:
  level: error
plugins:
  - tag: sequence_main
    type: sequence
    args:
      - exec: $forward_main
  - tag: forward_main
    type: forward
    args:
      upstreams:
        - addr: "udp://127.0.0.1:25999"
  - tag: listener
    type: udp_server
    args:
      entry: sequence_main
      listen: "127.0.0.1:{}"
      enable_audit: false
"#,
        free_udp_port()
    );
    fixture.write("config.yaml", &yaml);
    let assembly = assembly_for(&fixture);
    let bound = assembly
        .block_on(assembly.bind_host())
        .expect("DNS-only host binds");
    assert!(
        bound.api_addr().is_none(),
        "a DNS-only configuration must not open a management listener"
    );
    let dns = bound.dns_addr();
    let shutdown = TransportCancellation::new();
    let result = assembly.block_on(async {
        let task = tokio::task::spawn_local(bound.serve(shutdown.clone()));
        shutdown.cancel();
        task.await.expect("supervisor task")
    });
    result.expect("DNS-only supervisor shutdown is clean");
    assert!(dns.port() > 0);
}

#[test]
fn one_shutdown_scope_releases_both_listeners_for_rebind() {
    let fixture = fixture("lifecycle", free_udp_port(), free_tcp_port());
    let assembly = assembly_for(&fixture);
    let bound = assembly
        .block_on(assembly.bind_host())
        .expect("bound host listeners");
    let dns = bound.dns_addr();
    let api = bound.api_addr().expect("management listener");
    let shutdown = TransportCancellation::new();

    let result = assembly.block_on(async {
        let task = tokio::task::spawn_local(bound.serve(shutdown.clone()));

        // The DNS side really serves: the managed name is rejected locally.
        let listener = dns;
        let response = tokio::task::spawn_blocking(move || {
            udp_query(listener, &dns_query(0x2001, &["a", "example"]))
        })
        .await
        .expect("dns client task");
        assert_eq!(rcode(&response), 3);

        let metrics = http_request(api, &get("/metrics")).await;
        assert_eq!(metrics.status, 200);

        shutdown.cancel();
        task.await.expect("supervisor task")
    });
    result.expect("supervisor shutdown is clean");

    // Both sockets must be released once the supervisor returns.
    StdUdpSocket::bind(dns).expect("the DNS socket must be released");
    StdTcpListener::bind(api).expect("the management socket must be released");
}

#[test]
fn a_failed_management_bind_releases_the_dns_listener() {
    let dns_port = free_udp_port();
    #[cfg(target_os = "linux")]
    common::ports::check_release_probe(dns_port, common::ports::Protocol::Udp);
    let occupied = StdTcpListener::bind("127.0.0.1:0").expect("occupy management port");
    let api_port = occupied.local_addr().expect("occupied address").port();

    let fixture = fixture("api-bind-failure", dns_port, api_port);
    let assembly = assembly_for(&fixture);
    let bound = assembly.block_on(assembly.bind_host());
    assert!(
        bound.is_err(),
        "an occupied management port must fail the host bind"
    );
    drop(bound);

    // The DNS listener bound before the failure must not stay bound.
    common::ports::assert_released(dns_port, common::ports::Protocol::Udp);
}

#[test]
fn a_failed_dns_bind_releases_the_management_listener() {
    let api_port = free_tcp_port();
    #[cfg(target_os = "linux")]
    common::ports::check_release_probe(api_port, common::ports::Protocol::Tcp);
    let occupied = StdUdpSocket::bind("127.0.0.1:0").expect("occupy DNS port");
    let dns_port = occupied.local_addr().expect("occupied address").port();

    let fixture = fixture("dns-bind-failure", dns_port, api_port);
    let assembly = assembly_for(&fixture);
    let bound = assembly.block_on(assembly.bind_host());
    assert!(
        bound.is_err(),
        "an occupied DNS port must fail the host bind"
    );
    drop(bound);

    common::ports::assert_released(api_port, common::ports::Protocol::Tcp);
}

#[test]
fn a_running_side_failure_cancels_and_joins_the_other_listener() {
    let fixture = fixture("running-failure", free_udp_port(), free_tcp_port());
    let assembly = assembly_for(&fixture);
    let bound = assembly
        .block_on(assembly.bind_host())
        .expect("bound host listeners");
    let dns = bound.dns_addr();
    let api = bound.api_addr().expect("management listener");
    bound.inject_api_accept_fault_after(1);
    let shutdown = TransportCancellation::new();

    let result = assembly.block_on(async {
        let task = tokio::task::spawn_local(bound.serve(shutdown.clone()));
        // The first request is served; the next accepted connection makes the
        // listener fail, so the supervisor must cancel and join the DNS side.
        let first = http_request(api, &get("/metrics")).await;
        assert_eq!(first.status, 200);
        if let Ok(mut stream) = tokio::net::TcpStream::connect(api).await {
            let _ = stream.write_all(get("/metrics").as_bytes()).await;
            let _ = stream.shutdown().await;
        }
        task.await.expect("supervisor task")
    });

    assert!(
        result.is_err(),
        "a running-side failure must surface as a host error"
    );
    // The supervisor must have joined the DNS side and released both sockets.
    StdUdpSocket::bind(dns).expect("the DNS socket must be released");
    StdTcpListener::bind(api).expect("the management socket must be released");
}

#[test]
fn native_supervisor_health_matches_cli_identity_and_closes_with_listeners() {
    let dns_port = free_udp_port();
    let api_port = free_tcp_port();
    let fixture = fixture("health-supervisor", dns_port, api_port);
    let host = assembly_for(&fixture);
    host.block_on(async {
        let bound = host.bind_host().await.unwrap();
        let api = bound.api_addr().unwrap();
        let shutdown = TransportCancellation::new();
        let task = tokio::task::spawn_local(bound.serve(shutdown.clone()));
        let response = http_request(api, &get("/api/v1/system/health")).await;
        assert_eq!(response.status, 200);
        let health: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(health["ready"], true);
        assert_eq!(
            health["version"],
            atomdns_native_host::build_identity::VERSION
        );
        assert_eq!(health["runtime"], "rust");
        shutdown.cancel();
        task.await.unwrap().unwrap();
        assert!(tokio::net::TcpStream::connect(api).await.is_err());
    });
}

#[test]
fn without_ui_main_the_root_says_no_webui_is_installed_and_the_api_is_unaffected() {
    let fixture = fixture("no-webui", free_udp_port(), free_tcp_port());
    let host = assembly_for(&fixture);
    host.block_on(async {
        let bound = host.bind_host().await.unwrap();
        let api = bound.api_addr().unwrap();
        let shutdown = TransportCancellation::new();
        let task = tokio::task::spawn_local(bound.serve(shutdown.clone()));
        let page = http_request(api, &get("/")).await;
        assert_eq!(page.status, 404);
        assert_eq!(
            page.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert!(page.body.contains("没有安装 WebUI"), "{}", page.body);
        let health = http_request(api, &get("/api/v1/system/health")).await;
        assert_eq!(health.status, 200);
        // The program embeds no UI any more: no `/assets/...`, no `/log`.
        for path in [
            "/assets/vue-log/app.js",
            "/index.html",
            "/log",
            "/log/",
            "/log1",
            "/api/missing",
        ] {
            assert_eq!(http_request(api, &get(path)).await.status, 404, "{path}");
        }
        shutdown.cancel();
        task.await.unwrap().unwrap();
    });
}

#[cfg(target_os = "linux")]
#[test]
fn ui_main_is_the_root_served_live_over_real_http_without_audit_or_metrics() {
    let fixture = fixture("ui-main", free_udp_port(), free_tcp_port());
    fixture.write(
        "ui/main/ui-manifest.json",
        r#"{"manifest_schema":1,"ui_version":"v9.9.9","api_level":1}"#,
    );
    fixture.write("ui/main/index.html", "<html>main</html>");
    fixture.write("ui/main/app.js", "console.log(1)");
    let host = assembly_for(&fixture);
    host.block_on(async {
        let bound = host.bind_host().await.unwrap();
        let api = bound.api_addr().unwrap();
        let shutdown = TransportCancellation::new();
        let task = tokio::task::spawn_local(bound.serve(shutdown.clone()));
        let before = host.metrics_snapshot();
        host.start_audit();
        for (path, mime, body) in [
            ("/", "text/html; charset=utf-8", "<html>main</html>"),
            (
                "/app.js?v=proof",
                "text/javascript; charset=utf-8",
                "console.log(1)",
            ),
        ] {
            let response = http_request(api, &get(path)).await;
            assert_eq!(response.status, 200, "{path}: {response:?}");
            assert_eq!(response.body, body);
            assert_eq!(response.header("content-type"), Some(mime));
            assert_eq!(response.header("cache-control"), Some("no-store"));
            assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
            let head =
                http_request(api, &format!("HEAD {path} HTTP/1.1\r\nHost: test\r\n\r\n")).await;
            assert_eq!(head.status, 200);
            assert!(head.body.is_empty());
            assert_eq!(
                head.header("content-length"),
                response.header("content-length")
            );
        }
        // Files are read live.
        fixture.write("ui/main/app.js", "console.log(2)");
        assert_eq!(
            http_request(api, &get("/app.js")).await.body,
            "console.log(2)"
        );
        for path in [
            "/no-such.js",
            "/main/",
            "/%2e%2e/config.yaml",
            "/api/missing",
            "/plugins/missing",
            "/log",
        ] {
            let response = http_request(api, &get(path)).await;
            assert_eq!(response.status, 404, "{path}");
            assert!(response.header("location").is_none(), "{path}");
        }
        // Other methods are the API's (an unknown path stays 404).
        assert_eq!(http_request(api, &post("/", "")).await.status, 404);
        let health: serde_json::Value =
            serde_json::from_str(&http_request(api, &get("/api/v1/system/health")).await.body)
                .unwrap();
        let main = health["external_ui"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == "main")
            .unwrap()
            .clone();
        assert_eq!(main["path"], "/");
        assert_eq!(main["mounted"], true);
        assert_eq!(main["ui_version"], "v9.9.9");
        assert_eq!(host.metrics_snapshot(), before);
        assert!(host.audit_snapshot().records.is_empty());
        shutdown.cancel();
        task.await.unwrap().unwrap();
    });
}

#[cfg(target_os = "linux")]
#[test]
fn external_ui_is_live_confined_and_root_pinned() {
    use std::os::unix::fs::symlink;
    let fixture = fixture("external-ui", free_udp_port(), free_tcp_port());
    fixture.write("ui/demo/index.html", "initial");
    fixture.write("ui/demo/nested/file.js", "nested");
    fixture.write("ui/a?b%# 空/index.html", "reserved root");
    fixture.write("ui/demo/n?%# 空/index.html", "reserved nested");
    fixture.write("secret.txt", "SECRET");
    fixture.write("ui/api/index.html", "reserved");
    symlink(&fixture.root, fixture.root.join("ui/link")).unwrap();
    symlink(
        fixture.root.join("secret.txt"),
        fixture.root.join("ui/demo/leak"),
    )
    .unwrap();
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        fixture.root.join("ui/demo/fifo"),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
    )
    .unwrap();
    let _socket =
        std::os::unix::net::UnixListener::bind(fixture.root.join("ui/demo/socket")).unwrap();
    let host = assembly_for(&fixture);
    host.block_on(async {
        let bound = host.bind_host().await.unwrap();
        let api = bound.api_addr().unwrap();
        let shutdown = TransportCancellation::new();
        let task = tokio::task::spawn_local(bound.serve(shutdown.clone()));
        let redirect = http_request(api, &get("/demo?x=1")).await;
        assert_eq!(redirect.status, 301);
        assert_eq!(redirect.header("location"), Some("/demo/?x=1"));
        exercise_encoded_redirects(api).await;
        let initial = http_request(api, &get("/demo/")).await;
        assert_eq!(initial.status, 200);
        assert_eq!(initial.body, "initial");
        assert_eq!(initial.header("cache-control"), Some("no-store"));
        fixture.write("ui/demo/index.html", "changed");
        assert_eq!(http_request(api, &get("/demo/")).await.body, "changed");
        assert_eq!(
            http_request(api, &get("/demo/nested/file.js?v=1"))
                .await
                .body,
            "nested"
        );
        let dir = http_request(api, &get("/demo/nested?x=1")).await;
        assert_eq!(dir.status, 301);
        assert_eq!(dir.header("location"), Some("/demo/nested/?x=1"));
        let head = http_request(api, "HEAD /demo/ HTTP/1.1\r\nHost: test\r\n\r\n").await;
        assert_eq!(head.status, 200);
        assert!(head.body.is_empty());
        assert_eq!(head.header("content-length"), Some("7"));
        for path in [
            "/demo/leak",
            "/demo/fifo",
            "/demo/socket",
            "/link/secret.txt",
            "/api/",
            "/demo/%2e%2e/secret.txt",
            "/demo/a%2fb",
            "/demo/%00",
            "/demo/%ff",
            "/demo/missing",
            "/demo/nested/",
        ] {
            assert_eq!(http_request(api, &get(path)).await.status, 404, "{path}");
        }
        assert_eq!(http_request(api, &post("/demo/", "")).await.status, 405);
        let large = fs::File::create(fixture.root.join("ui/demo/large")).unwrap();
        large.set_len(16 * 1024 * 1024 + 1).unwrap();
        assert_eq!(http_request(api, &get("/demo/large")).await.status, 413);
        fs::rename(fixture.root.join("ui/demo"), fixture.root.join("ui/old")).unwrap();
        fixture.write("ui/demo/index.html", "replacement");
        assert_eq!(http_request(api, &get("/demo/")).await.body, "changed");
        for _ in 0..20 {
            fs::rename(
                fixture.root.join("ui/old/nested"),
                fixture.root.join("ui/old/safe"),
            )
            .unwrap();
            symlink(&fixture.root, fixture.root.join("ui/old/nested")).unwrap();
            let response = http_request(api, &get("/demo/nested/secret.txt")).await;
            assert_eq!(response.status, 404);
            assert!(!response.body.contains("SECRET"));
            fs::remove_file(fixture.root.join("ui/old/nested")).unwrap();
            fs::rename(
                fixture.root.join("ui/old/safe"),
                fixture.root.join("ui/old/nested"),
            )
            .unwrap();
        }
        exercise_ui_swaps(api, &fixture).await;
        fs::remove_file(fixture.root.join("ui/old/index.html")).unwrap();
        assert_eq!(http_request(api, &get("/demo/")).await.status, 404);
        shutdown.cancel();
        task.await.unwrap().unwrap();
    });
}

#[cfg(target_os = "linux")]
#[test]
#[allow(clippy::too_many_lines)]
fn external_ui_packages_use_any_directory_name_and_a_manifest_decides_mounting() {
    const GOOD: &str = r#"{"manifest_schema":1,"ui_version":"v9.9","built_at":"2026-10-17T00:00:00Z","api_level":1,"requires_api_level":1}"#;
    const TOO_NEW: &str =
        r#"{"manifest_schema":1,"ui_version":"v10","api_level":2,"requires_api_level":2}"#;
    let fixture = fixture("ui-packages", free_udp_port(), free_tcp_port());
    for (path, text) in [
        // The same package under two unrelated names: the mount name is the directory name.
        ("ui/pg/index.html", "<html>external</html>"),
        ("ui/pg/app.js", "console.log(1)"),
        ("ui/pg/ui-manifest.json", GOOD),
        ("ui/a/index.html", "<html>a</html>"),
        ("ui/a/ui-manifest.json", GOOD),
        // No manifest: generic static pages exactly as before (not a atomdns UI package).
        ("ui/plain/index.html", "<html>plain</html>"),
        ("ui/newer/index.html", "x"),
        ("ui/newer/ui-manifest.json", TOO_NEW),
        ("ui/broken/index.html", "x"),
        ("ui/broken/ui-manifest.json", "{nope"),
        ("ui/log/index.html", "x"),
        ("ui/log/ui-manifest.json", GOOD),
    ] {
        fixture.write(path, text);
    }
    let host = assembly_for(&fixture);
    host.block_on(async {
        let bound = host.bind_host().await.unwrap();
        let api = bound.api_addr().unwrap();
        let shutdown = TransportCancellation::new();
        let task = tokio::task::spawn_local(bound.serve(shutdown.clone()));
        let health = http_request(api, &get("/api/v1/system/health")).await;
        assert_eq!(health.status, 200, "readiness is not affected");
        let health: serde_json::Value = serde_json::from_str(&health.body).unwrap();
        let listed = health["external_ui"].as_array().unwrap();
        let find = |name: &str| listed.iter().find(|entry| entry["name"] == name).unwrap();
        for name in ["pg", "a"] {
            let entry = find(name);
            assert_eq!(
                (
                    entry["mounted"].as_bool(),
                    entry["kind"].as_str(),
                    entry["ui_version"].as_str(),
                    entry["built_at"].as_str()
                ),
                (
                    Some(true),
                    Some("atomdns_ui"),
                    Some("v9.9"),
                    Some("2026-10-17T00:00:00Z")
                ),
                "{name}"
            );
            assert!(entry["reason"].is_null(), "{name}");
        }
        let plain = find("plain");
        assert_eq!(
            (
                plain["mounted"].as_bool(),
                plain["kind"].as_str(),
                plain["reason"].as_str()
            ),
            (
                Some(true),
                Some("static"),
                Some("非 atomdns UI 包（无 manifest）")
            )
        );
        assert!(plain["ui_version"].is_null());
        for (name, kind, reason) in [
            ("newer", "atomdns_ui", "需要接口级别 2"),
            ("broken", "atomdns_ui", "不是合法的 JSON"),
            ("log", "unusable", "保留名"),
        ] {
            let entry = find(name);
            assert_eq!(
                (entry["mounted"].as_bool(), entry["kind"].as_str()),
                (Some(false), Some(kind)),
                "{name}"
            );
            assert!(
                entry["reason"].as_str().unwrap().contains(reason),
                "{name}: {entry}"
            );
        }
        // Mounted packages work under their own names, whatever those are.
        for (name, body) in [("pg", "<html>external</html>"), ("a", "<html>a</html>")] {
            let redirect = http_request(api, &get(&format!("/{name}?x=1"))).await;
            assert_eq!(
                (redirect.status, redirect.header("location")),
                (301, Some(format!("/{name}/?x=1").as_str()))
            );
            let index = http_request(api, &get(&format!("/{name}/"))).await;
            assert_eq!((index.status, index.body.as_str()), (200, body), "{name}");
            assert_eq!(
                index.header("content-type"),
                Some("text/html; charset=utf-8")
            );
            assert_eq!(index.header("cache-control"), Some("no-store"));
        }
        let script = http_request(api, &get("/pg/app.js")).await;
        assert_eq!(
            (script.status, script.header("content-type")),
            (200, Some("text/javascript; charset=utf-8"))
        );
        assert_eq!(script.header("x-content-type-options"), Some("nosniff"));
        // Files are re-read on every request: a replaced file is served at once.
        fixture.write("ui/pg/index.html", "<html>replaced</html>");
        assert_eq!(
            http_request(api, &get("/pg/")).await.body,
            "<html>replaced</html>"
        );
        // The package cannot read outside itself; the manifest is one of its public files.
        assert_eq!(
            http_request(api, &get("/pg/%2e%2e/config.yaml"))
                .await
                .status,
            404
        );
        assert_eq!(http_request(api, &get("/pg/missing.js")).await.status, 404);
        assert_eq!(
            http_request(api, &get("/pg/ui-manifest.json")).await.status,
            200
        );
        // A directory without a manifest keeps working as plain static pages.
        assert_eq!(
            http_request(api, &get("/plain/")).await.body,
            "<html>plain</html>"
        );
        // Refused or reserved: not served.
        for path in [
            "/newer/",
            "/broken/",
            "/broken/ui-manifest.json",
            "/log/",
            "/log",
        ] {
            assert_eq!(http_request(api, &get(path)).await.status, 404, "{path}");
        }
        // Without `ui/main`, `/` is the "no WebUI" page and everything else is unaffected.
        assert_eq!(http_request(api, &get("/")).await.status, 404);
        shutdown.cancel();
        task.await.unwrap().unwrap();
    });
}

#[cfg(target_os = "linux")]
async fn exercise_encoded_redirects(api: SocketAddr) {
    let get = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n");
    for (path, body) in [
        ("/a%3Fb%25%23%20%E7%A9%BA", "reserved root"),
        ("/demo/n%3F%25%23%20%E7%A9%BA", "reserved nested"),
    ] {
        let response = http_request(api, &get(&format!("{path}?safe=%E7%A9%BA&x=1"))).await;
        assert_eq!(response.status, 301);
        let expected = format!("{path}/?safe=%E7%A9%BA&x=1");
        assert_eq!(response.header("location"), Some(expected.as_str()));
        let followed = http_request(api, &get(&expected)).await;
        assert_eq!(followed.status, 200);
        assert_eq!(followed.body, body);
    }
}

#[cfg(target_os = "linux")]
async fn exercise_ui_swaps(api: SocketAddr, fixture: &Fixture) {
    use std::os::unix::fs::symlink;
    struct SwapOwner(
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        Option<std::thread::JoinHandle<()>>,
    );
    impl Drop for SwapOwner {
        fn drop(&mut self) {
            self.0.store(false, std::sync::atomic::Ordering::SeqCst);
            self.1.take().unwrap().join().unwrap();
        }
    }
    let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let flag = running.clone();
    let race_root = fixture.root.clone();
    let swap = SwapOwner(
        running,
        Some(std::thread::spawn(move || {
            while flag.load(std::sync::atomic::Ordering::SeqCst) {
                fs::rename(
                    race_root.join("ui/old/nested"),
                    race_root.join("ui/old/safe"),
                )
                .unwrap();
                symlink(&race_root, race_root.join("ui/old/nested")).unwrap();
                std::thread::yield_now();
                fs::remove_file(race_root.join("ui/old/nested")).unwrap();
                fs::rename(
                    race_root.join("ui/old/safe"),
                    race_root.join("ui/old/nested"),
                )
                .unwrap();
            }
        })),
    );
    for _ in 0..100 {
        let leak = http_request(api, &get("/demo/nested/secret.txt")).await;
        assert_eq!(leak.status, 404);
        assert!(!leak.body.contains("SECRET"));
        let legitimate = http_request(api, &get("/demo/nested/file.js")).await;
        assert!(matches!(legitimate.status, 200 | 404));
        if legitimate.status == 200 {
            assert_eq!(legitimate.body, "nested");
        }
    }
    drop(swap);
}
