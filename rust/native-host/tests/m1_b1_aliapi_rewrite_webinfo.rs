//! M1-b1: the `aliapi` upstream group (standard DNS upstreams, SOCKS5 for the
//! TCP-based ones), `rewrite` and `webinfo`, driven through real UDP/TCP/TLS
//! sockets, a local SOCKS5 proxy and the real management API. No test reaches
//! the public network.

#![allow(clippy::too_many_lines)]

use std::cell::RefCell;
use std::net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use atomdns_native_host::{BoundHost, HostAssembly, HostOptions, compile_yaml};
use atomdns_upstream_core::TransportCancellation;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// ----- fixture tree and wire helpers -------------------------------------------

struct Tree(PathBuf);

impl Tree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("m1-b1-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn write(&self, relative: &str, text: &str) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
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

fn free_udp_port() -> u16 {
    StdUdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(u8::try_from(label.len()).unwrap());
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn dns_query(name: &str, qtype: u16, extra: &[u8], additional: u16) -> Vec<u8> {
    let mut packet = vec![0x4b, 0x21, 0x01, 0x00, 0, 1, 0, 0, 0, 0];
    packet.extend_from_slice(&additional.to_be_bytes());
    packet.extend_from_slice(&wire_name(name));
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&[0, 1]);
    packet.extend_from_slice(extra);
    packet
}

fn question_end(packet: &[u8]) -> usize {
    let mut position = 12;
    while packet[position] != 0 {
        position += 1 + usize::from(packet[position]);
    }
    position + 5
}

fn qtype_of(packet: &[u8]) -> u16 {
    let end = question_end(packet);
    u16::from_be_bytes([packet[end - 4], packet[end - 3]])
}

fn qname_of(packet: &[u8]) -> String {
    let mut position = 12;
    let mut labels = Vec::new();
    while packet[position] != 0 {
        let length = usize::from(packet[position]);
        labels.push(
            String::from_utf8_lossy(&packet[position + 1..position + 1 + length]).into_owned(),
        );
        position += 1 + length;
    }
    labels.join(".")
}

/// A response to `query` with the given rcode and records (`name` points at
/// the question, `data` is the RDATA).
fn response(query: &[u8], rcode: u8, answers: &[(u16, u32, Vec<u8>)]) -> Vec<u8> {
    let end = question_end(query);
    let mut out = vec![query[0], query[1], 0x81, 0x80 | rcode];
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&u16::try_from(answers.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..end]);
    for (kind, ttl, data) in answers {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

fn a_answer(query: &[u8], marker: u8) -> Vec<u8> {
    response(query, 0, &[(1, 60, vec![192, 0, 2, marker])])
}

fn rcode(response: &[u8]) -> u8 {
    response[3] & 0x0f
}

fn ancount(response: &[u8]) -> u16 {
    u16::from_be_bytes([response[6], response[7]])
}

fn addresses(response: &[u8]) -> Vec<IpAddr> {
    atomdns_dns_core::observe_answer_addresses(response).unwrap()
}

/// TTL of the first answer record.
fn first_ttl(response: &[u8]) -> u32 {
    let mut at = question_end(response);
    // Skip the owner name: a compression pointer or a label sequence.
    if response[at] & 0xc0 == 0xc0 {
        at += 2;
    } else {
        while response[at] != 0 {
            at += 1 + usize::from(response[at]);
        }
        at += 1;
    }
    at += 4;
    u32::from_be_bytes([
        response[at],
        response[at + 1],
        response[at + 2],
        response[at + 3],
    ])
}

fn marker_ip(marker: u8) -> Vec<IpAddr> {
    vec![IpAddr::from([192, 0, 2, marker])]
}

// ----- local servers -----------------------------------------------------------

type Handler = Box<dyn Fn(&[u8]) -> Option<Vec<u8>> + Send>;

/// A UDP DNS server on a thread; `handler` returns the response or `None` to
/// stay silent. Every received query is recorded.
struct UdpServer {
    address: SocketAddr,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl UdpServer {
    fn start(handler: Handler) -> Self {
        Self::start_on("127.0.0.1:0", handler)
    }

    fn start_on(bind: &str, handler: Handler) -> Self {
        let socket = StdUdpSocket::bind(bind).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (record, stopped) = (Arc::clone(&seen), Arc::clone(&stop));
        let thread = thread::spawn(move || {
            let mut packet = vec![0_u8; 4096];
            while !stopped.load(Ordering::SeqCst) {
                let Ok((length, client)) = socket.recv_from(&mut packet) else {
                    continue;
                };
                record.lock().unwrap().push(packet[..length].to_vec());
                if let Some(reply) = handler(&packet[..length]) {
                    let _ = socket.send_to(&reply, client);
                }
            }
        });
        Self {
            address,
            seen,
            stop,
            thread: Some(thread),
        }
    }

    fn answering(marker: u8) -> Self {
        Self::start(Box::new(move |query| Some(a_answer(query, marker))))
    }

    fn silent() -> Self {
        Self::start(Box::new(|_| None))
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl Drop for UdpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

/// Serves plain DNS-over-TCP on `listener`, answering `marker`.
fn serve_tcp(listener: std::net::TcpListener, marker: u8, connections: Rc<AtomicUsize>) {
    listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            connections.fetch_add(1, Ordering::SeqCst);
            tokio::task::spawn_local(async move {
                let Ok(length) = stream.read_u16().await else {
                    return;
                };
                let mut packet = vec![0; usize::from(length)];
                if stream.read_exact(&mut packet).await.is_err() {
                    return;
                }
                let reply = a_answer(&packet, marker);
                let _ = stream.write_u16(u16::try_from(reply.len()).unwrap()).await;
                let _ = stream.write_all(&reply).await;
                let mut scratch = [0; 16];
                let _ =
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut scratch)).await;
            });
        }
    });
}

struct SecureFixture {
    root: rustls::pki_types::CertificateDer<'static>,
    leaf: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
}

fn secure_fixture() -> SecureFixture {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose, SanType, date_time_ymd,
    };
    let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut root_params = CertificateParams::default();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "m1-b1-test-root");
    root_params.not_before = date_time_ymd(2024, 1, 1);
    root_params.not_after = date_time_ymd(2036, 1, 1);
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = root_params.self_signed(&root_key).unwrap();
    let issuer = Issuer::from_params(&root_params, &root_key);
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "dns.example");
    leaf_params.subject_alt_names = vec![SanType::DnsName("dns.example".try_into().unwrap())];
    leaf_params.not_before = date_time_ymd(2024, 1, 1);
    leaf_params.not_after = date_time_ymd(2036, 1, 1);
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
    SecureFixture {
        root: root.der().clone(),
        leaf: leaf.der().clone(),
        key: rustls::pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der()).unwrap(),
    }
}

fn server_config(fixture: &SecureFixture, alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![fixture.leaf.clone(), fixture.root.clone()],
        fixture.key.clone_key(),
    )
    .unwrap();
    config.alpn_protocols = alpn.iter().map(|protocol| (*protocol).to_vec()).collect();
    Arc::new(config)
}

fn roots(fixture: &SecureFixture) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(fixture.root.clone()).unwrap();
    roots
}

/// `DoT` on `listener`, answering `marker`.
fn serve_dot(listener: std::net::TcpListener, config: Arc<rustls::ServerConfig>, marker: u8) {
    listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&config));
            tokio::task::spawn_local(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let Ok(length) = stream.read_u16().await else {
                    return;
                };
                let mut packet = vec![0; usize::from(length)];
                if stream.read_exact(&mut packet).await.is_err() {
                    return;
                }
                let reply = a_answer(&packet, marker);
                let _ = stream.write_u16(u16::try_from(reply.len()).unwrap()).await;
                let _ = stream.write_all(&reply).await;
                let _ = stream.flush().await;
                let mut scratch = [0; 16];
                let _ =
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut scratch)).await;
            });
        }
    });
}

/// `DoH` over HTTP/2 on `listener`, answering `marker`.
fn serve_doh(listener: std::net::TcpListener, config: Arc<rustls::ServerConfig>, marker: u8) {
    use base64::Engine as _;
    listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&config));
            tokio::task::spawn_local(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let Ok(mut connection) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    let target = request.uri().path_and_query().unwrap().as_str().to_owned();
                    let encoded = target
                        .split_once("dns=")
                        .unwrap()
                        .1
                        .split('&')
                        .next()
                        .unwrap();
                    let query = base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(encoded)
                        .unwrap();
                    let head = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/dns-message")
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(head, false).unwrap();
                    send.send_data(bytes::Bytes::from(a_answer(&query, marker)), true)
                        .unwrap();
                }
            });
        }
    });
}

/// A SOCKS5 proxy (no authentication) that records every CONNECT target and
/// resolves the names in `names` to local addresses.
fn serve_proxy(
    listener: std::net::TcpListener,
    names: Vec<(&'static str, SocketAddr)>,
    targets: Rc<RefCell<Vec<String>>>,
) {
    listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    tokio::task::spawn_local(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                return;
            };
            let names = names.clone();
            let targets = Rc::clone(&targets);
            tokio::task::spawn_local(async move {
                let mut greeting = [0u8; 3];
                if client.read_exact(&mut greeting).await.is_err() {
                    return;
                }
                client.write_all(&[5, 0]).await.unwrap();
                let mut head = [0u8; 4];
                client.read_exact(&mut head).await.unwrap();
                let host = if head[3] == 1 {
                    let mut ip = [0u8; 4];
                    client.read_exact(&mut ip).await.unwrap();
                    std::net::Ipv4Addr::from(ip).to_string()
                } else {
                    let mut length = [0u8; 1];
                    client.read_exact(&mut length).await.unwrap();
                    let mut name = vec![0u8; usize::from(length[0])];
                    client.read_exact(&mut name).await.unwrap();
                    String::from_utf8(name).unwrap()
                };
                let mut port = [0u8; 2];
                client.read_exact(&mut port).await.unwrap();
                let port = u16::from_be_bytes(port);
                targets.borrow_mut().push(format!("{host}:{port}"));
                let destination = names
                    .iter()
                    .find_map(|(name, address)| (*name == host).then_some(*address))
                    .unwrap_or_else(|| format!("{host}:{port}").parse().unwrap());
                let Ok(mut upstream) = TcpStream::connect(destination).await else {
                    return;
                };
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
}

// ----- host helpers -----------------------------------------------------------

struct Ports {
    dns: u16,
    api: u16,
}

fn ports() -> Ports {
    Ports {
        dns: free_udp_port(),
        api: free_tcp_port(),
    }
}

/// `plugins` + an entry sequence + a UDP listener (audit on) + the API.
fn config(ports: &Ports, plugins: &str, sequence: &str) -> String {
    format!(
        "log: {{level: error}}\napi: {{http: \"127.0.0.1:{api}\"}}\nplugins:\n{plugins}  - tag: entry\n    type: sequence\n    args:\n{sequence}  - tag: listener\n    type: udp_server\n    args: {{entry: entry, listen: \"127.0.0.1:{dns}\", enable_audit: true}}\n",
        api = ports.api,
        dns = ports.dns
    )
}

fn assemble(tree: &Tree, yaml: &str, options: HostOptions) -> HostAssembly {
    tree.write("config.yaml", yaml);
    let config =
        atomdns_native_host::load_and_compile(&tree.path("config.yaml")).expect("compiles");
    HostAssembly::with_options(config, options).expect("assembles")
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

async fn ask(port: u16, packet: &[u8], wait: Duration) -> Option<Vec<u8>> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(packet, ("127.0.0.1", port)).await.unwrap();
    let mut buffer = vec![0; 4096];
    let (length, _) = tokio::time::timeout(wait, socket.recv_from(&mut buffer))
        .await
        .ok()?
        .unwrap();
    buffer.truncate(length);
    Some(buffer)
}

async fn a_query(port: u16, name: &str) -> Vec<u8> {
    ask(port, &dns_query(name, 1, &[], 0), Duration::from_secs(8))
        .await
        .expect("a response")
}

// ----- aliapi: compile ---------------------------------------------------------

fn alias_yaml(args: &str) -> String {
    format!(
        "log: {{level: error}}\nplugins:\n  - tag: group\n    type: aliapi\n    args:\n{args}  - tag: entry\n    type: sequence\n    args:\n      - exec: $group\n  - tag: listener\n    type: udp_server\n    args: {{entry: entry, listen: \"127.0.0.1:15400\"}}\n"
    )
}

fn compile_error(args: &str) -> String {
    match compile_yaml(&alias_yaml(args)) {
        Ok(_) => panic!("must not compile: {args}"),
        Err(error) => format!("{} {}", error.path, error.reason),
    }
}

#[test]
fn aliapi_compiles_the_production_shapes() {
    // `domestic`, `foreign`, `nocnfake` as the production configuration writes them.
    let domestic = compile_yaml(&alias_yaml(
        "      concurrent: 3\n      upstreams:\n        - addr: \"223.5.5.5\"\n        - addr: \"223.6.6.6\"\n        - addr: \"114.114.114.114\"\n",
    ))
    .expect("bare IPs");
    let definition = &domestic.forward_definitions[0];
    assert_eq!(definition.concurrent, 3);
    assert_eq!(definition.entries.len(), 3);
    assert!(
        definition
            .entries
            .iter()
            .all(|entry| entry.target.socks5.is_none())
    );

    let foreign = compile_yaml(&alias_yaml(
        "      concurrent: 2\n      upstreams:\n        - addr: \"https://1.1.1.1/dns-query\"\n          socks5: \"192.0.2.1:7890\"\n        - addr: \"https://8.8.8.8/dns-query\"\n          socks5: \"192.0.2.1:7890\"\n          upstream_query_timeout: 1000\n",
    ))
    .expect("https via socks5");
    let entries = &foreign.forward_definitions[0].entries;
    assert_eq!(entries[0].target.socks5.as_deref(), Some("192.0.2.1:7890"));
    assert_eq!(entries[1].target.query_timeout, Duration::from_secs(1));
    assert_eq!(entries[0].target.query_timeout, Duration::from_secs(5));

    // `socks5: ""` is the same as no proxy.
    let empty = compile_yaml(&alias_yaml(
        "      socks5: \"\"\n      upstreams:\n        - addr: \"udp://127.0.0.1:7874\"\n",
    ))
    .expect("empty socks5");
    assert!(
        empty.forward_definitions[0].entries[0]
            .target
            .socks5
            .is_none()
    );
}

#[test]
fn aliapi_concurrent_is_clamped_and_plugin_defaults_fill_empty_values() {
    let wide = compile_yaml(&alias_yaml(
        "      concurrent: 99\n      socks5: \"127.0.0.1:1080\"\n      bootstrap: \"127.0.0.1:53\"\n      upstreams:\n        - addr: \"udp://127.0.0.1:5301\"\n        - addr: \"tcp://127.0.0.1:5302\"\n        - addr: \"tls://dns.example\"\n          socks5: \"127.0.0.1:2080\"\n        - {addr: \"https://dns.example/dns-query\", bootstrap_version: 4}\n",
    ))
    .expect("defaults");
    let definition = &wide.forward_definitions[0];
    assert_eq!(definition.concurrent, 20);
    let proxies: Vec<_> = definition
        .entries
        .iter()
        .map(|entry| entry.target.socks5.as_deref())
        .collect();
    // UDP ignores the proxy; the others inherit it unless they set their own.
    assert_eq!(
        proxies,
        [
            None,
            Some("127.0.0.1:1080"),
            Some("127.0.0.1:2080"),
            Some("127.0.0.1:1080")
        ]
    );
    assert_eq!(definition.entries[3].target.bootstrap_version, Some(4));
    assert!(definition.entries[3].target.bootstrap.is_some());

    let none = compile_yaml(&alias_yaml(
        "      concurrent: -4\n      upstreams:\n        - addr: \"udp://127.0.0.1:5301\"\n",
    ))
    .unwrap();
    assert_eq!(none.forward_definitions[0].concurrent, 1);
}

#[test]
fn aliapi_rejects_what_it_cannot_honor_instead_of_dropping_it() {
    let one = |extra: &str| {
        format!("      upstreams:\n        - addr: \"udp://127.0.0.1:5301\"\n{extra}")
    };
    // The signed AliDNS API, at the plugin and at the upstream level.
    assert!(
        compile_error(&format!("      account_id: \"1\"\n{}", one(""))).contains("signed AliDNS")
    );
    assert!(
        compile_error(&format!("      access_key_secret: x\n{}", one("")))
            .contains("signed AliDNS")
    );
    assert!(compile_error(&one("          type: aliapi\n")).contains("signed AliDNS"));
    // Presence is what counts: an empty or zero value still asks for the signed API.
    for field in [
        "account_id: \"\"",
        "access_key_secret: null",
        "ecs_client_mask: 0",
    ] {
        assert!(
            compile_error(&format!("      {field}\n{}", one(""))).contains("signed AliDNS"),
            "{field}"
        );
    }
    // Options the native transports do not implement.
    for (option, name) in [
        ("so_mark: 7", "so_mark"),
        ("bind_to_device: eth0", "bind_to_device"),
        ("enable_pipeline: true", "enable_pipeline"),
        ("idle_timeout: 30", "idle_timeout"),
    ] {
        let message = compile_error(&one(&format!("          {option}\n")));
        assert!(
            message.contains(name) && message.contains("unsupported"),
            "{option}: {message}"
        );
    }
    // Zero and false values are the defaults, not requests.
    compile_yaml(&alias_yaml(&one(
        "          so_mark: 0\n          enable_http3: false\n          idle_timeout: 0\n          max_conns: 3\n",
    )))
    .expect("defaults are accepted");
    // Plain misconfigurations.
    assert!(compile_error("      upstreams: []\n").contains("must not be empty"));
    assert!(compile_error("      upstreams:\n        - tag: a\n          addr: \"udp://127.0.0.1:1\"\n        - tag: a\n          addr: \"udp://127.0.0.1:2\"\n").contains("duplicated upstream tag"));
    assert!(compile_error("      upstreams:\n        - addr: \"\"\n").contains("addr is required"));
    assert!(compile_error(&one("          enable_http3: true\n")).contains("enable_http3"));
    assert!(
        compile_error("      socks5: '192.0.2.1:1080'\n      upstreams:\n        - addr: 'quic://192.0.2.53'\n")
            .contains("group's literal socks5 address")
    );
    assert!(
        compile_error("      upstreams:\n        - addr: \"dns.example\"\n")
            .contains("numeric dial_addr or bootstrap")
    );
    assert!(compile_error("      upstreams:\n        - addr: \"udp://127.0.0.1:1\"\n          upstream_query_timeout: -1\n").contains("negative"));
    assert!(
        compile_error(
            "      nonsense: 1\n      upstreams:\n        - addr: \"udp://127.0.0.1:1\"\n"
        )
        .contains("unsupported field")
    );
}

#[test]
fn a_proxied_hostname_needs_no_numeric_address_but_forward_still_rejects_socks5() {
    // The proxy resolves the name, so neither dial_addr nor bootstrap is needed.
    let config = compile_yaml(&alias_yaml(
        "      upstreams:\n        - {addr: \"https://dns.example/dns-query\", socks5: \"127.0.0.1:1080\"}\n        - {addr: \"tcp://dns.example\", socks5: \"127.0.0.1:1080\"}\n",
    ))
    .expect("proxied hostnames");
    let entries = &config.forward_definitions[0].entries;
    assert!(entries.iter().all(|entry| entry.target.dial_addr.is_none()));
    // A `forward` plugin keeps rejecting `socks5` (the option is aliapi's).
    let forward = "log: {level: error}\nplugins:\n  - tag: f\n    type: forward\n    args: {upstreams: [{addr: \"tcp://127.0.0.1:53\", socks5: \"127.0.0.1:1\"}]}\n  - tag: entry\n    type: sequence\n    args: [{exec: $f}]\n  - tag: l\n    type: udp_server\n    args: {entry: entry, listen: \"127.0.0.1:15400\"}\n";
    let Err(error) = compile_yaml(forward) else {
        panic!("forward must reject socks5")
    };
    assert!(error.reason.contains("unsupported"));
}

// ----- aliapi: queries ---------------------------------------------------------

#[test]
fn aliapi_races_concurrent_upstreams_and_takes_the_first_address_answer() {
    let dead = UdpServer::silent();
    let live = UdpServer::answering(33);
    let ports = ports();
    let tree = Tree::new("race");
    let plugins = format!(
        "  - tag: group\n    type: aliapi\n    args:\n      concurrent: 2\n      upstreams:\n        - {{tag: dead, addr: \"udp://{}\", upstream_query_timeout: 400}}\n        - {{tag: live, addr: \"udp://{}\"}}\n",
        dead.address, live.address
    );
    let host = assemble(
        &tree,
        &config(&ports, &plugins, "      - exec: $group\n"),
        HostOptions::default(),
    );
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        for _ in 0..4 {
            let started = Instant::now();
            let reply = a_query(ports.dns, "race.test").await;
            assert_eq!(rcode(&reply), 0);
            assert_eq!(addresses(&reply), ["192.0.2.33".parse::<IpAddr>().unwrap()]);
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "{:?}",
                started.elapsed()
            );
        }
        shutdown.cancel();
        task.await.unwrap();
    });
    // The audit names the answering entry.
    let record = &host.audit_snapshot().records[0];
    let diagnostics = record.upstream_diagnostics.as_ref().unwrap();
    assert_eq!(diagnostics.selected.as_ref().unwrap().entry, "live");
}

#[test]
fn aliapi_without_an_answer_is_servfail_after_its_own_timeout() {
    let dead = UdpServer::silent();
    let ports = ports();
    let tree = Tree::new("timeout");
    let plugins = format!(
        "  - tag: group\n    type: aliapi\n    args:\n      upstreams:\n        - {{addr: \"udp://{}\", upstream_query_timeout: 300}}\n",
        dead.address
    );
    let host = assemble(
        &tree,
        &config(&ports, &plugins, "      - exec: $group\n"),
        HostOptions::default(),
    );
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        let started = Instant::now();
        let reply = a_query(ports.dns, "slow.test").await;
        assert_eq!(rcode(&reply), 2);
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(3),
            "{elapsed:?}"
        );
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn aliapi_reaches_tcp_dot_and_doh_through_a_socks5_proxy() {
    let fixture = secure_fixture();
    let tree = Tree::new("socks");
    let ports = ports();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dot = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let doh = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (tcp_addr, secure_addr, doh_addr, proxy_addr) = (
        tcp.local_addr().unwrap(),
        dot.local_addr().unwrap(),
        doh.local_addr().unwrap(),
        proxy.local_addr().unwrap(),
    );
    // One group per transport, so each query has exactly one possible path.
    // `via_dot` leaves out the numeric address: the proxy resolves
    // `dns.example`, which no resolver here knows.
    let plugins = format!(
        "  - tag: via_tcp\n    type: aliapi\n    args:\n      socks5: \"{proxy_addr}\"\n      upstreams:\n        - addr: \"tcp://{tcp_addr}\"\n  - tag: via_dot\n    type: aliapi\n    args:\n      upstreams:\n        - addr: \"tls://dns.example:{dot_port}\"\n          socks5: \"{proxy_addr}\"\n  - tag: via_doh\n    type: aliapi\n    args:\n      upstreams:\n        - addr: \"https://dns.example/dns-query\"\n          dial_addr: \"{doh_addr}\"\n          socks5: \"{proxy_addr}\"\n",
        dot_port = secure_addr.port()
    );
    let sequence = "      - matches: qname full:tcp.test\n        exec: $via_tcp\n      - matches: qname full:dot.test\n        exec: $via_dot\n      - matches: qname full:doh.test\n        exec: $via_doh\n";
    let host = assemble(
        &tree,
        &config(&ports, &plugins, sequence),
        HostOptions::default().with_tls_roots(roots(&fixture)),
    );
    host.block_on(async {
        let targets = Rc::new(RefCell::new(Vec::new()));
        let connections = Rc::new(AtomicUsize::new(0));
        serve_tcp(tcp, 41, Rc::clone(&connections));
        serve_dot(dot, server_config(&fixture, &[]), 42);
        serve_doh(doh, server_config(&fixture, &[b"h2"]), 43);
        serve_proxy(
            proxy,
            vec![("dns.example", secure_addr)],
            Rc::clone(&targets),
        );
        let (shutdown, task) = serve(&host).await;
        let reply = a_query(ports.dns, "tcp.test").await;
        assert_eq!(addresses(&reply), marker_ip(41));
        let reply = a_query(ports.dns, "dot.test").await;
        assert_eq!(addresses(&reply), marker_ip(42));
        let reply = a_query(ports.dns, "doh.test").await;
        assert_eq!(addresses(&reply), marker_ip(43));
        assert_eq!(
            *targets.borrow(),
            [
                format!("{}:{}", tcp_addr.ip(), tcp_addr.port()),
                // A hostname reaches the proxy as a name, to be resolved there.
                format!("dns.example:{}", secure_addr.port()),
                format!("{}:{}", doh_addr.ip(), doh_addr.port()),
            ]
        );
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn a_proxied_doh_hostname_is_resolved_by_the_proxy() {
    let fixture = secure_fixture();
    let tree = Tree::new("socks-name");
    let ports = ports();
    let doh = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let (doh_addr, proxy_addr) = (doh.local_addr().unwrap(), proxy.local_addr().unwrap());
    let plugins = format!(
        "  - tag: group\n    type: aliapi\n    args:\n      socks5: \"{proxy_addr}\"\n      upstreams:\n        - addr: \"https://dns.example:{}/dns-query\"\n",
        doh_addr.port()
    );
    let host = assemble(
        &tree,
        &config(&ports, &plugins, "      - exec: $group\n"),
        HostOptions::default().with_tls_roots(roots(&fixture)),
    );
    host.block_on(async {
        let targets = Rc::new(RefCell::new(Vec::new()));
        serve_doh(doh, server_config(&fixture, &[b"h2"]), 44);
        serve_proxy(proxy, vec![("dns.example", doh_addr)], Rc::clone(&targets));
        let (shutdown, task) = serve(&host).await;
        let reply = a_query(ports.dns, "name.test").await;
        assert_eq!(addresses(&reply), [IpAddr::from([192, 0, 2, 44])]);
        assert_eq!(
            *targets.borrow(),
            [format!("dns.example:{}", doh_addr.port())]
        );
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn udp_ignores_the_proxy_and_a_dead_proxy_fails_the_tcp_upstream() {
    let udp = UdpServer::answering(51);
    let tree = Tree::new("socks-fail");
    let ports = ports();
    // A port nothing listens on.
    let closed = free_tcp_port();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let plugins = format!(
        "  - tag: via_udp\n    type: aliapi\n    args:\n      socks5: \"127.0.0.1:{closed}\"\n      upstreams:\n        - addr: \"udp://{}\"\n  - tag: via_tcp\n    type: aliapi\n    args:\n      socks5: \"127.0.0.1:{closed}\"\n      upstreams:\n        - addr: \"tcp://{tcp_addr}\"\n",
        udp.address
    );
    let sequence = "      - matches: qname full:udp.test\n        exec:\n          - $via_udp\n          - exit\n      - exec: $via_tcp\n";
    let host = assemble(
        &tree,
        &config(&ports, &plugins, sequence),
        HostOptions::default(),
    );
    host.block_on(async {
        let connections = Rc::new(AtomicUsize::new(0));
        serve_tcp(tcp, 52, Rc::clone(&connections));
        let (shutdown, task) = serve(&host).await;
        let reply = a_query(ports.dns, "udp.test").await;
        assert_eq!(addresses(&reply), [IpAddr::from([192, 0, 2, 51])]);
        // The TCP upstream does not fall back to a direct connection.
        let reply = a_query(ports.dns, "tcp.test").await;
        assert_eq!(rcode(&reply), 2);
        assert_eq!(connections.load(Ordering::SeqCst), 0);
        shutdown.cancel();
        task.await.unwrap();
    });
}

// ----- rewrite ----------------------------------------------------------------

const REWRITE_RULES: &str = "# static targets\ndomain:ip4.test 192.0.2.4\nfull:ip6.test 2001:db8::6\nfull:mapped.test ::ffff:192.0.2.9\ndomain:alias.test target.example\nfull:nx.test missing.example\n";

fn rewrite_dns_server() -> UdpServer {
    rewrite_dns_server_on("127.0.0.1:0")
}

fn rewrite_dns_server_on(bind: &str) -> UdpServer {
    UdpServer::start_on(
        bind,
        Box::new(|query| {
            Some(match qname_of(query).as_str() {
                "target.example" if qtype_of(query) == 1 => response(
                    query,
                    0,
                    &[(1, 600, vec![192, 0, 2, 77]), (1, 900, vec![192, 0, 2, 78])],
                ),
                "target.example" => response(query, 0, &[]),
                _ => response(query, 3, &[]),
            })
        }),
    )
}

fn rewrite_tree(name: &str, dns: SocketAddr, forward: SocketAddr) -> (Tree, Ports, String) {
    let tree = Tree::new(name);
    tree.write("rule/rewrite.txt", REWRITE_RULES);
    let ports = ports();
    let plugins = format!(
        "  - tag: fwd\n    type: forward\n    args: {{upstreams: [{{addr: \"udp://{forward}\"}}]}}\n  - tag: rewrite\n    type: rewrite\n    args:\n      files: [\"rule/rewrite.txt\"]\n      dns: \"{dns}\"\n"
    );
    let yaml = config(
        &ports,
        &plugins,
        "      - exec: $rewrite\n      - exec: $fwd\n",
    );
    (tree, ports, yaml)
}

#[test]
fn rewrite_answers_static_and_resolved_targets_and_accepts_the_query() {
    let dns = rewrite_dns_server();
    let forward = UdpServer::answering(99);
    let (tree, ports, yaml) = rewrite_tree("rewrite", dns.address, forward.address);
    let host = assemble(&tree, &yaml, HostOptions::default());
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        let ask_type = |name: &'static str, qtype: u16, extra: &'static [u8], additional: u16| {
            let packet = dns_query(name, qtype, extra, additional);
            async move {
                ask(ports.dns, &packet, Duration::from_secs(8))
                    .await
                    .unwrap()
            }
        };

        // A static IPv4 target: one answer with the fixed TTL, nothing forwarded.
        let reply = ask_type("www.ip4.test", 1, &[], 0).await;
        assert_eq!(
            (rcode(&reply), ancount(&reply), first_ttl(&reply)),
            (0, 1, 5)
        );
        assert_eq!(addresses(&reply), [IpAddr::from([192, 0, 2, 4])]);
        assert_eq!(reply[2] & 0x01, 0x01, "the query's RD flag is kept");
        // The other family and other types: NOERROR without answers.
        for qtype in [28, 15] {
            let reply = ask_type("www.ip4.test", qtype, &[], 0).await;
            assert_eq!((rcode(&reply), ancount(&reply)), (0, 0), "type {qtype}");
        }
        let reply = ask_type("ip6.test", 28, &[], 0).await;
        assert_eq!(
            addresses(&reply),
            ["2001:db8::6".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(first_ttl(&reply), 5);
        // An IPv4-mapped IPv6 target is IPv4.
        let reply = ask_type("mapped.test", 1, &[], 0).await;
        assert_eq!(addresses(&reply), [IpAddr::from([192, 0, 2, 9])]);
        assert_eq!(forward.count(), 0, "a match accepts the query");
        assert_eq!(dns.count(), 0);

        // A domain target is resolved through `dns`; EDNS 1232 + the DO bit
        // are carried, and every answer TTL becomes 5.
        let opt_with_do: &[u8] = &[0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0];
        let reply = ask_type("a.alias.test", 1, opt_with_do, 1).await;
        assert_eq!(
            (rcode(&reply), ancount(&reply), first_ttl(&reply)),
            (0, 2, 5)
        );
        assert_eq!(
            addresses(&reply),
            [IpAddr::from([192, 0, 2, 77]), IpAddr::from([192, 0, 2, 78])]
        );
        let sent = dns.seen.lock().unwrap().last().cloned().unwrap();
        assert_eq!(qname_of(&sent), "target.example");
        assert_eq!(
            u16::from_be_bytes([sent[10], sent[11]]),
            1,
            "one OPT record"
        );
        let opt = &sent[question_end(&sent)..];
        assert_eq!(&opt[1..5], &[0, 41, 0x04, 0xd0], "payload size 1232");
        assert_eq!(opt[7] & 0x80, 0x80, "DO bit");
        // Types other than A/AAAA never ask the DNS server.
        let before = dns.count();
        let reply = ask_type("a.alias.test", 15, &[], 0).await;
        assert_eq!((rcode(&reply), ancount(&reply)), (0, 0));
        assert_eq!(dns.count(), before);
        // A failed lookup is SERVFAIL.
        let reply = ask_type("nx.test", 1, &[], 0).await;
        assert_eq!(rcode(&reply), 2);

        // No rule: the rest of the sequence runs.
        let reply = ask_type("other.test", 1, &[], 0).await;
        assert_eq!(addresses(&reply), [IpAddr::from([192, 0, 2, 99])]);
        assert_eq!(forward.count(), 1);
        shutdown.cancel();
        task.await.unwrap();
    });
    // The audit label of a rewritten query.
    let records = host.audit_snapshot().records;
    let labelled = records
        .iter()
        .filter(|record| record.domain_set.as_deref() == Some("重定向"))
        .count();
    assert_eq!(labelled, 8);
    assert!(records.last().unwrap().domain_set.as_deref() != Some("重定向"));
}

#[test]
fn rewrite_resolves_a_named_dns_server_at_query_time() {
    use std::net::ToSocketAddrs;
    // The server listens on the address family the resolver lists first for `localhost`.
    let first = ("localhost", 0).to_socket_addrs().unwrap().next().unwrap();
    let bind = if first.is_ipv6() {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    };
    let dns = rewrite_dns_server_on(bind);
    let forward = UdpServer::answering(99);
    let tree = Tree::new("rewrite-named");
    tree.write("rule/rewrite.txt", REWRITE_RULES);
    let ports = ports();
    let plugins = format!(
        "  - tag: fwd\n    type: forward\n    args: {{upstreams: [{{addr: \"udp://{}\"}}]}}\n  - tag: rewrite\n    type: rewrite\n    args:\n      files: [\"rule/rewrite.txt\"]\n      dns: \"localhost:{}\"\n",
        forward.address,
        dns.address.port()
    );
    let host = assemble(
        &tree,
        &config(
            &ports,
            &plugins,
            "      - exec: $rewrite\n      - exec: $fwd\n",
        ),
        HostOptions::default(),
    );
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        let reply = a_query(ports.dns, "x.alias.test").await;
        assert_eq!(
            addresses(&reply),
            [IpAddr::from([192, 0, 2, 77]), IpAddr::from([192, 0, 2, 78])]
        );
        assert_eq!(first_ttl(&reply), 5);
        assert_eq!(rcode(&a_query(ports.dns, "nx.test").await), 2);
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn rewrite_resolves_a_domain_target_through_a_sequence_without_a_socket() {
    let dns = rewrite_dns_server();
    let forward = UdpServer::answering(99);
    let tree = Tree::new("rewrite-sequence");
    tree.write("rule/rewrite.txt", REWRITE_RULES);
    let ports = ports();
    // `$resolve` is a plain sequence of this process: it is not bound to any port.
    let plugins = format!(
        "  - tag: fwd\n    type: forward\n    args: {{upstreams: [{{addr: \"udp://{}\"}}]}}\n  - tag: fwd_dns\n    type: forward\n    args: {{upstreams: [{{addr: \"udp://{}\"}}]}}\n  - tag: resolve\n    type: sequence\n    args:\n      - exec: $fwd_dns\n  - tag: rewrite\n    type: rewrite\n    args:\n      files: [\"rule/rewrite.txt\"]\n      dns: \"$resolve\"\n",
        forward.address, dns.address
    );
    let yaml = config(
        &ports,
        &plugins,
        "      - exec: $rewrite\n      - exec: $fwd\n",
    );
    let host = assemble(&tree, &yaml, HostOptions::default());
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        let reply = a_query(ports.dns, "x.alias.test").await;
        assert_eq!(
            addresses(&reply),
            [IpAddr::from([192, 0, 2, 77]), IpAddr::from([192, 0, 2, 78])]
        );
        assert_eq!(first_ttl(&reply), 5);
        assert!(dns.count() >= 1, "the sequence reached its upstream");
        // The target does not exist: a failed lookup is SERVFAIL.
        assert_eq!(rcode(&a_query(ports.dns, "nx.test").await), 2);
        assert_eq!(forward.count(), 0, "a match accepts the query");
        shutdown.cancel();
        task.await.unwrap();
    });
    // Only the two client queries are audited, not the sequence runs.
    assert_eq!(host.audit_snapshot().records.len(), 2);
}

#[test]
fn rewrite_sequence_that_rewrites_again_ends_in_servfail_instead_of_looping() {
    let forward = UdpServer::answering(99);
    let tree = Tree::new("rewrite-sequence-loop");
    tree.write(
        "rule/rewrite.txt",
        "full:ping.test pong.test\nfull:pong.test ping.test\n",
    );
    let ports = ports();
    // `entry` itself runs `$rewrite`, so the two rules chase each other.
    let plugins = format!(
        "  - tag: fwd\n    type: forward\n    args: {{upstreams: [{{addr: \"udp://{}\"}}]}}\n  - tag: rewrite\n    type: rewrite\n    args:\n      files: [\"rule/rewrite.txt\"]\n      dns: \"$entry\"\n",
        forward.address
    );
    let yaml = config(
        &ports,
        &plugins,
        "      - exec: $rewrite\n      - exec: $fwd\n",
    );
    let host = assemble(&tree, &yaml, HostOptions::default());
    host.block_on(async {
        let (shutdown, task) = serve(&host).await;
        assert_eq!(rcode(&a_query(ports.dns, "ping.test").await), 2);
        assert_eq!(forward.count(), 0);
        // A name outside the loop is still forwarded.
        let reply = a_query(ports.dns, "other.test").await;
        assert_eq!(addresses(&reply), [IpAddr::from([192, 0, 2, 99])]);
        shutdown.cancel();
        task.await.unwrap();
    });
}

#[test]
fn rewrite_dns_must_name_an_existing_sequence() {
    let compile = |dns: &str| {
        let tree = Tree::new("rewrite-sequence-compile");
        tree.write("rule/ok.txt", "full:a.test b.test\n");
        let yaml = format!(
            "log: {{level: error}}\nplugins:\n  - tag: f\n    type: forward\n    args: {{upstreams: [{{addr: \"udp://127.0.0.1:9\"}}]}}\n  - tag: r\n    type: rewrite\n    args: {{files: [rule/ok.txt], dns: '{dns}'}}\n  - tag: entry\n    type: sequence\n    args: [{{exec: $r}}, {{exec: $f}}]\n  - tag: l\n    type: udp_server\n    args: {{entry: entry, listen: \"127.0.0.1:15401\"}}\n"
        );
        atomdns_native_host::compile_yaml_with_base(&yaml, &tree.0)
            .err()
            .map(|error| error.reason)
    };
    assert!(compile("$entry").is_none());
    assert!(
        compile("$missing")
            .unwrap()
            .contains("does not reference a sequence")
    );
    assert!(
        compile("$f")
            .unwrap()
            .contains("does not reference a sequence")
    );
    assert!(compile("$").unwrap().contains("exactly one sequence"));
}

// ----- webinfo ----------------------------------------------------------------
