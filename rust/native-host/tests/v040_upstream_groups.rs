//! v0.4.0: `aliapi` `show_when` (display only) and its validation,
//! `GET /api/v1/upstream/groups`, and the refusal of a list without an enabled
//! upstream (instead of a raw compile error, or an empty list silently
//! restoring the YAML list).

use std::path::PathBuf;

use atomdns_native_host::{BoundHost, HostAssembly};
use atomdns_upstream_core::TransportCancellation;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Tree(PathBuf);

impl Tree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("v040-groups-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("webinfo")).unwrap();
        Self(root)
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

const FLAGS: &str = r"  - tag: cn_fakeip
    type: feature_flag
    args: {label: 国内域名 FakeIP, description: d, section: mode, kind: bool, default: false}
  - tag: dns_mode
    type: feature_flag
    args:
      label: DNS 分流模式
      description: d
      section: mode
      kind: choice
      options: [{value: fakeip, label: FakeIP 分流}, {value: realip, label: RealIP 分流}]
      default: fakeip
";

/// A configuration with the two flags, three `aliapi` groups (`cnfake` and
/// `nocnfake` carry `show_when: <cnfake>` / `<nocnfake>`) and the API.
fn config(tree: &Tree, cnfake: &str, nocnfake: &str, api: u16) {
    let body = r#"  - tag: domestic
    type: aliapi
    args: {upstreams: [{tag: d1, addr: "udp://127.0.0.1:9"}]}
  - tag: cnfake
    type: aliapi
    args: {show_when: CNFAKE, upstreams: [{tag: c1, addr: "udp://127.0.0.1:9"}]}
  - tag: nocnfake
    type: aliapi
    args: {show_when: NOCNFAKE, upstreams: [{tag: n1, addr: "udp://127.0.0.1:9"}]}
  - tag: entry
    type: sequence
    args:
      - matches: flag cn_fakeip
        exec: $cnfake
      - exec: $domestic
      - exec: $nocnfake
  - tag: listener
    type: udp_server
    args: {entry: entry, listen: "127.0.0.1:LISTEN"}
"#
    .replace("NOCNFAKE", nocnfake)
    .replace("CNFAKE", cnfake)
    .replace("LISTEN", &free_port().to_string());
    let text = format!(
        "log: {{level: error}}\napi: {{http: \"127.0.0.1:{api}\"}}\nplugins:\n{FLAGS}{body}"
    );
    std::fs::write(tree.path("config.yaml"), text).unwrap();
}

fn compile_error(tree: &Tree) -> String {
    match atomdns_native_host::load_and_compile(&tree.path("config.yaml")) {
        Ok(_) => panic!("compiled"),
        Err(error) => error.to_string(),
    }
}

struct Http {
    status: u16,
    body: String,
}

async fn api(port: u16, method: &str, path: &str, body: &str) -> Http {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: native\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").expect("http response");
    Http {
        status: head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        body: body.to_owned(),
    }
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|error| panic!("{error}: {text}"))
}

#[test]
fn show_when_is_validated_like_the_flag_matcher() {
    let tree = Tree::new("validate");
    let port = free_port();
    for (cnfake, reason) in [
        ("\"flag nope\"", "unknown feature_flag `nope`"),
        ("\"flag cn_fakeip=on\"", "is a bool flag"),
        ("\"flag dns_mode\"", "is a choice flag"),
        ("\"flag dns_mode=other\"", "is not an option"),
        ("\"cn_fakeip\"", "show_when takes"),
        ("[]", "non-empty list"),
        ("[1]", "show_when[0]"),
        ("true", "expected a condition"),
    ] {
        config(&tree, cnfake, "\"flag dns_mode=fakeip\"", port);
        let error = compile_error(&tree);
        assert!(error.contains(reason), "{cnfake}: {error}");
        assert!(
            error.contains("show_when"),
            "{cnfake}: the path names the key: {error}"
        );
    }
    for cnfake in [
        "\"flag cn_fakeip\"",
        "\"!flag cn_fakeip\"",
        "[\"flag cn_fakeip\", \"!flag dns_mode=realip\"]",
    ] {
        config(&tree, cnfake, "\"flag dns_mode=fakeip\"", port);
        atomdns_native_host::load_and_compile(&tree.path("config.yaml"))
            .unwrap_or_else(|error| panic!("{cnfake}: {error}"));
    }
}

#[test]
fn groups_follow_the_flags_and_a_list_without_an_enabled_upstream_is_refused() {
    let tree = Tree::new("api");
    let port = free_port();
    config(&tree, "flag cn_fakeip", "flag dns_mode=fakeip", port);
    let host = HostAssembly::from_config_file(&tree.path("config.yaml")).expect("assembles");
    host.block_on(async {
        let bound: BoundHost = host.bind_host().await.expect("binds");
        let shutdown = TransportCancellation::new();
        let scope = shutdown.clone();
        let task = tokio::task::spawn_local(async move {
            bound.serve(scope).await.expect("clean shutdown");
        });
        let groups = |body: &str| -> Vec<(String, bool, Option<String>)> {
            json(body)
                .as_array()
                .unwrap()
                .iter()
                .map(|group| {
                    (
                        group["tag"].as_str().unwrap().to_owned(),
                        group["active"].as_bool().unwrap(),
                        group["inactive_reason"].as_str().map(str::to_owned),
                    )
                })
                .collect()
        };
        let reply = api(port, "GET", "/api/v1/upstream/groups", "").await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert_eq!(
            groups(&reply.body),
            vec![
                ("cnfake".into(), false, Some("仅在「国内域名 FakeIP」开启时使用".into())),
                ("domestic".into(), true, None),
                ("nocnfake".into(), true, None),
            ]
        );
        assert_eq!(json(&reply.body)[0]["show_when"], serde_json::json!(["flag cn_fakeip"]));
        assert_eq!(json(&reply.body)[0]["used_when"], "「国内域名 FakeIP」开启");
        assert_eq!(json(&reply.body)[1]["show_when"], serde_json::json!([]));
        assert!(json(&reply.body)[1].get("used_when").is_none());
        let capabilities = json(&api(port, "GET", "/api/v1/capabilities", "").await.body);
        assert_eq!(capabilities["endpoints"]["upstream"]["groups_get"], true);

        // A flag change publishes a generation whose groups say so.
        for (key, value) in [("cn_fakeip", "true"), ("dns_mode", "\"realip\"")] {
            let reply = api(port, "POST", &format!("/api/v1/flags/{key}"), &format!("{{\"value\":{value}}}")).await;
            assert_eq!(reply.status, 200, "{}", reply.body);
        }
        let reply = api(port, "GET", "/api/v1/upstream/groups", "").await;
        assert_eq!(
            groups(&reply.body),
            vec![
                ("cnfake".into(), true, None),
                ("domestic".into(), true, None),
                ("nocnfake".into(), false, Some("仅在「DNS 分流模式」为「FakeIP 分流」时使用".into())),
            ]
        );

        // Disabling the only upstream: a reason in words, nothing stored.
        let before = std::fs::read_to_string(tree.path("webinfo/settings.json")).unwrap_or_default();
        let disabled = r#"{"plugin_tag":"cnfake","upstreams":[{"tag":"c1","enabled":false,"protocol":"udp","addr":"udp://127.0.0.1:9"}]}"#;
        let reply = api(port, "POST", "/api/v1/upstream/config", disabled).await;
        assert_eq!(reply.status, 400);
        assert!(reply.body.contains("上游组「cnfake」至少要保留一个启用的上游"), "{}", reply.body);
        assert!(reply.body.contains("「国内域名 FakeIP」开启时使用；不想用它，关闭该开关即可"), "{}", reply.body);
        assert!(!reply.body.contains("$.plugins"), "{}", reply.body);
        let reply = api(port, "POST", "/api/v1/upstream/config", &disabled.replace("cnfake", "domestic").replace("c1", "d1")).await;
        assert_eq!(reply.status, 400);
        assert!(reply.body.contains("「domestic」") && !reply.body.contains("开关"), "{}", reply.body);
        assert_eq!(std::fs::read_to_string(tree.path("webinfo/settings.json")).unwrap_or_default(), before);

        // An empty list still means "restore the YAML list" (the frozen contract).
        let two = r#"{"plugin_tag":"cnfake","upstreams":[{"tag":"c1","enabled":true,"protocol":"udp","addr":"udp://127.0.0.1:9"},{"tag":"c2","enabled":false,"protocol":"udp","addr":"udp://127.0.0.1:10"}]}"#;
        assert_eq!(api(port, "POST", "/api/v1/upstream/config", two).await.status, 200);
        assert_eq!(json(&api(port, "GET", "/api/v1/upstream/config", "").await.body)["cnfake"].as_array().unwrap().len(), 2);
        let reply = api(port, "POST", "/api/v1/upstream/config", r#"{"plugin_tag":"cnfake","upstreams":[]}"#).await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert_eq!(json(&api(port, "GET", "/api/v1/upstream/config", "").await.body)["cnfake"].as_array().unwrap().len(), 1);

        shutdown.cancel();
        task.await.unwrap();
    });
}

/// atom: the FakeIP group `nocnfake` is fixed to sing-box. The API refuses to
/// change it and a list stored in `settings.json` (by hand) is ignored.
#[test]
fn the_fakeip_upstream_cannot_be_overridden() {
    let tree = Tree::new("atom-nocnfake");
    let port = free_port();
    config(&tree, "flag cn_fakeip", "flag dns_mode=fakeip", port);
    std::fs::write(
        tree.path("webinfo/settings.json"),
        r#"{"version":1,"upstreams":{"nocnfake":[{"tag":"x1","enabled":true,"protocol":"udp","addr":"udp://192.0.2.1:53"}]}}"#,
    )
    .unwrap();
    let host = HostAssembly::from_config_file(&tree.path("config.yaml")).expect("assembles");
    host.block_on(async {
        let bound: BoundHost = host.bind_host().await.expect("binds");
        let shutdown = TransportCancellation::new();
        let scope = shutdown.clone();
        let task = tokio::task::spawn_local(async move {
            bound.serve(scope).await.expect("clean shutdown");
        });
        let effective = json(&api(port, "GET", "/api/v1/upstream/config", "").await.body);
        let tags = effective["nocnfake"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["tag"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert_eq!(tags, ["n1"], "{effective}");

        let before = std::fs::read_to_string(tree.path("webinfo/settings.json")).unwrap();
        let change = r#"{"plugin_tag":"nocnfake","upstreams":[{"tag":"n2","enabled":true,"protocol":"udp","addr":"udp://127.0.0.1:10"}]}"#;
        let reply = api(port, "POST", "/api/v1/upstream/config", change).await;
        assert_eq!(reply.status, 400, "{}", reply.body);
        assert!(reply.body.contains("FakeIP 上游固定"), "{}", reply.body);
        assert_eq!(std::fs::read_to_string(tree.path("webinfo/settings.json")).unwrap(), before);

        shutdown.cancel();
        task.await.unwrap();
    });
}
