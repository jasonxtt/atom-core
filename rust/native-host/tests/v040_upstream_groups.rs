//! v0.4.0: `aliapi` `show_when` (display only) and its validation,
//! `GET /api/v1/upstream/groups`, and the refusal of a list without an enabled
//! upstream (instead of a raw compile error, or an empty list silently
//! restoring the YAML list).

use std::path::PathBuf;

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
