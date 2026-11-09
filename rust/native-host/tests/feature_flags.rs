//! M2-1: named feature flags (`feature_flag`) — declarations and their
//! validation, the `flag` matcher, the `flags` section of `settings.json`, the
//! one-time migration from the schema-2 `rule/switchN.txt` files, the
//! `/api/v1/flags` routes with hot apply, and the rule that every settings save
//! keeps the `flags` section (R1). Local DNS stubs stand in for the network.

#![allow(clippy::too_many_lines)]

use std::path::PathBuf;

use atomdns_native_host::HostAssembly;

// ----- fixtures -----------------------------------------------------------------

struct Tree(PathBuf);

impl Tree {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("m2-1-{name}-{}", std::process::id()));
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

    /// Writes `rule/switchN.txt` for each `(N, value)`.
    fn switches(&self, values: &[(u8, &str)]) {
        for (number, value) in values {
            self.write(&format!("rule/switch{number}.txt"), value);
        }
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

/// The flags of the tests: the shapes of the `config_rust` ones.
const FLAGS: &str = r"  - tag: core_mode
    type: feature_flag
    args:
      label: 核心运行模式
      description: 兼容或安全
      section: mode
      kind: choice
      options:
        - {value: compat, label: 兼容模式}
        - {value: safe, label: 安全模式}
      default: compat
  - tag: dns_mode
    type: feature_flag
    args:
      label: DNS 分流模式
      description: FakeIP 或 RealIP
      section: mode
      kind: choice
      options: [{value: fakeip, label: FakeIP}, {value: realip, label: RealIP}]
      default: fakeip
  - tag: cn_fakeip
    type: feature_flag
    args: {label: 国内 FakeIP, description: 测试, section: mode, kind: bool, default: false}
  - tag: prefer_v4
    type: feature_flag
    args: {label: IPv4 优先, description: 测试, section: mode, kind: bool, default: false}
  - tag: ddns_foreign
    type: feature_flag
    args: {label: DDNS 国外, description: 测试, section: upstream, kind: bool, default: false}
  - tag: block_empty
    type: feature_flag
    args: {label: 空结果屏蔽, description: 测试, section: blocking, kind: bool, default: true}
  - tag: block_blocklist
    type: feature_flag
    args: {label: 黑名单屏蔽, description: 测试, section: blocking, kind: bool, default: true}
  - tag: block_qtypes
    type: feature_flag
    args: {label: 类型屏蔽, description: 测试, section: blocking, kind: bool, default: true}
  - tag: block_ads
    type: feature_flag
    args: {label: 广告屏蔽, description: 测试, section: blocking, kind: bool, default: true}
  - tag: block_aaaa
    type: feature_flag
    args: {label: IPv6 屏蔽, description: 测试, section: blocking, kind: bool, default: false}
  - tag: lazy_cache
    type: feature_flag
    args: {label: 过期缓存 1, description: 测试, section: cache, kind: bool, default: true}
  - tag: full_cache
    type: feature_flag
    args: {label: 过期缓存 2, description: 测试, section: cache, kind: bool, default: true}
  - tag: client_routing
    type: feature_flag
    args:
      label: 客户端分流
      description: 测试
      section: client
      kind: choice
      options:
        - {value: none, label: 不区分}
        - {value: only_listed_proxy, label: 仅名单内客户端走代理}
        - {value: listed_direct, label: 名单内客户端不走代理}
      default: none
";

/// A configuration with only the flags and a trivial entry (compile-level tests).
fn flags_only(tree: &Tree, extra: &str, rules: &str) {
    tree.write(
        "config.yaml",
        &format!(
            "log: {{level: error}}\nplugins:\n{FLAGS}{extra}  - tag: fwd\n    type: forward\n    args: {{upstreams: [{{addr: \"udp://127.0.0.1:9\"}}]}}\n  - tag: entry\n    type: sequence\n    args:\n{rules}      - exec: reject 3\n  - tag: listener\n    type: udp_server\n    args: {{entry: entry, listen: \"127.0.0.1:{}\"}}\n",
            free_port()
        ),
    );
}

fn compile(tree: &Tree) -> Result<atomdns_native_host::CompiledConfig, String> {
    atomdns_native_host::load_and_compile(&tree.path("config.yaml"))
        .map_err(|error| error.to_string())
}

/// The load error of a configuration that must not compile.
fn compile_error(tree: &Tree, what: &str) -> String {
    match compile(tree) {
        Ok(_) => panic!("compiled: {what}"),
        Err(error) => error,
    }
}

/// `key -> (value, source)` from the effective report.
fn effective(
    config: &atomdns_native_host::CompiledConfig,
) -> std::collections::BTreeMap<String, (String, String)> {
    config
        .settings_report()
        .iter()
        .filter(|item| item.kind == "feature_flag")
        .map(|item| {
            (
                item.object.clone(),
                (item.value.clone(), item.source.to_owned()),
            )
        })
        .collect()
}

fn value(config: &atomdns_native_host::CompiledConfig, key: &str) -> String {
    effective(config)[key].0.clone()
}

/// Starts the host the way `atomdns start` does (with the startup migration).
fn start(tree: &Tree) -> HostAssembly {
    HostAssembly::from_config_file(&tree.path("config.yaml")).expect("assembles")
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|error| panic!("{error}: {text}"))
}

// ----- declarations and references -----------------------------------------------

#[test]
fn invalid_declarations_are_load_errors_with_their_path() {
    let tree = Tree::new("declarations");
    let declaration =
        |args: &str| format!("  - tag: bad\n    type: feature_flag\n    args: {args}\n");
    for (extra, expected) in [
        (
            "  - tag: Bad\n    type: feature_flag\n    args: {label: a, description: b, section: mode, kind: bool, default: true}\n".to_owned(),
            "must match",
        ),
        (declaration("{description: b, section: mode, kind: bool, default: true}"), "label"),
        (declaration("{label: a, description: ' ', section: mode, kind: bool, default: true}"), "must not be empty"),
        (declaration("{label: a, description: b, section: nowhere, kind: bool, default: true}"), "unknown section"),
        (declaration("{label: a, description: b, section: mode, kind: number, default: 1}"), "unknown kind"),
        (declaration("{label: a, description: b, section: mode, kind: bool, default: 'yes'}"), "expected true or false"),
        (declaration("{label: a, description: b, section: mode, kind: bool, default: true, options: []}"), "no options"),
        (declaration("{label: a, description: b, section: mode, kind: bool, default: true, value: x}"), "unsupported field"),
        (declaration("{label: a, description: b, section: mode, kind: bool, default: true, requery_on_change: 'yes'}"), "requery_on_change"),
        (declaration("{label: a, description: b, section: mode, kind: choice, options: [{value: x, label: X}], default: x}"), "at least two"),
        (declaration("{label: a, description: b, section: mode, kind: choice, options: [{value: x, label: X}, {value: x, label: Y}], default: x}"), "duplicate option"),
        (declaration("{label: a, description: b, section: mode, kind: choice, options: [{value: x, label: X}, {value: y, label: Y}], default: z}"), "not one of the options"),
        (declaration("{label: a, description: b, section: mode, kind: choice, options: [{value: X, label: X}, {value: y, label: Y}], default: y}"), "must match"),
        (
            "  - tag: core_mode\n    type: feature_flag\n    args: {label: a, description: b, section: mode, kind: bool, default: true}\n".to_owned(),
            "duplicate plugin tag",
        ),
    ] {
        flags_only(&tree, &extra, "");
        let error = compile_error(&tree, &extra);
        assert!(error.contains(expected), "{extra}: {error}");
    }
}

#[test]
fn invalid_references_and_removed_switches_are_load_errors() {
    let tree = Tree::new("references");
    for (rules, expected) in [
        (
            "      - matches: flag nothing\n        exec: reject 0\n",
            "unknown feature_flag `nothing`",
        ),
        (
            "      - matches: flag block_aaaa=on\n        exec: reject 0\n",
            "is a bool flag",
        ),
        (
            "      - matches: flag core_mode\n        exec: reject 0\n",
            "is a choice flag",
        ),
        (
            "      - matches: flag core_mode=leaky\n        exec: reject 0\n",
            "not an option of `core_mode`",
        ),
        (
            "      - matches: $core_mode\n        exec: reject 0\n",
            "is not a matcher",
        ),
        ("      - exec: $core_mode\n", "is not executable"),
        (
            "      - matches: \"switch3 'A'\"\n        exec: reject 0\n",
            "removed in configuration schema 3",
        ),
    ] {
        flags_only(&tree, "", rules);
        let error = compile_error(&tree, rules);
        assert!(error.contains(expected), "{rules}: {error}");
    }
    flags_only(
        &tree,
        "  - tag: switch3\n    type: switch3\n    args: {initial_value: rule/switch3.txt}\n",
        "",
    );
    let error = compile_error(&tree, "switch type");
    assert!(
        error.contains("removed in configuration schema 3"),
        "{error}"
    );
    assert!(error.contains("feature_flag"), "{error}");
}

#[test]
fn bad_flag_settings_are_load_errors() {
    let tree = Tree::new("bad-settings");
    flags_only(&tree, "", "");
    for (settings, expected) in [
        (
            r#"{"version":1,"flags":{"nothing":true}}"#,
            "no feature_flag `nothing`",
        ),
        (
            r#"{"version":1,"flags":{"block_aaaa":"on"}}"#,
            "not a valid bool value",
        ),
        (
            r#"{"version":1,"flags":{"core_mode":true}}"#,
            "not a valid choice value",
        ),
        (
            r#"{"version":1,"flags":{"core_mode":"leaky"}}"#,
            "not a valid choice value",
        ),
        (r#"{"version":1,"flags":[]}"#, "invalid settings"),
        // `null` is not "absent" (absent means "not migrated yet").
        (r#"{"version":1,"flags":null}"#, "invalid settings"),
    ] {
        tree.write("webinfo/settings.json", settings);
        let error = compile_error(&tree, settings);
        assert!(error.contains(expected), "{settings}: {error}");
    }
    tree.write(
        "webinfo/settings.json",
        r#"{"version":1,"flags":{"core_mode":"safe","block_aaaa":true}}"#,
    );
    let config = compile(&tree).unwrap();
    let flags = effective(&config);
    assert_eq!(flags["core_mode"], ("safe".into(), "settings".into()));
    assert_eq!(flags["block_aaaa"], ("true".into(), "settings".into()));
    assert_eq!(flags["dns_mode"], ("fakeip".into(), "yaml".into()));
}

// ----- the migration table ---------------------------------------------------------

#[test]
fn legacy_switch_files_map_to_the_flags() {
    let tree = Tree::new("legacy-table");
    flags_only(&tree, "", "");
    // Every switch the opposite of the package default.
    tree.switches(&[
        (1, "B"),
        (3, "B"),
        (4, "B"),
        (5, "B"),
        (6, "A"),
        (7, "B"),
        (8, "A"),
        (9, "B"),
        (13, "B"),
        (16, "A"),
        (17, "B"),
        (2, "A"),
        (12, "B"),
    ]);
    let config = compile(&tree).unwrap();
    let flags = effective(&config);
    for (key, expected) in [
        ("core_mode", "safe"),
        ("dns_mode", "realip"),
        ("cn_fakeip", "true"),
        ("prefer_v4", "true"),
        ("ddns_foreign", "true"),
        ("block_empty", "false"),
        ("block_blocklist", "false"),
        ("block_qtypes", "false"),
        ("block_ads", "false"),
        ("block_aaaa", "true"),
        ("lazy_cache", "false"),
        ("full_cache", "false"),
        ("client_routing", "only_listed_proxy"),
    ] {
        assert_eq!(
            flags[key],
            (expected.to_owned(), "legacy".to_owned()),
            "{key}"
        );
    }
    // The package defaults give the YAML defaults (source yaml), and a
    // surrounding blank is trimmed as the switch owners did.
    tree.switches(&[
        (1, "A\n"),
        (3, " A "),
        (4, "A"),
        (5, "A"),
        (6, "B"),
        (7, "A"),
        (8, "B"),
        (9, "A"),
        (13, "A"),
        (16, "B"),
        (17, "A"),
        (2, "B"),
        (12, "B"),
    ]);
    let config = compile(&tree).unwrap();
    assert!(
        effective(&config)
            .values()
            .all(|(_, source)| source == "yaml"),
        "{:?}",
        effective(&config)
    );
}

#[test]
fn client_routing_reproduces_every_switch2_switch12_combination() {
    let tree = Tree::new("legacy-client");
    flags_only(&tree, "", "");
    for (two, twelve, expected) in [
        (Some("A"), Some("B"), "only_listed_proxy"),
        (Some("B"), Some("A"), "listed_direct"),
        (Some("A"), Some("A"), "none"),
        (Some("B"), Some("B"), "none"),
        (Some("A"), Some("x"), "none"),
        (Some("a"), Some("B"), "none"),
        (None, Some("A"), "none"),
        (Some("B"), None, "none"),
        (None, None, "none"),
    ] {
        for (number, value) in [(2, two), (12, twelve)] {
            let path = tree.path(&format!("rule/switch{number}.txt"));
            match value {
                Some(value) => tree.write(&format!("rule/switch{number}.txt"), value),
                None => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        let config = compile(&tree).unwrap();
        assert_eq!(
            value(&config, "client_routing"),
            expected,
            "{two:?} {twelve:?}"
        );
    }
}

#[test]
fn missing_invalid_and_oversized_switch_files_keep_the_defaults() {
    let tree = Tree::new("legacy-invalid");
    flags_only(&tree, "", "");
    tree.switches(&[(3, "C"), (6, ""), (9, "b")]);
    tree.write("rule/switch16.txt", &"A".repeat(1024 * 1024 + 1));
    let config = compile(&tree).unwrap();
    assert_eq!(value(&config, "core_mode"), "compat");
    assert_eq!(value(&config, "block_aaaa"), "false");
    assert_eq!(value(&config, "cn_fakeip"), "false");
    assert_eq!(value(&config, "ddns_foreign"), "false");
    // Missing files (switch1, 4, …) keep the defaults as well.
    assert_eq!(value(&config, "block_empty"), "true");
    assert!(
        effective(&config)
            .values()
            .all(|(_, source)| source == "yaml")
    );
}

#[test]
fn a_declaration_the_table_does_not_fit_is_not_migrated() {
    let tree = Tree::new("legacy-unfit");
    // `core_mode` as a bool does not fit the table's options: left alone.
    tree.write(
        "config.yaml",
        &format!(
            "log: {{level: error}}\nplugins:\n  - tag: core_mode\n    type: feature_flag\n    args: {{label: a, description: b, section: mode, kind: bool, default: false}}\n  - tag: fwd\n    type: forward\n    args: {{upstreams: [{{addr: \"udp://127.0.0.1:9\"}}]}}\n  - tag: entry\n    type: sequence\n    args: [{{exec: reject 3}}]\n  - tag: listener\n    type: udp_server\n    args: {{entry: entry, listen: \"127.0.0.1:{}\"}}\n",
            free_port()
        ),
    );
    tree.switches(&[(3, "B")]);
    let config = compile(&tree).unwrap();
    assert_eq!(
        effective(&config)["core_mode"],
        ("false".into(), "yaml".into())
    );
}

#[test]
fn check_shows_the_legacy_values_and_writes_nothing() {
    let tree = Tree::new("check");
    flags_only(&tree, "", "");
    tree.switches(&[(3, "B"), (6, "A")]);
    let report = atomdns_native_host::check_config(&tree.path("config.yaml")).expect("check runs");
    let text = report.to_string();
    assert!(
        text.contains("EFFECTIVE feature_flag core_mode value=safe source=legacy"),
        "{text}"
    );
    assert!(
        text.contains("EFFECTIVE feature_flag block_aaaa value=true source=legacy"),
        "{text}"
    );
    assert!(
        text.contains("EFFECTIVE feature_flag dns_mode value=fakeip source=yaml"),
        "{text}"
    );
    assert!(!tree.path("webinfo").exists());
}

// ----- the startup migration --------------------------------------------------------

#[test]
fn startup_migrates_once_and_keeps_the_switch_files() {
    let tree = Tree::new("startup");
    flags_only(&tree, "", "");
    tree.switches(&[(3, "B"), (12, "A"), (2, "B"), (16, "A"), (4, "A")]);
    drop(start(&tree));
    let file = json(&tree.text("webinfo/settings.json"));
    assert_eq!(
        file,
        serde_json::json!({
            "version": 1,
            "flags": {"core_mode": "safe", "client_routing": "listed_direct", "ddns_foreign": true}
        })
    );
    // The switch files stay, but are not read again.
    assert_eq!(tree.text("rule/switch3.txt"), "B");
    tree.switches(&[(3, "A"), (6, "A")]);
    drop(start(&tree));
    assert_eq!(json(&tree.text("webinfo/settings.json")), file);
    let config = compile(&tree).unwrap();
    assert_eq!(
        effective(&config)["core_mode"],
        ("safe".into(), "settings".into())
    );
    assert_eq!(
        effective(&config)["block_aaaa"],
        ("false".into(), "yaml".into())
    );
}

#[test]
fn startup_with_default_values_records_an_empty_flags_section() {
    let tree = Tree::new("startup-defaults");
    flags_only(&tree, "", "");
    tree.switches(&[(3, "A"), (6, "B")]);
    drop(start(&tree));
    assert_eq!(
        json(&tree.text("webinfo/settings.json")),
        serde_json::json!({"version": 1, "flags": {}})
    );
    // Other settings already in the file are kept as they were.
    let tree = Tree::new("startup-keep");
    flags_only(
        &tree,
        "  - tag: main_proxy\n    type: socks5_proxy\n    args: {addr: \"\"}\n",
        "",
    );
    tree.write(
        "webinfo/settings.json",
        r#"{"version":1,"proxies":{"main_proxy":{"addr":"192.0.2.9:1080"}}}"#,
    );
    tree.switches(&[(7, "B")]);
    drop(start(&tree));
    assert_eq!(
        json(&tree.text("webinfo/settings.json")),
        serde_json::json!({
            "version": 1,
            "proxies": {"main_proxy": {"addr": "192.0.2.9:1080"}},
            "flags": {"block_ads": false}
        })
    );
}

// ----- the HTTP routes and hot apply -------------------------------------------------
