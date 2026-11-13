use serde_json::json;

use super::*;

const RESERVED: &[u16] = &[6666, 53, 7892, 7893, 9090];

fn node(name: &str) -> (String, Map<String, Value>) {
    let outbound =
        json!({"type": "trojan", "server": "a.example", "server_port": 443, "password": "x"});
    (name.to_owned(), outbound.as_object().unwrap().clone())
}

fn group(name: &str, kind: GroupKind, members: &[&str]) -> GroupInput {
    GroupInput {
        name: name.to_owned(),
        kind,
        members: members.iter().map(|m| (*m).to_owned()).collect(),
        filter: String::new(),
        order: Vec::new(),
        selected: String::new(),
        url: None,
        interval: None,
        tolerance: None,
    }
}

fn message(result: Result<(), Refusal>) -> String {
    result.unwrap_err().message
}

#[test]
fn a_new_installation_is_valid_and_empty() {
    let state = ProxyState::default();
    state.validate(RESERVED).unwrap();
    assert_eq!(state.group(DEFAULT_GROUP).unwrap().name, "默认代理");
    assert_eq!(state.final_group.selected, DEFAULT_GROUP);
    assert_eq!(state.empty_groups(), vec![DEFAULT_GROUP.to_owned()]);
    assert!(state.is_target(FINAL) && state.is_target(DEFAULT_GROUP) && !state.is_target("direct"));
}

#[test]
fn new_groups_join_final_and_get_urltest_defaults() {
    let mut state = ProxyState::default();
    let added = state.add_nodes(vec![node("香港"), node("日本")]);
    assert!(added.iter().all(|node| is_id(&node.id, "n-")));
    let auto = state.add_group(group(
        "自动",
        GroupKind::Urltest,
        &[&added[0].id, &added[1].id],
    ));
    assert!(is_id(&auto.id, "g-"));
    assert_eq!(auto.url.as_deref(), Some(DEFAULT_URL));
    assert_eq!(auto.interval.as_deref(), Some(DEFAULT_INTERVAL));
    assert_eq!(auto.tolerance, Some(DEFAULT_TOLERANCE));
    assert_eq!(
        state.final_group.members,
        vec![DEFAULT_GROUP.to_owned(), auto.id.clone()]
    );
    state.validate(RESERVED).unwrap();
}

#[test]
fn members_must_exist_and_never_be_direct() {
    let mut state = ProxyState::default();
    state.groups[0].members = vec!["n-deadbeef".into()];
    assert!(message(state.validate(RESERVED)).contains("不存在"));
    state.groups[0].members = vec!["direct".into()];
    assert!(message(state.validate(RESERVED)).contains("直连不能做成员"));
    let mut state = ProxyState::default();
    state.final_group.members.push("direct".into());
    assert!(message(state.validate(RESERVED)).contains("不存在"));
}

#[test]
fn group_cycles_are_refused() {
    let mut state = ProxyState::default();
    let a = state.add_group(group("A", GroupKind::Selector, &[]));
    let b = state.add_group(group("B", GroupKind::Selector, &[&a.id]));
    state.validate(RESERVED).unwrap();
    state
        .update_group(&a.id, group("A", GroupKind::Selector, &[&b.id]))
        .unwrap();
    let refused = message(state.validate(RESERVED));
    assert!(refused.contains("成环"), "{refused}");
    let mut state = ProxyState::default();
    state.groups[0].members = vec![DEFAULT_GROUP.into()];
    assert!(message(state.validate(RESERVED)).contains("不能包含自己"));
}

#[test]
fn the_builtin_group_cannot_be_deleted() {
    let mut state = ProxyState::default();
    assert_eq!(state.remove_group(DEFAULT_GROUP).unwrap_err().status, 400);
    state.groups.clear();
    assert!(message(state.validate(RESERVED)).contains("默认代理"));
}

#[test]
fn deleting_a_group_drops_it_everywhere_and_final_falls_back() {
    let mut state = ProxyState::default();
    let inner = state.add_group(group("内层", GroupKind::Selector, &[]));
    let outer = state.add_group(group("外层", GroupKind::Selector, &[&inner.id]));
    state.select(&outer.id, &inner.id).unwrap();
    state.select(FINAL, &inner.id).unwrap();
    state.remove_group(&inner.id).unwrap();
    assert!(state.group(&outer.id).unwrap().members.is_empty());
    assert!(state.group(&outer.id).unwrap().selected.is_empty());
    assert!(!state.final_group.members.contains(&inner.id));
    assert_eq!(state.final_group.selected, DEFAULT_GROUP);
    state.validate(RESERVED).unwrap();
    // Without "默认代理" in Final, the first member is selected.
    let mut state = ProxyState::default();
    let a = state.add_group(group("A", GroupKind::Selector, &[]));
    let b = state.add_group(group("B", GroupKind::Selector, &[]));
    state.final_group.members = vec![a.id.clone(), b.id.clone()];
    state.final_group.selected = a.id.clone();
    state.remove_group(&a.id).unwrap();
    assert_eq!(state.final_group.selected, b.id);
}

#[test]
fn deleting_a_node_empties_groups_instead_of_failing() {
    let mut state = ProxyState::default();
    let added = state.add_nodes(vec![node("香港")]);
    state.groups[0].members = vec![added[0].id.clone()];
    state.final_group.members.push(added[0].id.clone());
    state.select(FINAL, &added[0].id).unwrap();
    state.remove_node(&added[0].id).unwrap();
    assert!(state.groups[0].members.is_empty());
    assert_eq!(state.final_group.selected, DEFAULT_GROUP);
    assert_eq!(state.empty_groups(), vec![DEFAULT_GROUP.to_owned()]);
    assert_eq!(state.remove_node(&added[0].id).unwrap_err().status, 404);
}

#[test]
fn final_may_be_emptied_but_then_selects_nothing() {
    let mut state = ProxyState::default();
    state.final_group.members.clear();
    assert!(message(state.validate(RESERVED)).contains("没有成员"));
    state.final_group.selected.clear();
    state.validate(RESERVED).unwrap();
    assert_eq!(
        state.empty_groups(),
        vec![DEFAULT_GROUP.to_owned(), FINAL.to_owned()]
    );
}

#[test]
fn selection_rules() {
    let mut state = ProxyState::default();
    let added = state.add_nodes(vec![node("a"), node("b")]);
    let auto = state.add_group(group("自动", GroupKind::Urltest, &[&added[0].id]));
    state.groups[0].members = vec![added[0].id.clone(), added[1].id.clone()];
    assert_eq!(
        state.selection(DEFAULT_GROUP).as_deref(),
        Some(added[0].id.as_str())
    );
    state.select(DEFAULT_GROUP, &added[1].id).unwrap();
    assert_eq!(
        state.selection(DEFAULT_GROUP).as_deref(),
        Some(added[1].id.as_str())
    );
    assert!(
        state
            .select(&auto.id, &added[0].id)
            .unwrap_err()
            .message
            .contains("urltest")
    );
    assert!(state.select(DEFAULT_GROUP, "n-00000000").is_err());
    assert!(
        state.select(FINAL, &added[0].id).is_err(),
        "not a Final member"
    );
}

#[test]
fn outbounds_are_proxy_types_without_tag_or_detour() {
    let check = |value: Value| check_outbound(value.as_object().unwrap()).map_err(|r| r.message);
    check(json!({"type": "vless", "server": "a", "server_port": 1})).unwrap();
    check(json!({"type": "wireguard", "peers": []})).unwrap();
    assert!(
        check(json!({"type": "direct"}))
            .unwrap_err()
            .contains("不支持")
    );
    assert!(
        check(json!({"type": "selector", "outbounds": []}))
            .unwrap_err()
            .contains("不支持")
    );
    assert!(
        check(json!({"type": "vless", "server": "a", "tag": "x"}))
            .unwrap_err()
            .contains("tag")
    );
    assert!(
        check(json!({"type": "vless", "server": "a", "detour": "x"}))
            .unwrap_err()
            .contains("detour")
    );
    assert!(
        check(json!({"type": "vless"}))
            .unwrap_err()
            .contains("server")
    );
}

#[test]
fn settings_are_checked() {
    let ok = Settings::default();
    check_settings(&ok, RESERVED).unwrap();
    let with = |change: &dyn Fn(&mut Settings)| {
        let mut settings = Settings::default();
        change(&mut settings);
        check_settings(&settings, RESERVED).map_err(|r| r.message)
    };
    with(&|s| s.fakeip_range = "198.18.0.0/15".into()).unwrap();
    assert!(
        with(&|s| s.fakeip_range = "28.0.0.1/8".into())
            .unwrap_err()
            .contains("主机位")
    );
    assert!(with(&|s| s.fakeip_range = "28.0.0.0/28".into()).is_err());
    assert!(with(&|s| s.fakeip_range = "fc00::/7".into()).is_err());
    assert!(with(&|s| s.fakeip_range = "127.0.0.0/8".into()).is_err());
    with(&|s| s.resolver = "tcp://119.29.29.29:53".into()).unwrap();
    with(&|s| s.resolver = "223.5.5.5".into()).unwrap();
    assert!(with(&|s| s.resolver = "https://dns.alidns.com/dns-query".into()).is_err());
    assert!(with(&|s| s.resolver = "udp://dns.example".into()).is_err());
    assert!(with(&|s| s.mixed_port = 9090).unwrap_err().contains("占用"));
    assert!(with(&|s| s.mixed_port = 0).is_err());
    with(&|s| {
        s.direct_ttl_max = 86400;
        s.fakeip_ttl_max = 1;
    })
    .unwrap();
    assert!(
        with(&|s| s.direct_ttl_max = 0)
            .unwrap_err()
            .contains("direct_ttl_max")
    );
    assert!(with(&|s| s.fakeip_ttl_max = 86401).is_err());
    assert_eq!(
        parse_resolver("udp://1.2.3.4:5353").unwrap(),
        ("udp", "1.2.3.4".parse().unwrap(), 5353)
    );
}

#[test]
fn intervals_are_seconds_minutes_or_hours() {
    for good in ["30s", "3m", "1h30m", "90s"] {
        check_interval(good).unwrap();
    }
    for bad in ["", "3", "0s", "5ms", "m", "1d", "3 m"] {
        assert!(check_interval(bad).is_err(), "{bad}");
    }
}

#[test]
fn the_file_round_trips_and_a_bad_one_stops_loading() {
    let root = std::env::temp_dir().join(format!("atom-proxy-file-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(load(&root, RESERVED, None).unwrap(), ProxyState::default());
    let mut state = ProxyState::default();
    state.add_nodes(vec![node("香港")]);
    state.version = 3;
    save(&root, &state).unwrap();
    assert_eq!(load(&root, RESERVED, None).unwrap(), state);
    std::fs::write(root.join(PROXY_FILE), br#"{"version":1}"#).unwrap();
    assert!(load(&root, RESERVED, None).is_err());
    let mut broken = ProxyState::default();
    broken.groups.clear();
    save(&root, &broken).unwrap();
    assert!(load(&root, RESERVED, None).unwrap_err().contains("默认代理"));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn credentials_never_leave_through_the_view() {
    let outbound = json!({
        "type": "wireguard", "private_key": "k", "peers": [{"server": "a", "pre_shared_key": "psk", "public_key": "pub"}],
        "obfs": {"type": "salamander", "password": "o"}, "uuid": "u", "username": "n", "password": "p",
        "tls": {"enabled": true, "reality": {"public_key": "pk", "short_id": "01"}}
    });
    let shown = Value::Object(public_outbound(outbound.as_object().unwrap()));
    assert_eq!(
        shown,
        json!({
            "type": "wireguard", "peers": [{"server": "a", "public_key": "pub"}],
            "obfs": {"type": "salamander"},
            "tls": {"enabled": true, "reality": {"public_key": "pk"}}
        })
    );
}

#[test]
fn tls_keys_reality_ids_hysteria_obfs_and_auth_headers_are_hidden() {
    let outbound = json!({
        "type": "hysteria", "obfs": "secret-obfs", "auth_str": "a",
        "tls": {"enabled": true, "client_certificate": ["CERT"], "client_key": ["KEY"], "client_key_path": "/k.pem",
                "reality": {"enabled": true, "public_key": "pk", "short_id": "01"}},
        "transport": {"type": "ws", "headers": {"Host": "h.example", "Authorization": "Basic x", "cookie": "c"}},
        "extra_headers": {"Proxy-Authorization": "Basic y", "X-Other": "z"}
    });
    let shown = Value::Object(public_outbound(outbound.as_object().unwrap()));
    assert_eq!(
        shown,
        json!({
            "type": "hysteria",
            "tls": {"enabled": true, "client_certificate": ["CERT"], "client_key_path": "/k.pem",
                    "reality": {"enabled": true, "public_key": "pk"}},
            "transport": {"type": "ws", "headers": {"Host": "h.example"}},
            "extra_headers": {"X-Other": "z"}
        })
    );
    // hysteria2's obfs is an object: only its password goes.
    let hy2 = json!({"type": "hysteria2", "obfs": {"type": "salamander", "password": "p"}});
    assert_eq!(
        Value::Object(public_outbound(hy2.as_object().unwrap()))["obfs"],
        json!({"type": "salamander"})
    );
}

#[cfg(unix)]
#[test]
fn the_state_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = std::env::temp_dir().join(format!("atom-proxy-mode-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    save(&root, &ProxyState::default()).unwrap();
    let path = root.join(PROXY_FILE);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    save(&root, &ProxyState::default()).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn tor_options_are_left_out_of_the_view_whole() {
    let tor = json!({
        "type": "tor", "executable_path": "/usr/bin/tor", "data_directory": "tor",
        "extra_args": ["--HTTPSProxyAuthenticator", "alice:secret"],
        "torrc": {"HTTPSProxy": "10.0.0.1:3128", "HTTPSProxyAuthenticator": "alice:secret"}
    });
    let shown = Value::Object(public_outbound(tor.as_object().unwrap()));
    assert_eq!(
        shown,
        json!({"type": "tor", "executable_path": "/usr/bin/tor", "data_directory": "tor"})
    );
    assert!(!shown.to_string().contains("secret"));
}

#[test]
fn credential_names_are_matched_as_sing_box_decodes_them() {
    let http = json!({
        "type": "http", "server": "proxy.example", "server_port": 8080,
        "Username": "alice", "PASSWORD": "secret",
        "Headers": {"AUTHORIZATION": "Basic x", "Host": "h"},
        "Extra_Headers": {"Proxy-Authorization": "Basic y"},
        "TLS": {"enabled": true, "Client_Key": ["KEY"], "Reality": {"Short_ID": "01", "public_key": "pk"}},
        // Unicode simple folding: long s and the Kelvin sign.
        "pa\u{17f}sword": "s1", "\u{212a}ey": "k1"
    });
    let shown = Value::Object(public_outbound(http.as_object().unwrap()));
    assert_eq!(
        shown,
        json!({
            "type": "http", "server": "proxy.example", "server_port": 8080,
            "Headers": {"Host": "h"}, "Extra_Headers": {},
            "TLS": {"enabled": true, "Reality": {"public_key": "pk"}}
        })
    );
    let tor = json!({"type": "tor", "TORRC": {"HTTPSProxyAuthenticator": "a:b"}, "EXTRA_ARGS": ["x"], "Obfs": "o"});
    assert_eq!(
        Value::Object(public_outbound(tor.as_object().unwrap())),
        json!({"type": "tor"})
    );
    // The refused fields are matched the same way.
    for key in ["Detour", "TAG", "DeTour"] {
        let mut outbound = json!({"type": "socks", "server": "s", "server_port": 1});
        outbound[key] = json!("x");
        let refused = check_outbound(outbound.as_object().unwrap())
            .unwrap_err()
            .message;
        assert!(refused.contains("不能带"), "{key}: {refused}");
    }
}

#[test]
fn a_filter_pulls_matching_nodes_in_and_keeps_manual_members() {
    let mut state = ProxyState::default();
    let nodes = state.add_nodes(vec![node("美国 01"), node("日本 01"), node("us-west")]);
    let mut input = group("美国组", GroupKind::Selector, &[&nodes[1].id]);
    input.filter = " 美国|US ".to_owned();
    let group = state.add_group(input);
    state.validate(RESERVED).unwrap();
    let group = state.group(&group.id).unwrap().clone();
    assert_eq!(group.filter, "美国|US");
    assert_eq!(
        state.members_of(&group),
        vec![nodes[1].id.clone(), nodes[0].id.clone(), nodes[2].id.clone()]
    );
    // A node added later joins without touching the group.
    let later = state.add_nodes(vec![node("US-East")]);
    assert!(state.members_of(&group).contains(&later[0].id));
    assert!(state.groups_containing(&later[0].id).contains(&group.id));
}

#[test]
fn a_bad_filter_is_refused_and_a_rename_drops_a_stale_selection() {
    let mut state = ProxyState::default();
    let nodes = state.add_nodes(vec![node("美国 01")]);
    let mut input = group("g", GroupKind::Selector, &[]);
    input.filter = "(".to_owned();
    let id = state.add_group(input).id;
    assert!(message(state.validate(RESERVED)).contains("筛选正则无效"));
    state.groups.iter_mut().find(|g| g.id == id).unwrap().filter = "美国".to_owned();
    state.select(&id, &nodes[0].id).unwrap();
    state.validate(RESERVED).unwrap();
    state
        .update_node(&nodes[0].id, Some("日本 01".to_owned()), None)
        .unwrap();
    assert!(state.group(&id).unwrap().selected.is_empty());
    state.validate(RESERVED).unwrap();
}

#[test]
fn the_stored_order_arranges_manual_and_filtered_members() {
    let mut state = ProxyState::default();
    let nodes = state.add_nodes(vec![node("us-1"), node("us-2"), node("jp-1")]);
    let mut input = group("g", GroupKind::Selector, &[&nodes[2].id]);
    input.filter = "us".to_owned();
    // us-2 first, then the manual jp-1, a stale name ignored; us-1 is not named, so it follows.
    input.order = vec![nodes[1].id.clone(), nodes[2].id.clone(), "n-gone".to_owned()];
    let id = state.add_group(input).id;
    state.validate(RESERVED).unwrap();
    let group = state.group(&id).unwrap().clone();
    assert_eq!(
        state.members_of(&group),
        vec![nodes[1].id.clone(), nodes[2].id.clone(), nodes[0].id.clone()]
    );
}
