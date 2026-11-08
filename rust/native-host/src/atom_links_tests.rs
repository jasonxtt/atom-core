use base64::Engine as _;
use serde_json::json;

use super::*;

fn one(link: &str) -> (String, Value) {
    let (name, outbound) = parse_link(link).unwrap_or_else(|error| panic!("{link}: {error}"));
    (name, Value::Object(outbound))
}

#[test]
fn vless_reality_and_transports() {
    let (name, out) = one(
        "vless://5f0b2c1e-0000-4000-8000-000000000001@hk.example:443?encryption=none&security=reality&sni=www.apple.com&fp=chrome&pbk=PUBKEY&sid=ab12&type=tcp&flow=xtls-rprx-vision#%E9%A6%99%E6%B8%AF%2001",
    );
    assert_eq!(name, "香港 01");
    assert_eq!(out["type"], "vless");
    assert_eq!(out["server"], "hk.example");
    assert_eq!(out["server_port"], 443);
    assert_eq!(out["flow"], "xtls-rprx-vision");
    assert_eq!(out["tls"]["server_name"], "www.apple.com");
    assert_eq!(
        out["tls"]["reality"],
        json!({"enabled": true, "public_key": "PUBKEY", "short_id": "ab12"})
    );
    assert_eq!(out["tls"]["utls"]["fingerprint"], "chrome");
    assert!(out.get("transport").is_none());

    let (_, ws) = one(
        "vless://u@[2001:db8::1]:8443?security=tls&type=ws&host=cdn.example&path=%2Fws%3Fed%3D2048#x",
    );
    assert_eq!(ws["server"], "2001:db8::1");
    assert_eq!(
        ws["transport"],
        json!({"type": "ws", "path": "/ws?ed=2048", "headers": {"Host": "cdn.example"}})
    );
    assert_eq!(ws["tls"]["enabled"], true);

    let (_, grpc) = one("vless://u@g.example:443?security=tls&type=grpc&serviceName=svc");
    assert_eq!(
        grpc["transport"],
        json!({"type": "grpc", "service_name": "svc"})
    );
    let (name, plain) = one("vless://u@p.example:80?type=httpupgrade&host=h.example&path=/up");
    assert_eq!(
        name, "vless p.example:80",
        "a missing name becomes type server:port"
    );
    assert!(plain.get("tls").is_none());
    assert_eq!(plain["transport"]["type"], "httpupgrade");
    assert!(
        parse_link("vless://u@r.example:443?security=reality")
            .unwrap_err()
            .contains("pbk")
    );
}

#[test]
fn vmess_base64_json() {
    let body = json!({"v": "2", "ps": "日本", "add": "jp.example", "port": "443", "id": "uuid-1", "aid": 0,
        "scy": "auto", "net": "ws", "host": "jp.example", "path": "/v", "tls": "tls", "sni": "jp.example"});
    let link = format!(
        "vmess://{}",
        base64::engine::general_purpose::STANDARD.encode(body.to_string())
    );
    let (name, out) = one(&link);
    assert_eq!(name, "日本");
    assert_eq!(out["type"], "vmess");
    assert_eq!(out["server_port"], 443);
    assert_eq!(out["uuid"], "uuid-1");
    assert_eq!(out["security"], "auto");
    assert!(out.get("alter_id").is_none());
    assert_eq!(out["tls"]["server_name"], "jp.example");
    assert_eq!(out["transport"]["path"], "/v");
    assert!(parse_link("vmess://not-base64!").is_err());
}

#[test]
fn trojan_hysteria2_tuic_anytls() {
    let (_, trojan) = one("trojan://p%40ss@t.example:443?sni=s.example&allowInsecure=1#t");
    assert_eq!(trojan["password"], "p@ss");
    assert_eq!(
        trojan["tls"],
        json!({"enabled": true, "server_name": "s.example", "insecure": true})
    );

    let (_, hy2) = one(
        "hy2://secret@h.example:8443/?sni=h.example&obfs=salamander&obfs-password=ob&insecure=1#h",
    );
    assert_eq!(hy2["type"], "hysteria2");
    assert_eq!(hy2["password"], "secret");
    assert_eq!(hy2["obfs"], json!({"type": "salamander", "password": "ob"}));
    assert_eq!(hy2["tls"]["insecure"], true);
    let (_, hy2) = one("hysteria2://user:pw@h.example:443");
    assert_eq!(hy2["password"], "user:pw");

    let (_, tuic) = one(
        "tuic://uuid-2:pw@u.example:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=u.example",
    );
    assert_eq!(tuic["uuid"], "uuid-2");
    assert_eq!(tuic["password"], "pw");
    assert_eq!(tuic["congestion_control"], "bbr");
    assert_eq!(tuic["udp_relay_mode"], "native");
    assert_eq!(tuic["tls"]["alpn"], json!(["h3"]));

    let (_, anytls) = one("anytls://pw@a.example:443?sni=a.example&fp=firefox#a");
    assert_eq!(anytls["type"], "anytls");
    assert_eq!(anytls["tls"]["utls"]["fingerprint"], "firefox");
}

#[test]
fn shadowsocks_forms() {
    let user = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pa:ss");
    let (name, sip002) = one(&format!(
        "ss://{user}@s.example:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Db.example#S1"
    ));
    assert_eq!(name, "S1");
    assert_eq!(sip002["type"], "shadowsocks");
    assert_eq!(sip002["method"], "aes-256-gcm");
    assert_eq!(sip002["password"], "pa:ss");
    assert_eq!(sip002["plugin"], "obfs-local");
    assert_eq!(sip002["plugin_opts"], "obfs=http;obfs-host=b.example");

    let (_, clear) = one("ss://2022-blake3-aes-128-gcm:a2V5%3D@s.example:443#2022");
    assert_eq!(clear["method"], "2022-blake3-aes-128-gcm");
    assert_eq!(clear["password"], "a2V5=");

    let legacy =
        base64::engine::general_purpose::STANDARD.encode("chacha20-ietf-poly1305:p@w@1.2.3.4:8388");
    let (name, old) = one(&format!("ss://{legacy}#old"));
    assert_eq!(name, "old");
    assert_eq!(old["server"], "1.2.3.4");
    assert_eq!(old["password"], "p@w");
    assert!(parse_link("ss://bm90LWEtbGluaw#x").is_err());
}

#[test]
fn unsupported_and_numbered_errors() {
    assert!(parse_link("ssr://abc").unwrap_err().contains("ssr"));
    assert!(
        parse_link("vless://u@h.example")
            .unwrap_err()
            .contains("端口")
    );
    let error = from_links("trojan://p@t.example:443\n\n# comment\nwireguard://x@y:1").unwrap_err();
    assert!(error.starts_with("第 2 项"), "{error}");
    assert_eq!(
        from_links("trojan://p@t.example:443\n trojan://q@t.example:444 ")
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn clash_proxies() {
    let yaml = r#"
port: 7890
proxies:
  - {name: "ss1", type: ss, server: s.example, port: 8388, cipher: aes-128-gcm, password: pw, plugin: obfs, plugin-opts: {mode: tls, host: b.example}}
  - name: vm
    type: vmess
    server: v.example
    port: 443
    uuid: uuid-3
    alterId: 0
    cipher: auto
    tls: true
    servername: v.example
    network: ws
    ws-opts: {path: /ray, headers: {Host: v.example}}
  - name: vl
    type: vless
    server: l.example
    port: 443
    uuid: uuid-4
    flow: xtls-rprx-vision
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts: {public-key: KEY, short-id: "01"}
  - {name: tj, type: trojan, server: t.example, port: 443, password: pw, sni: t.example, skip-cert-verify: true, network: grpc, grpc-opts: {grpc-service-name: g}}
  - {name: hy, type: hysteria2, server: h.example, port: 443, password: pw, obfs: salamander, obfs-password: o}
  - {name: tu, type: tuic, server: u.example, port: 443, uuid: uuid-5, password: pw, congestion-controller: bbr, udp-relay-mode: native, alpn: [h3]}
  - {name: at, type: anytls, server: a.example, port: 443, password: pw}
"#;
    let nodes = from_clash_yaml(yaml).unwrap();
    let names: Vec<&str> = nodes.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["ss1", "vm", "vl", "tj", "hy", "tu", "at"]);
    let get = |index: usize| Value::Object(nodes[index].1.clone());
    assert_eq!(get(0)["plugin_opts"], "obfs=tls;obfs-host=b.example");
    assert_eq!(
        get(1)["transport"],
        json!({"type": "ws", "path": "/ray", "headers": {"Host": "v.example"}})
    );
    assert_eq!(get(1)["tls"]["server_name"], "v.example");
    assert_eq!(get(2)["tls"]["reality"]["public_key"], "KEY");
    assert_eq!(get(2)["tls"]["reality"]["short_id"], "01");
    assert_eq!(get(3)["transport"]["service_name"], "g");
    assert_eq!(get(3)["tls"]["insecure"], true);
    assert_eq!(get(4)["obfs"]["type"], "salamander");
    assert_eq!(get(5)["congestion_control"], "bbr");
    assert_eq!(get(6)["type"], "anytls");
    // A bare list and a single proxy work too.
    assert_eq!(
        from_clash_yaml("- {name: a, type: trojan, server: t, port: 1, password: p}")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        from_clash_yaml("{name: a, type: trojan, server: t, port: 1, password: p}")
            .unwrap()
            .len(),
        1
    );
    let error = from_clash_yaml("proxies:\n  - {name: ok, type: trojan, server: t, port: 1, password: p}\n  - {name: bad, type: snell, server: s, port: 1}").unwrap_err();
    assert!(
        error.starts_with("第 2 项") && error.contains("snell"),
        "{error}"
    );
    assert!(
        from_clash_yaml("proxies:\n  - {name: x, type: ss, server: s, port: 1, password: p}")
            .unwrap_err()
            .contains("cipher")
    );
}

#[test]
fn singbox_json_forms() {
    let single = from_singbox_json(json!({"type": "trojan", "tag": "我的节点", "server": "t", "server_port": 443, "password": "p"})).unwrap();
    assert_eq!(single[0].0, "我的节点");
    assert!(!single[0].1.contains_key("tag"));
    let whole = from_singbox_json(json!({
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "selector", "tag": "proxy", "outbounds": ["a"]},
            {"type": "vless", "tag": "a", "server": "v", "server_port": 443, "uuid": "u"},
        ]
    }))
    .unwrap();
    assert_eq!(whole.len(), 1);
    assert_eq!(whole[0].0, "a");
    assert!(
        from_singbox_json(json!([{"type": "direct"}]))
            .unwrap_err()
            .contains("不支持")
    );
    assert!(
        from_singbox_json(json!({"outbounds": [{"type": "direct"}]}))
            .unwrap_err()
            .contains("没有可导入")
    );
}
