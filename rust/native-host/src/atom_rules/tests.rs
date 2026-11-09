use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use atomdns_sequence_core::ExecutionState;

use super::*;

const MARKS: Marks = Marks {
    proxy: 41,
    direct: 42,
    block: 40,
};
/// The mark the test mapper would set for the `adguard` builtin.
const ADS: u64 = 1 << 5;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("atom-rules-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn load(root: &Path) -> Result<AtomRules, String> {
    AtomRules::load(
        root,
        MARKS,
        None,
        String::new(),
        vec![("adguard".to_owned(), BuiltinSet::Mark(ADS))],
        None,
    )
}

fn owner(root: &Path) -> AtomRules {
    load(root).unwrap()
}

fn input(matches: Match, action: Action) -> RuleInput {
    RuleInput {
        enabled: true,
        remark: String::new(),
        matches,
        action,
    }
}

fn suffix(names: &[&str]) -> Match {
    Match {
        suffix: names.iter().map(|name| (*name).to_owned()).collect(),
        ..Match::default()
    }
}

fn proxy(group: &str) -> Action {
    Action::Proxy {
        group_id: group.to_owned(),
    }
}

fn hit(rules: &AtomRules, name: &str) -> Option<Action> {
    rules.test(name, None, 0).map(|(_, rule)| rule.action)
}

fn ip(text: &str) -> Option<IpAddr> {
    Some(text.parse().unwrap())
}

#[test]
fn default_table_sends_lan_direct_and_blocks_ads() {
    let rules = owner(Path::new(""));
    let (version, list) = rules.rules();
    assert_eq!(version, 0);
    assert_eq!(
        list.iter().map(|rule| rule.id.as_str()).collect::<Vec<_>>(),
        ["r-lan", "r-ads"]
    );
    assert_eq!(hit(&rules, "nas.lan"), Some(Action::Direct));
    assert_eq!(hit(&rules, "printer.home.arpa."), Some(Action::Direct));
    assert_eq!(hit(&rules, "localhost"), Some(Action::Direct));
    assert_eq!(
        rules.test("ads.example", None, ADS).map(|(_, r)| r.action),
        Some(Action::Block)
    );
    assert_eq!(hit(&rules, "example.com"), None, "falls through");
    // Without the adguard builtin only the LAN rule is installed.
    let bare =
        AtomRules::load(Path::new(""), MARKS, None, String::new(), Vec::new(), None).unwrap();
    assert_eq!(bare.rules().1.len(), 1);
}

#[test]
fn first_enabled_match_wins_and_move_changes_it() {
    let rules = owner(Path::new(""));
    let (v1, proxied) = rules
        .create(
            input(suffix(&["example.com"]), proxy("g-a")),
            Some(0),
            None,
            None,
        )
        .unwrap();
    assert_eq!(v1, 1);
    let www = Match {
        domain: vec!["www.example.com".to_owned()],
        ..Match::default()
    };
    let (v2, direct) = rules
        .create(input(www, Action::Direct), Some(v1), None, None)
        .unwrap();
    assert_eq!(hit(&rules, "www.example.com"), Some(proxy("g-a")));
    assert_eq!(hit(&rules, "WWW.Example.COM."), Some(proxy("g-a")));
    let v3 = rules
        .move_rule(&direct.id, Some(&proxied.id), None, v2)
        .unwrap();
    assert_eq!(hit(&rules, "www.example.com"), Some(Action::Direct));
    assert_eq!(hit(&rules, "a.example.com"), Some(proxy("g-a")));
    // after_id puts it back below.
    let v4 = rules
        .move_rule(&direct.id, None, Some(&proxied.id), v3)
        .unwrap();
    assert_eq!(hit(&rules, "www.example.com"), Some(proxy("g-a")));
    // A disabled rule is skipped.
    let mut disabled = input(suffix(&["example.com"]), proxy("g-a"));
    disabled.enabled = false;
    rules.update(&proxied.id, disabled, Some(v4)).unwrap();
    assert_eq!(hit(&rules, "www.example.com"), Some(Action::Direct));
    assert_eq!(hit(&rules, "a.example.com"), None);
}

#[test]
fn stale_versions_are_refused_with_the_current_one() {
    let rules = owner(Path::new(""));
    let (version, rule) = rules
        .create(input(suffix(&["a.test"]), Action::Block), None, None, None)
        .unwrap();
    let stale = rules
        .move_rule(&rule.id, Some("r-lan"), None, version - 1)
        .unwrap_err();
    assert_eq!(stale.status, 409);
    assert_eq!(stale.version, Some(version));
    let stale = rules
        .create(
            input(suffix(&["b.test"]), Action::Block),
            Some(0),
            None,
            None,
        )
        .unwrap_err();
    assert_eq!((stale.status, stale.version), (409, Some(version)));
    assert_eq!(rules.delete(&rule.id, Some(0)).unwrap_err().status, 409);
    assert_eq!(rules.rules().1.len(), 3, "nothing changed");
    assert_eq!(rules.delete("r-none", None).unwrap_err().status, 404);
    assert_eq!(
        rules
            .move_rule(&rule.id, Some(&rule.id), None, version)
            .unwrap_err()
            .status,
        400
    );
    assert_eq!(
        rules
            .move_rule(&rule.id, None, None, version)
            .unwrap_err()
            .status,
        400
    );
    assert_eq!(rules.delete(&rule.id, Some(version)).unwrap(), version + 1);
}

#[test]
fn classes_are_anded_and_entries_ored() {
    let rules = owner(Path::new(""));
    let matches = Match {
        suffix: vec!["google.com".to_owned(), "youtube.com".to_owned()],
        client: vec!["192.168.1.0/24".to_owned(), "10.0.0.7".to_owned()],
        ..Match::default()
    };
    rules
        .create(input(matches, Action::Block), None, None, None)
        .unwrap();
    let only_client = Match {
        client: vec!["192.168.9.9".to_owned()],
        ..Match::default()
    };
    rules
        .create(input(only_client, Action::Direct), None, None, None)
        .unwrap();
    let action = |name: &str, client: &str| rules.test(name, ip(client), 0).map(|(_, r)| r.action);
    assert_eq!(
        action("www.youtube.com", "192.168.1.50"),
        Some(Action::Block)
    );
    assert_eq!(action("google.com", "10.0.0.7"), Some(Action::Block));
    assert_eq!(action("google.com", "10.0.0.8"), None);
    assert_eq!(action("example.com", "192.168.1.50"), None);
    assert_eq!(
        rules.test("google.com", None, 0),
        None,
        "no client: no match"
    );
    // A rule with only a client condition matches every name of that client.
    assert_eq!(
        action("anything.example", "192.168.9.9"),
        Some(Action::Direct)
    );
    // keyword and regex are name entries of the same class.
    let names = Match {
        keyword: vec!["tracker".to_owned()],
        regex: vec![r"^ad[0-9]+\.".to_owned()],
        ..Match::default()
    };
    rules
        .create(input(names, Action::Block), None, None, None)
        .unwrap();
    assert_eq!(hit(&rules, "eu.tracker.net"), Some(Action::Block));
    assert_eq!(hit(&rules, "ad12.cdn.net"), Some(Action::Block));
    assert_eq!(hit(&rules, "bad12.cdn.net"), None);
}

#[test]
fn invalid_rules_are_refused_and_change_nothing() {
    let rules = owner(Path::new(""));
    let refuse = |matches: Match, action: Action| {
        let refusal = rules
            .create(input(matches, action), None, None, None)
            .unwrap_err();
        assert_eq!(refusal.status, 400, "{}", refusal.message);
        refusal.message
    };
    let ip_rule = Match {
        ip_cidr: vec!["91.108.4.0/22".to_owned()],
        ..Match::default()
    };
    assert!(refuse(ip_rule, proxy("g")).contains("ip_cidr"));
    assert!(refuse(Match::default(), Action::Direct).contains("至少"));
    let regex = Match {
        regex: vec!["(".to_owned()],
        ..Match::default()
    };
    refuse(regex, Action::Block);
    let unknown = Match {
        ruleset: vec!["rs-missing".to_owned()],
        ..Match::default()
    };
    assert!(refuse(unknown, Action::Block).contains("rs-missing"));
    let client = Match {
        client: vec!["192.168.1.0/33".to_owned()],
        ..Match::default()
    };
    refuse(client, Action::Direct);
    refuse(suffix(&["a b.com"]), Action::Direct);
    refuse(suffix(&[""]), Action::Direct);
    refuse(suffix(&["例子.cn"]), Action::Direct);
    refuse(suffix(&["a.com"]), proxy(""));
    refuse(suffix(&["a.com"]), proxy(" g"));
    refuse(suffix(&["a.com"]), proxy(&"g".repeat(65)));
    assert_eq!(rules.rules().0, 0);
    assert_eq!(rules.rules().1.len(), 2);
}

#[test]
fn changes_persist_and_loading_writes_nothing() {
    let root = scratch("persist");
    let rules = owner(&root);
    assert!(!root.join(RULES_FILE).exists(), "load must not write");
    let (version, rule) = rules
        .create(
            input(suffix(&["kept.test"]), proxy("g-1")),
            None,
            Some("r-lan"),
            None,
        )
        .unwrap();
    drop(rules);
    let again = owner(&root);
    let (loaded, list) = again.rules();
    assert_eq!(loaded, version);
    assert_eq!(list[0], rule, "inserted before r-lan");
    assert_eq!(hit(&again, "a.kept.test"), Some(proxy("g-1")));
    let text = std::fs::read_to_string(root.join(RULES_FILE)).unwrap();
    assert!(text.contains("\"group_id\": \"g-1\""), "{text}");
    // A broken file stops the compile instead of being replaced.
    std::fs::write(root.join(RULES_FILE), b"{").unwrap();
    assert!(AtomRules::load(&root, MARKS, None, String::new(), Vec::new(), None).is_err());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn local_rulesets_are_referenced_edited_and_guarded() {
    let root = scratch("rulesets");
    let rules = owner(&root);
    let set = rules
        .create_ruleset(
            "streaming",
            Source::Local,
            vec!["netflix.com".to_owned(), "full:www.hulu.com".to_owned()],
        )
        .unwrap();
    assert!(set.id.starts_with("rs-"));
    assert_eq!(set.rule_count, 2);
    let matches = Match {
        ruleset: vec![set.id.clone()],
        ..Match::default()
    };
    let (_, rule) = rules
        .create(input(matches, proxy("g-us")), None, None, None)
        .unwrap();
    assert_eq!(hit(&rules, "api.netflix.com"), Some(proxy("g-us")));
    assert_eq!(hit(&rules, "www.hulu.com"), Some(proxy("g-us")));
    assert_eq!(hit(&rules, "hulu.com"), None, "full: is exact");
    rules
        .update_ruleset(&set.id, None, None, Some(vec!["disneyplus.com".to_owned()]))
        .unwrap();
    assert_eq!(hit(&rules, "api.netflix.com"), None, "the edit is live");
    assert_eq!(hit(&rules, "www.disneyplus.com"), Some(proxy("g-us")));
    assert_eq!(
        rules.ruleset_entries(&set.id).unwrap(),
        vec!["disneyplus.com".to_owned()]
    );
    // Reload: metadata and list come back from disk.
    drop(rules);
    let rules = owner(&root);
    assert_eq!(hit(&rules, "www.disneyplus.com"), Some(proxy("g-us")));
    // The edit is a new revision's file; the old one is gone.
    assert_eq!(rules.ruleset(&set.id).unwrap().revision, 2);
    assert!(!list_path(&root, &set.id, 1).exists());
    assert!(list_path(&root, &set.id, 2).exists());
    let blocked = rules.delete_ruleset(&set.id).unwrap_err();
    assert_eq!(
        (blocked.status, blocked.rules.clone()),
        (409, vec![rule.id.clone()])
    );
    rules.delete(&rule.id, None).unwrap();
    rules.delete_ruleset(&set.id).unwrap();
    assert!(!list_path(&root, &set.id, 2).exists());
    assert!(rules.rulesets().is_empty());
    // Bad entries and bad sources are refused.
    assert_eq!(
        rules
            .create_ruleset("x", Source::Local, vec!["regexp:(".to_owned()])
            .unwrap_err()
            .status,
        400
    );
    let ftp = Source::Remote {
        url: "ftp://example.com/list.txt".to_owned(),
        format: "auto".to_owned(),
        category: String::new(),
    };
    assert_eq!(
        rules
            .create_ruleset("x", ftp, Vec::new())
            .unwrap_err()
            .status,
        400
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn remote_downloads_are_converted_and_failures_recorded() {
    let root = scratch("remote");
    let rules = owner(&root);
    let source = Source::Remote {
        url: "https://example.com/list.yaml".to_owned(),
        format: "auto".to_owned(),
        category: String::new(),
    };
    let set = rules.create_ruleset("remote", source, Vec::new()).unwrap();
    assert_eq!(set.rule_count, 0);
    let yaml = b"payload:\n  - '+.openai.com'\n  - 'chat.example.org'\n";
    let converted = convert_download(yaml, "auto", "", "https://example.com/list.yaml");
    let stored = rules
        .store_download(
            &set.id,
            &set.source,
            rules.begin_download(&set.id),
            converted,
        )
        .unwrap();
    assert_eq!(stored.rule_count, 2);
    assert!(stored.last_error.is_empty());
    let matches = Match {
        ruleset: vec![set.id.clone()],
        ..Match::default()
    };
    rules
        .create(input(matches, proxy("g-ai")), None, None, None)
        .unwrap();
    assert_eq!(hit(&rules, "api.openai.com"), Some(proxy("g-ai")));
    assert_eq!(hit(&rules, "chat.example.org"), Some(proxy("g-ai")));
    // A failed refresh keeps the list and records the reason.
    let failed = rules
        .store_download(
            &set.id,
            &set.source,
            rules.begin_download(&set.id),
            Err("下载失败: timed out".to_owned()),
        )
        .unwrap();
    assert_eq!(failed.rule_count, 2);
    assert!(failed.last_error.contains("timed out"));
    assert_eq!(hit(&rules, "api.openai.com"), Some(proxy("g-ai")));
    assert!(convert_download(b"\n# nothing\n", "text", "", "x.txt").is_err());
    let text = convert_download(b"a.com\nfull:b.com\n", "text", "", "x.txt").unwrap();
    assert_eq!(text.0.len(), 2);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn proxy_rules_cannot_have_a_client_condition() {
    let root = scratch("client-proxy");
    let rules = owner(&root);
    let lan_client = Match {
        client: vec!["192.168.1.0/24".to_owned()],
        ..suffix(&["video.example"])
    };
    // sing-box binds per name: a client's proxy rule would bind every client.
    let refused = rules
        .create(input(lan_client.clone(), proxy("g-x")), None, None, None)
        .unwrap_err();
    assert_eq!(refused.status, 400);
    assert!(refused.message.contains("client"), "{}", refused.message);
    let only_client = Match {
        client: vec!["10.0.0.7".to_owned()],
        ..Match::default()
    };
    assert_eq!(
        rules
            .create(input(only_client, proxy("g-x")), None, None, None)
            .unwrap_err()
            .status,
        400
    );
    // Direct and block stay per client; a replace cannot turn one into proxy.
    let (_, rule) = rules
        .create(input(lan_client.clone(), Action::Direct), None, None, None)
        .unwrap();
    rules
        .create(input(lan_client.clone(), Action::Block), None, None, None)
        .unwrap();
    let version = rules.rules().0;
    assert_eq!(
        rules
            .update(&rule.id, input(lan_client, proxy("g-x")), None)
            .unwrap_err()
            .status,
        400
    );
    assert_eq!(rules.rules().0, version, "nothing changed");
    // A table file holding such a rule does not load (like a damaged file).
    drop(rules);
    // Disabled rules are validated too.
    std::fs::write(
        root.join(RULES_FILE),
        r#"{"version": 9, "rules": [{"id": "r-x", "enabled": false,
            "match": {"client": ["10.0.0.7"]},
            "action": {"type": "proxy", "group_id": "g-x"}}]}"#,
    )
    .unwrap();
    let error = load(&root).err().expect("refused");
    assert!(error.contains("client"), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_failed_ruleset_publication_leaves_the_old_list_in_force() {
    let root = scratch("ruleset-commit");
    let rules = owner(&root);
    let set = rules
        .create_ruleset("mine", Source::Local, vec!["old.example".to_owned()])
        .unwrap();
    let matches = Match {
        ruleset: vec![set.id.clone()],
        ..Match::default()
    };
    rules
        .create(input(matches, Action::Block), None, None, None)
        .unwrap();
    // The metadata write fails (its path is now a non-empty directory).
    let metadata = root.join(RULESETS_FILE);
    let saved = std::fs::read(&metadata).unwrap();
    std::fs::remove_file(&metadata).unwrap();
    std::fs::create_dir_all(metadata.join("blocker")).unwrap();
    let failed = rules
        .update_ruleset(&set.id, None, None, Some(vec!["new.example".to_owned()]))
        .unwrap_err();
    assert_eq!(failed.status, 500);
    assert_eq!(
        hit(&rules, "old.example"),
        Some(Action::Block),
        "still live"
    );
    assert_eq!(hit(&rules, "new.example"), None);
    assert!(
        !list_path(&root, &set.id, 2).exists(),
        "staged list removed"
    );
    // A restart still has the old list with the old metadata.
    drop(rules);
    std::fs::remove_dir_all(&metadata).unwrap();
    std::fs::write(&metadata, saved).unwrap();
    let rules = owner(&root);
    assert_eq!(hit(&rules, "old.example"), Some(Action::Block));
    assert_eq!(hit(&rules, "new.example"), None);
    assert_eq!(rules.ruleset_entries(&set.id).unwrap(), vec!["old.example"]);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_download_of_a_replaced_source_is_discarded() {
    let root = scratch("download-race");
    let rules = owner(&root);
    let remote = |url: &str| Source::Remote {
        url: url.to_owned(),
        format: "text".to_owned(),
        category: String::new(),
    };
    let set = rules
        .create_ruleset("r", remote("https://a.example/list.txt"), Vec::new())
        .unwrap();
    let started_with = set.source.clone();
    let ticket = rules.begin_download(&set.id);
    // The source changes while the download of A is still running.
    rules
        .update_ruleset(
            &set.id,
            None,
            Some(remote("https://b.example/list.txt")),
            None,
        )
        .unwrap();
    let late = convert_download(b"from-a.example\n", "text", "", "x.txt");
    let refused = rules
        .store_download(&set.id, &started_with, ticket, late)
        .unwrap_err();
    assert_eq!(refused.status, 409, "{}", refused.message);
    let current = rules.ruleset(&set.id).unwrap();
    assert_eq!((current.revision, current.rule_count), (0, 0));
    assert!(
        current.last_error.is_empty(),
        "the late result is not recorded"
    );
    let failed_late = rules.store_download(&set.id, &started_with, ticket, Err("x".to_owned()));
    assert_eq!(failed_late.unwrap_err().status, 409);
    // B's own download is installed.
    let b = convert_download(b"from-b.example\n", "text", "", "x.txt");
    let stored = rules
        .store_download(&set.id, &current.source, rules.begin_download(&set.id), b)
        .unwrap();
    assert_eq!((stored.revision, stored.rule_count), (1, 1));
    assert_eq!(
        rules.ruleset_entries(&set.id).unwrap(),
        vec!["domain:from-b.example"]
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn only_the_newest_overlapping_download_is_installed() {
    let root = scratch("download-overlap");
    let rules = owner(&root);
    let set = rules
        .create_ruleset(
            "r",
            Source::Remote {
                url: "https://a.example/list.txt".to_owned(),
                format: "text".to_owned(),
                category: String::new(),
            },
            Vec::new(),
        )
        .unwrap();
    let list = |name: &str| convert_download(name.as_bytes(), "text", "", "x.txt");
    // Refresh 1 starts (an older snapshot), then refresh 2 of the same URL.
    let first = rules.begin_download(&set.id);
    let second = rules.begin_download(&set.id);
    let newer = rules
        .store_download(&set.id, &set.source, second, list("newer.example\n"))
        .unwrap();
    assert_eq!(newer.revision, 1);
    // Refresh 1 finishes last: neither its list nor its failure lands.
    for late in [
        list("older.example\n"),
        Err("下载失败: timed out".to_owned()),
    ] {
        let refused = rules
            .store_download(&set.id, &set.source, first, late)
            .unwrap_err();
        assert_eq!(refused.status, 409, "{}", refused.message);
    }
    let current = rules.ruleset(&set.id).unwrap();
    assert_eq!((current.revision, current.last_error.as_str()), (1, ""));
    assert_eq!(
        rules.ruleset_entries(&set.id).unwrap(),
        vec!["domain:newer.example"]
    );
    // A ticket is single-generation: a newer start also retires the
    // ticket that already published.
    rules.begin_download(&set.id);
    assert_eq!(
        rules
            .store_download(&set.id, &set.source, second, list("x.example\n"))
            .unwrap_err()
            .status,
        409
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn rulesets_claiming_no_list_are_checked_on_load() {
    let root = scratch("revision-zero");
    let rules = owner(&root);
    rules
        .create_ruleset("mine", Source::Local, vec!["a.example".to_owned()])
        .unwrap();
    drop(rules);
    let metadata = root.join(RULESETS_FILE);
    let saved = std::fs::read_to_string(&metadata).unwrap();
    let forge = |edits: &[(&str, &str)]| {
        let mut forged = saved.clone();
        for (from, to) in edits {
            assert!(forged.contains(from), "{from}");
            forged = forged.replacen(from, to, 1);
        }
        std::fs::write(&metadata, forged).unwrap();
        load(&root).err().expect("refused")
    };
    // A local set always has a list (revision >= 1).
    let error = forge(&[(r#""revision": 1"#, r#""revision": 0"#)]);
    assert!(error.contains("revision"), "{error}");
    // The step-2 format before revisions: no field means 0, refused too.
    let error = forge(&[(",\n    \"revision\": 1", "")]);
    assert!(error.contains("revision"), "{error}");
    // A remote set with revision 0 but a rule count is inconsistent.
    let error = forge(&[
        (
            r#""type": "local","#,
            r#""type": "remote", "url": "https://example.com/l.txt","#,
        ),
        (r#""revision": 1"#, r#""revision": 0"#),
    ]);
    assert!(error.contains("rule_count 为 1"), "{error}");
    // The file as written loads.
    std::fs::write(&metadata, &saved).unwrap();
    assert!(load(&root).is_ok());
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_referenced_list_file_must_exist() {
    let root = scratch("missing-list");
    let rules = owner(&root);
    let local = rules
        .create_ruleset("mine", Source::Local, vec!["a.example".to_owned()])
        .unwrap();
    // A remote set whose first download failed has no list: revision 0.
    let remote = rules
        .create_ruleset(
            "remote",
            Source::Remote {
                url: "https://example.com/list.txt".to_owned(),
                format: "text".to_owned(),
                category: String::new(),
            },
            Vec::new(),
        )
        .unwrap();
    let remote = rules
        .store_download(
            &remote.id,
            &remote.source,
            rules.begin_download(&remote.id),
            Err("下载失败: timed out".to_owned()),
        )
        .unwrap();
    assert_eq!((remote.revision, remote.rule_count), (0, 0));
    assert!(!list_path(&root, &remote.id, 0).exists());
    drop(rules);
    let rules = owner(&root);
    assert!(rules.ruleset_entries(&remote.id).unwrap().is_empty());
    drop(rules);
    // A lost list file of a set that has one stops the load.
    std::fs::remove_file(list_path(&root, &local.id, 1)).unwrap();
    let error = load(&root).err().expect("refused");
    assert!(error.contains(&local.id), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

fn wire(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(u8::try_from(label.len()).unwrap());
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn state(name: &str, client: Option<&str>) -> ExecutionState {
    let mut raw = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    raw.extend_from_slice(&wire(name));
    raw.extend_from_slice(&[0, 1, 0, 1]);
    let (header, question) = atomdns_dns_core::parse_query(&raw).unwrap();
    let mut state = ExecutionState::new(header, question);
    if let Some(client) = client {
        state.query.client = atomdns_sequence_core::ClientContext::from_peer(
            client.parse().unwrap(),
            atomdns_sequence_core::ClientTransport::Udp,
        );
    }
    state
}

#[test]
fn the_fixture_marks_the_action_and_records_the_group() {
    let rules = Rc::new(owner(Path::new("")));
    rules
        .create(
            RuleInput {
                remark: "流|媒体".to_owned(),
                ..input(suffix(&["netflix.com"]), proxy("g-us"))
            },
            None,
            None,
            None,
        )
        .unwrap();
    let executor = rules.executor();
    let mut proxied = state("www.netflix.com", Some("192.168.1.2"));
    executor.execute(&mut proxied).unwrap();
    assert_eq!(proxied.fast_flags, 1 << 41);
    assert_eq!(proxied.outbound.as_deref(), Some("g-us"));
    assert_eq!(proxied.routing.domain_set.as_deref(), Some("规则:流/媒体"));
    assert!(
        proxied
            .routing
            .matched_rule_source
            .as_deref()
            .is_some_and(|source| source.starts_with("atom_rule:r-"))
    );
    let mut lan = state("nas.lan", None);
    executor.execute(&mut lan).unwrap();
    assert_eq!((lan.fast_flags, lan.outbound.clone()), (1 << 42, None));
    let mut ads = state("ads.example", None);
    ads.fast_flags = ADS;
    executor.execute(&mut ads).unwrap();
    assert_eq!(ads.fast_flags, ADS | 1 << 40);
    let mut other = state("example.com", None);
    executor.execute(&mut other).unwrap();
    assert_eq!((other.fast_flags, other.outbound.clone()), (0, None));
    assert_eq!(other.routing.domain_set, None);
}

mod engine {
    //! The whole path through a compiled configuration: the fixture's marks
    //! dispatch the query, and the forward of the FakeIP upstream receives
    //! the rule's group (SET) or none (CLEAR).
    use std::cell::RefCell;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::time::Instant;

    use atomdns_sequence_core::ExecutableId;
    use atomdns_upstream_core::{ExchangeResponse, Transport, TransportCancellation};

    use crate::assembly::HostOptions;
    use crate::execution::{
        ExchangeError, ExchangeExecutor, ExecutionRequest, InvocationExchange,
        execute_request_with_observation,
    };
    use crate::observer::{ExecutionCheckpoint, UpstreamAttemptLedgerHandle};

    /// Records `(upstream tag, 65001 payload as sent)` and answers 30.0.0.1.
    struct Recorder {
        /// Every forward invocation's executable and its definition's tag.
        tags: Vec<(ExecutableId, String)>,
        calls: RefCell<Vec<(String, Option<Vec<u8>>)>>,
    }

    impl Recorder {
        fn tag(&self, executable: ExecutableId) -> String {
            self.tags
                .iter()
                .find(|(id, _)| *id == executable)
                .map(|(_, tag)| tag.clone())
                .unwrap_or_default()
        }
    }

    fn directive(wire: &[u8]) -> Option<Vec<u8>> {
        let message = hickory_proto::op::Message::from_vec(wire).ok()?;
        let edns = message.extensions().as_ref()?;
        edns.options().as_ref().iter().find_map(|(code, option)| {
            (u16::from(*code) == 65001).then(|| match option {
                hickory_proto::rr::rdata::opt::EdnsOption::Unknown(_, data) => data.clone(),
                other => panic!("unexpected option {other:?}"),
            })
        })
    }

    fn answer(query: &[u8]) -> Vec<u8> {
        let (header, question) = atomdns_dns_core::parse_query(query).unwrap();
        let mut wire = vec![
            (header.id >> 8) as u8,
            header.id as u8,
            0x81,
            0x80,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
        ];
        wire.extend_from_slice(&question.qname_wire);
        wire.extend_from_slice(&[0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4]);
        wire.extend_from_slice(&[30, 0, 0, 1]);
        wire
    }

    impl ExchangeExecutor for Recorder {
        fn exchange<'a>(
            &'a self,
            _executable: ExecutableId,
            query: &'a [u8],
            _deadline: Instant,
            _cancellation: TransportCancellation,
        ) -> Pin<Box<dyn Future<Output = Result<ExchangeResponse, ExchangeError>> + 'a>> {
            let id = u16::from_be_bytes([query[0], query[1]]);
            let wire = answer(query);
            Box::pin(async move { Ok(ExchangeResponse::new(wire, id, id, Transport::Udp, false)) })
        }

        fn exchange_invocation_with_outbound<'a>(
            &'a self,
            executable: ExecutableId,
            query: &'a [u8],
            deadline: Instant,
            cancellation: TransportCancellation,
            attempts: UpstreamAttemptLedgerHandle,
            outbound: Option<Arc<str>>,
        ) -> Pin<Box<dyn Future<Output = Result<InvocationExchange, ExchangeError>> + 'a>> {
            let sent = crate::edns_directive::outgoing_query(
                query,
                self.tag(executable) == crate::edns_directive::FAKEIP_UPSTREAM,
                outbound.as_deref(),
            )
            .unwrap();
            self.calls
                .borrow_mut()
                .push((self.tag(executable), directive(&sent)));
            self.exchange_invocation(executable, query, deadline, cancellation, attempts)
        }
    }

    const YAML: &str = r"log: {level: error}
plugins:
  - tag: domestic
    type: forward
    args: {upstreams: [{addr: 'udp://127.0.0.1:15000'}]}
  - tag: nocnfake
    type: forward
    args: {upstreams: [{addr: 'udp://127.0.0.1:16666'}]}
  - tag: atom_rules
    type: atom_rules
    args: {marks: {proxy: 41, direct: 42, block: 40}}
  - tag: main
    type: sequence
    args:
      - exec: $atom_rules
      - matches: fast_mark 40
        exec: reject 0
      - matches: fast_mark 41
        exec: [$nocnfake, exit]
      - matches: fast_mark 42
        exec: [$domestic, exit]
      - exec: $nocnfake
  - tag: listener
    type: udp_server
    args: {entry: main, listen: '127.0.0.1:3099'}
";

    #[test]
    fn rule_actions_reach_the_upstreams_and_the_fakeip_directive() {
        let root = super::scratch("engine");
        let file = r#"{"version": 3, "rules": [
            {"id": "r-p", "enabled": true, "match": {"suffix": ["proxy.test"]},
             "action": {"type": "proxy", "group_id": "g-x"}},
            {"id": "r-d", "enabled": true, "match": {"domain": ["direct.test"]},
             "action": {"type": "direct"}},
            {"id": "r-b", "enabled": true, "match": {"suffix": ["block.test"]},
             "action": {"type": "block"}}
        ]}"#;
        std::fs::create_dir_all(root.join("webinfo")).unwrap();
        std::fs::write(root.join(super::RULES_FILE), file).unwrap();
        let assembly = crate::HostAssembly::with_options(
            crate::config::compile_yaml_with_base(YAML, &root).expect("config"),
            HostOptions::default(),
        )
        .expect("assembly");
        let config = assembly.config();
        let tags: Vec<_> = config
            .forward_invocations
            .iter()
            .map(|invocation| {
                let definition = &config.forward_definitions[invocation.definition];
                (invocation.executable, definition.tag.clone())
            })
            .collect();
        let recorder = Recorder {
            tags,
            calls: RefCell::new(Vec::new()),
        };
        let run = |name: &str| {
            recorder.calls.borrow_mut().clear();
            let mut raw = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
            raw.extend_from_slice(&super::wire(name));
            raw.extend_from_slice(&[0, 1, 0, 1]);
            let (header, question) = atomdns_dns_core::parse_query(&raw).unwrap();
            let result = assembly.block_on(execute_request_with_observation(
                ExecutionRequest {
                    client: Default::default(),
                    config,
                    cache: assembly.cache(),
                    options: &HostOptions::default(),
                    raw: &raw,
                    header,
                    question,
                },
                &recorder,
                TransportCancellation::new(),
                &mut ExecutionCheckpoint::new(true),
            ));
            (result, recorder.calls.borrow().clone())
        };
        let (result, calls) = run("www.proxy.test");
        assert_eq!(
            calls,
            vec![("nocnfake".to_owned(), Some(b"\x01\x01g-x".to_vec()))]
        );
        assert_eq!(result.domain_set.as_deref(), Some("规则:r-p"));
        let (_, calls) = run("direct.test");
        assert_eq!(calls, vec![("domestic".to_owned(), None)]);
        let (result, calls) = run("x.block.test");
        assert!(calls.is_empty());
        let message = hickory_proto::op::Message::from_vec(&result.response_wire).unwrap();
        assert_eq!(u16::from(message.response_code()), 0, "NOERROR");
        assert!(message.answers().is_empty(), "empty answer");
        let (_, calls) = run("other.test");
        assert_eq!(
            calls,
            vec![("nocnfake".to_owned(), Some(vec![1, 2]))],
            "CLEAR"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// An answer for `a.test` A with one record per `(address, ttl)`.
fn answer(records: &[([u8; 4], u32)]) -> Vec<u8> {
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
    wire[7] = u8::try_from(records.len()).unwrap();
    wire.extend_from_slice(&[1, b'a', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1]);
    for (address, ttl) in records {
        wire.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        wire.extend_from_slice(&ttl.to_be_bytes());
        wire.extend_from_slice(&[0, 4]);
        wire.extend_from_slice(address);
    }
    wire
}

fn ttls(wire: &[u8]) -> Vec<u32> {
    hickory_proto::op::Message::from_vec(wire)
        .unwrap()
        .answers()
        .iter()
        .map(hickory_proto::rr::Record::ttl)
        .collect()
}

#[test]
fn answers_have_their_ttls_capped() {
    let host = crate::atom_singbox::Host {
        binary: "/bin/true".into(),
        dir: "/nonexistent".into(),
        reload: vec!["true".into()],
        clash_api: "127.0.0.1:9".parse().unwrap(),
        dns_in: "127.0.0.1:9".parse().unwrap(),
        atomdns: "127.0.0.1:53".parse().unwrap(),
        redirect_port: 7892,
        tproxy_port: 7893,
        resolver_group: "domestic".into(),
        nft_table: None,
        nft: vec!["nft".into()],
    };
    let rules = AtomRules::load(
        Path::new(""),
        MARKS,
        None,
        String::new(),
        Vec::new(),
        Some(host),
    )
    .unwrap();
    // Defaults: FakeIPs 1 second, real addresses 300.
    let fake = answer(&[([28, 0, 0, 7], 600)]);
    assert_eq!(ttls(&rules.cap_ttls(&fake).unwrap()), [1]);
    let real = answer(&[([1, 2, 3, 4], 3600), ([1, 2, 3, 5], 20)]);
    assert_eq!(ttls(&rules.cap_ttls(&real).unwrap()), [300, 20]);
    // An answer without addresses is left alone.
    assert_eq!(rules.cap_ttls(&answer(&[])), None);
    assert_eq!(rules.cap_ttls(b"junk"), None);
    {
        let owner = rules.proxy.as_ref().unwrap();
        let mut state = owner.state.borrow_mut();
        state.settings.fakeip_ttl_max = 30;
        state.settings.direct_ttl_max = 60;
        state.settings.fakeip_range = "29.1.0.0/16".into();
    }
    assert_eq!(
        ttls(&rules.cap_ttls(&fake).unwrap()),
        [60],
        "28.0.0.7 is real now"
    );
    let fake = answer(&[([29, 1, 200, 1], 600)]);
    assert_eq!(ttls(&rules.cap_ttls(&fake).unwrap()), [30]);
    // Without a proxy side nothing is capped.
    assert_eq!(owner(Path::new("")).cap_ttls(&real), None);
}
