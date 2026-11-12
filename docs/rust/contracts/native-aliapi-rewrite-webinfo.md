# Native `aliapi`, `rewrite` and `webinfo` (M1-b1)

## 1. Scope / trigger

Pure-YAML behavior of three plugins (always available since `native_management` was removed in Phase 6b). Loading the runtime override files
(`config_overrides.json`, `upstream_overrides.json`) is **not** part of this contract: it is paused until the settings layer
is redesigned (gap list M1-f). `aliapi` takes its values from YAML only.

## 2. Signatures

- `config::aliapi::AliApiArgs::from_yaml(&RawMap, path)` decodes the YAML mapping into typed values;
  `AliApiArgs::build(plugin_tag, path) -> ForwardDefinitionConfig` is the single constructor of the upstream list and the SOCKS5
  routes. A settings layer builds an `AliApiArgs` and calls `build`; nothing else decides how defaults merge.
- `config::build_forward_target(addr, ForwardTargetOptions, path)` builds one validated endpoint descriptor (shared with
  `forward`, which never sets `socks5`).
- `atomdns_upstream_core::socks5::Route` + `Upstream/ReuseOwner/DotEndpoint/DohEndpoint::with_socks5` carry a proxy into the
  TCP, DoT and DoH transports. UDP never uses a proxy.
- `rewrite::Rewrite`, `webinfo::WebInfo`; `CompiledConfig::local` holds both.

## 3. Contracts

### aliapi

- Compiles to the same definition as `forward` (identical race semantics: random start, `concurrent` consecutive upstreams, an
  address answer wins, otherwise the best response, otherwise the first error). Differences: `concurrent` is clamped to 1..=20
  (default 1), plugin-wide `socks5/bootstrap/bootstrap_version` (and `so_mark/bind_to_device`, rejected) fill an upstream's empty
  values, an entry tag may contain whitespace, and `socks5` is accepted.
- `socks5` (`host:port`, no authentication, remote name resolution) applies to `tcp`, `tls` and `https` upstreams; for `udp` it is
  ignored. A proxied upstream with a host name and no numeric `dial_addr` sends the name to the proxy; `bootstrap` is not used.
  A proxy failure fails that upstream (no direct fallback).
- DoH3 (`h3://` or `https://` with `enable_http3: true`) and DoQ (`quic://` or `doq://`) require a direct UDP connection. A SOCKS5 address, an entry-level proxy reference, or `use_proxy: true` is a load error for either protocol.
- Rejected at load, never ignored: the signed AliDNS API (`type: aliapi`, or the mere presence of `account_id`, `access_key_id`,
  `access_key_secret`, `server_addr`, `ecs_client_ip`, `ecs_client_mask`, whatever the value), `so_mark`, `bind_to_device`, `enable_pipeline`, positive
  `idle_timeout`, unsupported schemes, negative timeouts, and unknown keys.
- `forward` keeps rejecting `socks5`.

### rewrite

- `files` (at least one; the first is the `/post` target, a missing file is allowed) and `dns` (`host[:port]`, port 53; a host name is resolved by the system resolver for each lookup, the first address is used; **`$sequence_tag`** names a sequence of this process, which is run over the query with no socket and no audit record. The tag must name a `sequence` (checked at compile time). Such a run answers like a listener would (`entry` option of the request); its own `rewrite` calls never start another one, so a sequence that rewrites again ends the lookup as a failure (SERVFAIL) instead of looping).
- A rule is `pattern target`, exactly two fields; blank lines and whole-line `#` comments are skipped; pattern grammar is the
  shared domain matcher (default `full`); a target is an IP (IPv4-mapped counts as IPv4) or a domain name.
- A match sets the audit `domain_set` label `重定向` and **accepts** the query (the rest of the current chain does not run).
  IP target: A/AAAA answer of the same family with TTL 5, every other type or family NOERROR without records. Domain target:
  A/AAAA only; one UDP query to `dns` (5 s, bounded by the request; EDNS 1232 with the original DO bit; RD/AD/CD copied);
  NOERROR -> original question plus all answers with TTL 5; anything else (including cancellation of the lookup by the
  request budget) -> SERVFAIL.
- `GET /plugins/<tag>/show` (rule lines joined by `\n`), `POST /plugins/<tag>/post` with `{"values":[...]}`: replaces every rule,
  writes the first file atomically (`join("\n")` + newline); a failed write keeps the new in-memory rules and answers 500
  `In-memory rules updated, but failed to write to file: ...`.

### webinfo

- `file` (required). Missing or empty file = `{}`; invalid JSON fails load (and `check`).
- `GET`/`PUT` on `/plugins/<tag>` (with or without trailing slash): sorted keys, HTML-escaped; PUT stores the document
  atomically (two-space indentation, no trailing newline) and echoes it; invalid JSON -> 400, failed save -> 500 and both the
  file and the in-memory document stay as they were. The parent directory is created by the first PUT, not at load.
- The `client.aliases` UI capability is advertised when a `webinfo` tagged `clientname` exists.

## 4. Validation matrix

Integration tests `rust/native-host/tests/m1_b1_aliapi_rewrite_webinfo.rs`, unit tests in `rewrite.rs`, `webinfo.rs`,
`socks5.rs`; evidence in `../validation-records/10-08-m1-b1/README.md`.

## 5. Known differences from the reference host

- Overrides (`config_overrides.json`, `upstream_overrides.json`) are not applied (paused).
- A rewritten response has RA set (like `hosts`); a failed webinfo save does not leave the new document in memory.
