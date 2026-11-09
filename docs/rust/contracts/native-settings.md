# Native typed settings (M1-f1)

Scope: the values the WebUI adjusts at run time — proxy address, ECS address, `aliapi` upstream lists, the `domain_output` generation switches, the `feature_flag` values ([native-feature-flags](native-feature-flags.md)) — as named
configuration objects referenced with `$tag`, a versioned `webinfo/settings.json` that stores overrides and managed upstream lists, one function that combines
both, and hot apply of a change. The reference host's `upstream_overrides.json`, `config_overrides.json`, global `replacements` and
`domain_generation_settings.json` are **not read**. Evidence: `docs/rust/validation-records/10-08-m1-f1/`. Design notes: the task's `research/design.md`.

## Objects and references

```yaml
- tag: main_proxy
  type: socks5_proxy        # args.addr: host:port, nonzero port, no authentication; empty or absent = no proxy (M1-f2)
- tag: client_ecs
  type: ecs_address         # args.addr: an IP, optionally /mask (the mask is ignored, as in quick `ecs`)
```
An empty `socks5_proxy` address is the "no proxy" state (the reference's empty global `socks5`): everything that references it connects directly, `use_proxy: true` included, and the overrides page shows `socks5: ""`. `ecs_address` always needs an address.
Both are non-executable (`exec: $main_proxy` is an error). References are `$tag` strings; an unknown tag or a tag of the wrong kind is a load error naming the YAML path.

- `aliapi`: plugin `proxy: $main_proxy` is the default proxy of entries that say `use_proxy: true` (default false); an entry may instead say `proxy: $other`. `use_proxy` without a plugin
  `proxy` is an error. The proxy applies to `tcp`/`tls`/`https` entries only (UDP ignores it, as in M1-b1). Literal `socks5:` stays accepted (plugin or entry) but excludes `proxy`/`use_proxy` in any form (even `use_proxy: false`), an entry `proxy`, and stored `upstreams` settings for a plugin with a literal `socks5` (all are load errors); use `proxy: $x` instead.
  Whether an entry is proxied is decided only by these keys; the reference's "`foreign`/`foreignecs` fall back to the global proxy" rule does not exist here.
- `sd_set_light`, `si_set`, `adguard_rule`: `proxy: $main_proxy` for downloads; a literal `socks5` excludes it.
- ECS: the quick form `ecs $client_ecs` (inside any sequence argument) and `ecs_handler.preset: $client_ecs`. The resolved address is a fixed address for the cache placement rule (M1-g).
- `domain_output`: new optional arg `enabled` (default true).

## `webinfo/settings.json` (under the configuration root)

```json
{"version":1,
 "proxies":{"main_proxy":{"addr":"192.0.2.9:7890"}},
 "ecs":{"client_ecs":{"addr":"198.51.100.5"}},
 "upstreams":{"foreign":[{"tag":"cf","enabled":true,"protocol":"tcp","addr":"1.1.1.1","use_proxy":true}]},
 "domain_generation":{"enabled":false,"plugins":{"my_realiplist":{"enabled":false}}}}
```
Addresses and switches store only differences from YAML. A non-empty upstream-list save always retains `upstreams.<tag>`, even when the entries equal YAML: its presence records UI/API management. Only an explicit empty-list save removes that group override and restores the YAML list and concurrency (sections omitted when empty; keys sorted; two-space indent; trailing newline).
`flags` (`{"<key>": true|false|"<option>"}`) is the one section kept when empty: its presence records the one-time migration of the schema-2 switch files, and every save (any route, the migration) keeps it unchanged unless it is the flag route itself. `upstreams.<tag>` replaces that `aliapi`'s whole YAML list (only `enabled`
entries compile; `concurrent = min(enabled count, 20)` for settings-managed lists; all entries disabled is an error). Groups without a stored list retain their YAML `concurrent`, bounded by the existing 1..20 limit and available upstream count. This applies identically on startup and hot apply, including settings-generated special groups. Entry fields are the WebUI's: `tag`, `enabled`, `protocol`
(`udp|tcp|tls|https|h3|quic`, aliases `dot|doh|doq`), `addr` (a scheme-less address gets the protocol's scheme), `dial_addr`, `upstream_query_timeout` (ms), `insecure_skip_verify`, `bootstrap`,
`bootstrap_version`, `enable_http3` for `https` or `h3`, and `use_proxy` (the reference's `use_socks_proxy` is accepted on input).
DoH3 and DoQ are direct-only. A proxy switch set to true is rejected for either protocol.
Refused options include `protocol: aliapi` / signed-API fields, a literal `socks5`, `so_mark`, `bind_to_device`, `enable_pipeline`, positive `idle_timeout`, and unknown fields.
Loading errors (start, `check`): unreadable or unparsable file, a version other than 1, an unknown top-level key, a settings key that names no object / the wrong kind, an invalid
value. A missing or empty file is "no settings". Compiling and `check` never write. (The `native_management` mode that used to bypass the settings API was removed in Phase 6b.)

## Tunable numbers of caches and learners (config schema 6)

`settings.json` also stores differences for the numbers the WebUI tunes, again only where they differ from the YAML:

```json
{"version":1,
 "caches":{"cache_all":{"size":50000,"lazy_cache_ttl":259200,"dump_interval":3600}},
 "learning":{"write_interval":43200,"categories":{"my_realiplist":{"ttl":1209600,"max_entries":50000}}}}
```

- `caches.<tag>` names a `cache`; fields are optional. `size` (entries) 1,000 – 100,000,000; `lazy_cache_ttl` (seconds an expired answer may still be served, 0 = none) 0 – 4,294,967,295; `dump_interval` (seconds) 60 – 31,536,000.
  They replace the cache's `size`, `lazy_cache_ttl` and `dump_interval`. All three belong to the cache identity (`same_cache_options`): a changed value **replaces that cache by an empty one** on the next generation (an empty dump is written first, see Commit order below).
- `learning.write_interval` (seconds, 60 – 31,536,000) applies to every `route_learner`; `learning.categories.<tag>` names a learner category: `ttl` 60 – 315,360,000 seconds, `max_entries` 1 – 262,144.
  They replace the category's `ttl`/`max_entries` and the learner's `write_interval`. A hot apply keeps the learned names (the learner state is handed over in memory when the categories are the same): entries expire at `last confirmation + ttl` with the new `ttl`,
  and a category holding more than its new `max_entries` keeps the most recently confirmed names (counted as evicted).
- Not tunable here, on purpose: marks, labels, sources, `exclude_ip`, `enable_ecs`, `dump_file`, `route_learn` conditions, `target_mapper`, which categories exist and their order.
- Loading errors: a key naming no `cache` / no category, an unknown field, or a value outside its range (the error names the key, e.g. `caches.cache_all.size`). A stored value equal to the YAML one is never written by the API; one written by hand is accepted and reported as `source=settings`.
- `check` and `GET /api/v1/settings/effective` add `cache` items (`size`, `lazy_cache_ttl`, `dump_interval` per cache) and `route_learner` items (`write_interval` per learner; `ttl`, `max_entries` per category).

**Downgrade hazard.** `Settings` refuses unknown keys, so a program from before schema 6 does not start with a `caches` or `learning` section in the file. Restore the defaults (API `DELETE`) or remove the two sections before going back.

### API

- `GET /api/v1/cache/settings` -> `{settings_file, caches:[{tag, size:{value,default,modified}, lazy_cache_ttl:{…}, dump_interval:{…}}]}` in configuration order. `POST /api/v1/cache/settings/{tag}` takes any of `size`, `lazy_cache_ttl`, `dump_interval`
  (a whole number, or `null` to return that field to the YAML value) and answers `{cache, reset:[tag…]}`; `reset` names the cache when the values changed, i.e. when it was replaced by an empty one. `DELETE …/{tag}` restores all three.
  404 unknown tag, 400 bad field or range, 405 other methods, 503 while a configuration update is being tried out.
- `GET /api/v1/learning/settings` -> `{settings_file, write_interval:{…}, categories:[{tag, ttl:{…}, max_entries:{…}}]}` in declaration order. `POST` takes `write_interval` and/or `categories:{<tag>:{ttl?, max_entries?}}` (`null` restores); one request publishes at most one generation.
  `DELETE` restores everything. Same status codes; 404 for an unknown category.
- A `cache` may carry a display `label` (see [native-cache-lifecycle](native-cache-lifecycle.md)); `GET /api/v1/cache/settings` returns it as `label` (`""` when none). The caches of the special groups (`cache_special_<slot>`, generated with the label `专属分流组「<name>」缓存` and the same defaults as the packaged group caches) are tunable too; settings for a group that no longer exists are ignored, not an error.
- Capabilities `cache.settings` (a `cache` exists, file-backed) and `learning.settings` (a `route_learner` exists, file-backed). Both are optional for the WebUI: a program without them simply shows no editing.

## The effective configuration

M1-e group-proxy rule (user approved 2026-10-09): owned special-group upstreams
with `use_proxy=true` require exactly one configured `socks5_proxy`, like the
overrides page. Zero objects reject the change with a missing-object reason;
multiple objects reject with an ambiguity reason. The sole object's address,
including its explicit empty "no proxy" value, applies. Group references inherit
the source plugin/entry's resolved proxy. Standard-mode groups resolve after the
ordinary typed settings overlay on every compile/apply; group entries and
sources appear in effective reports. Derived group YAML participates in the same
authority-file commit and startup recovery described in
[native-special-groups](native-special-groups.md). External review remains pending.

`config::settings::apply(definitions, settings)` runs inside the shared compile (`start`, `check`, hot apply): validate, resolve references to the literal forms the plugin compilers accept,
overlay settings, and report every item (`kind`, `object`, `field`, `value`, `source` = `yaml` | `settings`). `domain_output` `enabled` is the plugin's setting (else the YAML `enabled`), and only while the master setting is on. A disabled list records and publishes nothing and injects nothing into the mapper layer.
`atomdns check` prints `EFFECTIVE <kind> <object> <field>=<value> source=<source>` lines; `GET /api/v1/settings/effective` returns `{settings_file, items}`.

## Hot apply

A change builds new settings, recompiles the same YAML with them (any error rejects the change), and publishes the result as the next generation through the whole-generation path
(admission pause, management drain, switch rebase, cache policy gate, install, retirement of the old generation with rule sources / `domain_output` / `requery` fenced and joined, then a memory trim).
**Commit order:** (1) caches whose identity changed get an empty dump written; (2) the settings file is replaced durably (temporary file and parent directory are fsynced around the rename) after checking it still holds the bytes the candidate was built against (else
409); (3) the generation is published. Failure before (2) changes nothing; failure of (2) leaves the old file and generation (dumps may be empty: harmless, caches are only read at start); a crash
after (2) restarts into the new state, which the candidate compile already proved loadable; a failure while publishing stops the host the same way. A query keeps the generation it started with; the next
query uses the new one. The candidate compile runs on a thread of its own, one compile at a time (a later save waits for the earlier compile); the DNS thread keeps answering meanwhile.
A save whose compile overlapped another publication is refused with 409 (busy) and changes nothing; one that reaches publication while another is still publishing is refused as before. Shutdown during the compile abandons the change (nothing is written). Publishing the candidate and retiring the
old generation still run on the DNS thread and can delay answers briefly; UDP queries arriving meanwhile wait in the listener's enlarged kernel receive buffer (see
"UDP receive buffer and apply pause" in native-webui-hosting.md; measurements in `docs/rust/validation-records/10-22-offthread-apply/`).

## API

- `GET /api/v1/upstream/tags` (the `aliapi` tags), `GET /api/v1/upstream/config` (`{tag:[entries]}`: the effective list in the WebUI shape, `use_socks_proxy` = the effective switch),
  `GET /api/v1/upstream/runtime/{tag}` (`override_config` = the settings entries), `POST /api/v1/upstream/config {plugin_tag, upstreams}` (validated, stored, applied; an empty list removes the override,
  i.e. restores the YAML list — never "delete the last upstream"; a non-empty list without an enabled entry is refused before anything is stored with
  `400 上游组「<tag>」至少要保留一个启用的上游。`, plus `这个组只在<conditions>时使用；不想用它，关闭该开关即可。` when the group declares `show_when` (v0.4.0; before, the
  `aliapi` compile error `…upstreams must not be empty` came back as the 400 text);
  404 unknown tag; 400 with the reason above). Standard schema-4 profiles expose
  `/api/v1/upstream/sources`; special-group tags are refused by ordinary upstream
  POST and maintained through `/api/v1/special-groups` instead.
- `GET /api/v1/upstream/groups` (v0.4.0; capability `endpoints.upstream.groups_get`, operation `upstreams.read`) -> one object per `aliapi` tag (sorted by tag):
  `{tag, active, show_when: [conditions], used_when?, inactive_reason?}` (`used_when`: the conditions in words, e.g. `「国内域名 FakeIP」开启`, whenever there are any). An `aliapi` may declare `args.show_when` (display only, never affects resolution): one condition or a
  non-empty list of conditions that must all hold, each `flag <key>`, `flag <key>=<option>` or the same after `!`, validated at load like the `flag` matcher (unknown
  flag/option, bool/choice mismatch, any other shape → load error at `…args.show_when[i]`). `active` is whether they all hold in the current generation (a flag change
  publishes a new one); `inactive_reason` reads `仅在「<flag label>」开启时使用` / `仅在「<label>」为「<option label>」时使用` (`关闭` / `不是` for `!`, conditions joined by `且`).
  The WebUI hides inactive groups in 上游设置 (unless asked) and in the overview's upstream statistics.
- `GET /api/v1/overrides` -> `{socks5, ecs, replacements: []}` from the unique `socks5_proxy` / `ecs_address`; `POST` sets them (an empty value returns to the YAML value; non-empty `replacements` -> 400;
  several objects of a kind -> 409 `ambiguous`; no object but a value -> 400).
- `GET /api/v1/domain-generation` -> `{enabled, remember_direct, remember_proxy, no_v4, no_v6}`; `POST` takes a partial of the same keys and answers `{settings, flush_targets}`. `enabled` is the
  master switch; the four others are the `domain_output` plugins tagged `my_realiplist`, `my_fakeiplist`, `my_nov4list`, `my_nov6list` (the WebUI is bound to these tags). A list whose switch went from
  on to off (every list when the master goes off) is flushed after the apply; if a flush fails the answer is 500 `settings were applied, but flushing failed: ...` (the settings stay applied).
- Capabilities: `upstreams.manage` (an `aliapi` exists, file-backed), `system.global_overrides` (a `socks5_proxy` or `ecs_address`), `system.domain_generation` (a `domain_output`).

## Migration from the reference override files (M1-f2)

`atomdns-settings-migrate --from <reference dir> [-d <root>] -c <config> --out <dir>` reads `config_overrides.json`, `upstream_overrides.json` and `domain_generation_settings.json`
(in `webinfo/`, `state/` or the directory itself), compiles the native configuration to get the YAML defaults, and writes `settings.json` (address/switch differences plus managed upstream lists) and `migration-report.txt` to `--out`. Mapped upstream lists remain stored even when equal to YAML so their enabled-count concurrency survives migration.
It never changes its inputs or the native root. Exit code 0: everything mapped; 1: the report lists items that need a person (enabled signed-API entries, `so_mark`/`bind_to_device`/pipeline/HTTP3/QUIC/idle-timeout entries,
an entry's own `socks5` that differs from the global one, `replacements`, tags the configuration does not have, an enabled entry without a tag); 2: usage, I/O, parse or the migrated settings do not load.
The reference's rules are reproduced: `use_socks_proxy` unset means "TCP-class protocol and (own address or a `foreign`/`foreignecs` group)"; only those two groups fall back to the global address; UDP never uses a proxy.
They become explicit `use_proxy` values. A repeated upstream tag in a later group is renamed `<tag>-<group>` (upstream tags are unique here) and reported.

The GET entries of the settings-backed upstream page carry the reference field `use_socks_proxy` only (no `use_proxy`); `unsupported_features` omits `socks_proxy` there.
`check` marks an `aliapi` entry that really connects through a proxy address with ` [proxy]` in its `EFFECTIVE` value.

## Known differences from the reference

No `replacements`; no global override of every `socks5`/`ecs` string (explicit references instead); no implicit proxy for `foreign`/`foreignecs`; unmanaged YAML groups retain explicit `concurrent`, while managed groups derive it from enabled count (up to 20);
changes apply immediately (the reference asks for a restart on the overrides page); settings are per object tag.
