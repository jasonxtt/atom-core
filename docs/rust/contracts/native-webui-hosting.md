# Native WebUI hosting and runtime capabilities

This contract belongs to the opt-in pure Rust `atomdns-native-host`. It does not
select the production/default binary or close the full native migration gate.

## Same-origin hosting

**Since v0.4.0 the program embeds no WebUI** (`build.rs` embeds nothing; the former
`rust/native-host/ui/` tree is gone). The WebUI is the directory **`<config root>/ui/main/`**,
served at **`/`** without a prefix; every other `ui/<name>/` is served at `/<name>/` as before.
`/main/` is not a second address of the WebUI (404). The program serves no `/log`
(the compatibility UI belongs to the Go host only). No Go, Node, frontend proxy, source checkout
or external web server is required at runtime.

Routing, after the health route and the admission check: (1) a path whose first segment is a
mounted `ui/<name>` goes to that UI; (2) `/api`, `/api/…`, `/plugins`, `/plugins/…` and
`/metrics` always go to the API, whatever `ui/main` contains; (3) any other `GET`/`HEAD` is a
file of `ui/main` (`/` and a trailing `/` → that directory's `index.html`; a directory without
the slash → 301; missing → 404; above 16 MiB → 413); (4) other methods go to the API dispatcher
(an unknown path stays its 404). Files are live rereads with `Cache-Control: no-store`, accurate
MIME and `nosniff`; no listing, no SPA fallback, no ETags.

**Without a usable `ui/main`** (absent, a symbolic link, or refused by its manifest) only
`GET`/`HEAD /` answers, with `404` and a short `text/html` page: no WebUI is installed, unpack
`atomdns-webui.tar.gz` into `<config root>/ui/main/` and restart; the reason is added when
`ui/main` was refused. Every other non-API path is a plain 404, and the API, `/metrics` and
the other `ui/<name>/` mounts are unaffected. That is the pure-backend (headless) setup.

The UI directories are registered once from immediate real directories under the
**top-level configuration directory** `ui/<name>`. A basename `-c config.yaml`
uses that file's startup directory. In-memory compilation requires an explicit
nonempty base; no base means no mounts. Includes, process directory
changes and hot managed generations do not remount the registry. Reserved names:
`root`, `log`, `log1`, `legacy`, `blog`, `assets`, `debug`, `metrics`, `plugins`, `api`,
`chunks` (`assets` and `chunks` are top-level directories of the WebUI at `/`).
A safe mount `/name` redirects to `/name/`; directory requests require index.html.

Linux uses pinned directory descriptors and handle-relative `openat2` beneath
and no-symlink resolution. Path decoding occurs once and rejects malformed
encoding, encoded separators, backslashes, control/NUL bytes and dot traversal.
Symlink/device/FIFO/socket/nonregular/escape targets return no file contents.
Root replacement does not change the pinned mount. Unsupported platforms or
kernels fail closed for every UI directory (`/` shows the "no WebUI" page); the API continues. Startup
failures produce bounded diagnostics, without filenames/content disclosure.

**WebUI packages (UI-1, v0.4.0).** `npm run build` in `webui/` (atom step 6b; formerly `webui-log/`) builds the WebUI package into
`webui/dist/` (`index.html`, `app.js`, `app.css`, `chunks/`, `assets/`, `ui-manifest.json`) with
**relative** resource URLs (`base: './'`), so the same package works as `ui/main` at `/` and as any
`ui/<name>` at `/<name>/` (API calls are same-origin absolute paths); `npm run build:package` also
writes `release/atom-webui.tar.gz` (the package files at the top level). Online
updates replace `ui/main` with the release's package when, and only when, `ui/main` exists
([native-update](native-update.md)); other `ui/<name>` directories are never touched. Directory
names follow the rules above. A **atomdns UI package** is a directory that carries a
`ui-manifest.json`:

```json
{"manifest_schema": 1, "ui_version": "v0.7.3-12-gabcdef", "built_at": "2026-10-17T10:00:00Z", "api_level": 2, "requires_api_level": 2}
```

`manifest_schema` must be 1; `ui_version` is required (non-empty, at most 64 characters, no
control characters); `built_at` is optional; `api_level` is the interface level the UI was built for
and `requires_api_level` (default `api_level`) the least level it needs from the host. The host
provides `HOST_API_LEVEL = 2` and still serves UIs built for `MIN_UI_API_LEVEL = 2` or later
(`rust/native-host/src/ui_manifest.rs`; atom: level 2 is `/api/v1/atom/`, level 1 UIs used the
interfaces removed in step 6a; backward-compatible additions do not change the level). **Compatible ⇔ `requires_api_level ≤ HOST_API_LEVEL` and
`api_level ≥ MIN_UI_API_LEVEL`.** The manifest check applies **only to directories that have a
manifest**, `ui/main` included. At startup the registry looks in each pinned `ui/<name>` directory for
`ui-manifest.json` (beneath-only, no symlinks, a regular file of at most 64 KiB):
- **no manifest** → not a atomdns UI package: the directory is mounted as a generic static mount
  (other static pages an operator put there keep working), and health notes
  "非 atomdns UI 包（无 manifest）" (`kind: "static"`);
- **manifest, compatible, `index.html` a regular file** → mounted (`kind: "atomdns_ui"`, with its version);
- **manifest present but unreadable / not JSON / wrong schema / invalid version / incompatible level /
  `index.html` missing** → **not mounted** (`/<name>/` is 404; for `ui/main`, `/` shows the "no WebUI"
  page with the reason) with a fixed, content-free reason.
Reserved names and non-directories (a symlink, a file with the name of a directory entry) are listed as
`kind: "unusable"` and not mounted; plain files directly under `ui/` are ignored. The result is
decided at startup, like every mount; file contents are re-read live, so replacing files of the same
package takes effect at once, but a new package's manifest is judged (and the version shown) only at
the next start — restart once after a manual update. Usage: [docs/rust/external-ui.md](../external-ui.md).

Both static services share four active representation owners; saturation is
503. Non-representation 301/404/405 retain their status. Headers have a five-second
read budget; response transfers have ten seconds and chunks at most 64 KiB.
External metadata/open/read work runs outside the LocalSet, through one bounded
channel per owner. Cancellation closes the receiver and joins started blocking
workers before ownership/permits are released. Shutdown drains connections and
workers; a started stalled filesystem operation can delay that join. Static
requests do not acquire query/mutation leases or create DNS audit/metric events.

## Version and readiness

`atomdns version` prints only the product version and newline, exits zero before
config/runtime construction, and rejects extra arguments. Bare Cargo defaults
to `dev`; explicit `ATOMDNS_BUILD_VERSION` is nonempty and cannot contain CR/LF.
Health GET `/api/v1/system/health` shares this exact version. JSON fields are
`ready`, `runtime:"rust"`, `version`, `state`, `required_config_schema:null`,
`applied_config_schema:null`, `config_management_enabled:false`, and
`pending_cleanup` (array of paths, relative to the configuration root, of deleted
special-group files that could not be removed yet; empty normally, never affects
`ready`; see native-special-groups.md), `external_ui`
(an array, sorted by name, at most 64 entries, one per directory under `ui/`:
`{"name", "path", "mounted", "kind": "atomdns_ui"|"static"|"unusable", "ui_version", "built_at", "reason"}`;
`path` is `/` for `main` (the WebUI) and `/<name>/` otherwise (v0.4.0);
`reason` explains a refusal, or notes that a manifest-less directory is not a atomdns UI package; the
WebUI shows `main`'s `ui_version` as 界面版本 on the system page, a link to `/<name>/` for **every**
other mounted compatible atomdns UI package (not the one being viewed) and the reason of each refused
one; never affects `ready`) and `udp_receive_buffers` (one
`{listen, bytes}` per live UDP listener: the kernel receive buffer it was
granted, `null` when unreadable; see "UDP receive buffer and apply pause"
below; never affects `ready`). Null schemas do
not mean YAML schema zero or disable native managed group/upstream operations.
State values are `starting`, `ready`, `applying`, `recovery_required`, `stopping`,
and `closed`. Health is read-only and crosses the admission rejection barrier without a lease.
Only all-listener-ready lifecycle returns 200/ready:true; startup, applying,
recovery-required, stopping and closed return 503/ready:false. Other methods405.

## UDP receive buffer and apply pause

Saving settings (`native-settings.md`) or a special group (`native-special-groups.md`)
compiles the candidate configuration on a thread of its own (M2-3; before it, the
compile ran on the single DNS thread and DNS answers paused for about 0.4–0.65 s
with the production rule set). Publishing the candidate and retiring the old
generation still run on the DNS thread and can hold answers back briefly (the
measured figures are in `docs/rust/validation-records/10-22-offthread-apply/`).
UDP queries that arrive meanwhile wait in the kernel receive buffer of the
listener and are answered when the thread resumes; they are not dropped as long
as the buffer holds them. Every UDP DNS listener
therefore asks for an effective receive buffer of 4 MiB (about 3 400 small
packets, ten times the 500 qps × 0.65 s burst): first `SO_RCVBUF` (half of that,
since Linux stores double), then, if `net.core.rmem_max` capped it, `SO_RCVBUFFORCE`
(needs `CAP_NET_ADMIN`). Failure to reach the target never stops the host: the
value the system granted is kept, a warning names it, and `udp_receive_buffers`
in the health document shows it. On a host whose `rmem_max` is below 2 MiB and
which cannot force the option, a longer burst can still overflow the buffer;
raise `net.core.rmem_max`. TCP listeners are unaffected (connection-level flow
control).

## System operations (F-1)

Three operations that were reported unsupported are real now; each is gated by its
`ui_operations` entry and answers exactly the routes the maintained WebUI calls. Only the
maintained shell at `/` is in scope.

**Appearance — removed (UI redo part 1, 2026-10-23).** The former `appearance.server`
operation and every `/api/v1/appearance/…` route (panel background upload/history/image, text
and button colours) are gone: the routes answer `404` and the operation is no longer in
`ui_operations`. The management listener again accepts at most 1 MiB per request body (the cache
`load_dump` route keeps its own limit); the single-upload slot and the 120 s body deadline went with
the upload. The theme is a browser-side choice (light / dark / follow the system). State files an
older host wrote under `webinfo/` (`appearance_settings.json`, `appearance_text_settings.json`,
`appearance_button_settings.json`, `panel_background.bin`, `panel_background_history/`) are neither
read nor deleted; an external UI that wants a background ships it in its own static package.

**WebUI port (`system.webui_port`)** — `GET/POST /api/v1/system/webui-port`. The port is saved in
`webinfo/webui_port_settings.json` (`{"port": N}`) and **replaces the `api.http` port at the next
start** (the saved port wins over YAML, as in the reference). Saving does not switch the running
listener; `pending_restart` says so. `POST` rejects ports outside 1–65535 (400), a port that cannot
be bound (409) and answers `target_addr`, `message`. The active address is the one the management
listener actually bound.

**Restart (`system.restart`)** — `POST /api/v1/system/restart {"delay_ms": N}` (`N<=0` → 300; at
most 10 minutes) answers `{"status":"scheduled","delay_ms":N}` at once. The restart is **in place**:
after the delay the host stops exactly as it does for `SIGTERM` (admission stops, in-flight queries
finish or are cancelled, caches/domain lists/rule sources/audit settings are saved, listeners and
upstream connections are closed), then the process image is replaced with `execve` of the same
executable and arguments (the path recorded at start, so a binary upgraded in place is the one
that runs). The **process id does not change**, so the service manager never sees the service stop
— necessary because the production unit waits two minutes before restarting a stopped service.
The request is refused up front (500 `{"error": …}`) when the executable is missing or not
executable, and with 501 when the process did not record one. A final save that fails is logged and the
restart goes ahead (the cache dump is a convenience; an exit would cost the restart delay). If the
`execve` itself fails, the host starts again inside the same process and keeps serving. A
termination signal during a pending restart wins. DNS is unavailable from the close of the listeners
until the new process binds them (drain + save + `execve` + cold start with the loaded cache dump):
unlike the 0.4–0.65 s pause of a configuration save (no listener is closed then), queries sent
in between are lost. The measured gap is in the F-1 validation record.

**Process metrics (`metrics.process`)** — the process section of `GET /metrics` (Prometheus text,
read from `/proc/self`): `process_cpu_seconds_total`, `process_start_time_seconds`,
`process_resident_memory_bytes`, `process_virtual_memory_bytes`, `process_open_fds`,
`process_max_fds`, and the native gauge `atomdns_process_threads`. Go-runtime figures
(`go_gc_*`, `go_goroutines`, `go_info`, `go_memstats_*`) and the system network counters of the
reference's `process_network_*` do not exist in this runtime and are **not emitted**; the WebUI
shows only the available figures. The start time is the
process's (unchanged by an in-place restart, as in the reference). The upstream and cache series
of `/metrics` are described under "Diagnostics (F-2)" below.

## Diagnostics (F-2)

**Log capture (`capture.logs`)** — `POST /api/v1/capture/start` and `GET /api/v1/capture/logs`, with
the reference's contract. `start` takes an optional body `{"duration_seconds": n}` (empty body or
absent/null field: 120); `1 <= n <= 600`, otherwise `400 Duration must be between 1 and 600 seconds`;
an undecodable body is `400 Invalid request body: <decoder text>` (the text after the prefix is the
native decoder's); success is `200` with `Log capture started for N seconds. Log level set to DEBUG.`.
`logs` returns `200 application/json`, an array of line objects, and **empties the buffer** (read
once); no capture yet or an already read buffer gives `[]`. Other methods are `405`. A second `start`
empties the buffer and restarts the window. The window ends lazily at its deadline (no timer task);
lines already captured stay readable after it.

While a capture runs the diagnostic threshold of the host drops to debug (also for `log.file`/stderr)
and, at the end, the **configured `log.level` is in force again** — it is never overwritten (the
reference resets to info whatever was configured; this is an intentional difference). Captured lines
are `{level:"debug", time (RFC 3339), msg, logger_name, …fields}`: one `dns query completed` line
(`logger_name:"query"`) per query of an `enable_audit` listener with `trace_id`, `domain`, `qtype`,
`client`, `transport`, `outcome`, `cache` (`hit`/`miss`/`notapplicable`/`undetermined`), `elapsed_ms`,
and — when the response or the execution established them — `rcode`, `route`, `matched_group`,
`domain_set`, `upstream`, `failure`; plus the host's own low-frequency debug lines
(`logger_name:"host"`).

**Step trace (F-2b).** Before that summary line the capture also carries the reference's step log,
with its two messages and field names, under the **same `trace_id`** as the summary line and for the
same queries (those of `enable_audit` listeners): after every *named* matcher evaluation
`dns query flows through matcher` with `trace_id`, `domain`, `matcher_name`, `match_result`; and,
once every matcher of a rule matched and before its action runs, `dns query flows through plugin`
with `trace_id`, `query_id`, `domain`, `plugin_name` (a rule without an action is reported too, as
`no_exec`). `domain` is the question name at that step without the trailing dot (so a rewrite or
redirect shows). Lines are reported by the engine at the one place all matchers and rules run, so
the root sequence, `call`/`goto`/`jump` targets, sequences used as an `exec`, multi-`exec` rules
(the rule as `multi_exec[...]`, then each executable) and fallback/preference branches all report
(concurrent branches interleave; the lines carry their times). `logger_name` is the configuration
sequence that is executing; a synthetic inline sequence reports under the sequence it belongs to.
(Difference: the reference reports the rules reached through `jump`/`goto` under the logger of the
jumping sequence; here they are reported under the target sequence, so the UI's "进入序列" marker
names the sequence that really runs.) As in the
reference, the first false matcher of a rule ends its evaluation (later matchers of that rule are not
evaluated or reported), and a sequence that runs to its end reports nothing more.
Names are generated at configuration compile time with the reference's rules (`sequence.go`):
`matcher_name` is the tag of a `$tag` matcher, otherwise `anonymous_match(type: args)` with the
argument text as written (first-space split, trimmed), wrapped in `not(...)` for `!`; `plugin_name` is
`no_exec`, the tag of a single `$tag` exec, `anonymous_exec(type: args)` for a single quick exec, or
`multi_exec[tag-or-type,...]`. (The task text said "raw configuration text"; the reference's actual
output is the generated name above, which is what is implemented and compared.) Matchers and rules
the host inserts that have no configuration text (managed-profile rules, etc.) are not reported.
A query is traced only when it was admitted while a capture was running; queries already in flight
when `start` is called are not.

**Upstream attempt line.** While a capture runs, each upstream attempt of a forward group for a traced
query adds one line `dns upstream attempt` (`logger_name:"upstream"`) under the query's **`trace_id`**,
with `domain` (the name sent upstream: the redirect target when a redirect applies), `qtype`,
`entry_index`, `upstream` (`host:port` as configured) and `outcome`: `response` plus `rcode` (full,
including the OPT extension) and `has_address` (the Answer section holds an A/AAAA), or the failed
outcome (`failed`, `timedout`, `canceled`) without them. It lets a final SERVFAIL be traced to the leg
that supplied it; join it to the `dns query completed` line by `trace_id`. An untraced query (admitted
before the capture started) adds no line. The audit and API schemas are unchanged.

The per-query lines go **only to the capture buffer**, never to the log file or stderr, so a capture
does not put file I/O on the DNS thread; recording is a short critical section on a dedicated mutex.
With no capture running the engine does one `Option` check per matcher and per rule (no allocation,
no formatting) and admission one relaxed atomic load. The buffer is bounded: at most **32768 lines
and 8 MiB** of serialized text (one query's trace is about 10–20 lines; the reference's buffer is
unbounded), string values cut at 256 characters; the oldest line is dropped first and a `warn` line
`capture buffer limit reached: N older lines dropped` leads the next read.

**`/metrics` upstream series** — for every `aliapi` upstream **with a `tag`** (as in the reference),
from startup at zero: `atomdns_aliapi_query_total`, `_error_total`, `_upstream_winner_total`
(counters) and `atomdns_aliapi_response_latency_millisecond` (histogram: `_bucket{le=…}` with the
bounds `1,5,10,20,50,100,200,500,1000,2000,5000,+Inf`, `_sum`, `_count`), labelled `addr` (the
configured address text), `metrics_tag` (the plugin tag) and `tag` (the upstream tag). Units are
counts and whole milliseconds (truncated, as the reference). Semantics: `query_total` counts every
upstream attempt, including attempts later canceled (a concurrent group's losers); `error_total`
counts failed and timed-out attempts; a canceled or dropped attempt is neither an error nor a
latency observation (the reference lets losers finish, so they would count there); the latency
histogram observes successful attempts only; `winner_total` counts attempts whose response became
their group's final response. Counters stay monotonic across configuration changes (the reference
resets an upstream's counters when its group is rebuilt). The `atomdns_cache_*` series and the
process figures are unchanged.

*Not provided* (no matching native event, and nothing reads them): `atomdns_aliapi_inflight_queries`
(attempts are tallied when a query ends, so attempts in flight are not visible), and
`atomdns_aliapi_conn_opened_total` / `_conn_closed_total`; the `atomdns_forward_*` and
`atomdns_metrics_collector_*` families (`config_rust` uses neither plugin); the `go_*` runtime series.
They are not emitted as zeros.

**`/debug/pprof` — compatibility decision.** The native host does **not** serve the Go profiler
(`/debug/pprof/*`, `cmdline`, `profile`, `symbol`, `trace`): the paths answer `404`. The endpoint is
the Go runtime's profile format (feature-coverage C16, class "implementation detail"), no WebUI or
`config_all` path uses it, and there is no equivalent in a Rust binary. Replacements: the log capture
above, `/metrics`, and `perf` on the host (`perf record -e cpu-clock -F 999 --call-graph dwarf -p
<pid>`, as used for the 5D-2c profile).

## Capability discovery and UI

> atom (step 6b): this section and the two after it describe the retired AtomDNS WebUI
> (`webui-log/`, deleted) and its management interfaces (removed in step 6a). They are kept as
> history. The atom WebUI is `webui/`, built against `docs/api/openapi.yaml`.

Schema1 retains its existing keys and adds `ui_operations`: 30 IDs (the
[approved matrix](../plans/native-webui-runtime-capabilities.md) with `switches.manage`
replaced by `flags.manage` in M2-1 and `appearance.server` removed in the UI redo), each with
boolean `supported` and true→null / false→displayable-string `reason`. The WebUI
requires the complete matrix. Eligibility
comes from actual handlers/providers: a group profile alone does not
make local-rule writes available. Existing per-item format/read-only contracts
remain authoritative. Missing Go-only APIs do not gain fake success handlers.

Named `ip_set` show/post also participate in local-rule management: an eligible
single exclusive `.txt` source makes the existing `rules.local.manage` operation
available. Other IP shapes remain readable and POST returns 400 with the reason;
there is no ip_set save/flush route. See [response/IP policy](native-response-policy.md#named-ip_set-management-2026-10-22).

The Vue UI has pending/ready/error discovery, completing discovery before
optional requests. Since the UI redo (2026-10-23) it has no Go or old-native fallback:
any failed discovery (including 404), an invalid schema or a missing/incomplete
`ui_operations` shows a retryable error and blocks optional writes/requests. Retries
discard failed promises. Catalog-changing successful mutations refresh capabilities; a later
failed refresh keeps the actual mutation ACK factual and existing drafts visible.

Initial reads, all modes/tabs, refresh paths and handlers use the same operation
admission. Unsupported operations remain visibly disabled with family reasons.
The former `/plugins/switch*/show|post` controls and `switches.manage` were removed
in configuration schema 3 (M2-1); the UI redo part 1 removed the old switch pages, and part 2
renders [feature flags](native-feature-flags.md) (`flags.manage`) in the rule sub-items.
`/plugins/route_learner/status|entries` are gated by `lists.remembered`.
`rules.adguard` is supported when an `adguard_rule` tagged `adguard` exists, and
`rules.diversion` also when any `sd_set_light`/`si_set` exists; the diversion tab then
probes the built-in provider tags (`/plugins/{tag}/config`, 404 = not configured) and
uses the reference online-source workflow for the found ones. A special group's `special_route_N`
catalog is the same kind of online source (`sd_set_light`: URL and local file are both required) and is managed
as the group's subscriptions (see native-rule-providers.md).
Native identity displays the product version, without fabricated Go metrics. Audit/details, named-cache catalog/list/flush,
eligible local rules and native managed group/upstream workflows remain available.
The value-free `switches` capability extension (switch inventory) was removed with
the switches; flags are listed by `GET /api/v1/flags`.

## WebUI structure (UI redo part 1, 2026-10-23)

The WebUI is a sidebar layout with four modules; on narrow screens (≤ 760 px) the sidebar becomes
horizontally scrolling tab rows. Since v0.4.0 the eight 规则设置 sub-items are **collapsed by default**:
clicking 规则设置 only opens or closes the list (a button with `aria-expanded`, no navigation), a
sub-item opens its page, and arriving on any `#/rules/…` page opens the list with the current item
highlighted; on narrow screens the 规则设置 tab toggles the second row the same way.
Routes use `vue-router` hash history, so a reload keeps the page and unknown addresses return to
`#/overview`:

The 域名统计 card shows the exact unique question-name count within current
retained audit coverage, from `X-Audit-Distinct-Domains` on the domain rank
response. It is not the number of returned top rows and never clips at500.
The UI requests only20 display rows. A/AAAA, repeats, ASCII-case variants and
trailing dots do not inflate the count. Missing/invalid count metadata (including
an older backend) displays `--`; raw ranking labels and other card scopes remain
unchanged. Client-count rank truncation is not changed by this increment.

| Module | Addresses |
| --- | --- |
| 概览 | `#/overview` — figures from the retained audit records (their coverage is taken from `/api/v2/audit/stats/windows`; the per-window table was dropped in the part-1 rework), cache hit (summed `atomdns_cache_hit_total` / `atomdns_cache_query_total` of the named caches), CPU (one-core % between two `process_cpu_seconds_total` samples), memory (RSS), upstream (groups not in use under the current switches left out), routing, top domains/clients, slowest queries, learning summary (`/plugins/route_learner/status`) |
| 日志 | `#/logs` — live query (the client-alias button links to `#/rules/clients`); `#/logs/diagnostic` — diagnostic capture as its own page, reached from a button on the live page, with a way back |
| 规则设置 | `#/rules/{mode,upstream,routing,blocking,learning,cache,clients,special-groups}` — eight sub-items (part 2, below); `#/rules/rewrite` redirects to `#/rules/routing` |
| 系统管理 | `#/system` — one page of setting rows in five sections: version and update (with system info and configuration-package state), backup (export only), audit switch and capacity, theme and auto refresh, WebUI port / restart / reset statistics; the former `#/system/<section>` addresses redirect here |

### 规则设置 sub-items (UI redo part 2, 2026-10-24)

Every sub-item is switches → lists/subscriptions → actions. The switches of a sub-item are the flags whose declared `section` maps to it
(`mode`→运行模式, `upstream`→上游设置, `routing`/`rewrite`→分流规则, `blocking`→请求屏蔽, `learning`→域名学习, `cache`→缓存设置, `client`→客户端, `special_groups`→专属分流组),
in declaration order; a click is applied at once (`POST /api/v1/flags/{key}`), the other switches of the page wait meanwhile, a 409 re-reads the flags and asks for a retry, a 503
shows its reason, and a modified flag shows "已修改" with a restore-default (`DELETE`). Switching a flag that declares `requery_on_change` shows that the cache refresh was started
(`requery_triggered`).

| Sub-item | Content |
| --- | --- |
| 运行模式 | `mode` flags; the `realiplist` and `cnfakeipfilter` lists |
| 上游设置 | `upstream` flags; the upstream list by group (identifier, protocol, address, enabled, latency; other parameters in the edit dialog; restore default per group); groups whose `show_when` does not hold (`GET /api/v1/upstream/groups`, [native-settings](native-settings.md)) hidden unless "显示未生效的组" is on (then marked 当前未生效); disabling or deleting a group's last enabled upstream is refused before any request with the reason (and the switch to turn off instead); SOCKS5/ECS overrides; the special groups' upstreams read-only with a link. Since v0.4.0 `config_rust` declares no `upstream` flag (`ddns_foreign` is in 运行模式) |
| 分流规则 | `routing` flags; lists `whitelist`, `greylist`, `direct_ip`, `rewrite`, then `ddnslist` (DDNS 域名, with a link to 运行模式 for the DDNS priority flag); the five online sets (`geosite_cn`, `geosite_no_cn`, `geoip_cn`, `cuscn`, `cusnocn`); the special groups' lists read-only with links |
| 请求屏蔽 | `blocking` flags; `blocklist`; AdGuard subscriptions |
| 域名学习 | `learning` flags; the domain-generation switches (`/api/v1/domain-generation`); learned categories (counts, clearing one whole category) and entries (`/plugins/route_learner/entries`: category filter, search, sort, paging; no single-entry delete); requery state, run/cancel and timer |
| 缓存设置 | `cache` flags; cache statistics, per-cache and all clearing, cache entry viewer |
| 客户端 | `client` flags; the `client_ip` list; client aliases (`/plugins/clientname`: edit, add, import/export) |
| 专属分流组 | `special_groups` flags; the group list; one group in one place (`?group=<slot>` or `?group=new`): name and port, upstreams (own or referenced), its manual list, its subscriptions, delete |

All manual lists use one editor: line count, search that only filters the display, save through `/plugins/<tag>/post` with the server's error shown as it is, a re-read after
saving (a rule the server skipped is reported), and a guard against cut-off lists: `show` is asked for 20,001 lines, and a list that reaches that is shown read-only with a notice and cannot be
saved from the page. Leaving a page (or sub-item) with unsaved edits asks first (the router guard; the browser also asks before the tab closes). The fixed lists are always shown
(no longer hidden when `special_groups.enabled`). The online subscription table is shared by the five sets, AdGuard and a special group's subscriptions.

Theme: light / dark / follow the system (default), kept in the browser (`atomdns-theme`); every
browser key uses the `atomdns-` prefix and older `atomdns*` keys are not read. Value colours
(latency ≤ 50 ms green, ≤ 200 ms yellow, above red; cache hit ≥ 90 % green, ≥ 70 % yellow; CPU
> 50 % yellow, > 90 % red; memory > 128 MiB yellow, > 256 MiB red) are display only and defined
once in `webui-log/src/utils/overviewMetrics.js`.

## Build and evidence

`scripts/build-rust-native.sh` builds the program alone (locked Cargo release in a
source-hash-keyed Cargo directory, preventing restored older mtimes from reusing a stale
executable); it runs no frontend build. `BUILD_VERSION` overrides repository
`git describe --dirty` (fallback dev). `OUTPUT` defaults to `release/atomdns-native`. Its adjacent
`.manifest.json` records the source hashes (`rust/` and the two build scripts), compiler,
artifact SHA-256 and CLI version. Source ID is null unless `BUILD_SOURCE_ID` is explicitly
supplied; dirty code is not represented as clean HEAD. The WebUI is built separately
(`npm run build` / `npm run build:package` in `webui/`, above); Node is a build-time tool
only. Earlier evidence: [task evidence](../validation-records/10-04-rust-native-webui-runtime-capabilities/s6-status.md);
v0.4.0: [10-24-v0.4.0-ui-split](../validation-records/10-24-v0.4.0-ui-split/README.md).
