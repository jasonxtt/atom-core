# AGENTS.md

Start here.

Read these files for normal work:

1. `AGENTS.md`
2. `docs/ai/project-context.md`
3. `docs/ai/config-notes.md`

Read on demand (historical migration records, long; the 2026-10 Phase 1–5 narrative is not needed for ordinary work):

4. `docs/rust/contracts/index.md` when touching frozen product behavior
5. `docs/ai/rust-handover.md` / `docs/ai/rust-rewrite-plan.md` only for migration history or architecture questions
6. `.trellis/workflow.md` and the task's `prd.md` / `design.md` / `implement.md` when a local Trellis task is active; review rules are in `.trellis/spec/backend/quality-guidelines.md` ("Review loop")

This repository is `jasonxtt/atomdns` (local clone `/Users/tom/github/atomdns`,
default branch `main`). It is the Rust rewrite of MosDNS, named AtomDNS since
2026-10-30 (program/crate/package name `atomdns`; before that `rtdns`, and before
2026-10-21 the `rust` branch of `jasonxtt/mosdns`, itself a maintained fork of
`yyysuo/mosdns`). Commit IDs cited in older records are unchanged by the renames.
The old `/Users/tom/github/mosdns-rust` worktree is no longer used for new work.

## Scope and stable facts

- **This is a pure Rust project** (Phase 6a, 2026-10-18): it has no Go source, no `go.mod`, no cgo bridge (`rust/runtime`, `ATOMDNS_*_BACKEND`) and needs no Go toolchain to build. The Go MosDNS lives in `/Users/tom/github/mosdns` (`jasonxtt/mosdns`); the Go-side comparison tools and the reference binary are built from a pinned commit of that repository with `tools/go-reference/build.sh` (see `tools/go-reference/README.md`). Paths like `coremain/*.go` in Rust comments, contracts and validation records name files of that Go repository.
- The final Rust migration target is a pure Rust-native MosDNS-compatible binary/runtime; the Rust-native host still has to pass its final cutover gate before it replaces the production Go program.
- `/` is the maintained Vue UI. Since v0.4.0 the program embeds no UI: the WebUI is `<config root>/ui/main/` (served at `/`; built from `webui/` by `npm run build` / `npm run build:package`, archive `atom-webui.tar.gz`); any other `<config root>/ui/<name>/` is served at `/<name>/` (see `docs/rust/external-ui.md`). Without `ui/main` the host is a pure backend. It has no `/log` (that compatibility UI exists only in the Go repository). atom (step 6b): `webui/` is the atom WebUI (Vue 3 + Vite + TypeScript) built against `docs/api/openapi.yaml` (`npm run gen:api`); the former `webui-log/` was deleted.
- The canonical backend feature name is `special_groups`; do not reintroduce `route_group`.
- Do not import the upstream `nft` / `eBPF` direction. The detailed cutoff and decisions are in `UPSTREAM_SYNC.md`.

## Working rules

- Use `rg` for normal code, config, YAML, documentation, and UI-copy searches. Verify cross-module assumptions against current source.
- Product contracts and public validation summaries live in `docs/rust/contracts/` and `docs/rust/validation-summary.md`. Optional Trellis/AI tooling (`.trellis/`, `.agents/`, `.codex/`) is local-only and is not required to build a fresh clone. When a local Trellis task is active, use its `prd.md`, `design.md`, and `implement.md` as implementation gates. Keep Trellis auto-commit disabled and preserve unrelated dirty-worktree changes.
- Preserve the MosDNS product contract: YAML/config and sequence/plugin semantics, final DNS/routing/audit behavior, WebUI/API workflows, metrics/persistent formats, and other explicitly frozen user-visible behavior. Current Go code is a discovery reference, not the normative Rust implementation. Do not reproduce Go internals or accidental quirks unless they are explicitly classified as product contract.
- The Phase 1/2/3A hybrid scaffolding (cgo adapters, `ATOMDNS_*_BACKEND` selectors, Go mirrors/fallback, paired generations) was removed with the Go source in Phase 6a; do not reintroduce it. Historical documents about it (`cache-compatibility.md`, `matcher-compatibility.md`, `test-host-*.md`, validation records) stay as evidence.
- Treat WebUI changes as configuration workflow changes, not just frontend styling.
- Treat overview-card and narrow mobile-table CSS as behavior-sensitive. Avoid reintroducing the combination of `table-layout: fixed`, `calc(...)` column widths, and broad `overflow-wrap: anywhere` rules.
- Do not store passwords, tokens, or private credentials in repository docs.

## Build and validation

- Build the program with `scripts/build-rust-native.sh` (Rust only) and the WebUI with `npm run build` / `npm run build:package` in `webui`; release artifacts (program, WebUI, manifest): `scripts/build-rust-release.sh`.
- Production runs this program as `atomdns` since 2026-10-21 (manual cutover; the Go `atomdns` service stays installed for rollback). Do not publish a GitHub Release or deploy without explicit user approval.
- Naming (2026-10-22): the cargo bin is `atomdns`; releases and online updates come only from `jasonxtt/atomdns`, tags `vX.Y.Z`, assets `atomdns-linux-amd64.tar.gz` (file `atomdns`) and `atomdns-update-manifest.json`. Crate names (`atomdns-*`), `ATOMDNS_*` environment variables, metrics/API field names and the configuration package identifiers (`channel "rust"`, `rust-config-schema-N`, `config_rust_up.zip`) keep their old names. Release and manual-replacement steps: `docs/rust/release.md`.
- Config compatibility and switch-bit reservations are documented in `docs/ai/config-notes.md`; do not change them casually.
- When real deployment verification is requested, build locally, validate on `mos-test`, and promote to `atomdns` only after confirmation. Prefer the SSH aliases in `~/.ssh/config`.

## When you need deeper context

- Project shape and runtime behavior: `docs/ai/project-context.md`
- Config generation, package boundaries, and switch bits: `docs/ai/config-notes.md`
- Rust migration state and worktree ownership: `docs/ai/rust-handover.md`
- Rust architecture and phase gates: `docs/ai/rust-rewrite-plan.md`
- Upstream sync baseline and exclusions: `UPSTREAM_SYNC.md`
