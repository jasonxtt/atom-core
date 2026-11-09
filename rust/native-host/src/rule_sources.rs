//! Native rule-source management (M1-a2): the online sources of
//! `sd_set_light`, `si_set` and `adguard_rule`, the local list of
//! `domain_set_light`, and the hot rebuild of the `domain_mapper`s and direct
//! matchers that consume them.
//!
//! One `RuleSources` belongs to each compiled configuration. It keeps every
//! provider's manifest in memory (as the reference providers do), serializes
//! each provider's file and manifest writes, downloads with a bounded HTTP
//! client, and republishes query-side state as whole generations built on the
//! blocking pool. Background work runs as tracked jobs that shutdown cancels
//! and joins. Behavior follows the reference handlers; deliberate differences
//! are listed in `docs/rust/contracts/native-rule-providers.md`.

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use atomdns_matcher_core::{
    IpPrefixList, ValuedDomainMatcher, decode_domain_srs, decode_domain_srs_plain, decode_ip_srs,
};
use atomdns_upstream_core::TransportCancellation;
use serde::Serialize;

use crate::config::providers::{
    self, Counts, Filtered, LightSpec, ManifestSpec, MapperSpec, RuleEntry, Schema, SourceEntry,
};
use crate::managed::PersistGate;
use crate::policy::IpListHandle;
use crate::rule_binary::{self, Want};
use crate::rule_formats::{self, Format, Parsed, Skipped};

/// A value read whole at each use and replaced whole on publication. A reader
/// holding the previous `Rc` keeps using that generation until it drops it.
pub(crate) struct Live<T>(RefCell<Rc<T>>);

impl<T> Live<T> {
    pub(crate) fn new(value: T) -> Self {
        Self(RefCell::new(Rc::new(value)))
    }

    pub(crate) fn get(&self) -> Rc<T> {
        Rc::clone(&self.0.borrow())
    }

    /// Publishes `value` and returns the replaced generation.
    pub(crate) fn replace(&self, value: Rc<T>) -> Rc<T> {
        std::mem::replace(&mut *self.0.borrow_mut(), value)
    }
}

/// Download and scheduler timings. The defaults are the reference values;
/// tests shorten them.
#[derive(Clone, Debug)]
pub struct RuleTiming {
    /// Delay before the first auto-update check after the host starts.
    pub first_check: Duration,
    /// `sd_set_light`/`si_set` check period.
    pub source_period: Duration,
    /// `adguard_rule` check period.
    pub adguard_period: Duration,
    /// Overall download deadline for `sd_set_light`/`si_set`.
    pub source_timeout: Duration,
    /// Overall download deadline for `adguard_rule`.
    pub adguard_timeout: Duration,
    /// Largest accepted download body.
    pub max_download_bytes: usize,
}

impl Default for RuleTiming {
    fn default() -> Self {
        Self {
            first_check: Duration::from_secs(60),
            source_period: Duration::from_secs(600),
            adguard_period: Duration::from_secs(60),
            source_timeout: Duration::from_secs(60),
            adguard_timeout: Duration::from_secs(30),
            max_download_bytes: 64 * 1024 * 1024,
        }
    }
}

/// The reference zero `time.Time`, as Go prints it.
const ZERO_TIME: &str = "0001-01-01T00:00:00Z";
/// Seconds of the zero time relative to the Unix epoch.
const ZERO_UNIX: i64 = -62_135_596_800;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Light,
    Sd,
    Si,
    Adguard,
}

/// One rebuild target's state: a request while `Running` marks it `Dirty`
/// and the running job builds once more with fresh inputs.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Build {
    Idle,
    Running,
    Dirty,
}

struct ManifestOwner {
    spec: ManifestSpec,
    sources: RefCell<Vec<SourceEntry>>,
    unreadable: bool,
    /// Counts read at compile time, reconciled into the manifest at start.
    loaded_counts: RefCell<Counts>,
    /// Single flight per source key: `true` asks the running download to run
    /// once more when it finishes.
    flights: RefCell<std::collections::BTreeMap<String, bool>>,
}

/// One rule provider and its management state.
pub(crate) struct Provider {
    pub(crate) tag: String,
    pub(crate) kind: Kind,
    light: Option<LightSpec>,
    manifest: Option<ManifestOwner>,
    /// Serializes every manifest and rule-file write of this provider. The
    /// lock is shared by every generation that owns the same file (see
    /// `write_lock`), so a retired owner can never interleave with its successor.
    mutate: Arc<tokio::sync::Mutex<()>>,
    ip: Option<Rc<IpListHandle>>,
    filtered: RefCell<Option<Rc<Live<Filtered>>>>,
    reload: Cell<Build>,
    /// Why the latest reload kept the previous rules (`None`: it succeeded).
    failure: RefCell<Option<String>>,
}

impl Provider {
    pub(crate) fn light(spec: LightSpec) -> Self {
        let lock = write_lock(spec.writable_file().map_or_else(
            || PathBuf::from(format!("light:{}", spec.tag)),
            Path::to_path_buf,
        ));
        Self::new(spec.tag.clone(), Kind::Light, Some(spec), None, None, lock)
    }

    pub(crate) fn manifest(
        spec: ManifestSpec,
        manifest: providers::Manifest,
        counts: Counts,
        ip: Option<Rc<IpListHandle>>,
    ) -> Self {
        let kind = match spec.schema {
            Schema::Sd => Kind::Sd,
            Schema::Si => Kind::Si,
            Schema::Adguard => Kind::Adguard,
        };
        let owner = ManifestOwner {
            spec: spec.clone(),
            sources: RefCell::new(manifest.entries),
            unreadable: manifest.unreadable,
            loaded_counts: RefCell::new(counts),
            flights: RefCell::new(std::collections::BTreeMap::new()),
        };
        let lock = write_lock(spec.manifest.clone());
        Self::new(spec.tag, kind, None, Some(owner), ip, lock)
    }

    fn new(
        tag: String,
        kind: Kind,
        light: Option<LightSpec>,
        manifest: Option<ManifestOwner>,
        ip: Option<Rc<IpListHandle>>,
        mutate: Arc<tokio::sync::Mutex<()>>,
    ) -> Self {
        Self {
            tag,
            kind,
            light,
            manifest,
            mutate,
            ip,
            filtered: RefCell::new(None),
            reload: Cell::new(Build::Idle),
            failure: RefCell::new(None),
        }
    }

    pub(crate) fn attach_filtered(&self, live: Rc<Live<Filtered>>) {
        *self.filtered.borrow_mut() = Some(live);
    }

    fn owner(&self) -> &ManifestOwner {
        self.manifest.as_ref().expect("manifest provider")
    }

    fn key(&self, entry: &SourceEntry) -> String {
        if self.kind == Kind::Adguard {
            entry.id.clone()
        } else {
            entry.name.clone()
        }
    }

    fn find(&self, key: &str) -> Option<SourceEntry> {
        self.owner()
            .sources
            .borrow()
            .iter()
            .find(|entry| self.key(entry) == key)
            .cloned()
    }

    fn load_plan(&self) -> Plan {
        match (&self.light, &self.manifest) {
            (Some(spec), _) => Plan::Light(spec.clone()),
            (None, Some(owner)) => {
                Plan::Manifest(owner.spec.clone(), owner.sources.borrow().clone())
            }
            (None, None) => unreachable!("a provider is a list or a manifest"),
        }
    }
}

/// The `Send` inputs of one provider for a rebuild on the blocking pool.
enum Plan {
    Light(LightSpec),
    Manifest(ManifestSpec, Vec<SourceEntry>),
}

impl Plan {
    /// The rules a `domain_mapper` consumes from this provider.
    fn rules(&self) -> Result<providers::ProviderRules, String> {
        match self {
            Self::Light(spec) => providers::load_light(spec, None)
                .map(Rc::new)
                .map_err(|e| e.to_string()),
            Self::Manifest(spec, sources) => Ok(match spec.schema {
                Schema::Sd => Rc::new(providers::load_sd(spec, sources, None).0),
                Schema::Adguard => providers::load_adguard(spec, sources, false, None).0.deny,
                Schema::Si => Rc::new(Vec::new()),
            }),
        }
    }
}

/// One `domain_mapper` and the generation its executor reads.
pub(crate) struct MapperSlot {
    spec: MapperSpec,
    live: Rc<Live<ValuedDomainMatcher>>,
    build: Cell<Build>,
    /// Why the latest rebuild kept the previous matcher (`None`: it succeeded).
    failure: RefCell<Option<String>>,
}

impl MapperSlot {
    pub(crate) fn new(spec: MapperSpec, live: Rc<Live<ValuedDomainMatcher>>) -> Self {
        Self {
            spec,
            live,
            build: Cell::new(Build::Idle),
            failure: RefCell::new(None),
        }
    }
}

struct Inner {
    providers: Vec<Rc<Provider>>,
    mappers: Vec<Rc<MapperSlot>>,
    build_gate: RefCell<Option<PersistGate>>,
    builds: AtomicUsize,
}

#[derive(Clone, Default)]
struct Env {
    roots: Option<Arc<rustls::RootCertStore>>,
    timing: RuleTiming,
}

/// What one background job needs.
#[derive(Clone)]
struct Ctx {
    inner: Rc<Inner>,
    cancel: TransportCancellation,
    env: Env,
}

/// The management state of every rule provider of one compiled configuration.
pub struct RuleSources {
    inner: Rc<Inner>,
    env: RefCell<Env>,
    jobs: RefCell<tokio::task::JoinSet<()>>,
    cancel: TransportCancellation,
    closed: Cell<bool>,
}

impl Default for RuleSources {
    fn default() -> Self {
        Self::new(Vec::new(), Vec::new())
    }
}

/// An HTTP reply for the management API.
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) content_type: Option<&'static str>,
    pub(crate) body: Vec<u8>,
    /// Headers beyond `Content-Type` and `Content-Length`.
    pub(crate) headers: Vec<(&'static str, String)>,
}

const JSON_UTF8: &str = "application/json; charset=utf-8";

impl Reply {
    fn json<T: Serialize>(status: u16, content_type: &'static str, value: &T) -> Self {
        let mut body = serde_json::to_vec(value).expect("small API response serializes");
        body.push(b'\n');
        Self {
            status,
            content_type: Some(content_type),
            body,
            headers: Vec::new(),
        }
    }

    fn json_error(status: u16, message: &str) -> Self {
        Self::json(status, JSON_UTF8, &serde_json::json!({ "error": message }))
    }
}

impl RuleSources {
    pub(crate) fn new(providers: Vec<Rc<Provider>>, mappers: Vec<Rc<MapperSlot>>) -> Self {
        Self {
            inner: Rc::new(Inner {
                providers,
                mappers,
                build_gate: RefCell::new(None),
                builds: AtomicUsize::new(0),
            }),
            env: RefCell::new(Env::default()),
            jobs: RefCell::new(tokio::task::JoinSet::new()),
            cancel: TransportCancellation::new(),
            closed: Cell::new(false),
        }
    }

    /// Applies the host's trust roots and timings.
    pub(crate) fn configure(&self, roots: Option<Arc<rustls::RootCertStore>>, timing: RuleTiming) {
        *self.env.borrow_mut() = Env { roots, timing };
    }

    pub(crate) fn timing(&self) -> RuleTiming {
        self.env.borrow().timing.clone()
    }

    pub(crate) fn roots(&self) -> Option<Arc<rustls::RootCertStore>> {
        self.env.borrow().roots.clone()
    }

    pub(crate) fn provider(&self, tag: &str) -> Option<Rc<Provider>> {
        self.inner
            .providers
            .iter()
            .find(|provider| provider.tag == tag)
            .cloned()
    }

    fn ctx(&self) -> Ctx {
        Ctx {
            inner: Rc::clone(&self.inner),
            cancel: self.cancel.clone(),
            env: self.env.borrow().clone(),
        }
    }

    fn spawn(&self, job: impl std::future::Future<Output = ()> + 'static) {
        if self.closed.get() {
            return;
        }
        let mut jobs = self.jobs.borrow_mut();
        while jobs.try_join_next().is_some() {}
        jobs.spawn_local(job);
    }

    /// Stops this generation from starting new jobs or writes, at once. Called
    /// when a newer view is installed, before it admits any request; `close`
    /// later joins what is still running.
    pub(crate) fn fence(&self) {
        self.closed.set(true);
        self.cancel.cancel();
    }

    /// Cancels every background job (in-flight downloads stop at once) and
    /// joins them; a build already running on the blocking pool is awaited.
    pub(crate) async fn close(&self) {
        self.closed.set(true);
        self.cancel.cancel();
        let mut jobs = std::mem::take(&mut *self.jobs.borrow_mut());
        while jobs.join_next().await.is_some() {}
    }

    /// Start-up work the reference does while loading: rewrite stale rule
    /// counts, and download enabled AdGuard lists that are not on disk yet.
    pub(crate) fn start(&self) {
        let providers: Vec<_> = self
            .inner
            .providers
            .iter()
            .filter(|provider| provider.manifest.is_some())
            .cloned()
            .collect();
        if providers.is_empty() {
            return;
        }
        let ctx = self.ctx();
        self.spawn(async move {
            for provider in providers {
                let counts = std::mem::take(&mut *provider.owner().loaded_counts.borrow_mut());
                apply_counts(&ctx, &provider, counts).await;
                if provider.kind != Kind::Adguard {
                    continue;
                }
                let owner = provider.owner();
                let candidates: Vec<(String, PathBuf)> = owner
                    .sources
                    .borrow()
                    .iter()
                    .filter(|entry| entry.enabled)
                    .map(|entry| (entry.id.clone(), owner.spec.source_file(entry)))
                    .collect();
                let mut missing = Vec::new();
                for (id, file) in candidates {
                    let exists = tokio::task::spawn_blocking(move || file.exists())
                        .await
                        .unwrap_or(true);
                    if !exists {
                        missing.push(id);
                    }
                }
                if !missing.is_empty() && download_many(&ctx, &provider, missing).await {
                    changed(&ctx, &provider).await;
                }
            }
        });
    }

    /// Runs the reference auto-update predicate for the providers of `kinds`
    /// at `now` (Unix seconds) and downloads every due source.
    pub(crate) fn auto_update(&self, kinds: &[Kind], now: i64) {
        for provider in &self.inner.providers {
            if !kinds.contains(&provider.kind) || provider.manifest.is_none() {
                continue;
            }
            let due: Vec<String> = provider
                .owner()
                .sources
                .borrow()
                .iter()
                .filter(|entry| is_due(entry, now))
                .map(|entry| provider.key(entry))
                .collect();
            if due.is_empty() {
                continue;
            }
            let ctx = self.ctx();
            let provider = Rc::clone(provider);
            self.spawn(async move {
                if download_many(&ctx, &provider, due).await {
                    changed(&ctx, &provider).await;
                }
            });
        }
    }

    /// Arms a test-only gate that parks every rebuild on the blocking pool.
    #[doc(hidden)]
    pub fn inject_build_gate(&self, gate: PersistGate) {
        *self.inner.build_gate.borrow_mut() = Some(gate);
    }

    /// The number of mapper/provider builds completed so far (tests).
    #[doc(hidden)]
    #[must_use]
    pub fn completed_builds(&self) -> usize {
        self.inner.builds.load(Ordering::SeqCst)
    }

    /// Waits until no background job is left (tests).
    #[doc(hidden)]
    pub async fn settle(&self) {
        loop {
            {
                let mut jobs = self.jobs.borrow_mut();
                while jobs.try_join_next().is_some() {}
                if jobs.is_empty() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // ----- domain_set_light (atom `ddns`) -----------------------------------

    /// Every rule of a `domain_set_light` provider, as its files give them.
    pub(crate) async fn light_rules(&self, provider: &Provider) -> Result<Vec<String>, String> {
        let spec = provider.light.clone().ok_or("not a domain_set_light")?;
        match on_build_thread(move || providers::load_light(&spec, None)).await {
            Ok(Ok(rules)) => Ok(rules.into_iter().map(|entry| entry.rule).collect()),
            Ok(Err(error)) => Err(error.to_string()),
            Err(error) => Err(error.to_string()),
        }
    }

    /// Replaces the rules of a `domain_set_light` provider: the values are
    /// normalized like file lines, written to its file, and the matchers are
    /// rebuilt before this returns. The error is `(HTTP status, reason)`.
    pub(crate) async fn light_replace(
        &self,
        provider: &Rc<Provider>,
        values: Vec<String>,
    ) -> Result<Vec<String>, (u16, String)> {
        if self.closed.get() {
            return Err((503, "host is applying configuration".to_owned()));
        }
        let spec = provider
            .light
            .clone()
            .ok_or((500, "not a domain_set_light".to_owned()))?;
        // Other files or inline `exps` would keep their rules (codex review
        // of step 6a, round 3).
        if !spec.single_file() {
            return Err((
                409,
                format!(
                    "{} 的规则不只来自一个 .txt 文件（还有别的文件或内联条目），不能整份替换",
                    provider.tag
                ),
            ));
        }
        let file = spec
            .writable_file()
            .map(Path::to_path_buf)
            .ok_or((500, "no txt file configured".to_owned()))?;
        let values: Vec<String> = values
            .into_iter()
            .filter(|value| !value.contains('\n') && !value.contains('\r'))
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty() && !value.starts_with('#'))
            .collect();
        // The loader refuses a whole file for one overlong line.
        if let Some(long) = values
            .iter()
            .find(|value| value.len() >= providers::MAX_LINE_BYTES)
        {
            return Err((
                400,
                format!(
                    "条目太长（{} 字节，上限 {} 字节）",
                    long.len(),
                    providers::MAX_LINE_BYTES - 1
                ),
            ));
        }
        if let Some(reason) = values
            .iter()
            .find_map(|rule| providers::rule_refusal(&provider.tag, rule))
        {
            return Err((400, reason));
        }
        let guard = provider.mutate.lock().await;
        let bytes = rule_lines(values.iter().map(String::as_str));
        match tokio::task::spawn_blocking(move || write_atomically(&file, &bytes)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err((500, error.to_string())),
            Err(error) => return Err((500, error.to_string())),
        }
        drop(guard);
        changed_and_settled(&self.ctx(), provider)
            .await
            .map_err(|error| {
                (
                    500,
                    format!("名单已写入文件，但没有生效（重建失败，仍在用旧规则）: {error}"),
                )
            })?;
        Ok(values)
    }

    // ----- sd_set_light / si_set / adguard_rule (atom builtin `refresh`) ----

    /// Downloads every enabled source of a rule provider again and rebuilds
    /// its matchers before this returns. `(sources, updated)`: how many
    /// sources were downloaded and how many of them replaced their file (a
    /// failed download keeps the old file and is logged).
    /// The error is `(HTTP status, reason)`.
    pub(crate) async fn refresh(
        &self,
        provider: &Rc<Provider>,
    ) -> Result<(usize, usize), (u16, String)> {
        if self.closed.get() {
            return Err((503, "host is applying configuration".to_owned()));
        }
        if provider.manifest.is_none() {
            return Err((400, "this set has no downloadable sources".to_owned()));
        }
        let keys: Vec<String> = {
            let sources = provider.owner().sources.borrow();
            sources
                .iter()
                .filter(|entry| entry.enabled)
                .map(|entry| provider.key(entry))
                .collect()
        };
        let ctx = self.ctx();
        let mut updated = 0;
        for key in &keys {
            // A download of this source already running (startup, or another
            // refresh) would make ours return at once without its outcome:
            // wait for it, then download once more.
            while provider.owner().flights.borrow().contains_key(key) {
                if ctx.cancel.is_cancelled() {
                    return Err((503, "host is stopping".to_owned()));
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if download_source(&ctx, provider, key.clone()).await {
                updated += 1;
            }
        }
        if updated > 0 {
            changed_and_settled(&ctx, provider)
                .await
                .map_err(|error| (500, format!("下载成功，但重建失败，仍在用旧规则: {error}")))?;
        }
        Ok((keys.len(), updated))
    }
}

// ----- JSON views ------------------------------------------------------------

#[derive(Serialize)]
struct SourceView<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    files: &'a str,
    url: &'a str,
    #[serde(skip_serializing_if = "Format::is_auto")]
    format: Format,
    #[serde(skip_serializing_if = "str::is_empty")]
    category: &'a str,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    enable_regexp: Option<bool>,
    auto_update: bool,
    update_interval_hours: i64,
    rule_count: i64,
    last_updated: &'a str,
}

fn source_view(entry: &SourceEntry, kind: Kind) -> SourceView<'_> {
    SourceView {
        name: &entry.name,
        kind: &entry.kind,
        files: &entry.files,
        url: &entry.url,
        format: entry.format,
        category: &entry.category,
        enabled: entry.enabled,
        // `omitempty` in `sd_set_light`; `si_set` has no such field.
        enable_regexp: (kind == Kind::Sd && entry.enable_regexp).then_some(true),
        auto_update: entry.auto_update,
        update_interval_hours: entry.update_interval_hours,
        rule_count: entry.rule_count,
        last_updated: entry.last_updated.as_deref().unwrap_or(ZERO_TIME),
    }
}

#[derive(Serialize)]
struct RuleView<'a> {
    id: &'a str,
    name: &'a str,
    url: &'a str,
    #[serde(skip_serializing_if = "Format::is_auto")]
    format: Format,
    #[serde(skip_serializing_if = "str::is_empty")]
    category: &'a str,
    enabled: bool,
    auto_update: bool,
    update_interval_hours: i64,
    rule_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_updated: Option<&'a str>,
}

/// The reference `MarshalJSON` omits a zero `last_updated`.
fn rule_view(entry: &SourceEntry, print_zero: bool) -> RuleView<'_> {
    let last_updated = match entry.last_updated.as_deref() {
        Some(text) if unix_seconds(text) != Some(ZERO_UNIX) => Some(text),
        _ if print_zero => Some(ZERO_TIME),
        _ => None,
    };
    RuleView {
        id: &entry.id,
        name: &entry.name,
        url: &entry.url,
        format: entry.format,
        category: &entry.category,
        enabled: entry.enabled,
        auto_update: entry.auto_update,
        update_interval_hours: entry.update_interval_hours,
        rule_count: entry.rule_count,
        last_updated,
    }
}

/// The manifest bytes the reference writes: indented, sorted by name
/// (`sd_set_light`/`si_set`) or id (`adguard_rule`).
fn manifest_bytes(kind: Kind, sources: &mut [SourceEntry]) -> Vec<u8> {
    let bytes = if kind == Kind::Adguard {
        sources.sort_by(|a, b| a.id.cmp(&b.id));
        let views: Vec<_> = sources.iter().map(|e| rule_view(e, false)).collect();
        serde_json::to_vec_pretty(&views)
    } else {
        sources.sort_by(|a, b| a.name.cmp(&b.name));
        let views: Vec<_> = sources.iter().map(|e| source_view(e, kind)).collect();
        serde_json::to_vec_pretty(&views)
    };
    bytes.expect("manifest serializes")
}

/// Writes `sources` as the manifest, then adopts them in memory. On failure
/// neither the file nor memory changes. The caller holds the provider mutex.
async fn save_manifest(
    provider: &Provider,
    mut sources: Vec<SourceEntry>,
    failure: &str,
) -> Result<(), Reply> {
    let owner = provider.owner();
    if owner.unreadable {
        crate::diag::error_line!(
            "{}: source manifest {} could not be read at start; refusing to overwrite it",
            provider.tag,
            owner.spec.manifest.display()
        );
        return Err(Reply::json_error(500, failure));
    }
    let bytes = manifest_bytes(provider.kind, &mut sources);
    let path = owner.spec.manifest.clone();
    match tokio::task::spawn_blocking(move || write_atomically(&path, &bytes)).await {
        Ok(Ok(())) => {
            *owner.sources.borrow_mut() = sources;
            Ok(())
        }
        Ok(Err(error)) => {
            crate::diag::error_line!("{}: failed to save config: {error}", provider.tag);
            Err(Reply::json_error(500, failure))
        }
        Err(error) => {
            crate::diag::error_line!("{}: failed to save config: {error}", provider.tag);
            Err(Reply::json_error(500, failure))
        }
    }
}

/// Updates the in-memory counts and saves the manifest when any changed; a
/// failed save is logged and the counts stay in memory (as the reference).
async fn apply_counts(ctx: &Ctx, provider: &Provider, counts: Counts) {
    if counts.is_empty() || provider.owner().unreadable {
        return;
    }
    let _guard = provider.mutate.lock().await;
    // A fenced (retired) generation never writes after its successor exists.
    if ctx.cancel.is_cancelled() {
        return;
    }
    let mut sources = provider.owner().sources.borrow().clone();
    let mut changed = false;
    for (key, count) in counts {
        if let Some(entry) = sources.iter_mut().find(|e| provider.key(e) == key)
            && entry.rule_count != count
        {
            entry.rule_count = count;
            changed = true;
        }
    }
    if changed && save_manifest(provider, sources.clone(), "").await.is_err() {
        *provider.owner().sources.borrow_mut() = sources;
    }
}

// ----- downloads -------------------------------------------------------------

/// Downloads every source in `keys` concurrently; true when at least one
/// download replaced its file.
async fn download_many(ctx: &Ctx, provider: &Rc<Provider>, keys: Vec<String>) -> bool {
    let mut tasks = tokio::task::JoinSet::new();
    for key in keys {
        let ctx = ctx.clone();
        let provider = Rc::clone(provider);
        tasks.spawn_local(async move { download_source(&ctx, &provider, key).await });
    }
    let mut any = false;
    while let Some(result) = tasks.join_next().await {
        any |= result.unwrap_or(false);
    }
    any
}

/// Removes a source's single-flight entry however the download ends.
struct Flight<'a> {
    provider: &'a Provider,
    key: String,
}

impl Drop for Flight<'_> {
    fn drop(&mut self) {
        self.provider.owner().flights.borrow_mut().remove(&self.key);
    }
}

/// One source's download with single flight: a request for a source that is
/// already downloading makes that download run once more and returns false.
async fn download_source(ctx: &Ctx, provider: &Provider, key: String) -> bool {
    {
        let mut flights = provider.owner().flights.borrow_mut();
        if let Some(again) = flights.get_mut(&key) {
            *again = true;
            return false;
        }
        flights.insert(key.clone(), false);
    }
    let _flight = Flight {
        provider,
        key: key.clone(),
    };
    let mut replaced = false;
    loop {
        if ctx.cancel.is_cancelled() {
            return replaced;
        }
        match attempt(ctx, provider, &key).await {
            Ok(()) => replaced = true,
            Err(error) => {
                crate::diag::error_line!("{}: failed to update '{key}': {error}", provider.tag);
            }
        }
        let again = provider
            .owner()
            .flights
            .borrow_mut()
            .get_mut(&key)
            .map(std::mem::take)
            .unwrap_or(false);
        if !again {
            return replaced;
        }
    }
}

async fn attempt(ctx: &Ctx, provider: &Provider, key: &str) -> Result<(), String> {
    let owner = provider.owner();
    let entry = provider
        .find(key)
        .ok_or_else(|| format!("source '{key}' not found"))?;
    if entry.url.is_empty() {
        return Err("no URL configured".to_owned());
    }
    if provider.kind != Kind::Adguard && entry.files.is_empty() {
        return Err("no local file path configured".to_owned());
    }
    let file = owner.spec.source_file(&entry);
    let timeout = if provider.kind == Kind::Adguard {
        ctx.env.timing.adguard_timeout
    } else {
        ctx.env.timing.source_timeout
    };
    let bytes = crate::rule_download::fetch(
        crate::rule_download::Fetch {
            url: &entry.url,
            socks5: &owner.spec.socks5,
            timeout,
            max_bytes: ctx.env.timing.max_download_bytes,
            roots: ctx.env.roots.clone(),
        },
        &ctx.cancel,
    )
    .await?;
    let _guard = provider.mutate.lock().await;
    if ctx.cancel.is_cancelled() {
        return Err("canceled by shutdown".to_owned());
    }
    // The source may have been removed or repointed while downloading.
    let current = provider
        .find(key)
        .ok_or_else(|| "source was removed during the download".to_owned())?;
    if current.url != entry.url || owner.spec.source_file(&current) != file {
        return Err("source changed during the download; result discarded".to_owned());
    }
    let (kind, tag, regexp) = (provider.kind, provider.tag.clone(), current.enable_regexp);
    let (format, url) = (current.format, current.url.clone());
    let category = current.category.clone();
    crate::diag::debug_line!("{tag}: '{key}' downloaded {} bytes", bytes.len());
    let count = on_build_thread(move || {
        let source = Download {
            format,
            category: &category,
            url: &url,
        };
        store_download(kind, &tag, &bytes, &file, regexp, &source)
    })
    .await
    .map_err(|error| error.to_string())??;
    let mut sources = owner.sources.borrow().clone();
    if let Some(entry) = sources.iter_mut().find(|e| provider.key(e) == key) {
        if let Some(count) = count {
            entry.rule_count = count;
        }
        entry.last_updated = Some(now_text());
    }
    if save_manifest(provider, sources.clone(), "").await.is_err() {
        // As the reference: the new metadata stays in memory.
        *owner.sources.borrow_mut() = sources;
    }
    crate::diag::info_line!("{}: updated '{key}'", provider.tag);
    Ok(())
}

/// How a download is read: the source's `format`, `category` and address.
struct Download<'a> {
    format: Format,
    category: &'a str,
    url: &'a str,
}

/// What a download turns into: the bytes to store (`None` stores the download
/// as it is), the reference rule count, and what was not used.
struct Stored {
    content: Option<Vec<u8>>,
    count: Option<i64>,
    usable: usize,
    skipped: Skipped,
}

/// Validates downloaded content, converts it when it is not in the format the
/// provider reads, and replaces the rule file. Returns the reference rule
/// count for `sd_set_light` and `si_set`.
fn store_download(
    kind: Kind,
    tag: &str,
    bytes: &[u8],
    file: &Path,
    enable_regexp: bool,
    source: &Download<'_>,
) -> Result<Option<i64>, String> {
    let format = rule_formats::resolve(source.format, bytes, source.url);
    let (category, url) = (source.category, source.url);
    let stored = match kind {
        Kind::Sd => stored_domains(tag, bytes, enable_regexp, format, category, url)?,
        Kind::Si => stored_ips(bytes, format, category, url)?,
        Kind::Adguard => stored_adguard(tag, bytes, format, category, url)?,
        Kind::Light => return Err("not a downloadable provider".to_owned()),
    };
    let content = stored.content.as_deref().unwrap_or(bytes);
    write_atomically(file, content)
        .map_err(|error| format!("write {}: {error}", file.display()))?;
    let skipped = if stored.skipped.total() > 0 {
        format!(" ({})", stored.skipped.summary())
    } else {
        String::new()
    };
    crate::diag::info_line!(
        "{tag}: stored a {} download: {} usable rules, {} skipped{skipped}",
        format.as_str(),
        stored.usable,
        stored.skipped.total()
    );
    Ok(stored.count)
}

/// Reads a download that is not SRS: text, YAML and JSON by line or stream,
/// `.dat` for `category`, `.mrs` as the behavior `want` says.
fn read_download(
    bytes: &[u8],
    format: Format,
    category: &str,
    want: Want,
    regexp: bool,
) -> Result<Parsed, String> {
    let result = match format {
        Format::Dat | Format::Mrs => {
            rule_binary::parse(bytes, format == Format::Dat, category, want, regexp)
        }
        _ => rule_formats::parse(bytes, format, regexp),
    };
    result.map_err(|error| format!("invalid {} data: {error}", format.as_str()))
}

fn refused(tag: &str, rules: &[String]) -> Result<(), String> {
    match rules
        .iter()
        .find_map(|rule| providers::rule_refusal(tag, rule))
    {
        Some(reason) => Err(format!("content refused: {reason}")),
        None => Ok(()),
    }
}

fn no_rules(skipped: &Skipped) -> String {
    format!(
        "no usable rules in the download (skipped: {})",
        skipped.summary()
    )
}

fn stored_domains(
    tag: &str,
    bytes: &[u8],
    enable_regexp: bool,
    format: Format,
    category: &str,
    url: &str,
) -> Result<Stored, String> {
    if format == Format::Srs {
        let srs = decode_domain_srs(bytes, enable_regexp)
            .map_err(|error| format!("invalid SRS data: {error}"))?;
        refused(tag, &srs.rules)?;
        return Ok(Stored {
            content: None,
            count: Some(srs.rules.len() as i64),
            usable: srs.rules.len(),
            skipped: Skipped::default(),
        });
    }
    let mut parsed = read_download(bytes, format, category, Want::Domains, enable_regexp)?;
    parsed
        .skipped
        .add_many("ip rule in a domain set", parsed.ips.len() as u64);
    refused(tag, &parsed.domains)?;
    if parsed.domains.is_empty() {
        return Err(no_rules(&parsed.skipped));
    }
    Ok(Stored {
        content: Some(rule_formats::domain_file(&parsed.domains, format, url)),
        count: Some(parsed.domains.len() as i64),
        usable: parsed.domains.len(),
        skipped: parsed.skipped,
    })
}

fn stored_ips(bytes: &[u8], format: Format, category: &str, url: &str) -> Result<Stored, String> {
    if format == Format::Srs {
        let srs = decode_ip_srs(bytes).map_err(|error| format!("not a valid SRS file: {error}"))?;
        return Ok(Stored {
            content: None,
            count: Some(srs.prefixes.len() as i64),
            usable: srs.prefixes.len(),
            skipped: Skipped::default(),
        });
    }
    let mut parsed = read_download(bytes, format, category, Want::Ips, false)?;
    parsed
        .skipped
        .add_many("domain rule in an IP set", parsed.domains.len() as u64);
    if parsed.ips.is_empty() {
        return Err(no_rules(&parsed.skipped));
    }
    Ok(Stored {
        content: Some(rule_formats::ip_file(&parsed.ips, format, url)),
        count: Some(parsed.ips.len() as i64),
        usable: parsed.ips.len(),
        skipped: parsed.skipped,
    })
}

fn stored_adguard(
    tag: &str,
    bytes: &[u8],
    format: Format,
    category: &str,
    url: &str,
) -> Result<Stored, String> {
    if format == Format::Text {
        // AdGuard and hosts text is stored as it is (exceptions included).
        let (mut allow, mut deny) = (Vec::new(), Vec::<RuleEntry>::new());
        let usable = providers::parse_adguard_list(tag, "download", bytes, &mut allow, &mut deny);
        if allow.len() + deny.len() >= rule_formats::MAX_RULES {
            return Err(format!(
                "more than {} rules in one file",
                rule_formats::MAX_RULES
            ));
        }
        if usable > 0 && rule_formats::is_adguard_text(bytes) {
            let rules: Vec<String> = allow
                .into_iter()
                .chain(deny.into_iter().map(|entry| entry.rule))
                .collect();
            refused(tag, &rules)?;
            return Ok(Stored {
                content: None,
                count: None,
                usable: usable as usize,
                skipped: Skipped::default(),
            });
        }
    }
    let (domains, mut skipped) = if format == Format::Srs {
        // A block list must not match more than the file says.
        let srs = decode_domain_srs_plain(bytes, true)
            .map_err(|error| format!("invalid SRS data: {error}"))?;
        let mut skipped = Skipped::default();
        skipped.add_many("logical or conditional rule", srs.skipped);
        if !srs.complete {
            skipped.add_many("stopped before the end of the file", 1);
        }
        (srs.rules, skipped)
    } else {
        let mut parsed = read_download(bytes, format, category, Want::Domains, true)?;
        parsed
            .skipped
            .add_many("ip rule in a block list", parsed.ips.len() as u64);
        (parsed.domains, parsed.skipped)
    };
    refused(tag, &domains)?;
    let (content, written) = rule_formats::adguard_file(&domains, &mut skipped, format, url);
    if written == 0 {
        return Err(no_rules(&skipped));
    }
    Ok(Stored {
        content: Some(content),
        count: None,
        usable: written,
        skipped,
    })
}

// ----- rebuilds --------------------------------------------------------------

/// Resets a build state when a job ends early (shutdown), so it never stays
/// `Running` without a runner.
struct BuildGuard<'a>(&'a Cell<Build>);

impl Drop for BuildGuard<'_> {
    fn drop(&mut self) {
        self.0.set(Build::Idle);
    }
}

/// Runs `work` unless a build of this target is already running, in which
/// case that build is asked to run once more. Never two at a time.
async fn coalesced<F, Fut>(state: &Cell<Build>, mut work: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    if state.get() != Build::Idle {
        state.set(Build::Dirty);
        return;
    }
    let _guard = BuildGuard(state);
    loop {
        state.set(Build::Running);
        work().await;
        if state.get() != Build::Dirty {
            return;
        }
    }
}

/// After a provider changed: its own state (counts, `si_set` list, AdGuard
/// direct matcher), then every mapper that names it.
async fn changed(ctx: &Ctx, provider: &Rc<Provider>) {
    if ctx.cancel.is_cancelled() {
        return;
    }
    coalesced(&provider.reload, || reload_provider(ctx, provider)).await;
    let dependents: Vec<Rc<MapperSlot>> = ctx
        .inner
        .mappers
        .iter()
        .filter(|slot| slot.spec.rules.iter().any(|rule| rule.tag == provider.tag))
        .cloned()
        .collect();
    for slot in dependents {
        if ctx.cancel.is_cancelled() {
            return;
        }
        coalesced(&slot.build, || rebuild_mapper(ctx, &slot)).await;
    }
    // The replaced generations are dropped by now.
    let _ = on_build_thread(crate::memory::release_free_memory).await;
}

/// [`changed`], then waits until no rebuild of the provider or of a mapper
/// that names it is pending. A rebuild already running when [`changed`]
/// was called only gets marked dirty there and builds once more with the
/// files as they are now, so once everything is idle the latest write is
/// in use (atom: the API answers only then). An error says which rebuild
/// kept its previous rules (logged too).
async fn changed_and_settled(ctx: &Ctx, provider: &Rc<Provider>) -> Result<(), String> {
    changed(ctx, provider).await;
    let dependents: Vec<&Rc<MapperSlot>> = ctx
        .inner
        .mappers
        .iter()
        .filter(|slot| slot.spec.rules.iter().any(|rule| rule.tag == provider.tag))
        .collect();
    loop {
        let busy = provider.reload.get() != Build::Idle
            || dependents
                .iter()
                .any(|slot| slot.build.get() != Build::Idle);
        if ctx.cancel.is_cancelled() {
            return Err("host is stopping".to_owned());
        }
        if !busy {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut failed: Vec<String> = provider
        .failure
        .borrow()
        .iter()
        .map(|error| format!("{}: {error}", provider.tag))
        .collect();
    for slot in dependents {
        if let Some(error) = slot.failure.borrow().as_ref() {
            failed.push(format!("{}: {error}", slot.spec.tag));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("; "))
    }
}

/// Frees a replaced generation off the DNS thread, where dropping a large
/// matcher would stall queries for milliseconds. Not on the build thread
/// either: there it could wait behind another queued build and keep both
/// generations alive meanwhile. A generation a query still holds (none is
/// held across an await) is dropped by its last holder instead.
async fn drop_off_thread<T: Send + 'static>(replaced: Rc<T>) {
    if let Ok(replaced) = Rc::try_unwrap(replaced) {
        let _ = tokio::task::spawn_blocking(move || drop(replaced)).await;
    }
}

fn gate(ctx: &Ctx) -> Option<PersistGate> {
    ctx.inner.build_gate.borrow().clone()
}

enum Reloaded {
    Counts(Counts),
    Si(IpPrefixList, Counts),
    Adguard(Result<Box<Filtered>, String>, Counts),
}

async fn reload_provider(ctx: &Ctx, provider: &Rc<Provider>) {
    let Some(owner) = provider.manifest.as_ref() else {
        return;
    };
    let spec = owner.spec.clone();
    let sources = owner.sources.borrow().clone();
    let kind = provider.kind;
    let direct = provider.filtered.borrow().is_some();
    let gate = gate(ctx);
    let result = on_build_thread(move || {
        if let Some(gate) = gate {
            gate.wait();
        }
        match kind {
            Kind::Sd => Reloaded::Counts(count_sd(&spec, &sources)),
            Kind::Si => {
                let (list, counts) = providers::load_si(&spec, &sources, None);
                Reloaded::Si(list, counts)
            }
            Kind::Adguard => {
                let (rules, counts) = providers::load_adguard(&spec, &sources, true, None);
                let filtered = if direct {
                    rules.filtered(&spec.tag).map(Box::new)
                } else {
                    Err(String::new())
                };
                Reloaded::Adguard(filtered, counts)
            }
            Kind::Light => Reloaded::Counts(Vec::new()),
        }
    })
    .await;
    let counts = match result {
        Ok(Reloaded::Counts(counts)) => counts,
        Ok(Reloaded::Si(list, counts)) => {
            if let Some(handle) = &provider.ip {
                handle.publish(Rc::new(list));
            }
            counts
        }
        Ok(Reloaded::Adguard(filtered, counts)) => {
            let live = provider.filtered.borrow().clone();
            if let Some(live) = live {
                match filtered {
                    Ok(filtered) => drop_off_thread(live.replace(Rc::new(*filtered))).await,
                    Err(error) => {
                        crate::diag::error_line!(
                            "{}: rebuild failed, keeping the previous rules: {error}",
                            provider.tag
                        );
                        *provider.failure.borrow_mut() = Some(error);
                        return;
                    }
                }
            }
            counts
        }
        Err(error) => {
            crate::diag::error_line!("{}: reload failed: {error}", provider.tag);
            *provider.failure.borrow_mut() = Some(error.to_string());
            return;
        }
    };
    *provider.failure.borrow_mut() = None;
    ctx.inner.builds.fetch_add(1, Ordering::SeqCst);
    apply_counts(ctx, provider, counts).await;
}

/// The reference reload count of `sd_set_light`: each decodable enabled
/// source, one file at a time (only the count is kept).
fn count_sd(spec: &ManifestSpec, sources: &[SourceEntry]) -> Counts {
    let mut counts = Vec::new();
    for source in sources {
        if !source.enabled || source.files.is_empty() {
            continue;
        }
        let (_, mut one) = providers::load_sd(spec, std::slice::from_ref(source), None);
        counts.append(&mut one);
    }
    counts
}

async fn rebuild_mapper(ctx: &Ctx, slot: &Rc<MapperSlot>) {
    let mut plans: Vec<(String, Plan)> = Vec::new();
    for rule in &slot.spec.rules {
        if plans.iter().any(|(tag, _)| *tag == rule.tag) {
            continue;
        }
        if let Some(provider) = ctx.inner.providers.iter().find(|p| p.tag == rule.tag) {
            plans.push((rule.tag.clone(), provider.load_plan()));
        }
    }
    let spec = slot.spec.clone();
    let gate = gate(ctx);
    let built = on_build_thread(move || {
        if let Some(gate) = gate {
            gate.wait();
        }
        let mut rules: Vec<(String, providers::ProviderRules)> = Vec::with_capacity(plans.len());
        for (tag, plan) in plans {
            rules.push((tag, plan.rules()?));
        }
        providers::build_mapper_matcher(&spec, &|tag| {
            rules
                .iter()
                .find(|(name, _)| name == tag)
                .map(|(_, entries)| entries.as_slice())
        })
        .map_err(|error| error.to_string())
    })
    .await;
    match built {
        Ok(Ok(matcher)) => {
            *slot.failure.borrow_mut() = None;
            let replaced = slot.live.replace(Rc::new(matcher));
            ctx.inner.builds.fetch_add(1, Ordering::SeqCst);
            drop_off_thread(replaced).await;
        }
        Ok(Err(error)) => {
            crate::diag::error_line!(
                "{}: rebuild failed, keeping the previous rules: {error}",
                slot.spec.tag
            );
            *slot.failure.borrow_mut() = Some(error);
        }
        Err(error) => {
            crate::diag::error_line!("{}: rebuild failed: {error}", slot.spec.tag);
            *slot.failure.borrow_mut() = Some(error.to_string());
        }
    }
}

// ----- scheduler -------------------------------------------------------------

/// The host-lifetime auto-update loop: start-up work once, then the
/// reference cadence. It always acts on the currently committed view.
pub(crate) async fn supervise(
    control: crate::runtime_snapshot::RuntimeControl,
    shutdown: TransportCancellation,
) {
    // What compiling the configuration freed (rule text, build temporaries).
    let _ = on_build_thread(crate::memory::release_free_memory).await;
    let sources = Rc::clone(&control.view().config.rule_sources);
    sources.start();
    let timing = sources.timing();
    drop(sources);
    let start = tokio::time::Instant::now();
    let mut next_source = start + timing.first_check;
    let mut next_adguard = start + timing.first_check;
    loop {
        let next = next_source.min(next_adguard);
        tokio::select! {
            biased;
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep_until(next) => {}
        }
        let now = tokio::time::Instant::now();
        let mut kinds = Vec::new();
        if now >= next_source {
            kinds.extend([Kind::Sd, Kind::Si]);
            next_source = now + timing.source_period;
        }
        if now >= next_adguard {
            kinds.push(Kind::Adguard);
            next_adguard = now + timing.adguard_period;
        }
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs() as i64);
        control.view().config.rule_sources.auto_update(&kinds, unix);
    }
}

/// The reference predicate: enabled, auto-update on, a positive interval and
/// at least that many hours since `last_updated` (the zero time is due).
pub(crate) fn is_due(entry: &SourceEntry, now: i64) -> bool {
    if !entry.enabled || !entry.auto_update || entry.update_interval_hours <= 0 {
        return false;
    }
    let last = entry
        .last_updated
        .as_deref()
        .and_then(unix_seconds)
        .unwrap_or(ZERO_UNIX);
    i128::from(now) - i128::from(last) >= i128::from(entry.update_interval_hours) * 3600
}

// ----- helpers ---------------------------------------------------------------

/// The process-wide write lock of one manifest or rule file. Every
/// generation's provider for the same file gets the same lock.
pub(crate) fn write_lock(path: PathBuf) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>,
    > = std::sync::OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(locks.entry(path).or_default())
}

type BuildJob = Box<dyn FnOnce() + Send>;

/// Runs allocation-heavy rule work (decoding, building matchers) on one
/// long-lived thread instead of the blocking pool. Every rebuild then reuses
/// the same allocator arena, which bounds the memory a series of rebuilds
/// keeps resident; a pool thread per rebuild would leave each arena at its
/// own peak. The DNS runtime thread never runs this work.
pub(crate) async fn on_build_thread<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    static WORKER: std::sync::OnceLock<Result<std::sync::mpsc::Sender<BuildJob>, String>> =
        std::sync::OnceLock::new();
    let worker = WORKER.get_or_init(|| {
        let (sender, receiver) = std::sync::mpsc::channel::<BuildJob>();
        std::thread::Builder::new()
            .name("atomdns-rule-build".into())
            .spawn(move || {
                while let Ok(job) = receiver.recv() {
                    job();
                }
            })
            .map(|_| sender)
            .map_err(|error| error.to_string())
    });
    let sender = worker.as_ref().map_err(Clone::clone)?;
    let (reply, result) = tokio::sync::oneshot::channel();
    sender
        .send(Box::new(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
                .map_err(|_| "rule build panicked".to_owned());
            let _ = reply.send(outcome);
        }))
        .map_err(|_| "rule build thread stopped".to_owned())?;
    result
        .await
        .map_err(|_| "rule build thread stopped".to_owned())?
}

fn rule_lines<'a>(rules: impl Iterator<Item = &'a str>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for rule in rules {
        bytes.extend_from_slice(rule.as_bytes());
        bytes.push(b'\n');
    }
    bytes
}

/// Replaces `path` through a same-directory temporary file and a rename,
/// creating the directory when needed. A failure removes the temporary file
/// and leaves `path` untouched.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(directory)?;
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    let mut temporary = std::ffi::OsString::from(".");
    temporary.push(name);
    temporary.push(format!(
        ".tmp-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let temporary = directory.join(temporary);
    let outcome =
        std::fs::write(&temporary, bytes).and_then(|()| std::fs::rename(&temporary, path));
    if outcome.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    outcome
}

fn now_text() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| ZERO_TIME.to_owned())
}

/// Seconds since the Unix epoch of a manifest time (the RFC 3339 forms the
/// manifest decoder accepts), or `None` when it is not one.
pub(crate) fn unix_seconds(text: &str) -> Option<i64> {
    let mut padded = text.as_bytes().to_vec();
    if padded.len() > 12 && padded[11].is_ascii_digit() && padded[12] == b':' {
        padded.insert(11, b'0');
    }
    let b = padded.as_slice();
    let digits = |from: usize, n: usize| -> Option<i64> {
        let part = b.get(from..from + n)?;
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| part.iter().fold(0, |acc, d| acc * 10 + i64::from(d - b'0')))
    };
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    let mut i = 19;
    if matches!(b.get(i), Some(b'.' | b',')) {
        i += 1;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    let offset = match b.get(i)? {
        b'Z' => 0,
        sign @ (b'+' | b'-') => {
            let value = digits(i + 1, 2)? * 3600 + digits(i + 4, 2)? * 60;
            if *sign == b'-' { -value } else { value }
        }
        _ => return None,
    };
    // Days from the civil date (proleptic Gregorian), Howard Hinnant's method.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(enabled: bool, auto: bool, hours: i64, last: Option<&str>) -> SourceEntry {
        SourceEntry {
            name: "s".into(),
            enabled,
            auto_update: auto,
            update_interval_hours: hours,
            last_updated: last.map(str::to_owned),
            ..SourceEntry::default()
        }
    }

    #[test]
    fn times_parse_like_the_manifest_decoder() {
        assert_eq!(unix_seconds("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix_seconds(ZERO_TIME), Some(ZERO_UNIX));
        assert_eq!(unix_seconds("0001-01-01T08:00:00+08:00"), Some(ZERO_UNIX));
        assert_eq!(
            unix_seconds("2025-12-19T16:32:42.281233973+08:00"),
            Some(1_766_133_162)
        );
        assert_eq!(unix_seconds("2025-12-19T8:32:42Z"), Some(1_766_133_162));
        assert_eq!(unix_seconds("2025-12-19T08:32:42,5Z"), Some(1_766_133_162));
        assert_eq!(unix_seconds("not a time"), None);
    }

    #[test]
    fn the_due_predicate_follows_the_reference() {
        let now = unix_seconds("2026-10-08T12:00:00Z").unwrap();
        // Never updated (zero time or no field) is due.
        assert!(is_due(&entry(true, true, 24, None), now));
        assert!(is_due(&entry(true, true, 24, Some(ZERO_TIME)), now));
        // Exactly the interval is due; one second less is not.
        assert!(is_due(
            &entry(true, true, 24, Some("2026-10-07T12:00:00Z")),
            now
        ));
        assert!(!is_due(
            &entry(true, true, 24, Some("2026-10-07T12:00:01Z")),
            now
        ));
        // Offsets are honored.
        assert!(is_due(
            &entry(true, true, 1, Some("2026-10-08T19:00:00+08:00")),
            now
        ));
        assert!(!is_due(
            &entry(true, true, 1, Some("2026-10-08T19:30:00+08:00")),
            now
        ));
        // Disabled, auto-update off, or a non-positive interval is never due.
        assert!(!is_due(&entry(false, true, 24, None), now));
        assert!(!is_due(&entry(true, false, 24, None), now));
        assert!(!is_due(&entry(true, true, 0, None), now));
        assert!(!is_due(&entry(true, true, -1, None), now));
    }

    #[test]
    fn manifests_are_written_like_the_reference() {
        let mut sources = vec![
            SourceEntry {
                name: "b".into(),
                kind: "geositecn".into(),
                files: "srs/b.srs".into(),
                url: "https://x/b.srs".into(),
                enabled: true,
                update_interval_hours: 24,
                rule_count: 3,
                last_updated: Some("2025-12-19T16:32:42.281233973+08:00".into()),
                ..SourceEntry::default()
            },
            SourceEntry {
                name: "a".into(),
                enable_regexp: true,
                ..SourceEntry::default()
            },
        ];
        let sd = String::from_utf8(manifest_bytes(Kind::Sd, &mut sources.clone())).unwrap();
        assert_eq!(
            sd,
            "[\n  {\n    \"name\": \"a\",\n    \"type\": \"\",\n    \"files\": \"\",\n    \"url\": \"\",\n    \"enabled\": false,\n    \"enable_regexp\": true,\n    \"auto_update\": false,\n    \"update_interval_hours\": 0,\n    \"rule_count\": 0,\n    \"last_updated\": \"0001-01-01T00:00:00Z\"\n  },\n  {\n    \"name\": \"b\",\n    \"type\": \"geositecn\",\n    \"files\": \"srs/b.srs\",\n    \"url\": \"https://x/b.srs\",\n    \"enabled\": true,\n    \"auto_update\": false,\n    \"update_interval_hours\": 24,\n    \"rule_count\": 3,\n    \"last_updated\": \"2025-12-19T16:32:42.281233973+08:00\"\n  }\n]"
        );
        let si = String::from_utf8(manifest_bytes(Kind::Si, &mut sources)).unwrap();
        assert!(!si.contains("enable_regexp"));
        let mut rules = vec![
            SourceEntry {
                id: "2".into(),
                name: "z".into(),
                last_updated: Some(ZERO_TIME.into()),
                ..SourceEntry::default()
            },
            SourceEntry {
                id: "1".into(),
                name: "y".into(),
                last_updated: Some("2026-03-24T13:10:52.253656114+08:00".into()),
                ..SourceEntry::default()
            },
        ];
        let adguard = String::from_utf8(manifest_bytes(Kind::Adguard, &mut rules)).unwrap();
        assert!(adguard.find("\"id\": \"1\"").unwrap() < adguard.find("\"id\": \"2\"").unwrap());
        assert_eq!(adguard.matches("last_updated").count(), 1, "{adguard}");
    }

    #[test]
    fn one_file_has_one_write_lock_across_generations() {
        let a = write_lock(PathBuf::from("/x/srs/a.json"));
        let b = write_lock(PathBuf::from("/x/srs/a.json"));
        let c = write_lock(PathBuf::from("/x/srs/c.json"));
        assert!(Arc::ptr_eq(&a, &b));
        assert!(!Arc::ptr_eq(&a, &c));
    }

    #[test]
    fn atomic_writes_replace_or_leave_the_target() {
        let root = std::env::temp_dir().join(format!("rule-sources-write-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let target = root.join("deep/dir/file.json");
        write_atomically(&target, b"one").unwrap();
        write_atomically(&target, b"two").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"two");
        // A directory in the way of the rename fails without touching it.
        let blocked = root.join("blocked");
        std::fs::create_dir_all(blocked.join("child")).unwrap();
        assert!(write_atomically(&blocked, b"x").is_err());
        assert!(blocked.join("child").is_dir());
        let leftovers: Vec<_> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn store(
        kind: Kind,
        tag: &str,
        bytes: &[u8],
        file: &Path,
        regexp: bool,
        format: Format,
        url: &str,
    ) -> Result<Option<i64>, String> {
        let source = Download {
            format,
            category: "",
            url,
        };
        store_download(kind, tag, bytes, file, regexp, &source)
    }

    // ----- subscription formats ------------------------------------------------

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rule-formats-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn spec(schema: Schema, root: &Path) -> ManifestSpec {
        ManifestSpec {
            tag: "t".into(),
            schema,
            manifest: root.join("manifest.json"),
            dir: root.to_path_buf(),
            root_dir: root.to_path_buf(),
            socks5: String::new(),
        }
    }

    fn source(id: &str, files: &str, regexp: bool) -> SourceEntry {
        SourceEntry {
            id: id.into(),
            name: id.into(),
            files: files.into(),
            enabled: true,
            enable_regexp: regexp,
            ..SourceEntry::default()
        }
    }

    #[test]
    fn a_text_download_is_stored_converted_and_loaded_back() {
        let root = scratch("sd");
        let file = root.join("rules.txt");
        let list =
            b"# list\nDOMAIN-SUFFIX,suffix.example.com\nfull:www.example.org\n*.wild.example.net\n\
                     192.0.2.0/24\nPROCESS-NAME,x\n";
        for regexp in [false, true] {
            let count = store(
                Kind::Sd,
                "t",
                list,
                &file,
                regexp,
                Format::Auto,
                "https://example.com/list.conf",
            )
            .unwrap();
            let text = std::fs::read_to_string(&file).unwrap();
            assert!(
                text.starts_with("# atomdns: converted from text https://example.com/list.conf\n")
            );
            let spec = spec(Schema::Sd, &root);
            let entry = source("a", file.to_str().unwrap(), regexp);
            let (rules, counts) = providers::load_sd(&spec, &[entry], None);
            let rules: Vec<&str> = rules.iter().map(|r| r.rule.as_str()).collect();
            let mut expected = vec!["domain:suffix.example.com", "full:www.example.org"];
            if regexp {
                expected.push("regexp:^[^.]+\\.wild\\.example\\.net$");
            }
            assert_eq!(rules, expected);
            assert_eq!(count, Some(expected.len() as i64));
            assert_eq!(counts, [("a".to_owned(), expected.len() as i64)]);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_conversion_keeps_the_old_file() {
        let root = scratch("keep");
        let file = root.join("rules.txt");
        std::fs::write(&file, b"domain:old.example.com\n").unwrap();
        let url = "https://example.com/x";
        for (kind, bytes) in [
            (Kind::Sd, &b"<html>Not Found</html>"[..]),
            (Kind::Sd, b"192.0.2.0/24\n"),
            (Kind::Si, b"example.com\n"),
            (Kind::Adguard, b"192.0.2.0/24\n"),
            (Kind::Sd, b"payload:\n  - '*'\n"),
        ] {
            let result = store(kind, "t", bytes, &file, true, Format::Auto, url);
            assert!(result.is_err(), "{kind:?} {bytes:?}");
        }
        assert_eq!(std::fs::read(&file).unwrap(), b"domain:old.example.com\n");
        let refused = store(
            Kind::Sd,
            "t",
            b"regexp:\\p{L}+\n",
            &file,
            true,
            Format::Text,
            url,
        );
        assert!(refused.unwrap_err().contains("content refused"));
        assert_eq!(std::fs::read(&file).unwrap(), b"domain:old.example.com\n");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_ip_download_is_stored_converted_and_loaded_back() {
        let root = scratch("si");
        let file = root.join("ip.txt");
        let count = store(
            Kind::Si,
            "t",
            b"{\"version\":2,\"rules\":[{\"ip_cidr\":[\"192.0.2.0/24\",\"2001:db8::/32\"]},{\"domain\":[\"a.example.com\"]}]}",
            &file,
            false,
            Format::Auto,
            "https://example.com/ip.json",
        )
        .unwrap();
        assert_eq!(count, Some(2));
        let (list, counts) = providers::load_si(
            &spec(Schema::Si, &root),
            &[source("ip", file.to_str().unwrap(), false)],
            None,
        );
        assert_eq!(counts, [("ip".to_owned(), 2)]);
        assert!(list.contains("192.0.2.9".parse().unwrap()));
        assert!(list.contains("2001:db8::7".parse().unwrap()));
        assert!(!list.contains("198.51.100.1".parse().unwrap()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn adguard_text_is_kept_and_other_formats_are_converted() {
        let root = scratch("adguard");
        let file = root.join("1.rules");
        let url = "https://example.com/list";
        let adguard = b"! title\n||ads.example.com^\n@@||ok.example.com^\n0.0.0.0 hosts.example.org\n127.0.0.1 localhost\n";
        assert_eq!(
            store(Kind::Adguard, "t", adguard, &file, false, Format::Auto, url).unwrap(),
            None
        );
        assert_eq!(std::fs::read(&file).unwrap(), adguard);
        let load = |entry: &SourceEntry| {
            let (rules, counts) = providers::load_adguard(
                &spec(Schema::Adguard, &root),
                std::slice::from_ref(entry),
                false,
                None,
            );
            let deny: Vec<String> = rules.deny.iter().map(|e| e.rule.clone()).collect();
            (rules.allow, deny, counts)
        };
        let entry = source("1", "", false);
        let (allow, deny, counts) = load(&entry);
        assert_eq!(allow, ["domain:ok.example.com"]);
        assert_eq!(deny, ["domain:ads.example.com", "full:hosts.example.org"]);
        assert_eq!(counts, [("1".to_owned(), 3)]);

        let clash = b"payload:\n  - '+.suffix.example.com'\n  - 'www.example.org'\n  - DOMAIN-KEYWORD,track\n";
        store(
            Kind::Adguard,
            "t",
            clash,
            &file,
            false,
            Format::Auto,
            "https://example.com/c.yaml",
        )
        .unwrap();
        let (allow, deny, _) = load(&entry);
        assert!(allow.is_empty());
        assert_eq!(
            deny,
            [
                "domain:suffix.example.com",
                "full:www.example.org",
                "regexp:track"
            ]
        );

        let classic = b"DOMAIN-SUFFIX,a.example.com\nDOMAIN,b.example.com\n";
        store(
            Kind::Adguard,
            "t",
            classic,
            &file,
            false,
            Format::Auto,
            "https://example.com/c.list",
        )
        .unwrap();
        assert_eq!(
            load(&entry).1,
            ["domain:a.example.com", "full:b.example.com"]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn store_dat(
        kind: Kind,
        bytes: &[u8],
        file: &Path,
        regexp: bool,
        format: Format,
        category: &str,
        url: &str,
    ) -> Result<Option<i64>, String> {
        let source = Download {
            format,
            category,
            url,
        };
        store_download(kind, "t", bytes, file, regexp, &source)
    }

    #[test]
    fn a_dat_download_is_stored_converted_and_loaded_back() {
        use crate::rule_binary::tests::{c, geoip_entry, geosite_entry};
        let root = scratch("dat");
        let file = root.join("rules.txt");
        let url = "https://example.com/geosite.dat";
        let mut geosite = geosite_entry("other", &[(2, "other.example.org")]);
        geosite.extend(geosite_entry(
            "cn",
            &[
                (2, "suffix.example.com"),
                (3, "www.example.net"),
                (1, "^a\\.example\\.org$"),
            ],
        ));
        // Auto picks `dat` from the address; the category is needed.
        let error = store_dat(Kind::Sd, &geosite, &file, true, Format::Auto, "", url).unwrap_err();
        assert!(error.contains("category"), "{error}");
        assert!(!file.exists());
        for regexp in [false, true] {
            let count =
                store_dat(Kind::Sd, &geosite, &file, regexp, Format::Auto, "CN", url).unwrap();
            assert_eq!(count, Some(if regexp { 3 } else { 2 }));
            let entry = source("a", file.to_str().unwrap(), regexp);
            let (rules, _) = providers::load_sd(&spec(Schema::Sd, &root), &[entry], None);
            let rules: Vec<&str> = rules.iter().map(|r| r.rule.as_str()).collect();
            assert!(rules.contains(&"domain:suffix.example.com"), "{rules:?}");
            assert_eq!(rules.contains(&"regexp:^a\\.example\\.org$"), regexp);
        }
        // A missing category and a wrong file keep the good file.
        let before = std::fs::read(&file).unwrap();
        let error = store_dat(Kind::Sd, &geosite, &file, true, Format::Dat, "us", url).unwrap_err();
        assert!(error.contains("not found"), "{error}");
        assert!(store_dat(Kind::Sd, b"<html>", &file, true, Format::Dat, "cn", url).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), before);

        // geoip.dat for an IP set.
        let ip_file = root.join("ip.txt");
        let mut geoip = geoip_entry("cn", &[c(&[192, 0, 2, 0], 24)], false);
        geoip.extend(geoip_entry("rev", &[c(&[198, 51, 100, 0], 24)], true));
        let ip_url = "https://example.com/geoip.dat";
        assert_eq!(
            store_dat(
                Kind::Si,
                &geoip,
                &ip_file,
                false,
                Format::Auto,
                "cn",
                ip_url
            )
            .unwrap(),
            Some(1)
        );
        let (list, _) = providers::load_si(
            &spec(Schema::Si, &root),
            &[source("ip", ip_file.to_str().unwrap(), false)],
            None,
        );
        assert!(list.contains("192.0.2.9".parse().unwrap()));
        let error = store_dat(
            Kind::Si,
            &geoip,
            &ip_file,
            false,
            Format::Dat,
            "rev",
            ip_url,
        )
        .unwrap_err();
        assert!(error.contains("reverse match"), "{error}");

        // The same geosite category as a block list.
        let rules = root.join("1.rules");
        store_dat(
            Kind::Adguard,
            &geosite,
            &rules,
            false,
            Format::Dat,
            "cn",
            url,
        )
        .unwrap();
        let (loaded, _) = providers::load_adguard(
            &spec(Schema::Adguard, &root),
            &[source("1", "", false)],
            false,
            None,
        );
        let deny: Vec<String> = loaded.deny.iter().map(|e| e.rule.clone()).collect();
        // A block list has no regexp switch.
        assert_eq!(
            deny,
            [
                "domain:suffix.example.com",
                "full:www.example.net",
                "regexp:^a\\.example\\.org$"
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_mrs_download_is_stored_converted_and_loaded_back() {
        use crate::rule_binary::tests::{mapped, mrs_domain_file, mrs_ip_file};
        let root = scratch("mrs");
        let file = root.join("rules.txt");
        let url = "https://example.com/cn.mrs";
        let domains = mrs_domain_file(&["+.example.com", "www.example.net", "*.wild.example.org"]);
        for regexp in [false, true] {
            let count =
                store_dat(Kind::Sd, &domains, &file, regexp, Format::Auto, "", url).unwrap();
            assert_eq!(count, Some(if regexp { 3 } else { 2 }));
            let text = std::fs::read_to_string(&file).unwrap();
            assert!(text.starts_with("# atomdns: converted from mrs https://example.com/cn.mrs\n"));
            let entry = source("a", file.to_str().unwrap(), regexp);
            let (rules, _) = providers::load_sd(&spec(Schema::Sd, &root), &[entry], None);
            assert_eq!(rules.len(), if regexp { 3 } else { 2 });
        }
        // The other behavior and a damaged file keep the good file.
        let before = std::fs::read(&file).unwrap();
        let ips = mrs_ip_file(&[(mapped([192, 0, 2, 0]), mapped([192, 0, 2, 255]))]);
        let error = store_dat(Kind::Sd, &ips, &file, true, Format::Auto, "", url).unwrap_err();
        assert!(error.contains("behavior is ip"), "{error}");
        assert!(store_dat(Kind::Sd, &domains[..20], &file, true, Format::Auto, "", url).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), before);

        // Content is enough to tell an mrs file from a text address.
        let ip_file = root.join("ip.txt");
        let any = "https://example.com/download";
        assert_eq!(
            store_dat(Kind::Si, &ips, &ip_file, false, Format::Auto, "", any).unwrap(),
            Some(1)
        );
        let error =
            store_dat(Kind::Si, &domains, &ip_file, false, Format::Mrs, "", any).unwrap_err();
        assert!(error.contains("behavior is domain"), "{error}");

        let rules = root.join("1.rules");
        store_dat(
            Kind::Adguard,
            &domains,
            &rules,
            false,
            Format::Auto,
            "",
            url,
        )
        .unwrap();
        let (loaded, _) = providers::load_adguard(
            &spec(Schema::Adguard, &root),
            &[source("1", "", false)],
            false,
            None,
        );
        let mut deny: Vec<String> = loaded.deny.iter().map(|e| e.rule.clone()).collect();
        deny.sort();
        assert_eq!(
            deny,
            [
                "domain:example.com",
                "full:www.example.net",
                "regexp:^[^.]+\\.wild\\.example\\.org$"
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_category_field_is_written_only_when_set() {
        let mut sources = vec![SourceEntry {
            name: "a".into(),
            url: "https://example.com/geosite.dat".into(),
            format: Format::Dat,
            category: "cn".into(),
            ..SourceEntry::default()
        }];
        let text = String::from_utf8(manifest_bytes(Kind::Sd, &mut sources.clone())).unwrap();
        assert!(
            text.contains("\"format\": \"dat\",\n    \"category\": \"cn\""),
            "{text}"
        );
        let back = providers::parse_source_object(
            text.trim().trim_matches(['[', ']']).as_bytes(),
            Schema::Sd,
        )
        .unwrap();
        assert_eq!(back.category, "cn");
        sources[0].category.clear();
        sources[0].format = Format::Mrs;
        let plain = String::from_utf8(manifest_bytes(Kind::Sd, &mut sources)).unwrap();
        assert!(plain.contains("\"mrs\"") && !plain.contains("category"));
        let mut rules = vec![SourceEntry {
            id: "1".into(),
            category: "ads".into(),
            ..SourceEntry::default()
        }];
        let adguard = String::from_utf8(manifest_bytes(Kind::Adguard, &mut rules)).unwrap();
        assert!(adguard.contains("\"category\": \"ads\""));
        let view = serde_json::to_string(&rule_view(&rules[0], false)).unwrap();
        assert!(view.contains("\"category\":\"ads\""));
        assert!(
            !serde_json::to_string(&rule_view(&SourceEntry::default(), false))
                .unwrap()
                .contains("category")
        );
    }

    #[test]
    fn the_format_field_is_written_only_when_set() {
        let mut sources = vec![SourceEntry {
            name: "a".into(),
            url: "https://example.com/a.yaml".into(),
            format: Format::Yaml,
            ..SourceEntry::default()
        }];
        let sd = String::from_utf8(manifest_bytes(Kind::Sd, &mut sources.clone())).unwrap();
        assert!(sd.contains(
            "\"url\": \"https://example.com/a.yaml\",\n    \"format\": \"yaml\",\n    \"enabled\""
        ));
        let back =
            providers::parse_source_object(br#"{"name":"a","format":"YAML"}"#, Schema::Sd).unwrap();
        assert_eq!(back.format, Format::Yaml);
        sources[0].format = Format::Auto;
        let plain = String::from_utf8(manifest_bytes(Kind::Sd, &mut sources.clone())).unwrap();
        assert!(!plain.contains("format"));
        let mut rules = vec![SourceEntry {
            id: "1".into(),
            format: Format::Json,
            ..SourceEntry::default()
        }];
        let adguard = String::from_utf8(manifest_bytes(Kind::Adguard, &mut rules)).unwrap();
        assert!(adguard.contains("\"format\": \"json\""));
        rules[0].format = Format::Auto;
        assert!(
            !String::from_utf8(manifest_bytes(Kind::Adguard, &mut rules))
                .unwrap()
                .contains("format")
        );
        let view = serde_json::to_string(&source_view(&sources[0], Kind::Sd)).unwrap();
        assert!(!view.contains("format"));
    }

    #[test]
    fn a_mixed_text_file_is_converted_not_kept_as_adguard_text() {
        let root = scratch("mixed");
        let file = root.join("1.rules");
        let url = "https://example.com/mixed.txt";
        let mixed = b"DOMAIN-SUFFIX,ads.example.com\ntracker.example.net\n";
        store(Kind::Adguard, "t", mixed, &file, false, Format::Auto, url).unwrap();
        let (rules, _) = providers::load_adguard(
            &spec(Schema::Adguard, &root),
            &[source("1", "", false)],
            false,
            None,
        );
        let deny: Vec<&str> = rules.deny.iter().map(|e| e.rule.as_str()).collect();
        assert_eq!(
            deny,
            ["domain:ads.example.com", "domain:tracker.example.net"]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_block_list_from_srs_leaves_out_logical_rules() {
        use std::io::Write as _;
        // keyword ad | logical(keyword xy), inverted | keyword zz
        let kw = |word: &[u8]| {
            let mut item = vec![3, 1, word.len() as u8];
            item.extend(word);
            item
        };
        let mut body = vec![3, 0];
        body.extend(kw(b"ad"));
        body.push(0xff);
        body.extend([1, 0, 1, 0]);
        body.extend(kw(b"xy"));
        body.extend([0xff, 1, 0]);
        body.extend(kw(b"zz"));
        body.push(0xff);
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&body).unwrap();
        let mut file_bytes = b"SRS\x03".to_vec();
        file_bytes.extend(encoder.finish().unwrap());
        let root = scratch("srs-block");
        let file = root.join("1.rules");
        store(
            Kind::Adguard,
            "t",
            &file_bytes,
            &file,
            false,
            Format::Auto,
            "https://example.com/ads.srs",
        )
        .unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(
            text.contains("/ad/") && text.contains("/zz/") && !text.contains("xy"),
            "{text}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_hosts_list_cannot_expand_past_the_rule_limit() {
        let root = scratch("cap");
        let file = root.join("1.rules");
        std::fs::write(&file, b"keep\n").unwrap();
        let mut list = String::new();
        for _ in 0..1_100 {
            list.push_str("0.0.0.0");
            list.push_str(&" a.a".repeat(2_000));
            list.push('\n');
        }
        let error = store(
            Kind::Adguard,
            "t",
            list.as_bytes(),
            &file,
            false,
            Format::Auto,
            "https://example.com/hosts",
        )
        .unwrap_err();
        assert!(error.contains("more than"), "{error}");
        assert_eq!(std::fs::read(&file).unwrap(), b"keep\n");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_srs_address_that_returns_a_page_fails_and_keeps_the_file() {
        let root = scratch("srs-page");
        let file = root.join("rules.srs");
        std::fs::write(&file, b"old").unwrap();
        let page = b"<html>Not Found</html>\ndomain:page.example.com\n";
        for kind in [Kind::Sd, Kind::Si, Kind::Adguard] {
            let result = store(
                kind,
                "t",
                page,
                &file,
                true,
                Format::Auto,
                "https://example.com/geo.srs",
            );
            assert!(result.is_err(), "{kind:?}");
            assert_eq!(std::fs::read(&file).unwrap(), b"old", "{kind:?}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
