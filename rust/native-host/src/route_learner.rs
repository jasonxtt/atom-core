//! The `route_learner` plugin (the learned routing facts) and the
//! `route_learn` rules that feed it.
//!
//! One learner owns every category (remembered direct / proxy, no-V4 / no-V6,
//! special names): a table of normalised names per category, each entry with a
//! first / last confirmation time, a hit counter and the rule that confirmed
//! it. Entries expire individually, `ttl` seconds after their last
//! confirmation. A `domain_mapper` merges the learned facts into its own
//! result when it evaluates a name (the learned marks and labels come first,
//! the mapper default is not applied), so learning never touches a matcher.
//! The state is one JSON file, written periodically (only when something
//! changed), on request and when the host stops; a hot apply hands the live
//! state to the next generation in memory. See
//! `docs/rust/contracts/native-route-learner.md`.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use atomdns_sequence_core::{ExecutionState, ExecutorError, Matcher};
use atomdns_upstream_core::TransportCancellation;
use serde::Serialize;

use crate::config::providers::{append_joined, presentation_name};
use crate::rule_sources::Reply;

/// Hard upper bound of `max_entries` (the former `domain_output` key cap).
pub(crate) const MAX_ENTRIES_CAP: usize = 262_144;
const STATE_FORMAT: u64 = 1;
const TEXT: &str = "text/plain; charset=utf-8";
const JSON: &str = "application/json; charset=utf-8";
/// Longest name (without the trailing dot) that is recorded.
const MAX_NAME: usize = 253;
/// `entries` page size limits.
const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;

/// One category of a learner.
#[derive(Clone, Debug)]
pub(crate) struct CategorySpec {
    pub(crate) tag: String,
    pub(crate) mark: u8,
    pub(crate) label: String,
    pub(crate) source: String,
    /// Seconds from the last confirmation.
    pub(crate) ttl: u64,
    pub(crate) max_entries: usize,
    pub(crate) enabled: bool,
}

/// The validated arguments of one `route_learner`.
#[derive(Clone, Debug)]
pub(crate) struct Settings {
    pub(crate) target_mapper: String,
    pub(crate) file: PathBuf,
    pub(crate) write_interval: Duration,
    pub(crate) categories: Vec<CategorySpec>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Running,
    /// A newer generation owns the state: nothing is scheduled or written.
    Fenced,
    Closed,
}

#[derive(Clone, Copy)]
struct Entry {
    /// Seconds since the Unix epoch.
    first: u32,
    last: u32,
    hits: u32,
    reason: u16,
}

#[derive(Default, Clone, Copy)]
struct Counters {
    learned: u64,
    confirmed: u64,
    expired: u64,
    evicted: u64,
    flushed: u64,
}

#[derive(Clone)]
struct WriteInfo {
    at: u64,
    entries: usize,
    error: Option<String>,
}

/// The state that survives a hot apply: shared by every generation.
struct Shared {
    cats: Vec<HashMap<Box<str>, Entry>>,
    reasons: Vec<Box<str>>,
    /// Something other than a hit counter changed since the last write.
    changed: bool,
    /// A hit counter changed since the last write.
    hits_dirty: bool,
    counters: Counters,
    last_write: Option<WriteInfo>,
    seq: u64,
    last_written: Arc<Mutex<u64>>,
    clock_shift: i64,
}

impl Shared {
    fn new(tags: Vec<String>) -> Self {
        Self {
            cats: tags.iter().map(|_| HashMap::new()).collect(),
            reasons: Vec::new(),
            changed: false,
            hits_dirty: false,
            counters: Counters::default(),
            last_write: None,
            seq: 0,
            last_written: Arc::new(Mutex::new(0)),
            clock_shift: 0,
        }
    }

    fn now(&self) -> u64 {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        u64::try_from(i64::try_from(seconds).unwrap_or(i64::MAX) + self.clock_shift).unwrap_or(0)
    }

    fn intern(&mut self, reason: &str) -> u16 {
        if let Some(index) = self.reasons.iter().position(|have| &**have == reason) {
            return u16::try_from(index).unwrap_or(0);
        }
        if self.reasons.len() >= usize::from(u16::MAX) {
            return 0;
        }
        self.reasons.push(reason.into());
        u16::try_from(self.reasons.len() - 1).unwrap_or(0)
    }

    fn reason(&self, index: u16) -> &str {
        self.reasons.get(usize::from(index)).map_or("", |r| &**r)
    }

    fn total(&self) -> usize {
        self.cats.iter().map(HashMap::len).sum()
    }
}

/// What a lookup found for one name.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LearnedHit {
    /// Fast-flag bits (bit `mark` per category).
    pub(crate) flags: u64,
    /// Joined labels.
    pub(crate) tags: String,
    /// Joined rule sources.
    pub(crate) sources: String,
}

/// The runtime owner of one `route_learner` plugin.
pub struct RouteLearner {
    pub tag: String,
    settings: Arc<Settings>,
    shared: RefCell<Rc<RefCell<Shared>>>,
    phase: Cell<Phase>,
    started: Cell<bool>,
    /// The state came from the previous generation (nothing to load).
    adopted: Cell<bool>,
    /// A newer generation took this one's state over in memory.
    handed_over: Cell<bool>,
    cancel: TransportCancellation,
    jobs: RefCell<tokio::task::JoinSet<()>>,
    /// Display names of the `route_learn` rules (rule tag -> `label`), set while
    /// compiling; an entry's `reason` is the rule tag.
    reason_labels: RefCell<HashMap<String, String>>,
}

/// The compiled plugin.
pub struct RouteLearnerConfig {
    pub tag: String,
    pub runtime: Rc<RouteLearner>,
}

/// The compiled `route_learn` rule dispatched as an external.
pub struct RouteLearnConfig {
    pub tag: String,
    pub executable: atomdns_sequence_core::ExecutableId,
    pub runtime: Rc<RouteLearn>,
}

impl RouteLearner {
    pub(crate) fn new(tag: &str, settings: Settings) -> Self {
        let tags = settings.categories.iter().map(|c| c.tag.clone()).collect();
        Self {
            tag: tag.to_owned(),
            settings: Arc::new(settings),
            shared: RefCell::new(Rc::new(RefCell::new(Shared::new(tags)))),
            phase: Cell::new(Phase::Running),
            started: Cell::new(false),
            adopted: Cell::new(false),
            handed_over: Cell::new(false),
            reason_labels: RefCell::new(HashMap::new()),
            cancel: TransportCancellation::new(),
            jobs: RefCell::new(tokio::task::JoinSet::new()),
        }
    }

    pub(crate) fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The index of a category tag.
    pub(crate) fn category_index(&self, tag: &str) -> Option<usize> {
        self.settings.categories.iter().position(|c| c.tag == tag)
    }

    /// The category tags, in order.
    pub(crate) fn category_tags(&self) -> impl Iterator<Item = &str> {
        self.settings.categories.iter().map(|c| c.tag.as_str())
    }

    /// Whether `/plugins/<tag>/…` belongs to this learner.
    pub(crate) fn owns(&self, tag: &str) -> bool {
        tag == self.tag || self.category_index(tag).is_some()
    }

    // ----- lookup and learning ---------------------------------------------------

    /// The learned facts of a presentation-form name (a trailing dot is
    /// ignored; compared in ASCII lower case). Expired entries are dropped.
    pub(crate) fn lookup(&self, presentation: &str) -> Option<LearnedHit> {
        let mut buffer = [0_u8; MAX_NAME];
        let key = normalise(presentation, &mut buffer)?;
        let shared = self.shared.borrow();
        let mut state = shared.borrow_mut();
        if state.cats.iter().all(HashMap::is_empty) {
            return None;
        }
        let now = state.now();
        let mut hit: Option<LearnedHit> = None;
        let mut expired = 0_u64;
        let mut touched = false;
        for (index, spec) in self.settings.categories.iter().enumerate() {
            if !spec.enabled {
                continue;
            }
            let map = &mut state.cats[index];
            let Some(entry) = map.get_mut(key) else {
                continue;
            };
            if now >= u64::from(entry.last) + spec.ttl {
                map.remove(key);
                expired += 1;
                continue;
            }
            entry.hits = entry.hits.saturating_add(1);
            touched = true;
            let found = hit.get_or_insert_with(|| LearnedHit {
                flags: 0,
                tags: String::new(),
                sources: String::new(),
            });
            if spec.mark < 64 {
                found.flags |= 1 << spec.mark;
            }
            found.tags = append_joined(&found.tags, &spec.label);
            found.sources = append_joined(&found.sources, &spec.source);
        }
        if expired > 0 {
            state.counters.expired += expired;
            state.changed = true;
        }
        if touched {
            state.hits_dirty = true;
        }
        hit
    }

    /// Confirms `qname` (DNS wire form) in `categories` on behalf of rule
    /// `reason`.
    pub(crate) fn learn(&self, categories: &[usize], reason: &str, qname_wire: &[u8]) {
        // A retired generation keeps learning for the queries it still runs when
        // its state moved to the next generation in memory; otherwise (saved to
        // the file already, or closed) nobody would see it.
        match self.phase.get() {
            Phase::Running => {}
            Phase::Fenced if self.handed_over.get() => {}
            _ => return,
        }
        let Some(presentation) = presentation_name(qname_wire) else {
            return;
        };
        let mut buffer = [0_u8; MAX_NAME];
        let Some(key) = normalise(&presentation, &mut buffer) else {
            return;
        };
        let shared = self.shared.borrow();
        let mut state = shared.borrow_mut();
        let now = state.now();
        let stamp = clamp_secs(now);
        let reason = state.intern(reason);
        for &index in categories {
            let Some(spec) = self.settings.categories.get(index) else {
                continue;
            };
            if !spec.enabled {
                continue;
            }
            let live = state.cats[index]
                .get(key)
                .map(|entry| now < u64::from(entry.last) + spec.ttl);
            match live {
                Some(true) => {
                    if let Some(entry) = state.cats[index].get_mut(key) {
                        entry.last = stamp;
                        entry.reason = reason;
                    }
                    state.counters.confirmed += 1;
                    state.changed = true;
                    continue;
                }
                Some(false) => {
                    state.cats[index].remove(key);
                    state.counters.expired += 1;
                }
                None => {}
            }
            if state.cats[index].len() >= spec.max_entries {
                make_room(&mut state, index, spec, now);
            }
            state.cats[index].insert(
                key.into(),
                Entry {
                    first: stamp,
                    last: stamp,
                    hits: 0,
                    reason,
                },
            );
            state.counters.learned += 1;
            state.changed = true;
        }
    }

    /// Removes every expired entry; returns how many.
    fn sweep(&self, state: &mut Shared, now: u64) -> usize {
        let mut removed = 0;
        for (index, spec) in self.settings.categories.iter().enumerate() {
            let before = state.cats[index].len();
            state.cats[index].retain(|_, entry| now < u64::from(entry.last) + spec.ttl);
            removed += before - state.cats[index].len();
        }
        if removed > 0 {
            state.counters.expired += removed as u64;
            state.changed = true;
        }
        removed
    }

    // ----- lifecycle ---------------------------------------------------------------

    /// Loads the state file (unless the previous generation handed its state
    /// over) and starts the periodic writer. Called when the host (or a newly
    /// installed view) starts serving.
    pub(crate) fn start(self: &Rc<Self>) {
        if self.started.replace(true) || self.phase.get() != Phase::Running {
            return;
        }
        if !self.adopted.get() {
            self.load();
        }
        let this = Rc::clone(self);
        self.jobs.borrow_mut().spawn_local(async move {
            this.run().await;
        });
    }

    /// Names a `route_learn` rule for display (`reason_label` of its entries).
    pub(crate) fn set_reason_label(&self, rule: &str, label: &str) {
        self.reason_labels
            .borrow_mut()
            .insert(rule.to_owned(), label.to_owned());
    }

    /// Takes over the live state of the previous generation's learner of the
    /// same tag, when both have the same categories. Returns whether it did.
    pub(crate) fn adopt(&self, previous: &RouteLearner) -> bool {
        if previous.settings.categories.len() != self.settings.categories.len()
            || previous
                .settings
                .categories
                .iter()
                .zip(&self.settings.categories)
                .any(|(a, b)| a.tag != b.tag)
        {
            return false;
        }
        *self.shared.borrow_mut() = Rc::clone(&previous.shared.borrow());
        self.adopted.set(true);
        previous.handed_over.set(true);
        self.trim_to_capacity();
        true
    }

    /// Keeps the most recently confirmed names of a category that holds more
    /// than its capacity (a settings change lowered `max_entries`).
    fn trim_to_capacity(&self) {
        let shared = self.shared.borrow();
        let mut state = shared.borrow_mut();
        for (index, spec) in self.settings.categories.iter().enumerate() {
            let len = state.cats[index].len();
            if len <= spec.max_entries {
                continue;
            }
            let mut lasts: Vec<u32> = state.cats[index].values().map(|entry| entry.last).collect();
            lasts.sort_unstable_by(|a, b| b.cmp(a));
            let cutoff = lasts[spec.max_entries - 1];
            state.cats[index].retain(|_, entry| entry.last >= cutoff);
            let mut excess = state.cats[index].len().saturating_sub(spec.max_entries);
            state.cats[index].retain(|_, entry| {
                if excess > 0 && entry.last == cutoff {
                    excess -= 1;
                    false
                } else {
                    true
                }
            });
            let removed = len - state.cats[index].len();
            state.counters.evicted += removed as u64;
            state.changed = true;
        }
    }

    /// A newer generation takes over: stop scheduling. Unless it adopted the
    /// state in memory, save it synchronously so the new generation loads it.
    pub(crate) fn fence(&self) {
        if self.phase.get() != Phase::Running {
            return;
        }
        self.phase.set(Phase::Fenced);
        self.cancel.cancel();
        if self.started.get() && !self.handed_over.get() {
            let (rows, seq) = self.snapshot(true);
            if let Err(error) = self.persist_now(&rows, seq) {
                crate::diag::error_line!("{}: final save failed: {error}", self.tag);
            }
        }
    }

    /// Stops the writer and, unless a newer generation took over, saves once
    /// more.
    pub(crate) async fn close(&self) {
        let was = self.phase.replace(Phase::Closed);
        self.cancel.cancel();
        let mut jobs = std::mem::take(&mut *self.jobs.borrow_mut());
        while jobs.join_next().await.is_some() {}
        if was == Phase::Running && self.started.get() {
            let wanted = {
                let shared = self.shared.borrow();
                let state = shared.borrow();
                state.changed || state.hits_dirty
            };
            if wanted {
                if let Err(error) = self.write(true).await {
                    crate::diag::error_line!("{}: final save failed: {error}", self.tag);
                }
            }
        }
    }

    async fn run(self: Rc<Self>) {
        let period = self.settings.write_interval;
        let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => return,
                _ = ticker.tick() => {}
            }
            {
                let shared = self.shared.borrow();
                let mut state = shared.borrow_mut();
                let now = state.now();
                self.sweep(&mut state, now);
            }
            if let Err(error) = self.write(false).await {
                crate::diag::error_line!("{}: periodic write failed: {error}", self.tag);
            }
        }
    }

    // ----- persistence ---------------------------------------------------------------

    /// Rows of the live (unexpired) entries, and the next write number.
    fn snapshot(&self, reset: bool) -> (Vec<Row>, u64) {
        let shared = self.shared.borrow();
        let mut state = shared.borrow_mut();
        let now = state.now();
        self.sweep(&mut state, now);
        let mut rows = Vec::with_capacity(state.total());
        for (index, map) in state.cats.iter().enumerate() {
            for (name, entry) in map {
                rows.push(Row {
                    category: index,
                    name: name.to_string(),
                    first: entry.first,
                    last: entry.last,
                    hits: entry.hits,
                    reason: state.reason(entry.reason).to_owned(),
                });
            }
        }
        if reset {
            state.changed = false;
            state.hits_dirty = false;
        }
        state.seq += 1;
        (rows, state.seq)
    }

    fn persist_now(&self, rows: &[Row], seq: u64) -> Result<(), String> {
        let last = Arc::clone(&self.shared.borrow().borrow().last_written);
        persist(&self.settings, &last, seq, rows)
    }

    /// One write: snapshot on this thread, file on the blocking pool. Without
    /// `force` nothing is written unless an entry changed.
    async fn write(&self, force: bool) -> Result<(), String> {
        {
            let shared = self.shared.borrow();
            let state = shared.borrow();
            if !force && !state.changed {
                return Ok(());
            }
        }
        let (rows, seq) = self.snapshot(true);
        let entries = rows.len();
        let settings = Arc::clone(&self.settings);
        let last = Arc::clone(&self.shared.borrow().borrow().last_written);
        let outcome = tokio::task::spawn_blocking(move || persist(&settings, &last, seq, &rows))
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
        let shared = self.shared.borrow();
        let mut state = shared.borrow_mut();
        let at = state.now();
        match &outcome {
            Ok(()) => {
                state.last_write = Some(WriteInfo {
                    at,
                    entries,
                    error: None,
                });
            }
            Err(error) => {
                // Retry at the next tick; the in-memory state is untouched.
                state.changed = true;
                state.last_write = Some(WriteInfo {
                    at,
                    entries,
                    error: Some(error.clone()),
                });
            }
        }
        outcome
    }

    fn load(&self) {
        let Ok(bytes) = std::fs::read(&self.settings.file) else {
            return;
        };
        let text = String::from_utf8_lossy(&bytes);
        let file: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                crate::diag::error_line!(
                    "{}: {} is unreadable ({error}); starting with no learned names",
                    self.tag,
                    self.settings.file.display()
                );
                return;
            }
        };
        if file.get("format").and_then(serde_json::Value::as_u64) != Some(STATE_FORMAT) {
            crate::diag::error_line!(
                "{}: {} has an unknown format; starting with no learned names",
                self.tag,
                self.settings.file.display()
            );
            return;
        }
        let Some(categories) = file
            .get("categories")
            .and_then(serde_json::Value::as_object)
        else {
            return;
        };
        let shared = self.shared.borrow();
        let mut state = shared.borrow_mut();
        let now = state.now();
        for (index, spec) in self.settings.categories.iter().enumerate() {
            let Some(rows) = categories
                .get(&spec.tag)
                .and_then(serde_json::Value::as_array)
            else {
                continue;
            };
            let mut loaded: Vec<(Box<str>, Entry)> = Vec::new();
            for row in rows {
                let Some(row) = row.as_array() else { continue };
                let (Some(name), Some(first), Some(last), Some(hits), Some(reason)) = (
                    row.first().and_then(serde_json::Value::as_str),
                    row.get(1).and_then(serde_json::Value::as_u64),
                    row.get(2).and_then(serde_json::Value::as_u64),
                    row.get(3).and_then(serde_json::Value::as_u64),
                    row.get(4).and_then(serde_json::Value::as_str),
                ) else {
                    continue;
                };
                let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
                if name.is_empty() || name.len() > MAX_NAME || now >= last + spec.ttl {
                    continue;
                }
                let reason = state.intern(reason);
                loaded.push((
                    name.into_boxed_str(),
                    Entry {
                        first: clamp_secs(first),
                        last: clamp_secs(last),
                        hits: u32::try_from(hits).unwrap_or(u32::MAX),
                        reason,
                    },
                ));
            }
            if loaded.len() > spec.max_entries {
                loaded.sort_by_key(|loaded| std::cmp::Reverse(loaded.1.last));
                loaded.truncate(spec.max_entries);
            }
            state.cats[index].extend(loaded);
        }
    }

    // ----- HTTP ------------------------------------------------------------------------

    /// `GET /plugins/<tag>/<action>` for the learner's own tag (`entries`,
    /// `status`) or one of its category tags (`show`, `save`, `flush`,
    /// `restartall`).
    pub(crate) async fn handle(&self, tag: &str, method: &str, action: &str, query: &str) -> Reply {
        let category = self.category_index(tag);
        let known = match category {
            Some(_) => matches!(action, "show" | "save" | "flush" | "restartall"),
            None => matches!(action, "entries" | "status"),
        };
        if !known {
            return text(404, "404 page not found\n");
        }
        if method != "GET" {
            return reply(405, None, Vec::new());
        }
        match (category, action) {
            (None, "entries") => self.entries(query),
            (None, _) => self.status(),
            (Some(index), "show") => self.show(index, query),
            (Some(_), "restartall") => text(
                501,
                "restart is not supported by this host; restart the service instead\n",
            ),
            (Some(_), _) if self.phase.get() != Phase::Running || !self.started.get() => {
                text(503, "host is applying configuration\n")
            }
            (Some(index), "flush") => {
                {
                    let shared = self.shared.borrow();
                    let mut state = shared.borrow_mut();
                    let cleared = state.cats[index].len() as u64;
                    state.cats[index] = HashMap::new();
                    state.counters.flushed += cleared;
                    state.changed = true;
                }
                match self.write(true).await {
                    Ok(()) => reply(200, Some(TEXT), b"domain_output flushed".to_vec()),
                    Err(error) => text(500, &format!("{error}\n")),
                }
            }
            (Some(_), _) => match self.write(false).await {
                Ok(()) => reply(200, Some(TEXT), b"domain_output saved".to_vec()),
                Err(error) => text(500, &format!("{error}\n")),
            },
        }
    }

    /// Live (unexpired) rows of a category filtered by a lower-case substring.
    fn rows(&self, index: usize, search: &str) -> Vec<(Box<str>, Entry)> {
        let spec = &self.settings.categories[index];
        let shared = self.shared.borrow();
        let state = shared.borrow();
        let now = state.now();
        state.cats[index]
            .iter()
            .filter(|(name, entry)| {
                now < u64::from(entry.last) + spec.ttl
                    && (search.is_empty() || name.contains(search))
            })
            .map(|(name, entry)| (name.clone(), *entry))
            .collect()
    }

    fn show(&self, index: usize, query: &str) -> Reply {
        let params = Query::parse(query);
        let search = params.get("q").unwrap_or_default().to_lowercase();
        let limit = match params.get("limit").and_then(|v| v.parse::<i64>().ok()) {
            Some(limit) if limit > 0 => usize::try_from(limit).unwrap_or(usize::MAX),
            _ => 100,
        };
        let offset = params
            .get("offset")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(0)
            .max(0);
        let offset = usize::try_from(offset).unwrap_or(usize::MAX);
        let mut rows = self.rows(index, &search);
        let total = rows.len();
        rows.sort_by(|a, b| b.1.hits.cmp(&a.1.hits).then_with(|| a.0.cmp(&b.0)));
        let mut body = String::new();
        for (name, entry) in rows.iter().skip(offset).take(limit) {
            body.push_str(&format!(
                "{:010} {} {name}\n",
                entry.hits,
                crate::local_time::local_date_at(i64::from(entry.last))
            ));
        }
        let mut response = reply(200, Some(TEXT), body.into_bytes());
        response.headers = vec![
            ("X-Total-Count", total.to_string()),
            ("Access-Control-Expose-Headers", "X-Total-Count".to_owned()),
        ];
        response
    }

    fn entries(&self, query: &str) -> Reply {
        let params = Query::parse(query);
        let search = params.get("q").unwrap_or_default().to_lowercase();
        let wanted = params.get("category").filter(|c| !c.is_empty());
        let indexes: Vec<usize> = match wanted {
            Some(tag) => match self.category_index(&tag) {
                Some(index) => vec![index],
                None => return text(404, "unknown category\n"),
            },
            None => (0..self.settings.categories.len()).collect(),
        };
        let sort = params.get("sort").unwrap_or_default();
        let descending = params.get("order").as_deref() != Some("asc");
        let limit = params
            .get("limit")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|limit| *limit > 0)
            .unwrap_or(DEFAULT_LIMIT)
            .min(MAX_LIMIT);
        let offset = params
            .get("offset")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        let mut rows: Vec<(usize, Box<str>, Entry)> = Vec::new();
        for index in indexes {
            for (name, entry) in self.rows(index, &search) {
                rows.push((index, name, entry));
            }
        }
        let total = rows.len();
        rows.sort_by(|a, b| {
            let order = match sort.as_str() {
                "last" => a.2.last.cmp(&b.2.last),
                "first" => a.2.first.cmp(&b.2.first),
                _ => a.2.hits.cmp(&b.2.hits),
            };
            let order = if descending { order.reverse() } else { order };
            order
                .then_with(|| a.0.cmp(&b.0))
                .then_with(|| a.1.cmp(&b.1))
        });
        let shared = self.shared.borrow();
        let state = shared.borrow();
        let labels = self.reason_labels.borrow();
        let entries: Vec<serde_json::Value> = rows
            .iter()
            .skip(offset)
            .take(limit)
            .map(|(index, name, entry)| {
                let spec = &self.settings.categories[*index];
                serde_json::json!({
                    "category": spec.tag,
                    "conclusion": spec.label,
                    "mark": spec.mark,
                    "name": &**name,
                    "reason": state.reason(entry.reason),
                    "reason_label": labels.get(state.reason(entry.reason)).map_or("", String::as_str),
                    "first_confirmed": rfc3339(u64::from(entry.first)),
                    "last_confirmed": rfc3339(u64::from(entry.last)),
                    "expires_at": rfc3339(u64::from(entry.last) + spec.ttl),
                    "hits": entry.hits,
                })
            })
            .collect();
        let body = serde_json::to_vec(&serde_json::json!({ "total": total, "entries": entries }))
            .unwrap_or_default();
        let mut response = reply(200, Some(JSON), body);
        response.headers = vec![
            ("X-Total-Count", total.to_string()),
            ("Access-Control-Expose-Headers", "X-Total-Count".to_owned()),
        ];
        response
    }

    fn status(&self) -> Reply {
        let shared = self.shared.borrow();
        let state = shared.borrow();
        let now = state.now();
        let categories: Vec<serde_json::Value> = self
            .settings
            .categories
            .iter()
            .enumerate()
            .map(|(index, spec)| {
                serde_json::json!({
                    "tag": spec.tag,
                    "label": spec.label,
                    "mark": spec.mark,
                    "enabled": spec.enabled,
                    "entries": state.cats[index].len(),
                    // Unexpired ones only (an expired row waits for the sweep).
                    "live_entries": state.cats[index]
                        .values()
                        .filter(|entry| now < u64::from(entry.last) + spec.ttl)
                        .count(),
                    "max_entries": spec.max_entries,
                    "ttl_seconds": spec.ttl,
                })
            })
            .collect();
        let last_write = state.last_write.as_ref().map(|info| {
            serde_json::json!({
                "at": rfc3339(info.at),
                "entries": info.entries,
                "error": info.error,
            })
        });
        let counters = state.counters;
        let body = serde_json::to_vec(&serde_json::json!({
            "file": self.settings.file.display().to_string(),
            "write_interval_seconds": self.settings.write_interval.as_secs(),
            "categories": categories,
            "counters": {
                "learned": counters.learned,
                "confirmed": counters.confirmed,
                "expired": counters.expired,
                "evicted": counters.evicted,
                "flushed": counters.flushed,
            },
            "last_write": last_write,
        }))
        .unwrap_or_default();
        reply(200, Some(JSON), body)
    }

    // ----- test access -----------------------------------------------------------------

    /// Test access: pretend `seconds` more have passed.
    #[doc(hidden)]
    pub fn advance_clock(&self, seconds: i64) {
        self.shared.borrow().borrow_mut().clock_shift += seconds;
    }

    /// Test access: the live entries of a category (name, hits).
    #[doc(hidden)]
    #[must_use]
    pub fn names(&self, category: &str) -> Vec<(String, u32)> {
        let Some(index) = self.category_index(category) else {
            return Vec::new();
        };
        let mut rows: Vec<(String, u32)> = self
            .rows(index, "")
            .into_iter()
            .map(|(name, entry)| (name.to_string(), entry.hits))
            .collect();
        rows.sort();
        rows
    }
}

/// One `route_learn` rule: when every `when` matcher holds, confirms the
/// query name in its categories.
pub struct RouteLearn {
    pub tag: String,
    learner: Rc<RouteLearner>,
    categories: Vec<usize>,
    /// The rule's tag, stored with every entry it confirms.
    reason: Box<str>,
    /// `(matcher, reversed)` in the configured order.
    when: Vec<(Box<dyn Matcher>, bool)>,
}

impl RouteLearn {
    pub(crate) fn new(
        tag: &str,
        learner: Rc<RouteLearner>,
        categories: Vec<usize>,
        when: Vec<(Box<dyn Matcher>, bool)>,
    ) -> Self {
        Self {
            tag: tag.to_owned(),
            learner,
            categories,
            reason: tag.into(),
            when,
        }
    }

    /// Evaluates the conditions against the current state and learns. A
    /// matcher error fails the query, as it would in a sequence rule.
    pub(crate) fn run(&self, state: &ExecutionState) -> Result<(), ExecutorError> {
        for (matcher, reverse) in &self.when {
            let outcome = matcher
                .evaluate(state)
                .map_err(|error| ExecutorError::new(format!("{}: {error:?}", self.tag)))?;
            if outcome.matched == *reverse {
                return Ok(());
            }
        }
        self.learner.learn(
            &self.categories,
            &self.reason,
            &state.query.question.qname_wire,
        );
        Ok(())
    }
}

// ----- helpers ---------------------------------------------------------------------------

/// The lower-case key of a presentation name without its trailing dot.
fn normalise<'a>(name: &str, buffer: &'a mut [u8; MAX_NAME]) -> Option<&'a str> {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() || name.len() > MAX_NAME || !name.is_ascii() {
        return None;
    }
    let slot = &mut buffer[..name.len()];
    slot.copy_from_slice(name.as_bytes());
    slot.make_ascii_lowercase();
    std::str::from_utf8(slot).ok()
}

fn clamp_secs(seconds: u64) -> u32 {
    u32::try_from(seconds).unwrap_or(u32::MAX)
}

fn rfc3339(seconds: u64) -> String {
    time::OffsetDateTime::from_unix_timestamp(i64::try_from(seconds).unwrap_or(i64::MAX))
        .ok()
        .and_then(|moment| {
            moment
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// Makes room in a full category: drop the expired entries, then the oldest
/// sixteenth by last confirmation.
fn make_room(state: &mut Shared, index: usize, spec: &CategorySpec, now: u64) {
    let before = state.cats[index].len();
    state.cats[index].retain(|_, entry| now < u64::from(entry.last) + spec.ttl);
    state.counters.expired += (before - state.cats[index].len()) as u64;
    let len = state.cats[index].len();
    if len < spec.max_entries {
        return;
    }
    let drop_count = (len / 16).max(1);
    let mut lasts: Vec<u32> = state.cats[index].values().map(|entry| entry.last).collect();
    let (_, cutoff, _) = lasts.select_nth_unstable(drop_count - 1);
    let cutoff = *cutoff;
    let mut removed = 0;
    state.cats[index].retain(|_, entry| {
        if removed < drop_count && entry.last <= cutoff {
            removed += 1;
            false
        } else {
            true
        }
    });
    state.counters.evicted += removed as u64;
    if state.counters.evicted == removed as u64 {
        crate::diag::warn_line!(
            "{}: category is full ({} names); the least recently confirmed names are dropped",
            spec.tag,
            spec.max_entries
        );
    }
}

struct Row {
    category: usize,
    name: String,
    first: u32,
    last: u32,
    hits: u32,
    reason: String,
}

/// `[name, first, last, hits, reason]` of the state file.
type StateRow<'a> = (&'a str, u32, u32, u32, &'a str);

#[derive(Serialize)]
struct StateFile<'a> {
    format: u64,
    saved_at: u64,
    categories: BTreeMap<&'a str, Vec<StateRow<'a>>>,
}

/// Writes the rows. A snapshot older than one already written is dropped.
fn persist(
    settings: &Settings,
    last_written: &Mutex<u64>,
    seq: u64,
    rows: &[Row],
) -> Result<(), String> {
    let mut categories: BTreeMap<&str, Vec<StateRow<'_>>> = settings
        .categories
        .iter()
        .map(|spec| (spec.tag.as_str(), Vec::new()))
        .collect();
    for row in rows {
        if let Some(spec) = settings.categories.get(row.category) {
            categories.entry(spec.tag.as_str()).or_default().push((
                &row.name,
                row.first,
                row.last,
                row.hits,
                &row.reason,
            ));
        }
    }
    for list in categories.values_mut() {
        list.sort_by(|a, b| a.0.cmp(b.0));
    }
    let saved_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let bytes = serde_json::to_vec(&StateFile {
        format: STATE_FORMAT,
        saved_at,
        categories,
    })
    .map_err(|error| error.to_string())?;
    let mut guard = last_written
        .lock()
        .map_err(|_| "write lock poisoned".to_owned())?;
    if seq <= *guard {
        return Ok(());
    }
    write_file(&settings.file, &bytes)
        .map_err(|error| format!("{}: {error}", settings.file.display()))?;
    *guard = seq;
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    crate::rule_sources::write_atomically(path, bytes)
}

fn reply(status: u16, content_type: Option<&'static str>, body: Vec<u8>) -> Reply {
    Reply {
        status,
        content_type,
        body,
        headers: Vec::new(),
    }
}

fn text(status: u16, body: &str) -> Reply {
    reply(status, Some(TEXT), body.as_bytes().to_vec())
}

/// A decoded query string: the first value of each name wins.
struct Query(Vec<(String, String)>);

impl Query {
    fn parse(query: &str) -> Self {
        let mut pairs: Vec<(String, String)> = Vec::new();
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if !pairs.iter().any(|(have, _)| have == name) {
                pairs.push((name.to_owned(), decode(value)));
            }
        }
        Self(pairs)
    }

    fn get(&self, name: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(have, _)| have == name)
            .map(|(_, value)| value.clone())
    }
}

fn decode(value: &str) -> String {
    let value = value.replace('+', " ");
    crate::api::decode_plugin_tag(&value).map_or(value.clone(), std::borrow::Cow::into_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn spec(tag: &str, mark: u8, label: &str, ttl: u64, max_entries: usize) -> CategorySpec {
        CategorySpec {
            tag: tag.to_owned(),
            mark,
            label: label.to_owned(),
            source: format!("{tag}-source"),
            ttl,
            max_entries,
            enabled: true,
        }
    }

    fn learner(file: PathBuf, categories: Vec<CategorySpec>) -> Rc<RouteLearner> {
        Rc::new(RouteLearner::new(
            "learner",
            Settings {
                target_mapper: "m".to_owned(),
                file,
                write_interval: Duration::from_secs(3600),
                categories,
            },
        ))
    }

    fn two(file: PathBuf) -> Rc<RouteLearner> {
        learner(
            file,
            vec![
                spec("special", 4, "SPECIAL", 1000, 100),
                spec("direct", 11, "DIRECT", 100, 100),
            ],
        )
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("route-learner-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn names_are_normalised_and_the_lookup_merges_categories_in_order() {
        let l = two(PathBuf::from("unused.json"));
        let reason = "rule";
        l.learn(&[1], reason, &wire("Mixed.Example"));
        l.learn(&[0, 1], reason, &wire("both.example"));
        let hit = l.lookup("MIXED.example.").unwrap();
        assert_eq!(hit.flags, 1 << 11);
        assert_eq!(hit.tags, "DIRECT");
        assert_eq!(hit.sources, "direct-source");
        let both = l.lookup("both.example.").unwrap();
        assert_eq!(both.flags, (1 << 4) | (1 << 11));
        assert_eq!(both.tags, "SPECIAL|DIRECT");
        assert_eq!(both.sources, "special-source|direct-source");
        assert!(l.lookup("other.example.").is_none());
        // The root and an empty name are never recorded.
        l.learn(&[0], reason, &[0]);
        assert_eq!(l.names("special"), [("both.example".to_owned(), 1)]);
    }

    #[test]
    fn entries_expire_individually_from_their_last_confirmation() {
        let l = two(PathBuf::from("unused.json"));
        let reason = "rule";
        l.learn(&[1], reason, &wire("a.example"));
        l.advance_clock(60);
        l.learn(&[1], reason, &wire("b.example"));
        l.advance_clock(50);
        // a: 110 s old (ttl 100) -> gone; b: 50 s old -> alive.
        assert!(l.lookup("a.example.").is_none());
        assert!(l.lookup("b.example.").is_some());
        // A confirmation restarts the clock.
        l.learn(&[1], reason, &wire("b.example"));
        l.advance_clock(60);
        assert!(l.lookup("b.example.").is_some());
        l.advance_clock(50);
        assert!(l.lookup("b.example.").is_none());
        // Expired entries are learned afresh: first and hits restart.
        l.learn(&[1], reason, &wire("b.example"));
        assert_eq!(l.names("direct"), [("b.example".to_owned(), 0)]);
    }

    #[test]
    fn a_full_category_drops_expired_then_the_oldest_entries() {
        let l = learner(
            PathBuf::from("unused.json"),
            vec![spec("direct", 11, "DIRECT", 1000, 32)],
        );
        let reason = "rule";
        for index in 0..32 {
            l.advance_clock(1);
            l.learn(&[0], reason, &wire(&format!("n{index}.example")));
        }
        assert_eq!(l.names("direct").len(), 32);
        l.learn(&[0], reason, &wire("new.example"));
        let names = l.names("direct");
        // 32 / 16 = 2 oldest dropped, one added.
        assert_eq!(names.len(), 31);
        assert!(names.iter().any(|(name, _)| name == "new.example"));
        assert!(!names.iter().any(|(name, _)| name == "n0.example"));
        assert!(!names.iter().any(|(name, _)| name == "n1.example"));
        assert!(names.iter().any(|(name, _)| name == "n2.example"));
    }

    #[test]
    fn a_disabled_category_neither_learns_nor_answers() {
        let mut off = spec("direct", 11, "DIRECT", 100, 10);
        off.enabled = false;
        let l = learner(PathBuf::from("unused.json"), vec![off]);
        let reason = "rule";
        l.learn(&[0], reason, &wire("a.example"));
        assert!(l.lookup("a.example.").is_none());
        assert!(l.names("direct").is_empty());
    }

    #[test]
    fn hits_count_in_memory_and_the_state_round_trips_through_the_file() {
        let dir = scratch("roundtrip");
        let file = dir.join("gen/state.json");
        let first = two(file.clone());
        let reason = "learn_x";
        first.learn(&[1], reason, &wire("a.example"));
        first.learn(&[0], reason, &wire("b.example"));
        for _ in 0..3 {
            first.lookup("a.example.");
        }
        let (rows, seq) = first.snapshot(true);
        first.persist_now(&rows, seq).unwrap();
        let second = two(file.clone());
        second.load();
        assert_eq!(second.names("direct"), [("a.example".to_owned(), 3)]);
        assert_eq!(second.names("special"), [("b.example".to_owned(), 0)]);
        let reply = second.entries("category=direct");
        let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["entries"][0]["reason"], "learn_x");
        // An older snapshot never overwrites a newer file.
        let stale = first.persist_now(&[], seq);
        assert!(stale.is_ok());
        let again = two(file);
        again.load();
        assert_eq!(again.names("direct").len(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn loading_skips_expired_garbage_and_unknown_categories_and_trims_to_capacity() {
        let dir = scratch("load");
        let file = dir.join("state.json");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = serde_json::json!({
            "format": 1,
            "saved_at": now,
            "categories": {
                "direct": [
                    ["old.example", now - 500, now - 500, 1, "r"],
                    ["a.example", now - 40, now - 30, 2, "r"],
                    ["b.example", now - 40, now - 20, 2, "r"],
                    ["c.example", now - 40, now - 10, 2, "r"],
                    [7, "bad"],
                    "junk"
                ],
                "gone": [["x.example", now, now, 0, "r"]]
            }
        });
        std::fs::write(&file, body.to_string()).unwrap();
        let l = learner(file.clone(), vec![spec("direct", 11, "DIRECT", 100, 2)]);
        l.load();
        // Capacity 2 keeps the two most recently confirmed.
        let names: Vec<String> = l.names("direct").into_iter().map(|n| n.0).collect();
        assert_eq!(names, ["b.example", "c.example"]);
        // A damaged file or an unknown format starts empty.
        std::fs::write(&file, "{not json").unwrap();
        let broken = learner(file.clone(), vec![spec("direct", 11, "DIRECT", 100, 2)]);
        broken.load();
        assert!(broken.names("direct").is_empty());
        std::fs::write(&file, r#"{"format":9,"categories":{}}"#).unwrap();
        broken.load();
        assert!(broken.names("direct").is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn adoption_keeps_the_most_recently_confirmed_names_within_a_lowered_capacity() {
        let old = two(PathBuf::from("unused.json"));
        for name in ["a.example", "b.example"] {
            old.learn(&[1], "rule", &wire(name));
        }
        old.shared.borrow().borrow_mut().clock_shift = 5;
        for name in ["c.example", "d.example"] {
            old.learn(&[1], "rule", &wire(name));
        }
        let new = learner(
            PathBuf::from("unused.json"),
            vec![
                spec("special", 4, "SPECIAL", 1000, 100),
                spec("direct", 11, "DIRECT", 100, 2),
            ],
        );
        assert!(new.adopt(&old));
        let kept: Vec<String> = new
            .names("direct")
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(kept, ["c.example", "d.example"]);
        // Ties on the cut are broken by count, never by keeping too many.
        let tied = two(PathBuf::from("unused.json"));
        for name in ["a.example", "b.example", "c.example", "d.example"] {
            tied.learn(&[1], "rule", &wire(name));
        }
        let small = learner(
            PathBuf::from("unused.json"),
            vec![
                spec("special", 4, "SPECIAL", 1000, 100),
                spec("direct", 11, "DIRECT", 100, 3),
            ],
        );
        assert!(small.adopt(&tied));
        assert_eq!(small.names("direct").len(), 3);
    }

    #[test]
    fn adoption_shares_the_live_state_and_needs_the_same_categories() {
        let old = two(PathBuf::from("unused.json"));
        let reason = "rule";
        old.learn(&[1], reason, &wire("a.example"));
        let new = two(PathBuf::from("unused.json"));
        assert!(new.adopt(&old));
        assert_eq!(new.names("direct"), [("a.example".to_owned(), 0)]);
        // A learn on the retired generation lands in the same state.
        old.learn(&[1], reason, &wire("b.example"));
        assert_eq!(new.names("direct").len(), 2);
        let other = learner(
            PathBuf::from("unused.json"),
            vec![spec("direct", 11, "DIRECT", 100, 10)],
        );
        assert!(!other.adopt(&old));
        // The retired generation keeps learning into the shared state, and a
        // generation whose state was not handed over does not.
        old.fence();
        old.learn(&[1], reason, &wire("c.example"));
        assert_eq!(new.names("direct").len(), 3);
        let alone = two(PathBuf::from("unused.json"));
        alone.fence();
        alone.learn(&[1], reason, &wire("d.example"));
        assert!(alone.names("direct").is_empty());
    }
}
