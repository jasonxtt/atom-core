//! File-backed `domain_set` providers, and the persistence fault and gate the
//! cache tests arm.
//!
//! atom fork: the providers were writable through AtomDNS's plugin routes
//! (`/plugins/{tag}/save|post`), which atom step 6 removed; a provider is now
//! the rules its file held at load.

use std::fmt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use atomdns_matcher_core::MixMatcher;

/// Which step of the safe same-directory replacement fails.
///
/// Production never arms a fault. A test arms one to prove that old file bytes
/// and the old generation survive and that the temporary file is removed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PersistFault {
    /// Replace normally.
    #[default]
    None,
    /// Create the temporary file, then fail before it is complete.
    WriteTemp,
    /// Finish the temporary file, then fail instead of the final rename.
    Rename,
}

/// A test-only gate that parks the blocking persistence step so a test can
/// prove that a DNS reader is still served while an update is in flight.
///
/// The wait is bounded: if persistence were (wrongly) running on the DNS
/// runtime thread, the bound turns a hang into an ordinary test failure.
#[derive(Clone)]
pub struct PersistGate {
    state: Arc<(Mutex<bool>, Condvar)>,
    arrived: Arc<AtomicUsize>,
    bound: Duration,
}

impl PersistGate {
    /// A gate that parks persistence for at most three seconds per waiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new((Mutex::new(false), Condvar::new())),
            arrived: Arc::new(AtomicUsize::new(0)),
            bound: Duration::from_secs(3),
        }
    }

    /// True once at least one persistence step has entered the gate.
    #[must_use]
    pub fn arrived(&self) -> bool {
        self.arrived.load(Ordering::SeqCst) > 0
    }

    /// Releases every waiter immediately.
    pub fn release(&self) {
        let (lock, condvar) = &*self.state;
        let mut released = lock.lock().unwrap_or_else(|error| error.into_inner());
        *released = true;
        condvar.notify_all();
    }

    pub(crate) fn wait(&self) {
        self.arrived.fetch_add(1, Ordering::SeqCst);
        let (lock, condvar) = &*self.state;
        let mut released = lock.lock().unwrap_or_else(|error| error.into_inner());
        while !*released {
            let (guard, timeout) = condvar
                .wait_timeout(released, self.bound)
                .unwrap_or_else(|error| error.into_inner());
            released = guard;
            if timeout.timed_out() {
                return;
            }
        }
    }
}

impl Default for PersistGate {
    fn default() -> Self {
        Self::new()
    }
}

/// One immutable published generation: the accepted rule text and the compiled
/// matcher built from exactly those rules.
pub(crate) struct DomainSetGeneration {
    rules: Vec<String>,
    matcher: Rc<MixMatcher<()>>,
}

impl DomainSetGeneration {
    pub(crate) fn new(rules: Vec<String>, matcher: MixMatcher<()>) -> Self {
        Self {
            rules,
            matcher: Rc::new(matcher),
        }
    }
}

/// One managed provider keyed by its configured tag.
pub struct ManagedDomainSet {
    tag: String,
    file: PathBuf,
    source_path: String,
    generation: Rc<DomainSetGeneration>,
}

impl ManagedDomainSet {
    pub(crate) fn new(
        tag: String,
        file: PathBuf,
        source_path: String,
        rules: Vec<String>,
        matcher: MixMatcher<()>,
    ) -> Self {
        Self {
            tag,
            file,
            source_path,
            generation: Rc::new(DomainSetGeneration::new(rules, matcher)),
        }
    }

    #[must_use]
    pub fn tag(&self) -> &str {
        &self.tag
    }

    #[must_use]
    pub fn file(&self) -> &Path {
        &self.file
    }

    #[must_use]
    pub fn source_path(&self) -> &str {
        &self.source_path
    }

    /// The accepted rule text of the current generation.
    #[must_use]
    pub fn rules(&self) -> Vec<String> {
        self.generation.rules.clone()
    }

    /// The number of accepted rules in the current generation.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.generation.matcher.len()
    }

    /// True when the matcher accepts `domain`.
    #[must_use]
    pub fn matches(&self, domain: &str) -> bool {
        self.generation.matcher.r#match(domain).is_some()
    }
}

impl fmt::Debug for ManagedDomainSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedDomainSet")
            .field("tag", &self.tag)
            .field("file", &self.file)
            .field("rules", &self.rule_count())
            .finish()
    }
}

/// One query-time handle for a compiled `domain_set`. Query-only shapes read a
/// fixed startup matcher; managed shapes read the provider's current
/// generation at every evaluation.
#[derive(Clone)]
pub(crate) enum DomainSetHandle {
    Fixed(Rc<MixMatcher<()>>),
    Managed(Rc<ManagedDomainSet>),
    /// `adguard_rule`: matches when no allow rule matches and a block rule
    /// does. A hot reload publishes a new generation.
    Filtered(Rc<crate::rule_sources::Live<crate::config::providers::Filtered>>),
}

impl DomainSetHandle {
    pub(crate) fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Fixed(matcher) => matcher.r#match(domain).is_some(),
            Self::Managed(provider) => provider.matches(domain),
            Self::Filtered(live) => {
                let set = live.get();
                !set.allow.is_match(domain) && set.deny.is_match(domain)
            }
        }
    }

    /// True for the sets that match the reference's presentation-form name.
    pub(crate) fn uses_presentation_name(&self) -> bool {
        matches!(self, Self::Filtered(_))
    }

    pub(crate) fn rule_count(&self) -> usize {
        match self {
            Self::Fixed(matcher) => matcher.len(),
            Self::Managed(provider) => provider.rule_count(),
            Self::Filtered(live) => {
                let set = live.get();
                set.allow.len() + set.deny.len()
            }
        }
    }
}
