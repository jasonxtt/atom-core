//! atom fork: the binding ledger (atom `docs/design.md` §4.5).
//!
//! sing-box binds a group to a name only when a FakeIP query carries an
//! EDNS0 65001 directive, and clients keep their FakeIP for a while. So the
//! ledger remembers, per name, the last directive sing-box acknowledged
//! (SET a tag, or CLEAR), LRU-bounded. After a rule or ruleset change every
//! remembered name is decided again by the new table and each name whose
//! directive changes gets it at once, in a plain DNS query to sing-box's
//! `dns-in`: a client holding the FakeIP follows the new rules without
//! asking DNS again.
//!
//! The new directive of a name: a proxy rule → SET its group; a direct
//! rule → SET `direct`, a block rule → SET `block` (sing-box's own
//! outbounds: the held FakeIP goes direct or is refused at once); no rule
//! (the original judgment, which cannot be decided offline) → CLEAR, left
//! to `route.final`. Rules with a `client` condition are skipped: they are
//! direct or block only, their queries never reach sing-box, so the binding
//! is what every other client gets.
//!
//! The ledger is process-wide: it outlives configuration reloads, not a
//! restart. It is cleared when the FakeIP range changes (sing-box drops
//! every mapping and binding then).

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::atom_rules::{AtomRules, Verdict};
use crate::config::CompiledConfig;

/// The most names the ledger remembers (about 100 bytes each).
pub(crate) const CAPACITY: usize = 16384;
/// sing-box's own outbounds a direct or block decision binds to (generated
/// in every configuration, `atom_singbox.rs`).
const DIRECT: &str = "direct";
const BLOCK: &str = "block";
/// Directives in flight at once.
const WINDOW: usize = 32;
const TIMEOUT: Duration = Duration::from_secs(1);
const ATTEMPTS: usize = 2;

/// The directive sing-box last acknowledged for a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Binding {
    Set(Arc<str>),
    Clear,
}

impl Binding {
    fn tag(&self) -> Option<&str> {
        match self {
            Self::Set(tag) => Some(tag),
            Self::Clear => None,
        }
    }
}

/// Names (the query's wire name, as sent: sing-box keeps the case) and
/// their bindings, least recently recorded first out.
pub(crate) struct Lru {
    capacity: usize,
    tick: u64,
    entries: HashMap<Vec<u8>, (Binding, u64)>,
    order: BTreeMap<u64, Vec<u8>>,
}

impl Lru {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tick: 0,
            entries: HashMap::new(),
            order: BTreeMap::new(),
        }
    }

    /// Records `binding` for `name` as the most recent entry, dropping the
    /// least recent one beyond the capacity.
    pub(crate) fn record(&mut self, name: &[u8], binding: Binding) {
        self.tick += 1;
        if let Some((_, tick)) = self.entries.get(name) {
            self.order.remove(tick);
        }
        self.entries.insert(name.to_vec(), (binding, self.tick));
        self.order.insert(self.tick, name.to_vec());
        while self.entries.len() > self.capacity {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    #[cfg(test)]
    pub(crate) fn get(&self, name: &[u8]) -> Option<&Binding> {
        self.entries.get(name).map(|(binding, _)| binding)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    /// Every entry, least recent first.
    pub(crate) fn snapshot(&self) -> Vec<(Vec<u8>, Binding)> {
        self.order
            .values()
            .filter_map(|name| Some((name.clone(), self.entries.get(name)?.0.clone())))
            .collect()
    }
}

/// The directive a decision of the table means for sing-box.
pub(crate) fn wanted(verdict: Option<Verdict>) -> Binding {
    match verdict {
        Some(Verdict::Proxy(group)) => Binding::Set(group),
        Some(Verdict::Direct) => Binding::Set(Arc::from(DIRECT)),
        Some(Verdict::Block) => Binding::Set(Arc::from(BLOCK)),
        None => Binding::Clear,
    }
}

/// The entries whose directive changes under `decide`, with the new one.
pub(crate) fn plan(
    entries: &[(Vec<u8>, Binding)],
    decide: impl Fn(&[u8]) -> Option<Verdict>,
) -> Vec<(Vec<u8>, Binding)> {
    entries
        .iter()
        .filter_map(|(name, old)| {
            let new = wanted(decide(name));
            (new != *old).then(|| (name.clone(), new))
        })
        .collect()
}

/// The outcome of the latest recomputation (process-wide).
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SyncRecord {
    pub(crate) at: i64,
    pub(crate) trigger: String,
    /// Names whose directive changed.
    pub(crate) changed: usize,
    /// Of those, the ones sing-box did not acknowledge (kept as they were,
    /// tried again by the next recomputation).
    pub(crate) failed: usize,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) error: String,
}

static LEDGER: LazyLock<Mutex<Lru>> = LazyLock::new(|| Mutex::new(Lru::new(CAPACITY)));
static LAST: Mutex<Option<SyncRecord>> = Mutex::new(None);
/// One recomputation at a time: a later one starts from what the earlier
/// one left and decides with the newest table.
static RESYNC: LazyLock<tokio::sync::Mutex<()>> = LazyLock::new(|| tokio::sync::Mutex::new(()));

fn ledger() -> std::sync::MutexGuard<'static, Lru> {
    LEDGER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether a reply of sing-box's FakeIP DNS confirms the directive: a
/// response with NOERROR (sing-box answers with an error when it cannot
/// save the binding).
pub(crate) fn acknowledges(reply: &[u8]) -> bool {
    reply.len() >= 12 && reply[2] & 0x80 != 0 && reply[3] & 0x0f == 0
}

/// Records a directive sing-box answered (the FakeIP upstream's queries;
/// `outbound` `None` is CLEAR).
pub(crate) fn record(name: &[u8], outbound: Option<&str>) {
    let binding = match outbound {
        Some(tag) => Binding::Set(Arc::from(tag)),
        None => Binding::Clear,
    };
    ledger().record(name, binding);
}

/// Forgets every name (the FakeIP range changed).
pub(crate) fn clear() {
    ledger().clear();
}

/// `{size, capacity, last}` for `GET status`.
pub(crate) fn view() -> serde_json::Value {
    let last = LAST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    serde_json::json!({ "size": ledger().len(), "capacity": CAPACITY, "last": last })
}

/// Decides every remembered name again with `rules`' current table and
/// sends each changed directive to sing-box. A directive sing-box does not
/// acknowledge leaves the entry as it was. Without a proxy side nothing is
/// done.
pub(crate) async fn resync(config: &CompiledConfig, rules: &AtomRules, trigger: &str) {
    // The builtin sets a mapper marks: what it would set for the name.
    let mapper = rules.mapper.as_deref().and_then(|tag| {
        config
            .domain_mappers
            .iter()
            .find(|mapper| mapper.tag == tag)
    });
    let fast_flags = |name: &[u8]| mapper.map_or(0, |mapper| mapper.evaluate_wire(name).fast_flags);
    if let Some(done) = resync_with(&LEDGER, rules, fast_flags, trigger).await {
        if done.failed > 0 {
            crate::diag::warn_line!(
                "atom ledger: {} of {} directives to sing-box failed: {}",
                done.failed,
                done.changed,
                done.error
            );
        }
        *LAST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(done);
    }
}

/// [`resync`] on `ledger`, with the fast marks of a name from
/// `fast_flags`; `None`: nothing changed (or no proxy side).
async fn resync_with(
    ledger: &Mutex<Lru>,
    rules: &AtomRules,
    fast_flags: impl Fn(&[u8]) -> u64,
    trigger: &str,
) -> Option<SyncRecord> {
    let lock = || {
        ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    };
    let dns_in = rules.proxy_host()?.dns_in;
    let _serial = RESYNC.lock().await;
    let entries = lock().snapshot();
    let changes = plan(&entries, |name| rules.decide(name, fast_flags(name)));
    if changes.is_empty() {
        return None;
    }
    let (acknowledged, error) = send_all(dns_in, &changes).await;
    {
        let mut ledger = lock();
        for (index, (name, binding)) in changes.iter().enumerate() {
            if acknowledged[index] {
                ledger.record(name, binding.clone());
            }
        }
    }
    Some(SyncRecord {
        at: crate::atom_rules::now(),
        trigger: trigger.to_owned(),
        changed: changes.len(),
        failed: acknowledged.iter().filter(|ok| !**ok).count(),
        error,
    })
}

/// A query for `name` A carrying `binding` (the same form a FakeIP query of
/// a client takes on its way to sing-box, [`crate::edns_directive`]).
pub(crate) fn directive_query(id: u16, name: &[u8], binding: &Binding) -> Option<Vec<u8>> {
    let mut wire = id.to_be_bytes().to_vec();
    wire.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    wire.extend_from_slice(name);
    wire.extend_from_slice(&[0, 1, 0, 1]);
    crate::edns_directive::outgoing_query(&wire, true, binding.tag())
        .ok()
        .map(std::borrow::Cow::into_owned)
}

/// Sends every directive (at most [`WINDOW`] in flight, each tried
/// [`ATTEMPTS`] times) and returns which ones sing-box answered, with the
/// last error.
async fn send_all(dns_in: SocketAddr, changes: &[(Vec<u8>, Binding)]) -> (Vec<bool>, String) {
    let mut acknowledged = vec![false; changes.len()];
    let local: SocketAddr = if dns_in.is_ipv4() {
        ([127, 0, 0, 1], 0).into()
    } else {
        (std::net::Ipv6Addr::LOCALHOST, 0).into()
    };
    let socket = match tokio::net::UdpSocket::bind(local).await {
        Ok(socket) => socket,
        Err(error) => return (acknowledged, format!("bind: {error}")),
    };
    if let Err(error) = socket.connect(dns_in).await {
        return (acknowledged, format!("connect {dns_in}: {error}"));
    }
    let mut seed = [0u8; 2];
    let _ = getrandom::fill(&mut seed);
    // IDs stay distinct within one call (fewer than 65536 sends).
    let mut next_id = u16::from_be_bytes(seed);
    let mut error = String::new();
    let mut todo: Vec<usize> = (0..changes.len()).collect();
    for _ in 0..ATTEMPTS {
        for window in todo.chunks(WINDOW) {
            let mut waiting: HashMap<u16, usize> = HashMap::new();
            for &index in window {
                let (name, binding) = &changes[index];
                let id = next_id;
                next_id = next_id.wrapping_add(1);
                let Some(query) = directive_query(id, name, binding) else {
                    error = "invalid directive query".to_owned();
                    continue;
                };
                match socket.send(&query).await {
                    Ok(_) => {
                        waiting.insert(id, index);
                    }
                    Err(e) => error = format!("send: {e}"),
                }
            }
            let deadline = tokio::time::Instant::now() + TIMEOUT;
            let mut buffer = vec![0u8; 4096];
            while !waiting.is_empty() {
                match tokio::time::timeout_at(deadline, socket.recv(&mut buffer)).await {
                    Ok(Ok(len)) => {
                        let reply = &buffer[..len];
                        if len >= 12 {
                            if let Some(index) =
                                waiting.remove(&u16::from_be_bytes([reply[0], reply[1]]))
                            {
                                if acknowledges(reply) {
                                    acknowledged[index] = true;
                                } else {
                                    error = format!(
                                        "sing-box refused the directive (rcode {})",
                                        reply[3] & 0x0f
                                    );
                                }
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        // A refused port reports on the next receive.
                        error = format!("receive: {e}");
                        break;
                    }
                    Err(_) => {
                        error = format!("no answer from {dns_in} within {TIMEOUT:?}");
                        break;
                    }
                }
            }
        }
        todo.retain(|&index| !acknowledged[index]);
        if todo.is_empty() {
            return (acknowledged, String::new());
        }
    }
    (acknowledged, error)
}

#[cfg(test)]
#[path = "atom_ledger_tests.rs"]
mod tests;
