//! atom fork: the dry run of one query (`POST /api/v1/atom/rules/dryrun`,
//! atom `docs/design.md` §8): what the main flow would do with an A or
//! AAAA query for a name now, step by step, without leaving a trace.
//!
//! It drives the live generation's own compiled entry sequence with the
//! sequence machine, so the order, the matchers and the fixtures (the
//! mapper, the rule table, `fast_mark`, ...) are the real ones. Only the host
//! side of the dispatches differs ([`Dry::dispatch`]):
//!
//! - caches are passed by: never read, never written (the result is what a
//!   fresh judgment gives); the ones the query would use are listed;
//! - `route_learn` only says what it would learn; nothing is learned;
//! - `domain_output` (the top domains) records nothing;
//! - `rewrite` looks its rule up; a domain target is resolved as the
//!   plugin does (its sequence, dry like the rest, or its fixed server);
//! - the FakeIP upstream (sing-box) is not asked: no SET or CLEAR, no
//!   binding ledger entry; the query is answered with an empty NOERROR;
//! - every other upstream is really asked, past the caches, with the
//!   query the flow would send (ECS included), on a private attempt ledger
//!   and a private copy of the upstream rotation: nothing reaches the query
//!   log, the statistics or the upstream counters, and the next real query
//!   picks its upstream as it would have;
//! - learner lookups made by the mapper while the machine runs are
//!   read-only ([`crate::route_learner::peeking`]).
//!
//! The steps the answer lists are read off the rules the machine evaluated
//! ([`Recorder`]); the presentation (which rule is which step) is the only
//! part written for the dry run.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atomdns_sequence_core::{
    CancellationToken, ClientContext, ClientTransport, ExecutableId, ExecutionCompletion,
    ExecutionControl, ExecutionMachine, ExecutionState, ExecutorOutcome, MachineStep,
    ResponseState, RootFuelHandle, SequenceId, StepTrace,
};
use atomdns_upstream_core::TransportCancellation;
use serde_json::{Value, json};

use crate::assembly::ForwardCatalog;
use crate::atom_rules::{AtomRules, RuleCheck};
use crate::config::CompiledConfig;
use crate::execution::{ExchangeExecutor, QueryView, ScopedQueryPolicy};

/// The request budget of a front query (`execution.rs`).
const FUEL: u64 = 256;

/// One dry-run request.
pub(crate) struct Request {
    pub(crate) domain: String,
    pub(crate) client: Option<IpAddr>,
    /// 1 (A) or 28 (AAAA).
    pub(crate) qtype: u16,
}

/// One rule the machine evaluated: its position, whether every matcher
/// matched, and each matcher's result in order (to the first that failed).
#[derive(Debug)]
struct RuleEvent {
    sequence: SequenceId,
    pc: usize,
    matched: bool,
    matchers: Vec<(String, bool)>,
}

/// The step trace of a dry run. `muted` while the reference branch of
/// `prefer_ipv4` runs: only the main question's steps are shown.
#[derive(Default)]
struct Recorder {
    muted: Cell<bool>,
    pending: RefCell<Vec<(String, bool)>>,
    events: RefCell<Vec<RuleEvent>>,
    /// The `atom_rules` fixture's tag, and each rule as it was checked
    /// right before the fixture ran (the same table it ran on).
    rules_tag: String,
    rules: Option<Rc<AtomRules>>,
    checks: RefCell<Option<Vec<(crate::atom_rules::Rule, RuleCheck)>>>,
}

impl std::fmt::Debug for Recorder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Recorder")
            .field("events", &self.events)
            .finish_non_exhaustive()
    }
}

impl StepTrace for Recorder {
    fn matcher(&self, _sequence: &str, name: &str, matched: bool, _state: &ExecutionState) {
        if !self.muted.get() {
            self.pending.borrow_mut().push((name.to_owned(), matched));
        }
    }

    fn plugin(&self, _sequence: &str, name: &str, state: &ExecutionState) {
        // The fixture runs next, in this same synchronous step: no write
        // can replace the table in between.
        if !self.muted.get() && name == self.rules_tag && self.checks.borrow().is_none() {
            if let Some(rules) = &self.rules {
                *self.checks.borrow_mut() = Some(rules.explain(state));
            }
        }
    }

    fn rule(&self, sequence: SequenceId, pc: usize, matched: bool) {
        let matchers = std::mem::take(&mut *self.pending.borrow_mut());
        if !self.muted.get() {
            self.events.borrow_mut().push(RuleEvent {
                sequence,
                pc,
                matched,
                matchers,
            });
        }
    }
}

/// One upstream the dry run asked.
#[derive(Clone)]
struct Exchange {
    group: String,
    entry: Option<String>,
    ecs: Option<String>,
    rcode: Option<u8>,
    ips: Vec<IpAddr>,
    error: Option<String>,
}

/// A rewrite rule's answer: its target and what the answer holds.
#[derive(Clone)]
struct Rewritten {
    target: String,
    ips: Vec<IpAddr>,
    /// `None`: the lookup of a domain target failed (SERVFAIL).
    rcode: Option<u8>,
}

/// What the dispatches did (the main question's; not the reference
/// branch's).
#[derive(Default)]
struct Facts {
    /// `None`: not reached; `Some(None)`: no rule; `Some(Some(hit))`.
    rewrite: Option<Option<Rewritten>>,
    /// The caches the query would use, by label.
    caches: Vec<String>,
    upstreams: Vec<Exchange>,
    /// The FakeIP upstream was reached, with the rule's group (`None`:
    /// CLEAR, Final).
    fakeip: Option<Option<Arc<str>>>,
    would_learn: Vec<String>,
    /// The ECS subnet of the queries that follow.
    ecs: Option<String>,
    /// `prefer_ipv4` answered AAAA with an empty response.
    preferred_away: Option<&'static str>,
}

struct Outcome {
    state: ExecutionState,
    completion: Option<ExecutionCompletion>,
    error: Option<String>,
}

struct Dry<'a> {
    config: &'a CompiledConfig,
    forwards: &'a ForwardCatalog,
    recorder: Rc<Recorder>,
    facts: RefCell<Facts>,
    deadline: Instant,
    cancellation: TransportCancellation,
    /// The reference branch reached the FakeIP upstream (a FakeIP A answer).
    reference_fakeip: Cell<bool>,
    /// The dry run's own copy of the upstream rotation (shared with the
    /// reference branch of `prefer_ipv4`).
    rotation: Rc<Cell<u64>>,
}

type Step = Result<MachineStep, atomdns_sequence_core::ExecutionError>;

/// Every synchronous machine call runs with read-only learner lookups.
fn quiet(work: impl FnOnce() -> Step) -> Step {
    crate::route_learner::peeking(work)
}

impl<'a> Dry<'a> {
    fn muted(&self) -> bool {
        self.recorder.muted.get()
    }

    fn drive<'s>(
        &'s self,
        mut machine: ExecutionMachine<'a>,
        view: QueryView,
    ) -> Pin<Box<dyn Future<Output = Outcome> + 's>>
    where
        'a: 's,
    {
        Box::pin(async move {
            let mut step = quiet(|| machine.step());
            loop {
                let current = match step {
                    Ok(current) => current,
                    Err(error) => {
                        return Outcome {
                            state: machine.state().clone(),
                            completion: None,
                            error: Some(format!("{error:?}")),
                        };
                    }
                };
                step = match current {
                    MachineStep::Complete(completion) => {
                        return Outcome {
                            state: machine.state().clone(),
                            completion: Some(completion),
                            error: None,
                        };
                    }
                    // No cache is watched, so no boundary is ever reported;
                    // answered as the owner would anyway.
                    MachineStep::ScopeComplete(completion) | MachineStep::ScopeAborted(completion) => {
                        quiet(|| machine.resume_scope_completion(completion.token()))
                    }
                    MachineStep::Dispatch(dispatch) => {
                        let executable = dispatch.executable();
                        match self.dispatch(&mut machine, executable, &view).await {
                            Ok(outcome) => quiet(|| machine.resume(executable, Ok(outcome))),
                            Err(error) => {
                                return Outcome {
                                    state: machine.state().clone(),
                                    completion: None,
                                    error: Some(error),
                                };
                            }
                        }
                    }
                };
            }
        })
    }

    /// The host side of one dispatch, without its side effects.
    async fn dispatch(
        &self,
        machine: &mut ExecutionMachine<'a>,
        executable: ExecutableId,
        view: &QueryView,
    ) -> Result<ExecutorOutcome, String> {
        let config = self.config;
        let local = &config.local;
        if config.sleeps.iter().any(|sleep| sleep.executable == executable)
            || local.domain_outputs.iter().any(|output| output.executable == executable)
        {
            return Ok(ExecutorOutcome::Continue);
        }
        if let Some(learn) = local.learns.iter().find(|learn| learn.executable == executable) {
            let labels = learn
                .runtime
                .would_learn(machine.state())
                .map_err(|error| format!("{error:?}"))?;
            if !self.muted() {
                let mut facts = self.facts.borrow_mut();
                for label in labels {
                    if !facts.would_learn.contains(&label) {
                        facts.would_learn.push(label);
                    }
                }
            }
            return Ok(ExecutorOutcome::Continue);
        }
        if let Some(rewrite) = local.rewrites.iter().find(|rewrite| rewrite.executable == executable) {
            let Some(target) = rewrite.runtime.peek(&machine.state().query.question.qname_wire) else {
                if !self.muted() {
                    self.facts.borrow_mut().rewrite = Some(None);
                }
                return Ok(ExecutorOutcome::Continue);
            };
            let qtype = view.question.qtype;
            // `rewrite.rs` `run`: an address of the query's family, or an
            // empty NOERROR; a domain target asked of its DNS server.
            let hit = match target {
                crate::rewrite::Target::Ip(ip) => Rewritten {
                    target: ip.to_string(),
                    ips: if matches!((ip, qtype), (IpAddr::V4(_), 1) | (IpAddr::V6(_), 28)) {
                        vec![ip]
                    } else {
                        Vec::new()
                    },
                    rcode: Some(0),
                },
                crate::rewrite::Target::Domain(domain) => {
                    if rewrite.sequence.is_some() {
                        self.resolve_rewrite(&domain, qtype, rewrite.sequence).await
                    } else {
                        // A fixed or named DNS server: asked as `rewrite.rs`
                        // does (a plain query, no state of this process), on
                        // a copy of the state.
                        let mut copy = machine.state().clone();
                        let answered = rewrite
                            .runtime
                            .run(&mut copy, &view.raw, self.deadline, &[], None)
                            .await;
                        let mut hit = Rewritten {
                            target: domain.trim_end_matches('.').to_owned(),
                            ips: Vec::new(),
                            rcode: Some(0),
                        };
                        match (answered, &copy.response) {
                            (crate::rewrite::RewriteEnd::Answered, ResponseState::Raw(wire)) => {
                                hit.ips = atomdns_dns_core::observe_answer_addresses(wire.as_bytes())
                                    .unwrap_or_default();
                            }
                            _ => hit.rcode = None,
                        }
                        hit
                    }
                }
            };
            if !self.muted() {
                self.facts.borrow_mut().rewrite = Some(Some(hit));
            }
            // A rule answers the query: the chain is accepted.
            return Ok(ExecutorOutcome::Accept);
        }
        if let Some(policy) = config
            .response_policies
            .iter()
            .find(|policy| policy.executable == executable)
        {
            if let Some(target) = crate::execution::query_policy_target(&policy.policy, machine.state()) {
                let original = machine.state().query.clone();
                let scoped = match &target {
                    ScopedQueryPolicy::Redirect(name) => view.redirect(name),
                    ScopedQueryPolicy::Ecs(ecs) => view.with_ecs(ecs, original.client),
                }
                .map_err(|error| format!("{error:?}"))?;
                if matches!(target, ScopedQueryPolicy::Ecs(_)) && !self.muted() {
                    self.facts.borrow_mut().ecs = ecs_text(&scoped.raw);
                }
                let mut successor = machine
                    .fork_successor(CancellationToken::new())
                    .map_err(|error| format!("{error:?}"))?;
                successor.state_mut().query.header = scoped.header;
                successor.state_mut().query.question = scoped.question.clone();
                let mut outcome = self.drive(successor, scoped).await;
                if let Some(error) = outcome.error {
                    return Err(error);
                }
                outcome.state.query = original;
                *machine.state_mut() = outcome.state;
                return Ok(if outcome.completion == Some(ExecutionCompletion::Exited) {
                    ExecutorOutcome::Exit
                } else {
                    ExecutorOutcome::Accept
                });
            }
            crate::policy::apply_wire_policy(&policy.policy, machine.state_mut(), &view.raw)
                .map_err(|error| format!("{error:?}"))?;
            return Ok(ExecutorOutcome::Continue);
        }
        if config.fallbacks.iter().any(|policy| policy.executable == executable) {
            return Err("试运行不支持 fallback".to_owned());
        }
        if let Some(preference) = config
            .preferences
            .iter()
            .find(|preference| preference.executable == executable)
        {
            return self.prefer(machine, preference, view).await;
        }
        if let Some(cache) = config.cache_for_executable(executable) {
            if !self.muted() {
                let name = if cache.label.is_empty() {
                    cache.tag.clone()
                } else {
                    cache.label.clone()
                };
                let mut facts = self.facts.borrow_mut();
                if !facts.caches.contains(&name) {
                    facts.caches.push(name);
                }
            }
            return Ok(ExecutorOutcome::Continue);
        }
        if self.forwards.is_fakeip(executable) {
            if self.muted() {
                self.reference_fakeip.set(true);
            } else {
                self.facts.borrow_mut().fakeip = Some(machine.state().outbound.clone());
            }
            machine
                .state_mut()
                .set_synthesized_response(0)
                .map_err(|error| format!("{error:?}"))?;
            return Ok(ExecutorOutcome::Continue);
        }
        self.exchange(machine, executable, view).await
    }

    /// A rewrite's domain target, resolved as `rewrite.rs` does through its
    /// sequence (`dns: $sequence_local_in`), dry like the rest and without a
    /// client; only A/AAAA are resolved.
    async fn resolve_rewrite(
        &self,
        domain: &str,
        qtype: u16,
        sequence: Option<SequenceId>,
    ) -> Rewritten {
        let mut hit = Rewritten {
            target: domain.trim_end_matches('.').to_owned(),
            ips: Vec::new(),
            rcode: Some(0),
        };
        if !matches!(qtype, 1 | 28) {
            return hit;
        }
        let Some(sequence) = sequence else {
            hit.rcode = None;
            return hit;
        };
        let started = (|| {
            let raw = query_wire(domain, qtype).ok()?;
            let (header, question) = atomdns_dns_core::parse_query(&raw).ok()?;
            let control = ExecutionControl::with_shared_budget(
                RootFuelHandle::new(FUEL),
                CancellationToken::new(),
            );
            let machine = ExecutionMachine::new(
                &self.config.program,
                sequence,
                ExecutionState::new(header, question.clone()),
                control,
            )
            .ok()?;
            Some((machine, QueryView::new(raw, header, question)))
        })();
        let Some((machine, view)) = started else {
            hit.rcode = None;
            return hit;
        };
        let was_muted = self.recorder.muted.replace(true);
        // `rewrite.rs` gives the lookup at most five seconds.
        let outcome = tokio::time::timeout(Duration::from_secs(5), self.drive(machine, view)).await;
        self.recorder.muted.set(was_muted);
        let Ok(outcome) = outcome else {
            hit.rcode = None;
            return hit;
        };
        match (&outcome.error, &outcome.state.response) {
            (None, ResponseState::Raw(wire)) if wire.as_bytes().get(3).is_some_and(|b| b & 0x0f == 0) => {
                hit.ips = atomdns_dns_core::observe_answer_addresses(wire.as_bytes())
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|ip| matches!((ip, qtype), (IpAddr::V4(_), 1) | (IpAddr::V6(_), 28)))
                    .collect();
            }
            // A failed lookup or a non-NOERROR answer is SERVFAIL.
            _ => hit.rcode = None,
        }
        hit
    }

    /// Asks a real upstream, past the caches, on a private attempt ledger.
    async fn exchange(
        &self,
        machine: &mut ExecutionMachine<'a>,
        executable: ExecutableId,
        view: &QueryView,
    ) -> Result<ExecutorOutcome, String> {
        let group = self
            .config
            .forward_invocations
            .iter()
            .find(|invocation| invocation.executable == executable)
            .and_then(|invocation| self.config.forward_definitions.get(invocation.definition))
            .map(|definition| definition.tag.clone())
            .or_else(|| crate::execution::upstream_identity(self.config, executable))
            .unwrap_or_default();
        let ledger = crate::observer::UpstreamAttemptLedger::default().into_shared();
        let exchange = self
            .forwards
            .with_rotation(&self.rotation, || {
                self.forwards.exchange_invocation(
                    executable,
                    &view.raw,
                    self.deadline,
                    self.cancellation.child_token(),
                    ledger,
                )
            })
            .await;
        let ecs = self.facts.borrow().ecs.clone();
        let mut record = Exchange {
            group,
            entry: None,
            ecs,
            rcode: None,
            ips: Vec::new(),
            error: None,
        };
        let wire = match &exchange {
            Ok(batch) => {
                record.entry = batch.selected_entry.and_then(|entry| {
                    crate::execution::invocation_identity(self.config, executable, entry)
                });
                crate::execution::qualify_response(
                    batch.response.wire(),
                    view.header.id,
                    &view.question,
                )
            }
            Err(_) => None,
        };
        let outcome = match wire {
            Some(wire) => {
                record.rcode = wire.get(3).map(|byte| byte & 0x0f);
                record.ips = atomdns_dns_core::observe_answer_addresses(&wire).unwrap_or_default();
                machine.state_mut().set_raw_response(wire);
                Ok(ExecutorOutcome::Continue)
            }
            None => {
                let reason = match exchange {
                    Err(error) => format!("{error:?}"),
                    Ok(_) => "应答和问题不符".to_owned(),
                };
                record.error = Some(reason.clone());
                Err(format!("上游 {} 失败：{reason}", record.group))
            }
        };
        if !self.muted() {
            self.facts.borrow_mut().upstreams.push(record);
        }
        outcome
    }

    /// `prefer_ipv4` / `prefer_ipv6` (`execution.rs` `run_preference`): the
    /// preferred type runs on; the other one is answered empty when the
    /// remembered evidence or the reference query of the preferred type has
    /// an answer of that type. Nothing is remembered.
    async fn prefer(
        &self,
        machine: &mut ExecutionMachine<'a>,
        preference: &crate::config::PreferenceConfig,
        view: &QueryView,
    ) -> Result<ExecutorOutcome, String> {
        let preferred = match preference.family {
            crate::config::PreferenceFamily::Ipv4 => 1,
            crate::config::PreferenceFamily::Ipv6 => 28,
        };
        let qtype = view.question.qtype;
        if qtype == preferred || !matches!(qtype, 1 | 28) {
            return Ok(ExecutorOutcome::Continue);
        }
        let key = crate::execution::preference_cache_key(&view.question);
        let now = preference.clock.now();
        let remembered = preference
            .evidence
            .borrow()
            .get(&key)
            .is_some_and(|expiry| *expiry > now);
        if remembered {
            if !self.muted() {
                self.facts.borrow_mut().preferred_away = Some("remembered");
            }
            machine
                .state_mut()
                .set_synthesized_response(0)
                .map_err(|error| format!("{error:?}"))?;
            return Ok(ExecutorOutcome::Accept);
        }
        let successor = machine
            .fork_successor(CancellationToken::new())
            .map_err(|error| format!("{error:?}"))?;
        let original = successor
            .fork_branch(CancellationToken::new())
            .map_err(|error| format!("{error:?}"))?;
        let mut reference = successor
            .fork_branch(CancellationToken::new())
            .map_err(|error| format!("{error:?}"))?;
        reference.state_mut().set_response(ResponseState::None);
        let reference_raw = crate::execution::rewrite_query_qtype(&view.raw, preferred)
            .ok_or_else(|| "preference query rewrite failed".to_owned())?;
        let (header, question) = atomdns_dns_core::parse_query(&reference_raw)
            .map_err(|error| format!("{error:?}"))?;
        reference.state_mut().query.question = question.clone();
        let reference_view = QueryView::new(reference_raw, header, question);
        // The reference branch runs on its own muted recorder and facts, at
        // the same time as the original one (the steps shown are the
        // original's); it shares the rotation copy.
        let child = Dry {
            config: self.config,
            forwards: self.forwards,
            recorder: Rc::new(Recorder {
                muted: Cell::new(true),
                ..Recorder::default()
            }),
            facts: RefCell::new(Facts::default()),
            deadline: self.deadline,
            cancellation: self.cancellation.child_token(),
            reference_fakeip: Cell::new(false),
            rotation: Rc::clone(&self.rotation),
        };
        let control = std::mem::replace(reference.control_mut(), ExecutionControl::with_fuel(0));
        *reference.control_mut() =
            control.with_step_trace(Rc::clone(&child.recorder) as Rc<dyn StepTrace>);
        let answered = |other: &Outcome| {
            other.error.is_none()
                && (child.reference_fakeip.get()
                    || matches!(&other.state.response, ResponseState::Raw(wire)
                        if crate::execution::response_has_type(wire.as_bytes(), preferred)))
        };
        // `run_preference`: the reference wins as soon as it has an answer
        // of the preferred type; once the original ends, the reference gets
        // 500 ms more.
        let mut first_branch = self.drive(original, view.clone());
        let mut reference_branch = child.drive(reference, reference_view);
        let mut first: Option<Outcome> = None;
        let mut other: Option<Outcome> = None;
        let wait = tokio::time::sleep(Duration::from_secs(31_536_000));
        tokio::pin!(wait);
        let preferred_answer = loop {
            if other.as_ref().is_some_and(&answered) {
                break true;
            }
            if first.is_some() && other.is_some() {
                break false;
            }
            tokio::select! {
                biased;
                outcome = &mut first_branch, if first.is_none() => {
                    first = Some(outcome);
                    let left = self.deadline.saturating_duration_since(Instant::now());
                    wait.as_mut().reset(tokio::time::Instant::now() + left.min(Duration::from_millis(500)));
                }
                outcome = &mut reference_branch, if other.is_none() => other = Some(outcome),
                () = &mut wait, if first.is_some() && other.is_none() => break false,
            }
        };
        drop(first_branch);
        drop(reference_branch);
        if preferred_answer {
            if !self.muted() {
                self.facts.borrow_mut().preferred_away = Some("reference");
            }
            machine
                .state_mut()
                .set_synthesized_response(0)
                .map_err(|error| format!("{error:?}"))?;
            return Ok(ExecutorOutcome::Accept);
        }
        let Some(first) = first else {
            return Err("preference branch did not finish".to_owned());
        };
        if let Some(error) = first.error {
            return Err(error);
        }
        *machine.state_mut() = first.state;
        Ok(if first.completion == Some(ExecutionCompletion::Exited) {
            ExecutorOutcome::Exit
        } else {
            ExecutorOutcome::Accept
        })
    }
}

/// The ECS subnet a query carries, `address/source`.
fn ecs_text(raw: &[u8]) -> Option<String> {
    let subnet = crate::ecs::query_opt(raw).ok()??.ecs?;
    let ip = match subnet.family {
        1 => {
            let mut octets = [0u8; 4];
            for (slot, byte) in octets.iter_mut().zip(&subnet.address) {
                *slot = *byte;
            }
            IpAddr::from(octets)
        }
        2 => {
            let mut octets = [0u8; 16];
            for (slot, byte) in octets.iter_mut().zip(&subnet.address) {
                *slot = *byte;
            }
            IpAddr::from(octets)
        }
        _ => return None,
    };
    Some(format!("{ip}/{}", subnet.source))
}

/// The query a client would send: RD, one question, EDNS (1232).
fn query_wire(domain: &str, qtype: u16) -> Result<Vec<u8>, String> {
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    let mut name = Name::from_utf8(domain).map_err(|_| format!("`{domain}` 不是域名"))?;
    name.set_fqdn(true);
    let mut id = [0u8; 2];
    let _ = getrandom::fill(&mut id);
    let mut message = Message::new();
    message
        .set_id(u16::from_be_bytes(id))
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(name, RecordType::from(qtype)));
    let mut edns = Edns::new();
    edns.set_max_payload(1232);
    message.set_edns(edns);
    message.to_vec().map_err(|error| error.to_string())
}

/// Runs the dry run of `request` on `config` (the live generation) and its
/// upstreams. `Err`: the request itself is unusable (400).
pub(crate) async fn run(
    config: &CompiledConfig,
    forwards: &ForwardCatalog,
    rules: &AtomRules,
    request: &Request,
    request_deadline: Duration,
) -> Result<Value, String> {
    let raw = query_wire(&request.domain, request.qtype)?;
    let (header, question) =
        atomdns_dns_core::parse_query(&raw).map_err(|_| format!("`{}` 不是域名", request.domain))?;
    let entry = config
        .program
        .sequences
        .iter()
        .find(|sequence| !sequence.synthetic && sequence.name == config.listener.entry)
        .map_or(config.sequence.sequence, |sequence| sequence.id);
    let recorder = Rc::new(Recorder {
        rules_tag: config.local.atom_rules_tag.clone(),
        rules: config.local.atom_rules.clone(),
        ..Recorder::default()
    });
    let mut state = ExecutionState::new(header, question.clone());
    if let Some(client) = request.client {
        state.query.client = ClientContext::from_peer(client, ClientTransport::Udp);
    }
    let control = ExecutionControl::with_shared_budget(
        RootFuelHandle::new(FUEL),
        CancellationToken::new(),
    )
    .with_step_trace(recorder.clone() as Rc<dyn StepTrace>);
    let dry = Dry {
        config,
        forwards,
        recorder: Rc::clone(&recorder),
        facts: RefCell::new(Facts::default()),
        // The budget a front query gets (`HostOptions::request_deadline`).
        deadline: Instant::now() + request_deadline,
        cancellation: TransportCancellation::new(),
        reference_fakeip: Cell::new(false),
        rotation: Rc::new(Cell::new(forwards.rotation_now())),
    };
    let machine = ExecutionMachine::new(&config.program, entry, state, control)
        .map_err(|error| format!("{error:?}"))?;
    let outcome = dry.drive(machine, QueryView::new(raw, header, question)).await;
    let facts = dry.facts.into_inner();
    let mut view = present(config, rules, request, &recorder, &facts, &outcome);
    if let Some(start) = view["conclusion"]["outbound"].as_str().map(str::to_owned) {
        match crate::atom_proxy_api::outbound_chain(rules, &start).await {
            Ok(chain) => view["conclusion"]["chain"] = chain.into(),
            Err(error) => view["conclusion"]["chain_error"] = error.into(),
        }
    }
    Ok(view)
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

/// What a rule of the flow is, for the steps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Rewrite,
    BlockQtypes,
    BlockAaaa,
    PreferV4,
    Rules,
    /// A fast-mark branch: learned no-V4/V6, geosite, remembered proxy or
    /// direct (the key and name of the step).
    Mark(&'static str),
    /// A rule of the probe (its response checks).
    Probe,
}

/// The original-judgment branch keys the WebUI's `original.ts` uses.
fn branch_of(key: &str) -> &'static str {
    match key {
        "no_v4" | "no_v6" => "empty",
        "geosite_no_cn" => "geosite_no_cn",
        "geosite_cn" => "geosite_cn",
        "remember_proxy" => "remember_proxy",
        "remember_direct" => "remember_direct",
        _ => "rest",
    }
}

fn step_name(key: &str) -> &'static str {
    match key {
        "rewrite" => "重写",
        "block_qtypes" => "类型屏蔽",
        "block_aaaa" => "IPv6 屏蔽",
        "prefer_v4" => "IPv4 优先",
        "rules" => "规则表",
        "no_v4" => "学到的无 V4",
        "no_v6" => "学到的无 V6",
        "geosite_no_cn" => "geosite 非国内",
        "geosite_cn" => "geosite 国内",
        "remember_proxy" => "记忆代理",
        "remember_direct" => "记忆直连",
        _ => "其余 · 探测",
    }
}

/// `anonymous_match(kind: args)` (`config.rs` `matcher_trace_name`), and
/// whether it is `not(...)`.
fn parse_matcher(name: &str) -> (bool, String, String) {
    let (reverse, inner) = match name.strip_prefix("not(").and_then(|rest| rest.strip_suffix(')')) {
        Some(inner) => (true, inner),
        None => (false, name),
    };
    match inner
        .strip_prefix("anonymous_match(")
        .and_then(|rest| rest.strip_suffix(')'))
        .and_then(|rest| rest.split_once(": "))
    {
        Some((kind, args)) => (reverse, kind.to_owned(), args.to_owned()),
        None => (reverse, String::new(), inner.to_owned()),
    }
}

/// The fast marks of the original branches: the learner's categories and
/// the mapper's geosite sets.
fn mark_keys(config: &CompiledConfig, rules: &AtomRules) -> Vec<(u8, &'static str)> {
    let mut keys = Vec::new();
    for learner in &config.local.learners {
        for category in &learner.runtime.settings().categories {
            let key = match category.tag.as_str() {
                "my_nov4list" => "no_v4",
                "my_nov6list" => "no_v6",
                "my_fakeiplist" => "remember_proxy",
                "my_realiplist" => "remember_direct",
                _ => continue,
            };
            keys.push((category.mark, key));
        }
    }
    for (name, key) in [("geosite_no_cn", "geosite_no_cn"), ("geosite_cn", "geosite_cn")] {
        if let Some(mask) = rules.builtin_mask(name) {
            if mask != 0 {
                keys.push((mask.trailing_zeros() as u8, key));
            }
        }
    }
    keys
}

fn classify(
    config: &CompiledConfig,
    marks: &[(u8, &'static str)],
    rules_tag: &str,
    event: &RuleEvent,
) -> Option<Kind> {
    let rule = config
        .program
        .sequence(event.sequence)?
        .rules
        .get(event.pc)?;
    let names: Vec<&str> = rule.matchers.iter().map(|m| m.name.as_str()).collect();
    let plugin = rule.plugin_name.as_deref().unwrap_or("");
    let has = |text: &str| names.iter().any(|name| *name == text);
    if config.local.rewrites.iter().any(|rewrite| rewrite.tag == plugin) && names.is_empty() {
        return Some(Kind::Rewrite);
    }
    if has("anonymous_match(flag: block_qtypes)") {
        return Some(Kind::BlockQtypes);
    }
    if has("anonymous_match(flag: block_aaaa)") {
        return Some(Kind::BlockAaaa);
    }
    if has("anonymous_match(flag: prefer_v4)") {
        return Some(Kind::PreferV4);
    }
    if plugin == rules_tag && names.is_empty() {
        return Some(Kind::Rules);
    }
    if let Some((false, kind, args)) = names.first().map(|name| parse_matcher(name)) {
        if kind == "fast_mark" {
            if let Some((_, key)) = marks
                .iter()
                .find(|(mark, _)| args.trim() == mark.to_string())
            {
                return Some(Kind::Mark(key));
            }
        }
    }
    if names
        .iter()
        .any(|name| matches!(parse_matcher(name).1.as_str(), "resp_ip" | "rcode"))
    {
        return Some(Kind::Probe);
    }
    None
}

/// Why a rule did not match: its first failing matcher, in a few words.
fn miss_reason(config: &CompiledConfig, event: &RuleEvent, step: &str) -> String {
    let Some((name, _)) = event.matchers.iter().find(|(_, matched)| !matched) else {
        return "未命中".to_owned();
    };
    let (reverse, kind, args) = parse_matcher(name);
    match kind.as_str() {
        "flag" => {
            let (key, option) = args.split_once('=').map_or((args.as_str(), None), |(k, o)| (k, Some(o)));
            let label = config
                .flags
                .iter()
                .find(|flag| flag.key == key)
                .map_or(key.to_owned(), |flag| flag.label.clone());
            match option {
                Some(option) if !reverse => format!("{label}不是 {option}"),
                _ if reverse => format!("{label}开"),
                _ => format!("{label}关"),
            }
        }
        "qtype" => "查询类型不符".to_owned(),
        "fast_mark" => match step {
            "no_v4" | "no_v6" | "remember_proxy" | "remember_direct" => "没有记录".to_owned(),
            _ => "不在名单".to_owned(),
        },
        _ => "未命中".to_owned(),
    }
}

fn rcode_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".to_owned(),
        2 => "SERVFAIL".to_owned(),
        3 => "NXDOMAIN".to_owned(),
        5 => "REFUSED".to_owned(),
        other => format!("RCODE {other}"),
    }
}

fn exchange_view(exchange: &Exchange) -> Value {
    json!({
        "upstream": exchange.group,
        "entry": exchange.entry,
        "ecs": exchange.ecs,
        "rcode": exchange.rcode.map(rcode_name),
        "ips": exchange.ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "error": exchange.error,
    })
}

#[allow(clippy::too_many_lines)]
fn present(
    config: &CompiledConfig,
    rules: &AtomRules,
    request: &Request,
    recorder: &Recorder,
    facts: &Facts,
    outcome: &Outcome,
) -> Value {
    let marks = mark_keys(config, rules);
    let events = recorder.events.borrow();
    let mut steps: Vec<Value> = Vec::new();
    let index_of = |steps: &mut Vec<Value>, key: &str| -> usize {
        if let Some(at) = steps.iter().position(|step| step["key"] == key) {
            return at;
        }
        steps.push(json!({ "key": key, "name": step_name(key), "result": "miss", "detail": "" }));
        steps.len() - 1
    };
    // Per step: the first rule decides the reason; any matched rule a hit.
    let mut branch: Option<&'static str> = None;
    let mut last_hit: Option<String> = None;
    let mut probe_reason: Option<String> = None;
    let mut rules_reached = false;
    for event in events.iter() {
        let Some(kind) = classify(config, &marks, &recorder.rules_tag, event) else {
            continue;
        };
        let key: String = match kind {
            Kind::Rewrite => "rewrite".into(),
            Kind::BlockQtypes => "block_qtypes".into(),
            Kind::BlockAaaa => "block_aaaa".into(),
            Kind::PreferV4 => {
                if request.qtype != 28 {
                    continue;
                }
                "prefer_v4".into()
            }
            Kind::Rules => {
                rules_reached = true;
                "rules".into()
            }
            // The learned empty answer of the other type does not apply.
            Kind::Mark("no_v4") if request.qtype != 1 => continue,
            Kind::Mark("no_v6") if request.qtype != 28 => continue,
            Kind::Mark(key) => key.into(),
            Kind::Probe => "rest".into(),
        };
        let fresh = !steps.iter().any(|step| step["key"] == key.as_str());
        let at = index_of(&mut steps, &key);
        if kind == Kind::Probe {
            if event.matched && probe_reason.is_none() {
                probe_reason = event.matchers.iter().find_map(|(name, _)| {
                    let (reverse, kind, args) = parse_matcher(name);
                    (kind == "resp_ip" && !reverse).then(|| match args.trim() {
                        "$direct_ip" => "direct_ip".to_owned(),
                        "$geoip_cn" => "国内 IP".to_owned(),
                        "0.0.0.0/0" => "其他 IPv4".to_owned(),
                        "2000::/3" => "其他 IPv6".to_owned(),
                        other => other.trim_start_matches('$').to_owned(),
                    })
                });
            }
            continue;
        }
        if event.matched {
            if steps[at]["result"] != "hit" {
                steps[at]["result"] = "hit".into();
                steps[at]["detail"] = "".into();
            }
            if let Kind::Mark(key) = kind {
                branch.get_or_insert(branch_of(key));
            }
            last_hit = Some(key.clone());
        } else if fresh {
            steps[at]["detail"] = miss_reason(config, event, &key).into();
        }
    }

    // The rewrite step: what its lookup found.
    if let Some(found) = &facts.rewrite {
        let at = index_of(&mut steps, "rewrite");
        match found {
            Some(hit) => {
                steps[at]["result"] = "hit".into();
                steps[at]["detail"] = format!("→ {}", hit.target).into();
            }
            None => {
                steps[at]["result"] = "miss".into();
                steps[at]["detail"] = "未命中".into();
            }
        }
    }
    let rewritten = matches!(facts.rewrite, Some(Some(_)));

    // The rule table: every rule up to the hit.
    let mut rule_hit: Option<crate::atom_rules::Rule> = None;
    if let Some(checks) = recorder.checks.borrow().as_ref() {
        rule_hit = checks
            .iter()
            .find(|(_, check)| *check == RuleCheck::Hit)
            .map(|(rule, _)| rule.clone());
        let at = index_of(&mut steps, "rules");
        let list: Vec<Value> = checks
            .iter()
            .enumerate()
            .map(|(index, (rule, check))| {
                json!({
                    "index": index,
                    "id": rule.id,
                    "remark": rule.remark,
                    "status": match check {
                        RuleCheck::Hit => "hit",
                        RuleCheck::Miss => "miss",
                        RuleCheck::Off => "off",
                        RuleCheck::SingBox => "singbox",
                    },
                })
            })
            .collect();
        steps[at]["rules"] = list.into();
        match &rule_hit {
            Some(rule) => {
                steps[at]["result"] = "hit".into();
                steps[at]["rule"] = serde_json::to_value(rule).unwrap_or_default();
                steps[at]["detail"] = format!(
                    "第 {} 条 · {}",
                    checks.len(),
                    if rule.remark.is_empty() { &rule.id } else { &rule.remark }
                )
                .into();
            }
            None => {
                steps[at]["result"] = "miss".into();
                steps[at]["detail"] = "没有规则命中".into();
            }
        }
    } else if rules_reached {
        let at = index_of(&mut steps, "rules");
        steps[at]["detail"] = "没有规则命中".into();
    }

    // The original judgment's remaining branch: the probe.
    let probed = rule_hit.is_none()
        && !rewritten
        && branch.is_none()
        && facts.preferred_away.is_none()
        && (facts.fakeip.is_some() || !facts.upstreams.is_empty() || probe_reason.is_some());
    if probed {
        branch = Some("rest");
        let at = index_of(&mut steps, "rest");
        steps[at]["result"] = "hit".into();
        let mut detail = Vec::new();
        if let Some(exchange) = facts.upstreams.first() {
            steps[at]["probe"] = exchange_view(exchange);
            detail.push(match (&exchange.error, exchange.ips.is_empty()) {
                (Some(_), _) => "上游失败".to_owned(),
                (None, true) => format!("无 IP（{}）", exchange.rcode.map(rcode_name).unwrap_or_default()),
                (None, false) => probe_reason.clone().unwrap_or_else(|| "有 IP".to_owned()),
            });
        }
        detail.push("探测结果，未学习".to_owned());
        steps[at]["detail"] = detail.join(" · ").into();
        steps[at]["would_learn"] = facts.would_learn.clone().into();
    }
    if facts.preferred_away.is_some() {
        let at = index_of(&mut steps, "prefer_v4");
        steps[at]["result"] = "hit".into();
        steps[at]["detail"] = "有 A 记录 → AAAA 空应答".into();
        last_hit = Some("prefer_v4".into());
    }

    // The conclusion.
    let via = if rewritten {
        "rewrite".to_owned()
    } else if facts.preferred_away.is_some() {
        "prefer_v4".to_owned()
    } else if rule_hit.is_some() {
        "rule".to_owned()
    } else if let Some(branch) = branch {
        branch.to_owned()
    } else {
        last_hit.clone().unwrap_or_default()
    };
    let caches = facts.caches.clone();
    let last = facts.upstreams.last();
    let mut conclusion = if let Some(error) = &outcome.error {
        json!({ "kind": "fail", "detail": error })
    } else if let Some(Some(hit)) = &facts.rewrite {
        let ips: Vec<String> = hit.ips.iter().map(ToString::to_string).collect();
        match hit.rcode {
            None => json!({ "kind": "fail", "detail": hit.target, "rcode": "SERVFAIL" }),
            Some(_) if ips.is_empty() => {
                json!({ "kind": "empty", "detail": hit.target, "rcode": "NOERROR" })
            }
            Some(_) => json!({ "kind": "direct", "detail": hit.target, "ips": ips }),
        }
    } else if facts.preferred_away.is_some() {
        json!({ "kind": "empty", "detail": "IPv4 优先" })
    } else if let Some(outbound) = &facts.fakeip {
        json!({
            "kind": "proxy",
            "outbound": outbound.as_deref().unwrap_or(crate::atom_proxy::FINAL),
            "directive": outbound.as_deref().map_or("CLEAR".to_owned(), |tag| format!("SET {tag}")),
        })
    } else if matches!(
        rule_hit.as_ref().map(|rule| &rule.action),
        Some(crate::atom_rules::Action::Block)
    ) {
        json!({ "kind": "block" })
    } else {
        match &outcome.state.response {
            ResponseState::Raw(wire) => {
                let ips = atomdns_dns_core::observe_answer_addresses(wire.as_bytes()).unwrap_or_default();
                let rcode = wire.as_bytes().get(3).map(|byte| byte & 0x0f).unwrap_or(0);
                if ips.is_empty() {
                    json!({ "kind": "empty", "rcode": rcode_name(rcode) })
                } else {
                    json!({ "kind": "direct", "ips": ips.iter().map(ToString::to_string).collect::<Vec<_>>() })
                }
            }
            ResponseState::Synthesized(response) => {
                json!({ "kind": "empty", "rcode": rcode_name(u8::try_from(response.rcode()).unwrap_or(2)) })
            }
            ResponseState::None => json!({ "kind": "empty" }),
        }
    };
    conclusion["via"] = via.into();
    if conclusion["kind"] == "direct" && !rewritten {
        if let Some(exchange) = last {
            conclusion["upstream"] = exchange.group.clone().into();
            conclusion["entry"] = exchange.entry.clone().into();
            conclusion["ecs"] = exchange.ecs.clone().into();
        }
    }
    if matches!(conclusion["kind"].as_str(), Some("direct" | "proxy")) && !rewritten {
        conclusion["caches"] = caches.into();
    }
    if let Some(rule) = &rule_hit {
        conclusion["rule"] = json!({ "id": rule.id, "remark": rule.remark });
    }

    // The binding sing-box holds (the ledger) against the would-be one.
    let recorded = crate::atom_ledger::binding_of(&request.domain);
    let recorded_text = recorded.as_ref().map(|binding| match binding.tag() {
        Some(tag) => format!("SET {tag}"),
        None => "CLEAR".to_owned(),
    });
    let expected: Option<String> = match conclusion["kind"].as_str() {
        // sing-box answers AAAA empty before it reads the directive
        // (`ForwardCatalog::fakeip_name`): only A changes a binding.
        Some("proxy") if request.qtype == 1 => conclusion["directive"].as_str().map(str::to_owned),
        // A rule's direct or block decision is what a rule change sends
        // (`atom_ledger::wanted`); the original judgment sends nothing.
        // A client rule's queries never reach sing-box, and the ledger's
        // recomputation decides without a client: nothing to expect.
        Some("direct") if rule_hit.as_ref().is_some_and(|rule| rule.matches.client.is_empty()) => {
            Some("SET direct".to_owned())
        }
        Some("block") if rule_hit.as_ref().is_some_and(|rule| rule.matches.client.is_empty()) => {
            Some("SET block".to_owned())
        }
        _ => None,
    };
    let matches = if conclusion["kind"] == "proxy" && request.qtype != 1 {
        true
    } else {
        match (&recorded_text, &expected) {
        // Without a record sing-box holds no binding: right for CLEAR, and
        // for a direct or block rule (its queries never reach sing-box).
        (None, Some(expected)) => conclusion["kind"] != "proxy" || expected == "CLEAR",
        (Some(recorded), Some(expected)) => recorded == expected,
        (None, None) => true,
        // Nothing would be sent: a FakeIP a client still holds goes by the
        // remembered directive, which is a proxy one unless direct or block.
        (Some(recorded), None) => recorded == "SET direct" || recorded == "SET block",
        }
    };

    json!({
        "domain": request.domain,
        "qtype": if request.qtype == 28 { "AAAA" } else { "A" },
        "client": request.client.map(|ip| ip.to_string()),
        "steps": steps,
        "branch": if rule_hit.is_some() || rewritten { None } else { branch },
        "conclusion": conclusion,
        "upstreams": facts.upstreams.iter().map(exchange_view).collect::<Vec<_>>(),
        "binding": { "recorded": recorded_text, "expected": expected, "match": matches },
    })
}

#[cfg(test)]
#[path = "atom_dryrun_tests.rs"]
mod tests;
