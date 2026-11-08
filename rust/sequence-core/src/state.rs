use std::collections::BTreeSet;
use std::sync::Arc;

use atomdns_dns_core::{QueryHeader, QuestionInfo, ResponseError as DnsResponseError, TtlInfo};

const MAX_SYNTHESIZED_RCODE: u16 = 0x0fff;

/// Owned query data and the typed state carried by a sequence invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionState {
    pub query: QueryState,
    pub marks: BTreeSet<u32>,
    pub fast_flags: u64,
    pub response: ResponseState,
    pub routing: RoutingState,
    /// Query-local dynamic labels; never part of response provenance or dumps.
    pub domain_set_overlay: Option<RoutingLabelOverlay>,
    /// atom fork: the outbound tag a matched rule chose for this query. The
    /// host sends it to the `FakeIP` upstream as EDNS0 65001 SET; `None` sends
    /// CLEAR there. Other upstreams never see it.
    pub outbound: Option<Arc<str>>,
    response_generation: u64,
    response_origin: Option<ResponseOrigin>,
}

impl ExecutionState {
    #[must_use]
    pub fn new(header: QueryHeader, question: QuestionInfo) -> Self {
        Self {
            query: QueryState {
                header,
                question,
                client: ClientContext::default(),
            },
            marks: BTreeSet::new(),
            fast_flags: 0,
            response: ResponseState::None,
            routing: RoutingState::default(),
            domain_set_overlay: None,
            outbound: None,
            response_generation: 0,
            response_origin: None,
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            query: self.query.clone(),
            marks: self.marks.iter().copied().collect(),
            fast_flags: self.fast_flags,
            response: self.response.clone(),
            routing: self.routing.clone(),
        }
    }

    pub fn set_response(&mut self, response: ResponseState) {
        self.response_generation = self.response_generation.wrapping_add(1);
        self.response = response;
        self.response_origin = None;
    }

    /// Identity of the latest response replacement event. This is distinct
    /// from response bytes so a parent replacing a child with an identical
    /// wire still gets independent final-response provenance.
    #[must_use]
    pub fn response_generation(&self) -> u64 {
        self.response_generation
    }

    pub fn set_raw_response(&mut self, wire: Vec<u8>) {
        self.set_response(ResponseState::Raw(OwnedResponseWire(wire)));
    }

    /// The immutable supplier of this response, independent from attempts in
    /// the current request. Explicit replacement clears it; wire decoration keeps it.
    #[must_use]
    pub fn response_origin(&self) -> Option<&ResponseOrigin> {
        self.response_origin.as_ref()
    }

    pub fn set_raw_response_with_origin(&mut self, wire: Vec<u8>, origin: Option<ResponseOrigin>) {
        self.set_raw_response(wire);
        self.response_origin = origin;
    }

    pub fn rewrite_raw_response(&mut self, wire: Vec<u8>) {
        let origin = self.response_origin.take();
        self.set_raw_response_with_origin(wire, origin);
    }

    /// Sets a synthesized response after validating its configured RCODE.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseError::InvalidRcode`] when `rcode` is outside the
    /// supported `0..=0x0fff` range.
    pub fn set_synthesized_response(&mut self, rcode: u16) -> Result<(), ResponseError> {
        self.set_response(ResponseState::Synthesized(SynthesizedResponse::new(rcode)?));
        Ok(())
    }

    pub fn apply_mutation(&mut self, mutation: StateMutation) {
        match mutation {
            StateMutation::AddMark(mark) => {
                self.marks.insert(mark);
            }
            StateMutation::RemoveMark(mark) => {
                self.marks.remove(&mark);
            }
            StateMutation::SetFastFlags(flags) => {
                self.fast_flags = flags;
            }
            StateMutation::SetRouting { field, value } => {
                if field == RoutingField::DomainSet {
                    self.domain_set_overlay = None;
                    self.routing.effective_domain_set = None;
                }
                self.routing.set(field, value);
            }
            StateMutation::SetRoutingFields {
                domain_set,
                effective_tag,
                matched_rule_source,
            } => {
                self.routing.domain_set = domain_set;
                self.domain_set_overlay = None;
                self.routing.effective_domain_set = None;
                self.routing.effective_tag = effective_tag;
                self.routing.matched_rule_source = matched_rule_source;
            }
            StateMutation::SetResponse(response) => {
                self.set_response(response);
            }
        }
    }

    /// Inspects a raw response without consuming or replacing its wire bytes.
    ///
    /// `None` and synthesized responses do not require wire inspection and
    /// return `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns the inspector's typed error when the owned raw wire is
    /// malformed.
    pub fn inspect_response<I: ResponseInspector + ?Sized>(
        &self,
        inspector: &I,
    ) -> Result<Option<ResponseInspection>, ResponseError> {
        match &self.response {
            ResponseState::None | ResponseState::Synthesized(_) => Ok(None),
            ResponseState::Raw(wire) => inspector.inspect(&wire.0).map(Some),
        }
    }
}

/// Host-supplied provenance for the response that owns the wire. Identity is
/// allocated once by compilation and shared across requests and cache entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseOrigin {
    pub identity: std::sync::Arc<str>,
    pub peer: Option<std::net::SocketAddr>,
    pub transport: Option<&'static str>,
}

/// Trusted listener identity; unknown embedders never acquire a guessed peer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientContext {
    peer_ip: Option<std::net::IpAddr>,
    transport: ClientTransport,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ClientTransport {
    #[default]
    Unknown,
    Udp,
    Tcp,
}

impl ClientContext {
    #[must_use]
    pub fn from_peer(peer: std::net::IpAddr, transport: ClientTransport) -> Self {
        let peer = match peer {
            std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(peer, std::net::IpAddr::V4),
            std::net::IpAddr::V4(_) => peer,
        };
        Self {
            peer_ip: Some(peer),
            transport,
        }
    }

    #[must_use]
    pub fn peer_ip(self) -> Option<std::net::IpAddr> {
        self.peer_ip
    }

    #[must_use]
    pub fn transport(self) -> ClientTransport {
        self.transport
    }
}

/// The owned query/question portion of [`ExecutionState`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryState {
    pub client: ClientContext,
    pub header: QueryHeader,
    pub question: QuestionInfo,
}

/// Typed routing/audit fields used by the sequence contract.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RoutingState {
    pub domain_set: Option<String>,
    /// Response-owned labels used to derive the effective route, before a
    /// query-local learning annotation. Not a public audit or dump field.
    pub effective_domain_set: Option<String>,
    pub effective_tag: Option<String>,
    pub matched_group: Option<String>,
    pub final_sequence: Option<String>,
    pub final_upstream: Option<String>,
    pub final_upstream_targets: Option<String>,
    pub selected_upstream: Option<String>,
    pub matched_rule_source: Option<String>,
}

/// A mapper's live label prefix and the labels it replaces in a stored result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingLabelOverlay {
    /// Byte length of the live prefix already present in `domain_set`.
    pub prefix_len: usize,
    /// Category labels precede mapper defaults in `replaced`. Defaults are
    /// superseded only when this query has a live learning prefix.
    pub dynamic_label_count: usize,
    pub replaced: Arc<[String]>,
}

impl ExecutionState {
    /// Restores response-owned labels while retaining the mapper's live prefix.
    pub fn restore_cached_domain_set(&mut self, cached: String) {
        if cached.is_empty() {
            return;
        }
        let Some(overlay) = &self.domain_set_overlay else {
            self.routing.domain_set = Some(cached);
            self.routing.effective_domain_set = None;
            return;
        };
        let current = self.routing.domain_set.as_deref().unwrap_or("");
        let superseded = |part: &str| {
            overlay
                .replaced
                .iter()
                .take(if overlay.prefix_len == 0 {
                    overlay.dynamic_label_count
                } else {
                    overlay.replaced.len()
                })
                .any(|label| label == part)
                && !current.split('|').any(|label| label.trim() == part)
        };
        // With no learning annotation or stale label, keep the original
        // move-only restoration path (and the stored string's formatting).
        if overlay.prefix_len == 0 && !cached.split('|').map(str::trim).any(superseded) {
            self.routing.domain_set = Some(cached);
            self.routing.effective_domain_set = None;
            return;
        }
        let mut joined = current.get(..overlay.prefix_len).unwrap_or("").to_owned();
        for part in cached.split('|').map(str::trim).filter(|s| !s.is_empty()) {
            if superseded(part) || joined.split('|').any(|label| label == part) {
                continue;
            }
            if !joined.is_empty() {
                joined.push('|');
            }
            joined.push_str(part);
        }
        // If only expired learning labels remain, keep the current mapper
        // result (including its default) rather than an empty label.
        if !joined.is_empty() {
            self.routing.domain_set = Some(joined);
        }
        self.routing.effective_domain_set =
            (self.routing.domain_set.as_deref() != Some(cached.as_str())).then_some(cached);
    }
}

impl RoutingState {
    /// The response's labels before query-local learning annotations.
    #[must_use]
    pub fn response_domain_set(&self) -> Option<&str> {
        self.effective_domain_set
            .as_deref()
            .or(self.domain_set.as_deref())
    }

    fn set(&mut self, field: RoutingField, value: Option<String>) {
        match field {
            RoutingField::DomainSet => self.domain_set = value,
            RoutingField::EffectiveTag => self.effective_tag = value,
            RoutingField::MatchedGroup => self.matched_group = value,
            RoutingField::FinalSequence => self.final_sequence = value,
            RoutingField::FinalUpstream => self.final_upstream = value,
            RoutingField::FinalUpstreamTargets => self.final_upstream_targets = value,
            RoutingField::SelectedUpstream => self.selected_upstream = value,
            RoutingField::MatchedRuleSource => self.matched_rule_source = value,
        }
    }
}

/// A closed set of routing fields that a matcher may update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoutingField {
    DomainSet,
    EffectiveTag,
    MatchedGroup,
    FinalSequence,
    FinalUpstream,
    FinalUpstreamTargets,
    SelectedUpstream,
    MatchedRuleSource,
}

/// The complete response state; raw bytes are never replaced by a lossy
/// decoded representation during inspection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseState {
    None,
    Raw(OwnedResponseWire),
    Synthesized(SynthesizedResponse),
}

impl ResponseState {
    #[must_use]
    pub fn synthesized_rcode(&self) -> Option<u16> {
        match self {
            Self::Synthesized(response) => Some(response.rcode),
            Self::None | Self::Raw(_) => None,
        }
    }
}

/// Caller-owned raw DNS response bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnedResponseWire(pub Vec<u8>);

impl OwnedResponseWire {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A locally synthesized response. RCODE validation is intentionally wider
/// than the four-bit DNS header because configured `AtomDNS` reject values use
/// the range `0..=0x0fff`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SynthesizedResponse {
    rcode: u16,
}

impl SynthesizedResponse {
    /// Creates a synthesized response for a configured RCODE.
    ///
    /// # Errors
    ///
    /// Returns [`ResponseError::InvalidRcode`] when `rcode` is outside the
    /// supported `0..=0x0fff` range.
    pub fn new(rcode: u16) -> Result<Self, ResponseError> {
        if rcode > MAX_SYNTHESIZED_RCODE {
            return Err(ResponseError::InvalidRcode(rcode));
        }
        Ok(Self { rcode })
    }

    #[must_use]
    pub fn rcode(&self) -> u16 {
        self.rcode
    }
}

/// A canonical, deterministic observation of the caller-owned state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateSnapshot {
    pub query: QueryState,
    pub marks: Vec<u32>,
    pub fast_flags: u64,
    pub response: ResponseState,
    pub routing: RoutingState,
}

/// Typed matcher-produced state changes. Matchers cannot mutate state
/// directly; the dispatcher applies this closed mutation set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateMutation {
    AddMark(u32),
    RemoveMark(u32),
    SetFastFlags(u64),
    SetRouting {
        field: RoutingField,
        value: Option<String>,
    },
    SetRoutingFields {
        domain_set: Option<String>,
        effective_tag: Option<String>,
        matched_rule_source: Option<String>,
    },
    SetResponse(ResponseState),
}

/// The only response inspection error exposed by the sequence state layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseError {
    InvalidRcode(u16),
    MalformedRawResponse { source: DnsResponseError },
}

/// The small inspection seam required by `Phase3B`. Implementations return a
/// TTL observation but do not take ownership of or modify the wire.
pub trait ResponseInspector {
    /// Inspects a complete raw response without taking ownership of it.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the wire cannot be inspected.
    fn inspect(&self, wire: &[u8]) -> Result<ResponseInspection, ResponseError>;
}

/// The production-free inspector backed by the already-reviewed dns-core
/// response walk.
#[derive(Clone, Copy, Debug, Default)]
pub struct DnsResponseInspector;

impl ResponseInspector for DnsResponseInspector {
    fn inspect(&self, wire: &[u8]) -> Result<ResponseInspection, ResponseError> {
        let ttl = atomdns_dns_core::observe_response_ttl(wire)
            .map_err(|source| ResponseError::MalformedRawResponse { source })?;
        Ok(ResponseInspection { ttl })
    }
}

/// The supported, non-consuming response observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseInspection {
    pub ttl: TtlInfo,
}
