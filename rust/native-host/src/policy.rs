//! Immutable startup response-policy descriptors; no request-time file I/O.
use crate::config::ConfigError;
use atomdns_matcher_core::{IpPrefixList, MixMatcher, normalize};
use atomdns_sequence_core::{ExecutableId, ExecutionState, ExecutorError};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::PathBuf;
use std::rc::Rc;

pub const POLICY_LINE_LIMIT: usize = 64 * 1024;
pub const POLICY_BYTES_LIMIT: usize = 64 * 1024 * 1024;
pub const POLICY_RULE_LIMIT: usize = 1_000_000;

pub struct DomainPayload<T> {
    matcher: MixMatcher<usize>,
    values: Vec<T>,
}

#[cfg(test)]
mod special_group_cname_tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, Record, RecordType, rdata};

    #[test]
    fn compressed_group_cname_policy_preserves_control_sections_and_routing() {
        for (kind, with_ip, dname, rcode, changes) in [
            (RecordType::A, true, false, ResponseCode::NoError, true),
            (RecordType::AAAA, true, false, ResponseCode::NoError, true),
            (RecordType::A, false, false, ResponseCode::NoError, false),
            (RecordType::A, true, true, ResponseCode::NoError, false),
            (RecordType::MX, true, false, ResponseCode::NoError, false),
            (RecordType::A, false, false, ResponseCode::NXDomain, false),
        ] {
            let qname = Name::from_ascii("original.example.").unwrap();
            let target = Name::from_ascii("target.example.").unwrap();
            let mut query = Message::new();
            query
                .set_id(91)
                .add_query(Query::query(qname.clone(), kind));
            let raw = query.to_vec().unwrap();
            let (header, question) = atomdns_dns_core::parse_query(&raw).unwrap();
            let mut state = ExecutionState::new(header, question);
            state.routing.matched_group = Some("special_50".into());
            state.routing.final_upstream = Some("actual_supplier".into());
            let route = state.routing.clone();
            let mut response = query.clone();
            response
                .set_message_type(MessageType::Response)
                .set_response_code(rcode)
                .set_recursion_available(true)
                .set_authentic_data(true);
            response.add_answer(Record::from_rdata(
                qname.clone(),
                37,
                RData::CNAME(rdata::CNAME(target.clone())),
            ));
            if with_ip {
                let data = if kind == RecordType::AAAA {
                    RData::AAAA(rdata::AAAA("2001:db8::7".parse().unwrap()))
                } else {
                    RData::A(rdata::A("192.0.2.7".parse().unwrap()))
                };
                response.add_answer(Record::from_rdata(target.clone(), 41, data));
            }
            if dname {
                response.add_answer(Record::from_rdata(
                    target.clone(),
                    31,
                    RData::Unknown {
                        code: RecordType::Unknown(39),
                        rdata: rdata::NULL::with(encode_name("renamed.example.")),
                    },
                ));
            }
            response.add_name_server(Record::from_rdata(
                target.clone(),
                70,
                RData::NS(rdata::NS(Name::from_ascii("ns.example.").unwrap())),
            ));
            response.add_additional(Record::from_rdata(
                Name::from_ascii("ns.example.").unwrap(),
                75,
                RData::A(rdata::A("192.0.2.8".parse().unwrap())),
            ));
            let mut wire = response.to_vec().unwrap();
            // An ECS-bearing OPT must survive reconstruction, including scope.
            let count = u16::from_be_bytes([wire[10], wire[11]]) + 1;
            wire[10..12].copy_from_slice(&count.to_be_bytes());
            wire.extend([
                0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 11, 0, 8, 0, 7, 0, 1, 24, 16, 192, 0, 2,
            ]);
            assert!(wire.windows(2).any(|w| w[0] & 0xc0 == 0xc0));
            let before = Message::from_vec(&wire).unwrap();
            state.set_raw_response(wire.clone());
            assert!(!apply_wire_policy(&ResponsePolicy::CnameRemover, &mut state, &raw).unwrap());
            assert_eq!(state.routing, route);
            let atomdns_sequence_core::ResponseState::Raw(after) = &state.response else {
                panic!("raw response")
            };
            if !changes {
                assert_eq!(after.as_bytes(), wire);
                continue;
            }
            let after = Message::from_vec(after.as_bytes()).unwrap();
            assert_eq!(after.answers().len(), 1);
            assert_eq!(after.answers()[0].name(), &qname);
            assert_eq!(after.answers()[0].ttl(), 41);
            let mut expected_header = *before.header();
            expected_header.set_answer_count(1);
            assert_eq!(after.header(), &expected_header);
            assert_eq!(after.name_servers(), before.name_servers());
            assert_eq!(after.additionals(), before.additionals());
            assert_eq!(after.extensions(), before.extensions());
        }
    }
}
impl<T> DomainPayload<T> {
    #[must_use]
    pub fn lookup(&self, domain: &str) -> Option<&T> {
        self.matcher
            .r#match(domain)
            .map(|index| &self.values[*index])
    }
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostAddresses {
    pub ipv4: Vec<std::net::Ipv4Addr>,
    pub ipv6: Vec<std::net::Ipv6Addr>,
}
pub enum ResponsePolicy {
    CnameRemover,
    Hosts(Rc<DomainPayload<HostAddresses>>),
    Redirect(Rc<DomainPayload<String>>),
    Ttl(TtlPolicy),
    Ecs(crate::ecs::EcsPolicy),
}
pub struct ResponsePolicyConfig {
    pub tag: String,
    pub executable: ExecutableId,
    pub policy: ResponsePolicy,
}
pub struct IpSetConfig {
    pub tag: String,
    pub prefixes: Rc<IpListHandle>,
}

/// A prefix list read whole at every lookup. Fixed lists are never replaced;
/// an `si_set` publishes a new list on a hot update, and a lookup that already
/// took the old one finishes on it.
pub struct IpListHandle(std::cell::RefCell<Rc<IpPrefixList>>);

impl IpListHandle {
    pub(crate) fn new(list: Rc<IpPrefixList>) -> Self {
        Self(std::cell::RefCell::new(list))
    }

    /// True when the current list covers `address`.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        self.current().contains(address)
    }

    /// True when the current list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.current().is_empty()
    }

    pub(crate) fn current(&self) -> Rc<IpPrefixList> {
        Rc::clone(&self.0.borrow())
    }

    pub(crate) fn publish(&self, list: Rc<IpPrefixList>) {
        *self.0.borrow_mut() = list;
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TtlPolicy {
    Fixed(u32),
    Range { min: u32, max: u32 },
}
impl TtlPolicy {
    pub(crate) fn parse(args: &str, path: &str) -> Result<Self, ConfigError> {
        let number = |n: &str| {
            if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ConfigError::new(
                    path,
                    "ttl requires unsigned decimal uint32",
                ));
            }
            n.parse::<u32>()
                .map_err(|_| ConfigError::new(path, "ttl requires uint32 fixed or min-max"))
        };
        if args.split_whitespace().count() != 1 {
            return Err(ConfigError::new(
                path,
                "ttl requires exactly one fixed or min-max argument",
            ));
        }
        match args.split_once('-') {
            Some((min, max)) => Ok(Self::Range {
                min: number(min)?,
                max: number(max)?,
            }),
            None => Ok(Self::Fixed(number(args)?)),
        }
    }
}

/// Budgets count all source bytes and non-comment rules, including overwritten rules.
#[derive(Default)]
pub(crate) struct RuleBudget {
    bytes: usize,
    rules: usize,
}
impl RuleBudget {
    pub(crate) fn load_with_inputs(
        &mut self,
        inline: &[String],
        files: &[PathBuf],
        missing_ok: bool,
        path: &str,
        mut inputs: Option<&mut crate::special_groups::CandidateInputSet>,
        mut consume: impl FnMut(&str, &str) -> Result<(), ConfigError>,
    ) -> Result<(), ConfigError> {
        for (index, line) in inline.iter().enumerate() {
            self.line(line.as_bytes(), &format!("{path}[{index}]"), &mut consume)?;
        }
        for file in files {
            let file_path = file.clone();
            let open_result =
                crate::transaction::blocking_io(move || std::fs::File::open(file_path)).map_err(
                    |error| {
                        ConfigError::new(
                            file.display().to_string(),
                            format!("cannot open rule file on bounded worker: {error}"),
                        )
                    },
                )?;
            let input = match open_result {
                Ok(file) => file,
                Err(error) if missing_ok && error.kind() == std::io::ErrorKind::NotFound => {
                    crate::diag::warn_line!("{}: missing IP rule file, skipped", file.display());
                    if let Some(inputs) = inputs.as_deref_mut() {
                        inputs.record_missing(file).map_err(|reason| {
                            ConfigError::new(file.display().to_string(), reason)
                        })?;
                    }
                    continue;
                }
                Err(error) => {
                    return Err(ConfigError::new(
                        file.display().to_string(),
                        format!("cannot read rules: {error}"),
                    ));
                }
            };
            let mut reader = BufReader::new(input);
            let mut source_bytes = Vec::new();
            let mut index = 0;
            loop {
                // A bounded read prevents a single hostile line allocating the whole file.
                let (next_reader, read, line) = crate::transaction::blocking_io(move || {
                    let mut line = Vec::new();
                    let read = reader
                        .by_ref()
                        .take((POLICY_LINE_LIMIT + 2) as u64)
                        .read_until(b'\n', &mut line)?;
                    Ok::<_, std::io::Error>((reader, read, line))
                })
                .map_err(|error| {
                    ConfigError::new(
                        file.display().to_string(),
                        format!("cannot read rules on bounded worker: {error}"),
                    )
                })?
                .map_err(|error| {
                    ConfigError::new(
                        file.display().to_string(),
                        format!("cannot read rules: {error}"),
                    )
                })?;
                reader = next_reader;
                if read == 0 {
                    break;
                }
                source_bytes.extend_from_slice(&line);
                index += 1;
                self.line(&line, &format!("{}:{index}", file.display()), &mut consume)?;
            }
            if let Some(inputs) = inputs.as_deref_mut() {
                inputs
                    .record_bytes(file, &source_bytes)
                    .map_err(|reason| ConfigError::new(file.display().to_string(), reason))?;
            }
        }
        Ok(())
    }
    fn line(
        &mut self,
        bytes: &[u8],
        path: &str,
        consume: &mut impl FnMut(&str, &str) -> Result<(), ConfigError>,
    ) -> Result<(), ConfigError> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .ok_or_else(|| ConfigError::new(path, "policy byte limit exceeded"))?;
        if self.bytes > POLICY_BYTES_LIMIT {
            return Err(ConfigError::new(path, "policy byte limit exceeded"));
        }
        let content = bytes
            .strip_suffix(b"\n")
            .unwrap_or(bytes)
            .strip_suffix(b"\r")
            .unwrap_or(bytes.strip_suffix(b"\n").unwrap_or(bytes));
        if content.len() > POLICY_LINE_LIMIT {
            return Err(ConfigError::new(path, "policy line limit exceeded"));
        }
        if bytes.contains(&0)
            || bytes.starts_with(b"SRS")
            || bytes.starts_with(b"\x1f\x8b")
            || bytes.starts_with(b"\x78\x01")
            || bytes.starts_with(b"\x78\x9c")
            || bytes.starts_with(b"\x78\xda")
        {
            return Err(ConfigError::new(
                path,
                "unsupported binary/compressed rule format",
            ));
        }
        let text = std::str::from_utf8(content)
            .map_err(|_| ConfigError::new(path, "rules must be UTF-8 text"))?;
        let text = text.split('#').next().unwrap_or("").trim();
        if text.is_empty() {
            return Ok(());
        }
        self.rules += 1;
        if self.rules > POLICY_RULE_LIMIT {
            return Err(ConfigError::new(path, "policy rule limit exceeded"));
        }
        consume(text, path)
    }
}

pub(crate) fn domain_payload_with_inputs<T>(
    inline: &[String],
    files: &[PathBuf],
    path: &str,
    inputs: Option<&mut crate::special_groups::CandidateInputSet>,
    parse: impl Fn(&[&str], &str) -> Result<T, ConfigError>,
) -> Result<DomainPayload<T>, ConfigError> {
    let mut entries: Vec<(String, T)> = Vec::new();
    let mut positions = BTreeMap::new();
    RuleBudget::default().load_with_inputs(
        inline,
        files,
        false,
        path,
        inputs,
        |line, location| {
            let fields: Vec<_> = line.split_whitespace().collect();
            let (kind, pattern) = fields[0].split_once(':').unwrap_or(("full", fields[0]));
            let pattern = if kind == "regexp" {
                pattern.to_owned()
            } else {
                normalize(pattern)
            };
            let canonical = format!("{kind}:{pattern}");
            // Validate each rule even if a later duplicate would replace it.
            let mut validator = MixMatcher::new();
            validator
                .add(&canonical, ())
                .map_err(|error| ConfigError::new(location, error.to_string()))?;
            let value = parse(&fields[1..], location)?;
            if let Some(index) = positions.get(&canonical).copied() {
                entries[index] = (canonical, value);
            } else {
                positions.insert(canonical.clone(), entries.len());
                entries.push((canonical, value));
            }
            Ok(())
        },
    )?;
    let mut matcher = MixMatcher::new();
    let mut values = Vec::with_capacity(entries.len());
    for (rule, value) in entries {
        matcher
            .add(&rule, values.len())
            .map_err(|error| ConfigError::new(path, error.to_string()))?;
        values.push(value);
    }
    Ok(DomainPayload { matcher, values })
}
pub(crate) fn hosts_with_inputs(
    inline: &[String],
    files: &[PathBuf],
    path: &str,
    inputs: Option<&mut crate::special_groups::CandidateInputSet>,
) -> Result<DomainPayload<HostAddresses>, ConfigError> {
    domain_payload_with_inputs(inline, files, path, inputs, |fields, location| {
        let mut result = HostAddresses {
            ipv4: Vec::new(),
            ipv6: Vec::new(),
        };
        for field in fields {
            match field.parse::<IpAddr>().map_err(|_| {
                ConfigError::new(location, format!("invalid hosts address `{field}`"))
            })? {
                IpAddr::V4(ip) => result.ipv4.push(ip),
                IpAddr::V6(ip) => result.ipv6.push(ip),
            }
        }
        Ok(result)
    })
}
#[cfg(test)]
fn hosts(
    inline: &[String],
    files: &[PathBuf],
    path: &str,
) -> Result<DomainPayload<HostAddresses>, ConfigError> {
    hosts_with_inputs(inline, files, path, None)
}
pub(crate) fn redirects_with_inputs(
    inline: &[String],
    files: &[PathBuf],
    path: &str,
    inputs: Option<&mut crate::special_groups::CandidateInputSet>,
) -> Result<DomainPayload<String>, ConfigError> {
    domain_payload_with_inputs(inline, files, path, inputs, |fields, location| {
        if fields.len() != 1 {
            return Err(ConfigError::new(
                location,
                "redirect rule requires exactly two fields",
            ));
        }
        let mut name = hickory_proto::rr::Name::from_ascii(fields[0]).map_err(|error| {
            ConfigError::new(location, format!("invalid redirect target: {error}"))
        })?;
        name.set_fqdn(true);
        Ok(name.to_ascii())
    })
}
pub(crate) fn ip_prefix(field: &str, path: &str) -> Result<(IpAddr, u8), ConfigError> {
    let (address, bits) = match field.split_once('/') {
        Some((a, b)) => (a, Some(b)),
        None => (field, None),
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| ConfigError::new(path, format!("invalid IP/prefix `{field}`")))?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    let bits = bits
        .map(|b| b.parse::<u8>())
        .transpose()
        .map_err(|_| ConfigError::new(path, "invalid prefix width"))?
        .unwrap_or(width);
    if bits > width {
        return Err(ConfigError::new(path, "invalid prefix width"));
    }
    Ok((address, bits))
}
/// The IP entry of one list line: its first word, or a range written with spaces around the
/// dash (`10.0.0.1 - 10.0.0.9`). The dash only joins when both sides are addresses, so a
/// trailing note such as `192.0.2.1 - office` still reads as the single address.
pub(crate) fn ip_line_field(line: &str) -> String {
    let line = line.trim();
    let first = line.split_whitespace().next().unwrap_or("");
    let rest = line[first.len()..].trim_start();
    let (head, tail) = if let Some(head) = first.strip_suffix('-') {
        (head, rest)
    } else if let Some(tail) = rest.strip_prefix('-') {
        (first, tail.trim_start())
    } else {
        return first.to_owned();
    };
    let end = tail.split_whitespace().next().unwrap_or("");
    if head.parse::<IpAddr>().is_ok() && end.parse::<IpAddr>().is_ok() {
        format!("{head}-{end}")
    } else {
        first.to_owned()
    }
}
/// An inline entry must be the whole entry: a range may have spaces around its dash, but
/// anything else after the address is an error (unlike a list line, which may carry a note).
pub(crate) fn ip_inline_field(entry: &str) -> String {
    let squeezed: String = entry.split_whitespace().collect();
    let field = ip_line_field(entry);
    if squeezed == field {
        field
    } else {
        entry.trim().to_owned()
    }
}
/// One IP list entry: an address, a prefix, or an inclusive range `start-end` of two
/// addresses of one family, which becomes the fewest prefixes covering it.
pub(crate) fn ip_entries(field: &str, path: &str) -> Result<Vec<(IpAddr, u8)>, ConfigError> {
    let Some((start, end)) = field.split_once('-') else {
        return ip_prefix(field, path).map(|prefix| vec![prefix]);
    };
    let invalid = || ConfigError::new(path, format!("invalid IP range `{field}`"));
    let start = start.parse::<IpAddr>().map_err(|_| invalid())?;
    let end = end.parse::<IpAddr>().map_err(|_| invalid())?;
    let (start, end, width) = match (start, end) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u128::from(u32::from(a)), u128::from(u32::from(b)), 32),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), 128),
        _ => return Err(invalid()),
    };
    if start > end {
        return Err(invalid());
    }
    Ok(covering_prefixes(start, end, width)
        .into_iter()
        .map(|(network, bits)| {
            let ip = match width {
                32 => IpAddr::from(std::net::Ipv4Addr::from(network as u32)),
                _ => IpAddr::from(std::net::Ipv6Addr::from(network)),
            };
            (ip, bits)
        })
        .collect())
}
/// The fewest aligned blocks covering `start..=end` (addresses of `width` bits),
/// as (network, prefix length).
fn covering_prefixes(start: u128, end: u128, width: u32) -> Vec<(u128, u8)> {
    let mut blocks = Vec::new();
    let mut next = start;
    loop {
        // The largest host-bit count that both the remaining span and the alignment of
        // `next` allow.
        let fits = match (end - next).checked_add(1) {
            Some(count) => 127 - count.leading_zeros(),
            None => 128,
        };
        let aligned = if next == 0 {
            128
        } else {
            next.trailing_zeros()
        };
        let host_bits = fits.min(aligned).min(width);
        let last = if host_bits == 128 {
            u128::MAX
        } else {
            next + ((1u128 << host_bits) - 1)
        };
        blocks.push((next, (width - host_bits) as u8));
        if last >= end {
            return blocks;
        }
        next = last + 1;
    }
}
#[cfg(test)]
mod ip_entry_tests {
    use super::*;

    fn text(entries: &[(IpAddr, u8)]) -> Vec<String> {
        entries
            .iter()
            .map(|(ip, bits)| format!("{ip}/{bits}"))
            .collect()
    }

    #[test]
    fn a_range_becomes_the_covering_prefixes() {
        let entries = ip_entries("10.0.0.100-10.0.0.199", "test").unwrap();
        assert_eq!(
            text(&entries),
            [
                "10.0.0.100/30",
                "10.0.0.104/29",
                "10.0.0.112/28",
                "10.0.0.128/26",
                "10.0.0.192/29"
            ]
        );
    }

    #[test]
    fn single_addresses_and_prefixes_are_unchanged() {
        assert_eq!(
            text(&ip_entries("192.0.2.7", "test").unwrap()),
            ["192.0.2.7/32"]
        );
        assert_eq!(
            text(&ip_entries("198.51.100.0/24", "test").unwrap()),
            ["198.51.100.0/24"]
        );
        assert_eq!(
            text(&ip_entries("2001:db8::/32", "test").unwrap()),
            ["2001:db8::/32"]
        );
    }

    #[test]
    fn ranges_cover_exactly_their_addresses() {
        for (start, end) in [
            (0u32, 0u32),
            (5, 9),
            (250, 1030),
            (0, u32::MAX),
            (u32::MAX - 3, u32::MAX),
        ] {
            let blocks = covering_prefixes(u128::from(start), u128::from(end), 32);
            let total: u128 = blocks.iter().map(|(_, bits)| 1u128 << (32 - bits)).sum();
            assert_eq!(total, u128::from(end - start) + 1, "{start}-{end}");
            assert_eq!(blocks[0].0, u128::from(start));
        }
        let whole = covering_prefixes(0, u128::MAX, 128);
        assert_eq!(whole, [(0, 0)]);
    }

    #[test]
    fn a_range_may_have_spaces_around_the_dash() {
        for line in [
            "10.0.0.100 - 10.0.0.199",
            "10.0.0.100 -10.0.0.199",
            "10.0.0.100- 10.0.0.199",
            "10.0.0.100-10.0.0.199 # office",
        ] {
            assert_eq!(ip_line_field(line), "10.0.0.100-10.0.0.199", "{line}");
        }
        assert_eq!(
            text(&ip_entries(&ip_line_field("2001:db8::1 - 2001:db8::2"), "test").unwrap()),
            ["2001:db8::1/128", "2001:db8::2/128"]
        );
    }

    #[test]
    fn an_inline_entry_is_the_whole_entry() {
        assert_eq!(ip_inline_field("10.0.0.1 - 10.0.0.9"), "10.0.0.1-10.0.0.9");
        assert_eq!(ip_inline_field(" 192.0.2.1 "), "192.0.2.1");
        for entry in [
            "192.0.2.1 invalid",
            "192.0.2.1 - office",
            "192.0.2.1 # note",
        ] {
            assert!(
                ip_entries(&ip_inline_field(entry), "test").is_err(),
                "{entry}"
            );
        }
        assert!(ip_entries(&ip_inline_field("10.0.0.1 - 10.0.0.9"), "test").is_ok());
    }

    #[test]
    fn a_dash_before_a_note_does_not_make_a_range() {
        for line in [
            "192.0.2.1 - office",
            "192.0.2.1 -x",
            "192.0.2.1",
            "192.0.2.1 # a-b",
        ] {
            assert_eq!(ip_line_field(line), "192.0.2.1", "{line}");
        }
        assert_eq!(ip_line_field("198.51.100.0/24 - lan"), "198.51.100.0/24");
        assert_eq!(ip_line_field("10.0.0.1 - "), "10.0.0.1");
    }

    #[test]
    fn invalid_ranges_are_rejected() {
        for field in [
            "10.0.0.199-10.0.0.100",
            "10.0.0.1-2001:db8::1",
            "10.0.0.1-",
            "-10.0.0.1",
            "10.0.0.1-x",
        ] {
            assert!(ip_entries(field, "test").is_err(), "{field}");
        }
    }
}
#[cfg(test)]
pub(crate) fn ip_list(
    inline: &[String],
    files: &[PathBuf],
    path: &str,
) -> Result<Rc<IpListHandle>, ConfigError> {
    ip_list_with_inputs(inline, files, path, None)
}
pub(crate) fn ip_list_with_inputs(
    inline: &[String],
    files: &[PathBuf],
    path: &str,
    inputs: Option<&mut crate::special_groups::CandidateInputSet>,
) -> Result<Rc<IpListHandle>, ConfigError> {
    for (index, entry) in inline.iter().enumerate() {
        ip_entries(&ip_inline_field(entry), &format!("{path}.ips[{index}]"))?;
    }
    let mut prefixes = IpPrefixList::new();
    RuleBudget::default().load_with_inputs(
        inline,
        files,
        true,
        path,
        inputs,
        |line, location| {
            for (ip, bits) in ip_entries(&ip_line_field(line), location)? {
                prefixes.append(ip, bits);
            }
            Ok(())
        },
    )?;
    prefixes.rebuild();
    Ok(Rc::new(IpListHandle::new(Rc::new(prefixes))))
}
/// Applies one non-scoped policy atomically. True means hosts replaced the
/// response; TTL transforms preserve the existing supplier identity.
pub(crate) fn apply_wire_policy(
    policy: &ResponsePolicy,
    state: &mut ExecutionState,
    query_wire: &[u8],
) -> Result<bool, ExecutorError> {
    match policy {
        ResponsePolicy::CnameRemover => {
            if !matches!(state.query.question.qtype, 1 | 28) {
                return Ok(false);
            }
            let atomdns_sequence_core::ResponseState::Raw(wire) = &state.response else {
                return Ok(false);
            };
            let mut message = hickory_proto::op::Message::from_vec(wire.as_bytes())
                .map_err(|e| ExecutorError::new(format!("invalid CNAME response: {e}")))?;
            use hickory_proto::rr::RecordType;
            if message
                .answers()
                .iter()
                .any(|r| u16::from(r.record_type()) == 39)
                || !message
                    .answers()
                    .iter()
                    .any(|r| matches!(r.record_type(), RecordType::A | RecordType::AAAA))
                || !message
                    .answers()
                    .iter()
                    .any(|r| r.record_type() == RecordType::CNAME)
            {
                return Ok(false);
            }
            let name = hickory_proto::rr::Name::from_ascii(
                crate::matchers::wire_name_to_ascii_domain(&state.query.question.qname_wire)
                    .ok_or_else(|| ExecutorError::new("invalid question name"))?,
            )
            .map_err(|e| ExecutorError::new(e.to_string()))?;
            message
                .answers_mut()
                .retain(|r| r.record_type() != RecordType::CNAME);
            for answer in message.answers_mut() {
                answer.set_name(name.clone());
            }
            state.rewrite_raw_response(
                message
                    .to_vec()
                    .map_err(|e| ExecutorError::new(e.to_string()))?,
            );
            Ok(false)
        }
        ResponsePolicy::Hosts(rules) => {
            let q = &state.query.question;
            if q.qclass != 1 || !matches!(q.qtype, 1 | 28) {
                return Ok(false);
            }
            let Some(domain) = crate::matchers::wire_name_to_ascii_domain(&q.qname_wire) else {
                return Ok(false);
            };
            let Some(addresses) = rules.lookup(&domain) else {
                return Ok(false);
            };
            if addresses.ipv4.is_empty() && addresses.ipv6.is_empty() {
                return Ok(false);
            }
            let data: Vec<Vec<u8>> = if q.qtype == 1 {
                addresses
                    .ipv4
                    .iter()
                    .map(|ip| ip.octets().to_vec())
                    .collect()
            } else {
                addresses
                    .ipv6
                    .iter()
                    .map(|ip| ip.octets().to_vec())
                    .collect()
            };
            let count = u16::try_from(data.len())
                .map_err(|_| ExecutorError::new("too many hosts addresses"))?;
            let mut wire = atomdns_dns_core::synthesize_response(&state.query.header, q, 0)
                .map_err(|_| ExecutorError::new("cannot construct hosts response"))?;
            wire[2] |= query_wire.get(2).copied().unwrap_or(0) & 1;
            wire[6..8].copy_from_slice(&count.to_be_bytes());
            if data.is_empty() {
                wire[8..10].copy_from_slice(&1_u16.to_be_bytes());
                let mut soa = encode_name("fake-ns.atomdns.fake.root.");
                soa.extend(encode_name("fake-mbox.atomdns.fake.root."));
                for field in [2_021_110_400_u32, 1800, 900, 604800, 86400] {
                    soa.extend(field.to_be_bytes());
                }
                append_record(&mut wire, &q.qname_wire, 6, 300, &soa)?;
            } else {
                for address in data {
                    append_record(&mut wire, &q.qname_wire, q.qtype, 10, &address)?;
                }
            }
            if wire.len() > 65535 {
                return Err(ExecutorError::new("hosts response exceeds DNS wire limit"));
            }
            state.set_raw_response(wire);
            Ok(true)
        }
        ResponsePolicy::Ttl(policy) => {
            let wire = match &state.response {
                atomdns_sequence_core::ResponseState::None => return Ok(false),
                atomdns_sequence_core::ResponseState::Raw(wire) => wire.as_bytes().to_vec(),
                atomdns_sequence_core::ResponseState::Synthesized(response) => {
                    atomdns_dns_core::synthesize_response(
                        &state.query.header,
                        &state.query.question,
                        u8::try_from(response.rcode())
                            .map_err(|_| ExecutorError::new("unsupported synthesized rcode"))?,
                    )
                    .map_err(|_| ExecutorError::new("cannot construct TTL response"))?
                }
            };
            let patched = match policy {
                TtlPolicy::Fixed(0) => {
                    atomdns_dns_core::observe_response_ttl(&wire).map_err(|error| {
                        ExecutorError::new(format!("invalid TTL response: {error:?}"))
                    })?;
                    return Ok(false);
                }
                TtlPolicy::Fixed(ttl) => atomdns_dns_core::replace_response_ttls(&wire, *ttl),
                TtlPolicy::Range { min, max } => {
                    atomdns_dns_core::clamp_response_ttls(&wire, *min, *max)
                }
            }
            .map_err(|error| ExecutorError::new(format!("invalid TTL response: {error:?}")))?;
            state.rewrite_raw_response(patched);
            Ok(false)
        }
        ResponsePolicy::Redirect(_) | ResponsePolicy::Ecs(_) => Ok(false),
    }
}
fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(u8::try_from(label.len()).unwrap_or(0));
        out.extend(label.as_bytes());
    }
    out.push(0);
    out
}
fn append_record(
    wire: &mut Vec<u8>,
    name: &[u8],
    kind: u16,
    ttl: u32,
    data: &[u8],
) -> Result<(), ExecutorError> {
    let len = u16::try_from(data.len()).map_err(|_| ExecutorError::new("record too large"))?;
    wire.extend(name);
    wire.extend(kind.to_be_bytes());
    wire.extend(1_u16.to_be_bytes());
    wire.extend(ttl.to_be_bytes());
    wire.extend(len.to_be_bytes());
    wire.extend(data);
    Ok(())
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{DNSClass, Name, RecordType};
    fn state(kind: RecordType, class: DNSClass, name: &str) -> (ExecutionState, Vec<u8>) {
        let mut query = Query::query(Name::from_ascii(name).unwrap(), kind);
        query.set_query_class(class);
        let mut message = Message::new();
        message.add_query(query);
        let wire = message.to_vec().unwrap();
        let (header, question) = atomdns_dns_core::parse_query(&wire).unwrap();
        (ExecutionState::new(header, question), wire)
    }
    #[test]
    fn no_op_hosts_preserves_existing_response_and_generation() {
        let rules = hosts(
            &["a.example 192.0.2.1".into(), "empty.example".into()],
            &[],
            "fixture",
        )
        .unwrap();
        let policy = ResponsePolicy::Hosts(Rc::new(rules));
        for (name, kind, class) in [
            ("miss.example", RecordType::A, DNSClass::IN),
            ("empty.example", RecordType::A, DNSClass::IN),
            ("a.example", RecordType::MX, DNSClass::IN),
            ("a.example", RecordType::A, DNSClass::CH),
        ] {
            let (mut state, raw) = state(kind, class, name);
            state.set_synthesized_response(3).unwrap();
            let previous = state.clone();
            assert!(!apply_wire_policy(&policy, &mut state, &raw).unwrap());
            assert_eq!(state, previous);
        }
    }
    #[test]
    fn malformed_ttl_response_is_not_partially_committed() {
        for policy in [
            TtlPolicy::Fixed(0),
            TtlPolicy::Fixed(60),
            TtlPolicy::Range { min: 10, max: 100 },
        ] {
            let (mut state, raw) = state(RecordType::A, DNSClass::IN, "a.example");
            state.set_raw_response(vec![0; 13]);
            let previous = state.clone();
            assert!(apply_wire_policy(&ResponsePolicy::Ttl(policy), &mut state, &raw).is_err());
            assert_eq!(state, previous);
        }
    }
}
