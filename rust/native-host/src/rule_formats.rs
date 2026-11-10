//! Rule formats an online subscription can be downloaded in, and their
//! conversion to what the providers read.
//!
//! The content of a download is untrusted. Everything here is bounded: lines
//! are scanned one at a time, the YAML subset is read by hand (no alias
//! expansion), JSON is read as a stream without building a document tree, and
//! a file yields at most [`MAX_RULES`] rules. A download is converted once;
//! start-up and hot reloads read the converted file with
//! [`parse_text_lines`].

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::config::providers;
use crate::rule_binary;

/// The most rules one file may yield.
pub(crate) const MAX_RULES: usize = 2_000_000;
/// A line this long or longer is skipped (the reference scanner limit).
const MAX_LINE_BYTES: usize = 64 * 1024;
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// The `format` field of a source.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Format {
    #[default]
    Auto,
    Srs,
    Text,
    Yaml,
    Json,
    /// v2ray `geosite.dat` / `geoip.dat` (one category).
    Dat,
    /// mihomo binary rule set.
    Mrs,
}

impl Format {
    /// Parses a manifest or API value (case and surrounding space are ignored).
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(Self::Auto),
            "srs" => Some(Self::Srs),
            "text" => Some(Self::Text),
            "yaml" => Some(Self::Yaml),
            "json" => Some(Self::Json),
            "dat" => Some(Self::Dat),
            "mrs" => Some(Self::Mrs),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Srs => "srs",
            Self::Text => "text",
            Self::Yaml => "yaml",
            Self::Json => "json",
            Self::Dat => "dat",
            Self::Mrs => "mrs",
        }
    }

    /// `skip_serializing_if` takes a reference.
    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(crate) fn is_auto(&self) -> bool {
        *self == Self::Auto
    }
}

impl serde::Serialize for Format {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Whether `bytes` start like an SRS file (`SRS` and a version byte 0..=3).
pub(crate) fn is_srs(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes.starts_with(b"SRS") && bytes[3] <= 3
}

/// The concrete format of a download. An explicit `format` wins; `auto` looks
/// at the SRS magic, then the extension of the address, then the content.
pub(crate) fn resolve(format: Format, bytes: &[u8], url: &str) -> Format {
    if format != Format::Auto {
        return format;
    }
    if is_srs(bytes) {
        return Format::Srs;
    }
    if rule_binary::is_mrs(bytes) {
        return Format::Mrs;
    }
    let path = url
        .split(['?', '#'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    // A `.srs` address that does not deliver SRS (a 404 or portal page) must
    // fail like it always did, not be read as text.
    if path.ends_with(".srs") {
        return Format::Srs;
    }
    if path.ends_with(".dat") {
        return Format::Dat;
    }
    if path.ends_with(".mrs") {
        return Format::Mrs;
    }
    if path.ends_with(".yaml") || path.ends_with(".yml") {
        return Format::Yaml;
    }
    if path.ends_with(".json") {
        return Format::Json;
    }
    if [".txt", ".list", ".conf"]
        .iter()
        .any(|extension| path.ends_with(extension))
    {
        return Format::Text;
    }
    let body = bytes.strip_prefix(BOM).unwrap_or(bytes);
    if body
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_some_and(|byte| *byte == b'{')
    {
        return Format::Json;
    }
    if body
        .split(|byte| *byte == b'\n')
        .any(|line| line.starts_with(b"payload:"))
    {
        return Format::Yaml;
    }
    Format::Text
}

/// Rules that were not used, by reason.
#[derive(Debug, Default)]
pub(crate) struct Skipped(BTreeMap<&'static str, u64>);

impl Skipped {
    pub(super) fn add(&mut self, reason: &'static str) {
        self.add_many(reason, 1);
    }

    pub(crate) fn add_many(&mut self, reason: &'static str, count: u64) {
        if count > 0 {
            *self.0.entry(reason).or_default() += count;
        }
    }

    pub(crate) fn total(&self) -> u64 {
        self.0.values().sum()
    }

    /// The counts by reason (atom: kept with a downloaded ruleset).
    pub(crate) fn counts(&self) -> std::collections::BTreeMap<String, u64> {
        self.0
            .iter()
            .map(|(reason, count)| ((*reason).to_owned(), *count))
            .collect()
    }

    /// `reason=count, …` for the download log.
    pub(crate) fn summary(&self) -> String {
        let parts: Vec<String> = self
            .0
            .iter()
            .map(|(reason, count)| format!("{reason}={count}"))
            .collect();
        parts.join(", ")
    }
}

/// What a file holds: domain rules in provider text form (`domain:`, `full:`,
/// `keyword:`, `regexp:`), IP prefixes, and what was left out.
#[derive(Debug, Default)]
pub(crate) struct Parsed {
    pub(crate) domains: Vec<String>,
    pub(crate) ips: Vec<(IpAddr, u8)>,
    pub(crate) skipped: Skipped,
}

impl Parsed {
    pub(super) fn check_room(&self) -> Result<(), String> {
        if self.domains.len() + self.ips.len() >= MAX_RULES {
            return Err(format!("more than {MAX_RULES} rules in one file"));
        }
        Ok(())
    }

    pub(super) fn push_domain(&mut self, rule: String) -> Result<(), String> {
        self.check_room()?;
        self.domains.push(rule);
        Ok(())
    }

    pub(super) fn push_ip(&mut self, prefix: (IpAddr, u8)) -> Result<(), String> {
        self.check_room()?;
        self.ips.push(prefix);
        Ok(())
    }
}

/// What a bare domain (`example.com`) means in the file being read.
#[derive(Clone, Copy)]
enum Bare {
    /// Text lists (atomdns, v2ray): the domain and its subdomains.
    Domain,
    /// Clash rule-provider YAML: exactly this name.
    Full,
}

#[derive(Clone, Copy)]
pub(super) enum Name {
    Domain,
    Full,
    Keyword,
}

impl Name {
    pub(super) fn prefix(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Full => "full",
            Self::Keyword => "keyword",
        }
    }
}

/// Reads `bytes` in `format` (`Text`, `Yaml` or `Json`).
///
/// `regexp` says whether regular expressions may be used; when false they are
/// counted as skipped.
///
/// # Errors
///
/// A message when the content is not that format or holds too many rules.
pub(crate) fn parse(bytes: &[u8], format: Format, regexp: bool) -> Result<Parsed, String> {
    let bytes = bytes.strip_prefix(BOM).unwrap_or(bytes);
    let mut out = Parsed::default();
    match format {
        Format::Yaml => parse_yaml(bytes, regexp, &mut out)?,
        Format::Json => parse_json(bytes, regexp, &mut out)?,
        Format::Text => parse_lines(bytes, Bare::Domain, regexp, &mut out)?,
        Format::Auto | Format::Srs | Format::Dat | Format::Mrs => {
            return Err("not a text format".to_owned());
        }
    }
    Ok(out)
}

/// Reads the converted (or hand-written) text file of a source.
///
/// # Errors
///
/// A message when the file holds too many rules.
pub(crate) fn parse_text_lines(bytes: &[u8], regexp: bool) -> Result<Parsed, String> {
    parse(bytes, Format::Text, regexp)
}

fn parse_lines(bytes: &[u8], bare: Bare, regexp: bool, out: &mut Parsed) -> Result<(), String> {
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.len() >= MAX_LINE_BYTES {
            out.skipped.add("line too long");
            continue;
        }
        parse_line(&String::from_utf8_lossy(line), bare, regexp, out)?;
    }
    Ok(())
}

fn is_regexp_line(line: &str) -> bool {
    line.starts_with("regexp:")
        || line
            .get(..12)
            .is_some_and(|head| head.eq_ignore_ascii_case("DOMAIN-REGEX"))
}

fn parse_line(raw: &str, bare: Bare, regexp: bool, out: &mut Parsed) -> Result<(), String> {
    let mut line = raw.trim();
    if line.is_empty()
        || line.starts_with(['#', '!', ';'])
        || line.starts_with("//")
        || (line.starts_with('[') && line.ends_with(']'))
    {
        return Ok(());
    }
    if !is_regexp_line(line)
        && let Some(at) = line.find(" #").or_else(|| line.find("\t#"))
    {
        line = line[..at].trim_end();
    }
    for (prefix, kind) in [
        ("domain:", Name::Domain),
        ("full:", Name::Full),
        ("keyword:", Name::Keyword),
    ] {
        if let Some(value) = line.strip_prefix(prefix) {
            let value = value.split_whitespace().next().unwrap_or("");
            let value = value.split(":@").next().unwrap_or("");
            return push_name(kind, value, out);
        }
    }
    if let Some(pattern) = line.strip_prefix("regexp:") {
        return push_regexp(pattern.trim(), regexp, out);
    }
    if let Some((head, rest)) = line.split_once(',')
        && is_type_word(head.trim())
    {
        return classic(head.trim(), rest, regexp, out);
    }
    if let Some(done) = dnsmasq(line, out) {
        return done;
    }
    if line.starts_with("||") {
        return adblock(line, out);
    }
    let mut tokens = line.split_whitespace();
    let first = tokens.next().unwrap_or("");
    if first.parse::<IpAddr>().is_ok() && line.split_whitespace().nth(1).is_some() {
        return hosts(tokens, out);
    }
    if line.split_whitespace().nth(1).is_some() {
        out.skipped.add("unrecognized");
        return Ok(());
    }
    mihomo_or_bare(line, bare, regexp, out)
}

fn is_type_word(head: &str) -> bool {
    head.len() >= 2
        && head.starts_with(|c: char| c.is_ascii_alphabetic())
        && head.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Clash / Surge / QuantumultX rule lines: `TYPE,value[,options…]`.
fn classic(kind: &str, rest: &str, regexp: bool, out: &mut Parsed) -> Result<(), String> {
    let value = rest.split(',').next().unwrap_or("").trim();
    match kind.to_ascii_lowercase().as_str() {
        "domain" | "host" => push_name(Name::Full, value, out),
        "domain-suffix" | "host-suffix" => push_name(Name::Domain, value, out),
        "domain-keyword" | "host-keyword" => push_name(Name::Keyword, value, out),
        "domain-regex" => {
            // The pattern may hold commas, so it cannot be told from the
            // options that follow it; refuse to cut it.
            if rest.contains(',') {
                out.skipped.add("regexp with a comma");
                return Ok(());
            }
            push_regexp(value, regexp, out)
        }
        "ip-cidr" | "ip-cidr6" | "ip6-cidr" => push_prefix(value, out),
        _ => {
            out.skipped.add("unsupported rule type");
            Ok(())
        }
    }
}

/// `server=/a/b/target`, `address=/a/b/ip`, `ipset=/a/b/set`, `nftset=/a/b/set`.
fn dnsmasq(line: &str, out: &mut Parsed) -> Option<Result<(), String>> {
    let (key, rest) = line.split_once("=/")?;
    if !matches!(key, "server" | "address" | "ipset" | "nftset" | "local") {
        return None;
    }
    let mut segments: Vec<&str> = rest.split('/').collect();
    // The last segment is the target (possibly empty), never a domain.
    segments.pop();
    if segments.is_empty() {
        out.skipped.add("invalid name");
        return Some(Ok(()));
    }
    for segment in segments {
        if let Err(error) = push_name(Name::Domain, segment, out) {
            return Some(Err(error));
        }
    }
    Some(Ok(()))
}

/// AdGuard `||name^`; every other adblock form is left out.
fn adblock(line: &str, out: &mut Parsed) -> Result<(), String> {
    match providers::adguard_rules(line).as_slice() {
        [(false, rule)] if !rule.starts_with("regexp:") => out.push_domain(rule.clone()),
        _ => {
            out.skipped.add("unsupported adblock rule");
            Ok(())
        }
    }
}

const LOCAL_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
];

pub(crate) fn is_local_name(name: &str) -> bool {
    LOCAL_NAMES
        .iter()
        .any(|local| name.eq_ignore_ascii_case(local))
}

/// `<ip> name [name…] [# comment]`.
fn hosts<'a>(names: impl Iterator<Item = &'a str>, out: &mut Parsed) -> Result<(), String> {
    for name in names.take_while(|name| !name.starts_with('#')) {
        if is_local_name(name) {
            continue;
        }
        if name.contains('.') {
            push_name(Name::Full, name, out)?;
        } else {
            out.skipped.add("invalid name");
        }
    }
    Ok(())
}

fn mihomo_or_bare(line: &str, bare: Bare, regexp: bool, out: &mut Parsed) -> Result<(), String> {
    if let Some(name) = line.strip_prefix("+.").or_else(|| line.strip_prefix('.')) {
        return push_name(Name::Domain, name, out);
    }
    if line.contains('*') {
        return match wildcard_regexp(line) {
            Some(pattern) => push_regexp(&pattern, regexp, out),
            None => {
                out.skipped.add("invalid name");
                Ok(())
            }
        };
    }
    if line.contains('/') || line.parse::<IpAddr>().is_ok() {
        return push_prefix(line, out);
    }
    if !line.contains('.') {
        out.skipped.add("unrecognized");
        return Ok(());
    }
    let kind = match bare {
        Bare::Domain => Name::Domain,
        Bare::Full => Name::Full,
    };
    push_name(kind, line, out)
}

/// mihomo wildcards: a whole `*` label is exactly one label; `*` inside a
/// label is any run of characters within that label.
fn wildcard_regexp(pattern: &str) -> Option<String> {
    let labels: Vec<&str> = pattern.trim_matches('.').split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'*'))
        })
    {
        return None;
    }
    let converted: Vec<String> = labels
        .iter()
        .map(|label| match *label {
            "*" => "[^.]+".to_owned(),
            other => other.to_ascii_lowercase().replace('*', "[^.]*"),
        })
        .collect();
    Some(format!("^{}$", converted.join("\\.")))
}

pub(super) fn name_ok(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

pub(super) fn push_name(kind: Name, value: &str, out: &mut Parsed) -> Result<(), String> {
    let value = value.trim();
    // A keyword keeps its dots: `.ads` is not `ads`.
    let value = if matches!(kind, Name::Keyword) {
        value
    } else {
        value.trim_matches('.')
    };
    if !value.is_ascii() {
        out.skipped.add("non-ASCII name");
        return Ok(());
    }
    if !name_ok(value) {
        out.skipped.add("invalid name");
        return Ok(());
    }
    out.push_domain(format!("{}:{}", kind.prefix(), value.to_ascii_lowercase()))
}

pub(super) fn push_regexp(pattern: &str, regexp: bool, out: &mut Parsed) -> Result<(), String> {
    if !regexp {
        out.skipped.add("regexp disabled");
        return Ok(());
    }
    if pattern.is_empty() {
        out.skipped.add("invalid name");
        return Ok(());
    }
    // A rule is one line of the converted file and is read back trimmed: a line
    // break would inject another rule, edge whitespace would be lost.
    if pattern.chars().any(char::is_control) || pattern.trim() != pattern {
        out.skipped
            .add("regexp with a control character or edge space");
        return Ok(());
    }
    out.push_domain(format!("regexp:{pattern}"))
}

/// `a.b.c.d`, `a.b.c.d/n`, an IPv6 address or prefix.
pub(crate) fn parse_prefix(value: &str) -> Option<(IpAddr, u8)> {
    let (address, bits) = match value.split_once('/') {
        Some((address, bits)) => (
            address.parse::<IpAddr>().ok()?,
            Some(bits.parse::<u8>().ok()?),
        ),
        None => (value.parse::<IpAddr>().ok()?, None),
    };
    let widest = if address.is_ipv4() { 32 } else { 128 };
    let bits = bits.unwrap_or(widest);
    (bits <= widest).then_some((address, bits))
}

pub(super) fn push_prefix(value: &str, out: &mut Parsed) -> Result<(), String> {
    match parse_prefix(value.trim()) {
        Some(prefix) => out.push_ip(prefix),
        None => {
            out.skipped.add("invalid address");
            Ok(())
        }
    }
}

// ----- YAML (Clash rule providers) -------------------------------------------

/// Reads the top-level `payload:` list of strings; nothing else of the YAML
/// language is interpreted.
fn parse_yaml(bytes: &[u8], regexp: bool, out: &mut Parsed) -> Result<(), String> {
    let (mut found, mut in_payload) = (false, false);
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.len() >= MAX_LINE_BYTES {
            out.skipped.add("line too long");
            continue;
        }
        let line = String::from_utf8_lossy(line);
        let line = line.trim_end();
        let body = line.trim_start();
        if body.is_empty() || body.starts_with('#') || line == "---" || line == "..." {
            continue;
        }
        let indented = line.starts_with([' ', '\t']);
        if !indented && !line.starts_with("- ") && line != "-" {
            in_payload = false;
            if let Some(rest) = line.strip_prefix("payload:") {
                let rest = rest.trim();
                if rest.starts_with('[') || rest.starts_with('{') {
                    return Err("flow-style payload is not supported".to_owned());
                }
                found = true;
                in_payload = true;
            }
            continue;
        }
        if !in_payload {
            continue;
        }
        let Some(item) = body.strip_prefix('-') else {
            out.skipped.add("unrecognized");
            continue;
        };
        parse_line(&yaml_scalar(item.trim()), Bare::Full, regexp, out)?;
    }
    if !found {
        return Err("no payload list found".to_owned());
    }
    Ok(())
}

/// The text of a plain, single- or double-quoted scalar.
fn yaml_scalar(item: &str) -> String {
    for quote in ['\'', '"'] {
        if let Some(rest) = item.strip_prefix(quote) {
            let mut text = String::new();
            let mut chars = rest.chars().peekable();
            while let Some(c) = chars.next() {
                match (c, quote) {
                    ('\'', '\'') if chars.peek() == Some(&'\'') => {
                        chars.next();
                        text.push('\'');
                    }
                    (c, q) if c == q => break,
                    ('\\', '"') => match chars.next() {
                        Some(escaped @ ('"' | '\\')) => text.push(escaped),
                        Some(other) => {
                            text.push('\\');
                            text.push(other);
                        }
                        None => {}
                    },
                    (c, _) => text.push(c),
                }
            }
            return text;
        }
    }
    item.to_owned()
}

// ----- JSON (sing-box source rule sets) --------------------------------------

fn parse_json(bytes: &[u8], regexp: bool, out: &mut Parsed) -> Result<(), String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    Document { regexp, out }
        .deserialize(&mut deserializer)
        .map_err(|error| format!("invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("invalid JSON: {error}"))
}

struct Document<'a> {
    regexp: bool,
    out: &'a mut Parsed,
}

impl<'de> DeserializeSeed<'de> for Document<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Document<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a rule set object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            if key == "rules" {
                map.next_value_seed(Rules {
                    regexp: self.regexp,
                    out: &mut *self.out,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct Rules<'a> {
    regexp: bool,
    out: &'a mut Parsed,
}

impl<'de> DeserializeSeed<'de> for Rules<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Rules<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a list of rules")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq
            .next_element_seed(Rule {
                regexp: self.regexp,
                out: &mut *self.out,
            })?
            .is_some()
        {}
        Ok(())
    }
}

/// One headless rule. Its conditions are read into lists first because the
/// rule is only usable when it has no other condition.
struct Rule<'a> {
    regexp: bool,
    out: &'a mut Parsed,
}

#[derive(Default)]
struct Conditions {
    domain: Vec<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    regex: Vec<String>,
    cidr: Vec<String>,
    /// A condition atomdns cannot express (or `type: logical`, `invert: true`).
    other: bool,
}

impl<'de> DeserializeSeed<'de> for Rule<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Rule<'_> {
    type Value = ();

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a rule object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        use serde::de::Error;
        let mut found = Conditions::default();
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "domain" => found.domain = map.next_value::<Strings>()?.0,
                "domain_suffix" => found.suffix = map.next_value::<Strings>()?.0,
                "domain_keyword" => found.keyword = map.next_value::<Strings>()?.0,
                "domain_regex" => found.regex = map.next_value::<Strings>()?.0,
                "ip_cidr" => found.cidr = map.next_value::<Strings>()?.0,
                "type" => found.other |= map.next_value::<String>()? != "default",
                "invert" => found.other |= map.next_value::<bool>()?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                    found.other = true;
                }
            }
        }
        apply(&found, self.regexp, self.out).map_err(A::Error::custom)
    }
}

/// A string or a list of strings.
struct Strings(Vec<String>);

impl<'de> serde::Deserialize<'de> for Strings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct One;
        impl<'de> Visitor<'de> for One {
            type Value = Strings;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a string or a list of strings")
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Strings, E> {
                Ok(Strings(vec![value.to_owned()]))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strings, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<String>()? {
                    if values.len() >= MAX_RULES {
                        return Err(serde::de::Error::custom(format!(
                            "more than {MAX_RULES} values in one list"
                        )));
                    }
                    values.push(value);
                }
                Ok(Strings(values))
            }
        }
        deserializer.deserialize_any(One)
    }
}

fn apply(found: &Conditions, regexp: bool, out: &mut Parsed) -> Result<(), String> {
    let has_domain = !(found.domain.is_empty()
        && found.suffix.is_empty()
        && found.keyword.is_empty()
        && found.regex.is_empty());
    if found.other {
        out.skipped.add("unsupported rule");
        return Ok(());
    }
    // Conditions of one rule all have to match; the two kinds cannot be
    // split into two sets without matching more than the rule does.
    if has_domain && !found.cidr.is_empty() {
        out.skipped.add("mixed domain and ip rule");
        return Ok(());
    }
    for value in &found.domain {
        push_name(Name::Full, value, out)?;
    }
    for value in &found.suffix {
        push_name(Name::Domain, value, out)?;
    }
    for value in &found.keyword {
        push_name(Name::Keyword, value, out)?;
    }
    for value in &found.regex {
        push_regexp(value, regexp, out)?;
    }
    for value in &found.cidr {
        push_prefix(value, out)?;
    }
    Ok(())
}

// ----- AdGuard text ------------------------------------------------------------

/// Whether `bytes` are AdGuard (or hosts) text: every line that gives a domain
/// rule when read as rule text is also read by the AdGuard reader. A file that
/// mixes in other syntax (Clash rules, dnsmasq lines, …) is converted instead,
/// because the AdGuard reader would silently ignore those lines.
pub(crate) fn is_adguard_text(bytes: &[u8]) -> bool {
    bytes
        .split(|byte| *byte == b'\n')
        .take_while(|line| line.len() < MAX_LINE_BYTES)
        .all(|line| {
            let line = String::from_utf8_lossy(line);
            if !providers::adguard_rules(&line).is_empty() {
                return true;
            }
            let mut out = Parsed::default();
            parse_line(&line, Bare::Domain, true, &mut out).is_err() || out.domains.is_empty()
        })
}

// ----- converted files -------------------------------------------------------

fn header(format: Format, url: &str) -> String {
    let url: String = url
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    format!("# atomdns: converted from {} {url}\n", format.as_str())
}

/// The converted file of a domain set: one rule per line.
pub(crate) fn domain_file(domains: &[String], format: Format, url: &str) -> Vec<u8> {
    let mut text = header(format, url);
    for rule in domains {
        text.push_str(rule);
        text.push('\n');
    }
    text.into_bytes()
}

/// The converted file of an IP set: one CIDR per line.
pub(crate) fn ip_file(ips: &[(IpAddr, u8)], format: Format, url: &str) -> Vec<u8> {
    let mut text = header(format, url);
    for (address, bits) in ips {
        text.push_str(&format!("{address}/{bits}\n"));
    }
    text.into_bytes()
}

/// The rule the AdGuard reader gets back from the line written for `rule`.
fn adguard_form(rule: &str) -> Option<(String, String)> {
    let (kind, value) = rule.split_once(':')?;
    match kind {
        "domain" => Some((format!("||{value}^"), rule.to_owned())),
        "full" => Some((value.to_owned(), rule.to_owned())),
        "regexp" => Some((format!("/{value}/"), rule.to_owned())),
        "keyword" => {
            let escaped = value.replace('.', "\\.");
            Some((format!("/{escaped}/"), format!("regexp:{escaped}")))
        }
        _ => None,
    }
}

/// AdGuard text for domain rules. A rule whose line the AdGuard reader would
/// not read back as the same rule is left out and counted.
pub(crate) fn adguard_file(
    domains: &[String],
    skipped: &mut Skipped,
    format: Format,
    url: &str,
) -> (Vec<u8>, usize) {
    let mut text = header(format, url);
    let mut written = 0;
    for rule in domains {
        // One rule is one line; a line break would start another rule.
        let readable = adguard_form(rule)
            .filter(|_| !rule.chars().any(char::is_control))
            .filter(|(line, expected)| {
                providers::adguard_rules(line).as_slice() == [(false, expected.clone())]
            });
        match readable {
            Some((line, _)) => {
                text.push_str(&line);
                text.push('\n');
                written += 1;
            }
            None => skipped.add("not representable as AdGuard"),
        }
    }
    (text.into_bytes(), written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(input: &str) -> Parsed {
        parse(input.as_bytes(), Format::Text, true).unwrap()
    }

    fn domains(input: &str) -> Vec<String> {
        text(input).domains
    }

    #[test]
    fn format_values_and_serialization() {
        assert_eq!(Format::parse(" YAML "), Some(Format::Yaml));
        assert_eq!(Format::parse("auto"), Some(Format::Auto));
        assert_eq!(Format::parse(" DAT "), Some(Format::Dat));
        assert_eq!(Format::parse("mrs"), Some(Format::Mrs));
        assert_eq!(Format::parse("mmdb"), None);
        assert_eq!(serde_json::to_string(&Format::Srs).unwrap(), "\"srs\"");
        assert!(Format::default().is_auto());
    }

    #[test]
    fn auto_detection_order() {
        let url = "https://example.com/a.txt";
        assert_eq!(resolve(Format::Auto, b"SRS\x03xyz", url), Format::Srs);
        assert_eq!(
            resolve(Format::Auto, b"{}", "https://example.com/a.yml?x=1"),
            Format::Yaml
        );
        assert_eq!(
            resolve(Format::Auto, b"x", "https://example.com/a.JSON#f"),
            Format::Json
        );
        for extension in ["txt", "list", "conf"] {
            let url = format!("https://example.com/a.{extension}");
            assert_eq!(
                resolve(Format::Auto, b"{\"a\":1}", &url),
                Format::Text,
                "{url}"
            );
        }
        let plain = "https://example.com/rules";
        assert_eq!(
            resolve(Format::Auto, b"  \n{\"rules\":[]}", plain),
            Format::Json
        );
        assert_eq!(
            resolve(Format::Auto, b"# c\npayload:\n  - a.example\n", plain),
            Format::Yaml
        );
        assert_eq!(resolve(Format::Auto, b"a.example\n", plain), Format::Text);
        assert_eq!(resolve(Format::Json, b"SRS\x03", plain), Format::Json);
        assert_eq!(
            resolve(Format::Auto, b"<html>", "https://example.com/a.SRS?x=1"),
            Format::Srs
        );
        assert_eq!(
            resolve(Format::Auto, b"x", "https://example.com/geosite.DAT?x=1"),
            Format::Dat
        );
        assert_eq!(
            resolve(Format::Auto, b"x", "https://example.com/cn.mrs"),
            Format::Mrs
        );
        assert!(!is_srs(b"SRS\x09"));
        assert!(!is_srs(b"SRS"));
    }

    #[test]
    fn plain_and_prefixed_lines() {
        let got = domains(
            "# c\n! c\n// c\n; c\n[Rule]\n\nexample.com\n.example.org\n+.example.net\n\
             domain:Sub.Example.com @cn\nfull:www.example.com\nkeyword:ads\n\
             domain:a.example.com:@ads\n",
        );
        assert_eq!(
            got,
            [
                "domain:example.com",
                "domain:example.org",
                "domain:example.net",
                "domain:sub.example.com",
                "full:www.example.com",
                "keyword:ads",
                "domain:a.example.com",
            ]
        );
    }

    #[test]
    fn classic_rules() {
        let parsed = text(
            "DOMAIN,full.example.com\ndomain-suffix,suffix.example.com,PROXY\n\
             Domain-Keyword,kw,REJECT\nHOST,h.example.com\nHOST-SUFFIX,hs.example.com\n\
             HOST-KEYWORD,hk\nDOMAIN-REGEX,^a[0-9]\\.example\\.com$\n\
             IP-CIDR,192.0.2.0/24,no-resolve\nIP-CIDR6,2001:db8::/32\nIP6-CIDR,2001:db8:1::/48\n\
             PROCESS-NAME,foo\nGEOIP,CN\nDST-PORT,53\nDOMAIN-REGEX,a{1,3}\\.example,REJECT\n",
        );
        assert_eq!(
            parsed.domains,
            [
                "full:full.example.com",
                "domain:suffix.example.com",
                "keyword:kw",
                "full:h.example.com",
                "domain:hs.example.com",
                "keyword:hk",
                "regexp:^a[0-9]\\.example\\.com$",
            ]
        );
        assert_eq!(parsed.ips.len(), 3);
        assert_eq!(parsed.skipped.total(), 4);
        assert!(parsed.skipped.summary().contains("unsupported rule type=3"));
        assert!(parsed.skipped.summary().contains("regexp with a comma=1"));
    }

    #[test]
    fn dnsmasq_lines() {
        let got = domains(
            "server=/a.example.com/b.example.org/192.0.2.53\naddress=/c.example.com/\n\
             ipset=/d.example.com/set\nnftset=/e.example.com/4#inet#t#s\n\
             server=/f.example.com/\n",
        );
        assert_eq!(
            got,
            [
                "domain:a.example.com",
                "domain:b.example.org",
                "domain:c.example.com",
                "domain:d.example.com",
                "domain:e.example.com",
                "domain:f.example.com",
            ]
        );
    }

    #[test]
    fn hosts_lines() {
        let parsed = text(
            "127.0.0.1 localhost\n::1 localhost ip6-localhost\n0.0.0.0 ad.example.com tr.example.org # x\n\
             192.0.2.7 intra.example.net\n0.0.0.0 0.0.0.0\n:: v6.example.com\n",
        );
        assert_eq!(
            parsed.domains,
            [
                "full:ad.example.com",
                "full:tr.example.org",
                "full:intra.example.net",
                "full:v6.example.com",
            ]
        );
        assert!(parsed.ips.is_empty());
    }

    #[test]
    fn adguard_and_mihomo_forms() {
        let parsed = text(
            "||ads.example.com^\n||*.wild.example.org^\n@@||ok.example.com^\n||x.example.com^$important\n\
             |http://a.example.com\n*.one.example.com\n*.*.two.example.com\nwww.*.example.org\n\
             a*b.example.net\n",
        );
        assert_eq!(
            parsed.domains,
            [
                "domain:ads.example.com",
                "domain:wild.example.org",
                "regexp:^[^.]+\\.one\\.example\\.com$",
                "regexp:^[^.]+\\.[^.]+\\.two\\.example\\.com$",
                "regexp:^www\\.[^.]+\\.example\\.org$",
                "regexp:^a[^.]*b\\.example\\.net$",
            ]
        );
        assert_eq!(parsed.skipped.total(), 3);
        for rule in &parsed.domains {
            if let Some(pattern) = rule.strip_prefix("regexp:") {
                atomdns_matcher_core::check_go_regexp(pattern).unwrap();
            }
        }
    }

    #[test]
    fn ip_lines_and_unrecognized_text() {
        let parsed = text(
            "192.0.2.1\n198.51.100.0/24\n2001:db8::/32\n2001:db8::1\n203.0.113.0/33\n\
             localhost\nnot a rule\n<html>\n",
        );
        assert_eq!(parsed.ips.len(), 4);
        assert!(parsed.domains.is_empty());
        assert_eq!(parsed.skipped.total(), 4);
        assert_eq!(
            parse_prefix("192.0.2.1"),
            Some(("192.0.2.1".parse().unwrap(), 32))
        );
        assert_eq!(
            parse_prefix("2001:db8::1"),
            Some(("2001:db8::1".parse().unwrap(), 128))
        );
    }

    #[test]
    fn regexp_needs_the_switch() {
        let input = "regexp:^a\\.example\\.com$\nDOMAIN-REGEX,^b\\.example\\.com$\n*.c.example.com\nd.example.com\n";
        let off = parse(input.as_bytes(), Format::Text, false).unwrap();
        assert_eq!(off.domains, ["domain:d.example.com"]);
        assert!(off.skipped.summary().contains("regexp disabled=3"));
        let on = parse(input.as_bytes(), Format::Text, true).unwrap();
        assert_eq!(on.domains.len(), 4);
    }

    #[test]
    fn a_regexp_cannot_carry_a_line_break_into_the_converted_file() {
        let json = "{\"rules\":[{\"domain_regex\":[\")\\nregexp:\\\\p{L}+\",\"a\\rb\",\" ^c$\",\"^ok\\\\.example\\\\.com$\"]}]}";
        let parsed = parse(json.as_bytes(), Format::Json, true).unwrap();
        assert_eq!(parsed.domains, ["regexp:^ok\\.example\\.com$"]);
        assert!(
            parsed
                .skipped
                .summary()
                .contains("regexp with a control character or edge space=3")
        );
        let file = String::from_utf8(domain_file(
            &parsed.domains,
            Format::Json,
            "https://example.com/a.json",
        ))
        .unwrap();
        assert_eq!(file.lines().count(), 2);
        // The block-list writer also takes rules that did not come from the
        // line parsers (an SRS file): a rule with a line break is left out.
        let mut skipped = Skipped::default();
        let rules = [
            ")\n||victim.example^\n(".to_owned(),
            "ok.example.com".to_owned(),
        ]
        .map(|body| format!("regexp:{body}"));
        let (text, written) = adguard_file(
            &rules,
            &mut skipped,
            Format::Srs,
            "https://example.com/a.srs",
        );
        assert_eq!(written, 1);
        assert_eq!(String::from_utf8(text).unwrap().lines().count(), 2);
        assert_eq!(skipped.total(), 1);
    }

    #[test]
    fn non_ascii_and_oversized_lines_are_skipped() {
        let mut input = String::from("例え.example.com\nok.example.com\n");
        input.push_str(&"a".repeat(MAX_LINE_BYTES));
        input.push_str("\nlast.example.com\n");
        let parsed = text(&input);
        assert_eq!(
            parsed.domains,
            ["domain:ok.example.com", "domain:last.example.com"]
        );
        assert_eq!(parsed.skipped.total(), 2);
    }

    #[test]
    fn rule_count_is_limited() {
        let mut parsed = Parsed::default();
        parsed.domains.resize(MAX_RULES, String::new());
        assert!(parsed.push_domain("full:a.example".to_owned()).is_err());
        assert!(parsed.push_ip(("192.0.2.1".parse().unwrap(), 32)).is_err());
        let small = Parsed::default();
        assert!(small.check_room().is_ok());
    }

    #[test]
    fn yaml_payload() {
        let input = "# header\nbehavior: domain\npayload:\n  - '+.suffix.example.com'\n  \
                     - \"full.example.com\"   # note\n  - plain.example.org\n  - DOMAIN-SUFFIX,c.example.com\n  \
                     - '192.0.2.0/24'\n  - 'it''s.example.com'\n  - 'q.example.com'\nother:\n  - ignored.example.com\n";
        let parsed = parse(input.as_bytes(), Format::Yaml, true).unwrap();
        assert_eq!(
            parsed.domains,
            [
                "domain:suffix.example.com",
                "full:full.example.com",
                "full:plain.example.org",
                "domain:c.example.com",
                "full:q.example.com",
            ]
        );
        assert_eq!(parsed.ips.len(), 1);
        assert_eq!(parsed.skipped.total(), 1);
        // Unindented list items under `payload:` are accepted too.
        let flat = parse(
            b"payload:\n- a.example.com\n- b.example.com\n",
            Format::Yaml,
            true,
        )
        .unwrap();
        assert_eq!(flat.domains.len(), 2);
    }

    #[test]
    fn yaml_without_payload_or_with_flow_style_is_refused() {
        assert!(parse(b"rules:\n  - a.example.com\n", Format::Yaml, true).is_err());
        assert!(parse(b"payload: ['a.example.com']\n", Format::Yaml, true).is_err());
        let empty = parse(b"payload: # none\n", Format::Yaml, true).unwrap();
        assert!(empty.domains.is_empty());
    }

    #[test]
    fn yaml_aliases_are_not_expanded() {
        let input = "x: &a [1,2,3]\ny: &b [*a,*a,*a,*a]\npayload:\n  - *b\n  - ok.example.com\n";
        let parsed = parse(input.as_bytes(), Format::Yaml, true).unwrap();
        assert_eq!(parsed.domains, ["full:ok.example.com"]);
        assert_eq!(parsed.skipped.total(), 1);
    }

    #[test]
    fn json_rule_set() {
        let input = r#"{"version": 2, "rules": [
            {"domain": "full.example.com", "domain_suffix": [".suf.example.com", "s2.example.com"]},
            {"domain_keyword": ["kw"], "domain_regex": "^r\\.example\\.com$"},
            {"ip_cidr": ["192.0.2.0/24", "2001:db8::/32", "198.51.100.9", "bad"]},
            {"domain": ["port.example.com"], "port": [443]},
            {"type": "logical", "mode": "and", "rules": [{"domain": ["l.example.com"]}]},
            {"domain": ["inv.example.com"], "invert": true},
            {"domain": ["both.example.com"], "ip_cidr": ["203.0.113.0/24"]},
            {"type": "default", "invert": false, "domain": ["ok.example.com"]}
        ]}"#;
        let parsed = parse(input.as_bytes(), Format::Json, true).unwrap();
        assert_eq!(
            parsed.domains,
            [
                "full:full.example.com",
                "domain:suf.example.com",
                "domain:s2.example.com",
                "keyword:kw",
                "regexp:^r\\.example\\.com$",
                "full:ok.example.com",
            ]
        );
        assert_eq!(parsed.ips.len(), 3);
        let summary = parsed.skipped.summary();
        assert!(summary.contains("unsupported rule=3"), "{summary}");
        assert!(summary.contains("mixed domain and ip rule=1"), "{summary}");
        assert!(summary.contains("invalid address=1"), "{summary}");
        let off = parse(input.as_bytes(), Format::Json, false).unwrap();
        assert!(off.skipped.summary().contains("regexp disabled=1"));
    }

    #[test]
    fn broken_json_is_refused() {
        assert!(parse(b"{\"rules\": [", Format::Json, true).is_err());
        assert!(parse(b"{\"rules\": [{\"domain\": 5}]}", Format::Json, true).is_err());
        assert!(parse(b"{\"rules\": []} x", Format::Json, true).is_err());
        let none = parse(b"{\"version\": 1}", Format::Json, true).unwrap();
        assert!(none.domains.is_empty());
    }

    #[test]
    fn keywords_keep_their_dots() {
        let parsed = text("keyword:.ads\nkeyword:ads.\nDOMAIN-KEYWORD,.x\n.dom.example.com.\n");
        assert_eq!(
            parsed.domains,
            [
                "keyword:.ads",
                "keyword:ads.",
                "keyword:.x",
                "domain:dom.example.com"
            ]
        );
        let json = br#"{"rules":[{"domain_keyword":[".ads"]}]}"#;
        assert_eq!(
            parse(json, Format::Json, true).unwrap().domains,
            ["keyword:.ads"]
        );
    }

    #[test]
    fn adguard_text_is_told_from_mixed_files() {
        assert!(is_adguard_text(
            b"! t\n||ads.example.com^\n@@||ok.example.com^\nplain.example.org\n0.0.0.0 h.example.net\n\
              example.com##.banner\n||x.example.com^$important\n/ads[0-9]/\n|http://a.example.com\n"
        ));
        assert!(!is_adguard_text(
            b"DOMAIN-SUFFIX,ads.example.com\ntracker.example.net\n"
        ));
        assert!(!is_adguard_text(
            b"||ads.example.com^\nserver=/dns.example.com/192.0.2.53\n"
        ));
        assert!(!is_adguard_text(b"+.mihomo.example.com\n"));
        assert!(!is_adguard_text(b"192.0.2.1 other.example.com\n"));
        assert!(is_adguard_text(b"192.0.2.0/24\n"));
    }

    #[test]
    fn converted_files_read_back() {
        let parsed = text(
            "example.com\nfull:www.example.org\nkeyword:ads\nregexp:^a\\.example$\n198.51.100.0/24\n",
        );
        let file = domain_file(
            &parsed.domains,
            Format::Text,
            "https://example.com/a\nb.txt",
        );
        let first = String::from_utf8(file.clone()).unwrap();
        assert!(first.starts_with("# atomdns: converted from text https://example.com/a b.txt\n"));
        let again = parse_text_lines(&file, true).unwrap();
        assert_eq!(again.domains, parsed.domains);
        let ips = ip_file(&parsed.ips, Format::Text, "https://example.com/i.txt");
        assert_eq!(parse_text_lines(&ips, true).unwrap().ips, parsed.ips);
    }

    #[test]
    fn adguard_text_reads_back_as_the_same_rules() {
        let rules: Vec<String> = [
            "domain:ads.example.com",
            "full:www.example.org",
            "keyword:track.ing",
            "regexp:^a[0-9]+\\.example\\.com$",
            "full:single",
            "domain:with space.example",
            "regexp:a##b",
        ]
        .map(str::to_owned)
        .to_vec();
        let mut skipped = Skipped::default();
        let (file, written) = adguard_file(
            &rules,
            &mut skipped,
            Format::Json,
            "https://example.com/x.json",
        );
        assert_eq!(written, 4);
        assert_eq!(skipped.total(), 3);
        let (mut allow, mut deny) = (Vec::new(), Vec::new());
        let count = providers::parse_adguard_list("t", "n", &file, &mut allow, &mut deny);
        assert_eq!(count, 4);
        assert!(allow.is_empty());
        let got: Vec<&str> = deny.iter().map(|entry| entry.rule.as_str()).collect();
        assert_eq!(
            got,
            [
                "domain:ads.example.com",
                "full:www.example.org",
                "regexp:track\\.ing",
                "regexp:^a[0-9]+\\.example\\.com$",
            ]
        );
    }
}
