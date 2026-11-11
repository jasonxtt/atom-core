//! Binary rule files an online subscription can be downloaded in: v2ray
//! `geosite.dat` / `geoip.dat` and mihomo `.mrs`.
//!
//! The content of a download is untrusted. Everything here is bounded: a zstd
//! stream is decoded through a hard output limit, protobuf is walked flat over
//! the input slice (no recursion, no copies of categories that are not
//! wanted), and declared counts never size an allocation. Both readers only
//! produce the [`Parsed`] rules the text formats produce, so storing, regexp
//! gating and the AdGuard conversion are shared.

use std::collections::BTreeSet;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use atomdns_matcher_core::{
    MAX_INFLATED_BYTES, MAX_SET_BYTES, MAX_SET_WORDS, range_to_prefixes, succinct_set_keys,
};
use ruzstd::decoding::StreamingDecoder;

use crate::rule_formats::{Name, Parsed, name_ok, push_name, push_regexp};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const MRS_MAGIC: [u8; 4] = *b"MRS\x01";
/// How many category names an error lists.
const LISTED_CATEGORIES: usize = 20;

/// What a subscription needs from a file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Want {
    Domains,
    Ips,
}

impl Want {
    fn noun(self) -> &'static str {
        match self {
            Self::Domains => "domain",
            Self::Ips => "ip",
        }
    }
}

/// A byte cursor over a slice; every read is bounds-checked.
struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        if len > self.buf.len() {
            return Err("truncated data".to_owned());
        }
        let (head, tail) = self.buf.split_at(len);
        self.buf = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn be_u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().expect("8 bytes")))
    }

    /// A non-negative big-endian int64 that fits `usize`.
    fn be_len(&mut self) -> Result<usize, String> {
        let value = i64::from_be_bytes(self.be_u64()?.to_be_bytes());
        usize::try_from(value).map_err(|_| "invalid length".to_owned())
    }

    /// Protobuf varint: at most 10 bytes, the last one at most 1.
    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for index in 0..10 {
            let byte = self.u8()?;
            if index == 9 && byte > 1 {
                break;
            }
            value |= u64::from(byte & 0x7f) << (7 * index);
            if byte < 0x80 {
                return Ok(value);
            }
        }
        Err("invalid varint".to_owned())
    }

    /// A protobuf tag: (field number, wire type).
    fn tag(&mut self) -> Result<(u64, u8), String> {
        let tag = self.varint()?;
        Ok((tag >> 3, (tag & 7) as u8))
    }

    /// A length-delimited payload.
    fn delimited(&mut self) -> Result<&'a [u8], String> {
        let len = usize::try_from(self.varint()?).map_err(|_| "invalid length".to_owned())?;
        self.take(len)
    }

    fn skip(&mut self, wire: u8) -> Result<(), String> {
        match wire {
            0 => self.varint().map(drop),
            1 => self.take(8).map(drop),
            2 => self.delimited().map(drop),
            5 => self.take(4).map(drop),
            _ => Err(format!("unsupported wire type {wire}")),
        }
    }
}

/// A field that must be length-delimited.
fn delimited_field<'a>(cursor: &mut Cursor<'a>, wire: u8, name: &str) -> Result<&'a [u8], String> {
    if wire != 2 {
        return Err(format!("field {name} has the wrong wire type {wire}"));
    }
    cursor.delimited()
}

// ----- .dat ------------------------------------------------------------------

/// The `country_code` of a GeoSite / GeoIP message (empty when absent).
fn country_code(entry: &[u8]) -> Result<String, String> {
    let mut cursor = Cursor { buf: entry };
    let mut code = String::new();
    while !cursor.is_empty() {
        let (field, wire) = cursor.tag()?;
        if field == 1 {
            code = String::from_utf8_lossy(delimited_field(&mut cursor, wire, "country_code")?)
                .into_owned();
        } else {
            cursor.skip(wire)?;
        }
    }
    Ok(code)
}

/// The entries of the list whose `country_code` is `category`. Other entries
/// are skipped by length. Fails when there is none, listing some categories.
fn dat_entries<'a>(bytes: &'a [u8], category: &str) -> Result<Vec<&'a [u8]>, String> {
    let mut cursor = Cursor { buf: bytes };
    let (mut found, mut seen, mut total) = (Vec::new(), Vec::new(), 0usize);
    while !cursor.is_empty() {
        let (field, wire) = cursor.tag()?;
        if field != 1 {
            cursor.skip(wire)?;
            continue;
        }
        let entry = delimited_field(&mut cursor, wire, "entry")?;
        let code = country_code(entry)?;
        total += 1;
        if code.eq_ignore_ascii_case(category) {
            found.push(entry);
        } else if seen.len() < LISTED_CATEGORIES {
            seen.push(code);
        }
    }
    if found.is_empty() {
        return Err(format!(
            "category {category:?} not found; the file has {total} categories, e.g. {}",
            seen.join(", ")
        ));
    }
    Ok(found)
}

/// Domain rules of one category of a `geosite.dat`.
///
/// # Errors
///
/// A message when the file is malformed or the category is missing.
pub(crate) fn parse_geosite(bytes: &[u8], category: &str, regexp: bool) -> Result<Parsed, String> {
    let mut out = Parsed::default();
    for entry in dat_entries(bytes, category)? {
        let mut cursor = Cursor { buf: entry };
        while !cursor.is_empty() {
            let (field, wire) = cursor.tag()?;
            if field == 2 {
                geosite_domain(
                    delimited_field(&mut cursor, wire, "domain")?,
                    regexp,
                    &mut out,
                )?;
            } else {
                cursor.skip(wire)?;
            }
        }
    }
    Ok(out)
}

fn geosite_domain(message: &[u8], regexp: bool, out: &mut Parsed) -> Result<(), String> {
    let mut cursor = Cursor { buf: message };
    let (mut kind, mut value) = (0u64, &[][..]);
    while !cursor.is_empty() {
        let (field, wire) = cursor.tag()?;
        match field {
            1 if wire == 0 => kind = cursor.varint()?,
            1 => return Err(format!("field type has the wrong wire type {wire}")),
            2 => value = delimited_field(&mut cursor, wire, "value")?,
            _ => cursor.skip(wire)?,
        }
    }
    let value = String::from_utf8_lossy(value);
    match kind {
        0 => push_name(Name::Keyword, &value, out),
        1 => push_regexp(&value, regexp, out),
        2 => push_name(Name::Domain, &value, out),
        3 => push_name(Name::Full, &value, out),
        _ => {
            out.skipped.add("unknown domain type");
            Ok(())
        }
    }
}

/// IP prefixes of one category of a `geoip.dat`.
///
/// # Errors
///
/// A message when the file is malformed, the category is missing or it is a
/// reverse match.
pub(crate) fn parse_geoip(bytes: &[u8], category: &str) -> Result<Parsed, String> {
    let mut out = Parsed::default();
    for entry in dat_entries(bytes, category)? {
        let mut cursor = Cursor { buf: entry };
        while !cursor.is_empty() {
            let (field, wire) = cursor.tag()?;
            match field {
                2 => geoip_cidr(delimited_field(&mut cursor, wire, "cidr")?, &mut out)?,
                3 if wire == 0 => {
                    if cursor.varint()? != 0 {
                        return Err(format!(
                            "category {category:?} is a reverse match (everything but the \
                             listed networks), which cannot be used"
                        ));
                    }
                }
                3 => {
                    return Err(format!(
                        "field reverse_match has the wrong wire type {wire}"
                    ));
                }
                _ => cursor.skip(wire)?,
            }
        }
    }
    Ok(out)
}

fn geoip_cidr(message: &[u8], out: &mut Parsed) -> Result<(), String> {
    let mut cursor = Cursor { buf: message };
    let (mut ip, mut prefix) = (&[][..], 0u64);
    while !cursor.is_empty() {
        let (field, wire) = cursor.tag()?;
        match field {
            1 => ip = delimited_field(&mut cursor, wire, "ip")?,
            2 if wire == 0 => prefix = cursor.varint()?,
            2 => return Err(format!("field prefix has the wrong wire type {wire}")),
            _ => cursor.skip(wire)?,
        }
    }
    let address = match ip.len() {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(ip).expect("4 bytes"))),
        16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip).expect("16 bytes"))),
        _ => {
            out.skipped.add("invalid address");
            return Ok(());
        }
    };
    let width = if address.is_ipv4() { 32 } else { 128 };
    if prefix > width {
        out.skipped.add("invalid address");
        return Ok(());
    }
    out.push_ip((network(address, prefix as u8), prefix as u8))
}

/// `address` with the host bits cleared.
fn network(address: IpAddr, bits: u8) -> IpAddr {
    match address {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

// ----- .mrs ------------------------------------------------------------------

/// Decodes one zstd frame, refusing more than `limit` bytes of output. The
/// decoder rejects frames that declare a window larger than the limit.
fn inflate(bytes: &[u8], limit: u64) -> Result<Vec<u8>, String> {
    let decoder = StreamingDecoder::new_with_max_window_size(bytes, limit)
        .map_err(|error| format!("invalid zstd data: {error}"))?;
    let mut out = Vec::new();
    decoder
        .take(limit + 1)
        .read_to_end(&mut out)
        .map_err(|error| format!("invalid zstd data: {error}"))?;
    if out.len() as u64 > limit {
        return Err(format!("decompressed size exceeds {} MiB", limit >> 20));
    }
    Ok(out)
}

/// Whether `bytes` are a zstd frame that starts with the MRS magic.
pub(crate) fn is_mrs(bytes: &[u8]) -> bool {
    if !bytes.starts_with(&ZSTD_MAGIC) {
        return false;
    }
    let Ok(decoder) = StreamingDecoder::new_with_max_window_size(bytes, MAX_INFLATED_BYTES) else {
        return false;
    };
    let mut head = Vec::new();
    decoder.take(4).read_to_end(&mut head).is_ok() && head == MRS_MAGIC
}

/// Rules of a mihomo `.mrs` file; `behavior` has to be what `want` needs.
///
/// # Errors
///
/// A message when the file is malformed, too large or of the other behavior.
pub(crate) fn parse_mrs(bytes: &[u8], want: Want, regexp: bool) -> Result<Parsed, String> {
    let data = inflate(bytes, MAX_INFLATED_BYTES)?;
    let mut cursor = Cursor { buf: &data };
    if cursor.take(4)? != MRS_MAGIC {
        return Err("not an mrs rule set".to_owned());
    }
    let behavior = match cursor.u8()? {
        0 => Want::Domains,
        1 => Want::Ips,
        other => return Err(format!("unsupported mrs behavior {other}")),
    };
    if behavior != want {
        return Err(format!(
            "mrs behavior is {}, this subscription needs {}",
            behavior.noun(),
            want.noun()
        ));
    }
    let _count = cursor.be_u64()?;
    let extra = cursor.be_len()?;
    cursor.take(extra)?;
    if cursor.u8()? != 1 {
        return Err("unsupported mrs payload version".to_owned());
    }
    match want {
        Want::Domains => mrs_domains(&mut cursor, regexp),
        Want::Ips => mrs_ranges(&mut cursor),
    }
}

/// `len` big-endian words, `len` between 1 and `max`, present in the input.
fn words(cursor: &mut Cursor<'_>, max: u64) -> Result<Vec<u64>, String> {
    let len = cursor.be_len()?;
    if len == 0 || len as u64 > max {
        return Err("invalid domain set size".to_owned());
    }
    let raw = cursor.take(len.checked_mul(8).ok_or("invalid domain set size")?)?;
    Ok(raw
        .chunks_exact(8)
        .map(|word| u64::from_be_bytes(word.try_into().expect("8 bytes")))
        .collect())
}

fn mrs_domains(cursor: &mut Cursor<'_>, regexp: bool) -> Result<Parsed, String> {
    let leaves = words(cursor, MAX_SET_WORDS)?;
    let bitmap = words(cursor, MAX_SET_WORDS)?;
    let len = cursor.be_len()?;
    if len == 0 || len as u64 > MAX_SET_BYTES {
        return Err("invalid domain set size".to_owned());
    }
    let labels = cursor.take(len)?.to_vec();
    let keys = succinct_set_keys(leaves, bitmap, labels)
        .map_err(|error| format!("invalid domain set: {error}"))?;
    let mut out = Parsed::default();
    mihomo_rules(&keys, regexp, &mut out)?;
    Ok(out)
}

fn plain_name(name: &str) -> bool {
    name_ok(name) && !name.starts_with('.') && !name.ends_with('.') && !name.contains("..")
}

/// Turns the keys of a mihomo `DomainSet` into rules. A key is the reversed
/// pattern: `example.com` matches that name only, `+.example.com` (stored as
/// `moc.elpmaxe.+`) its subdomains only, and `+.example.com` in a rule file
/// (both keys) the name and its subdomains; a whole `*` label matches one
/// label.
fn mihomo_rules(keys: &[Vec<u8>], regexp: bool, out: &mut Parsed) -> Result<(), String> {
    let (mut exact, mut subdomains) = (BTreeSet::new(), BTreeSet::new());
    for raw in keys {
        if raw.is_empty() {
            continue;
        }
        if !raw.is_ascii() {
            out.skipped.add("non-ASCII name");
            continue;
        }
        let key: String = raw
            .iter()
            .rev()
            .map(|byte| char::from(byte.to_ascii_lowercase()))
            .collect();
        let (only_subdomains, name) = match key.strip_prefix("+.") {
            Some(rest) => (true, rest),
            None => (false, key.as_str()),
        };
        if name.contains('*') {
            wildcard_rule(name, only_subdomains, regexp, out)?;
        } else if !plain_name(name) {
            out.skipped.add("invalid name");
        } else if only_subdomains {
            subdomains.insert(name.to_owned());
        } else {
            exact.insert(name.to_owned());
        }
    }
    for name in &exact {
        if subdomains.remove(name) {
            out.push_domain(format!("domain:{name}"))?;
        } else {
            out.push_domain(format!("full:{name}"))?;
        }
    }
    // Subdomains without the name itself: `domain:` would match too much.
    for name in &subdomains {
        let pattern = format!("^.+\\.{}$", name.replace('.', "\\."));
        push_regexp(&pattern, regexp, out)?;
    }
    Ok(())
}

fn wildcard_rule(
    name: &str,
    only_subdomains: bool,
    regexp: bool,
    out: &mut Parsed,
) -> Result<(), String> {
    let labels: Vec<&str> = name.split('.').collect();
    if labels
        .iter()
        .any(|label| *label != "*" && !plain_name(label))
    {
        out.skipped.add("invalid name");
        return Ok(());
    }
    let converted: Vec<&str> = labels
        .iter()
        .map(|label| if *label == "*" { "[^.]+" } else { label })
        .collect();
    let lead = if only_subdomains { ".+\\." } else { "" };
    push_regexp(&format!("^{lead}{}$", converted.join("\\.")), regexp, out)
}

fn mrs_ranges(cursor: &mut Cursor<'_>) -> Result<Parsed, String> {
    let count = cursor.be_len()?;
    if count == 0 || count > cursor.buf.len() / 32 {
        return Err("invalid range count".to_owned());
    }
    let mut out = Parsed::default();
    for _ in 0..count {
        let from = unmap(cursor.take(16)?);
        let to = unmap(cursor.take(16)?);
        let mut prefixes = Vec::new();
        range_to_prefixes(from, to, &mut prefixes);
        if prefixes.is_empty() {
            out.skipped.add("invalid range");
        }
        for prefix in prefixes {
            out.push_ip(prefix)?;
        }
    }
    Ok(out)
}

/// An IPv4-mapped address becomes IPv4 (`netip.Addr.Unmap`).
fn unmap(bytes: &[u8]) -> IpAddr {
    let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).expect("16 bytes"));
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// Reads a download in `format` (`Dat` or `Mrs`) for a subscription that needs
/// `want`.
///
/// # Errors
///
/// A message when the file cannot be used.
pub(crate) fn parse(
    bytes: &[u8],
    is_dat: bool,
    category: &str,
    want: Want,
    regexp: bool,
) -> Result<Parsed, String> {
    if !is_dat {
        return parse_mrs(bytes, want, regexp);
    }
    if category.trim().is_empty() {
        return Err("a .dat download needs a category".to_owned());
    }
    match want {
        Want::Domains => parse_geosite(bytes, category.trim(), regexp),
        Want::Ips => parse_geoip(bytes, category.trim()),
    }
}

/// Reads a download whose kind the file decides (atom: a ruleset holds names
/// or prefixes): a `.mrs` by its `behavior`, a `.dat` as a geosite category
/// and, when it is not one, as a geoip category (each reader rejects the
/// other's entries by their wire types).
///
/// # Errors
///
/// A message when the file cannot be used either way.
pub(crate) fn parse_any(
    bytes: &[u8],
    is_dat: bool,
    category: &str,
    regexp: bool,
) -> Result<Parsed, String> {
    if !is_dat {
        let want = if mrs_behavior(bytes) == Some(1) {
            Want::Ips
        } else {
            Want::Domains
        };
        return parse_mrs(bytes, want, regexp);
    }
    if !category.trim().is_empty() && dat_is_geoip(bytes, category.trim())? {
        return parse(bytes, true, category, Want::Ips, regexp);
    }
    parse(bytes, true, category, Want::Domains, regexp).or_else(|names| {
        parse(bytes, true, category, Want::Ips, regexp)
            .map_err(|ips| format!("not a geosite category ({names}) nor a geoip one ({ips})"))
    })
}

/// Whether `category` of a `.dat` is a geoip one: it has the `reverse_match`
/// field or a cidr (whose first field is the address bytes; a geosite domain
/// starts with its type varint or its value). A reverse match is refused:
/// even an empty one stands for every address but the listed ones.
fn dat_is_geoip(bytes: &[u8], category: &str) -> Result<bool, String> {
    let mut geoip = false;
    for entry in dat_entries(bytes, category)? {
        let mut cursor = Cursor { buf: entry };
        while !cursor.is_empty() {
            match cursor.tag()? {
                (3, 0) => {
                    if cursor.varint()? != 0 {
                        return Err(format!("不支持 GeoIP 反向匹配（分类 {category:?}）"));
                    }
                    geoip = true;
                }
                (2, 2) => {
                    let mut message = Cursor { buf: cursor.delimited()? };
                    if !message.is_empty() && message.tag()? == (1, 2) {
                        geoip = true;
                    }
                }
                (_, wire) => cursor.skip(wire)?,
            }
        }
    }
    Ok(geoip)
}

/// The `behavior` byte of an `.mrs` file (read without inflating the rest).
fn mrs_behavior(bytes: &[u8]) -> Option<u8> {
    let decoder = StreamingDecoder::new_with_max_window_size(bytes, MAX_INFLATED_BYTES).ok()?;
    let mut head = Vec::new();
    decoder.take(5).read_to_end(&mut head).ok()?;
    (head.len() == 5 && head[..4] == MRS_MAGIC).then(|| head[4])
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // ----- protobuf builders -----

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn field_bytes(field: u64, data: &[u8]) -> Vec<u8> {
        let mut out = varint(field << 3 | 2);
        out.extend(varint(data.len() as u64));
        out.extend(data);
        out
    }

    fn field_varint(field: u64, value: u64) -> Vec<u8> {
        let mut out = varint(field << 3);
        out.extend(varint(value));
        out
    }

    pub(crate) fn geosite_entry(code: &str, domains: &[(u64, &str)]) -> Vec<u8> {
        let mut entry = field_bytes(1, code.as_bytes());
        for (kind, value) in domains {
            let mut domain = field_varint(1, *kind);
            domain.extend(field_bytes(2, value.as_bytes()));
            // An attribute, which is ignored.
            let mut attribute = field_bytes(1, b"ads");
            attribute.extend(field_varint(2, 1));
            domain.extend(field_bytes(3, &attribute));
            entry.extend(field_bytes(2, &domain));
        }
        field_bytes(1, &entry)
    }

    pub(crate) fn c(ip: &[u8], prefix: u64) -> (Vec<u8>, u64) {
        (ip.to_vec(), prefix)
    }

    pub(crate) fn geoip_entry(code: &str, cidrs: &[(Vec<u8>, u64)], reverse: bool) -> Vec<u8> {
        let mut entry = field_bytes(1, code.as_bytes());
        for (ip, prefix) in cidrs {
            let mut cidr = field_bytes(1, ip);
            cidr.extend(field_varint(2, *prefix));
            entry.extend(field_bytes(2, &cidr));
        }
        if reverse {
            entry.extend(field_varint(3, 1));
        }
        field_bytes(1, &entry)
    }

    #[test]
    fn varints_and_lengths_are_bounded() {
        assert_eq!(Cursor { buf: &[0xAC, 0x02] }.varint(), Ok(300));
        // Eleven continuation bytes.
        assert!(Cursor { buf: &[0xFF; 11] }.varint().is_err());
        // A tenth byte above 1 overflows 64 bits.
        let mut ten = vec![0xFF; 9];
        ten.push(2);
        assert!(Cursor { buf: &ten }.varint().is_err());
        // Truncated varint.
        assert!(Cursor { buf: &[0x80] }.varint().is_err());
        // A length past the end.
        assert!(Cursor { buf: &[5, 1, 2] }.delimited().is_err());
        assert!(Cursor { buf: &[0xFF; 10] }.delimited().is_err());
    }

    // ----- geosite.dat -----

    fn geosite() -> Vec<u8> {
        let mut file = geosite_entry("OTHER", &[(2, "other.example.org")]);
        file.extend(geosite_entry(
            "CN",
            &[
                (0, "Ads"),
                (1, "^a[0-9]\\.example\\.com$"),
                (2, "Example.com"),
                (3, "www.example.net"),
                (9, "future.example.com"),
            ],
        ));
        // A type that is absent means Plain (0).
        let mut plain = field_bytes(2, "kw".as_bytes());
        plain.extend(field_varint(9, 7));
        let entry = [field_bytes(1, b"cn"), field_bytes(2, &plain)].concat();
        file.extend(field_bytes(1, &entry));
        file
    }

    #[test]
    fn geosite_maps_every_type_and_ignores_attributes() {
        let parsed = parse_geosite(&geosite(), "Cn", true).unwrap();
        assert_eq!(
            parsed.domains,
            [
                "keyword:ads",
                "regexp:^a[0-9]\\.example\\.com$",
                "domain:example.com",
                "full:www.example.net",
                "keyword:kw",
            ]
        );
        assert_eq!(parsed.skipped.summary(), "unknown domain type=1");
    }

    #[test]
    fn a_geosite_regexp_with_a_line_break_is_skipped() {
        let file = geosite_entry(
            "cn",
            &[(1, ")\nregexp:\\p{L}+"), (1, "a\r"), (2, "ok.example.com")],
        );
        let parsed = parse_geosite(&file, "cn", true).unwrap();
        assert_eq!(parsed.domains, ["domain:ok.example.com"]);
        assert_eq!(
            parsed.skipped.summary(),
            "regexp with a control character or edge space=2"
        );
    }

    #[test]
    fn geosite_regexps_need_the_switch() {
        let parsed = parse_geosite(&geosite(), "cn", false).unwrap();
        assert_eq!(parsed.domains.len(), 4);
        assert!(parsed.skipped.summary().contains("regexp disabled=1"));
    }

    #[test]
    fn a_missing_category_lists_the_file() {
        let error = parse_geosite(&geosite(), "us", true).unwrap_err();
        assert!(error.contains("\"us\" not found"), "{error}");
        assert!(error.contains("3 categories"), "{error}");
        assert!(error.contains("OTHER, CN, cn"), "{error}");
        let mut many = Vec::new();
        for index in 0..30 {
            many.extend(geosite_entry(&format!("C{index}"), &[(2, "a.example.com")]));
        }
        let error = parse_geosite(&many, "zz", true).unwrap_err();
        assert!(error.contains("30 categories"), "{error}");
        assert!(error.contains("C19") && !error.contains("C20"), "{error}");
    }

    #[test]
    fn damaged_protobuf_is_refused() {
        let good = geosite();
        // Cut anywhere: never a panic, and a cut inside a message is an error.
        for cut in 0..good.len() {
            let _ = parse_geosite(&good[..cut], "cn", true);
        }
        assert!(parse_geosite(&good[..good.len() - 1], "cn", true).is_err());
        // The entry field with a varint wire type.
        assert!(parse_geosite(&field_varint(1, 5), "cn", true).is_err());
        // country_code with a varint wire type.
        let entry = field_varint(1, 5);
        assert!(parse_geosite(&field_bytes(1, &entry), "cn", true).is_err());
        // A group wire type.
        assert!(parse_geosite(&[0x0B], "cn", true).is_err());
        // A length that reaches past the file.
        assert!(parse_geosite(&[0x0A, 0x7F, 1], "cn", true).is_err());
        // Domain type with the wrong wire type.
        let bad = [field_bytes(1, b"cn"), field_bytes(2, &field_bytes(1, b"x"))].concat();
        assert!(parse_geosite(&field_bytes(1, &bad), "cn", true).is_err());
    }

    // ----- geoip.dat -----

    #[test]
    fn geoip_reads_prefixes_and_clears_host_bits() {
        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut file = geoip_entry("OTHER", &[c(&[203, 0, 113, 0], 24)], false);
        file.extend(geoip_entry(
            "CN",
            &[
                c(&[192, 0, 2, 0], 24),
                c(&[198, 51, 100, 77], 24),
                c(&[203, 0, 113, 9], 32),
                c(&v6, 32),
                c(&[1, 2, 3], 8),
                c(&[198, 51, 100, 0], 33),
            ],
            false,
        ));
        let parsed = parse_geoip(&file, "cn").unwrap();
        let got: Vec<String> = parsed.ips.iter().map(|(a, b)| format!("{a}/{b}")).collect();
        assert_eq!(
            got,
            [
                "192.0.2.0/24",
                "198.51.100.0/24",
                "203.0.113.9/32",
                "2001:db8::/32"
            ]
        );
        assert_eq!(parsed.skipped.summary(), "invalid address=2");
    }

    #[test]
    fn geoip_reverse_match_is_refused() {
        let file = geoip_entry("CN", &[c(&[192, 0, 2, 0], 24)], true);
        let error = parse_geoip(&file, "cn").unwrap_err();
        assert!(error.contains("reverse match"), "{error}");
        // A reverse match in another category does not matter.
        let mut file = geoip_entry("OTHER", &[c(&[192, 0, 2, 0], 24)], true);
        file.extend(geoip_entry("CN", &[c(&[198, 51, 100, 0], 24)], false));
        assert_eq!(parse_geoip(&file, "cn").unwrap().ips.len(), 1);
        assert!(parse_geoip(&file, "us").unwrap_err().contains("not found"));
    }

    #[test]
    fn dat_needs_a_category() {
        let error = parse(&geosite(), true, " ", Want::Domains, true).unwrap_err();
        assert!(error.contains("category"), "{error}");
    }

    // ----- zstd and mrs -----

    /// A zstd frame of raw blocks (a valid frame without compression).
    fn zstd_raw(data: &[u8]) -> Vec<u8> {
        let mut out = ZSTD_MAGIC.to_vec();
        out.extend([0x00, 0x50]); // no content size; window 1 MiB * 1.0
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[][..]]
        } else {
            data.chunks(60_000).collect()
        };
        for (index, chunk) in chunks.iter().enumerate() {
            let last = u32::from(index + 1 == chunks.len());
            let header = (chunk.len() as u32) << 3 | last;
            out.extend(&header.to_le_bytes()[..3]);
            out.extend(*chunk);
        }
        out
    }

    /// A zstd frame of `blocks` RLE blocks of 128 KiB (a decompression bomb).
    fn zstd_bomb(blocks: usize, window_byte: u8) -> Vec<u8> {
        let mut out = ZSTD_MAGIC.to_vec();
        out.extend([0x00, window_byte]);
        for index in 0..blocks {
            let last = u32::from(index + 1 == blocks);
            let header = (131_072u32 << 3) | (1 << 1) | last;
            out.extend(&header.to_le_bytes()[..3]);
            out.push(b'a');
        }
        out
    }

    fn set_bit(words: &mut Vec<u64>, index: usize, value: u64) {
        while index >> 6 >= words.len() {
            words.push(0);
        }
        words[index >> 6] |= value << (index & 63);
    }

    /// Port of mihomo `buildDomainSet`: `keys` are the reversed patterns.
    fn build_set(mut keys: Vec<Vec<u8>>) -> (Vec<u64>, Vec<u64>, Vec<u8>) {
        keys.sort();
        keys.dedup();
        let (mut leaves, mut bitmap, mut labels) = (Vec::new(), Vec::new(), Vec::new());
        let (mut bit, mut node) = (0, 0);
        let mut queue = vec![(0usize, keys.len())];
        let mut column = 0;
        while !queue.is_empty() {
            let mut next = Vec::new();
            for &(mut start, end) in &queue {
                if column == keys[start].len() {
                    set_bit(&mut leaves, node, 1);
                    start += 1;
                }
                let mut j = start;
                while j < end {
                    let from = j;
                    while j < end && keys[j][column] == keys[from][column] {
                        j += 1;
                    }
                    next.push((from, j));
                    labels.push(keys[from][column]);
                    set_bit(&mut bitmap, bit, 0);
                    bit += 1;
                }
                set_bit(&mut bitmap, bit, 1);
                bit += 1;
                node += 1;
            }
            queue = next;
            column += 1;
        }
        (leaves, bitmap, labels)
    }

    /// The keys mihomo stores for rule-file lines (`DomainSetBuilder.Insert`).
    fn mihomo_keys(patterns: &[&str]) -> Vec<Vec<u8>> {
        let reversed = |text: &str| text.bytes().rev().collect::<Vec<u8>>();
        let mut keys = Vec::new();
        for pattern in patterns {
            if let Some(rest) = pattern.strip_prefix("+.") {
                keys.push(reversed(rest));
                keys.push(reversed(pattern));
            } else if let Some(rest) = pattern.strip_prefix('.') {
                keys.push(reversed(&format!("+.{rest}")));
            } else {
                keys.push(reversed(pattern));
            }
        }
        keys
    }

    fn be64(value: u64) -> [u8; 8] {
        value.to_be_bytes()
    }

    fn mrs_header(behavior: u8) -> Vec<u8> {
        let mut out = MRS_MAGIC.to_vec();
        out.push(behavior);
        out.extend(be64(1)); // count
        out.extend(be64(0)); // extra length
        out
    }

    pub(crate) fn mrs_domain_file(patterns: &[&str]) -> Vec<u8> {
        let (leaves, bitmap, labels) = build_set(mihomo_keys(patterns));
        let mut body = mrs_header(0);
        body.push(1);
        body.extend(be64(leaves.len() as u64));
        leaves.iter().for_each(|word| body.extend(be64(*word)));
        body.extend(be64(bitmap.len() as u64));
        bitmap.iter().for_each(|word| body.extend(be64(*word)));
        body.extend(be64(labels.len() as u64));
        body.extend(&labels);
        zstd_raw(&body)
    }

    pub(crate) fn mapped(octets: [u8; 4]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[10] = 0xff;
        out[11] = 0xff;
        out[12..].copy_from_slice(&octets);
        out
    }

    pub(crate) fn mrs_ip_file(ranges: &[([u8; 16], [u8; 16])]) -> Vec<u8> {
        let mut body = mrs_header(1);
        body.push(1);
        body.extend(be64(ranges.len() as u64));
        for (from, to) in ranges {
            body.extend(from);
            body.extend(to);
        }
        zstd_raw(&body)
    }

    #[test]
    fn mrs_domains_map_every_kind_of_key() {
        let file = mrs_domain_file(&[
            "+.example.com",
            "www.example.net",
            ".sub.example.org",
            "*.wild.example.com",
            "a.*.mid.example.com",
            "*.example.net",
            "+.*.deep.example.com",
        ]);
        let parsed = parse_mrs(&file, Want::Domains, true).unwrap();
        let mut got = parsed.domains.clone();
        got.sort();
        let mut want = vec![
            "domain:example.com".to_owned(),
            "full:www.example.net".to_owned(),
            "regexp:^.+\\.sub\\.example\\.org$".to_owned(),
            "regexp:^[^.]+\\.wild\\.example\\.com$".to_owned(),
            "regexp:^a\\.[^.]+\\.mid\\.example\\.com$".to_owned(),
            "regexp:^[^.]+\\.example\\.net$".to_owned(),
            "regexp:^[^.]+\\.deep\\.example\\.com$".to_owned(),
            "regexp:^.+\\.[^.]+\\.deep\\.example\\.com$".to_owned(),
        ];
        want.sort();
        assert_eq!(got, want);
        assert_eq!(parsed.skipped.total(), 0);
        for rule in &parsed.domains {
            if let Some(pattern) = rule.strip_prefix("regexp:") {
                atomdns_matcher_core::check_go_regexp(pattern).unwrap();
            }
        }
    }

    #[test]
    fn mrs_regexps_need_the_switch() {
        let file = mrs_domain_file(&["+.example.com", "*.example.net", ".example.org"]);
        let parsed = parse_mrs(&file, Want::Domains, false).unwrap();
        assert_eq!(parsed.domains, ["domain:example.com"]);
        assert!(parsed.skipped.summary().contains("regexp disabled=2"));
    }

    #[test]
    fn mrs_ranges_become_the_fewest_prefixes() {
        let v6 = |high: u8, tail: u8| {
            let mut out = [0u8; 16];
            out[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
            out[14] = high;
            out[15] = tail;
            out
        };
        let file = mrs_ip_file(&[
            (mapped([192, 0, 2, 0]), mapped([192, 0, 2, 255])), // a whole /24
            (mapped([198, 51, 100, 7]), mapped([198, 51, 100, 7])), // one address
            (mapped([203, 0, 113, 250]), mapped([203, 0, 113, 255])), // two prefixes
            (v6(0, 0), v6(0, 255)),                             // IPv6 /120
            (v6(1, 0xfa), v6(2, 5)),                            // across a byte
            (mapped([192, 0, 2, 9]), v6(0, 1)),                 // mixed families
            (mapped([192, 0, 2, 9]), mapped([192, 0, 2, 1])),   // from > to
        ]);
        let parsed = parse_mrs(&file, Want::Ips, false).unwrap();
        let got: Vec<String> = parsed.ips.iter().map(|(a, b)| format!("{a}/{b}")).collect();
        assert_eq!(
            got,
            [
                "192.0.2.0/24",
                "198.51.100.7/32",
                "203.0.113.250/31",
                "203.0.113.252/30",
                "2001:db8::/120",
                "2001:db8::1fa/127",
                "2001:db8::1fc/126",
                "2001:db8::200/126",
                "2001:db8::204/127",
            ]
        );
        assert_eq!(parsed.skipped.summary(), "invalid range=2");
    }

    #[test]
    fn mrs_behavior_must_match_the_subscription() {
        let domains = mrs_domain_file(&["+.example.com"]);
        let ips = mrs_ip_file(&[(mapped([192, 0, 2, 0]), mapped([192, 0, 2, 255]))]);
        let error = parse_mrs(&domains, Want::Ips, false).unwrap_err();
        assert!(error.contains("behavior is domain"), "{error}");
        let error = parse_mrs(&ips, Want::Domains, true).unwrap_err();
        assert!(error.contains("behavior is ip"), "{error}");
        let mut classical = mrs_header(2);
        classical.push(1);
        let error = parse_mrs(&zstd_raw(&classical), Want::Domains, true).unwrap_err();
        assert!(error.contains("unsupported mrs behavior 2"), "{error}");
    }

    #[test]
    fn mrs_is_recognized_by_its_content() {
        assert!(is_mrs(&mrs_domain_file(&["+.example.com"])));
        assert!(!is_mrs(&zstd_raw(b"hello world")));
        assert!(!is_mrs(b"plain text"));
        assert!(!is_mrs(&ZSTD_MAGIC));
    }

    #[test]
    fn mrs_damage_is_refused_without_panics() {
        let good = mrs_domain_file(&["+.example.com", "www.example.net"]);
        assert!(parse_mrs(&good, Want::Domains, true).is_ok());
        // Not zstd at all, a cut stream.
        assert!(parse_mrs(b"hello", Want::Domains, true).is_err());
        for cut in 0..good.len() {
            let _ = parse_mrs(&good[..cut], Want::Domains, true);
        }
        let plain = |body: &[u8]| zstd_raw(body);
        // Wrong magic, bad payload version, negative or oversized extra.
        let mut body = mrs_header(0);
        body[0] = b'X';
        assert!(parse_mrs(&plain(&body), Want::Domains, true).is_err());
        let mut body = mrs_header(0);
        body.push(2);
        assert!(parse_mrs(&plain(&body), Want::Domains, true).is_err());
        let mut body = mrs_header(0);
        body[13..21].copy_from_slice(&be64(u64::MAX));
        assert!(parse_mrs(&plain(&body), Want::Domains, true).is_err());
        let mut body = mrs_header(0);
        body[13..21].copy_from_slice(&be64(1 << 40));
        assert!(parse_mrs(&plain(&body), Want::Domains, true).is_err());
        // A set that declares more words than the file holds.
        let mut body = mrs_header(0);
        body.push(1);
        body.extend(be64(1_000_000));
        assert!(parse_mrs(&plain(&body), Want::Domains, true).is_err());
        let mut body = mrs_header(0);
        body.push(1);
        body.extend(be64(u64::MAX));
        assert!(parse_mrs(&plain(&body), Want::Domains, true).is_err());
        // A zero-length set part.
        let mut body = mrs_header(0);
        body.push(1);
        body.extend(be64(0));
        assert!(parse_mrs(&plain(&body), Want::Domains, true).is_err());
        // A range count larger than the data.
        let mut body = mrs_header(1);
        body.push(1);
        body.extend(be64(1 << 40));
        assert!(parse_mrs(&plain(&body), Want::Ips, false).is_err());
        let mut body = mrs_header(1);
        body.push(1);
        body.extend(be64(3));
        body.extend([0u8; 32]);
        assert!(parse_mrs(&plain(&body), Want::Ips, false).is_err());
    }

    #[test]
    fn a_decompression_bomb_is_stopped_at_the_limit() {
        // 600 blocks of 128 KiB are 75 MiB from 1.8 KB.
        let bomb = zstd_bomb(600, 0x50);
        assert!(bomb.len() < 4000);
        let error = parse_mrs(&bomb, Want::Domains, true).unwrap_err();
        assert!(error.contains("exceeds 64 MiB"), "{error}");
        // Just inside the limit is read (and then fails as an mrs file).
        let inside = zstd_bomb(500, 0x50);
        let error = parse_mrs(&inside, Want::Domains, true).unwrap_err();
        assert!(!error.contains("exceeds"), "{error}");
        // A frame that declares a window of 256 MiB is refused up front.
        let huge = zstd_bomb(1, 0x90);
        let error = parse_mrs(&huge, Want::Domains, true).unwrap_err();
        assert!(error.contains("zstd"), "{error}");
        assert!(!is_mrs(&huge));
    }
}
