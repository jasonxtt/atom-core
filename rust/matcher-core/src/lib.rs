//! Pure Rust domain matcher core for AtomDNS.
//!
//! Implements the four Go domain matcher types (full, domain/suffix, keyword,
//! regex) and their `MixMatcher` combination with precedence
//! full → domain → regex → keyword. Normalization matches Go's
//! `NormalizeDomain` (lowercase + strip trailing dot).

#![allow(clippy::pedantic)]

mod compact;
mod full;
mod ipnet;
mod keyword;
mod mix;
mod mix_set;
mod normalize;
mod regex;
mod srs;
mod trie;
mod valued;

pub use full::FullMatcher;
pub use ipnet::IpPrefixList;
pub use keyword::KeywordMatcher;
pub use mix::MixMatcher;
pub use mix_set::{MixSet, MixSetBuilder};
pub use normalize::normalize;
pub use regex::{RegexBuildError, RegexMatcher, check_go_regexp};
pub use srs::{
    DomainSrs, IpSrs, MAX_INFLATED_BYTES, MAX_SET_BYTES, MAX_SET_WORDS, MixedSrs, PlainDomainSrs,
    SrsError, decode_domain_srs, decode_domain_srs_plain, decode_ip_srs, decode_srs,
    range_to_prefixes,
    succinct_set_keys,
};
pub use trie::DomainSuffixMatcher;
pub use valued::{
    ValuedBuildError, ValuedDomainMatcher, ValuedMatchResult, ValuedRule, ValuedRuleRef,
};

/// Domain matcher trait, generic over the result value.
///
/// Return of `None` means no match. Boolean matchers use `()` as the value.
pub trait DomainMatcher {
    type Value;
    fn r#match(&self, domain: &str) -> Option<&Self::Value>;
}
