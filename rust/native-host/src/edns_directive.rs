//! EDNS0 option 65001: the outbound directive for sing-box's FakeIP DNS
//! (atom fork; protocol in the atom repository's
//! `docs/singbox-fakeip-outbound.md`). The payload is `[version=1, op, tag...]`,
//! op 1 SET (the rest is the outbound tag) or 2 CLEAR.
//!
//! sing-box trusts whatever 65001 it receives, so the trust boundary is here:
//! every query leaving for an upstream loses the 65001 options the client put
//! in it, and only the FakeIP upstream (`nocnfake`) gets one, written by us.
use std::borrow::Cow;

use atomdns_sequence_core::ExecutorError;

pub(crate) const OPTION_CODE: u16 = 65001;
/// The `aliapi` group whose queries go to sing-box's `dns-in`.
pub(crate) const FAKEIP_UPSTREAM: &str = "nocnfake";
const VERSION: u8 = 1;
const OP_CLEAR: u8 = 2;

/// The query as it is sent to one upstream. A query for a normal upstream that
/// carries no 65001 is returned as it is. Stripping walks the OPT record only
/// structurally, so it does not depend on what the other options mean (a
/// duplicate ECS is still stripped); a query whose additional record cannot be
/// walked is refused rather than forwarded with options we could not see. A
/// query for the FakeIP upstream must also pass the full OPT validation: it
/// never reaches sing-box with options we did not check.
pub(crate) fn outgoing_query(raw: &[u8], fakeip: bool) -> Result<Cow<'_, [u8]>, ExecutorError> {
    if fakeip {
        crate::ecs::query_opt(raw)?;
    }
    let invalid = || ExecutorError::new("invalid query");
    let (header, question) = atomdns_dns_core::parse_query(raw).map_err(|_| invalid())?;
    let mut options = Vec::new();
    let mut stripped = false;
    // OPT class (UDP payload size) and TTL (extended rcode, version, flags).
    let mut fields = vec![4, 208, 0, 0, 0, 0];
    if header.arcount == 1 {
        let owner = crate::ecs::name_end(raw, 12)? + 4;
        // The owner name must be a valid name, pointers followed: a pointer
        // past the end, onto itself or into a loop must not pass as the
        // OPT's name (the walk below only skips it).
        atomdns_dns_core::parse_question(raw, owner).map_err(|_| invalid())?;
        let record = crate::ecs::name_end(raw, owner)?;
        let fixed = raw.get(record..record + 10).ok_or_else(invalid)?;
        let rdata = record + 10;
        let end = rdata + usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
        let mut rest = raw.get(rdata..end).ok_or_else(invalid)?;
        if u16::from_be_bytes([fixed[0], fixed[1]]) != 41 {
            // Not an OPT record: no EDNS options to strip (fakeip already
            // refused it in query_opt).
            return Ok(Cow::Borrowed(raw));
        }
        fields = fixed[2..8].to_vec();
        while !rest.is_empty() {
            let [a, b, c, d, ..] = *rest else {
                return Err(ExecutorError::new("short EDNS option"));
            };
            let len = 4 + usize::from(u16::from_be_bytes([c, d]));
            let option = rest
                .get(..len)
                .ok_or_else(|| ExecutorError::new("short EDNS payload"))?;
            if u16::from_be_bytes([a, b]) == OPTION_CODE {
                stripped = true;
            } else {
                options.extend_from_slice(option);
            }
            rest = &rest[len..];
        }
    }
    if !fakeip && !stripped {
        return Ok(Cow::Borrowed(raw));
    }
    if fakeip {
        options.extend_from_slice(&OPTION_CODE.to_be_bytes());
        options.extend_from_slice(&[0, 2, VERSION, OP_CLEAR]);
    }
    // Rebuild header + question from the expanded name: a compressed question
    // name may point into bytes after it (name storage, or option payloads
    // that move once a 65001 is removed).
    let mut wire = raw[..12].to_vec();
    wire[10..12].copy_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&question.qname_wire);
    wire.extend_from_slice(&question.qtype.to_be_bytes());
    wire.extend_from_slice(&question.qclass.to_be_bytes());
    wire.extend_from_slice(&[0, 0, 41]);
    wire.extend_from_slice(&fields);
    wire.extend_from_slice(
        &u16::try_from(options.len())
            .map_err(|_| ExecutorError::new("oversized OPT"))?
            .to_be_bytes(),
    );
    wire.extend_from_slice(&options);
    Ok(Cow::Owned(wire))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAR: [u8; 6] = [0xfd, 0xe9, 0, 2, 1, 2];

    /// A query for `a.cn` A, optionally with an OPT carrying `options`.
    fn query(options: Option<&[u8]>) -> Vec<u8> {
        let mut wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        wire.extend_from_slice(&[1, b'a', 2, b'c', b'n', 0, 0, 1, 0, 1]);
        if let Some(options) = options {
            wire[11] = 1;
            wire.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0]);
            wire.extend_from_slice(&u16::try_from(options.len()).unwrap().to_be_bytes());
            wire.extend_from_slice(options);
        }
        wire
    }

    /// The 65001 payloads of the query's OPT, in order.
    fn directives(wire: &[u8]) -> Vec<Vec<u8>> {
        let mut found = Vec::new();
        let mut rest = edns_options(wire);
        while rest.len() >= 4 {
            let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
            if u16::from_be_bytes([rest[0], rest[1]]) == OPTION_CODE {
                found.push(rest[4..4 + len].to_vec());
            }
            rest = &rest[4 + len..];
        }
        found
    }

    /// The option bytes of the OPT right after the question (none without
    /// one). Independent of ECS validation, which duplicate ECS fails.
    fn edns_options(wire: &[u8]) -> &[u8] {
        let opt = crate::ecs::name_end(wire, 12).unwrap() + 4;
        if u16::from_be_bytes([wire[10], wire[11]]) == 0 {
            return &[];
        }
        assert_eq!(&wire[opt..opt + 3], &[0, 0, 41], "root-named OPT");
        let options = &wire[opt + 11..];
        assert_eq!(
            options.len(),
            usize::from(u16::from_be_bytes([wire[opt + 9], wire[opt + 10]]))
        );
        options
    }

    #[test]
    fn fakeip_upstream_gets_clear_without_client_opt() {
        let plain = query(None);
        let out = outgoing_query(&plain, true).unwrap();
        assert_eq!(directives(&out), vec![vec![1, 2]]);
        assert_eq!(&out[..10], &plain[..10]);
        assert_eq!(&out[10..12], &[0, 1], "ARCOUNT");
        assert_eq!(&out[12..22], &plain[12..22], "question");
    }

    #[test]
    fn forged_set_is_replaced_by_clear_for_fakeip_upstream() {
        let forged = [0xfd, 0xe9, 0, 5, 1, 1, b'b', b'a', b'd'];
        let wire = query(Some(&forged));
        let out = outgoing_query(&wire, true).unwrap();
        assert_eq!(directives(&out), vec![vec![1, 2]]);
    }

    #[test]
    fn forged_directive_is_stripped_for_other_upstreams() {
        // A cookie (10) and an ECS (8) around two forged 65001 options.
        let mut options = vec![0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        options.extend_from_slice(&[0xfd, 0xe9, 0, 5, 1, 1, b'b', b'a', b'd']);
        options.extend_from_slice(&[0, 8, 0, 7, 0, 1, 24, 0, 1, 2, 3]);
        options.extend_from_slice(&CLEAR);
        let wire = query(Some(&options));
        let out = outgoing_query(&wire, false).unwrap();
        assert!(directives(&out).is_empty());
        assert_eq!(
            edns_options(&out),
            &[
                0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 8, 0, 7, 0, 1, 24, 0, 1, 2, 3
            ][..]
        );
    }

    #[test]
    fn other_upstreams_get_the_query_unchanged() {
        let plain = query(None);
        assert!(matches!(
            outgoing_query(&plain, false).unwrap(),
            Cow::Borrowed(_)
        ));
        let cookie = query(Some(&[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]));
        let out = outgoing_query(&cookie, false).unwrap();
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out.as_ref(), cookie.as_slice());
    }

    #[test]
    fn fakeip_upstream_keeps_other_options_and_payload_size() {
        let wire = query(Some(&[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8]));
        let out = outgoing_query(&wire, true).unwrap();
        let mut expected = vec![0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        expected.extend_from_slice(&CLEAR);
        assert_eq!(edns_options(&out), expected.as_slice());
        let message = hickory_proto::op::Message::from_vec(&out).unwrap();
        assert_eq!(message.extensions().as_ref().unwrap().max_payload(), 4096);
    }

    #[test]
    fn forged_set_with_duplicate_ecs_is_stripped_for_other_upstreams() {
        // query_opt refuses duplicate ECS; stripping must not depend on it.
        let ecs = [0, 8, 0, 7, 0, 1, 24, 0, 1, 2, 3];
        let mut options = vec![0xfd, 0xe9, 0, 5, 1, 1, b'b', b'a', b'd'];
        options.extend_from_slice(&ecs);
        options.extend_from_slice(&ecs);
        let wire = query(Some(&options));
        assert!(crate::ecs::query_opt(&wire).is_err());
        let out = outgoing_query(&wire, false).unwrap();
        assert!(directives(&out).is_empty());
        assert_eq!(edns_options(&out), [ecs, ecs].concat().as_slice());
        assert_eq!(&out[12..22], &wire[12..22], "question");
        // The FakeIP upstream still refuses an OPT it cannot validate.
        assert!(outgoing_query(&wire, true).is_err());
    }

    #[test]
    fn question_pointing_into_a_moved_option_is_expanded() {
        // The question name is a pointer to `x.test` stored in a cookie
        // payload after a forged SET; removing the SET moves the cookie.
        let mut wire = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1];
        wire.extend_from_slice(&[0xc0, 42, 0, 1, 0, 1]);
        wire.extend_from_slice(&[0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 21]);
        wire.extend_from_slice(&[0xfd, 0xe9, 0, 5, 1, 1, b'b', b'a', b'd']);
        assert_eq!(wire.len(), 38);
        wire.extend_from_slice(&[0, 10, 0, 8]);
        wire.extend_from_slice(b"\x01x\x04test\x00");
        let cookie = wire[38..].to_vec();
        for fakeip in [false, true] {
            let out = outgoing_query(&wire, fakeip).unwrap();
            let message = hickory_proto::op::Message::from_vec(&out).unwrap();
            assert_eq!(message.queries()[0].name().to_ascii(), "x.test.");
            assert_eq!(&out[12..20], b"\x01x\x04test\x00", "expanded question");
            let mut expected = cookie.clone();
            if fakeip {
                expected.extend_from_slice(&CLEAR);
            }
            assert_eq!(edns_options(&out), expected.as_slice());
        }
    }

    #[test]
    fn unwalkable_opt_is_refused() {
        // The option claims more payload than the OPT holds.
        let wire = query(Some(&[0xfd, 0xe9, 0, 9, 1, 1]));
        assert!(outgoing_query(&wire, false).is_err());
        assert!(outgoing_query(&wire, true).is_err());
    }

    #[test]
    fn opt_owner_pointer_must_reach_a_valid_name() {
        // An OPT (TYPE 41, RDLENGTH 0) whose owner is a compression pointer:
        // past the end, onto itself, or into a loop through the header's ID
        // bytes (owner -> 0 -> owner). Skipping the owner alone accepts all
        // three; they must be refused for every upstream, not forwarded as
        // they are.
        let base = query(None);
        let owner = u8::try_from(base.len()).unwrap();
        let cases = [
            ("out of range", [0xc0, 0xff], None::<[u8; 2]>),
            ("self", [0xc0, owner], None),
            ("loop", [0xc0, 0], Some([0xc0, owner])),
        ];
        for (name, pointer, id) in cases {
            let mut wire = base.clone();
            wire[11] = 1;
            if let Some(id) = id {
                wire[..2].copy_from_slice(&id);
            }
            wire.extend_from_slice(&pointer);
            wire.extend_from_slice(&[0, 41, 16, 0, 0, 0, 0, 0, 0, 0]);
            assert!(outgoing_query(&wire, false).is_err(), "{name}");
            assert!(outgoing_query(&wire, true).is_err(), "{name}");
        }
        // A pointer to the (valid) question name is still accepted.
        let mut wire = base.clone();
        wire[11] = 1;
        wire.extend_from_slice(&[0xc0, 12, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(
            outgoing_query(&wire, false).unwrap(),
            Cow::Borrowed(_)
        ));
    }
}
