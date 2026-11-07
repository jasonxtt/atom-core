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
/// carries no 65001 is returned as it is; one whose OPT this host cannot read
/// is passed on unchanged too, as before (a query for the FakeIP upstream is
/// then an error: it must never reach sing-box with options we did not check).
pub(crate) fn outgoing_query(raw: &[u8], fakeip: bool) -> Result<Cow<'_, [u8]>, ExecutorError> {
    let opt = match crate::ecs::query_opt(raw) {
        Ok(opt) => opt,
        Err(error) if fakeip => return Err(error),
        Err(_) => return Ok(Cow::Borrowed(raw)),
    };
    let mut options = Vec::new();
    let mut stripped = false;
    if let Some(opt) = &opt {
        // query_opt has validated every option's length.
        let mut rest = opt.other.as_slice();
        while let [a, b, c, d, ..] = *rest {
            let len = 4 + usize::from(u16::from_be_bytes([c, d]));
            let (option, tail) = rest.split_at(len.min(rest.len()));
            if u16::from_be_bytes([a, b]) == OPTION_CODE {
                stripped = true;
            } else {
                options.extend_from_slice(option);
            }
            rest = tail;
        }
        if let Some(ecs) = &opt.ecs {
            options.extend_from_slice(&ecs.option());
        }
    }
    if !fakeip && !stripped {
        return Ok(Cow::Borrowed(raw));
    }
    if fakeip {
        options.extend_from_slice(&OPTION_CODE.to_be_bytes());
        options.extend_from_slice(&[0, 2, VERSION, OP_CLEAR]);
    }
    let (mut wire, fixed) = match opt {
        Some(opt) => (raw[..opt.offset].to_vec(), opt.fixed),
        None => {
            // Rebuild header + question: the question name may point into
            // trailing name storage that must not stay before the OPT.
            let (_, question) = atomdns_dns_core::parse_query(raw)
                .map_err(|_| ExecutorError::new("invalid query"))?;
            let mut wire = raw[..12].to_vec();
            wire.extend_from_slice(&question.qname_wire);
            wire.extend_from_slice(&question.qtype.to_be_bytes());
            wire.extend_from_slice(&question.qclass.to_be_bytes());
            (wire, vec![0, 0, 41, 4, 208, 0, 0, 0, 0])
        }
    };
    wire[10..12].copy_from_slice(&1u16.to_be_bytes());
    wire.extend_from_slice(&fixed);
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
        let message = hickory_proto::op::Message::from_vec(wire).expect("valid query");
        let Some(edns) = message.extensions() else {
            return Vec::new();
        };
        let mut found = Vec::new();
        let mut rest = edns_options(wire);
        while rest.len() >= 4 {
            let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
            if u16::from_be_bytes([rest[0], rest[1]]) == OPTION_CODE {
                found.push(rest[4..4 + len].to_vec());
            }
            rest = &rest[4 + len..];
        }
        assert!(edns.max_payload() >= 512);
        found
    }

    fn edns_options(wire: &[u8]) -> &[u8] {
        let opt = crate::ecs::query_opt(wire).unwrap().expect("OPT");
        &wire[opt.offset + 11..]
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
}
