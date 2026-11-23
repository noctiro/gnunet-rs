//! Bounded ordinary DNS question correlation, independent of native authority.
use crate::{MAX_DNS_BYTES, Query};
use gnunet_dns::{Arena, Header, Limits, Reader};
use gnunet_types::Error;

/// Validate a question-bearing DNS query before an explicit native exchange.
/// Parses every question and record-owner name, checks section/RDLEN framing
/// and the exact packet end without allocating. Record data remains opaque.
/// This is ordinary DNS validation, not mDNS, DNSSEC or source authentication.
///
/// # Errors
/// Refuses responses, empty question sections, oversized or malformed messages,
/// truncated sections, trailing bytes and exhausted bounded parser work.
pub fn validate_questioned_query(bytes: &[u8]) -> Result<(), Error> {
    Query::decode(bytes)?;
    let header = Header::decode(bytes)?;
    if header.counts.queries == 0 {
        return Err(Error::Unsupported);
    }
    validate_framing(bytes, header)
}

fn validate_framing(bytes: &[u8], header: Header) -> Result<(), Error> {
    let queries = usize::from(header.counts.queries);
    let records = [
        header.counts.answers,
        header.counts.authority,
        header.counts.additional,
    ]
    .into_iter()
    .try_fold(0usize, |total, count| total.checked_add(usize::from(count)))
    .ok_or(Error::Overflow)?;
    let minimum = queries
        .checked_mul(5)
        .and_then(|length| {
            records
                .checked_mul(11)
                .and_then(|rr| length.checked_add(rr))
        })
        .and_then(|length| length.checked_add(12))
        .ok_or(Error::Overflow)?;
    if minimum > bytes.len() {
        return Err(Error::Truncated);
    }
    let limits = Limits {
        maximum_packet_bytes: MAX_DNS_BYTES,
        maximum_queries: queries,
        maximum_records: records,
        ..Limits::DNS
    };
    let mut reader = Reader::at(bytes, 12, bytes.len(), limits)?;
    for _ in 0..queries {
        let mut name = [0; gnunet_dns::MAX_WIRE_NAME_LENGTH];
        let _query = reader.query(&mut Arena::new(&mut name))?;
    }
    for _ in 0..records {
        let mut name = [0; gnunet_dns::MAX_WIRE_NAME_LENGTH];
        let _owner = reader.name(&mut Arena::new(&mut name))?;
        let at = reader.position();
        let header_end = at.checked_add(10).ok_or(Error::Overflow)?;
        let record = bytes.get(at..header_end).ok_or(Error::Truncated)?;
        let length = usize::from(u16::from_be_bytes([record[8], record[9]]));
        let end = header_end.checked_add(length).ok_or(Error::Overflow)?;
        if end > bytes.len() {
            return Err(Error::Truncated);
        }
        // Reader owns compression and name parsing. Preserve its original work
        // budget while skipping the opaque record's fixed header and RDATA.
        let work = reader
            .remaining_work()
            .checked_sub(end - at)
            .ok_or(Error::Capacity)?;
        reader = Reader::at(
            bytes,
            end,
            bytes.len(),
            Limits {
                maximum_work: work,
                ..limits
            },
        )?;
    }
    if reader.position() != bytes.len() {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Match a reply to an original question-bearing ordinary DNS query.
/// Requires the original ID, opcode and every name/type/class, comparing DNS
/// names without ASCII case sensitivity. A zero-question reply is refused even
/// for protocol errors; no native sender, request or output authority is granted.
/// Checks section framing for a matching reply. Record data and DNSSEC remain
/// outside this correlation check.
///
/// # Errors
/// Returns malformed question and matching message framing errors. Unrelated
/// or zero-question replies return `Ok(false)`.
pub fn questioned_reply_matches(query: &[u8], reply: &[u8]) -> Result<bool, Error> {
    Query::decode(query)?;
    if reply.len() > MAX_DNS_BYTES {
        return Err(Error::TooLarge);
    }
    let header = Header::decode(reply)?;
    if header.counts.queries == 0 || !questions_match(query, reply)? {
        return Ok(false);
    }
    validate_questioned_query(query)?;
    validate_framing(reply, header)?;
    Ok(true)
}

/// Correlate a complete DNS gateway reply, allowing a zero-question error.
///
/// The original query must already have passed `validate_questioned_query`.
/// A match checks the original ID and opcode, all response framing, and every
/// question if present. Native sender authority and DNSSEC remain separate.
///
/// # Errors
/// Refuses oversized bodies and malformed framing of an otherwise matching reply.
pub fn gateway_reply_matches(query: &[u8], reply: &[u8]) -> Result<bool, Error> {
    if !response_matches_questions(query, reply)? {
        return Ok(false);
    }
    validate_framing(reply, Header::decode(reply)?)?;
    Ok(true)
}

/// Correlate a DNS response header and questions without reading its records.
///
/// A truncated UDP response can omit parts of its record sections. Use this
/// check to select a TCP retry; validate framing before delivering any response.
/// As with the gateway's full resolver correlation, a zero-question error with
/// the original ID and opcode can match. Native sender authority is separate.
///
/// # Errors
/// Refuses oversized bodies, malformed DNS headers and invalid question framing.
pub fn response_matches_questions(query: &[u8], reply: &[u8]) -> Result<bool, Error> {
    Query::decode(query)?;
    if reply.len() > MAX_DNS_BYTES {
        return Err(Error::TooLarge);
    }
    questions_match(query, reply)
}

/// The ordinary gateway preserves its existing zero-question error shortcut.
pub(crate) fn questions_match(query: &[u8], answer: &[u8]) -> Result<bool, Error> {
    let a = Header::decode(query)?;
    let b = Header::decode(answer)?;
    if a.id != b.id
        || b.flags.bits() & 0x8000 == 0
        || (a.flags.bits() & 0x7800) != (b.flags.bits() & 0x7800)
    {
        return Ok(false);
    }
    if b.counts.queries == 0 && b.flags.bits() & 15 != 0 {
        return Ok(true);
    }
    let maximum_queries = query.len().saturating_sub(12) / 5;
    if a.counts.queries != b.counts.queries || usize::from(a.counts.queries) > maximum_queries {
        return Ok(false);
    }
    let limits = Limits {
        maximum_queries,
        ..Limits::DNS
    };
    let mut qa = Reader::at(query, 12, query.len(), limits)?;
    let mut qb = Reader::at(answer, 12, answer.len(), limits)?;
    for _ in 0..a.counts.queries {
        let mut left = [0; 255];
        let mut right = [0; 255];
        let a = qa.query(&mut Arena::new(&mut left))?;
        let b = qb.query(&mut Arena::new(&mut right))?;
        if a.kind != b.kind
            || a.class != b.class
            || !a.name.wire().eq_ignore_ascii_case(b.name.wire())
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const QUERY: [u8; 29] =
        *b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03org\x00\x00\x01\x00\x01";

    fn answer() -> [u8; 29] {
        let mut answer = QUERY;
        answer[2] |= 0x80;
        answer
    }

    #[test]
    fn ordinary_correlation_requires_id_opcode_and_each_original_question() {
        let mut matching = answer();
        matching[13..20].make_ascii_uppercase();
        assert_eq!(questioned_reply_matches(&QUERY, &matching), Ok(true));
        for (at, value) in [(0, 0), (2, 0x89), (13, b'x'), (26, 28), (28, 3)] {
            let mut unrelated = answer();
            unrelated[at] = value;
            assert_eq!(questioned_reply_matches(&QUERY, &unrelated), Ok(false));
        }
        assert_eq!(questioned_reply_matches(&QUERY, &QUERY), Ok(false));
        let mut malformed = answer();
        malformed[7] = 1;
        assert_eq!(
            questioned_reply_matches(&QUERY, &malformed),
            Err(Error::Truncated)
        );
        let mut error = [0; 12];
        error[..4].copy_from_slice(b"\x12\x34\x81\x03");
        assert_eq!(questioned_reply_matches(&QUERY, &error), Ok(false));
        assert_eq!(questions_match(&QUERY, &error), Ok(true));
    }

    #[test]
    fn compressed_questions_use_the_shared_semantic_name_parser() {
        let mut query = [0; 46];
        query[..29].copy_from_slice(&QUERY);
        query[29..].copy_from_slice(&QUERY[12..]);
        query[5] = 2;
        let mut reply = [0; 35];
        reply[..29].copy_from_slice(&answer());
        reply[5] = 2;
        reply[29..].copy_from_slice(b"\xc0\x0c\x00\x01\x00\x01");
        assert_eq!(questioned_reply_matches(&query, &reply), Ok(true));
        reply[30] = 29;
        assert!(questioned_reply_matches(&query, &reply).is_err());
    }

    #[test]
    fn original_query_checks_sections_extents_and_query_role_without_allocating() {
        assert_eq!(validate_questioned_query(&QUERY), Ok(()));
        assert_eq!(validate_questioned_query(&answer()), Err(Error::Malformed));
        assert_eq!(validate_questioned_query(&[0; 12]), Err(Error::Unsupported));
        assert_eq!(
            validate_questioned_query(&QUERY[..28]),
            Err(Error::Truncated)
        );
        let mut additional = [0; 40];
        additional[..29].copy_from_slice(&QUERY);
        additional[11] = 1;
        additional[29..].copy_from_slice(b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00");
        assert_eq!(validate_questioned_query(&additional), Ok(()));
        additional[39] = 1;
        assert_eq!(
            validate_questioned_query(&additional),
            Err(Error::Truncated)
        );
        let mut trailing = [0; 30];
        trailing[..29].copy_from_slice(&QUERY);
        assert_eq!(validate_questioned_query(&trailing), Err(Error::Malformed));
        let mut looped = QUERY;
        looped[12..14].copy_from_slice(b"\xc0\x0c");
        assert!(validate_questioned_query(&looped).is_err());
    }
}
