//! Standard DNS question validation and bounded projection of real GNS results.
//! No DNS callback, resolver, clock, socket or worker is owned by this module.
use crate::{Failure, Record};
use gnunet_dns::{
    AbsoluteTime, Arena, Flags, Header, Idna, Name, Packet, Query, RData, Reader,
    Record as DnsRecord, Type, class,
};
use gnunet_gnsrecord::RecordFlags;
use gnunet_types::Error as Fault;

const CLASSIC_UDP: usize = 512;
const OPT: Type = Type(41);
const OPT_BYTES: usize = 11;
const DO: u16 = 0x8000;
const TEXT_BYTES: usize = gnunet_dns::MAX_NAME_LENGTH * 4 + 1;

#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub(super) packet_bytes: usize,
    pub(super) records: usize,
    /// Aggregate projectable source RDATA, including TXT length prefixes.
    pub(super) record_bytes: usize,
    pub(super) arena_bytes: usize,
    /// Aggregate low-level RDATA Reader byte/label/pointer work.
    pub(super) work: usize,
}
impl Limits {
    pub(super) fn validate(self) -> Result<(), Fault> {
        if !(CLASSIC_UDP..=usize::from(u16::MAX)).contains(&self.packet_bytes)
            || !(1..=usize::from(u16::MAX)).contains(&self.records)
            || self.record_bytes == 0
            || self.arena_bytes < gnunet_dns::MAX_WIRE_NAME_LENGTH
            || self.work == 0
        {
            return Err(Fault::InvalidInput);
        }
        // Validate all later capacity arithmetic before any allocation.
        self.record_bytes
            .checked_add(self.records)
            .ok_or(Fault::Overflow)?;
        self.arena_bytes
            .checked_add(TEXT_BYTES * 2)
            .ok_or(Fault::Overflow)?;
        Ok(())
    }
    fn dns(self, packet_bytes: usize, work: usize) -> gnunet_dns::Limits {
        gnunet_dns::Limits {
            maximum_packet_bytes: packet_bytes,
            maximum_queries: 1,
            maximum_records: self.records,
            maximum_compression_hops: gnunet_dns::MAX_COMPRESSION_HOPS,
            maximum_work: work,
            maximum_text_input_bytes: TEXT_BYTES,
        }
    }
}
fn bytes(size: usize) -> Result<Vec<u8>, Fault> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(size)
        .map_err(|_| Fault::Capacity)?;
    result.resize(size, 0);
    Ok(result)
}
fn copy(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(input.len())
        .map_err(|_| Fault::Capacity)?;
    result.extend_from_slice(input);
    Ok(result)
}
#[derive(Clone, Copy)]
struct Edns {
    flags: u16,
}

/// An owned expanded original question. Compression offsets are not copied into
/// a reply whose other sections differ; original label bytes/case/type/class
/// remain unchanged. Native Unicode text is only the GNS lookup selector.
pub(super) struct Question {
    id: [u8; 2],
    flags: u16,
    wire: Vec<u8>,
    native: String,
    kind: u16,
    udp: usize,
    edns: Option<Edns>,
}
impl Question {
    /// Other query profiles and malformed packets are returned to the caller,
    /// which must Forward the original DNS callback rather than inventing a GNS
    /// lookup. Only ordinary IN QUERY with optional one well-formed EDNS0 OPT is
    /// intercepted; TSIG, transfers and other additional records remain external.
    pub(super) fn parse(
        raw: &[u8],
        _now: u64,
        limits: Limits,
        idna: &impl Idna,
    ) -> Result<Self, Fault> {
        limits.validate()?;
        let header = Header::decode(raw)?;
        let count = header.counts;
        // AD in a request is a capability indication, not an authentication
        // receipt. It is accepted here but never copied into the response AD.
        if header.flags.bits() & !0x0130 != 0
            || count.queries != 1
            || count.answers != 0
            || count.authority != 0
            || count.additional > 1
        {
            return Err(Fault::Unsupported);
        }
        if raw.len() > limits.packet_bytes {
            return Err(Fault::Capacity);
        }
        let parse_extent = raw
            .len()
            .checked_add(
                gnunet_dns::MAX_WIRE_NAME_LENGTH
                    .checked_mul(2)
                    .ok_or(Fault::Overflow)?,
            )
            .ok_or(Fault::Overflow)?
            .min(limits.arena_bytes);
        let mut storage = bytes(parse_extent)?;
        let mut arena = Arena::new(&mut storage);
        let mut queries = [Query::EMPTY];
        let mut records = [DnsRecord::EMPTY];
        // A query has no ordinary TTL-bearing records. Epoch zero preserves the
        // OPT's non-temporal TTL word exactly, even near the clock's u64 bound.
        let packet = Packet::parse(
            raw,
            AbsoluteTime::UNIX_EPOCH,
            &mut arena,
            &mut queries,
            &mut records,
            limits.dns(limits.packet_bytes, limits.work),
        )?;
        if packet.consumed != raw.len() || !packet.trailing.is_empty() {
            return Err(Fault::Malformed);
        }
        let query = *packet.queries.first().ok_or(Fault::Malformed)?;
        if query.class != class::INTERNET || !ordinary_type(query.kind.0) {
            return Err(Fault::Unsupported);
        }
        // A literal dot/NUL within one opaque DNS label cannot be flattened into
        // a GNS dot-separated name without changing label boundaries.
        if query
            .name
            .labels()
            .any(|label| label.contains(&b'.') || label.contains(&0))
        {
            return Err(Fault::Unsupported);
        }
        let mut udp = CLASSIC_UDP;
        let edns = if let Some(opt) = packet.additional.first() {
            if opt.kind != OPT || opt.name.wire() != [0] {
                return Err(Fault::Unsupported);
            }
            let ttl = u32::try_from(opt.expiration.as_micros() / 1_000_000)
                .map_err(|_| Fault::Overflow)?;
            // Queries have no extended error code. A nonzero EDNS version is
            // left to the original DNS owner, not silently answered as EDNS0.
            if ttl >> 16 != 0 {
                return Err(Fault::Unsupported);
            }
            let RData::Raw(options) = opt.data else {
                return Err(Fault::Malformed);
            };
            options_valid(options)?;
            udp = usize::from(opt.class).max(CLASSIC_UDP);
            Some(Edns {
                flags: ttl as u16 & DO,
            })
        } else {
            None
        };
        let wire = copy(query.name.wire())?;
        // Drop native compression provenance when converting the expanded name;
        // only its actual original labels, not a C text-buffer bound, matter.
        let name = Name::from_wire(&wire)?;
        let text_extent = wire
            .len()
            .checked_mul(4)
            .ok_or(Fault::Overflow)?
            .min(TEXT_BYTES);
        let mut text = bytes(text_extent)?;
        let mut work = bytes(text_extent)?;
        let used = name.write_native_text(idna, &mut work, &mut text)?;
        let native = std::str::from_utf8(&text[..used]).map_err(|_| Fault::Malformed)?;
        if native.is_empty() || native.as_bytes().contains(&0) {
            return Err(Fault::Unsupported);
        }
        let mut owned = String::new();
        owned
            .try_reserve_exact(native.len())
            .map_err(|_| Fault::Capacity)?;
        owned.push_str(native);
        Ok(Self {
            id: header.id,
            flags: header.flags.bits(),
            wire,
            native: owned,
            kind: query.kind.0,
            udp: udp.min(limits.packet_bytes),
            edns,
        })
    }
    pub(super) fn name(&self) -> &str {
        &self.native
    }
    pub(super) fn kind(&self) -> u16 {
        self.kind
    }

    pub(super) fn reply(
        &self,
        outcome: &Result<Vec<Record>, Failure>,
        now: u64,
        limits: Limits,
    ) -> Result<Reply, Fault> {
        limits.validate()?;
        if now == u64::MAX {
            return Err(Fault::InvalidInput);
        }
        let rcode = match outcome {
            Ok(_) => 0,
            Err(Failure::NotFound | Failure::Revoked) => 3,
            Err(_) => 2,
        };
        let allow_security = self.edns.is_some_and(|edns| edns.flags & DO != 0);
        let records = outcome.as_ref().map(Vec::as_slice).unwrap_or(&[]);
        if records.len() > limits.records {
            return Err(Fault::Capacity);
        }
        let extent = arena_extent(records, self.kind, now, allow_security, limits)?;
        let mut storage = bytes(extent)?;
        let mut arena = Arena::new(&mut storage);
        let owner = Name::from_wire(&self.wire)?;
        let query = [Query {
            name: owner,
            kind: Type(self.kind),
            class: class::INTERNET,
        }];
        let mut answers = Vec::new();
        let mut additional = Vec::new();
        let mut omitted = 0;
        let mut payload = 0usize;
        let mut work = limits.work;
        if let Ok(records) = outcome {
            if records.len() > limits.records {
                return Err(Fault::Capacity);
            }
            let answer_slots = records
                .iter()
                .filter(|record| {
                    self.kind == 255 || record.record_type.value() == u32::from(self.kind)
                })
                .count();
            answers
                .try_reserve_exact(answer_slots)
                .map_err(|_| Fault::Capacity)?;
            additional
                .try_reserve_exact(records.len() - answer_slots)
                .map_err(|_| Fault::Capacity)?;
            for record in records {
                let Some(kind) = eligible(record, self.kind, now, allow_security) else {
                    omitted += 1;
                    continue;
                };
                let encoded = if kind == Type::TXT.0 {
                    record
                        .data
                        .len()
                        .checked_add(record.data.len().div_ceil(255).max(1))
                        .ok_or(Fault::Overflow)?
                } else {
                    record.data.len()
                };
                if encoded > usize::from(u16::MAX) {
                    omitted += 1;
                    continue;
                }
                payload = payload.checked_add(encoded).ok_or(Fault::Overflow)?;
                if payload > limits.record_bytes {
                    return Err(Fault::Capacity);
                }
                let data = match project(kind, &record.data, &mut arena, limits, &mut work) {
                    Ok(data) => data,
                    Err(
                        Fault::Malformed
                        | Fault::Truncated
                        | Fault::InvalidInput
                        | Fault::Unsupported
                        | Fault::TooLarge,
                    ) => {
                        omitted += 1;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                // DNS TTL is an unsigned interval bounded to31 bits (RFC2181 section8).
                // Clamp rather than letting the native u32 narrowing wrap a
                // very long GNS/never lifetime into an unrelated TTL.
                let ttl = ((record.expiration_time - now) / 1_000_000).min(i32::MAX as u64);
                let expiration = now
                    .checked_add(ttl * 1_000_000)
                    .filter(|n| *n != u64::MAX)
                    .ok_or(Fault::Overflow)?;
                let projected = DnsRecord {
                    name: owner,
                    kind: Type(kind),
                    class: class::INTERNET,
                    expiration: AbsoluteTime::from_micros(expiration),
                    data,
                };
                projected.encoded_len()?;
                if self.kind == 255 || self.kind == kind {
                    answers.push(projected);
                } else {
                    additional.push(projected);
                }
            }
        }
        let maximum = self.udp.min(limits.packet_bytes);
        let reserved = if self.edns.is_some() { OPT_BYTES } else { 0 };
        let business = maximum.checked_sub(reserved).ok_or(Fault::Capacity)?;
        let base = gnunet_dns::HEADER_LEN
            .checked_add(query[0].encoded_len())
            .ok_or(Fault::Overflow)?;
        let mut remaining = business.checked_sub(base).ok_or(Fault::Capacity)?;
        let mut truncated = false;
        fit_sets(
            &mut answers,
            &mut remaining,
            true,
            &mut truncated,
            &mut omitted,
        )?;
        fit_sets(
            &mut additional,
            &mut remaining,
            false,
            &mut truncated,
            &mut omitted,
        )?;
        let flags = Flags::default()
            .with_query_or_response(true)
            .with_authoritative_answer(true)
            .with_recursion_desired(self.flags & 0x0100 != 0)
            .with_checking_disabled(self.flags & 0x0010 != 0)
            .with_message_truncated(truncated)
            .with_return_code(rcode)?
            .bits();
        let packet = Packet::new(self.id, flags, &query, &answers, &[], &additional);
        let full_size = packet.encoded_len()?;
        if full_size > business {
            return Err(Fault::Overflow);
        }
        let output_extent = full_size.checked_add(reserved).ok_or(Fault::Overflow)?;
        let mut bytes = bytes(output_extent)?;
        let report = packet.pack(
            AbsoluteTime::from_micros(now),
            &mut bytes,
            u16::try_from(business).map_err(|_| Fault::TooLarge)?,
        )?;
        if report.truncated || report.counts.queries != 1 {
            return Err(Fault::Capacity);
        }
        let emitted = usize::from(report.counts.answers) + usize::from(report.counts.additional);
        omitted += answers.len() + additional.len() - emitted;
        let mut written = report.written;
        if let Some(edns) = self.edns {
            // RFC6891 requires response OPT whenever the accepted query had one.
            // Reserve its11 bytes before business packing so truncation cannot
            // drop it. Unknown input options are ignored, never blindly echoed.
            let opt = DnsRecord {
                name: Name::ROOT,
                kind: OPT,
                class: u16::try_from(limits.packet_bytes).map_err(|_| Fault::TooLarge)?,
                expiration: AbsoluteTime::from_micros(u64::from(edns.flags) * 1_000_000),
                data: RData::Raw(&[]),
            };
            written += opt.encode(AbsoluteTime::UNIX_EPOCH, &mut bytes[written..])?;
            let mut header = Header::decode(&bytes)?;
            header.counts.additional = header
                .counts
                .additional
                .checked_add(1)
                .ok_or(Fault::Overflow)?;
            header.encode(&mut bytes)?;
        }
        bytes.truncate(written);
        Ok(Reply {
            bytes,
            truncated,
            omitted,
            rcode,
        })
    }
}
/// Only ordinary data questions. Protocol meta-RRs/transfer/mail pseudo-types
/// are returned to the native DNS owner; ALL255 is a valid ordinary question.
fn ordinary_type(kind: u16) -> bool {
    kind != 0 && kind != 41 && !(249..=254).contains(&kind)
}

fn eligible(record: &Record, question: u16, now: u64, allow_security: bool) -> Option<u16> {
    let kind = u16::try_from(record.record_type.value()).ok()?;
    if !ordinary_type(kind)
        || kind == 255
        || record.flags.contains(RecordFlags::RELATIVE_EXPIRATION)
        || record.expiration_time < now
    {
        return None;
    }
    // RFC3225 section3 / RFC4035 section3.2.1: an explicit type/ANY question
    // remains answerable without DO, but unrequested authenticating DNSSEC
    // material is not automatically added. This supplies no validation receipt.
    if !allow_security
        && question != 255
        && question != kind
        && matches!(kind, 24 | 25 | 30 | 43 | 46 | 47 | 48 | 50 | 51)
    {
        return None;
    }
    Some(kind)
}
fn arena_extent(
    records: &[Record],
    question: u16,
    now: u64,
    allow_security: bool,
    limits: Limits,
) -> Result<usize, Fault> {
    let mut extent = 0usize;
    let mut payload = 0usize;
    for record in records {
        let Some(kind) = eligible(record, question, now, allow_security) else {
            continue;
        };
        let size = if kind == Type::TXT.0 {
            record
                .data
                .len()
                .checked_add(record.data.len().div_ceil(255).max(1))
                .ok_or(Fault::Overflow)?
        } else {
            record.data.len()
        };
        if size > usize::from(u16::MAX) {
            continue;
        }
        payload = payload.checked_add(size).ok_or(Fault::Overflow)?;
        if payload > limits.record_bytes {
            return Err(Fault::Capacity);
        }
        // Reader copies only one expanded name for host/MX/SRV, two for SOA;
        // CERT/URI/raw payload copies cannot exceed their original value size.
        let copied = if kind == Type::SOA.0 {
            gnunet_dns::MAX_WIRE_NAME_LENGTH
                .checked_mul(2)
                .ok_or(Fault::Overflow)?
        } else if Type(kind).is_hostname() || matches!(kind, 15 | 33) {
            gnunet_dns::MAX_WIRE_NAME_LENGTH
        } else {
            size
        };
        extent = extent.checked_add(copied).ok_or(Fault::Overflow)?;
    }
    Ok(extent.min(limits.arena_bytes))
}
#[derive(Clone, Copy)]
struct Set {
    kind: u16,
    size: usize,
    count: usize,
    expires: u64,
    keep: bool,
}
fn fit_sets(
    records: &mut Vec<DnsRecord<'_>>,
    remaining: &mut usize,
    required: bool,
    truncated: &mut bool,
    omitted: &mut usize,
) -> Result<(), Fault> {
    let mut sets: Vec<Set> = Vec::new();
    sets.try_reserve_exact(records.len())
        .map_err(|_| Fault::Capacity)?;
    for record in records.iter() {
        sets.push(Set {
            kind: record.kind.0,
            size: record.encoded_len()?,
            count: 1,
            expires: record.expiration.as_micros(),
            keep: false,
        });
    }
    sets.sort_unstable_by_key(|set| set.kind);
    let mut used = 0;
    for at in 0..sets.len() {
        let next = sets[at];
        if used != 0 && sets[used - 1].kind == next.kind {
            let set = &mut sets[used - 1];
            set.size = set.size.checked_add(next.size).ok_or(Fault::Overflow)?;
            set.count = set.count.checked_add(next.count).ok_or(Fault::Overflow)?;
            set.expires = set.expires.min(next.expires);
        } else {
            sets[used] = next;
            used += 1;
        }
    }
    sets.truncate(used);
    // Same owner/class throughout. RFC2181 sections5.1/5.2/9 require common
    // minimum TTL and whole optional RRSets. Optional additional omission alone
    // does not set TC; missing required answer sets do. Original row order stays.
    for set in &mut sets {
        set.keep = set.size <= *remaining;
        if set.keep {
            *remaining -= set.size;
        } else {
            *omitted = omitted.checked_add(set.count).ok_or(Fault::Overflow)?;
            *truncated |= required;
        }
    }
    for record in records.iter_mut() {
        let index = sets
            .binary_search_by_key(&record.kind.0, |set| set.kind)
            .map_err(|_| Fault::Stale)?;
        record.expiration = AbsoluteTime::from_micros(sets[index].expires);
    }
    records.retain(|record| {
        sets.binary_search_by_key(&record.kind.0, |set| set.kind)
            .is_ok_and(|i| sets[i].keep)
    });
    Ok(())
}
fn options_valid(mut bytes: &[u8]) -> Result<(), Fault> {
    while !bytes.is_empty() {
        let head = bytes.get(..4).ok_or(Fault::Truncated)?;
        let size = usize::from(u16::from_be_bytes([head[2], head[3]]));
        bytes = bytes
            .get(4..)
            .and_then(|tail| tail.get(size..))
            .ok_or(Fault::Truncated)?;
    }
    Ok(())
}
fn project<'a>(
    kind: u16,
    input: &[u8],
    arena: &mut Arena<'a>,
    limits: Limits,
    work: &mut usize,
) -> Result<RData<'a>, Fault> {
    if (kind == Type::A.0 && input.len() != 4) || (kind == Type::AAAA.0 && input.len() != 16) {
        return Err(Fault::Malformed);
    }
    if kind == Type::TXT.0 {
        // GNS text and the native DNS provider both expose raw concatenated TXT
        // octets (auxiliary/dns.rs::txt). RFC1035 section3.3.14 requires one or
        // more length-prefixed character-strings on DNS wire, including [0] for
        // an empty text. Byte segmentation preserves binary/UTF8 octets exactly.
        let count = input.len().div_ceil(255).max(1);
        let size = input.len().checked_add(count).ok_or(Fault::Overflow)?;
        if size > usize::from(u16::MAX) {
            return Err(Fault::TooLarge);
        }
        *work = work.checked_sub(size).ok_or(Fault::Capacity)?;
        let mut txt = bytes(size)?;
        let mut offset = 0;
        if input.is_empty() {
            txt[0] = 0;
        } else {
            for part in input.chunks(255) {
                txt[offset] = part.len() as u8;
                offset += 1;
                txt[offset..offset + part.len()].copy_from_slice(part);
                offset += part.len();
            }
        }
        return Ok(RData::Raw(arena.copy(&txt)?));
    }
    let mut reader = Reader::new(input, limits.dns(usize::from(u16::MAX), *work))?;
    let data = reader.data(Type(kind), arena);
    *work = reader.remaining_work();
    let data = data?;
    if reader.position() != input.len() {
        return Err(Fault::Malformed);
    }
    Ok(data)
}

pub(super) struct Reply {
    pub(super) bytes: Vec<u8>,
    pub(super) truncated: bool,
    pub(super) omitted: usize,
    pub(super) rcode: u8,
}
