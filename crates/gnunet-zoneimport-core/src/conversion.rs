//! Original NS/IN response matching and bounded DNS-to-GNS conversion.
//!
//! None of these values authenticate a resolver, DNSSEC, or a source socket.
//! The host must first associate the datagram/TCP stream with the original
//! request/upstream and native budget. Only a complete matching NOERROR reply
//! can produce a converted set; truncation and failure never produce empty data.
use core::{
    fmt,
    fmt::Write as _,
    net::{Ipv4Addr, Ipv6Addr},
};
use gnunet_dns::{Arena, Flags, Header, Idna, Name, Packet, Query, RData, Reader, Record, Type};
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType};
use gnunet_types::Error;
use gnunet_wire::official::{AbsoluteTime, RelativeTime};
const OPT: Type = Type(41);
/// Original immutable wire question and opaque transaction identifier.
#[derive(Clone, Copy, Debug)]
pub struct Expected<'a> {
    /// Original two ID octets, not converted through a native-endian integer.
    pub id: [u8; 2],
    /// Original sole NS/IN question. DNS wire names compare case insensitively.
    pub question: Query<'a>,
}
/// Explicit rejection. No error or partial buffer authorizes a NAMESTORE write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// Existing parser, codec, arithmetic or resource refusal.
    Protocol(Error),
    /// Packet transaction ID does not match this original request.
    Identifier,
    /// Not a normal DNS response/opcode, or impossible response metadata.
    Header,
    /// Missing, additional, or mismatching original question.
    Question,
    /// Actual complete DNS response code, including EDNS extension. NXDOMAIN,
    /// SERVFAIL and REFUSED are failures, never successful empty record sets.
    ResponseCode(u16),
    /// Only unsupported live matching DNAME data was found. Preserve old data;
    /// do not confuse this case with genuine NOERROR/NODATA.
    UnsupportedOnly,
}
impl From<Error> for Failure {
    fn from(cause: Error) -> Self {
        Self::Protocol(cause)
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zoneimport DNS conversion: {self:?}")
    }
}
impl core::error::Error for Failure {}
/// Existing mature DNS parser storage; memory remains exclusively caller-owned.
pub struct Storage<'slots, 'arena> {
    /// Bounded name/payload arena. Prefix inspection may additionally spend one
    /// expanded question name before complete packet parsing.
    pub arena: &'slots mut Arena<'arena>,
    /// Query slots for the complete packet; normal import requires exactly one.
    pub questions: &'slots mut [Query<'arena>],
    /// Total answer/authority/additional record slots.
    pub records: &'slots mut [Record<'arena>],
}
/// A complete packet bound to the original question, not an authentication proof.
pub struct Matched<'slots, 'arena> {
    packet: Packet<'slots, 'arena>,
    received_at: AbsoluteTime,
}
impl Matched<'_, '_> {
    /// Explicit original parse timestamp used to form DNS absolute expirations.
    pub const fn received_at(&self) -> AbsoluteTime {
        self.received_at
    }
    /// Count actual expired IN records matching this original question across
    /// all three sections. Glue belonging to another owner is not included.
    /// This bounded, allocation-free observation grants no conversion/write;
    /// callers may retain the count even if later conversion refuses capacity.
    pub fn expired_matching_records(&self, now: AbsoluteTime) -> usize {
        records(&self.packet)
            .filter(|record| {
                record.kind != OPT
                    && record.class == gnunet_dns::class::INTERNET
                    && same_name(record.name, self.packet.queries[0].name)
                    && record.expiration.as_micros() <= now.as_micros()
            })
            .count()
    }
    /// Exact parsed flags, including untrusted AA/AD indications.
    pub const fn flags(&self) -> Flags {
        Flags::from_bits_preserve(self.packet.flags)
    }
}
/// Prefix inspection distinguishes transport fallback from complete conversion.
pub enum Response<'slots, 'arena> {
    /// ID/QR/opcode/sole complete question matched, but TC is set. Retry only on
    /// the original upstream via TCP within the same original request bounds.
    NeedTcp,
    /// Complete matching NOERROR packet. The caller still supplies source facts.
    Answer(Matched<'slots, 'arena>),
}
fn same_name(left: Name<'_>, right: Name<'_>) -> bool {
    left.wire().eq_ignore_ascii_case(right.wire())
}
fn same_question(left: Query<'_>, right: Query<'_>) -> bool {
    left.kind == right.kind && left.class == right.class && same_name(left.name, right.name)
}
/// Inspect the fixed header and complete original question before touching RR
/// data. TC can request TCP even if its RR section is truncated. Non-TC packets
/// must fully parse under the existing DNS bounds and have no uncounted tail.
pub fn inspect<'slots, 'arena: 'slots>(
    input: &[u8],
    expected: Expected<'_>,
    received_at: AbsoluteTime,
    storage: Storage<'slots, 'arena>,
    limits: gnunet_dns::Limits,
) -> Result<Response<'slots, 'arena>, Failure> {
    if expected.question.kind != Type::NS || expected.question.class != gnunet_dns::class::INTERNET
    {
        return Err(Error::InvalidInput.into());
    }
    let header = Header::decode(input)?;
    if header.id != expected.id {
        return Err(Failure::Identifier);
    }
    if !header.flags.query_or_response()
        || header.flags.opcode() != gnunet_dns::opcode::QUERY
        || header.flags.reserved_zero()
    {
        return Err(Failure::Header);
    }
    if header.counts.queries != 1 {
        return Err(Failure::Question);
    }
    let mut reader = Reader::at(input, gnunet_dns::HEADER_LEN, input.len(), limits)?;
    let query = reader.query(storage.arena)?;
    if !same_question(query, expected.question) {
        return Err(Failure::Question);
    }
    if header.flags.return_code() != 0 {
        return Err(Failure::ResponseCode(u16::from(header.flags.return_code())));
    }
    if header.flags.message_truncated() {
        return Ok(Response::NeedTcp);
    }
    let first_record = reader.position();
    let packet = Packet::parse(
        input,
        received_at,
        storage.arena,
        storage.questions,
        storage.records,
        limits,
    )?;
    if packet.queries.len() != 1 || !same_question(packet.queries[0], expected.question) {
        return Err(Failure::Question);
    }
    if !packet.trailing.is_empty() || packet.consumed != input.len() {
        return Err(Error::Malformed.into());
    }
    let extended = extended_code(input, first_record, header, limits)?;
    if extended != 0 {
        return Err(Failure::ResponseCode(extended));
    }
    Ok(Response::Answer(Matched {
        packet,
        received_at,
    }))
}
// OPT's high TTL octet is an extended return code, not a DNS expiration. This
// metadata walk reuses the mature Name reader and reads only fixed RR headers;
// RDATA/decompression/length validation remains Packet::parse's responsibility.
fn extended_code(
    input: &[u8],
    mut position: usize,
    header: Header,
    limits: gnunet_dns::Limits,
) -> Result<u16, Failure> {
    let total = usize::from(header.counts.answers)
        .checked_add(usize::from(header.counts.authority))
        .and_then(|n| n.checked_add(usize::from(header.counts.additional)))
        .ok_or(Error::Overflow)?;
    let normal = usize::from(header.counts.answers) + usize::from(header.counts.authority);
    let mut extended = None;
    let mut work = limits.maximum_work;
    for index in 0..total {
        let mut names = [0; gnunet_dns::MAX_WIRE_NAME_LENGTH];
        let mut arena = Arena::new(&mut names);
        let mut reader = Reader::at(
            input,
            position,
            input.len(),
            gnunet_dns::Limits {
                maximum_work: work,
                ..limits
            },
        )?;
        let name = reader.name(&mut arena)?;
        position = reader.position();
        work = reader.remaining_work();
        let end = position.checked_add(10).ok_or(Error::Overflow)?;
        let fields = input.get(position..end).ok_or(Error::Truncated)?;
        let kind = Type(u16::from_be_bytes([fields[0], fields[1]]));
        let length = usize::from(u16::from_be_bytes([fields[8], fields[9]]));
        position = end.checked_add(length).ok_or(Error::Overflow)?;
        if position > input.len() {
            return Err(Error::Truncated.into());
        }
        work = work
            .checked_sub(10usize.checked_add(length).ok_or(Error::Overflow)?)
            .ok_or(Error::Capacity)?;
        if kind == OPT {
            if index < normal || name.wire() != Name::ROOT.wire() || extended.is_some() {
                return Err(Error::Malformed.into());
            }
            if fields[5] != 0 {
                return Err(Error::Unsupported.into());
            }
            extended = Some(u16::from(fields[4]) << 4);
        }
    }
    Ok(extended.unwrap_or(0) | u16::from(header.flags.return_code()))
}
/// Public source policy; no hidden clock read renews an original expiration.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Floor applied only to still-live DNS records/glue, after TTL0 is ignored.
    /// FOREVER is a valid data value and never extends the caller native budget.
    pub minimum_expiration: RelativeTime,
    /// Next refresh of a genuinely empty complete NOERROR set, normally one day.
    /// FOREVER disables its automatic refresh; request/native budgets stay finite.
    pub empty_refresh: RelativeTime,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            minimum_expiration: RelativeTime::ZERO,
            empty_refresh: RelativeTime::from_micros(86_400_000_000),
        }
    }
}
/// Actual converted-set metadata, not a STORE reply or DNS authentication receipt.
#[derive(Clone, Copy, Debug)]
pub struct Summary {
    /// Number of actual produced GNS values.
    pub records: usize,
    /// Earliest actual resulting absolute expiration, absent for genuine empty.
    pub earliest_expiry: Option<AbsoluteTime>,
    /// Original next refresh coordinate: earliest expiry or empty policy target.
    pub refresh: AbsoluteTime,
    /// True only when the complete matching response has no applicable data.
    pub empty: bool,
    /// Live matching DNAME records actually skipped alongside supported values.
    /// An unsupported-only response returns Failure instead of empty=true.
    pub skipped_dname: usize,
}
impl Summary {
    /// True means supported content was retained but unsupported DNAME was skipped.
    pub const fn partial_supported(&self) -> bool {
        self.skipped_dname != 0
    }
}
/// Blank caller-owned metadata slot. No public populated-value constructor.
#[derive(Clone, Copy, Debug)]
pub struct Slot {
    kind: RecordType,
    expires: AbsoluteTime,
    start: usize,
    end: usize,
}
impl Slot {
    /// Empty placeholder for a caller's bounded row pool.
    pub const EMPTY: Self = Self {
        kind: RecordType::ANY,
        expires: AbsoluteTime::UNIX_EPOCH,
        start: 0,
        end: 0,
    };
}
/// Caller supplies bounded output plus explicit existing complete IDNA backend.
pub struct Buffers<'out, 'work, 'idna, I: Idna> {
    /// Maximum returned record count; no extra row is allocated on expansion.
    pub slots: &'out mut [Slot],
    /// Total expanded, uncompressed GNS values; one final set must fit separately.
    pub bytes: &'out mut [u8],
    /// Name projection staging, including possible Unicode expansion.
    pub name: &'work mut [u8],
    /// Existing DNS native-name backend work; distinct from staging/output.
    pub text: &'work mut [u8],
    /// Complete selected IDNA implementation; no default/partial backend exists.
    pub idna: &'idna I,
    /// Finite total record/glue visit budget; NS/glue search spends it explicitly.
    pub maximum_work: usize,
}
/// Borrowed original-owner record set. On failure no partial set is returned.
pub struct Converted<'out, 'owner> {
    owner: &'owner str,
    slots: &'out [Slot],
    bytes: &'out [u8],
    summary: Summary,
}
impl Converted<'_, '_> {
    /// Original request hostname, not a reconstructed DNS question or authority.
    pub const fn owner(&self) -> &str {
        self.owner
    }
    /// Actual final conversion metadata for the original Core query job.
    pub const fn summary(&self) -> Summary {
        self.summary
    }
    /// Actual records with absolute expirations and no synthetic flags. A later
    /// NAMESTORE batch still needs its own real original admission/reply.
    pub fn records(&self) -> impl ExactSizeIterator<Item = RecordData<'_>> {
        self.slots.iter().map(|slot| RecordData {
            expiration_time: slot.expires.as_micros(),
            record_type: slot.kind,
            flags: RecordFlags::NONE,
            data: &self.bytes[slot.start..slot.end],
        })
    }
}
struct Writer<'a> {
    slots: &'a mut [Slot],
    bytes: &'a mut [u8],
    count: usize,
    used: usize,
    work: usize,
    earliest: Option<AbsoluteTime>,
}
impl Writer<'_> {
    fn visit(&mut self) -> Result<(), Failure> {
        self.work = self.work.checked_sub(1).ok_or(Error::Capacity)?;
        Ok(())
    }
    fn credit(&self, length: usize) -> Result<usize, Failure> {
        let end = self.used.checked_add(length).ok_or(Error::Overflow)?;
        if self.count >= self.slots.len() || end > self.bytes.len() {
            return Err(Error::Capacity.into());
        }
        Ok(end)
    }
    fn commit(&mut self, kind: RecordType, expires: AbsoluteTime, end: usize) {
        self.slots[self.count] = Slot {
            kind,
            expires,
            start: self.used,
            end,
        };
        self.count += 1;
        self.used = end;
        self.earliest = Some(self.earliest.map_or(expires, |old| old.min(expires)));
    }
    fn raw(
        &mut self,
        kind: RecordType,
        expires: AbsoluteTime,
        input: &[u8],
    ) -> Result<(), Failure> {
        let end = self.credit(input.len())?;
        self.bytes[self.used..end].copy_from_slice(input);
        self.commit(kind, expires, end);
        Ok(())
    }
    fn typed(&mut self, record: Record<'_>, expires: AbsoluteTime) -> Result<(), Failure> {
        let length = record.data_len()?;
        let end = self.credit(length)?;
        record.data.encode(&mut self.bytes[self.used..end])?;
        self.commit(RecordType::new(u32::from(record.kind.0)), expires, end);
        Ok(())
    }
    fn delegation(
        &mut self,
        owner: &str,
        server: &[u8],
        expires: AbsoluteTime,
    ) -> Result<(), Failure> {
        if server.is_empty() || server.contains(&0) {
            return Err(Error::Malformed.into());
        }
        let length = owner
            .len()
            .checked_add(server.len())
            .and_then(|n| n.checked_add(2))
            .ok_or(Error::Overflow)?;
        let end = self.credit(length)?;
        let output = &mut self.bytes[self.used..end];
        output[..owner.len()].copy_from_slice(owner.as_bytes());
        output[owner.len()] = 0;
        output[owner.len() + 1..length - 1].copy_from_slice(server);
        output[length - 1] = 0;
        self.commit(RecordType::GNS2DNS, expires, end);
        Ok(())
    }
    fn txt(&mut self, input: &[u8], expires: AbsoluteTime) -> Result<(), Failure> {
        if input.is_empty() {
            return Err(Error::Malformed.into());
        }
        let mut cursor = 0usize;
        let mut length = 0usize;
        while cursor < input.len() {
            let n = usize::from(input[cursor]);
            cursor += 1;
            cursor = cursor
                .checked_add(n)
                .filter(|end| *end <= input.len())
                .ok_or(Error::Malformed)?;
            length = length.checked_add(n).ok_or(Error::Overflow)?;
        }
        let end = self.credit(length)?;
        cursor = 0;
        let mut target = self.used;
        while cursor < input.len() {
            let n = usize::from(input[cursor]);
            cursor += 1;
            self.bytes[target..target + n].copy_from_slice(&input[cursor..cursor + n]);
            target += n;
            cursor += n;
        }
        // GNS TXT is plain octets (LSD0001 D.2); multiple DNS strings concatenate.
        // This is not a UTF-8 projection: empty pieces and embedded NUL survive.
        self.commit(RecordType::TXT, expires, end);
        Ok(())
    }
}
fn expiration(
    original: AbsoluteTime,
    now: AbsoluteTime,
    minimum: RelativeTime,
) -> Option<AbsoluteTime> {
    if original <= now {
        return None;
    }
    // Official relative_to_absolute treats FOREVER and finite addition overflow
    // as FOREVER. This is a record-data floor, never an operation/native budget.
    let floor = now.as_micros().saturating_add(minimum.as_micros());
    Some(original.max(AbsoluteTime::from_micros(floor)))
}
fn records<'s, 'a>(packet: &'s Packet<'_, 'a>) -> impl Iterator<Item = Record<'a>> + 's
where
    'a: 's,
{
    packet
        .answers
        .iter()
        .chain(packet.authority)
        .chain(packet.additional)
        .copied()
}
fn render_name(
    name: Name<'_>,
    idna: &impl Idna,
    text: &mut [u8],
    output: &mut [u8],
) -> Result<usize, Failure> {
    // GNS2DNS uses C-string components; raw NUL/dot inside one DNS label cannot
    // be faithfully represented by that format. Do not silently truncate it.
    if name
        .labels()
        .any(|label| label.contains(&0) || label.contains(&b'.'))
    {
        return Err(Error::Malformed.into());
    }
    let count = name.write_native_text(idna, text, output)?;
    if output[..count].contains(&0) {
        return Err(Error::Malformed.into());
    }
    Ok(count)
}
struct Text<'a> {
    output: &'a mut [u8],
    used: usize,
}
impl fmt::Write for Text<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self
            .used
            .checked_add(value.len())
            .filter(|end| *end <= self.output.len())
            .ok_or(fmt::Error)?;
        self.output[self.used..end].copy_from_slice(value.as_bytes());
        self.used = end;
        Ok(())
    }
}
/// Convert only an inspected complete answer. `hostname` is the exact original
/// Core request's UTF-8 owner, not a DNS packet claim. `now` is one explicit
/// current canonical sample; original DNS TTL expirations are never recomputed.
/// Output buffers may change on error, but no partial Converted authority exists.
pub fn convert<'out, 'owner, I: Idna>(
    answer: &Matched<'_, '_>,
    hostname: &'owner str,
    now: AbsoluteTime,
    policy: Policy,
    buffers: Buffers<'out, '_, '_, I>,
) -> Result<Converted<'out, 'owner>, Failure> {
    if hostname.is_empty()
        || hostname.len() > 65535
        || hostname.as_bytes().contains(&0)
        || policy.empty_refresh == RelativeTime::ZERO
        || buffers.maximum_work == 0
    {
        return Err(Error::InvalidInput.into());
    }
    let Buffers {
        slots,
        bytes,
        name,
        text,
        idna,
        maximum_work,
    } = buffers;
    let mut writer = Writer {
        slots,
        bytes,
        count: 0,
        used: 0,
        work: maximum_work,
        earliest: None,
    };
    let mut skipped_dname = 0usize;
    for record in records(&answer.packet) {
        writer.visit()?;
        if record.kind == OPT
            || record.class != gnunet_dns::class::INTERNET
            || !same_name(record.name, answer.packet.queries[0].name)
        {
            continue;
        }
        let Some(expires) = expiration(record.expiration, now, policy.minimum_expiration) else {
            continue;
        };
        if record.kind == Type::DNAME {
            skipped_dname = skipped_dname.checked_add(1).ok_or(Error::Overflow)?;
            continue;
        }
        if record.kind == Type::NS {
            let RData::Hostname(server) = record.data else {
                return Err(Error::Malformed.into());
            };
            let mut found = false;
            for glue in records(&answer.packet) {
                writer.visit()?;
                if glue.class != gnunet_dns::class::INTERNET || !same_name(glue.name, server) {
                    continue;
                }
                let Some(glue_expires) =
                    expiration(glue.expiration, now, policy.minimum_expiration)
                else {
                    continue;
                };
                match (glue.kind, glue.data) {
                    (Type::A, RData::Raw(raw)) => {
                        let address =
                            Ipv4Addr::from(<[u8; 4]>::try_from(raw).map_err(|_| Error::Malformed)?);
                        let mut output = Text {
                            output: &mut *name,
                            used: 0,
                        };
                        write!(output, "{address}").map_err(|_| Error::Capacity)?;
                        writer.delegation(hostname, &output.output[..output.used], glue_expires)?;
                        found = true;
                    }
                    (Type::AAAA, RData::Raw(raw)) => {
                        let address = Ipv6Addr::from(
                            <[u8; 16]>::try_from(raw).map_err(|_| Error::Malformed)?,
                        );
                        let mut output = Text {
                            output: &mut *name,
                            used: 0,
                        };
                        write!(output, "{address}").map_err(|_| Error::Capacity)?;
                        writer.delegation(hostname, &output.output[..output.used], glue_expires)?;
                        found = true;
                    }
                    (Type::CNAME, RData::Hostname(target)) => {
                        let count = render_name(target, idna, text, name)?;
                        writer.delegation(hostname, &name[..count], glue_expires)?;
                        found = true;
                    }
                    _ => {}
                }
            }
            if !found {
                let count = render_name(server, idna, text, name)?;
                writer.delegation(hostname, &name[..count], expires)?;
            }
        } else if record.kind == Type::TXT {
            let RData::Raw(raw) = record.data else {
                return Err(Error::Malformed.into());
            };
            writer.txt(raw, expires)?;
        } else if let RData::Raw(raw) = record.data {
            if (record.kind == Type::A && raw.len() != 4)
                || (record.kind == Type::AAAA && raw.len() != 16)
            {
                return Err(Error::Malformed.into());
            }
            writer.raw(RecordType::new(u32::from(record.kind.0)), expires, raw)?;
        } else {
            writer.typed(record, expires)?;
        }
    }
    if writer.count == 0 && skipped_dname != 0 {
        return Err(Failure::UnsupportedOnly);
    }
    let empty = writer.count == 0;
    let refresh = match writer.earliest {
        Some(at) => at,
        None => AbsoluteTime::from_micros(
            now.as_micros()
                .saturating_add(policy.empty_refresh.as_micros()),
        ),
    };
    let summary = Summary {
        records: writer.count,
        earliest_expiry: writer.earliest,
        refresh,
        empty,
        skipped_dname,
    };
    Ok(Converted {
        owner: hostname,
        slots: &writer.slots[..writer.count],
        bytes: &writer.bytes[..writer.used],
        summary,
    })
}
