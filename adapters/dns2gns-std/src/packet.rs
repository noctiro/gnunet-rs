//! Bounded ordinary DNS packets and GNS observations for the DNS2GNS gateway.
//!
//! No network, allocation service, crypto, implicit IDNA backend or worker is
//! created here. A VPN plan is not an allocation; only an actual caller-supplied
//! mapping callback may replace it with an address. DNS AD follows the public
//! proxy convention, not an independent authentication receipt from this codec.
use gnunet_dns::{self as dns, AbsoluteTime, Arena, Header, Name, Packet, RData, Record};
use gnunet_gnsrecord::{RecordData, RecordSet, RecordType};
use gnunet_types::Error as Fault;
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

/// Local finite packet/work/storage ceilings, independent of native send success.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original UDP input/output payload capacity, at most the IPv4-safe65507.
    pub maximum_packet_bytes: usize,
    /// Counted DNS records or original GNS records accepted for one reply.
    pub maximum_records: usize,
    /// Aggregate serialized GNS record bytes, including record headers and
    /// opaque values but excluding padding. This is not a DNS-name limit.
    pub maximum_gns_bytes: usize,
    /// Temporary parser arena maximum; actual allocation follows bytes/counts.
    pub maximum_arena_bytes: usize,
    /// Original parser byte/pointer work budget per complete parse.
    pub maximum_work: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            maximum_packet_bytes: 65507,
            maximum_records: 2048,
            maximum_gns_bytes: 65535,
            maximum_arena_bytes: 2 * 1024 * 1024,
            maximum_work: 8 * 1024 * 1024,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Failure> {
        if !(dns::HEADER_LEN..=65507).contains(&self.maximum_packet_bytes)
            || self.maximum_records > u16::MAX as usize
            || self.maximum_gns_bytes > u16::MAX as usize
            || self.maximum_arena_bytes == 0
            || self.maximum_work == 0
        {
            return Err(Failure::Protocol(Fault::InvalidInput));
        }
        Ok(())
    }
    fn dns(self) -> dns::Limits {
        dns::Limits {
            maximum_packet_bytes: self.maximum_packet_bytes,
            maximum_queries: 1,
            maximum_records: self.maximum_records,
            maximum_work: self.maximum_work,
            ..dns::Limits::DNS
        }
    }
}

/// Structural or explicit local failure. None means an empty successful reply.
#[derive(Debug)]
pub enum Failure {
    /// Original pure DNS/record framing or resource error.
    Protocol(Fault),
    /// Query/response header does not match this ordinary request.
    Header,
    /// Original transaction identifier did not match the actual upstream request.
    Identifier,
    /// Actual datagram source differed from the original selected upstream.
    Source,
    /// Question name/type/class/opcode did not match the original query.
    Question,
    /// One known original GNS record was malformed.
    Record {
        /// Original record index.
        index: usize,
        /// Original format failure.
        cause: Fault,
    },
    /// A real VPN callback is still required before packing the response.
    PendingVpn,
    /// VPN plan or original Query belongs to a different response/request.
    Foreign,
    /// The original VPN plan was already consumed.
    AlreadyMapped,
    /// Actual mapped address has a different family from the original request.
    Family,
}
impl From<Fault> for Failure {
    fn from(error: Fault) -> Self {
        Self::Protocol(error)
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DNS2GNS packet: {self:?}")
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) | Self::Record { cause: error, .. } => Some(error),
            _ => None,
        }
    }
}

/// One original fully parsed ordinary query, retaining its exact forwarding bytes.
pub struct Query {
    domain: Arc<()>,
    raw: Vec<u8>,
    header: Header,
    name_wire: Vec<u8>,
    name: Vec<u8>,
    kind: dns::Type,
    class: u16,
}
impl fmt::Debug for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Query")
            .field("id", &self.header.id)
            .field("bytes", &self.raw.len())
            .field("kind", &self.kind)
            .field("class", &self.class)
            .finish()
    }
}
impl Query {
    /// Parse all counted input before admission. QD is checked before indexing;
    /// QR must be0 and AN/NS empty. Additional records, original opcode/class
    /// and raw trailing bytes are retained. Root is represented by `.` for the
    /// nonempty ordinary with-TLD name interface.
    pub fn parse(
        raw: &[u8],
        now: AbsoluteTime,
        limits: Limits,
        idna: &impl dns::Idna,
    ) -> Result<Self, Failure> {
        limits.validate()?;
        let header = Header::decode(raw)?;
        if header.counts.queries != 1
            || header.flags.query_or_response()
            || header.counts.answers != 0
            || header.counts.authority != 0
        {
            return Err(Failure::Header);
        }
        let (name_wire, name, kind, class) = with_packet(raw, now, limits, |packet| {
            let question = packet.queries.first().ok_or(Failure::Question)?;
            let wire = copy(question.name.wire())?;
            let name = if question.name.wire() == [0] {
                copy(b".")?
            } else {
                // UTF-8 may expand each original octet by at most four bytes.
                // This storage is based on this actual name, not a packet cap.
                let extent = wire.len().checked_mul(4).ok_or(Fault::Overflow)?;
                let mut work = filled(extent)?;
                let mut text = filled(extent)?;
                let n = question
                    .name
                    .write_native_text(idna, &mut work, &mut text)?;
                text.truncate(n);
                if text.is_empty() || text.contains(&0) {
                    return Err(Failure::Question);
                }
                text
            };
            Ok((wire, name, question.kind, question.class))
        })?;
        Ok(Self {
            domain: Arc::new(()),
            raw: copy(raw)?,
            header,
            name_wire,
            name,
            kind,
            class,
        })
    }
    /// Exact original datagram, suitable for the original DNS stub request.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Native public name bytes for with-TLD routing; never an empty root name.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// Original client transaction identifier.
    #[must_use]
    pub const fn id(&self) -> [u8; 2] {
        self.header.id
    }
    /// Original question type, unchanged even for non-query opcodes/classes.
    #[must_use]
    pub const fn kind(&self) -> dns::Type {
        self.kind
    }
    /// Original question class.
    #[must_use]
    pub const fn class(&self) -> u16 {
        self.class
    }
}

/// Address family requested from the actual VPN allocation service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// IPv4 address for an A query.
    V4,
    /// IPv6 address for an AAAA query.
    V6,
}

/// Opaque original response/slot identity. It carries no allocation authority.
#[derive(Clone)]
pub struct VpnId {
    domain: Arc<()>,
    index: usize,
}
impl PartialEq for VpnId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &other.domain) && self.index == other.index
    }
}
impl Eq for VpnId {}
impl fmt::Debug for VpnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VpnId")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}
/// Borrowed plan awaiting the actual VPN service callback. Peer/service are
/// public record claims, not independently authenticated by this packet layer.
pub struct VpnNeed<'a> {
    id: VpnId,
    peer: [u8; 32],
    protocol: u16,
    service: &'a [u8],
    family: Family,
    expiration: AbsoluteTime,
}
impl VpnNeed<'_> {
    /// Clone only this original plan token, never a replacement operation.
    #[must_use]
    pub fn id(&self) -> VpnId {
        self.id.clone()
    }
    /// Original public peer claim.
    #[must_use]
    pub const fn peer(&self) -> [u8; 32] {
        self.peer
    }
    /// Original network-decoded transport protocol.
    #[must_use]
    pub const fn protocol(&self) -> u16 {
        self.protocol
    }
    /// Exact service-name bytes without the final NUL. Hashing remains the
    /// caller's existing public descriptor operation; no algorithm is added.
    #[must_use]
    pub fn service(&self) -> &[u8] {
        self.service
    }
    /// Exact requested address family.
    #[must_use]
    pub const fn family(&self) -> Family {
        self.family
    }
    /// Original record expiration, not the native request deadline.
    #[must_use]
    pub const fn expiration(&self) -> AbsoluteTime {
        self.expiration
    }
}

enum Value {
    V4([u8; 4]),
    V6([u8; 16]),
    Cname(Vec<u8>),
    Vpn {
        peer: [u8; 32],
        protocol: u16,
        service: Vec<u8>,
        family: Family,
    },
}
struct Entry {
    expiration: AbsoluteTime,
    value: Value,
}
/// Owned bounded GNS-to-DNS plan. Pending VPN rows occupy their original answer
/// position until an actual callback supplies the matching address family.
pub struct Response {
    query: Arc<()>,
    vpn: Arc<()>,
    entries: Vec<Entry>,
    skipped: usize,
}
impl Response {
    /// Convert actual GNS service records. Canonical CNAME data is an entire
    /// uncompressed DNS name, as emitted by the public record plugin. Unlike
    /// the old proxy's C-string consumer, its first label byte is not text.
    pub fn from_gns(
        query: &Query,
        records: RecordSet<'_>,
        now: AbsoluteTime,
        limits: Limits,
    ) -> Result<Self, Failure> {
        limits.validate()?;
        if records.len() > limits.maximum_records
            || records.record_bytes().len() > limits.maximum_gns_bytes
        {
            return Err(Fault::Capacity.into());
        }
        let mut entries = Vec::new();
        let mut skipped = 0;
        for (index, record) in records.iter().enumerate() {
            let record = record?;
            let value = match record.record_type {
                RecordType::A => {
                    Value::V4(
                        <[u8; 4]>::try_from(record.data).map_err(|_| Failure::Record {
                            index,
                            cause: Fault::Malformed,
                        })?,
                    )
                }
                RecordType::AAAA => {
                    Value::V6(
                        <[u8; 16]>::try_from(record.data).map_err(|_| Failure::Record {
                            index,
                            cause: Fault::Malformed,
                        })?,
                    )
                }
                RecordType::CNAME => {
                    Name::from_wire(record.data)
                        .map_err(|cause| Failure::Record { index, cause })?;
                    Value::Cname(copy(record.data)?)
                }
                RecordType::VPN if query.kind == dns::Type::A || query.kind == dns::Type::AAAA => {
                    let data = record.data;
                    if data.len() < 35
                        || data.last() != Some(&0)
                        || data[34..data.len() - 1].contains(&0)
                    {
                        return Err(Failure::Record {
                            index,
                            cause: Fault::Malformed,
                        });
                    }
                    let service = &data[34..data.len() - 1];
                    Value::Vpn {
                        peer: data[..32].try_into().map_err(|_| Fault::Truncated)?,
                        protocol: u16::from_be_bytes([data[32], data[33]]),
                        service: copy(service)?,
                        family: if query.kind == dns::Type::A {
                            Family::V4
                        } else {
                            Family::V6
                        },
                    }
                }
                _ => {
                    skipped += 1;
                    continue;
                }
            };
            entries.try_reserve(1).map_err(|_| Fault::Capacity)?;
            entries.push(Entry {
                expiration: expiration(record, now),
                value,
            });
        }
        Ok(Self {
            query: query.domain.clone(),
            vpn: Arc::new(()),
            entries,
            skipped,
        })
    }
    /// Original source records omitted by this DNS projection. This can be
    /// nonzero with zero projected answers; it does not mean the GNS source was
    /// empty or that the omitted record types were implemented here.
    #[must_use]
    pub const fn skipped(&self) -> usize {
        self.skipped
    }
    /// Next unresolved original plan. Re-reading it does not allocate an address
    /// or authorize replaying an already admitted native VPN request.
    #[must_use]
    pub fn next_vpn(&self) -> Option<VpnNeed<'_>> {
        self.entries.iter().enumerate().find_map(|(index, entry)| {
            let Value::Vpn {
                peer,
                protocol,
                service,
                family,
            } = &entry.value
            else {
                return None;
            };
            Some(VpnNeed {
                id: VpnId {
                    domain: self.vpn.clone(),
                    index,
                },
                peer: *peer,
                protocol: *protocol,
                service,
                family: *family,
                expiration: entry.expiration,
            })
        })
    }
    /// Apply the actual original VPN callback, bounded by the original requested
    /// lease target. The native owner must first validate operation/epoch/source;
    /// an intent, metadata or local write cannot supply an address. The VPN
    /// reply itself does not prove the service's future lease holding time.
    /// DNS expiration is min(original GNS expiration, original requested lease
    /// target); the callback never starts a new lifetime.
    pub fn apply_vpn_bounded(
        &mut self,
        id: &VpnId,
        address: IpAddr,
        requested_lease_until: AbsoluteTime,
    ) -> Result<(), Failure> {
        if !Arc::ptr_eq(&self.vpn, &id.domain) {
            return Err(Failure::Foreign);
        }
        let entry = self.entries.get_mut(id.index).ok_or(Failure::Foreign)?;
        let Value::Vpn { family, .. } = &entry.value else {
            return Err(Failure::AlreadyMapped);
        };
        if !matches!(
            (*family, address),
            (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_))
        ) {
            return Err(Failure::Family);
        }
        entry.expiration = AbsoluteTime::from_micros(
            entry
                .expiration
                .as_micros()
                .min(requested_lease_until.as_micros()),
        );
        entry.value = match address {
            IpAddr::V4(ip) => Value::V4(ip.octets()),
            IpAddr::V6(ip) => Value::V6(ip.octets()),
        };
        Ok(())
    }
    /// Pack with actual section counts/TC. The original question and counted
    /// additional records are retained; no private fragmentation/TCP is added.
    /// No response is returned while any original VPN plan is unresolved.
    pub fn finish(
        self,
        query: &Query,
        now: AbsoluteTime,
        limits: Limits,
    ) -> Result<Reply, Failure> {
        limits.validate()?;
        if !Arc::ptr_eq(&self.query, &query.domain) {
            return Err(Failure::Foreign);
        }
        if self.next_vpn().is_some() {
            return Err(Failure::PendingVpn);
        }
        with_packet(query.raw(), now, limits, |original| {
            let question = original.queries.first().ok_or(Failure::Question)?;
            let mut answers = Vec::new();
            answers
                .try_reserve_exact(self.entries.len())
                .map_err(|_| Fault::Capacity)?;
            for entry in &self.entries {
                let (kind, data) = match &entry.value {
                    Value::V4(address) => (dns::Type::A, RData::Raw(address)),
                    Value::V6(address) => (dns::Type::AAAA, RData::Raw(address)),
                    Value::Cname(wire) => {
                        (dns::Type::CNAME, RData::Hostname(Name::from_wire(wire)?))
                    }
                    Value::Vpn { .. } => return Err(Failure::PendingVpn),
                };
                answers.push(Record {
                    name: question.name,
                    kind,
                    class: 1,
                    expiration: entry.expiration,
                    data,
                });
            }
            let flags = query
                .header
                .flags
                .with_query_or_response(true)
                .with_return_code(0)?
                .with_checking_disabled(false)
                .with_authenticated_data(true)
                .with_reserved_zero(false)
                .with_recursion_available(true)
                .with_message_truncated(false)
                .with_authoritative_answer(false);
            let packet = Packet::new(
                query.id(),
                flags.bits(),
                original.queries,
                &answers,
                &[],
                original.additional,
            );
            let required = packet.encoded_len()?;
            let mut bytes = filled(required.min(limits.maximum_packet_bytes))?;
            let report = packet.pack(
                now,
                &mut bytes,
                u16::try_from(limits.maximum_packet_bytes).map_err(|_| Fault::Capacity)?,
            )?;
            bytes.truncate(report.written);
            Ok(Reply {
                bytes,
                report,
                skipped: self.skipped,
            })
        })
    }
}

/// Packed bytes are ready for the original UDP send; they are not a send receipt.
pub struct Reply {
    /// Actual complete packet prefix produced by Packet::pack.
    pub bytes: Vec<u8>,
    /// Actual encoded section counts and truncation, independent of native IO.
    pub report: dns::PackReport,
    /// Unsupported GNS records omitted beside supported answers.
    pub skipped: usize,
}
impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("bytes", &self.bytes.len())
            .field("report", &self.report)
            .field("skipped", &self.skipped)
            .finish()
    }
}

/// Validate the actual selected upstream in addition to the native request
/// token checked by the caller. The expected ID is the stub's actual wire ID,
/// which may differ from the original client's ID. Restore only that original
/// ID after source/QR/opcode/complete-question validation. TC can legitimately
/// truncate its RR body; a non-TC response must parse all counted records.
pub fn validate_upstream(
    query: &Query,
    raw: &[u8],
    actual_source: SocketAddr,
    expected_source: SocketAddr,
    expected_upstream_id: [u8; 2],
    now: AbsoluteTime,
    limits: Limits,
) -> Result<Vec<u8>, Failure> {
    limits.validate()?;
    if actual_source != expected_source {
        return Err(Failure::Source);
    }
    let header = Header::decode(raw)?;
    if header.id != expected_upstream_id {
        return Err(Failure::Identifier);
    }
    if !header.flags.query_or_response() || header.counts.queries != 1 {
        return Err(Failure::Header);
    }
    if header.flags.opcode() != query.header.flags.opcode() {
        return Err(Failure::Question);
    }
    let mut storage = [0; dns::MAX_WIRE_NAME_LENGTH];
    let mut arena = Arena::new(&mut storage);
    let mut reader = dns::Reader::at(raw, dns::HEADER_LEN, raw.len(), limits.dns())?;
    let question = reader.query(&mut arena)?;
    if question.kind != query.kind
        || question.class != query.class
        || !question.name.wire().eq_ignore_ascii_case(&query.name_wire)
    {
        return Err(Failure::Question);
    }
    if !header.flags.message_truncated() {
        with_packet(raw, now, limits, |_| Ok(()))?;
    }
    let mut bytes = copy(raw)?;
    bytes[..2].copy_from_slice(&query.id());
    Ok(bytes)
}

fn expiration(record: RecordData<'_>, now: AbsoluteTime) -> AbsoluteTime {
    AbsoluteTime::from_micros(if record.has_relative_expiration() {
        now.as_micros().saturating_add(record.expiration_time)
    } else {
        record.expiration_time
    })
}
fn copy(input: &[u8]) -> Result<Vec<u8>, Failure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| Fault::Capacity)?;
    output.extend_from_slice(input);
    Ok(output)
}
fn filled(length: usize) -> Result<Vec<u8>, Failure> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| Fault::Capacity)?;
    output.resize(length, 0);
    Ok(output)
}
fn with_packet<T>(
    raw: &[u8],
    now: AbsoluteTime,
    limits: Limits,
    use_packet: impl FnOnce(Packet<'_, '_>) -> Result<T, Failure>,
) -> Result<T, Failure> {
    let header = Header::decode(raw)?;
    if raw.len() > limits.maximum_packet_bytes || header.counts.queries != 1 {
        return Err(Failure::Header);
    }
    let count = usize::from(header.counts.answers)
        .checked_add(header.counts.authority.into())
        .and_then(|n| n.checked_add(header.counts.additional.into()))
        .ok_or(Fault::Overflow)?;
    if count > limits.maximum_records {
        return Err(Fault::Capacity.into());
    }
    let minimum = count
        .checked_mul(11)
        .and_then(|n| n.checked_add(dns::HEADER_LEN + 5))
        .ok_or(Fault::Overflow)?;
    if minimum > raw.len() {
        return Err(Fault::Truncated.into());
    }
    // At most three expanded names (owner+SOA targets) per actual record.
    // All raw data/trailing bytes combined fit the original input extent.
    let names = count
        .checked_mul(3)
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_mul(dns::MAX_WIRE_NAME_LENGTH))
        .ok_or(Fault::Overflow)?;
    let extent = raw.len().checked_add(names).ok_or(Fault::Overflow)?;
    if extent > limits.maximum_arena_bytes {
        return Err(Fault::Capacity.into());
    }
    let mut storage = filled(extent)?;
    let mut arena = Arena::new(&mut storage);
    let mut questions = [dns::Query::EMPTY];
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(|_| Fault::Capacity)?;
    records.resize(count, Record::EMPTY);
    let packet = Packet::parse(
        raw,
        now,
        &mut arena,
        &mut questions,
        &mut records,
        limits.dns(),
    )?;
    use_packet(packet)
}
