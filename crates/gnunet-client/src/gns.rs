//! Official GNS lookup IPC and bounded original-query ownership.
//!
//! Record replies are structural observations from the selected GNS service.
//! Zone authentication, recursion and encrypted-block verification belong to
//! that service; a client write is not a successful name resolution.
use gnunet_gnsrecord::{RecordData, RecordSet, RecordType, ZONE_WIRE_LEN, ZoneKey};
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader, message_type};
mod owner;
pub use owner::{AttemptId, Client, Epoch, Instance, Outbound, QueryId, Received};

/// Pinned public service's name extent limit, excluding the terminating NUL.
pub const MAX_NAME_BYTES: usize = 252;
/// Official lookup header before typed zone and terminated name.
pub const LOOKUP_HEADER_LEN: usize = 20;
/// Official reply header before the serialized record set.
pub const RESULT_HEADER_LEN: usize = 12;

/// Four unchanged ID bytes echoed by the service. Zero is a legal ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireId(pub [u8; 4]);
impl WireId {
    /// Encode the ordinary public C API's network-order request counter.
    #[must_use]
    pub const fn from_counter(value: u32) -> Self {
        Self(value.to_be_bytes())
    }
}
/// Local lookup policy, preserving unknown signed-field bits on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalOptions(u16);
impl LocalOptions {
    /// Resolve through local namecache and DHT.
    pub const DEFAULT: Self = Self(0);
    /// Resolve only through local namecache.
    pub const NO_DHT: Self = Self(1);
    /// Require the first zone lookup locally; subsequent authorities may use DHT.
    pub const LOCAL_MASTER: Self = Self(2);
    /// Preserve all sixteen wire bits without inventing flag combinations.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }
    /// Complete uninterpreted wire representation.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
}
/// Original lookup semantics, independent of its logical ID and physical MQ.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    /// Explicit starting public zone.
    pub zone: ZoneKey,
    /// Original local lookup policy.
    pub options: LocalOptions,
    /// Maximum further GNS authority traversals.
    pub recursion_depth: u16,
    /// Full DNS/GNS record type, including extension values.
    pub record_type: RecordType,
}
/// Borrowed official type500 request, without casefolding or normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lookup<'a> {
    id: WireId,
    parameters: Parameters,
    name: &'a [u8],
}
impl<'a> Lookup<'a> {
    /// Validate a terminated-name-compatible request in the pinned service profile.
    /// UTF-8 interpretation and label normalization remain service decisions.
    pub fn new(id: WireId, parameters: Parameters, name: &'a [u8]) -> Result<Self, Error> {
        if name.len() > MAX_NAME_BYTES {
            return Err(Error::TooLarge);
        }
        if name.contains(&0) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            id,
            parameters,
            name,
        })
    }
    /// Parse one complete original request with checked zone/name extents.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(bytes)?;
        if f.header().message_type() != message_type::GNS_LOOKUP {
            return Err(Error::Unsupported);
        }
        let fixed = bytes.get(..LOOKUP_HEADER_LEN).ok_or(Error::Truncated)?;
        let key_len = usize::try_from(u32::from_be_bytes(
            fixed[16..20].try_into().map_err(|_| Error::Truncated)?,
        ))
        .map_err(|_| Error::TooLarge)?;
        let name_start = LOOKUP_HEADER_LEN
            .checked_add(key_len)
            .ok_or(Error::Overflow)?;
        let zone_bytes = bytes
            .get(LOOKUP_HEADER_LEN..name_start)
            .ok_or(Error::Truncated)?;
        let name = bytes.get(name_start..).ok_or(Error::Truncated)?;
        if name.last() != Some(&0) {
            return Err(Error::Malformed);
        }
        let name = &name[..name.len() - 1];
        let parameters = Parameters {
            zone: ZoneKey::from_wire(zone_bytes)?,
            options: LocalOptions::from_bits(u16::from_be_bytes([fixed[8], fixed[9]])),
            recursion_depth: u16::from_be_bytes([fixed[10], fixed[11]]),
            record_type: RecordType::new(u32::from_be_bytes(
                fixed[12..16].try_into().map_err(|_| Error::Truncated)?,
            )),
        };
        Self::new(
            WireId(fixed[4..8].try_into().map_err(|_| Error::Truncated)?),
            parameters,
            name,
        )
    }
    /// Original exact request ID.
    #[must_use]
    pub const fn id(self) -> WireId {
        self.id
    }
    /// Original lookup semantics.
    #[must_use]
    pub const fn parameters(self) -> Parameters {
        self.parameters
    }
    /// Original name bytes, excluding its final NUL.
    #[must_use]
    pub const fn name(self) -> &'a [u8] {
        self.name
    }
    /// Exact immutable frame length.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        LOOKUP_HEADER_LEN + ZONE_WIRE_LEN + self.name.len() + 1
    }
    /// Encode without modifying output on refusal.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len();
        let header = MessageHeader::from_total_size(message_type::GNS_LOOKUP, n)?;
        if output.len() < n {
            return Err(Error::Capacity);
        }
        header.encode(output)?;
        output[4..8].copy_from_slice(&self.id.0);
        output[8..10].copy_from_slice(&self.parameters.options.bits().to_be_bytes());
        output[10..12].copy_from_slice(&self.parameters.recursion_depth.to_be_bytes());
        output[12..16].copy_from_slice(&self.parameters.record_type.value().to_be_bytes());
        output[16..20].copy_from_slice(&(ZONE_WIRE_LEN as u32).to_be_bytes());
        output[20..20 + ZONE_WIRE_LEN].copy_from_slice(&self.parameters.zone.to_wire());
        output[20 + ZONE_WIRE_LEN..n - 1].copy_from_slice(self.name);
        output[n - 1] = 0;
        Ok(n)
    }
}
/// Structurally validated type501 reply. Records are not authenticated here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupResult<'a> {
    id: WireId,
    records: RecordSet<'a>,
}
impl<'a> LookupResult<'a> {
    /// Validate every record and the zero padding within the explicit record budget.
    pub fn decode(bytes: &'a [u8], maximum_records: usize) -> Result<Self, Error> {
        let f = Frame::decode(bytes)?;
        if f.header().message_type() != message_type::GNS_LOOKUP_RESULT {
            return Err(Error::Unsupported);
        }
        let fixed = bytes.get(..RESULT_HEADER_LEN).ok_or(Error::Truncated)?;
        let count = usize::try_from(u32::from_be_bytes(
            fixed[8..12].try_into().map_err(|_| Error::Truncated)?,
        ))
        .map_err(|_| Error::TooLarge)?;
        let records = RecordSet::parse(&bytes[RESULT_HEADER_LEN..], count, maximum_records)?;
        Ok(Self {
            id: WireId(fixed[4..8].try_into().map_err(|_| Error::Truncated)?),
            records,
        })
    }
    /// Original unchanged echoed request ID.
    #[must_use]
    pub const fn id(self) -> WireId {
        self.id
    }
    /// Borrowed record set; zero records is the protocol's empty result.
    #[must_use]
    pub const fn records(self) -> RecordSet<'a> {
        self.records
    }
}
/// Encode the official canonical reply padding, leaving output intact on refusal.
pub fn encode_result(
    id: WireId,
    records: &[RecordData<'_>],
    output: &mut [u8],
) -> Result<usize, Error> {
    let body = gnunet_gnsrecord::serialized_len(records)?;
    let n = RESULT_HEADER_LEN.checked_add(body).ok_or(Error::Overflow)?;
    let header = MessageHeader::from_total_size(message_type::GNS_LOOKUP_RESULT, n)?;
    let count = u32::try_from(records.len()).map_err(|_| Error::TooLarge)?;
    if output.len() < n {
        return Err(Error::Capacity);
    }
    header.encode(output)?;
    output[4..8].copy_from_slice(&id.0);
    output[8..12].copy_from_slice(&count.to_be_bytes());
    gnunet_gnsrecord::serialize(records, &mut output[RESULT_HEADER_LEN..n])?;
    Ok(n)
}
