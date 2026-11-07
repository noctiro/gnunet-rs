//! Official R5N P2P GET, PUT and RESULT byte layouts.
//!
//! Source baseline: v0.29.1 `src/service/dht/dht.h:428` (PUT),
//! `gnunet-service-dht_neighbours.c:111,168` (RESULT/GET), and its
//! `check_dht_p2p_*` handlers at lines 1942, 2445 and 2758.
//! `gnunet_dht_service.h:88,166` defines route bits and 96-byte path entries.
//! This module checks framing and metadata bounds. Expiration, path signatures,
//! Bloom-filter operations, block validation and routing belong to their owners.
/// Official local DHT application and monitor IPC.
pub mod ipc;
use super::{AbsoluteTime, Frame, MessageHeader, message_type};
mod cursor;
use cursor::{Reader, Writer};
use gnunet_types::Error;

/// Peer-identity Bloom filter bytes, `src/service/dht/dht.h:34`.
pub const PEER_BLOOM_LEN: usize = 128;
/// One path entry: 64-byte EdDSA signature followed by the 32-byte signer identity.
pub const PATH_ELEMENT_LEN: usize = 96;
/// Fixed GET frame bytes, including the common header.
pub const GET_FIXED_LEN: usize = 208;
/// Fixed PUT frame bytes, including the common header.
pub const PUT_FIXED_LEN: usize = 216;
/// Fixed RESULT frame bytes, including the common header.
pub const RESULT_FIXED_LEN: usize = 88;

/// Route-option bit field. Unknown bits are retained, as in the reference wire handlers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteOptions(u16);
impl RouteOptions {
    /// Default routing behavior.
    pub const NONE: Self = Self(0);
    /// Process the query at each visited peer.
    pub const DEMULTIPLEX_EVERYWHERE: Self = Self(1);
    /// Carry signed route metadata.
    pub const RECORD_ROUTE: Self = Self(2);
    /// Permit approximate results.
    pub const FIND_APPROXIMATE: Self = Self(4);
    /// The message includes a truncated-path predecessor identity.
    pub const TRUNCATED: Self = Self(8);
    /// Reference monitor's internal last-hop bit; not an instruction to route a wire message.
    pub const LAST_HOP: Self = Self(32768);
    /// Preserve an uninterpreted route bit field without imposing a private registry.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }
    /// Host-order route bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
    /// Whether all specified bits are present.
    #[must_use]
    pub const fn contains(self, option: Self) -> bool {
        self.0 & option.0 == option.0
    }
}
impl core::ops::BitOr for RouteOptions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// A borrowed path whose byte length is exactly divisible by the official entry size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Path<'a>(&'a [u8]);
impl<'a> Path<'a> {
    /// Validate an externally owned serialized path; no signatures are verified here.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        if !bytes.len().is_multiple_of(PATH_ELEMENT_LEN) {
            return Err(Error::InvalidInput);
        }
        if bytes.len() / PATH_ELEMENT_LEN > usize::from(u16::MAX) {
            return Err(Error::TooLarge);
        }
        Ok(Self(bytes))
    }
    /// An empty path.
    #[must_use]
    pub const fn empty() -> Self {
        Self(&[])
    }
    /// Number of entries, rather than bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.0.len() / PATH_ELEMENT_LEN
    }
    /// Whether the path contains no entries.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }
    /// Canonical serialized path bytes.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
    /// Iterate the exact borrowed signature/predecessor pairs.
    pub fn elements(self) -> impl ExactSizeIterator<Item = PathElement<'a>> + DoubleEndedIterator {
        self.0
            .as_chunks::<PATH_ELEMENT_LEN>()
            .0
            .iter()
            .map(|bytes| PathElement { bytes })
    }
}

/// One structurally validated path element; its signature remains untrusted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathElement<'a> {
    bytes: &'a [u8],
}
impl<'a> PathElement<'a> {
    /// Exactly 64 bytes of EdDSA signature.
    #[must_use]
    pub fn signature(self) -> &'a [u8] {
        &self.bytes[..64]
    }
    /// Exactly 32 bytes of the recorded signer identity.
    /// The legacy C field is named `pred`; its actual verifier uses it as the
    /// signing public key and obtains the predecessor from the previous entry.
    #[must_use]
    pub fn predecessor(self) -> &'a [u8] {
        &self.bytes[64..]
    }
}

/// Official DHT GET, with independently borrowed result filter and extended query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetMessage<'a> {
    /// Official 32-bit block type; zero requests any block type.
    pub block_type: u32,
    /// Original route bits, including unknown assignments.
    pub options: RouteOptions,
    /// Number of already traversed hops.
    pub hop_count: u16,
    /// Desired replication level.
    pub desired_replication_level: u16,
    /// Fixed peer-identity Bloom filter.
    pub peer_bloom: &'a [u8; PEER_BLOOM_LEN],
    /// Requested 512-bit key.
    pub key: &'a [u8; 64],
    /// Variable result Bloom filter; its length is an explicit BE16 field.
    pub result_filter: &'a [u8],
    /// Remaining plugin-specific extended query.
    pub extended_query: &'a [u8],
}
impl<'a> GetMessage<'a> {
    /// Decode exactly one official GET frame, including its size/type header.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        Self::from_frame(Frame::decode(input)?)
    }
    /// Decode an already framed message without copying payload bytes.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, Error> {
        if frame.header().message_type() != message_type::DHT_P2P_GET {
            return Err(Error::Unsupported);
        }
        let mut reader = Reader::new(frame.payload());
        let block_type = reader.u32()?;
        let options = RouteOptions::from_bits(reader.u16()?);
        let hop_count = reader.u16()?;
        let desired_replication_level = reader.u16()?;
        let result_filter_size = usize::from(reader.u16()?);
        let peer_bloom = array(&mut reader)?;
        let key = array(&mut reader)?;
        let result_filter = reader.take(result_filter_size)?;
        let extended_query = reader.take(reader.remaining())?;
        Ok(Self {
            block_type,
            options,
            hop_count,
            desired_replication_level,
            peer_bloom,
            key,
            result_filter,
            extended_query,
        })
    }
    /// Check all variable lengths before exposing an encoded-size quote.
    pub fn encoded_len(self) -> Result<usize, Error> {
        u16::try_from(self.result_filter.len()).map_err(|_| Error::TooLarge)?;
        total_len(GET_FIXED_LEN, &[self.result_filter, self.extended_query])
    }
    /// Encode after validating every length; refusal leaves output unchanged.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        let mut writer = start(output, size, message_type::DHT_P2P_GET)?;
        writer.u32(self.block_type)?;
        writer.u16(self.options.bits())?;
        writer.u16(self.hop_count)?;
        writer.u16(self.desired_replication_level)?;
        writer.u16(u16::try_from(self.result_filter.len()).map_err(|_| Error::TooLarge)?)?;
        writer.put(self.peer_bloom)?;
        writer.put(self.key)?;
        writer.put(self.result_filter)?;
        writer.put(self.extended_query)?;
        Ok(size)
    }
}

/// Official DHT PUT. Payload and path signatures are untrusted until separately validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PutMessage<'a> {
    /// Official nonzero 32-bit content type.
    pub block_type: u32,
    /// Message route flags.
    pub options: RouteOptions,
    /// Number of already traversed hops.
    pub hop_count: u16,
    /// Desired replication level.
    pub desired_replication_level: u16,
    /// Expiration in absolute microseconds.
    pub expiration: AbsoluteTime,
    /// Fixed peer-identity Bloom filter.
    pub peer_bloom: &'a [u8; PEER_BLOOM_LEN],
    /// Storage key.
    pub key: &'a [u8; 64],
    /// Present exactly when TRUNCATED is set.
    pub truncated_peer: Option<&'a [u8; 32]>,
    /// Signed path entries in the reference signature/identity ordering.
    pub put_path: Path<'a>,
    /// Present exactly when RECORD_ROUTE is set.
    pub sender_signature: Option<&'a [u8; 64]>,
    /// Block bytes, whose validation is delegated to the content-type owner.
    pub payload: &'a [u8],
}
impl<'a> PutMessage<'a> {
    /// Decode exactly one official PUT frame.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        Self::from_frame(Frame::decode(input)?)
    }
    /// Parse borrowed framing; matches the reference handler's variable-field ordering.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, Error> {
        if frame.header().message_type() != message_type::DHT_P2P_PUT {
            return Err(Error::Unsupported);
        }
        let mut reader = Reader::new(frame.payload());
        let block_type = reader.u32()?;
        if block_type == 0 {
            return Err(Error::InvalidInput);
        }
        let options = RouteOptions::from_bits(reader.u16()?);
        let hop_count = reader.u16()?;
        let desired_replication_level = reader.u16()?;
        let put_path_len = usize::from(reader.u16()?);
        let expiration = AbsoluteTime::from_micros(reader.u64()?);
        let peer_bloom = array(&mut reader)?;
        let key = array(&mut reader)?;
        let truncated_peer = read_truncated(options, &mut reader)?;
        let put_path = read_path(put_path_len, &mut reader)?;
        let sender_signature = read_signature(options, &mut reader)?;
        let payload = reader.take(reader.remaining())?;
        Ok(Self {
            block_type,
            options,
            hop_count,
            desired_replication_level,
            expiration,
            peer_bloom,
            key,
            truncated_peer,
            put_path,
            sender_signature,
            payload,
        })
    }
    /// Validate block type, flag-dependent fields and total BE16 frame size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        if self.block_type == 0 {
            return Err(Error::InvalidInput);
        }
        validate_metadata(self.options, self.truncated_peer, self.sender_signature)?;
        total_len(
            PUT_FIXED_LEN,
            &[
                self.truncated_peer.map_or(&[][..], |p| &p[..]),
                self.put_path.as_bytes(),
                self.sender_signature.map_or(&[][..], |s| &s[..]),
                self.payload,
            ],
        )
    }
    /// Encode complete official bytes, without an extra native envelope.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        let mut writer = start(output, size, message_type::DHT_P2P_PUT)?;
        writer.u32(self.block_type)?;
        writer.u16(self.options.bits())?;
        writer.u16(self.hop_count)?;
        writer.u16(self.desired_replication_level)?;
        writer.u16(u16::try_from(self.put_path.len()).map_err(|_| Error::TooLarge)?)?;
        writer.u64(self.expiration.as_micros())?;
        writer.put(self.peer_bloom)?;
        writer.put(self.key)?;
        write_metadata(
            &mut writer,
            self.truncated_peer,
            self.put_path,
            self.sender_signature,
        )?;
        writer.put(self.payload)?;
        Ok(size)
    }
}

/// Official DHT RESULT, with separate PUT/GET paths and no private request identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultMessage<'a> {
    /// Official 32-bit content type.
    pub block_type: u32,
    /// Original opaque16-bit reserved field. Originators set zero; forwarding
    /// preserves its complete value even when nonzero.
    pub reserved: u16,
    /// Route flags.
    pub options: RouteOptions,
    /// Expiration in absolute microseconds.
    pub expiration: AbsoluteTime,
    /// Requested query key.
    pub key: &'a [u8; 64],
    /// Present exactly when TRUNCATED is set.
    pub truncated_peer: Option<&'a [u8; 32]>,
    /// Route before storing the block.
    pub put_path: Path<'a>,
    /// Return-route entries collected by the GET.
    pub get_path: Path<'a>,
    /// Present exactly when RECORD_ROUTE is set.
    pub sender_signature: Option<&'a [u8; 64]>,
    /// Block bytes.
    pub payload: &'a [u8],
}
impl<'a> ResultMessage<'a> {
    /// Decode exactly one official RESULT frame, retaining its opaque reserved field.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        Self::from_frame(Frame::decode(input)?)
    }
    /// Parse an already framed result without authenticating block or path signatures.
    pub fn from_frame(frame: Frame<'a>) -> Result<Self, Error> {
        if frame.header().message_type() != message_type::DHT_P2P_RESULT {
            return Err(Error::Unsupported);
        }
        let mut reader = Reader::new(frame.payload());
        let block_type = reader.u32()?;
        let reserved = reader.u16()?;
        let options = RouteOptions::from_bits(reader.u16()?);
        let put_len = usize::from(reader.u16()?);
        let get_len = usize::from(reader.u16()?);
        let expiration = AbsoluteTime::from_micros(reader.u64()?);
        let key = array(&mut reader)?;
        let truncated_peer = read_truncated(options, &mut reader)?;
        let put_path = read_path(put_len, &mut reader)?;
        let get_path = read_path(get_len, &mut reader)?;
        let sender_signature = read_signature(options, &mut reader)?;
        let payload = reader.take(reader.remaining())?;
        Ok(Self {
            block_type,
            reserved,
            options,
            expiration,
            key,
            truncated_peer,
            put_path,
            get_path,
            sender_signature,
            payload,
        })
    }
    /// Validate flag-dependent metadata and total encoded frame size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        validate_metadata(self.options, self.truncated_peer, self.sender_signature)?;
        total_len(
            RESULT_FIXED_LEN,
            &[
                self.truncated_peer.map_or(&[][..], |p| &p[..]),
                self.put_path.as_bytes(),
                self.get_path.as_bytes(),
                self.sender_signature.map_or(&[][..], |s| &s[..]),
                self.payload,
            ],
        )
    }
    /// Encode the original field ordering and unchanged reserved field.
    /// New result originators must supply zero explicitly.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        let mut writer = start(output, size, message_type::DHT_P2P_RESULT)?;
        writer.u32(self.block_type)?;
        writer.u16(self.reserved)?;
        writer.u16(self.options.bits())?;
        writer.u16(u16::try_from(self.put_path.len()).map_err(|_| Error::TooLarge)?)?;
        writer.u16(u16::try_from(self.get_path.len()).map_err(|_| Error::TooLarge)?)?;
        writer.u64(self.expiration.as_micros())?;
        writer.put(self.key)?;
        if let Some(peer) = self.truncated_peer {
            writer.put(peer)?;
        }
        writer.put(self.put_path.as_bytes())?;
        writer.put(self.get_path.as_bytes())?;
        if let Some(signature) = self.sender_signature {
            writer.put(signature)?;
        }
        writer.put(self.payload)?;
        Ok(size)
    }
}

fn array<'a, const N: usize>(reader: &mut Reader<'a>) -> Result<&'a [u8; N], Error> {
    reader.take(N)?.try_into().map_err(|_| Error::Truncated)
}
fn read_path<'a>(count: usize, reader: &mut Reader<'a>) -> Result<Path<'a>, Error> {
    Path::new(reader.take(count.checked_mul(PATH_ELEMENT_LEN).ok_or(Error::Overflow)?)?)
}
fn read_truncated<'a>(
    options: RouteOptions,
    reader: &mut Reader<'a>,
) -> Result<Option<&'a [u8; 32]>, Error> {
    if options.contains(RouteOptions::TRUNCATED) {
        array(reader).map(Some)
    } else {
        Ok(None)
    }
}
fn read_signature<'a>(
    options: RouteOptions,
    reader: &mut Reader<'a>,
) -> Result<Option<&'a [u8; 64]>, Error> {
    if options.contains(RouteOptions::RECORD_ROUTE) {
        array(reader).map(Some)
    } else {
        Ok(None)
    }
}
fn validate_metadata(
    options: RouteOptions,
    truncated_peer: Option<&[u8; 32]>,
    signature: Option<&[u8; 64]>,
) -> Result<(), Error> {
    if options.contains(RouteOptions::TRUNCATED) != truncated_peer.is_some()
        || options.contains(RouteOptions::RECORD_ROUTE) != signature.is_some()
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn write_metadata(
    writer: &mut Writer<'_>,
    truncated_peer: Option<&[u8; 32]>,
    path: Path<'_>,
    signature: Option<&[u8; 64]>,
) -> Result<(), Error> {
    if let Some(peer) = truncated_peer {
        writer.put(peer)?;
    }
    writer.put(path.as_bytes())?;
    if let Some(signature) = signature {
        writer.put(signature)?;
    }
    Ok(())
}
fn total_len(fixed: usize, fields: &[&[u8]]) -> Result<usize, Error> {
    let mut size = fixed;
    for field in fields {
        size = size.checked_add(field.len()).ok_or(Error::Overflow)?;
    }
    MessageHeader::from_total_size(message_type::DHT_P2P_GET, size)?;
    Ok(size)
}
fn start(output: &mut [u8], size: usize, kind: super::MessageType) -> Result<Writer<'_>, Error> {
    if output.len() < size {
        return Err(Error::Capacity);
    }
    MessageHeader::from_total_size(kind, size)?.encode(output)?;
    Ok(Writer::new(&mut output[super::HEADER_LEN..size]))
}

/// Official CORE158 wrapper around one original complete DHT network frame.
/// The outer frame grants no authentication or routing authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreEnvelope<'a> {
    inner: &'a [u8],
}
impl<'a> CoreEnvelope<'a> {
    /// Validate one complete inner frame; no private fields are inserted.
    pub fn new(inner: &'a [u8]) -> Result<Self, Error> {
        Frame::decode(inner)?;
        total_len(4, &[inner])?;
        Ok(Self { inner })
    }
    /// Decode exactly one outer wrapper and its complete inner frame.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        if frame.header().message_type() != message_type::DHT_CORE {
            return Err(Error::Unsupported);
        }
        Self::new(frame.payload())
    }
    /// Original complete DHT network frame.
    #[must_use]
    pub const fn inner(self) -> &'a [u8] {
        self.inner
    }
    /// Outer size includes its four-byte official header.
    pub fn encoded_len(self) -> Result<usize, Error> {
        total_len(4, &[self.inner])
    }
    /// Encode only after full validation, preserving original bytes exactly.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        let mut writer = start(output, size, message_type::DHT_CORE)?;
        writer.put(self.inner)?;
        Ok(size)
    }
}
