//! Official GNUnet v0.29.1 FS GAP messages carried by CORE service FS/version1.
//! GET137 has optional PeerIdentity32 entries and an optional reply Bloom filter;
//! PUT138 has no request ID or query key. No negative/END/cancel is defined.
use super::{AbsoluteTime, Frame, MessageHeader, RelativeTime, fs::BlockType, message_type as mt};
use gnunet_types::Error;

/// Complete fixed GetMessage, including its query hash.
pub const GET_PREFIX: usize = 88;
/// Complete fixed PutMessage prefix.
pub const PUT_PREFIX: usize = 16;
/// Smallest bit array produced by the official FS BLOCK Bloom group.
pub const MIN_BLOOM_BYTES: usize = 8;
/// Largest bit array produced by the official FS BLOCK Bloom group.
pub const MAX_BLOOM_BYTES: usize = 1 << 15;
/// Actual optional return-to identity bit; reply may go to this connected peer.
pub const RETURN_TO: u32 = 1;
/// Actual optional preferred content-provider identity bit.
pub const TRANSMIT_TO: u32 = 4;
/// Optional identities understood by the current C handler.
pub const KNOWN_OPTIONS: u32 = RETURN_TO | TRANSMIT_TO;

/// Borrowed original GET. Codec preserves every bitmap entry, including unknown
/// future bits; an owner decides which extensions it can actually interpret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Get<'a> {
    /// Actual block registry value, including ANY/future assignments.
    pub block_type: BlockType,
    /// Actual offered priority, not a local transmission or peer-success receipt.
    pub priority: u32,
    /// Signed seconds on the actual C send/create path. The header's historical
    /// "milliseconds" comment differs from get_message(/1e6)/pr_create(*SECONDS).
    pub ttl_seconds: i32,
    /// Unused original field. Canonical new GETs set it to zero.
    pub reserved: u32,
    /// One PeerIdentity32 per set bit, in increasing bit order.
    pub bitmap: u32,
    /// Original content query, not a peer hash or request identifier.
    pub query: &'a [u8; 64],
    /// Exact optional identity bytes, including future bitmap entries.
    pub identities: &'a [u8],
    /// Empty, or the actual serialized BLOCK group: native nonce4 followed by
    /// a power-of-two bit array of8..32768 bytes. The pinned C sender emits this
    /// form; its checker incorrectly tests the whole tail for power-of-two.
    /// Normal interoperable outbound owners may omit the optional hint.
    pub bloom: &'a [u8],
}
impl<'a> Get<'a> {
    /// Decode one complete official GET, preserving all borrowed tail bytes.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        if frame.header().message_type() != mt::FS_GET {
            return Err(Error::Unsupported);
        }
        if bytes.len() < GET_PREFIX {
            return Err(Error::Malformed);
        }
        let bitmap = number(bytes, 20)?;
        let end = GET_PREFIX + bitmap.count_ones() as usize * 32;
        let identities = bytes.get(GET_PREFIX..end).ok_or(Error::Truncated)?;
        let value = Self {
            block_type: BlockType::new(number(bytes, 4)?),
            priority: number(bytes, 8)?,
            ttl_seconds: i32::from_be_bytes(
                bytes[12..16].try_into().map_err(|_| Error::Malformed)?,
            ),
            reserved: number(bytes, 16)?,
            bitmap,
            query: bytes[24..GET_PREFIX]
                .try_into()
                .map_err(|_| Error::Malformed)?,
            identities,
            bloom: &bytes[end..],
        };
        value.encoded_len()?;
        Ok(value)
    }
    /// Borrow an exact specified optional identity. Unknown bits still count.
    pub fn identity(self, bit: u32) -> Result<Option<&'a [u8; 32]>, Error> {
        if !bit.is_power_of_two() {
            return Err(Error::InvalidInput);
        }
        if self.bitmap & bit == 0 {
            return Ok(None);
        }
        let index = (self.bitmap & (bit - 1)).count_ones() as usize * 32;
        self.identities
            .get(index..index + 32)
            .ok_or(Error::Truncated)?
            .try_into()
            .map(Some)
            .map_err(|_| Error::Malformed)
    }
    /// Validate complete official shape before touching destination bytes.
    pub fn encoded_len(self) -> Result<usize, Error> {
        if self.identities.len() != self.bitmap.count_ones() as usize * 32
            || (!self.bloom.is_empty()
                && !self.bloom.len().checked_sub(4).is_some_and(|bytes| {
                    (MIN_BLOOM_BYTES..=MAX_BLOOM_BYTES).contains(&bytes) && bytes.is_power_of_two()
                }))
        {
            return Err(Error::Malformed);
        }
        let size = GET_PREFIX
            .checked_add(self.identities.len())
            .and_then(|n| n.checked_add(self.bloom.len()))
            .ok_or(Error::Overflow)?;
        MessageHeader::from_total_size(mt::FS_GET, size)?;
        Ok(size)
    }
    /// Encode exact original fields; a refusal leaves all output unchanged.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        let out = output.get_mut(..size).ok_or(Error::Capacity)?;
        MessageHeader::from_total_size(mt::FS_GET, size)?.encode(out)?;
        out[4..8].copy_from_slice(&self.block_type.value().to_be_bytes());
        out[8..12].copy_from_slice(&self.priority.to_be_bytes());
        out[12..16].copy_from_slice(&self.ttl_seconds.to_be_bytes());
        out[16..20].copy_from_slice(&self.reserved.to_be_bytes());
        out[20..24].copy_from_slice(&self.bitmap.to_be_bytes());
        out[24..GET_PREFIX].copy_from_slice(self.query);
        let end = GET_PREFIX + self.identities.len();
        out[GET_PREFIX..end].copy_from_slice(self.identities);
        out[end..].copy_from_slice(self.bloom);
        Ok(size)
    }
}
/// Actual GAP PUT. Derive the key from validated block bytes before routing it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Put<'a> {
    /// Actual returned block type; ANY/type6 are not transferable results.
    pub block_type: BlockType,
    /// Original block expiry, independent of request/operation lifetime.
    pub expiration: AbsoluteTime,
    /// Original complete block, without a query ID or reply metadata additions.
    pub block: &'a [u8],
}
impl<'a> Put<'a> {
    /// Decode exact official PUT. Actual C rejects internal type6 on this path.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        if frame.header().message_type() != mt::FS_PUT {
            return Err(Error::Unsupported);
        }
        if bytes.len() < PUT_PREFIX {
            return Err(Error::Malformed);
        }
        let value = Self {
            block_type: BlockType::new(number(bytes, 4)?),
            expiration: AbsoluteTime::decode(&bytes[8..PUT_PREFIX])?,
            block: &bytes[PUT_PREFIX..],
        };
        value.encoded_len()?;
        Ok(value)
    }
    /// Exact official frame length. Payload validation belongs to a block owner.
    pub fn encoded_len(self) -> Result<usize, Error> {
        if self.block_type == BlockType::ANY {
            return Err(Error::Malformed);
        }
        if self.block_type.value() == 6 {
            return Err(Error::Unsupported);
        }
        let size = PUT_PREFIX
            .checked_add(self.block.len())
            .ok_or(Error::Overflow)?;
        MessageHeader::from_total_size(mt::FS_PUT, size)?;
        Ok(size)
    }
    /// Encode exact original fields, after complete shape/capacity checks.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        let out = output.get_mut(..size).ok_or(Error::Capacity)?;
        MessageHeader::from_total_size(mt::FS_PUT, size)?.encode(out)?;
        out[4..8].copy_from_slice(&self.block_type.value().to_be_bytes());
        out[8..PUT_PREFIX].copy_from_slice(&self.expiration.to_be_bytes());
        out[PUT_PREFIX..].copy_from_slice(self.block);
        Ok(size)
    }
}
/// Complete official MigrationStopMessage. Its relative duration pauses only
/// unsolicited file-block migration, never solicited GAP results/queries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationStop {
    /// Original field, canonically zero.
    pub reserved: u32,
    /// Original relative microseconds, including the FOREVER sentinel.
    pub duration: RelativeTime,
}
impl MigrationStop {
    /// Decode the exact sixteen-byte official control without losing duration.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        if frame.header().message_type() != mt::FS_MIGRATION_STOP {
            return Err(Error::Unsupported);
        }
        if bytes.len() != 16 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            reserved: number(bytes, 4)?,
            duration: RelativeTime::decode(&bytes[8..16])?,
        })
    }
    /// Encode the exact control without inventing a migration result.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let out = output.get_mut(..16).ok_or(Error::Capacity)?;
        MessageHeader::from_total_size(mt::FS_MIGRATION_STOP, 16)?.encode(out)?;
        out[4..8].copy_from_slice(&self.reserved.to_be_bytes());
        out[8..16].copy_from_slice(&self.duration.to_be_bytes());
        Ok(16)
    }
}
fn number(bytes: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        bytes
            .get(at..at + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
