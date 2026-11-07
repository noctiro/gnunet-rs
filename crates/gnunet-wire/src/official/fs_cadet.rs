//! Official non-anonymous FS application messages carried inside CADET.
//!
//! GNUnet v0.29.1 `service/fs/gnunet-service-fs_cadet.h` defines a fixed
//! hash query and a typed, expiry-bearing encrypted-block reply. There is no
//! request identifier, negative answer, END, or per-query cancel message. A
//! missing block is silence; channel destruction is not an absence proof.
//! These codecs check layout only. They neither authenticate blocks nor make
//! local FS CLIENT metadata or native CADET delivery acknowledgements.
use super::fs::BlockType;
use super::{AbsoluteTime, Frame, MessageHeader, message_type as mt};
use gnunet_types::Error;

/// Official application-port preimage. Hash these exact bytes with GNUnet's
/// standard SHA-512, without a final NUL, before opening/creating a CADET port.
pub const PORT_LABEL: &[u8] = b"fs-block";
/// Exact CadetQueryMessage size, including its four-byte application header.
pub const QUERY_BYTES: usize = 72;
/// CadetReplyMessage prefix, including its four-byte application header.
pub const REPLY_PREFIX: usize = 16;
/// Largest block expressible by this application's BE16 total-size field.
/// Native CADET imposes its additional smaller application-message limit.
pub const MAX_WIRE_BLOCK_BYTES: usize = u16::MAX as usize - REPLY_PREFIX;

/// Original hash query. The peer target and port belong to its actual CADET
/// channel and are not duplicated as private fields in this application frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Query<'a> {
    /// Requested official block registry value. D/I are the intended transfer
    /// path; the pinned service forwards other values to DATASTORE as supplied.
    pub block_type: BlockType,
    /// Original query key, borrowing the exact complete frame or caller bytes.
    pub query: &'a [u8; 64],
}
impl<'a> Query<'a> {
    /// Decode exactly one fixed-size official FS_CADET_QUERY message.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        if frame.header().message_type() != mt::FS_CADET_QUERY {
            return Err(Error::Unsupported);
        }
        if bytes.len() != QUERY_BYTES {
            return Err(Error::Malformed);
        }
        Ok(Self {
            block_type: BlockType::new(number(bytes, 4)?),
            query: bytes[8..QUERY_BYTES]
                .try_into()
                .map_err(|_| Error::Malformed)?,
        })
    }
    /// Fixed complete message size.
    #[must_use]
    pub const fn encoded_len(self) -> usize {
        QUERY_BYTES
    }
    /// Encode the original public fields. Capacity failure changes no output.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let header = MessageHeader::from_total_size(mt::FS_CADET_QUERY, QUERY_BYTES)?;
        let out = output.get_mut(..QUERY_BYTES).ok_or(Error::Capacity)?;
        header.encode(out)?;
        out[4..8].copy_from_slice(&self.block_type.value().to_be_bytes());
        out[8..].copy_from_slice(self.query);
        Ok(QUERY_BYTES)
    }
}

/// Untrusted encrypted block reply. It contains neither the query hash nor a
/// request ID: the receiver derives the official block key from the real block,
/// then matches type/key against its still-owned channel requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reply<'a> {
    /// Actual nonzero block registry value, including future assignments.
    pub block_type: BlockType,
    /// Original content expiration, not an operation deadline or fresh lease.
    pub expiration: AbsoluteTime,
    /// Complete original block bytes. Payload authentication is a higher layer.
    pub block: &'a [u8],
}
impl<'a> Reply<'a> {
    /// Decode exactly one FS_CADET_REPLY, retaining its original payload bytes.
    /// ANY is a request wildcard and cannot identify an actual returned block.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        if frame.header().message_type() != mt::FS_CADET_REPLY {
            return Err(Error::Unsupported);
        }
        if bytes.len() < REPLY_PREFIX {
            return Err(Error::Malformed);
        }
        let block_type = BlockType::new(number(bytes, 4)?);
        if block_type == BlockType::ANY {
            return Err(Error::Malformed);
        }
        Ok(Self {
            block_type,
            expiration: AbsoluteTime::decode(&bytes[8..REPLY_PREFIX])?,
            block: &bytes[REPLY_PREFIX..],
        })
    }
    /// Check the actual returned type and complete BE16 framing capacity.
    pub fn encoded_len(self) -> Result<usize, Error> {
        if self.block_type == BlockType::ANY {
            return Err(Error::InvalidInput);
        }
        let size = REPLY_PREFIX
            .checked_add(self.block.len())
            .ok_or(Error::Overflow)?;
        MessageHeader::from_total_size(mt::FS_CADET_REPLY, size)?;
        Ok(size)
    }
    /// Encode only original reply fields; no local ClientPut fields are guessed.
    /// All validation/capacity refusals preserve the entire destination buffer.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        let header = MessageHeader::from_total_size(mt::FS_CADET_REPLY, size)?;
        let out = output.get_mut(..size).ok_or(Error::Capacity)?;
        header.encode(out)?;
        out[4..8].copy_from_slice(&self.block_type.value().to_be_bytes());
        out[8..REPLY_PREFIX].copy_from_slice(&self.expiration.to_be_bytes());
        out[REPLY_PREFIX..].copy_from_slice(self.block);
        Ok(size)
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
