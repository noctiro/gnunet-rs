//! Official v0.29.1 NAMECACHE ciphertext-block IPC. The numeric RID belongs to
//! one original connection. Cancel is local callback suppression, not a frame.
use super::{AbsoluteTime, Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;
/// Official query length: SHA512 of the carried derived public key.
pub const QUERY_LEN: usize = 64;
/// Header and request id.
pub const PREFIX: usize = 8;
/// Fixed LOOKUP and DELETE request size.
pub const QUERY_MESSAGE_LEN: usize = PREFIX + QUERY_LEN;
/// CACHE and LOOKUP response prefix, including expiration.
pub const BLOCK_PREFIX: usize = 16;
/// CACHE and DELETE response size, including signed operation result.
pub const RESULT_LEN: usize = 12;
/// Maximum ciphertext block fitting a complete official IPC frame.
pub const MAX_WIRE_BLOCK_BYTES: usize = 65535 - BLOCK_PREFIX;
/// Public namecache service API's declared maximum value size.
pub const MAX_VALUE_SIZE: usize = 63 * 1024;
/// Official GNUNET_SYSERR operation result.
pub const SYSERR: i32 = -1;
/// Official GNUNET_NO operation result.
pub const NO: i32 = 0;
/// Official GNUNET_OK / GNUNET_YES operation result.
pub const OK: i32 = 1;
fn rid(input: &[u8]) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        input
            .get(4..8)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn size(kind: MessageType, prefix: usize, body: usize) -> Result<usize, Error> {
    let n = prefix.checked_add(body).ok_or(Error::Overflow)?;
    MessageHeader::from_total_size(kind, n)?;
    Ok(n)
}
fn header(output: &mut [u8], kind: MessageType, n: usize, rid: u32) -> Result<(), Error> {
    MessageHeader::from_total_size(kind, n)?.encode(output)?;
    output[4..8].copy_from_slice(&rid.to_be_bytes());
    Ok(())
}
/// One operation on the original NAMECACHE service connection. Blocks are
/// borrowed ciphertext bytes; cryptographic/structural checking is a higher layer.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    /// Look up at most one encrypted block.
    Lookup {
        /// Original connection-local request id.
        rid: u32,
        /// Derived public-key hash.
        query: &'a [u8; QUERY_LEN],
    },
    /// Cache the complete official encrypted record block.
    Cache {
        /// Original connection-local request id.
        rid: u32,
        /// Preserved outer field. The official service ignores this value and
        /// obtains expiration from the enclosed block; its API producer sends0.
        expiration: AbsoluteTime,
        /// Complete block, including its own size/type prefix.
        block: &'a [u8],
    },
    /// Remove all stored versions under the supplied query.
    Delete {
        /// Original connection-local request id.
        rid: u32,
        /// Derived public-key hash.
        query: &'a [u8; QUERY_LEN],
    },
}
impl<'a> Request<'a> {
    /// Decode exactly one frame without allocating or interpreting block bytes.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        let id = rid(input)?;
        match frame.header().message_type() {
            mt::NAMECACHE_LOOKUP_BLOCK | mt::NAMECACHE_BLOCK_DELETE => {
                if input.len() != QUERY_MESSAGE_LEN {
                    return Err(Error::Malformed);
                }
                let query = input[PREFIX..].try_into().map_err(|_| Error::Malformed)?;
                if frame.header().message_type() == mt::NAMECACHE_LOOKUP_BLOCK {
                    Ok(Self::Lookup { rid: id, query })
                } else {
                    Ok(Self::Delete { rid: id, query })
                }
            }
            mt::NAMECACHE_BLOCK_CACHE => {
                let fixed = input.get(..BLOCK_PREFIX).ok_or(Error::Truncated)?;
                Ok(Self::Cache {
                    rid: id,
                    expiration: AbsoluteTime::decode(&fixed[8..16])?,
                    block: &input[BLOCK_PREFIX..],
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Original request id, never a process-wide generation.
    pub const fn request_id(self) -> u32 {
        match self {
            Self::Lookup { rid, .. } | Self::Cache { rid, .. } | Self::Delete { rid, .. } => rid,
        }
    }
    /// Official message type.
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::Lookup { .. } => mt::NAMECACHE_LOOKUP_BLOCK,
            Self::Cache { .. } => mt::NAMECACHE_BLOCK_CACHE,
            Self::Delete { .. } => mt::NAMECACHE_BLOCK_DELETE,
        }
    }
    /// Entire frame size, checking the BE16 limit independently of API policy.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::Cache { block, .. } => size(self.message_type(), BLOCK_PREFIX, block.len()),
            _ => Ok(QUERY_MESSAGE_LEN),
        }
    }
    /// Encode atomically with respect to invalid length or insufficient capacity.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if output.len() < n {
            return Err(Error::Capacity);
        }
        header(output, self.message_type(), n, self.request_id())?;
        match self {
            Self::Lookup { query, .. } | Self::Delete { query, .. } => {
                output[PREFIX..n].copy_from_slice(query)
            }
            Self::Cache {
                expiration, block, ..
            } => {
                output[8..16].copy_from_slice(&expiration.to_be_bytes());
                output[BLOCK_PREFIX..n].copy_from_slice(block);
            }
        }
        Ok(n)
    }
}
/// One response. The original signed result is preserved, including unknown
/// positive/negative values. A lookup has no additional ACK or stream terminator.
#[derive(Clone, Copy, Debug)]
pub enum Response<'a> {
    /// One encrypted block, or expiration0 for an unsuccessful lookup. The
    /// C client ignores any body accompanying expiration0; this codec preserves it.
    Lookup {
        /// Original operation id echoed by the service.
        rid: u32,
        /// Actual block expiration for a hit, zero for a miss.
        expiration: AbsoluteTime,
        /// Whole encrypted block, or canonical empty body for a miss.
        block: &'a [u8],
    },
    /// Actual cache-backend operation result.
    Cache {
        /// Original operation id echoed by the service.
        rid: u32,
        /// GNUNET_OK, GNUNET_NO, GNUNET_SYSERR, or a future signed result.
        result: i32,
    },
    /// Actual delete-backend operation result.
    Delete {
        /// Original operation id echoed by the service.
        rid: u32,
        /// GNUNET_OK removed, GNUNET_NO absent, GNUNET_SYSERR failure.
        result: i32,
    },
}
impl<'a> Response<'a> {
    /// Decode one complete response, retaining its exact outer expiration/body.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        let id = rid(input)?;
        match frame.header().message_type() {
            mt::NAMECACHE_LOOKUP_BLOCK_RESPONSE => {
                let fixed = input.get(..BLOCK_PREFIX).ok_or(Error::Truncated)?;
                Ok(Self::Lookup {
                    rid: id,
                    expiration: AbsoluteTime::decode(&fixed[8..16])?,
                    block: &input[BLOCK_PREFIX..],
                })
            }
            mt::NAMECACHE_BLOCK_CACHE_RESPONSE | mt::NAMECACHE_BLOCK_DELETE_RESPONSE => {
                if input.len() != RESULT_LEN {
                    return Err(Error::Malformed);
                }
                let result =
                    i32::from_be_bytes(input[8..12].try_into().map_err(|_| Error::Malformed)?);
                if frame.header().message_type() == mt::NAMECACHE_BLOCK_CACHE_RESPONSE {
                    Ok(Self::Cache { rid: id, result })
                } else {
                    Ok(Self::Delete { rid: id, result })
                }
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Echoed original request id.
    pub const fn request_id(self) -> u32 {
        match self {
            Self::Lookup { rid, .. } | Self::Cache { rid, .. } | Self::Delete { rid, .. } => rid,
        }
    }
    /// Official response message type.
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::Lookup { .. } => mt::NAMECACHE_LOOKUP_BLOCK_RESPONSE,
            Self::Cache { .. } => mt::NAMECACHE_BLOCK_CACHE_RESPONSE,
            Self::Delete { .. } => mt::NAMECACHE_BLOCK_DELETE_RESPONSE,
        }
    }
    /// Entire response frame length.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::Lookup { block, .. } => size(self.message_type(), BLOCK_PREFIX, block.len()),
            _ => Ok(RESULT_LEN),
        }
    }
    /// Encode after all capacity/length checks, preserving signed numeric results.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if output.len() < n {
            return Err(Error::Capacity);
        }
        header(output, self.message_type(), n, self.request_id())?;
        match self {
            Self::Lookup {
                expiration, block, ..
            } => {
                output[8..16].copy_from_slice(&expiration.to_be_bytes());
                output[BLOCK_PREFIX..n].copy_from_slice(block);
            }
            Self::Cache { result, .. } | Self::Delete { result, .. } => {
                output[8..12].copy_from_slice(&result.to_be_bytes())
            }
        }
        Ok(n)
    }
}
