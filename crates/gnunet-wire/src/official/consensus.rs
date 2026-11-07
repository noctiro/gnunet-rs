//! Active contrib CONSENSUS IPC and old SET round-context/wrapper formats.
//! No inactive541–545 peer transport, private ACK or caller allocation is added.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;
/// Actual common prefix of an IPC join.
pub const JOIN_PREFIX: usize = 88;
/// Public application type ceiling; larger values are reserved by CONSENSUS.
pub const USER_TYPE_MAX: u16 = 0xfff0;
/// Standard outer generic SET element type.
pub const BLOCK_TYPE: u16 = 25;
/// Actual wrapper prefix, including its marker byte.
pub const ELEMENT_PREFIX: usize = 3;
/// Largest application element that fits both real SET union element carriers
/// inside one CADET application message. Local INSERT IPC capacity is separate.
pub const MAX_APPLICATION_ELEMENT_BYTES: usize =
    super::cadet::MAX_APPLICATION_MESSAGE_SIZE - super::set::UNION_ELEMENT_PREFIX - ELEMENT_PREFIX;
fn be16(b: &[u8], i: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(
        b.get(i..i + 2)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn be32(b: &[u8], i: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        b.get(i..i + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn be64(b: &[u8], i: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        b.get(i..i + 8)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn size(t: MessageType, n: usize) -> Result<usize, Error> {
    MessageHeader::from_total_size(t, n)?;
    Ok(n)
}
fn begin(o: &mut [u8], t: MessageType, n: usize) -> Result<(), Error> {
    if o.len() < n {
        return Err(Error::Capacity);
    }
    MessageHeader::from_total_size(t, n)?.encode(o)?;
    Ok(())
}
/// Original local join. Peer identity bytes and times are data, not source proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Join<'a> {
    /// Original application/session hash, independent of the derived global ID.
    pub session: [u8; 64],
    /// Original absolute UTC microseconds.
    pub start: u64,
    /// Original absolute UTC expiration, never renewed by a retry.
    pub deadline: u64,
    /// Participants, optionally omitting the actual local identity.
    pub peers: &'a [[u8; 32]],
}
/// Only normal active client requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientRequest<'a> {
    /// Join520, exactly88+32*n bytes.
    Join(Join<'a>),
    /// Insert521, exact BE16 type and opaque original payload.
    Insert {
        /// Original application type.
        element_type: u16,
        /// Opaque payload, not a private frame.
        data: &'a [u8],
    },
    /// Conclude524, exactly one header. It is not a successful consensus ACK.
    Conclude,
}
impl<'a> ClientRequest<'a> {
    /// Borrow exactly one complete standard frame; business bounds are separate.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        match f.header().message_type() {
            mt::CONSENSUS_CLIENT_JOIN => {
                let b = input.get(..JOIN_PREFIX).ok_or(Error::Truncated)?;
                let raw = &input[JOIN_PREFIX..];
                let (peers, rem) = raw.as_chunks::<32>();
                if !rem.is_empty() || usize::try_from(be32(b, 4)?).ok() != Some(peers.len()) {
                    return Err(Error::Malformed);
                }
                Ok(Self::Join(Join {
                    session: b[8..72].try_into().map_err(|_| Error::Truncated)?,
                    start: be64(b, 72)?,
                    deadline: be64(b, 80)?,
                    peers,
                }))
            }
            mt::CONSENSUS_CLIENT_INSERT => Ok(Self::Insert {
                element_type: be16(input, 4)?,
                data: input.get(6..).ok_or(Error::Truncated)?,
            }),
            mt::CONSENSUS_CLIENT_CONCLUDE if input.len() == 4 => Ok(Self::Conclude),
            _ => Err(Error::Unsupported),
        }
    }
    /// Actual standard complete frame size, checked before output mutation.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::Join(j) => {
                u32::try_from(j.peers.len()).map_err(|_| Error::TooLarge)?;
                size(
                    mt::CONSENSUS_CLIENT_JOIN,
                    j.peers
                        .len()
                        .checked_mul(32)
                        .and_then(|n| n.checked_add(JOIN_PREFIX))
                        .ok_or(Error::Overflow)?,
                )
            }
            Self::Insert { data, .. } => size(
                mt::CONSENSUS_CLIENT_INSERT,
                data.len().checked_add(6).ok_or(Error::Overflow)?,
            ),
            Self::Conclude => Ok(4),
        }
    }
    /// Encode exact source fields; unlike the C API's zero-filled INSERT omission,
    /// an explicitly supplied nonzero type is never silently discarded.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        let t = match self {
            Self::Join(_) => mt::CONSENSUS_CLIENT_JOIN,
            Self::Insert { .. } => mt::CONSENSUS_CLIENT_INSERT,
            Self::Conclude => mt::CONSENSUS_CLIENT_CONCLUDE,
        };
        begin(out, t, n)?;
        match self {
            Self::Join(j) => {
                out[4..8].copy_from_slice(&(j.peers.len() as u32).to_be_bytes());
                out[8..72].copy_from_slice(&j.session);
                out[72..80].copy_from_slice(&j.start.to_be_bytes());
                out[80..88].copy_from_slice(&j.deadline.to_be_bytes());
                for (dst, p) in out[88..n].as_chunks_mut::<32>().0.iter_mut().zip(j.peers) {
                    *dst = *p;
                }
            }
            Self::Insert { element_type, data } => {
                out[4..6].copy_from_slice(&element_type.to_be_bytes());
                out[6..n].copy_from_slice(data);
            }
            Self::Conclude => {}
        }
        Ok(n)
    }
}
/// Normal server output, with no fabricated failure/insert acknowledgement frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientResponse<'a> {
    /// Actual received523 application element.
    Element {
        /// Original BE16 application type.
        element_type: u16,
        /// Original opaque payload.
        data: &'a [u8],
    },
    /// Actual conclude525 terminal. EOF/timeouts are never substituted for it.
    Done,
}
impl<'a> ClientResponse<'a> {
    /// Decode exactly one normal server frame.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        match f.header().message_type() {
            mt::CONSENSUS_CLIENT_RECEIVED_ELEMENT => Ok(Self::Element {
                element_type: be16(input, 4)?,
                data: input.get(6..).ok_or(Error::Truncated)?,
            }),
            mt::CONSENSUS_CLIENT_CONCLUDE_DONE if input.len() == 4 => Ok(Self::Done),
            _ => Err(Error::Unsupported),
        }
    }
    /// Checked standard complete frame extent.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::Element { data, .. } => size(
                mt::CONSENSUS_CLIENT_RECEIVED_ELEMENT,
                data.len().checked_add(6).ok_or(Error::Overflow)?,
            ),
            Self::Done => Ok(4),
        }
    }
    /// Encode the real normal result only.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        begin(
            out,
            match self {
                Self::Element { .. } => mt::CONSENSUS_CLIENT_RECEIVED_ELEMENT,
                Self::Done => mt::CONSENSUS_CLIENT_CONCLUDE_DONE,
            },
            n,
        )?;
        if let Self::Element { element_type, data } = self {
            out[4..6].copy_from_slice(&element_type.to_be_bytes());
            out[6..n].copy_from_slice(data);
        }
        Ok(n)
    }
}
/// Actual16-byte message nested in old generic SET's operation request context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoundContext {
    /// Raw phase0..8. Only real network phases are authorized by the core.
    pub kind: u16,
    /// First participant in the actual cyclic canonical role ordering.
    pub peer1: i16,
    /// Second participant in the same ordering.
    pub peer2: i16,
    /// Repetition, -1 for initial all-to-all.
    pub repetition: i16,
    /// Gradecast leader, -1 for initial all-to-all.
    pub leader: i16,
    /// Original raw contested field; active C sends0 and uses wrapper markers.
    pub contested: u16,
}
impl RoundContext {
    /// Decode the exact547 context without authorizing its peer/task claims.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        if f.header().message_type() != mt::CONSENSUS_P2P_ROUND_CONTEXT || input.len() != 16 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            kind: be16(input, 4)?,
            peer1: be16(input, 6)? as i16,
            peer2: be16(input, 8)? as i16,
            repetition: be16(input, 10)? as i16,
            leader: be16(input, 12)? as i16,
            contested: be16(input, 14)?,
        })
    }
    /// Exact standard context size.
    pub const fn encoded_len(self) -> usize {
        16
    }
    /// Encode exact signed two's-complement fields in network byte order.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        begin(out, mt::CONSENSUS_P2P_ROUND_CONTEXT, 16)?;
        for (i, v) in [
            self.kind,
            self.peer1 as u16,
            self.peer2 as u16,
            self.repetition as u16,
            self.leader as u16,
            self.contested,
        ]
        .into_iter()
        .enumerate()
        {
            out[4 + 2 * i..6 + 2 * i].copy_from_slice(&v.to_be_bytes());
        }
        Ok(16)
    }
}
/// Borrowed type25 body. A nonzero marker is data, never authenticated authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Block<'a> {
    /// Real16-bit nested application block type, encoded BE16.
    pub payload_type: u16,
    /// 0 payload,1 contested,2 size; other opaque markers remain representable.
    pub marker: u8,
    /// Original bytes after the three-byte wrapper.
    pub data: &'a [u8],
}
impl<'a> Block<'a> {
    /// Borrow the full wrapper; nested validation belongs to the selected registry.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        Ok(Self {
            payload_type: be16(input, 0)?,
            marker: *input.get(2).ok_or(Error::Truncated)?,
            data: &input[3..],
        })
    }
    /// Actual body extent, independent of an outer SET frame.
    pub fn encoded_len(self) -> Result<usize, Error> {
        self.data.len().checked_add(3).ok_or(Error::Overflow)
    }
    /// Encode no host-endian promotion or private extended payload-type field.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        out[..2].copy_from_slice(&self.payload_type.to_be_bytes());
        out[2] = self.marker;
        out[3..n].copy_from_slice(self.data);
        Ok(n)
    }
    /// Exact legacy12-byte size marker fields. Sender's actual source identity
    /// must still be checked; an8-bit field cannot prove a larger participant index.
    pub fn size_marker(self) -> Result<(u64, u8), Error> {
        if self.marker != 2 || self.data.len() != 9 {
            return Err(Error::Malformed);
        }
        Ok((be64(self.data, 0)?, self.data[8]))
    }
}

#[cfg(test)]
#[path = "consensus_tests.rs"]
mod tests;
