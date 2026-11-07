//! Official active RPS contrib IPC and CADET peer messages, v0.29.1.
//!
//! The reference `src/contrib/service/rps/rps.h` defines packed frames. Peer
//! lists are borrowed without allocation, authentication or sampler claims.
//! Client sampling uses the biased stream and a separate sampler; no invented
//! request-for-N, sampler-result, ACK or END message is provided here.
//!
//! View/stream replies declare a u64 count but both reference producers and
//! consumers use htonl/ntohl. Their actual source ABI is selected explicitly by
//! [`ReplyCountProfile`](crate::official::rps::ReplyCountProfile); it is not negotiated or guessed from incoming bytes.
//! Message955 is registered upstream but its malicious handler is disabled in
//! the normal build and is deliberately absent from these normal operations.

use super::{Frame, MessageHeader, MessageType, RelativeTime, message_type as mt};
use gnunet_types::Error;

/// Exact public peer identity extent.
pub const PEER_BYTES: usize = 32;
/// Exact subgroup/CADET port hash extent.
pub const GROUP_BYTES: usize = 64;

fn prefix(input: &[u8], size: usize) -> Result<&[u8], Error> {
    input.get(..size).ok_or(Error::Truncated)
}
fn fixed(input: &[u8], size: usize) -> Result<(), Error> {
    prefix(input, size)?;
    if input.len() != size {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn u32_at(input: &[u8], at: usize) -> Result<u32, Error> {
    let bytes = input.get(at..at + 4).ok_or(Error::Truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
fn peers(input: &[u8], start: usize, count: u32) -> Result<&[[u8; PEER_BYTES]], Error> {
    let bytes = input.get(start..).ok_or(Error::Truncated)?;
    let (peers, remainder) = bytes.as_chunks::<PEER_BYTES>();
    if !remainder.is_empty() || usize::try_from(count).ok() != Some(peers.len()) {
        return Err(Error::Malformed);
    }
    Ok(peers)
}
fn size(kind: MessageType, prefix: usize, count: usize) -> Result<usize, Error> {
    u32::try_from(count).map_err(|_| Error::TooLarge)?;
    let bytes = count
        .checked_mul(PEER_BYTES)
        .and_then(|n| n.checked_add(prefix))
        .ok_or(Error::Overflow)?;
    MessageHeader::from_total_size(kind, bytes)?;
    Ok(bytes)
}
fn begin(output: &mut [u8], kind: MessageType, size: usize) -> Result<(), Error> {
    if output.len() < size {
        return Err(Error::Capacity);
    }
    MessageHeader::from_total_size(kind, size)?.encode(output)?;
    Ok(())
}
fn write_peers(output: &mut [u8], peers: &[[u8; PEER_BYTES]]) {
    for (target, peer) in output.as_chunks_mut::<PEER_BYTES>().0.iter_mut().zip(peers) {
        target.copy_from_slice(peer);
    }
}

/// Actual C platform for the htonl-assigned packed u64 reply-count field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyCountProfile {
    /// Native little endian: BE32 count followed by four zero bytes on output.
    CNativeLittle,
    /// Native big endian: four zero bytes followed by BE32 count on output.
    CNativeBig,
}
impl ReplyCountProfile {
    /// Explicit local-target ABI selection; no peer detection or wire fallback.
    #[must_use]
    pub const fn native() -> Self {
        if cfg!(target_endian = "little") {
            Self::CNativeLittle
        } else {
            Self::CNativeBig
        }
    }
    fn read(self, input: &[u8]) -> Result<u32, Error> {
        fixed(input, 8)?;
        // C converts its native u64 to the u32 argument of ntohl. The other
        // native word is ignored on input, rather than treated as a new count.
        u32_at(
            input,
            match self {
                Self::CNativeLittle => 0,
                Self::CNativeBig => 4,
            },
        )
    }
    fn write(self, count: u32) -> [u8; 8] {
        let mut bytes = [0; 8];
        let at = match self {
            Self::CNativeLittle => 0,
            Self::CNativeBig => 4,
        };
        bytes[at..at + 4].copy_from_slice(&count.to_be_bytes());
        bytes
    }
}

/// Normal RPS messages carried by the actual subgroup CADET channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerMessage<'a> {
    /// Header-only liveliness probe950; this codec proves no peer is live.
    CheckLive,
    /// Header-only push951; the sender identity comes from its actual channel.
    Push,
    /// Header-only pull request952.
    PullRequest,
    /// Pull reply953 with BE32 count and exact original peer order.
    PullReply {
        /// Borrowed identities; no implicit sorting or duplicate removal.
        peers: &'a [[u8; PEER_BYTES]],
    },
}
impl<'a> PeerMessage<'a> {
    /// Decode one complete frame, rejecting excess header-only or list bytes.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        match frame.header().message_type() {
            mt::RPS_PP_CHECK_LIVE => {
                fixed(input, 4)?;
                Ok(Self::CheckLive)
            }
            mt::RPS_PP_PUSH => {
                fixed(input, 4)?;
                Ok(Self::Push)
            }
            mt::RPS_PP_PULL_REQUEST => {
                fixed(input, 4)?;
                Ok(Self::PullRequest)
            }
            mt::RPS_PP_PULL_REPLY => Ok(Self::PullReply {
                peers: peers(input, 8, u32_at(input, 4)?)?,
            }),
            _ => Err(Error::Unsupported),
        }
    }
    /// Actual official message assignment.
    #[must_use]
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::CheckLive => mt::RPS_PP_CHECK_LIVE,
            Self::Push => mt::RPS_PP_PUSH,
            Self::PullRequest => mt::RPS_PP_PULL_REQUEST,
            Self::PullReply { .. } => mt::RPS_PP_PULL_REPLY,
        }
    }
    /// Complete bounded frame size; this does not admit a native message.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::PullReply { peers } => size(self.message_type(), 8, peers.len()),
            _ => Ok(4),
        }
    }
    /// Encode directly into caller storage; preflight failure changes no bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        begin(output, self.message_type(), size)?;
        if let Self::PullReply { peers } = self {
            output[4..8].copy_from_slice(&(peers.len() as u32).to_be_bytes());
            write_peers(&mut output[8..size], peers);
        }
        Ok(size)
    }
}

/// Normal active RPS client-to-service operations, independent of C API handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientRequest<'a> {
    /// Seed954; the service decides which actual peers enter its view/sampler.
    Seed {
        /// Original identities, with a BE32 count derived from this exact slice.
        peers: &'a [[u8; PEER_BYTES]],
    },
    /// Start subgroup956, retaining the actual packed source fields.
    SubStart {
        /// Raw ignored alignment bytes; the normal C producer emits zero.
        reserved: [u8; 4],
        /// Mean round interval in official network-order microseconds.
        round_interval: RelativeTime,
        /// Actual subgroup CADET port hash, not a shared string or integer port.
        group: [u8; GROUP_BYTES],
    },
    /// Stop subgroup957.
    SubStop {
        /// Exact subgroup hash supplied by the original caller.
        group: [u8; GROUP_BYTES],
    },
    /// Request view updates1130; zero requests an unbounded subscription.
    ViewRequest {
        /// BE32 source update count; not a sampler-result count or wire RID.
        updates: u32,
    },
    /// Header-only view cancellation1132, with no response or completion frame.
    ViewCancel,
    /// Header-only biased-stream subscription1133.
    StreamRequest,
    /// Header-only biased-stream cancellation1135.
    StreamCancel,
}
impl<'a> ClientRequest<'a> {
    /// Decode exactly one normal client frame; malicious955 remains unsupported.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        match frame.header().message_type() {
            mt::RPS_CS_SEED => Ok(Self::Seed {
                peers: peers(input, 8, u32_at(input, 4)?)?,
            }),
            mt::RPS_CS_SUB_START => {
                fixed(input, 80)?;
                Ok(Self::SubStart {
                    reserved: input[4..8].try_into().map_err(|_| Error::Truncated)?,
                    round_interval: RelativeTime::decode(&input[8..16])?,
                    group: input[16..80].try_into().map_err(|_| Error::Truncated)?,
                })
            }
            mt::RPS_CS_SUB_STOP => {
                fixed(input, 68)?;
                Ok(Self::SubStop {
                    group: input[4..68].try_into().map_err(|_| Error::Truncated)?,
                })
            }
            mt::RPS_CS_DEBUG_VIEW_REQUEST => {
                fixed(input, 8)?;
                Ok(Self::ViewRequest {
                    updates: u32_at(input, 4)?,
                })
            }
            mt::RPS_CS_DEBUG_VIEW_CANCEL => {
                fixed(input, 4)?;
                Ok(Self::ViewCancel)
            }
            mt::RPS_CS_DEBUG_STREAM_REQUEST => {
                fixed(input, 4)?;
                Ok(Self::StreamRequest)
            }
            mt::RPS_CS_DEBUG_STREAM_CANCEL => {
                fixed(input, 4)?;
                Ok(Self::StreamCancel)
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Actual official message assignment.
    #[must_use]
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::Seed { .. } => mt::RPS_CS_SEED,
            Self::SubStart { .. } => mt::RPS_CS_SUB_START,
            Self::SubStop { .. } => mt::RPS_CS_SUB_STOP,
            Self::ViewRequest { .. } => mt::RPS_CS_DEBUG_VIEW_REQUEST,
            Self::ViewCancel => mt::RPS_CS_DEBUG_VIEW_CANCEL,
            Self::StreamRequest => mt::RPS_CS_DEBUG_STREAM_REQUEST,
            Self::StreamCancel => mt::RPS_CS_DEBUG_STREAM_CANCEL,
        }
    }
    /// Complete bounded frame size, with no per-message allocation.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::Seed { peers } => size(self.message_type(), 8, peers.len()),
            Self::SubStart { .. } => Ok(80),
            Self::SubStop { .. } => Ok(68),
            Self::ViewRequest { .. } => Ok(8),
            _ => Ok(4),
        }
    }
    /// Encode directly into caller storage; capacity/size refusal is atomic.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        begin(output, self.message_type(), size)?;
        match self {
            Self::Seed { peers } => {
                output[4..8].copy_from_slice(&(peers.len() as u32).to_be_bytes());
                write_peers(&mut output[8..size], peers);
            }
            Self::SubStart {
                reserved,
                round_interval,
                group,
            } => {
                output[4..8].copy_from_slice(&reserved);
                output[8..16].copy_from_slice(&round_interval.to_be_bytes());
                output[16..80].copy_from_slice(&group);
            }
            Self::SubStop { group } => output[4..68].copy_from_slice(&group),
            Self::ViewRequest { updates } => {
                output[4..8].copy_from_slice(&updates.to_be_bytes());
            }
            Self::ViewCancel | Self::StreamRequest | Self::StreamCancel => {}
        }
        Ok(size)
    }
}

/// Service-to-client view/biased-stream batches, not uniform sampler output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientResponse<'a> {
    /// View reply1131 with packed header/id/u64-count prefix16.
    View {
        /// Raw ignored source ID; the normal C producer leaves it zero.
        id: [u8; 4],
        /// Borrowed original view order; may be empty and grants no peer liveness.
        peers: &'a [[u8; PEER_BYTES]],
    },
    /// Biased stream reply1134 with packed header/u64-count prefix12.
    Stream {
        /// Borrowed original stream order; this is input to a caller's sampler.
        peers: &'a [[u8; PEER_BYTES]],
    },
}
impl<'a> ClientResponse<'a> {
    /// Decode with the explicitly selected actual source ABI. No alternate
    /// profile is tried on mismatch; C's ignored native high count word is not
    /// interpreted as another count or protocol extension.
    pub fn decode(input: &'a [u8], profile: ReplyCountProfile) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        match frame.header().message_type() {
            mt::RPS_CS_DEBUG_VIEW_REPLY => {
                let p = prefix(input, 16)?;
                Ok(Self::View {
                    id: p[4..8].try_into().map_err(|_| Error::Truncated)?,
                    peers: peers(input, 16, profile.read(&p[8..16])?)?,
                })
            }
            mt::RPS_CS_DEBUG_STREAM_REPLY => {
                let p = prefix(input, 12)?;
                Ok(Self::Stream {
                    peers: peers(input, 12, profile.read(&p[4..12])?)?,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Actual official message assignment.
    #[must_use]
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::View { .. } => mt::RPS_CS_DEBUG_VIEW_REPLY,
            Self::Stream { .. } => mt::RPS_CS_DEBUG_STREAM_REPLY,
        }
    }
    /// Borrow the exact original identities without copying, sorting or sampling.
    #[must_use]
    pub const fn peers(self) -> &'a [[u8; PEER_BYTES]] {
        match self {
            Self::View { peers, .. } | Self::Stream { peers } => peers,
        }
    }
    /// Complete bounded frame size; no native write or completion is implied.
    pub fn encoded_len(self) -> Result<usize, Error> {
        size(
            self.message_type(),
            if matches!(self, Self::View { .. }) {
                16
            } else {
                12
            },
            self.peers().len(),
        )
    }
    /// Encode C's actual htonl-assigned count, zeroing its unused native high
    /// word as the producer does. Decoding arbitrary ignored high bytes does
    /// not make this encoder a lossless re-emitter of noncanonical raw frames.
    pub fn encode(self, output: &mut [u8], profile: ReplyCountProfile) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        begin(output, self.message_type(), size)?;
        let peers = self.peers();
        let start = match self {
            Self::View { id, .. } => {
                output[4..8].copy_from_slice(&id);
                output[8..16].copy_from_slice(&profile.write(peers.len() as u32));
                16
            }
            Self::Stream { .. } => {
                output[4..12].copy_from_slice(&profile.write(peers.len() as u32));
                12
            }
        };
        write_peers(&mut output[start..size], peers);
        Ok(size)
    }
}
