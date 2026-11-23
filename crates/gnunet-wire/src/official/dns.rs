//! Official DNS interception IPC. Request IDs are opaque eight-byte echoes.
//! This protocol is distinct from the outbound DNSSTUB UDP API.
use super::{Frame, MessageHeader, message_type as mt};
use gnunet_types::Error;
/// Intercept monitoring before resolution.
pub const REQUEST_MONITOR: u32 = 1;
/// Intercept unresolved requests.
pub const PRE_RESOLUTION: u32 = 2;
/// Intercept resolved responses for transformation.
pub const POST_RESOLUTION: u32 = 4;
/// Monitor the final response.
pub const RESPONSE_MONITOR: u32 = 8;

const REPLY_HEADER_BYTES: usize = 16;

/// Maximum answer payload within one official DNS client reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyLimit(usize);

impl ReplyLimit {
    /// The largest answer representable in an official DNS client frame.
    pub const MAXIMUM: Self = Self(u16::MAX as usize - REPLY_HEADER_BYTES);

    /// Derive the payload limit from the allowed complete reply frame size.
    ///
    /// # Errors
    /// Refuses a frame cap outside the wire range or a budget too small to send
    /// a drop or forward decision.
    pub fn from_frame_bytes(frame_bytes: usize) -> Result<Self, Error> {
        if !(REPLY_HEADER_BYTES..=usize::from(u16::MAX)).contains(&frame_bytes) {
            return Err(Error::InvalidInput);
        }
        Ok(Self(frame_bytes - REPLY_HEADER_BYTES))
    }

    /// Maximum DNS payload bytes without the fixed reply header.
    #[must_use]
    pub const fn answer_bytes(self) -> usize {
        self.0
    }
}
/// Official reply decision on one original service request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision<'a> {
    /// Drop this intercepted request.
    Drop,
    /// Forward the original packet unchanged.
    Forward,
    /// Replace it with exactly these DNS payload bytes, without UDP headers.
    Answer(&'a [u8]),
}
/// Client-to-service messages. No cancellation/ACK/RID allocation command exists.
#[derive(Clone, Copy, Debug)]
pub enum Request<'a> {
    /// Subscribe on this original MQ. Whole-write is not service acceptance.
    Init {
        /// Official flags bit mask.
        flags: u32,
    },
    /// Resolve one original callback, using its opaque request identifier.
    Reply {
        /// Exact unmodified service identifier.
        id: [u8; 8],
        /// Real business decision.
        decision: Decision<'a>,
    },
}
impl<'a> Request<'a> {
    /// Decode a complete checked message, borrowing DNS bytes.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        match frame.header().message_type() {
            mt::DNS_CLIENT_INIT if input.len() == 8 => Ok(Self::Init {
                flags: u32::from_be_bytes(input[4..8].try_into().map_err(|_| Error::Truncated)?),
            }),
            mt::DNS_CLIENT_RESPONSE => {
                let fixed = input.get(..REPLY_HEADER_BYTES).ok_or(Error::Truncated)?;
                let id = fixed[8..].try_into().map_err(|_| Error::Truncated)?;
                let decision =
                    match u32::from_be_bytes(fixed[4..8].try_into().map_err(|_| Error::Truncated)?)
                    {
                        0 if input.len() == REPLY_HEADER_BYTES => Decision::Drop,
                        1 if input.len() == REPLY_HEADER_BYTES => Decision::Forward,
                        2 => Decision::Answer(&input[REPLY_HEADER_BYTES..]),
                        _ => return Err(Error::Malformed),
                    };
                Ok(Self::Reply { id, decision })
            }
            mt::DNS_CLIENT_INIT => Err(Error::Malformed),
            _ => Err(Error::Unsupported),
        }
    }
    /// Complete official frame size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let n = match self {
            Self::Init { .. } => 8,
            Self::Reply {
                decision: Decision::Answer(dns),
                ..
            } => REPLY_HEADER_BYTES
                .checked_add(dns.len())
                .ok_or(Error::Overflow)?,
            Self::Reply { .. } => REPLY_HEADER_BYTES,
        };
        MessageHeader::from_total_size(
            match self {
                Self::Init { .. } => mt::DNS_CLIENT_INIT,
                _ => mt::DNS_CLIENT_RESPONSE,
            },
            n,
        )?;
        Ok(n)
    }
    /// Preflight before modifying caller output.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        let kind = match self {
            Self::Init { .. } => mt::DNS_CLIENT_INIT,
            _ => mt::DNS_CLIENT_RESPONSE,
        };
        MessageHeader::from_total_size(kind, n)?.encode(out)?;
        match self {
            Self::Init { flags } => out[4..8].copy_from_slice(&flags.to_be_bytes()),
            Self::Reply { id, decision } => {
                let code: u32 = match decision {
                    Decision::Drop => 0,
                    Decision::Forward => 1,
                    Decision::Answer(_) => 2,
                };
                out[4..8].copy_from_slice(&code.to_be_bytes());
                out[8..REPLY_HEADER_BYTES].copy_from_slice(&id);
                if let Decision::Answer(dns) = decision {
                    out[REPLY_HEADER_BYTES..n].copy_from_slice(dns)
                }
            }
        }
        Ok(n)
    }
}
/// One intercepted request, whose ID belongs only to its original physical MQ.
#[derive(Clone, Copy, Debug)]
pub struct Response<'a> {
    /// Exact service opaque ID; it has no client-defined numeric byte order.
    pub id: [u8; 8],
    /// Original DNS datagram payload, without UDP headers.
    pub dns: &'a [u8],
}
impl<'a> Response<'a> {
    /// Decode exactly one official service request. Reserved must be zero.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(input)?;
        if frame.header().message_type() != mt::DNS_CLIENT_REQUEST {
            return Err(Error::Unsupported);
        }
        let fixed = input.get(..16).ok_or(Error::Truncated)?;
        if fixed[4..8] != [0; 4] {
            return Err(Error::Malformed);
        }
        Ok(Self {
            id: fixed[8..16].try_into().map_err(|_| Error::Truncated)?,
            dns: &input[16..],
        })
    }
    /// Complete official frame size.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let n = 16usize.checked_add(self.dns.len()).ok_or(Error::Overflow)?;
        MessageHeader::from_total_size(mt::DNS_CLIENT_REQUEST, n)?;
        Ok(n)
    }
    /// Encode for an actual DNS service producer; no synthetic acknowledgement.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(mt::DNS_CLIENT_REQUEST, n)?.encode(out)?;
        out[4..8].fill(0);
        out[8..16].copy_from_slice(&self.id);
        out[16..n].copy_from_slice(self.dns);
        Ok(n)
    }
}
