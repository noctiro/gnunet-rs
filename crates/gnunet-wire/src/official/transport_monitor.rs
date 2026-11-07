//! Active TRANSPORT monitor1250..1252 and virtual-link listing1255..1257.
//! These observations grant no route, authentication, credit or delivery receipt.
use super::{Frame, MessageHeader, message_type as mt};
use gnunet_types::Error;

/// Fixed request size including the common header.
pub const REQUEST_BYTES: usize = 40;
/// Fixed monitor record prefix, followed by one NUL-terminated address.
pub const MONITOR_BYTES: usize = 84;
/// Fixed link record prefix, followed by one NUL-terminated communicator list.
pub const LINK_BYTES: usize = 148;

/// One original physical connection's observation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    /// All-zero peer selects all physical neighbour queues.
    Monitor {
        /// Enumerate once and require END; otherwise subscribe to changes.
        one_shot: bool,
        /// Original peer selector; zero selects all peers.
        peer: [u8; 32],
    },
    /// All-zero peer selects all currently eligible virtual links.
    Links {
        /// Include actual links not currently established.
        include_unconfirmed: bool,
        /// Original peer selector or observed peer identity; zero selector means all.
        peer: [u8; 32],
    },
}
impl Request {
    /// Decode one exact fixed request; flags are the public YES/NO values.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let f = Frame::decode(bytes)?;
        if bytes.len() != REQUEST_BYTES {
            return Err(Error::Malformed);
        }
        let flag = match u32_at(bytes, 4)? {
            0 => false,
            1 => true,
            _ => return Err(Error::Malformed),
        };
        let peer = bytes[8..40].try_into().map_err(|_| Error::Truncated)?;
        match f.header().message_type() {
            mt::TRANSPORT_MONITOR_START => Ok(Self::Monitor {
                one_shot: flag,
                peer,
            }),
            mt::TRANSPORT_LINK_LIST_REQUEST => Ok(Self::Links {
                include_unconfirmed: flag,
                peer,
            }),
            _ => Err(Error::Unsupported),
        }
    }
    /// Validate capacity before writing any bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let (kind, flag, peer) = match self {
            Self::Monitor { one_shot, peer } => (mt::TRANSPORT_MONITOR_START, one_shot, peer),
            Self::Links {
                include_unconfirmed,
                peer,
            } => (mt::TRANSPORT_LINK_LIST_REQUEST, include_unconfirmed, peer),
        };
        let b = output.get_mut(..REQUEST_BYTES).ok_or(Error::Capacity)?;
        b.fill(0);
        MessageHeader::from_total_size(kind, REQUEST_BYTES)?.encode(b)?;
        b[4..8].copy_from_slice(&u32::from(flag).to_be_bytes());
        b[8..40].copy_from_slice(&peer);
        Ok(REQUEST_BYTES)
    }
}

/// Actual physical queue observations. Time fields retain their public domains.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Monitor<'a> {
    /// Actual official network-type value.
    pub network: u32,
    /// Original peer selector or observed peer identity; zero selector means all.
    pub peer: [u8; 32],
    /// GNUnet absolute microseconds of the last actual validation.
    pub last_validation: u64,
    /// GNUnet absolute expiration of the original validation.
    pub valid_until: u64,
    /// GNUnet absolute scheduled validation target, or NEVER.
    pub next_validation: u64,
    /// Measured relative microseconds, or FOREVER when unknown.
    pub rtt: u64,
    /// DOWN=-1, OUTBOUND=0, INBOUND=1, encoded as NBO int32.
    pub status: i32,
    /// Actual pending original message count for this queue.
    pub pending_messages: u32,
    /// Actual pending encoded message bytes for this queue.
    pub pending_bytes: u32,
    /// Original NUL-free queue address; encoder supplies its one terminator.
    pub address: &'a [u8],
}
/// Actual virtual-link observations. Unknown RTT uses the public FOREVER value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Link<'a> {
    /// Original final virtual-link target.
    pub target: [u8; 32],
    /// Whether the actual link/path is currently established.
    pub confirmed: bool,
    /// Direct0 or DV1.
    pub route: u32,
    /// Actual intermediate DV vector count; direct uses zero.
    pub distance: u32,
    /// Actual queues to the selected direct neighbour or DV first hop.
    pub queues: u32,
    /// Signed current remaining CORE receive window.
    pub core_receive_window: i32,
    /// Messages currently withholding receive credit.
    pub stalled: u32,
    /// Original application messages pending for this target.
    pub pending: u32,
    /// Retransmissions of the implementation's running Flow task.
    pub flow_retransmissions: u32,
    /// Actual per-target incoming RAM/credit policy.
    pub available_window: u64,
    /// Actual retained/debited incoming bytes.
    pub incoming_ram: u64,
    /// Window most recently granted to the other peer.
    pub incoming_window: u64,
    /// Actual cumulative incoming use.
    pub incoming_used: u64,
    /// Signed actual sender-loss estimate; may be negative.
    pub incoming_loss: i64,
    /// Actual window granted by the other peer.
    pub outbound_window: u64,
    /// Actual cumulative outbound use.
    pub outbound_used: u64,
    /// Measured Flow-exchange relative time, or FOREVER.
    pub flow_rtt: u64,
    /// The other peer's actual reported DV RTT, or FOREVER.
    pub other_rtt: u64,
    /// Actual GNUnet absolute time of the last local Flow submission.
    pub last_flow_transmission: u64,
    /// NUL-free comma-separated actual first-hop communicator prefixes.
    pub communicators: &'a [u8],
}
/// One standard observation record or actual finite enumeration END.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// A physical neighbour-queue record or monitoring request.
    Monitor(Monitor<'a>),
    /// Actual one-shot monitoring enumeration END.
    MonitorEnd,
    /// One actual virtual-link observation.
    Link(Link<'a>),
    /// Actual virtual-link listing enumeration END.
    LinksEnd,
}
impl<'a> Response<'a> {
    /// Return exact encoded size after validating fields and the standard frame cap.
    pub fn encoded_len(self) -> Result<usize, Error> {
        let (base, tail) = match self {
            Self::Monitor(m) => {
                if !(-1..=1).contains(&m.status) {
                    return Err(Error::Malformed);
                }
                (MONITOR_BYTES, m.address)
            }
            Self::Link(l) => {
                if l.route > 1 {
                    return Err(Error::Malformed);
                }
                (LINK_BYTES, l.communicators)
            }
            Self::MonitorEnd | Self::LinksEnd => return Ok(4),
        };
        if tail.contains(&0) {
            return Err(Error::Malformed);
        }
        base.checked_add(tail.len())
            .and_then(|n| n.checked_add(1))
            .filter(|n| *n <= u16::MAX as usize)
            .ok_or(Error::TooLarge)
    }
    /// Encode atomically after full field and output-capacity preflight.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let size = self.encoded_len()?;
        let kind = match self {
            Self::Monitor(_) => mt::TRANSPORT_MONITOR_DATA,
            Self::MonitorEnd => mt::TRANSPORT_MONITOR_END,
            Self::Link(_) => mt::TRANSPORT_LINK_LIST_RESPONSE,
            Self::LinksEnd => mt::TRANSPORT_LINK_LIST_RESPONSE_END,
        };
        let b = output.get_mut(..size).ok_or(Error::Capacity)?;
        b.fill(0);
        MessageHeader::from_total_size(kind, size)?.encode(b)?;
        match self {
            Self::Monitor(m) => {
                b[4..8].copy_from_slice(&m.network.to_be_bytes());
                b[8..40].copy_from_slice(&m.peer);
                for (offset, value) in [
                    (40, m.last_validation),
                    (48, m.valid_until),
                    (56, m.next_validation),
                    (64, m.rtt),
                ] {
                    b[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
                }
                b[72..76].copy_from_slice(&m.status.to_be_bytes());
                b[76..80].copy_from_slice(&m.pending_messages.to_be_bytes());
                b[80..84].copy_from_slice(&m.pending_bytes.to_be_bytes());
                b[84..size - 1].copy_from_slice(m.address);
            }
            Self::Link(l) => {
                b[4..36].copy_from_slice(&l.target);
                for (offset, value) in [
                    (36, u32::from(l.confirmed)),
                    (40, l.route),
                    (44, l.distance),
                    (48, l.queues),
                    (56, l.stalled),
                    (60, l.pending),
                    (64, l.flow_retransmissions),
                ] {
                    b[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
                }
                b[52..56].copy_from_slice(&l.core_receive_window.to_be_bytes());
                for (offset, value) in [
                    (68, l.available_window),
                    (76, l.incoming_ram),
                    (84, l.incoming_window),
                    (92, l.incoming_used),
                    (108, l.outbound_window),
                    (116, l.outbound_used),
                    (124, l.flow_rtt),
                    (132, l.other_rtt),
                    (140, l.last_flow_transmission),
                ] {
                    b[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
                }
                b[100..108].copy_from_slice(&l.incoming_loss.to_be_bytes());
                b[148..size - 1].copy_from_slice(l.communicators);
            }
            Self::MonitorEnd | Self::LinksEnd => {}
        }
        Ok(size)
    }
    /// Decode one exact current standard response or request; validate its fixed prefix/tail.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(bytes)?;
        let tail = |n| -> Result<&'a [u8], Error> {
            let t = bytes.get(n..).ok_or(Error::Truncated)?;
            if t.last() != Some(&0) || t[..t.len() - 1].contains(&0) {
                return Err(Error::Malformed);
            }
            Ok(&t[..t.len() - 1])
        };
        Ok(match f.header().message_type() {
            mt::TRANSPORT_MONITOR_END if bytes.len() == 4 => Self::MonitorEnd,
            mt::TRANSPORT_LINK_LIST_RESPONSE_END if bytes.len() == 4 => Self::LinksEnd,
            mt::TRANSPORT_MONITOR_DATA => {
                let address = tail(MONITOR_BYTES)?;
                let status =
                    i32::from_be_bytes(bytes[72..76].try_into().map_err(|_| Error::Truncated)?);
                if !(-1..=1).contains(&status) {
                    return Err(Error::Malformed);
                }
                Self::Monitor(Monitor {
                    network: u32_at(bytes, 4)?,
                    peer: bytes[8..40].try_into().map_err(|_| Error::Truncated)?,
                    last_validation: u64_at(bytes, 40)?,
                    valid_until: u64_at(bytes, 48)?,
                    next_validation: u64_at(bytes, 56)?,
                    rtt: u64_at(bytes, 64)?,
                    status,
                    pending_messages: u32_at(bytes, 76)?,
                    pending_bytes: u32_at(bytes, 80)?,
                    address,
                })
            }
            mt::TRANSPORT_LINK_LIST_RESPONSE => {
                let communicators = tail(LINK_BYTES)?;
                let confirmed = match u32_at(bytes, 36)? {
                    0 => false,
                    1 => true,
                    _ => return Err(Error::Malformed),
                };
                let route = u32_at(bytes, 40)?;
                if route > 1 {
                    return Err(Error::Malformed);
                }
                Self::Link(Link {
                    target: bytes[4..36].try_into().map_err(|_| Error::Truncated)?,
                    confirmed,
                    route,
                    distance: u32_at(bytes, 44)?,
                    queues: u32_at(bytes, 48)?,
                    core_receive_window: i32::from_be_bytes(
                        bytes[52..56].try_into().map_err(|_| Error::Truncated)?,
                    ),
                    stalled: u32_at(bytes, 56)?,
                    pending: u32_at(bytes, 60)?,
                    flow_retransmissions: u32_at(bytes, 64)?,
                    available_window: u64_at(bytes, 68)?,
                    incoming_ram: u64_at(bytes, 76)?,
                    incoming_window: u64_at(bytes, 84)?,
                    incoming_used: u64_at(bytes, 92)?,
                    incoming_loss: i64::from_be_bytes(
                        bytes[100..108].try_into().map_err(|_| Error::Truncated)?,
                    ),
                    outbound_window: u64_at(bytes, 108)?,
                    outbound_used: u64_at(bytes, 116)?,
                    flow_rtt: u64_at(bytes, 124)?,
                    other_rtt: u64_at(bytes, 132)?,
                    last_flow_transmission: u64_at(bytes, 140)?,
                    communicators,
                })
            }
            _ => return Err(Error::Unsupported),
        })
    }
}
fn u32_at(b: &[u8], n: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        b.get(n..n + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn u64_at(b: &[u8], n: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(
        b.get(n..n + 8)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
