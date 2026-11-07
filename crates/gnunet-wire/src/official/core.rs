//! Current v0.29.1 CORE application/monitor IPC layouts, not CAKE peer records.
//!
//! `core.h` and the active service/library handlers define types 64,65,67,68,
//! 70,71,74,75,76,78,79. Registry-only 69/1811 have no current CORE layout.
//! Class values in INIT_REPLY/CONNECT are source-native enum32; all other
//! multi-byte numeric fields in this module use network byte order.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;

/// CORE_INIT fixed prefix, followed by BE16 message-type subscriptions.
pub const INIT_PREFIX: usize = 8;
/// CORE_INIT_REPLY and CORE_NOTIFY_CONNECT total size in the current enum32 ABI.
pub const PEER_CLASS_LEN: usize = 44;
/// CORE_NOTIFY_DISCONNECT and CORE_SEND_READY total size.
pub const PEER_LEN: usize = 40;
/// CORE_SEND_REQUEST fixed total size.
pub const SEND_REQUEST_LEN: usize = 56;
/// CORE_SEND prefix before a complete sequence of inner messages.
pub const SEND_PREFIX: usize = 48;
/// CORE_NOTIFY_INBOUND/OUTBOUND prefix before a full message or header preview.
pub const TRAFFIC_PREFIX: usize = 36;
/// CORE_MONITOR_NOTIFY total size.
pub const MONITOR_LEN: usize = 48;
/// Largest complete inner-message sequence representable in CORE_SEND.
pub const MAX_SEND_BYTES: usize = 65_487;
/// Current C remote-session aggregate request limit, independent of IPC framing.
/// Its transmission path also requires each individual inner message to be smaller.
/// Local self-loopback does not use the remote session queue.
pub const REMOTE_REQUEST_LIMIT: usize = 63 * 1024;
/// Connectivity status notification option, in the current source bit registry.
pub const STATUS_CHANGE: u32 = 4;
/// Request complete inbound messages in addition to registered message types.
pub const FULL_INBOUND: u32 = 8;
/// Request only headers of otherwise unregistered inbound messages.
pub const HEADER_INBOUND: u32 = 16;
/// Request complete outgoing message notifications.
pub const FULL_OUTBOUND: u32 = 32;
/// Request only headers of outgoing messages.
pub const HEADER_OUTBOUND: u32 = 64;
/// All currently defined INIT option bits.
pub const OPTIONS: u32 =
    STATUS_CHANGE | FULL_INBOUND | HEADER_INBOUND | FULL_OUTBOUND | HEADER_OUTBOUND;

/// Official peer identity bytes; decoding grants no authentication authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerId(pub [u8; 32]);
/// Informational current source peer class, preserving unrecognized enum values.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerClass(pub u32);
impl PeerClass {
    /// Unspecified capabilities.
    pub const UNKNOWN: Self = Self(0);
    /// Unwilling to expend more than minimal resources.
    pub const UNWILLING: Self = Self(1);
    /// Mobile device.
    pub const MOBILE: Self = Self(2);
    /// Desktop device.
    pub const DESKTOP: Self = Self(3);
    /// Network router.
    pub const ROUTER: Self = Self(4);
    /// Server device.
    pub const SERVER: Self = Self(5);
}
/// Explicit native enum32 profile used only by class fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClassOrder {
    /// Current normal Darwin arm64/Linux x86_64 enum32 profile.
    Little,
    /// Native big-endian enum32 reference profile.
    Big,
}
impl ClassOrder {
    fn encode(self, class: PeerClass) -> [u8; 4] {
        match self {
            Self::Little => class.0.to_le_bytes(),
            Self::Big => class.0.to_be_bytes(),
        }
    }
    fn decode(self, bytes: [u8; 4]) -> PeerClass {
        PeerClass(match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        })
    }
}
#[derive(Clone, Copy, Debug)]
enum TypeStorage<'a> {
    Host(&'a [u16]),
    Network(&'a [u8]),
}
/// Borrowed subscription numbers, with no native endian cast or allocation.
#[derive(Clone, Copy, Debug)]
pub struct MessageTypes<'a>(TypeStorage<'a>);
impl<'a> MessageTypes<'a> {
    /// View host-order message numbers; validation of total size occurs on encode.
    #[must_use]
    pub const fn new(values: &'a [u16]) -> Self {
        Self(TypeStorage::Host(values))
    }
    fn from_network(bytes: &'a [u8]) -> Result<Self, Error> {
        if !bytes.len().is_multiple_of(2) {
            return Err(Error::Malformed);
        }
        Ok(Self(TypeStorage::Network(bytes)))
    }
    /// Number of subscribed message assignments.
    #[must_use]
    pub const fn len(self) -> usize {
        match self.0 {
            TypeStorage::Host(v) => v.len(),
            TypeStorage::Network(v) => v.len() / 2,
        }
    }
    /// Whether there are no registered message assignments.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len() == 0
    }
    /// Iterate official message numbers in host order.
    pub fn iter(self) -> impl Iterator<Item = u16> + 'a {
        (0..self.len()).map(move |index| match self.0 {
            TypeStorage::Host(values) => values[index],
            TypeStorage::Network(bytes) => {
                u16::from_be_bytes([bytes[index * 2], bytes[index * 2 + 1]])
            }
        })
    }
}
impl PartialEq for MessageTypes<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}
impl Eq for MessageTypes<'_> {}

/// A current CORE client request. No service-info field exists in current INIT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Register options and message subscriptions on this physical MQ.
    Init {
        /// Current option bits, independent of C callback organization.
        options: u32,
        /// Message types of interest.
        types: MessageTypes<'a>,
    },
    /// Ask for permission to transmit one retained original message sequence.
    SendRequest {
        /// MQ priority/preference flags.
        priority: u32,
        /// Original absolute deadline in microseconds, including ZERO/FOREVER.
        deadline: u64,
        /// Intended target, including local loopback identity.
        peer: PeerId,
        /// Exact promised message bytes, excluding CORE_SEND's prefix.
        size: u16,
        /// Per-peer echoed correlation number.
        request_id: u16,
    },
    /// Transmit only after the matching nonzero SEND_READY permit.
    Send {
        /// MQ priority/preference flags.
        priority: u32,
        /// Original request's absolute deadline.
        deadline: u64,
        /// Intended target.
        peer: PeerId,
        /// Nonempty exact complete sequence of official inner messages.
        messages: &'a [u8],
    },
    /// Start a continuous peer/KX monitor; INIT is not required first.
    Monitor,
}
impl<'a> Request<'a> {
    /// Decode one exact current request, rejecting malformed/unknown layouts.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        match frame.header().message_type() {
            mt::CORE_INIT => {
                let options = number(bytes, 4)?;
                options_valid(options)?;
                let types =
                    MessageTypes::from_network(bytes.get(INIT_PREFIX..).ok_or(Error::Truncated)?)?;
                Ok(Self::Init { options, types })
            }
            mt::CORE_SEND_REQUEST => {
                exact(bytes, SEND_REQUEST_LEN)?;
                if number(bytes, 48)? != 0 {
                    return Err(Error::Malformed);
                }
                let size = short(bytes, 52)?;
                send_size(usize::from(size))?;
                Ok(Self::SendRequest {
                    priority: number(bytes, 4)?,
                    deadline: long(bytes, 8)?,
                    peer: peer(bytes, 16)?,
                    size,
                    request_id: short(bytes, 54)?,
                })
            }
            mt::CORE_SEND => {
                let messages = bytes.get(SEND_PREFIX..).ok_or(Error::Truncated)?;
                message_sequence(messages)?;
                Ok(Self::Send {
                    priority: number(bytes, 4)?,
                    deadline: long(bytes, 8)?,
                    peer: peer(bytes, 16)?,
                    messages,
                })
            }
            mt::CORE_MONITOR_PEERS => {
                exact(bytes, 4)?;
                Ok(Self::Monitor)
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Encode atomically; preflight failures consume no output bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let (kind, size) = match self {
            Self::Init { options, types } => {
                options_valid(options)?;
                let bytes = types
                    .len()
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(INIT_PREFIX))
                    .ok_or(Error::Overflow)?;
                (mt::CORE_INIT, bytes)
            }
            Self::SendRequest { size, .. } => {
                send_size(usize::from(size))?;
                (mt::CORE_SEND_REQUEST, SEND_REQUEST_LEN)
            }
            Self::Send { messages, .. } => {
                message_sequence(messages)?;
                (mt::CORE_SEND, SEND_PREFIX + messages.len())
            }
            Self::Monitor => (mt::CORE_MONITOR_PEERS, 4),
        };
        let bytes = prepare(output, kind, size)?;
        match self {
            Self::Init { options, types } => {
                bytes[4..8].copy_from_slice(&options.to_be_bytes());
                for (position, kind) in types.iter().enumerate() {
                    bytes[8 + position * 2..10 + position * 2].copy_from_slice(&kind.to_be_bytes());
                }
            }
            Self::SendRequest {
                priority,
                deadline,
                peer,
                size,
                request_id,
            } => {
                send_prefix(bytes, priority, deadline, peer);
                bytes[52..54].copy_from_slice(&size.to_be_bytes());
                bytes[54..56].copy_from_slice(&request_id.to_be_bytes());
            }
            Self::Send {
                priority,
                deadline,
                peer,
                messages,
            } => {
                send_prefix(bytes, priority, deadline, peer);
                bytes[SEND_PREFIX..].copy_from_slice(messages);
            }
            Self::Monitor => {}
        }
        Ok(size)
    }
}

/// Direction of a traffic notification; both directions can contain previews.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// A message received from the peer.
    Inbound,
    /// A message sent to the peer.
    Outbound,
}
/// Complete message or an explicitly incomplete four-byte header preview.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Traffic<'a> {
    /// One exact complete message.
    Full(&'a [u8]),
    /// Only the original header, whose declared size can exceed four.
    Header(MessageHeader),
}
impl<'a> Traffic<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let header = MessageHeader::decode(bytes)?;
        if bytes.len() == 4 && header.size() > 4 {
            return Ok(Self::Header(header));
        }
        Frame::decode(bytes)?;
        Ok(Self::Full(bytes))
    }
    /// Header of the original message, including its full advertised size.
    pub fn header(self) -> Result<MessageHeader, Error> {
        match self {
            Self::Full(bytes) => MessageHeader::decode(bytes),
            Self::Header(header) => Ok(header),
        }
    }
}
/// Informational monitor state, preserving future values without granting authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KxState(pub u32);
impl KxState {
    /// Initial peer state.
    pub const DOWN: Self = Self(0);
    /// Initial snapshot finished; peer is zero and timeout FOREVER on the wire.
    pub const SNAPSHOT_FINISHED: Self = Self(11);
    /// Current C API's local service-disconnect callback value; not a wire END.
    pub const LOCAL_SERVICE_DISCONNECT: Self = Self(12);
}
/// One current CORE service response; decoding establishes framing, not authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// Genuine response to this client's INIT.
    InitReply {
        /// Local service identity, also usable for actual self-loopback sends.
        identity: PeerId,
        /// Informational native enum32 class.
        class: PeerClass,
    },
    /// An application peer is now available.
    Connected {
        /// Official peer identity.
        peer: PeerId,
        /// Informational native enum32 class.
        class: PeerClass,
    },
    /// A previously available peer is gone.
    Disconnected(PeerId),
    /// Traffic matching subscriptions or requested observational options.
    Traffic {
        /// Inbound or outbound notification.
        direction: Direction,
        /// Sender for inbound or receiver for outbound.
        peer: PeerId,
        /// Complete message or explicit header-only preview.
        traffic: Traffic<'a>,
    },
    /// Original send permission, or zero-size rejection.
    SendReady {
        /// Original target.
        peer: PeerId,
        /// Original echoed per-peer correlation number.
        request_id: u16,
        /// Permitted bytes, zero for rejection.
        size: u16,
    },
    /// One monitor update, including the initial snapshot marker.
    Monitor {
        /// Peer/KX state or snapshot marker.
        state: KxState,
        /// Peer, zero for the initial snapshot marker.
        peer: PeerId,
        /// Absolute timeout, including FOREVER.
        timeout: u64,
    },
}
impl<'a> Response<'a> {
    /// Decode one exact response with an explicit class ABI profile.
    pub fn decode(bytes: &'a [u8], order: ClassOrder) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        match frame.header().message_type() {
            mt::CORE_INIT_REPLY | mt::CORE_NOTIFY_CONNECT => {
                exact(bytes, PEER_CLASS_LEN)?;
                if number(bytes, 4)? != 0 {
                    return Err(Error::Malformed);
                }
                let peer = peer(bytes, 8)?;
                let class = order.decode(array(bytes, 40)?);
                Ok(if frame.header().message_type() == mt::CORE_INIT_REPLY {
                    Self::InitReply {
                        identity: peer,
                        class,
                    }
                } else {
                    Self::Connected { peer, class }
                })
            }
            mt::CORE_NOTIFY_DISCONNECT => {
                exact(bytes, PEER_LEN)?;
                if number(bytes, 4)? != 0 {
                    return Err(Error::Malformed);
                }
                Ok(Self::Disconnected(peer(bytes, 8)?))
            }
            mt::CORE_NOTIFY_INBOUND | mt::CORE_NOTIFY_OUTBOUND => Ok(Self::Traffic {
                direction: if frame.header().message_type() == mt::CORE_NOTIFY_INBOUND {
                    Direction::Inbound
                } else {
                    Direction::Outbound
                },
                peer: peer(bytes, 4)?,
                traffic: Traffic::decode(bytes.get(TRAFFIC_PREFIX..).ok_or(Error::Truncated)?)?,
            }),
            mt::CORE_SEND_READY => {
                exact(bytes, PEER_LEN)?;
                let size = short(bytes, 4)?;
                if size != 0 && size < 4 {
                    return Err(Error::Malformed);
                }
                Ok(Self::SendReady {
                    peer: peer(bytes, 8)?,
                    request_id: short(bytes, 6)?,
                    size,
                })
            }
            mt::CORE_MONITOR_NOTIFY => {
                exact(bytes, MONITOR_LEN)?;
                Ok(Self::Monitor {
                    state: KxState(number(bytes, 4)?),
                    peer: peer(bytes, 8)?,
                    timeout: long(bytes, 40)?,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Encode exact current service bytes, including the explicit class ABI profile.
    pub fn encode(self, output: &mut [u8], order: ClassOrder) -> Result<usize, Error> {
        let (kind, size) = match self {
            Self::InitReply { .. } => (mt::CORE_INIT_REPLY, PEER_CLASS_LEN),
            Self::Connected { .. } => (mt::CORE_NOTIFY_CONNECT, PEER_CLASS_LEN),
            Self::Disconnected(_) => (mt::CORE_NOTIFY_DISCONNECT, PEER_LEN),
            Self::Traffic {
                direction, traffic, ..
            } => {
                let size = match traffic {
                    Traffic::Full(bytes) => {
                        Frame::decode(bytes)?;
                        bytes.len()
                    }
                    Traffic::Header(_) => 4,
                };
                (
                    match direction {
                        Direction::Inbound => mt::CORE_NOTIFY_INBOUND,
                        Direction::Outbound => mt::CORE_NOTIFY_OUTBOUND,
                    },
                    TRAFFIC_PREFIX + size,
                )
            }
            Self::SendReady { size, .. } => {
                if size != 0 && size < 4 {
                    return Err(Error::InvalidInput);
                }
                (mt::CORE_SEND_READY, PEER_LEN)
            }
            Self::Monitor { .. } => (mt::CORE_MONITOR_NOTIFY, MONITOR_LEN),
        };
        let bytes = prepare(output, kind, size)?;
        match self {
            Self::InitReply {
                identity: peer,
                class,
            }
            | Self::Connected { peer, class } => {
                bytes[8..40].copy_from_slice(&peer.0);
                bytes[40..44].copy_from_slice(&order.encode(class));
            }
            Self::Disconnected(peer) => bytes[8..40].copy_from_slice(&peer.0),
            Self::Traffic { peer, traffic, .. } => {
                bytes[4..36].copy_from_slice(&peer.0);
                match traffic {
                    Traffic::Full(payload) => bytes[36..].copy_from_slice(payload),
                    Traffic::Header(header) => {
                        header.encode(&mut bytes[36..])?;
                    }
                }
            }
            Self::SendReady {
                peer,
                request_id,
                size,
            } => {
                bytes[4..6].copy_from_slice(&size.to_be_bytes());
                bytes[6..8].copy_from_slice(&request_id.to_be_bytes());
                bytes[8..40].copy_from_slice(&peer.0);
            }
            Self::Monitor {
                state,
                peer,
                timeout,
            } => {
                bytes[4..8].copy_from_slice(&state.0.to_be_bytes());
                bytes[8..40].copy_from_slice(&peer.0);
                bytes[40..48].copy_from_slice(&timeout.to_be_bytes());
            }
        }
        Ok(size)
    }
}

fn options_valid(options: u32) -> Result<(), Error> {
    if options & !OPTIONS != 0 {
        Err(Error::Unsupported)
    } else {
        Ok(())
    }
}
fn send_size(size: usize) -> Result<(), Error> {
    if size < 4 {
        Err(Error::InvalidInput)
    } else if size > MAX_SEND_BYTES {
        Err(Error::TooLarge)
    } else {
        Ok(())
    }
}
/// Validate a complete nonempty CORE_SEND inner-message sequence without allocation.
pub fn message_sequence(mut bytes: &[u8]) -> Result<(), Error> {
    send_size(bytes.len())?;
    while !bytes.is_empty() {
        let (_, rest) = Frame::decode_prefix(bytes)?;
        bytes = rest;
    }
    Ok(())
}
fn send_prefix(bytes: &mut [u8], priority: u32, deadline: u64, peer: PeerId) {
    bytes[4..8].copy_from_slice(&priority.to_be_bytes());
    bytes[8..16].copy_from_slice(&deadline.to_be_bytes());
    bytes[16..48].copy_from_slice(&peer.0);
}
fn exact(bytes: &[u8], size: usize) -> Result<(), Error> {
    if bytes.len() == size {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}
fn array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], Error> {
    bytes
        .get(offset..offset + N)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn number(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(array(bytes, offset)?))
}
fn short(bytes: &[u8], offset: usize) -> Result<u16, Error> {
    Ok(u16::from_be_bytes(array(bytes, offset)?))
}
fn long(bytes: &[u8], offset: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(array(bytes, offset)?))
}
fn peer(bytes: &[u8], offset: usize) -> Result<PeerId, Error> {
    Ok(PeerId(array(bytes, offset)?))
}
fn prepare(output: &mut [u8], kind: MessageType, size: usize) -> Result<&mut [u8], Error> {
    let header = MessageHeader::from_total_size(kind, size)?;
    let bytes = output.get_mut(..size).ok_or(Error::Capacity)?;
    bytes.fill(0);
    header.encode(bytes)?;
    Ok(bytes)
}
