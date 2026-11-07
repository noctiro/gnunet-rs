//! Official TRANSPORT-to-CORE IPC messages 360..366, GNUnet v0.29.1.
//!
//! This is the current `GNUNET_TRANSPORT_CORE_VERSION` layout: no legacy SEND
//! timeout or quota fields. It is not the CORE CAKE protocol or a TRANSPORT
//! service implementation. Codecs authenticate neither peers nor application data.
use gnunet_types::Error;
use gnunet_wire::official::{Frame, MessageHeader, MessageType, message_type as mt};

mod owner;
pub use owner::{
    ConnectionEpoch, Event, Instance, Peer, ReceiveId, SendId, SendOutcome, TransportClient,
};

/// Bytes in START, CONNECT, DISCONNECT, SEND_OK and RECV_OK.
pub const FIXED_LEN: usize = 40;
/// Bytes before the inner message in SEND.
pub const SEND_PREFIX_LEN: usize = 40;
/// Bytes before the inner message in RECV.
pub const RECEIVE_PREFIX_LEN: usize = 36;
/// Largest inner message accepted by the official current SEND envelope.
pub const MAX_SEND_MESSAGE_LEN: usize = 65_495;
/// Initial per-peer send credit of the current official TRANSPORT client.
pub const SEND_WINDOW: u32 = 4;
/// Initial per-peer receive credit of the current official TRANSPORT service.
pub const RECEIVE_WINDOW: usize = 4;

/// Official peer identity bytes, without key ownership or authentication authority.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerId(pub [u8; 32]);

/// Current START options and claimed local peer identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Start {
    /// Bit 0 requests a self-identity check; bit 1 selects payload delivery.
    pub options: u32,
    /// Claimed local identity, zero-filled when no check was requested.
    pub identity: PeerId,
}
impl Start {
    /// Construct the same option bits as the official public client.
    #[must_use]
    pub const fn new(identity: Option<PeerId>, receive_payload: bool) -> Self {
        let (check, identity) = match identity {
            Some(peer) => (1, peer),
            None => (0, PeerId([0; 32])),
        };
        Self {
            options: check | if receive_payload { 2 } else { 0 },
            identity,
        }
    }
    fn validate(self) -> Result<(), Error> {
        if self.options & !3 != 0 {
            Err(Error::Unsupported)
        } else {
            Ok(())
        }
    }
}

/// One current public-client request, borrowing a complete nested message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request<'a> {
    /// Register this physical service connection before sending peer data.
    Start(Start),
    /// Submit one message. Transmission does not imply delivery or persistence.
    Send {
        /// Destination peer.
        peer: PeerId,
        /// Official opaque MQ priority/preference flags, in host byte order.
        priority: u32,
        /// Exactly one complete official inner message.
        message: &'a [u8],
    },
    /// Return receive credit only after application processing.
    ReceiveContinue {
        /// Peer whose receive window increases.
        peer: PeerId,
        /// Positive count of processed messages.
        increase: u32,
    },
}
impl<'a> Request<'a> {
    /// Decode exactly one current-profile request; reject unknown/trailing bytes.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        let payload = frame.payload();
        match frame.header().message_type() {
            mt::TRANSPORT_START => {
                fixed(bytes)?;
                let start = Start {
                    options: number(payload, 0)?,
                    identity: peer(payload, 4)?,
                };
                start.validate()?;
                Ok(Self::Start(start))
            }
            mt::TRANSPORT_SEND => {
                let message = nested(bytes, SEND_PREFIX_LEN)?;
                Ok(Self::Send {
                    priority: number(payload, 0)?,
                    peer: peer(payload, 4)?,
                    message,
                })
            }
            mt::TRANSPORT_RECV_OK => {
                fixed(bytes)?;
                let increase = number(payload, 0)?;
                if increase == 0 {
                    return Err(Error::Malformed);
                }
                Ok(Self::ReceiveContinue {
                    peer: peer(payload, 4)?,
                    increase,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Encode atomically: invalid input or short output leaves every byte intact.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let (kind, size) = match self {
            Self::Start(start) => {
                start.validate()?;
                (mt::TRANSPORT_START, FIXED_LEN)
            }
            Self::Send { message, .. } => {
                Frame::decode(message)?;
                if message.len() > MAX_SEND_MESSAGE_LEN {
                    return Err(Error::TooLarge);
                }
                (mt::TRANSPORT_SEND, SEND_PREFIX_LEN + message.len())
            }
            Self::ReceiveContinue { increase: 0, .. } => return Err(Error::InvalidInput),
            Self::ReceiveContinue { .. } => (mt::TRANSPORT_RECV_OK, FIXED_LEN),
        };
        let bytes = prepare(kind, size, output)?;
        match self {
            Self::Start(start) => {
                bytes[4..8].copy_from_slice(&start.options.to_be_bytes());
                bytes[8..40].copy_from_slice(&start.identity.0);
            }
            Self::Send {
                peer,
                priority,
                message,
            } => {
                bytes[4..8].copy_from_slice(&priority.to_be_bytes());
                bytes[8..40].copy_from_slice(&peer.0);
                bytes[40..].copy_from_slice(message);
            }
            Self::ReceiveContinue { peer, increase } => {
                bytes[4..8].copy_from_slice(&increase.to_be_bytes());
                bytes[8..40].copy_from_slice(&peer.0);
            }
        }
        Ok(size)
    }
}

/// One service response; SEND_OK is flow-control credit, not a delivery receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    /// A peer became available to this connection.
    Connected(PeerId),
    /// A previously announced peer is no longer available.
    Disconnected(PeerId),
    /// One unit of this peer's send window is returned.
    SendCredit(PeerId),
    /// An inner message requiring explicit application processing credit.
    Received {
        /// Sender announced on this connection.
        peer: PeerId,
        /// Exactly one complete borrowed inner message.
        message: &'a [u8],
    },
}
impl<'a> Response<'a> {
    /// Decode one exact current-profile response, validating nested framing.
    /// Reserved fields must be zero in this strict supported profile.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        match frame.header().message_type() {
            mt::TRANSPORT_CONNECT | mt::TRANSPORT_DISCONNECT | mt::TRANSPORT_SEND_OK => {
                fixed(bytes)?;
                if number(frame.payload(), 0)? != 0 {
                    return Err(Error::Malformed);
                }
                let id = peer(frame.payload(), 4)?;
                Ok(match frame.header().message_type() {
                    mt::TRANSPORT_CONNECT => Self::Connected(id),
                    mt::TRANSPORT_DISCONNECT => Self::Disconnected(id),
                    _ => Self::SendCredit(id),
                })
            }
            mt::TRANSPORT_RECV => Ok(Self::Received {
                peer: peer(frame.payload(), 0)?,
                message: nested(bytes, RECEIVE_PREFIX_LEN)?,
            }),
            _ => Err(Error::Unsupported),
        }
    }
    /// Encode a service-side test/host response with unchanged official bytes.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let (kind, id, size) = match self {
            Self::Connected(id) => (mt::TRANSPORT_CONNECT, id, FIXED_LEN),
            Self::Disconnected(id) => (mt::TRANSPORT_DISCONNECT, id, FIXED_LEN),
            Self::SendCredit(id) => (mt::TRANSPORT_SEND_OK, id, FIXED_LEN),
            Self::Received { peer, message } => {
                Frame::decode(message)?;
                (mt::TRANSPORT_RECV, peer, RECEIVE_PREFIX_LEN + message.len())
            }
        };
        let bytes = prepare(kind, size, output)?;
        match self {
            Self::Received { message, .. } => {
                bytes[4..36].copy_from_slice(&id.0);
                bytes[36..].copy_from_slice(message);
            }
            _ => bytes[8..40].copy_from_slice(&id.0),
        }
        Ok(size)
    }
}

fn fixed(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() == FIXED_LEN {
        Ok(())
    } else {
        Err(Error::Malformed)
    }
}
fn nested(bytes: &[u8], prefix: usize) -> Result<&[u8], Error> {
    let message = bytes.get(prefix..).ok_or(Error::Truncated)?;
    Frame::decode(message)?;
    Ok(message)
}
fn number(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn peer(bytes: &[u8], offset: usize) -> Result<PeerId, Error> {
    Ok(PeerId(
        bytes
            .get(offset..offset + 32)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?,
    ))
}
fn prepare(kind: MessageType, size: usize, output: &mut [u8]) -> Result<&mut [u8], Error> {
    let header = MessageHeader::from_total_size(kind, size)?;
    let bytes = output.get_mut(..size).ok_or(Error::Capacity)?;
    bytes.fill(0);
    header.encode(bytes)?;
    Ok(bytes)
}
