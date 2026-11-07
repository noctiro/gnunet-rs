//! Actual v0.29.1 MESSENGER IPC container codec. This has no synthetic RID,
//! general ACK, cancel, message delivery proof or room/member state machine.
//! Encoded chat-message tails remain opaque; parse their envelope separately.
pub use super::identity::KeyType;
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use core::fmt;
use gnunet_types::Error;
/// Exact typed body grammar for every active kind.
pub mod body;
/// Serialized signed-message header and exact signed/hash coverage views.
pub mod envelope;
/// Structural public-key/encrypted packet framing.
pub mod keys;
/// Typed signed/short message integration and canonical hash ranges.
pub mod message;
/// Bounded footer parsing and caller-supplied padding bytes.
pub mod padding;
/// Explicit producer-endian and FILE-name serialization profile.
pub mod profile;
/// Packed room/epoch/encryption record structures.
pub mod records;
/// Actual Messenger API version in this pin (0.8).
pub const VERSION: u32 = 8;
/// CREATE and DESTROY fixed frame size.
pub const CONNECTION_LEN: usize = 4;
/// Full room interaction container before any optional initial public key.
pub const ROOM_LEN: usize = 228;
/// Room/member identifier plus raw reset field.
pub const MEMBER_LEN: usize = 104;
/// SEND prefix before the complete encoded message.
pub const SEND_PREFIX: usize = 68;
/// GET request and actual missing-message notification size.
pub const GET_LEN: usize = 132;
/// RECV prefix before the complete encoded message.
pub const RECV_PREFIX: usize = 328;
/// Opaque potentially sensitive body. Debug never exposes chat text, transcript,
/// private/group payload, capability or other carried material. The borrowed
/// view cannot erase its owner; use a zeroizing owner for retained frames.
#[derive(Clone, Copy)]
pub struct SensitiveBytes<'a>(&'a [u8]);
impl<'a> SensitiveBytes<'a> {
    /// Explicitly borrow bytes without asserting their inner message grammar.
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
    /// Explicit sensitive borrow for encoding/parsing, never logging.
    pub const fn expose(self) -> &'a [u8] {
        self.0
    }
    /// Actual length without exposing contents.
    pub const fn len(self) -> usize {
        self.0.len()
    }
    /// Whether no bytes are carried.
    pub const fn is_empty(self) -> bool {
        self.0.is_empty()
    }
}
impl fmt::Debug for SensitiveBytes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SensitiveBytes").field(&self.len()).finish()
    }
}
/// Exact serialized blindable public key (BE32 family plus32 public bytes).
#[derive(Clone, Copy)]
pub struct PublicKey<'a> {
    bytes: &'a [u8; 36],
    kind: KeyType,
}
impl<'a> PublicKey<'a> {
    /// Validate exact structural length and supported official tag, not a point.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        let bytes: &[u8; 36] = bytes.try_into().map_err(|_| Error::Malformed)?;
        let kind =
            KeyType::from_value(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))?;
        Ok(Self { bytes, kind })
    }
    /// Official key family.
    pub const fn key_type(self) -> KeyType {
        self.kind
    }
    /// Exact serialized public bytes.
    pub const fn as_bytes(self) -> &'a [u8; 36] {
        self.bytes
    }
}
impl fmt::Debug for PublicKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.kind).finish()
    }
}
/// Shared room interaction fields, in exact official door/key/previous/epoch
/// order. Even fields unused by a particular producer are preserved verbatim.
#[derive(Clone, Copy)]
pub struct Room<'a> {
    /// Original public entry peer, or the producer's zero-filled unused field.
    pub door: &'a [u8; 32],
    /// Original opaque room key/capability identifier.
    pub key: &'a [u8; 64],
    /// Original previous message hash.
    pub previous: &'a [u8; 64],
    /// Original epoch hash, including a producer's unused zero field.
    pub epoch: &'a [u8; 64],
}
impl fmt::Debug for Room<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Room(opaque identifiers)")
    }
}
fn array<const N: usize>(bytes: &[u8], at: usize) -> Result<&[u8; N], Error> {
    bytes
        .get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn room(bytes: &[u8]) -> Result<Room<'_>, Error> {
    Ok(Room {
        door: array(bytes, 4)?,
        key: array(bytes, 36)?,
        previous: array(bytes, 100)?,
        epoch: array(bytes, 164)?,
    })
}
fn exact(bytes: &[u8], n: usize) -> Result<(), Error> {
    if bytes.len() != n {
        Err(Error::Malformed)
    } else {
        Ok(())
    }
}
fn size(kind: MessageType, prefix: usize, tail: usize) -> Result<usize, Error> {
    let n = prefix.checked_add(tail).ok_or(Error::Overflow)?;
    MessageHeader::from_total_size(kind, n)?;
    Ok(n)
}
fn put_room(out: &mut [u8], r: Room<'_>) {
    out[4..36].copy_from_slice(r.door);
    out[36..100].copy_from_slice(r.key);
    out[100..164].copy_from_slice(r.previous);
    out[164..228].copy_from_slice(r.epoch);
}
/// Actual active client-to-service IPC. CREATE has no key/name payload; OPEN
/// and ENTRY may append one complete initial public key, unlike their replies.
#[derive(Clone, Copy)]
pub enum Request<'a> {
    /// Create the client handle; no generic acknowledgement follows.
    Create,
    /// Physically retire the client handle/MQ at the service.
    Destroy,
    /// Request an open room.
    Open {
        /// Actual original room fields.
        room: Room<'a>,
        /// Optional complete initial public key.
        public_key: Option<PublicKey<'a>>,
    },
    /// Request entering through the actual public door.
    Entry {
        /// Actual original room fields.
        room: Room<'a>,
        /// Optional complete initial public key.
        public_key: Option<PublicKey<'a>>,
    },
    /// Request closing a room.
    Close {
        /// Actual original room fields.
        room: Room<'a>,
    },
    /// Request original room-message state synchronization.
    Sync {
        /// Actual original room fields.
        room: Room<'a>,
    },
    /// Submit one encoded signed message; this container does not validate or
    /// authenticate the encoded message body, signature or room authorization.
    Send {
        /// Original room key.
        key: &'a [u8; 64],
        /// Original sensitive encoded message, without copying or reinterpretation.
        message: SensitiveBytes<'a>,
    },
    /// Request the actual message under a hash in its original room.
    Get {
        /// Original room key.
        key: &'a [u8; 64],
        /// Actual requested message hash.
        hash: &'a [u8; 64],
    },
}
impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerRequest")
            .field("type", &self.message_type())
            .field("encoded_bytes", &self.encoded_len())
            .finish()
    }
}
impl<'a> Request<'a> {
    /// Decode exact outer IPC framing and every fixed/optional field. Unknown
    /// registry constants without active producers/handlers are Unsupported.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let frame = Frame::decode(bytes)?;
        match frame.header().message_type() {
            mt::MESSENGER_CONNECTION_CREATE => {
                exact(bytes, 4)?;
                Ok(Self::Create)
            }
            mt::MESSENGER_CONNECTION_DESTROY => {
                exact(bytes, 4)?;
                Ok(Self::Destroy)
            }
            kind @ (mt::MESSENGER_ROOM_OPEN | mt::MESSENGER_ROOM_ENTRY) => {
                let fields = room(bytes)?;
                let tail = &bytes[ROOM_LEN..];
                let public_key = if tail.is_empty() {
                    None
                } else {
                    Some(PublicKey::new(tail)?)
                };
                if kind == mt::MESSENGER_ROOM_OPEN {
                    Ok(Self::Open {
                        room: fields,
                        public_key,
                    })
                } else {
                    Ok(Self::Entry {
                        room: fields,
                        public_key,
                    })
                }
            }
            mt::MESSENGER_ROOM_CLOSE => {
                exact(bytes, ROOM_LEN)?;
                Ok(Self::Close { room: room(bytes)? })
            }
            mt::MESSENGER_ROOM_SYNC => {
                exact(bytes, ROOM_LEN)?;
                Ok(Self::Sync { room: room(bytes)? })
            }
            mt::MESSENGER_ROOM_SEND_MESSAGE => {
                let key = array(bytes, 4)?;
                Ok(Self::Send {
                    key,
                    message: SensitiveBytes::new(&bytes[SEND_PREFIX..]),
                })
            }
            mt::MESSENGER_ROOM_GET_MESSAGE => {
                exact(bytes, GET_LEN)?;
                Ok(Self::Get {
                    key: array(bytes, 4)?,
                    hash: array(bytes, 68)?,
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Actual official message type, not an invented per-operation identifier.
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::Create => mt::MESSENGER_CONNECTION_CREATE,
            Self::Destroy => mt::MESSENGER_CONNECTION_DESTROY,
            Self::Open { .. } => mt::MESSENGER_ROOM_OPEN,
            Self::Entry { .. } => mt::MESSENGER_ROOM_ENTRY,
            Self::Close { .. } => mt::MESSENGER_ROOM_CLOSE,
            Self::Sync { .. } => mt::MESSENGER_ROOM_SYNC,
            Self::Send { .. } => mt::MESSENGER_ROOM_SEND_MESSAGE,
            Self::Get { .. } => mt::MESSENGER_ROOM_GET_MESSAGE,
        }
    }
    /// Entire outer frame size. An inner message's semantic validity is separate.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::Create | Self::Destroy => Ok(4),
            Self::Open { public_key, .. } | Self::Entry { public_key, .. } => {
                size(self.message_type(), ROOM_LEN, public_key.map_or(0, |_| 36))
            }
            Self::Close { .. } | Self::Sync { .. } => Ok(ROOM_LEN),
            Self::Send { message, .. } => size(self.message_type(), SEND_PREFIX, message.len()),
            Self::Get { .. } => Ok(GET_LEN),
        }
    }
    /// Encode after all size/capacity checks, preserving caller output on failure.
    pub fn encode(self, output: &mut [u8]) -> Result<usize, Error> {
        let n = self.encoded_len()?;
        if output.len() < n {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(self.message_type(), n)?.encode(output)?;
        match self {
            Self::Create | Self::Destroy => {}
            Self::Open { room, public_key } | Self::Entry { room, public_key } => {
                put_room(output, room);
                if let Some(key) = public_key {
                    output[ROOM_LEN..n].copy_from_slice(key.as_bytes());
                }
            }
            Self::Close { room } | Self::Sync { room } => put_room(output, room),
            Self::Send { key, message } => {
                output[4..68].copy_from_slice(key);
                output[SEND_PREFIX..n].copy_from_slice(message.expose());
            }
            Self::Get { key, hash } => {
                output[4..68].copy_from_slice(key);
                output[68..132].copy_from_slice(hash);
            }
        }
        Ok(n)
    }
}
/// Actual active service notifications. None establishes cryptographic validity,
/// remote delivery, or a completed local room/member state transition by itself.
#[derive(Clone, Copy)]
pub enum Response<'a> {
    /// Current original room member id and raw reset value.
    MemberId {
        /// Original room key.
        key: &'a [u8; 64],
        /// Original member id.
        id: &'a [u8; 32],
        /// Original producer-native reset value, including unknown values.
        reset: u32,
    },
    /// Actual open-room notification.
    Open(Room<'a>),
    /// Actual enter-room notification.
    Entry(Room<'a>),
    /// Actual close-room notification.
    Close(Room<'a>),
    /// Actual room synchronization state.
    Sync(Room<'a>),
    /// Actual missing-message notification, not a generic request ACK.
    Missing {
        /// Original room key.
        key: &'a [u8; 64],
        /// Actual absent message hash.
        hash: &'a [u8; 64],
    },
    /// Actual received encoded message and its original attribution metadata.
    Receive {
        /// Original room key.
        key: &'a [u8; 64],
        /// Original sender hash.
        sender: &'a [u8; 64],
        /// Original context hash.
        context: &'a [u8; 64],
        /// Original message hash.
        hash: &'a [u8; 64],
        /// Original epoch hash.
        epoch: &'a [u8; 64],
        /// Original BE32 flags, including unknown bits.
        flags: u32,
        /// Original sensitive encoded message bytes.
        message: SensitiveBytes<'a>,
    },
}
impl fmt::Debug for Response<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerResponse")
            .field("type", &self.message_type())
            .field("encoded_bytes", &self.encoded_len())
            .finish()
    }
}
impl<'a> Response<'a> {
    /// Decode exactly one actual outer notification, borrowing opaque message data.
    pub fn decode(bytes: &'a [u8], profile: profile::Profile) -> Result<Self, Error> {
        profile.validate()?;
        let frame = Frame::decode(bytes)?;
        match frame.header().message_type() {
            mt::MESSENGER_CONNECTION_MEMBER_ID => {
                exact(bytes, MEMBER_LEN)?;
                Ok(Self::MemberId {
                    key: array(bytes, 4)?,
                    id: array(bytes, 68)?,
                    reset: profile.endian.read_u32(*array(bytes, 100)?),
                })
            }
            kind @ (mt::MESSENGER_ROOM_OPEN
            | mt::MESSENGER_ROOM_ENTRY
            | mt::MESSENGER_ROOM_CLOSE
            | mt::MESSENGER_ROOM_SYNC) => {
                exact(bytes, ROOM_LEN)?;
                let r = room(bytes)?;
                Ok(match kind {
                    mt::MESSENGER_ROOM_OPEN => Self::Open(r),
                    mt::MESSENGER_ROOM_ENTRY => Self::Entry(r),
                    mt::MESSENGER_ROOM_CLOSE => Self::Close(r),
                    _ => Self::Sync(r),
                })
            }
            mt::MESSENGER_ROOM_GET_MESSAGE => {
                exact(bytes, GET_LEN)?;
                Ok(Self::Missing {
                    key: array(bytes, 4)?,
                    hash: array(bytes, 68)?,
                })
            }
            mt::MESSENGER_ROOM_RECV_MESSAGE => {
                let flags = u32::from_be_bytes(*array(bytes, 324)?);
                Ok(Self::Receive {
                    key: array(bytes, 4)?,
                    sender: array(bytes, 68)?,
                    context: array(bytes, 132)?,
                    hash: array(bytes, 196)?,
                    epoch: array(bytes, 260)?,
                    flags,
                    message: SensitiveBytes::new(&bytes[RECV_PREFIX..]),
                })
            }
            _ => Err(Error::Unsupported),
        }
    }
    /// Actual official notification type.
    pub const fn message_type(self) -> MessageType {
        match self {
            Self::MemberId { .. } => mt::MESSENGER_CONNECTION_MEMBER_ID,
            Self::Open(_) => mt::MESSENGER_ROOM_OPEN,
            Self::Entry(_) => mt::MESSENGER_ROOM_ENTRY,
            Self::Close(_) => mt::MESSENGER_ROOM_CLOSE,
            Self::Sync(_) => mt::MESSENGER_ROOM_SYNC,
            Self::Missing { .. } => mt::MESSENGER_ROOM_GET_MESSAGE,
            Self::Receive { .. } => mt::MESSENGER_ROOM_RECV_MESSAGE,
        }
    }
    /// Entire outer notification length, checked against the official BE16 limit.
    pub fn encoded_len(self) -> Result<usize, Error> {
        match self {
            Self::MemberId { .. } => Ok(MEMBER_LEN),
            Self::Open(_) | Self::Entry(_) | Self::Close(_) | Self::Sync(_) => Ok(ROOM_LEN),
            Self::Missing { .. } => Ok(GET_LEN),
            Self::Receive { message, .. } => size(self.message_type(), RECV_PREFIX, message.len()),
        }
    }
    /// Encode without data allocation. Size/capacity failure preserves output.
    pub fn encode(self, profile: profile::Profile, output: &mut [u8]) -> Result<usize, Error> {
        profile.validate()?;
        let n = self.encoded_len()?;
        if output.len() < n {
            return Err(Error::Capacity);
        }
        MessageHeader::from_total_size(self.message_type(), n)?.encode(output)?;
        match self {
            Self::MemberId { key, id, reset } => {
                output[4..68].copy_from_slice(key);
                output[68..100].copy_from_slice(id);
                output[100..104].copy_from_slice(&profile.endian.write_u32(reset));
            }
            Self::Open(r) | Self::Entry(r) | Self::Close(r) | Self::Sync(r) => put_room(output, r),
            Self::Missing { key, hash } => {
                output[4..68].copy_from_slice(key);
                output[68..132].copy_from_slice(hash);
            }
            Self::Receive {
                key,
                sender,
                context,
                hash,
                epoch,
                flags,
                message,
            } => {
                output[4..68].copy_from_slice(key);
                output[68..132].copy_from_slice(sender);
                output[132..196].copy_from_slice(context);
                output[196..260].copy_from_slice(hash);
                output[260..324].copy_from_slice(epoch);
                output[324..328].copy_from_slice(&flags.to_be_bytes());
                output[RECV_PREFIX..n].copy_from_slice(message.expose());
            }
        }
        Ok(n)
    }
}
