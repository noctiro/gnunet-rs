//! Conditional official CONVERSATION IPC, CADET and helper audio frames.
//!
//! These borrowed formats authenticate no caller, signature, expiration, source
//! or media. Call carries private key bytes and deliberately has no Debug/Clone.
//! Opaque key/signature extents are retained; the actual cryptographic owner
//! must validate their supported typed encoding before use.
use super::{Frame, MessageHeader, MessageType, message_type as mt};
use gnunet_types::Error;
/// Official signed ringing purpose.
pub const RING_PURPOSE: u32 = 20;
/// Exact signed purpose/port/target/expiration extent.
pub const RING_INFO_BYTES: usize = 112;
fn array<const N: usize>(b: &[u8], at: usize) -> Result<&[u8; N], Error> {
    b.get(at..at.checked_add(N).ok_or(Error::Overflow)?)
        .ok_or(Error::Truncated)?
        .try_into()
        .map_err(|_| Error::Truncated)
}
fn u32be(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_be_bytes(*array(b, at)?))
}
fn u64be(b: &[u8], at: usize) -> Result<u64, Error> {
    Ok(u64::from_be_bytes(*array(b, at)?))
}
fn extent(prefix: usize, a: usize, b: usize) -> Result<usize, Error> {
    prefix
        .checked_add(a)
        .and_then(|n| n.checked_add(b))
        .ok_or(Error::Overflow)
}
fn exact(b: &[u8], n: usize) -> Result<(), Error> {
    if b.len() != n {
        return Err(Error::Malformed);
    }
    Ok(())
}
/// Standard client control operations. Direction and call state are business rules.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientControl {
    /// Local phone accepts an incoming ringing call.
    PickUp,
    /// Local or remote call ends.
    HangUp,
    /// Audio is suspended.
    Suspend,
    /// Audio is resumed.
    Resume,
    /// Service reports the remote side picked up.
    PickedUp,
}
impl ClientControl {
    fn kind(self) -> MessageType {
        match self {
            Self::PickUp => mt::CONVERSATION_CS_PHONE_PICK_UP,
            Self::HangUp => mt::CONVERSATION_CS_PHONE_HANG_UP,
            Self::Suspend => mt::CONVERSATION_CS_PHONE_SUSPEND,
            Self::Resume => mt::CONVERSATION_CS_PHONE_RESUME,
            Self::PickedUp => mt::CONVERSATION_CS_PHONE_PICKED_UP,
        }
    }
    fn decode(t: MessageType) -> Result<Self, Error> {
        match t {
            mt::CONVERSATION_CS_PHONE_PICK_UP => Ok(Self::PickUp),
            mt::CONVERSATION_CS_PHONE_HANG_UP => Ok(Self::HangUp),
            mt::CONVERSATION_CS_PHONE_SUSPEND => Ok(Self::Suspend),
            mt::CONVERSATION_CS_PHONE_RESUME => Ok(Self::Resume),
            mt::CONVERSATION_CS_PHONE_PICKED_UP => Ok(Self::PickedUp),
            _ => Err(Error::Unsupported),
        }
    }
}
/// Header-only CADET control operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerControl {
    /// Remote call ends.
    HangUp,
    /// Incoming call is accepted.
    PickUp,
    /// Remote audio is suspended.
    Suspend,
    /// Remote audio is resumed.
    Resume,
}
impl PeerControl {
    fn kind(self) -> MessageType {
        match self {
            Self::HangUp => mt::CONVERSATION_CADET_PHONE_HANG_UP,
            Self::PickUp => mt::CONVERSATION_CADET_PHONE_PICK_UP,
            Self::Suspend => mt::CONVERSATION_CADET_PHONE_SUSPEND,
            Self::Resume => mt::CONVERSATION_CADET_PHONE_RESUME,
        }
    }
    fn decode(t: MessageType) -> Result<Self, Error> {
        match t {
            mt::CONVERSATION_CADET_PHONE_HANG_UP => Ok(Self::HangUp),
            mt::CONVERSATION_CADET_PHONE_PICK_UP => Ok(Self::PickUp),
            mt::CONVERSATION_CADET_PHONE_SUSPEND => Ok(Self::Suspend),
            mt::CONVERSATION_CADET_PHONE_RESUME => Ok(Self::Resume),
            _ => Err(Error::Unsupported),
        }
    }
}
/// One actual complete message. Private call material and audio are not printable
/// through Debug and are never copied into an owned generic frame by this codec.
pub enum Message<'a> {
    /// Original helper audio payload730, without a client call ID.
    HelperAudio(&'a [u8]),
    /// Register731 at an original CADET port.
    Register {
        /// Raw official reserved field; new ordinary producers use zero.
        reserved: u32,
        /// Exact port hash.
        port: &'a [u8; 64],
    },
    /// Outgoing local request734. Key material is the original private encoding.
    Call {
        /// Raw official reserved field.
        reserved: u32,
        /// Target peer identity.
        target: &'a [u8; 32],
        /// Target port hash.
        port: &'a [u8; 64],
        /// Original complete typed private key; owner must erase its storage.
        private_key: &'a [u8],
    },
    /// Service notification735, with the original caller public key.
    Ring {
        /// Original CID bytes interpreted big endian. C also raw-copies native
        /// CID values; this number's high bit never establishes call authority.
        cid: u32,
        /// Complete typed public key encoding.
        public_key: &'a [u8],
    },
    /// Exact local CID control732/733/736/737/738.
    Control {
        /// Actual operation.
        action: ClientControl,
        /// Original local call identifier.
        cid: u32,
    },
    /// Original local audio739.
    Audio {
        /// Original local call identifier.
        cid: u32,
        /// Opaque original compressed audio bytes.
        data: &'a [u8],
    },
    /// Actual signed caller introduction740 over the admitted CADET channel.
    PeerRing {
        /// Raw official reserved field.
        reserved: u32,
        /// Original absolute UTC microseconds.
        expiration: u64,
        /// Complete typed caller public key.
        public_key: &'a [u8],
        /// Complete typed signature over RingInfo, never over this frame.
        signature: &'a [u8],
    },
    /// Header-only peer control741–744; contains no CID or invented receipt.
    PeerControl(PeerControl),
    /// Original peer audio745; contains no local CID.
    PeerAudio(&'a [u8]),
}
impl<'a> Message<'a> {
    /// Decode exactly one complete frame, preserving reserved and original bytes.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let f = Frame::decode(input)?;
        let t = f.header().message_type();
        match t {
            mt::CONVERSATION_AUDIO => Ok(Self::HelperAudio(&input[4..])),
            mt::CONVERSATION_CS_PHONE_REGISTER => {
                exact(input, 72)?;
                Ok(Self::Register {
                    reserved: u32be(input, 4)?,
                    port: array(input, 8)?,
                })
            }
            mt::CONVERSATION_CS_PHONE_CALL => {
                let n = usize::try_from(u32be(input, 104)?).map_err(|_| Error::TooLarge)?;
                exact(input, extent(108, n, 0)?)?;
                Ok(Self::Call {
                    reserved: u32be(input, 4)?,
                    target: array(input, 8)?,
                    port: array(input, 40)?,
                    private_key: &input[108..],
                })
            }
            mt::CONVERSATION_CS_PHONE_RING => {
                let n = usize::try_from(u32be(input, 8)?).map_err(|_| Error::TooLarge)?;
                exact(input, extent(12, n, 0)?)?;
                Ok(Self::Ring {
                    cid: u32be(input, 4)?,
                    public_key: &input[12..],
                })
            }
            mt::CONVERSATION_CS_AUDIO => Ok(Self::Audio {
                cid: u32be(input, 4)?,
                data: input.get(8..).ok_or(Error::Truncated)?,
            }),
            mt::CONVERSATION_CADET_PHONE_RING => {
                let key = usize::try_from(u32be(input, 16)?).map_err(|_| Error::TooLarge)?;
                let sig = usize::try_from(u32be(input, 20)?).map_err(|_| Error::TooLarge)?;
                exact(input, extent(24, key, sig)?)?;
                let end = extent(24, key, 0)?;
                Ok(Self::PeerRing {
                    reserved: u32be(input, 4)?,
                    expiration: u64be(input, 8)?,
                    public_key: &input[24..end],
                    signature: &input[end..],
                })
            }
            mt::CONVERSATION_CADET_AUDIO => Ok(Self::PeerAudio(&input[4..])),
            _ => {
                if let Ok(action) = ClientControl::decode(t) {
                    exact(input, 8)?;
                    Ok(Self::Control {
                        action,
                        cid: u32be(input, 4)?,
                    })
                } else {
                    let action = PeerControl::decode(t)?;
                    exact(input, 4)?;
                    Ok(Self::PeerControl(action))
                }
            }
        }
    }
    fn shape(&self) -> Result<(MessageType, usize), Error> {
        let (kind, n) = match self {
            Self::HelperAudio(b) => (mt::CONVERSATION_AUDIO, extent(4, b.len(), 0)?),
            Self::Register { .. } => (mt::CONVERSATION_CS_PHONE_REGISTER, 72),
            Self::Call { private_key, .. } => (
                mt::CONVERSATION_CS_PHONE_CALL,
                extent(108, private_key.len(), 0)?,
            ),
            Self::Ring { public_key, .. } => (
                mt::CONVERSATION_CS_PHONE_RING,
                extent(12, public_key.len(), 0)?,
            ),
            Self::Control { action, .. } => (action.kind(), 8),
            Self::Audio { data, .. } => (mt::CONVERSATION_CS_AUDIO, extent(8, data.len(), 0)?),
            Self::PeerRing {
                public_key,
                signature,
                ..
            } => (
                mt::CONVERSATION_CADET_PHONE_RING,
                extent(24, public_key.len(), signature.len())?,
            ),
            Self::PeerControl(action) => (action.kind(), 4),
            Self::PeerAudio(b) => (mt::CONVERSATION_CADET_AUDIO, extent(4, b.len(), 0)?),
        };
        MessageHeader::from_total_size(kind, n)?;
        Ok((kind, n))
    }
    /// Checked complete extent, before any output or admission.
    pub fn encoded_len(&self) -> Result<usize, Error> {
        Ok(self.shape()?.1)
    }
    /// Encode into caller storage. Every fallible shape/extent check precedes
    /// mutation; no private allocation, signature or media conversion occurs.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let (kind, n) = self.shape()?;
        if out.len() < n {
            return Err(Error::Capacity);
        }
        let out = &mut out[..n];
        MessageHeader::from_total_size(kind, n)?.encode(out)?;
        match self {
            Self::HelperAudio(b) | Self::PeerAudio(b) => out[4..].copy_from_slice(b),
            Self::Register { reserved, port } => {
                out[4..8].copy_from_slice(&reserved.to_be_bytes());
                out[8..72].copy_from_slice(*port);
            }
            Self::Call {
                reserved,
                target,
                port,
                private_key,
            } => {
                out[4..8].copy_from_slice(&reserved.to_be_bytes());
                out[8..40].copy_from_slice(*target);
                out[40..104].copy_from_slice(*port);
                out[104..108].copy_from_slice(&(private_key.len() as u32).to_be_bytes());
                out[108..].copy_from_slice(private_key);
            }
            Self::Ring { cid, public_key } => {
                out[4..8].copy_from_slice(&cid.to_be_bytes());
                out[8..12].copy_from_slice(&(public_key.len() as u32).to_be_bytes());
                out[12..].copy_from_slice(public_key);
            }
            Self::Control { cid, .. } => out[4..8].copy_from_slice(&cid.to_be_bytes()),
            Self::Audio { cid, data } => {
                out[4..8].copy_from_slice(&cid.to_be_bytes());
                out[8..].copy_from_slice(data);
            }
            Self::PeerRing {
                reserved,
                expiration,
                public_key,
                signature,
            } => {
                let end = 24 + public_key.len();
                out[4..8].copy_from_slice(&reserved.to_be_bytes());
                out[8..16].copy_from_slice(&expiration.to_be_bytes());
                out[16..20].copy_from_slice(&(public_key.len() as u32).to_be_bytes());
                out[20..24].copy_from_slice(&(signature.len() as u32).to_be_bytes());
                out[24..end].copy_from_slice(public_key);
                out[end..].copy_from_slice(signature);
            }
            Self::PeerControl(_) => {}
        }
        Ok(n)
    }
}
/// Exact signed ringing context reconstructed from original local port/peer and
/// original message expiration. Its source binding and authentication are external.
pub struct RingInfo<'a> {
    /// Original called port.
    pub port: &'a [u8; 64],
    /// Original target peer identity, not the caller identity.
    pub target: &'a [u8; 32],
    /// Original absolute UTC microseconds.
    pub expiration: u64,
}
impl RingInfo<'_> {
    /// Encode exactly112 signed bytes including BE32 size and purpose20.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let out = out.get_mut(..RING_INFO_BYTES).ok_or(Error::Capacity)?;
        out[..4].copy_from_slice(&(RING_INFO_BYTES as u32).to_be_bytes());
        out[4..8].copy_from_slice(&RING_PURPOSE.to_be_bytes());
        out[8..72].copy_from_slice(self.port);
        out[72..104].copy_from_slice(self.target);
        out[104..112].copy_from_slice(&self.expiration.to_be_bytes());
        Ok(RING_INFO_BYTES)
    }
}

/// Exact version/reserved/peer/port GNS PHONE record extent.
pub const PHONE_RECORD_BYTES: usize = 104;
/// Original public PHONE value. Shape does not qualify its version, GNS source,
/// expiration, target peer or CADET line. Consumers select their actual profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhoneRecord {
    /// Original BE32 version. Standard current producers use one.
    pub version: u32,
    /// Original BE32 reserved word. Current v1 producers use zero.
    pub reserved: u32,
    /// Original public peer hosting the line.
    pub peer: [u8; 32],
    /// Exact CADET port hash, not a locally invented numeric line.
    pub port: [u8; 64],
}
impl PhoneRecord {
    /// Construct the actual current standard version1/reserved0 record.
    #[must_use]
    pub const fn v1(peer: [u8; 32], port: [u8; 64]) -> Self {
        Self {
            version: 1,
            reserved: 0,
            peer,
            port,
        }
    }
    /// Borrow no storage and preserve every original field after exact sizing.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        exact(input, PHONE_RECORD_BYTES)?;
        Ok(Self {
            version: u32be(input, 0)?,
            reserved: u32be(input, 4)?,
            peer: *array(input, 8)?,
            port: *array(input, 40)?,
        })
    }
    /// Encode in caller storage, preserving output on capacity refusal.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize, Error> {
        let out = output
            .get_mut(..PHONE_RECORD_BYTES)
            .ok_or(Error::Capacity)?;
        out[..4].copy_from_slice(&self.version.to_be_bytes());
        out[4..8].copy_from_slice(&self.reserved.to_be_bytes());
        out[8..40].copy_from_slice(&self.peer);
        out[40..104].copy_from_slice(&self.port);
        Ok(PHONE_RECORD_BYTES)
    }
}
