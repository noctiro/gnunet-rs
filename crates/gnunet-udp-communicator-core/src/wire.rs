//! Exact v0.29.1 byte fields, independent of native structs and allocators.
use crate::PeerId;
use gnunet_types::Error;
/// Prefix shared by InitialKX and UDPBox: public selector32 then GCM tag16.
pub const PREFIX: usize = 48;
/// peer32, signature64 and monotonic timestampBE64.
pub const CONFIRMATION: usize = 104;
/// Complete purpose33 signed region (purpose8 + two peers64 + enc32 + time8).
pub const HANDSHAKE_SIGNED: usize = 112;
/// Official UDP backchannel ACK type.
pub const ACK: u16 = 1460;
/// Official encrypted padding type.
pub const PAD: u16 = 1461;
/// Official in-box ordinary-KEM rekey type.
pub const REKEY: u16 = 1462;
/// Public authenticated-header fields; decoding itself asserts no authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Confirmation {
    /// Claimed sender identity.
    pub sender: PeerId,
    /// Purpose33 signature, checked separately against the complete transcript.
    pub signature: [u8; 64],
    /// Monotonic sender timestamp, not wall-clock expiry.
    pub monotonic: u64,
}
impl Confirmation {
    /// Decode the fixed prefix, preserving following encrypted-payload plaintext.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        let b = input.get(..CONFIRMATION).ok_or(Error::Truncated)?;
        Ok(Self {
            sender: b[..32].try_into().map_err(|_| Error::Truncated)?,
            signature: b[32..96].try_into().map_err(|_| Error::Truncated)?,
            monotonic: u64::from_be_bytes(b[96..104].try_into().map_err(|_| Error::Truncated)?),
        })
    }
    /// Capacity refusal leaves output unchanged.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let b = out.get_mut(..CONFIRMATION).ok_or(Error::Capacity)?;
        b[..32].copy_from_slice(&self.sender);
        b[32..96].copy_from_slice(&self.signature);
        b[96..104].copy_from_slice(&self.monotonic.to_be_bytes());
        Ok(CONFIRMATION)
    }
}
/// Exactly the source UdpHandshakeSignature; no C padding or private context.
#[must_use]
pub fn handshake_region(
    sender: PeerId,
    receiver: PeerId,
    enc: &[u8; 32],
    monotonic: u64,
) -> [u8; HANDSHAKE_SIGNED] {
    let mut b = [0; HANDSHAKE_SIGNED];
    b[..4].copy_from_slice(&(HANDSHAKE_SIGNED as u32).to_be_bytes());
    b[4..8].copy_from_slice(&33u32.to_be_bytes());
    b[8..40].copy_from_slice(&sender);
    b[40..72].copy_from_slice(&receiver);
    b[72..104].copy_from_slice(enc);
    b[104..].copy_from_slice(&monotonic.to_be_bytes());
    b
}
/// Master-wide64-byte HKDF marker, not an AES-CMAC or payload authentication tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ack {
    /// Highest cached BOX sequence offered by the receiver.
    pub allowed: u32,
    /// Exact secret acknowledgement marker.
    pub cmac: [u8; 64],
}
fn prefix(input: &[u8], expected: u16, minimum: usize) -> Result<usize, Error> {
    let h = input.get(..4).ok_or(Error::Truncated)?;
    let n = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if u16::from_be_bytes([h[2], h[3]]) != expected || n < minimum {
        return Err(Error::Malformed);
    }
    if input.len() < n {
        return Err(Error::Truncated);
    }
    Ok(n)
}
impl Ack {
    /// Source encrypted ACK accepts extensions in its declared extent; tail is
    /// separate plaintext. Backchannel decoding below requires the exact72 bytes.
    pub fn decode_prefix(input: &[u8]) -> Result<(Self, usize), Error> {
        let n = prefix(input, ACK, 72)?;
        Ok((
            Self {
                allowed: u32::from_be_bytes(input[4..8].try_into().map_err(|_| Error::Truncated)?),
                cmac: input[8..72].try_into().map_err(|_| Error::Truncated)?,
            },
            n,
        ))
    }
    /// Actual enc_notify_cb accepts only the exact complete72-byte message.
    pub fn decode_backchannel(input: &[u8]) -> Result<Self, Error> {
        let (ack, n) = Self::decode_prefix(input)?;
        if n != 72 || input.len() != 72 {
            return Err(Error::Malformed);
        }
        Ok(ack)
    }
    /// Emit one complete official ACK, before any optional payload/padding.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let b = out.get_mut(..72).ok_or(Error::Capacity)?;
        b[..2].copy_from_slice(&72u16.to_be_bytes());
        b[2..4].copy_from_slice(&ACK.to_be_bytes());
        b[4..8].copy_from_slice(&self.allowed.to_be_bytes());
        b[8..].copy_from_slice(&self.cmac);
        Ok(72)
    }
}
/// Authenticated ordinary0x0020 encapsulation; distinct from initial Elligator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rekey(pub [u8; 32]);
impl Rekey {
    /// Source encrypted REKEY accepts a declared extent of at least36 bytes.
    pub fn decode_prefix(input: &[u8]) -> Result<(Self, usize), Error> {
        let n = prefix(input, REKEY, 36)?;
        Ok((
            Self(input[4..36].try_into().map_err(|_| Error::Truncated)?),
            n,
        ))
    }
    /// Encode one complete36-byte official rekey header.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let b = out.get_mut(..36).ok_or(Error::Capacity)?;
        b[..2].copy_from_slice(&36u16.to_be_bytes());
        b[2..4].copy_from_slice(&REKEY.to_be_bytes());
        b[4..].copy_from_slice(&self.0);
        Ok(36)
    }
}
/// One source-compatible leading communicator control.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    /// Secret/window acknowledgement, not application delivery.
    Ack(Ack),
    /// New ordinary KEM secret inside an authenticated datagram.
    Rekey(Rekey),
}
/// Borrowed plaintext boundaries; parsing releases no business ACK or replay credit.
pub struct Body<'a> {
    /// At most one leading source-compatible communicator control.
    pub control: Option<Control>,
    /// First following common-framed payload, if any.
    pub message: Option<&'a [u8]>,
    /// Remaining encrypted padding, never silently treated as another payload.
    pub padding: &'a [u8],
}
impl<'a> Body<'a> {
    /// Fixed C sends one application message, optionally preceded by one control.
    /// Its remaining padding can have a PAD header or just1..4 random bytes.
    pub fn decode(input: &'a [u8]) -> Result<Self, Error> {
        let Some(h) = input.get(..4) else {
            return Ok(Self {
                control: None,
                message: None,
                padding: input,
            });
        };
        let kind = u16::from_be_bytes([h[2], h[3]]);
        let (control, rest) = match kind {
            ACK => {
                let (c, n) = Ack::decode_prefix(input)?;
                (Some(Control::Ack(c)), &input[n..])
            }
            REKEY => {
                let (c, n) = Rekey::decode_prefix(input)?;
                (Some(Control::Rekey(c)), &input[n..])
            }
            PAD => {
                return Ok(Self {
                    control: None,
                    message: None,
                    padding: input,
                });
            }
            _ => (None, input),
        };
        let Some(h) = rest.get(..4) else {
            return Ok(Self {
                control,
                message: None,
                padding: rest,
            });
        };
        let n = usize::from(u16::from_be_bytes([h[0], h[1]]));
        let kind = u16::from_be_bytes([h[2], h[3]]);
        if n < 4 || n > rest.len() {
            return if control.is_some() {
                Ok(Self {
                    control,
                    message: None,
                    padding: rest,
                })
            } else {
                Err(Error::Malformed)
            };
        }
        if kind == PAD {
            return Ok(Self {
                control,
                message: None,
                padding: rest,
            });
        }
        if kind == ACK || kind == REKEY {
            return Err(Error::Malformed);
        }
        Ok(Self {
            control,
            message: Some(&rest[..n]),
            padding: &rest[n..],
        })
    }
}
/// Clear LAN broadcast; its signature binds an explicit source address hash.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Broadcast {
    /// Claimed broadcaster.
    pub sender: PeerId,
    /// Purpose34 signature; native address normalization remains a host boundary.
    pub signature: [u8; 64],
}
impl Broadcast {
    /// A broadcast is exactly96 bytes and has no common message header.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        if input.len() != 96 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            sender: input[..32].try_into().map_err(|_| Error::Truncated)?,
            signature: input[32..].try_into().map_err(|_| Error::Truncated)?,
        })
    }
    /// Capacity refusal is atomic.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let b = out.get_mut(..96).ok_or(Error::Capacity)?;
        b[..32].copy_from_slice(&self.sender);
        b[32..].copy_from_slice(&self.signature);
        Ok(96)
    }
}
/// Exact purpose34 region with an explicitly provided source address SHA512.
#[must_use]
pub fn broadcast_region(sender: PeerId, address_hash: &[u8; 64]) -> [u8; 104] {
    let mut b = [0; 104];
    b[..4].copy_from_slice(&104u32.to_be_bytes());
    b[4..8].copy_from_slice(&34u32.to_be_bytes());
    b[8..40].copy_from_slice(&sender);
    b[40..].copy_from_slice(address_hash);
    b
}
