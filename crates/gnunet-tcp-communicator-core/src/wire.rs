//! Exact private TCP communicator wire layouts; BOX length excludes its prefix.
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature};
use gnunet_types::Error;
use gnunet_wire::official::message_type as mt;
/// Source `TCPBox`, also fixed FINISH size.
pub const BOX_PREFIX: usize = 36;
/// Maximum full BOX: payload65535 plus prefix36.
pub const MAX_RECORD: usize = gnunet_wire::official::MAX_MESSAGE_SIZE + BOX_PREFIX;
/// Source `TCPConfirmation`, without its representative prefix.
pub const CONFIRMATION: usize = 136;
/// Representative32 followed by encrypted confirmation136.
pub const INITIAL_KX: usize = 168;
/// Source signed confirmation acknowledgement.
pub const ACK: usize = 140;
/// Source authenticated rekey record.
pub const REKEY: usize = 140;
/// Official communicator message types; these are not negotiated aliases.
pub const REKEY_TYPE: u16 = mt::COMMUNICATOR_TCP_REKEY.value();
/// Official BOX message type.
pub const BOX_TYPE: u16 = mt::COMMUNICATOR_TCP_BOX.value();
/// Official FINISH message type.
pub const FINISH_TYPE: u16 = mt::COMMUNICATOR_TCP_FINISH.value();
/// Official confirmation acknowledgement message type.
pub const ACK_TYPE: u16 = mt::COMMUNICATOR_TCP_CONFIRMATION_ACK.value();
/// Official initial handshake signature purpose.
pub const HANDSHAKE_PURPOSE: u32 = 31;
/// Official rekey signature purpose.
pub const REKEY_PURPOSE: u32 = 32;
/// Official acknowledgement signature purpose.
pub const ACK_PURPOSE: u32 = 39;
/// An untrusted Elligator representative; not an ordinary X25519 public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Representative(pub [u8; 32]);
/// Exact one-record framing extent, with no protocol/admission authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Shape {
    /// Payload length excludes the36-byte prefix.
    Box(u16),
    /// Fixed140-byte signed acknowledgement, without a ratcheting MAC.
    Ack,
    /// Fixed140-byte authenticated rekey.
    Rekey,
    /// Fixed36-byte authenticated FINISH.
    Finish,
}
impl Shape {
    /// Read four decrypted bytes, checking fixed record sizes.
    pub fn decode(header: &[u8]) -> Result<Self, Error> {
        let h: &[u8; 4] = header
            .get(..4)
            .ok_or(Error::Truncated)?
            .try_into()
            .map_err(|_| Error::Truncated)?;
        let size = u16::from_be_bytes([h[0], h[1]]) as usize;
        match u16::from_be_bytes([h[2], h[3]]) {
            BOX_TYPE => Ok(Self::Box(size as u16)),
            ACK_TYPE if size == ACK => Ok(Self::Ack),
            REKEY_TYPE if size == REKEY => Ok(Self::Rekey),
            FINISH_TYPE if size == BOX_PREFIX => Ok(Self::Finish),
            ACK_TYPE | REKEY_TYPE | FINISH_TYPE => Err(Error::Malformed),
            _ => Err(Error::Unsupported),
        }
    }
    /// Full bytes consumed from this encrypted stream record.
    #[must_use]
    pub const fn length(self) -> usize {
        match self {
            Self::Box(n) => BOX_PREFIX + n as usize,
            Self::Ack => ACK,
            Self::Rekey => REKEY,
            Self::Finish => BOX_PREFIX,
        }
    }
}
/// Borrowed source identity/signature/timestamp/challenge fields.
#[derive(Clone, Copy)]
pub struct Confirmation<'a> {
    bytes: &'a [u8; CONFIRMATION],
    challenge: &'a [u8; 32],
}
impl<'a> Confirmation<'a> {
    /// Retain exactly136 bytes; trailing bytes belong to the next protocol item.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        let bytes: &'a [u8; CONFIRMATION] = bytes.try_into().map_err(|_| {
            if bytes.len() < CONFIRMATION {
                Error::Truncated
            } else {
                Error::Malformed
            }
        })?;
        Ok(Self {
            bytes,
            challenge: bytes[104..].try_into().map_err(|_| Error::Malformed)?,
        })
    }
    /// Claimed source sender, without verification/admission.
    #[must_use]
    pub fn sender(self) -> EddsaPublicKey {
        EddsaPublicKey::from_bytes(array(&self.bytes[..32]))
    }
    /// Sender's source monotonic microseconds, not receiver wall-clock freshness.
    #[must_use]
    pub fn monotonic(self) -> u64 {
        u64::from_be_bytes(array(&self.bytes[96..104]))
    }
    /// Exact caller-generated opaque32-byte challenge.
    #[must_use]
    pub fn challenge(self) -> &'a [u8; 32] {
        self.challenge
    }
    /// Verify the source signed region, including intended receiver and representative.
    /// This does not commit peerstore replay state or admit a transport queue.
    pub fn verify(self, receiver: EddsaPublicKey, enc: Representative) -> Result<(), Error> {
        let region = handshake_region(
            self.sender(),
            receiver,
            enc,
            self.monotonic(),
            self.challenge(),
        );
        self.sender().verify(
            HANDSHAKE_PURPOSE,
            &region,
            &EddsaSignature::from_bytes(array(&self.bytes[32..96])),
        )
    }
}
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0; N];
    out.copy_from_slice(bytes);
    out
}
fn purpose<const N: usize>(number: u32) -> [u8; N] {
    let mut out = [0; N];
    out[..4].copy_from_slice(&(N as u32).to_be_bytes());
    out[4..8].copy_from_slice(&number.to_be_bytes());
    out
}
/// Reconstruct source `TcpHandshakeSignature` size144 and exact field order.
#[must_use]
pub fn handshake_region(
    sender: EddsaPublicKey,
    receiver: EddsaPublicKey,
    enc: Representative,
    mono: u64,
    challenge: &[u8; 32],
) -> [u8; 144] {
    let mut out = purpose(HANDSHAKE_PURPOSE);
    out[8..40].copy_from_slice(sender.as_bytes());
    out[40..72].copy_from_slice(receiver.as_bytes());
    out[72..104].copy_from_slice(&enc.0);
    out[104..112].copy_from_slice(&mono.to_be_bytes());
    out[112..].copy_from_slice(challenge);
    out
}
/// Reconstruct source `TcpHandshakeAckSignature` size112.
#[must_use]
pub fn ack_region(
    sender: EddsaPublicKey,
    receiver: EddsaPublicKey,
    mono: u64,
    challenge: &[u8; 32],
) -> [u8; 112] {
    let mut out = purpose(ACK_PURPOSE);
    out[8..40].copy_from_slice(sender.as_bytes());
    out[40..72].copy_from_slice(receiver.as_bytes());
    out[72..80].copy_from_slice(&mono.to_be_bytes());
    out[80..].copy_from_slice(challenge);
    out
}
/// Reconstruct source `TcpRekeySignature` size112, ordinary encapsulation bytes.
#[must_use]
pub fn rekey_region(
    sender: EddsaPublicKey,
    receiver: EddsaPublicKey,
    enc: &[u8; 32],
    mono: u64,
) -> [u8; 112] {
    let mut out = purpose(REKEY_PURPOSE);
    out[8..40].copy_from_slice(sender.as_bytes());
    out[40..72].copy_from_slice(receiver.as_bytes());
    out[72..104].copy_from_slice(enc);
    out[104..].copy_from_slice(&mono.to_be_bytes());
    out
}
/// Write the exact unencrypted confirmation for an actual Elligator KEM result.
/// Fresh representative/shared-secret generation remains an explicit missing primitive.
pub fn confirmation(
    key: &EddsaPrivateKey,
    receiver: EddsaPublicKey,
    enc: Representative,
    mono: u64,
    challenge: &[u8; 32],
) -> Result<[u8; CONFIRMATION], Error> {
    let region = handshake_region(key.public_key(), receiver, enc, mono, challenge);
    let sig = key.sign(HANDSHAKE_PURPOSE, &region)?;
    let mut out = [0; CONFIRMATION];
    out[..32].copy_from_slice(key.public_key().as_bytes());
    out[32..96].copy_from_slice(sig.as_bytes());
    out[96..104].copy_from_slice(&mono.to_be_bytes());
    out[104..].copy_from_slice(challenge);
    Ok(out)
}
/// Write the signed acknowledgement before ordered CTR encryption; no HMAC field.
pub fn acknowledgement(
    key: &EddsaPrivateKey,
    receiver: EddsaPublicKey,
    mono: u64,
    challenge: &[u8; 32],
) -> Result<[u8; ACK], Error> {
    let region = ack_region(key.public_key(), receiver, mono, challenge);
    let sig = key.sign(ACK_PURPOSE, &region)?;
    let mut out = [0; ACK];
    out[..2].copy_from_slice(&(ACK as u16).to_be_bytes());
    out[2..4].copy_from_slice(&ACK_TYPE.to_be_bytes());
    out[4..36].copy_from_slice(key.public_key().as_bytes());
    out[36..100].copy_from_slice(sig.as_bytes());
    out[100..108].copy_from_slice(&mono.to_be_bytes());
    out[108..].copy_from_slice(challenge);
    Ok(out)
}
/// Verify exact signed acknowledgement and challenge. As in source, its signature
/// binds the claimed sender; comparing that sender with the queue target remains
/// a separately visible owner policy (source currently omits that equality).
pub fn verify_ack(
    bytes: &[u8],
    receiver: EddsaPublicKey,
    challenge: &[u8; 32],
) -> Result<EddsaPublicKey, Error> {
    if bytes.len() != ACK || Shape::decode(bytes)? != Shape::Ack {
        return Err(Error::Malformed);
    }
    let sender = EddsaPublicKey::from_bytes(array(&bytes[4..36]));
    let mono = u64::from_be_bytes(array(&bytes[100..108]));
    let actual = array(&bytes[108..]);
    if actual != *challenge {
        return Err(Error::Authentication);
    }
    sender.verify(
        ACK_PURPOSE,
        &ack_region(sender, receiver, mono, &actual),
        &EddsaSignature::from_bytes(array(&bytes[36..100])),
    )?;
    Ok(sender)
}
/// Prepare the exact signed rekey with its record MAC slot zeroed. The caller
/// supplies a real ordinary EdDSA KEM encapsulation, never an Elligator alias.
pub fn rekey(
    key: &EddsaPrivateKey,
    receiver: EddsaPublicKey,
    enc: &[u8; 32],
    mono: u64,
) -> Result<[u8; REKEY], Error> {
    let signature = key.sign(
        REKEY_PURPOSE,
        &rekey_region(key.public_key(), receiver, enc, mono),
    )?;
    let mut out = [0; REKEY];
    out[..2].copy_from_slice(&(REKEY as u16).to_be_bytes());
    out[2..4].copy_from_slice(&REKEY_TYPE.to_be_bytes());
    out[36..68].copy_from_slice(enc);
    out[68..132].copy_from_slice(signature.as_bytes());
    out[132..].copy_from_slice(&mono.to_be_bytes());
    Ok(out)
}
/// Verify the exact known-target rekey signature after record-MAC validation.
/// This does not accept/store replay time or perform the replacement KEM.
pub fn verify_rekey(
    bytes: &[u8],
    sender: EddsaPublicKey,
    receiver: EddsaPublicKey,
) -> Result<([u8; 32], u64), Error> {
    if bytes.len() != REKEY || Shape::decode(bytes)? != Shape::Rekey {
        return Err(Error::Malformed);
    }
    let enc = array(&bytes[36..68]);
    let mono = u64::from_be_bytes(array(&bytes[132..]));
    sender.verify(
        REKEY_PURPOSE,
        &rekey_region(sender, receiver, &enc, mono),
        &EddsaSignature::from_bytes(array(&bytes[68..132])),
    )?;
    Ok((enc, mono))
}
