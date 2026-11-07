//! Exact encoded signed/short message containers and coverage boundaries.
//! Body-kind grammar, padding interpretation and signature verification are
//! deliberately separate. Lossless raw tails include any original padding.
use super::{KeyType, SensitiveBytes, array};
use crate::official::AbsoluteTime;
use core::fmt;
use gnunet_types::Error;
/// BE32 key family and64-byte signature, for both active blindable families.
pub const SIGNATURE_LEN: usize = 68;
/// Signature68 + timestamp8 + sender32 + previous64 + kind4.
pub const HEADER_LEN: usize = 176;
/// Short private-message plaintext container: carried hash64 and kind4.
pub const SHORT_PREFIX: usize = 68;
/// Official CHAT_MESSAGE purpose number.
pub const SIGNATURE_PURPOSE: u32 = 12;
/// Signature-purpose header8 plus message hash64.
pub const SIGNED_HASH_LEN: usize = 72;
/// Official peer message padding ceiling, separate from whole IPC frame bounds.
pub const MAX_PADDED_MESSAGE_BYTES: usize = 65524;
/// Original numeric message kind. All28 active kinds are represented despite
/// the stale C KIND_MAX macro ending at21; unknown numeric values are preserved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Kind(u32);
impl Kind {
    /// Unknown/unsupported inner kind. No body validity is implied.
    pub const UNKNOWN: Self = Self(0);
    /// Official message kind 1 (INFO).
    pub const INFO: Self = Self(1);
    /// Official message kind 2 (JOIN).
    pub const JOIN: Self = Self(2);
    /// Official message kind 3 (LEAVE).
    pub const LEAVE: Self = Self(3);
    /// Official message kind 4 (NAME).
    pub const NAME: Self = Self(4);
    /// Official message kind 5 (KEY).
    pub const KEY: Self = Self(5);
    /// Official message kind 6 (PEER).
    pub const PEER: Self = Self(6);
    /// Official message kind 7 (ID).
    pub const ID: Self = Self(7);
    /// Official message kind 8 (MISS).
    pub const MISS: Self = Self(8);
    /// Official message kind 9 (MERGE).
    pub const MERGE: Self = Self(9);
    /// Official message kind 10 (REQUEST).
    pub const REQUEST: Self = Self(10);
    /// Official message kind 11 (INVITE).
    pub const INVITE: Self = Self(11);
    /// Official message kind 12 (TEXT).
    pub const TEXT: Self = Self(12);
    /// Official message kind 13 (FILE).
    pub const FILE: Self = Self(13);
    /// Official message kind 14 (PRIVATE).
    pub const PRIVATE: Self = Self(14);
    /// Official message kind 15 (DELETION).
    pub const DELETION: Self = Self(15);
    /// Official message kind 16 (CONNECTION).
    pub const CONNECTION: Self = Self(16);
    /// Official message kind 17 (TICKET).
    pub const TICKET: Self = Self(17);
    /// Official message kind 18 (TRANSCRIPT).
    pub const TRANSCRIPT: Self = Self(18);
    /// Official message kind 19 (TAG).
    pub const TAG: Self = Self(19);
    /// Official message kind 20 (SUBSCRIPTION).
    pub const SUBSCRIPTION: Self = Self(20);
    /// Official message kind 21 (TALK).
    pub const TALK: Self = Self(21);
    /// Official message kind 22 (ANNOUNCEMENT).
    pub const ANNOUNCEMENT: Self = Self(22);
    /// Official message kind 23 (SECRET).
    pub const SECRET: Self = Self(23);
    /// Official message kind 24 (APPEAL).
    pub const APPEAL: Self = Self(24);
    /// Official message kind 25 (ACCESS).
    pub const ACCESS: Self = Self(25);
    /// Official message kind 26 (REVOLUTION).
    pub const REVOLUTION: Self = Self(26);
    /// Official message kind 27 (GROUP).
    pub const GROUP: Self = Self(27);
    /// Official message kind 28 (AUTHORIZATION).
    pub const AUTHORIZATION: Self = Self(28);
    /// Preserve an original numeric kind without inventing a body codec.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }
    /// Original BE32 kind value in host byte order.
    pub const fn value(self) -> u32 {
        self.0
    }
    /// Whether the current pin has an active named kind for this number.
    pub const fn is_known(self) -> bool {
        self.0 >= 1 && self.0 <= 28
    }
}
/// Borrowed supported public signature serialization. Construction validates
/// length/tag only and never claims signature validity.
#[derive(Clone, Copy)]
pub struct Signature<'a> {
    bytes: &'a [u8; 68],
    kind: KeyType,
}
impl<'a> Signature<'a> {
    /// Validate the exact serialized size and active family tag.
    pub fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        let bytes: &[u8; 68] = bytes.try_into().map_err(|_| Error::Malformed)?;
        let kind = KeyType::from_value(u32::from_be_bytes(*array(bytes, 0)?))?;
        Ok(Self { bytes, kind })
    }
    /// Active official algorithm family.
    pub const fn key_type(self) -> KeyType {
        self.kind
    }
    /// Original family tag and public signature bytes.
    pub const fn serialized(self) -> &'a [u8; 68] {
        self.bytes
    }
    /// Original64-byte public signature, without a tag reinterpretation.
    pub fn bytes(self) -> &'a [u8] {
        &self.bytes[4..]
    }
}
impl fmt::Debug for Signature<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature(unverified)")
            .field(&self.kind)
            .finish()
    }
}
/// Encoded message header fields. These do not establish member identity,
/// previous-message continuity, temporal validity or room authorization.
#[derive(Clone, Copy)]
pub struct Header<'a> {
    /// Carried unverified signature and algorithm tag.
    pub signature: Signature<'a>,
    /// Original timestamp, with zero used by some official epoch messages.
    pub timestamp: AbsoluteTime,
    /// Original member id in its room.
    pub sender_id: &'a [u8; 32],
    /// Original previous-message hash.
    pub previous: &'a [u8; 64],
    /// Original numeric body kind.
    pub kind: Kind,
}
impl fmt::Debug for Header<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageHeader(unverified)")
            .field("kind", &self.kind)
            .field("timestamp", &self.timestamp)
            .finish_non_exhaustive()
    }
}
/// Borrowed complete encoded signed message. Structure/header validity is
/// distinct from body grammar, hash equality, signature and authority checks.
#[derive(Clone, Copy)]
pub struct Envelope<'a> {
    bytes: &'a [u8],
}
impl fmt::Debug for Envelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Envelope(unverified)")
            .field("encoded_bytes", &self.bytes.len())
            .finish()
    }
}
impl<'a> Envelope<'a> {
    /// Check the whole fixed header, supported signature tag and u16 message
    /// length domain. The tail remains opaque body plus original padding.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        u16::try_from(bytes.len()).map_err(|_| Error::TooLarge)?;
        bytes.get(..HEADER_LEN).ok_or(Error::Truncated)?;
        Signature::new(&bytes[..SIGNATURE_LEN])?;
        Ok(Self { bytes })
    }
    /// Decode exact original header fields from this already bounded envelope.
    pub fn header(self) -> Result<Header<'a>, Error> {
        Ok(Header {
            signature: Signature::new(&self.bytes[..68])?,
            timestamp: AbsoluteTime::decode(&self.bytes[68..76])?,
            sender_id: array(self.bytes, 76)?,
            previous: array(self.bytes, 108)?,
            kind: Kind::new(u32::from_be_bytes(*array(self.bytes, 172)?)),
        })
    }
    /// Exact original encoded bytes. This explicit borrow may expose chat secrets.
    pub const fn expose_encoded(self) -> &'a [u8] {
        self.bytes
    }
    /// Exact raw body plus padding; no length footer is guessed or stripped.
    pub fn raw_body(self) -> SensitiveBytes<'a> {
        SensitiveBytes::new(&self.bytes[HEADER_LEN..])
    }
    /// Raw hash_message range if its caller_length is this full buffer length.
    /// Packed signed room traffic instead passes the unpadded length: use
    /// message::Message::hash_input after explicit body/padding decoding for
    /// that canonical range. Returning raw bytes performs no authentication.
    pub fn hash_input(self) -> SensitiveBytes<'a> {
        SensitiveBytes::new(&self.bytes[SIGNATURE_LEN..])
    }
}
/// Encode an already selected header and opaque original body/padding. This
/// never generates padding, truncates body data, signs or authenticates it.
pub fn encode(
    header: Header<'_>,
    body: SensitiveBytes<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    let len = HEADER_LEN.checked_add(body.len()).ok_or(Error::Overflow)?;
    u16::try_from(len).map_err(|_| Error::TooLarge)?;
    if output.len() < len {
        return Err(Error::Capacity);
    }
    output[..68].copy_from_slice(header.signature.serialized());
    output[68..76].copy_from_slice(&header.timestamp.to_be_bytes());
    output[76..108].copy_from_slice(header.sender_id);
    output[108..172].copy_from_slice(header.previous);
    output[172..176].copy_from_slice(&header.kind.value().to_be_bytes());
    output[HEADER_LEN..len].copy_from_slice(body.expose());
    Ok(len)
}
/// Write the exact public signature-purpose/hash record used by sign_message
/// and verify_message: BE32 size72, BE32 purpose12, hash64. The caller supplies
/// the actual digest; this function does not compute or endorse it.
pub fn signed_hash_payload(hash: &[u8; 64], output: &mut [u8]) -> Result<usize, Error> {
    if output.len() < SIGNED_HASH_LEN {
        return Err(Error::Capacity);
    }
    output[..4].copy_from_slice(&(SIGNED_HASH_LEN as u32).to_be_bytes());
    output[4..8].copy_from_slice(&SIGNATURE_PURPOSE.to_be_bytes());
    output[8..72].copy_from_slice(hash);
    Ok(SIGNED_HASH_LEN)
}
/// Structural short message after authorized private-message decryption. The
/// carried hash must be compared with SHA512(hash_input()) before interpreting
/// the body. This view performs neither that verification nor decryption.
#[derive(Clone, Copy)]
pub struct ShortMessage<'a> {
    bytes: &'a [u8],
}
impl fmt::Debug for ShortMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShortMessage(unverified)")
            .field("encoded_bytes", &self.bytes.len())
            .finish()
    }
}
impl<'a> ShortMessage<'a> {
    /// Validate only the hash/kind prefix and u16 encoding domain.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, Error> {
        u16::try_from(bytes.len()).map_err(|_| Error::TooLarge)?;
        bytes.get(..SHORT_PREFIX).ok_or(Error::Truncated)?;
        Ok(Self { bytes })
    }
    /// Original unverified carried digest.
    pub fn carried_hash(self) -> Result<&'a [u8; 64], Error> {
        array(self.bytes, 0)
    }
    /// Original numeric body kind.
    pub fn kind(self) -> Kind {
        Kind::new(u32::from_be_bytes([
            self.bytes[64],
            self.bytes[65],
            self.bytes[66],
            self.bytes[67],
        ]))
    }
    /// Exact short-message hash input: kind and raw body/padding after hash64.
    pub fn hash_input(self) -> SensitiveBytes<'a> {
        SensitiveBytes::new(&self.bytes[64..])
    }
    /// Exact original raw body/padding, with no text or secret-key interpretation.
    pub fn raw_body(self) -> SensitiveBytes<'a> {
        SensitiveBytes::new(&self.bytes[SHORT_PREFIX..])
    }
}

/// Encode a short private-message plaintext container with a caller-supplied
/// carried digest. This does not compute/check that digest or encrypt anything.
pub fn encode_short(
    hash: &[u8; 64],
    kind: Kind,
    body: SensitiveBytes<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    let len = SHORT_PREFIX
        .checked_add(body.len())
        .ok_or(Error::Overflow)?;
    u16::try_from(len).map_err(|_| Error::TooLarge)?;
    if output.len() < len {
        return Err(Error::Capacity);
    }
    output[..64].copy_from_slice(hash);
    output[64..68].copy_from_slice(&kind.value().to_be_bytes());
    output[SHORT_PREFIX..len].copy_from_slice(body.expose());
    Ok(len)
}
