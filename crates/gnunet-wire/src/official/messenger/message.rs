//! Typed message/body/padding integration. Canonical signed-message hashing
//! excludes parsed outer padding; short-message hashing includes its padding.
use super::{
    SensitiveBytes,
    body::Body,
    envelope::{self, Envelope, Header, ShortMessage},
    padding,
    profile::Profile,
};
use core::fmt;
use gnunet_types::Error;
/// Explicit original short-body and immutable short-padding producers. This
/// metadata adds no wire field; the carried short digest still covers padding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShortProfiles {
    /// Body grammar, including original FILE NAME_MAX.
    pub body: Profile,
    /// Original inner padding encoder, independent from any outer relay.
    pub padding: Profile,
}
impl ShortProfiles {
    /// Explicit same-producer contract.
    pub const fn same(profile: Profile) -> Self {
        Self {
            body: profile,
            padding: profile,
        }
    }
    /// Validate the declarations without claiming AEAD or sender authority.
    pub fn validate(self) -> Result<(), Error> {
        self.body.validate()?;
        self.padding.validate()
    }
}
/// Structurally decoded signed message. No hash/signature, room authorization or
/// crypto check has occurred. The immutable original bytes remain authoritative.
#[derive(Clone, Copy)]
pub struct Message<'a> {
    original: Envelope<'a>,
    profile: Profile,
    padding_profile: Profile,
    /// Exact original header fields.
    header: Header<'a>,
    /// Exact typed unpadded body fields, with sensitive Debug redacted.
    body: Body<'a>,
    /// Exact recognized original padding, including marker and count.
    padding: SensitiveBytes<'a>,
}
impl fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message(unverified)")
            .field("kind", &self.body.kind())
            .field("padding_bytes", &self.padding.len())
            .finish()
    }
}
impl<'a> Message<'a> {
    /// Exact header copied from the immutable original encoding.
    pub const fn header(self) -> Header<'a> {
        self.header
    }
    /// Exact typed body borrowed from the immutable original encoding.
    pub const fn body(self) -> Body<'a> {
        self.body
    }
    /// Original recognized padding; callers cannot replace its bounds.
    pub const fn padding(self) -> SensitiveBytes<'a> {
        self.padding
    }
    /// Decode using an explicit original producer profile and transport padding
    /// policy. Body bounds are rechecked after any footer is removed.
    pub fn decode(bytes: &'a [u8], profile: Profile, mode: padding::Decode) -> Result<Self, Error> {
        Self::decode_with_profiles(bytes, profile, profile, mode)
    }
    /// Decode the original signed-body layout independently of this envelope's
    /// unsigned padding producer. A relay may repack padding without changing
    /// signed bytes. Both profiles are explicit; this never guesses either one.
    pub fn decode_with_profiles(
        bytes: &'a [u8],
        profile: Profile,
        padding_profile: Profile,
        mode: padding::Decode,
    ) -> Result<Self, Error> {
        profile.validate()?;
        padding_profile.validate()?;
        let original = Envelope::decode(bytes)?;
        let header = original.header()?;
        let split = padding::split(original.raw_body(), padding_profile, mode)?;
        let body = Body::decode(header.kind, split.content.expose(), profile)?;
        Ok(Self {
            original,
            profile,
            padding_profile,
            header,
            body,
            padding: split.padding,
        })
    }
    /// Explicit original signed-body producer profile; it is not inferred from
    /// a forwarding socket or a valid-looking footer.
    pub const fn profile(self) -> Profile {
        self.profile
    }
    /// Explicit encoder of this original envelope's outer padding.
    pub const fn padding_profile(self) -> Profile {
        self.padding_profile
    }
    /// Exact original signed-message hash input used by pack_message/tunnel:
    /// all bytes after tagged signature68 through the unpadded encoded length.
    /// It excludes recognized outer padding and performs no hashing/verification.
    pub fn hash_input(self) -> SensitiveBytes<'a> {
        let bytes = self.original.expose_encoded();
        SensitiveBytes::new(&bytes[envelope::SIGNATURE_LEN..bytes.len() - self.padding.len()])
    }
    /// Exact original full encoded bytes for forwarding/storage, including pad.
    pub const fn original(self) -> Envelope<'a> {
        self.original
    }
}
/// Structurally decoded private/transcript/secret inner short message. Its
/// carried digest must still be checked; body validity is not decryption proof.
#[derive(Clone, Copy)]
pub struct Short<'a> {
    original: ShortMessage<'a>,
    body_profile: Profile,
    padding_profile: Profile,
    /// Exact typed unpadded body fields.
    body: Body<'a>,
    /// Complete recognized original padding.
    padding: SensitiveBytes<'a>,
}
impl fmt::Debug for Short<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Short(unverified)")
            .field("kind", &self.body.kind())
            .field("padding_bytes", &self.padding.len())
            .finish()
    }
}
impl<'a> Short<'a> {
    /// Exact typed body borrowed from the immutable original encoding.
    pub const fn body(self) -> Body<'a> {
        self.body
    }
    /// Original recognized padding; callers cannot replace its bounds.
    pub const fn padding(self) -> SensitiveBytes<'a> {
        self.padding
    }
    /// Decode structure only, after the caller's authorized decryption if any.
    pub fn decode(bytes: &'a [u8], profile: Profile, mode: padding::Decode) -> Result<Self, Error> {
        Self::decode_with_profiles(bytes, profile, profile, mode)
    }
    /// Decode explicit original plaintext-body and immutable short-padding
    /// encoders separately. Short padding participates in the carried hash;
    /// a relay cannot rewrite it like unsigned outer-message padding.
    pub fn decode_with_profiles(
        bytes: &'a [u8],
        body_profile: Profile,
        padding_profile: Profile,
        mode: padding::Decode,
    ) -> Result<Self, Error> {
        body_profile.validate()?;
        padding_profile.validate()?;
        let original = ShortMessage::decode(bytes)?;
        let split = padding::split(original.raw_body(), padding_profile, mode)?;
        let body = Body::decode(original.kind(), split.content.expose(), body_profile)?;
        Ok(Self {
            original,
            body_profile,
            padding_profile,
            body,
            padding: split.padding,
        })
    }
    /// Actual explicitly decoded plaintext body producer.
    pub const fn body_profile(self) -> Profile {
        self.body_profile
    }
    /// Actual explicitly decoded short-padding producer, not a relay profile.
    pub const fn padding_profile(self) -> Profile {
        self.padding_profile
    }
    /// Exact short-message hash input includes kind/body AND padding. The C
    /// encode/decode_short_message pair hashes before padding interpretation.
    pub fn hash_input(self) -> SensitiveBytes<'a> {
        self.original.hash_input()
    }
    /// Original carried digest, still unverified.
    pub fn carried_hash(self) -> Result<&'a [u8; 64], Error> {
        self.original.carried_hash()
    }
    /// Original structural short container.
    pub const fn original(self) -> ShortMessage<'a> {
        self.original
    }
}
/// Exact signed encoded length for this typed body and explicit padding choice.
pub fn encoded_len(
    body: Body<'_>,
    profile: Profile,
    padding: padding::Encode<'_>,
) -> Result<usize, Error> {
    padding::encoded_length(
        envelope::HEADER_LEN
            .checked_add(body.encoded_len(profile)?)
            .ok_or(Error::Overflow)?,
        padding,
    )
}
/// Encode a complete signed structure. The header signature is supplied by its
/// real owner; encoding never creates/validates a signature or successful event.
/// The kind must match the typed body. All external shape checks precede writes.
pub fn encode(
    header: Header<'_>,
    body: Body<'_>,
    profile: Profile,
    pad: padding::Encode<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    if header.kind != body.kind() {
        return Err(Error::InvalidInput);
    }
    let unpadded = envelope::HEADER_LEN
        .checked_add(body.encoded_len(profile)?)
        .ok_or(Error::Overflow)?;
    let total = padding::encoded_length(unpadded, pad)?;
    if output.len() < total {
        return Err(Error::Capacity);
    }
    envelope::encode(header, SensitiveBytes::new(&[]), output)?;
    body.encode(profile, &mut output[envelope::HEADER_LEN..unpadded])?;
    padding::write(unpadded, pad, profile, output)
}
/// Encode a complete short structure from a caller-supplied carried digest.
/// A crypto owner must hash kind/body/padding and install the real digest;
/// these structural bytes are never labeled verified by this encoder.
pub fn encode_short(
    hash: &[u8; 64],
    body: Body<'_>,
    profile: Profile,
    pad: padding::Encode<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    let unpadded = envelope::SHORT_PREFIX
        .checked_add(body.encoded_len(profile)?)
        .ok_or(Error::Overflow)?;
    let total = padding::encoded_length(unpadded, pad)?;
    if output.len() < total {
        return Err(Error::Capacity);
    }
    envelope::encode_short(hash, body.kind(), SensitiveBytes::new(&[]), output)?;
    body.encode(profile, &mut output[envelope::SHORT_PREFIX..unpadded])?;
    padding::write(unpadded, pad, profile, output)
}
