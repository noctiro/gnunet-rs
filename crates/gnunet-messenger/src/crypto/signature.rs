//! Standard SHA512 and actual CHAT_MESSAGE purpose12 signatures. Key selection
//! must come from the caller's authorized original member/peer state.
use super::Error;
use crate::{SensitiveBuffer, wire};
use core::fmt;
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature, gns::PkeySecret, hash512};
use gnunet_identity::SecretKey;
use gnunet_types::Error as Fault;
use gnunet_wire::official::AbsoluteTime;
use subtle::ConstantTimeEq;
use wire::{
    KeyType, PublicKey,
    body::Body,
    envelope::{self, Header, Signature},
    message::{Message, Short},
    padding,
    profile::Profile,
};
use zeroize::Zeroizing;
/// Exact canonical original signed-message digest, excluding recognized outer
/// padding. This alone checks neither a signature nor a claimed sender.
pub fn message_hash(message: Message<'_>) -> [u8; 64] {
    hash512(message.hash_input().expose())
}
/// Official size72/purpose12/digest64 record for an actual remote PILS signer or
/// local identity owner. Supplying this record does not fabricate PILS success.
pub fn signing_payload(digest: &[u8; 64]) -> Result<[u8; 72], Error> {
    let mut region = [0; 72];
    envelope::signed_hash_payload(digest, &mut region)?;
    Ok(region)
}
/// Sign the official hash record with an actual zeroizing IDENTITY key. The
/// caller authorizes its original member/peer role; this function performs no
/// key-file read, identity lookup or private storage. Temporaries erase on drop.
pub fn sign_digest(key: &SecretKey, digest: &[u8; 64]) -> Result<[u8; 68], Error> {
    let payload = signing_payload(digest)?;
    let mut raw = Zeroizing::new([0; 32]);
    raw.copy_from_slice(&key.expose_serialized()[4..]);
    let signature = match key.key_type() {
        KeyType::Ecdsa => {
            PkeySecret::from_bytes(*raw)?.sign(envelope::SIGNATURE_PURPOSE, &[&payload])?
        }
        KeyType::Eddsa => *EddsaPrivateKey::from_seed(*raw)
            .sign(envelope::SIGNATURE_PURPOSE, &payload)?
            .as_bytes(),
    };
    let mut encoded = [0; 68];
    encoded[..4].copy_from_slice(&key.key_type().value().to_be_bytes());
    encoded[4..].copy_from_slice(&signature);
    Ok(encoded)
}
/// Sealed proof that this original message's actual signature passed under this
/// caller-selected key. It grants no room membership, DAG continuity or epoch
/// permission. Public fields cannot be replaced after verification.
pub struct SignatureChecked<'a> {
    message: Message<'a>,
    digest: [u8; 64],
    public_key: [u8; 36],
}
impl fmt::Debug for SignatureChecked<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignatureChecked([REDACTED], room authorization pending)")
    }
}
impl<'a> SignatureChecked<'a> {
    /// Original immutable checked wire structure.
    pub const fn message(&self) -> Message<'a> {
        self.message
    }
    /// Actual canonical signed-message hash, potentially private-room metadata.
    pub const fn digest(&self) -> &[u8; 64] {
        &self.digest
    }
    /// Exact caller-selected public key under which the signature passed.
    pub const fn public_key(&self) -> &[u8; 36] {
        &self.public_key
    }
}
/// Hash and verify the exact original purpose72 record. Algorithm-family equality
/// is mandatory; no carried public key is trusted implicitly as a room member.
pub fn verify_member<'a>(
    message: Message<'a>,
    public: PublicKey<'_>,
) -> Result<SignatureChecked<'a>, Error> {
    let signature = message.header().signature;
    if signature.key_type() != public.key_type() {
        return Err(Fault::Authentication.into());
    }
    let digest = message_hash(message);
    let payload = signing_payload(&digest)?;
    let raw_public: &[u8; 32] = public.as_bytes()[4..]
        .try_into()
        .map_err(|_| Fault::Malformed)?;
    let raw_signature: &[u8; 64] = signature.bytes().try_into().map_err(|_| Fault::Malformed)?;
    match public.key_type() {
        KeyType::Ecdsa => gnunet_crypto::gns::verify_pkey(
            raw_public,
            envelope::SIGNATURE_PURPOSE,
            &[&payload],
            raw_signature,
        )?,
        KeyType::Eddsa => EddsaPublicKey::from_bytes(*raw_public).verify(
            envelope::SIGNATURE_PURPOSE,
            &payload,
            &EddsaSignature::from_bytes(*raw_signature),
        )?,
    }
    Ok(SignatureChecked {
        message,
        digest,
        public_key: *public.as_bytes(),
    })
}
/// Verify the same actual purpose record with the original caller-selected peer
/// identity. This is an EdDSA check; peer/contact/transport admission is separate.
pub fn verify_peer<'a>(
    message: Message<'a>,
    peer: &[u8; 32],
) -> Result<SignatureChecked<'a>, Error> {
    let mut public = [0; 36];
    public[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
    public[4..].copy_from_slice(peer);
    verify_member(message, PublicKey::new(&public)?)
}
/// A short message whose carried hash equals actual SHA512(kind/body/padding).
/// Hash equality is unkeyed and proves neither encryption nor a sender identity.
pub struct HashCheckedShort<'a> {
    pub(super) short: Short<'a>,
}
impl fmt::Debug for HashCheckedShort<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HashCheckedShort([REDACTED], sender authorization pending)")
    }
}
impl<'a> HashCheckedShort<'a> {
    /// Immutable original typed short structure, with sealed padding bounds.
    pub const fn short(&self) -> Short<'a> {
        self.short
    }
}
/// Compute and compare the full original short-message digest in constant time.
pub fn check_short(short: Short<'_>) -> Result<HashCheckedShort<'_>, Error> {
    let computed = hash512(short.hash_input().expose());
    if !bool::from(computed.ct_eq(short.carried_hash()?)) {
        return Err(Fault::Authentication.into());
    }
    Ok(HashCheckedShort { short })
}
/// Verify the original short digest before interpreting padding/body fields,
/// matching the actual reference consumer's cryptographic ordering.
pub fn decode_short<'a>(
    bytes: &'a [u8],
    profile: Profile,
    mode: padding::Decode,
) -> Result<HashCheckedShort<'a>, Error> {
    decode_short_with_profiles(bytes, profile, profile, mode)
}
/// Check the exact carried digest before explicit plaintext-body and short-
/// padding parsing. No ciphertext or signed bytes are normalized/rehashed.
pub fn decode_short_with_profiles<'a>(
    bytes: &'a [u8],
    body_profile: Profile,
    padding_profile: Profile,
    mode: padding::Decode,
) -> Result<HashCheckedShort<'a>, Error> {
    let raw = envelope::ShortMessage::decode(bytes)?;
    let computed = hash512(raw.hash_input().expose());
    if !bool::from(computed.ct_eq(raw.carried_hash()?)) {
        return Err(Fault::Authentication.into());
    }
    Ok(HashCheckedShort {
        short: Short::decode_with_profiles(bytes, body_profile, padding_profile, mode)?,
    })
}
/// Explicit outgoing header fields; unlike a decoded/checked view, this draft
/// has no immutable original encoding and claims no signature or authorization.
#[derive(Clone, Copy)]
pub struct SigningHeader<'a> {
    /// Original configured timestamp.
    pub timestamp: AbsoluteTime,
    /// Selected original room member ID.
    pub sender_id: &'a [u8; 32],
    /// Selected previous original message hash.
    pub previous: &'a [u8; 64],
}
impl<const N: usize> SensitiveBuffer<N> {
    /// Encode and actually sign one typed message into erased owner storage.
    /// Initial dummy bytes exist only in this owner until replaced by the real
    /// signature; any signing failure erases the entire owner before returning.
    pub fn encode_signed(
        &mut self,
        key: &SecretKey,
        header: SigningHeader<'_>,
        body: Body<'_>,
        profile: Profile,
        pad: padding::Encode<'_>,
    ) -> Result<(), Error> {
        let mut placeholder = [0; 68];
        placeholder[..4].copy_from_slice(&key.key_type().value().to_be_bytes());
        let fields = Header {
            signature: Signature::new(&placeholder)?,
            timestamp: header.timestamp,
            sender_id: header.sender_id,
            previous: header.previous,
            kind: body.kind(),
        };
        self.encode_message(fields, body, profile, pad)?;
        let mode = match pad {
            padding::Encode::Absent => padding::Decode::Absent,
            padding::Encode::ToLength { .. } => padding::Decode::Required,
        };
        let result = (|| {
            let digest = message_hash(self.message(profile, mode)?);
            let signature = sign_digest(key, &digest)?;
            self.bytes[..68].copy_from_slice(&signature);
            Ok(())
        })();
        if result.is_err() {
            self.clear();
        }
        result
    }
    /// Encode a short structure and install its actual digest over kind/body/
    /// padding. This does not label the unkeyed hash as sender authentication.
    pub fn encode_hashed_short(
        &mut self,
        body: Body<'_>,
        profile: Profile,
        pad: padding::Encode<'_>,
    ) -> Result<(), Error> {
        self.encode_short(&[0; 64], body, profile, pad)?;
        let digest = hash512(&self.bytes[64..self.len]);
        self.bytes[..64].copy_from_slice(&digest);
        Ok(())
    }
}
