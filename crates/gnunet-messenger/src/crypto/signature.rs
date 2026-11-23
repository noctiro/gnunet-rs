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
    KeyType, PublicKey, SensitiveBytes,
    body::Body,
    envelope::{self, Header, Kind, Signature},
    message::{Message, Short},
    padding,
    profile::Profile,
};
use zeroize::{Zeroize, Zeroizing};
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
        KeyType::Eddsa => sign_peer_payload(&EddsaPrivateKey::from_seed(*raw), &payload)?,
    };
    Ok(tag_signature(key.key_type(), &signature))
}

fn sign_peer_payload(
    key: &EddsaPrivateKey,
    payload: &[u8; envelope::SIGNED_HASH_LEN],
) -> Result<[u8; 64], Error> {
    Ok(*key.sign(envelope::SIGNATURE_PURPOSE, payload)?.as_bytes())
}

fn tag_signature(kind: KeyType, signature: &[u8; 64]) -> [u8; envelope::SIGNATURE_LEN] {
    let mut encoded = [0; envelope::SIGNATURE_LEN];
    encoded[..4].copy_from_slice(&kind.value().to_be_bytes());
    encoded[4..].copy_from_slice(signature);
    encoded
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

fn draft_header<'a>(
    header: SigningHeader<'a>,
    kind: Kind,
    placeholder: &'a [u8; envelope::SIGNATURE_LEN],
) -> Result<Header<'a>, Error> {
    Ok(Header {
        signature: Signature::new(placeholder)?,
        timestamp: header.timestamp,
        sender_id: header.sender_id,
        previous: header.previous,
        kind,
    })
}

fn finish_signature(
    frame: &mut [u8],
    profile: Profile,
    pad: padding::Encode<'_>,
    sign: impl FnOnce(&[u8; 64]) -> Result<[u8; envelope::SIGNATURE_LEN], Error>,
) -> Result<(), Error> {
    let mode = match pad {
        padding::Encode::Absent => padding::Decode::Absent,
        padding::Encode::ToLength { .. } => padding::Decode::Required,
    };
    let digest = message_hash(Message::decode(frame, profile, mode)?);
    let signature = sign(&digest)?;
    frame[..envelope::SIGNATURE_LEN].copy_from_slice(&signature);
    Ok(())
}

/// Sign an already encoded, unpadded Messenger body with the native EdDSA peer
/// key and write the official frame into caller storage without allocating.
/// The body must match `kind` and `profile`; its bytes are preserved exactly.
/// This establishes a signature and gives no room or source authorization.
///
/// # Errors
/// Rejects an invalid profile, padding shape, body or short output. Failures
/// after encoding starts erase only the frame prefix; the unused tail is untouched.
pub fn encode_signed_peer(
    key: &EddsaPrivateKey,
    header: SigningHeader<'_>,
    kind: Kind,
    body: SensitiveBytes<'_>,
    profile: Profile,
    pad: padding::Encode<'_>,
    output: &mut [u8],
) -> Result<usize, Error> {
    profile.validate()?;
    let unpadded = envelope::HEADER_LEN
        .checked_add(body.len())
        .ok_or(Fault::Overflow)?;
    let total = padding::encoded_length(unpadded, pad)?;
    let frame = output.get_mut(..total).ok_or(Fault::Capacity)?;
    let placeholder = tag_signature(KeyType::Eddsa, &[0; 64]);
    let fields = draft_header(header, kind, &placeholder)?;
    let result = (|| {
        let unpadded = envelope::encode(fields, body, frame)?;
        padding::write(unpadded, pad, profile, frame)?;
        finish_signature(frame, profile, pad, |digest| {
            let payload = signing_payload(digest)?;
            let signature = sign_peer_payload(key, &payload)?;
            Ok(tag_signature(KeyType::Eddsa, &signature))
        })
    })();
    if result.is_err() {
        frame.zeroize();
    }
    result.map(|()| total)
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
        let placeholder = tag_signature(key.key_type(), &[0; 64]);
        let fields = draft_header(header, body.kind(), &placeholder)?;
        self.encode_message(fields, body, profile, pad)?;
        let result = finish_signature(&mut self.bytes[..self.len], profile, pad, |digest| {
            sign_digest(key, digest)
        });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check native peer signing against the existing typed encoder and output bounds"
    )]
    fn peer_frame_matches_typed_signing_with_the_same_key_and_padding() -> Result<(), Error> {
        const TOTAL: usize = 192;
        let peer = EddsaPrivateKey::from_seed([0x59; 32]);
        let mut tagged = Zeroizing::new([0x59; 36]);
        tagged[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
        let member = SecretKey::from_serialized(&tagged[..])?;
        let public = peer.public_key();
        let fields = SigningHeader {
            timestamp: AbsoluteTime::from_micros(17),
            sender_id: public.as_bytes(),
            previous: &[0x24; 64],
        };
        let profile = Profile::BIG_255;
        let pad = padding::Encode::ToLength {
            total: TOTAL,
            noise: SensitiveBytes::new(&[0x6e; TOTAL - envelope::HEADER_LEN - 4 - 3]),
        };
        let body = Body::Info { version: 3 };
        let mut typed = SensitiveBuffer::<TOTAL>::new();
        typed.encode_signed(&member, fields, body, profile, pad)?;
        let mut raw = [0; 4];
        let len = body.encode(profile, &mut raw)?;
        let mut output = [0xa5; TOTAL + 1];
        let written = encode_signed_peer(
            &peer,
            fields,
            body.kind(),
            SensitiveBytes::new(&raw[..len]),
            profile,
            pad,
            &mut output,
        )?;
        assert_eq!(written, TOTAL);
        assert_eq!(&output[..written], typed.expose());
        assert_eq!(output[written], 0xa5);
        verify_peer(
            Message::decode(&output[..written], profile, padding::Decode::Required)?,
            public.as_bytes(),
        )?;
        Ok(())
    }
}
