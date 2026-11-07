//! Real short-message hashing, explicit entropy padding, HPKE PRIVATE and
//! XChaCha20Poly1305 SECRET. Plaintext stays in caller-selected erased storage.
use super::{AeadKey, EcdhePublic, EcdheSecret, Entropy, Error, group::HPKE_INFO, signature};
use crate::{SensitiveBuffer, wire};
use gnunet_crypto::hash512;
use gnunet_session_crypto::{aead, hpke};
use gnunet_types::Error as Fault;
use subtle::ConstantTimeEq;
use wire::{
    PublicKey, SensitiveBytes,
    body::Body,
    envelope::{self, Kind},
    message::{Message, Short, ShortProfiles},
    padding,
    profile::Profile,
};
/// Exact official PRIVATE/transcript eligibility: INVITE/TEXT/FILE/TICKET/
/// TRANSCRIPT/TAG/TALK. Service kinds and nested PRIVATE/SECRET are excluded by
/// is_service_message; epoch SECRET wrapping has its own caller state policy.
pub const fn permits_private(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::INVITE
            | Kind::TEXT
            | Kind::FILE
            | Kind::TICKET
            | Kind::TRANSCRIPT
            | Kind::TAG
            | Kind::TALK
    )
}
// Any encrypted/transcript body produced here must fit a real packed peer
// message with its signed header and minimum footer, rather than rely on C's
// u16 truncation at the final65524 bucket.
fn outer_fits(body_len: usize) -> Result<(), Error> {
    let required = body_len
        .checked_add(envelope::HEADER_LEN)
        .and_then(|n| n.checked_add(padding::MIN_PADDING))
        .ok_or(Fault::Overflow)?;
    if required > envelope::MAX_PADDED_MESSAGE_BYTES {
        return Err(Fault::TooLarge.into());
    }
    Ok(())
}
fn short_size(body: Body<'_>, profile: Profile, overhead: usize) -> Result<(usize, usize), Error> {
    let plain = envelope::SHORT_PREFIX
        .checked_add(body.encoded_len(profile)?)
        .ok_or(Fault::Overflow)?;
    let packet = padding::rounded_length(plain, overhead, profile)?;
    Ok((plain, packet.checked_sub(overhead).ok_or(Fault::Overflow)?))
}
// Padding bytes are written directly into the caller's erased plaintext owner,
// avoiding a second padding-sized scratch allocation. The exact marker/count
// and rounding come from the same explicit wire profile/length functions.
fn padded_short(
    body: Body<'_>,
    profiles: ShortProfiles,
    overhead: usize,
    output: &mut [u8],
    entropy: &mut impl Entropy,
) -> Result<usize, Error> {
    let (unpadded, total) = short_size(body, profiles.body, overhead)?;
    if output.len() < total {
        return Err(Fault::Capacity.into());
    }
    let count = total.checked_sub(unpadded).ok_or(Fault::Overflow)?;
    if count < padding::MIN_PADDING {
        return Err(Fault::InvalidInput.into());
    }
    let footer = profiles
        .padding
        .endian
        .write_u16(u16::try_from(count).map_err(|_| Fault::TooLarge)?);
    let result = (|| {
        wire::message::encode_short(
            &[0; 64],
            body,
            profiles.body,
            padding::Encode::Absent,
            output,
        )?;
        output[unpadded] = 0;
        if count > padding::MIN_PADDING {
            entropy
                .fill(&mut output[unpadded + 1..total - 2])
                .map_err(|_| Fault::Entropy)?;
        }
        output[total - 2..total].copy_from_slice(&footer);
        let digest = hash512(&output[64..total]);
        output[..64].copy_from_slice(&digest);
        Ok(total)
    })();
    if result.is_err() {
        gnunet_crypto::erase(&mut output[..total]);
    }
    result
}
impl<const N: usize> SensitiveBuffer<N> {
    /// Actually hash/pad/encrypt an eligible original body into a PRIVATE
    /// ciphertext-only body. Explicit scratch holds only the short plaintext and
    /// is erased on success/failure. Select both capacities from caller budgets.
    /// The returned bytes need an actual outer signature and room admission.
    pub fn seal_private<const M: usize>(
        &mut self,
        recipient: EcdhePublic,
        body: Body<'_>,
        profile: Profile,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        self.seal_private_profiled(
            recipient,
            body,
            ShortProfiles::same(profile),
            scratch,
            entropy,
        )
    }
    /// Seal the real original short using explicit body and padding encoders.
    /// This does not normalize an existing signed body or reuse a relay footer.
    pub fn seal_private_profiled<const M: usize>(
        &mut self,
        recipient: EcdhePublic,
        body: Body<'_>,
        profiles: ShortProfiles,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        profiles.validate()?;
        if !permits_private(body.kind()) {
            return Err(Fault::InvalidInput.into());
        }
        let (_, plain) = short_size(body, profiles.body, wire::keys::HPKE_OVERHEAD)?;
        let total = plain
            .checked_add(wire::keys::HPKE_OVERHEAD)
            .ok_or(Fault::Overflow)?;
        outer_fits(total)?;
        if plain > M || total > N {
            return Err(Fault::Capacity.into());
        }
        self.clear();
        scratch.clear();
        let result = (|| {
            scratch.len = padded_short(
                body,
                profiles,
                wire::keys::HPKE_OVERHEAD,
                &mut *scratch.bytes,
                entropy,
            )?;
            let lengths = hpke::seal_oneshot(
                recipient,
                HPKE_INFO,
                &[],
                scratch.expose(),
                &mut *self.bytes,
                entropy,
            )?;
            if lengths.total_written != total {
                return Err(Fault::Conflict.into());
            }
            self.len = total;
            Ok(())
        })();
        scratch.clear();
        if result.is_err() {
            self.clear();
        }
        result
    }
    /// Authenticate/decrypt exact official PRIVATE with info="messenger" and
    /// empty AAD, then check the carried short hash before releasing a view.
    /// Caller authorizes the recipient and verifies the original outer signer.
    pub fn open_private<'a>(
        &'a mut self,
        message: Message<'_>,
        recipient: &EcdheSecret,
        profile: Profile,
    ) -> Result<signature::HashCheckedShort<'a>, Error> {
        self.open_private_with_profiles(message, recipient, profile, profile)
    }
    /// Actual original plaintext body/padding profiles; neither is the relay
    /// outer-padding decoder. AEAD and carried short hash remain mandatory.
    pub fn open_private_with_profiles<'a>(
        &'a mut self,
        message: Message<'_>,
        recipient: &EcdheSecret,
        body_profile: Profile,
        padding_profile: Profile,
    ) -> Result<signature::HashCheckedShort<'a>, Error> {
        let Body::Private { data } = message.body() else {
            return Err(Fault::InvalidInput.into());
        };
        body_profile.validate()?;
        padding_profile.validate()?;
        let n = data
            .len()
            .checked_sub(wire::keys::HPKE_OVERHEAD)
            .ok_or(Fault::Truncated)?;
        if n < envelope::SHORT_PREFIX {
            return Err(Fault::Truncated.into());
        }
        if n > N {
            return Err(Fault::Capacity.into());
        }
        self.clear();
        let result = hpke::open_oneshot(recipient, HPKE_INFO, &[], data.expose(), &mut *self.bytes);
        let written = match result {
            Ok(n) => n,
            Err(error) => {
                self.clear();
                return Err(error.into());
            }
        };
        self.finish_open(written, body_profile, padding_profile)
    }
    /// Actually hash/pad/encrypt one body into the complete raw SECRET body:
    /// identifier32/nonce24/mac16/ciphertext. New nonce and filler come only from
    /// the caller's entropy. State must authorize the selected epoch identifier.
    pub fn seal_secret<const M: usize>(
        &mut self,
        identifier: &[u8; 32],
        key: &AeadKey,
        body: Body<'_>,
        profile: Profile,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        self.seal_secret_profiled(
            identifier,
            key,
            body,
            ShortProfiles::same(profile),
            scratch,
            entropy,
        )
    }
    /// Seal the real original short using explicit body and padding encoders.
    /// This does not normalize an existing signed body or reuse a relay footer.
    pub fn seal_secret_profiled<const M: usize>(
        &mut self,
        identifier: &[u8; 32],
        key: &AeadKey,
        body: Body<'_>,
        profiles: ShortProfiles,
        scratch: &mut SensitiveBuffer<M>,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        profiles.validate()?;
        let (_, plain) = short_size(body, profiles.body, 0)?;
        let total = plain.checked_add(72).ok_or(Fault::Overflow)?;
        u16::try_from(total).map_err(|_| Fault::TooLarge)?;
        outer_fits(total)?;
        if plain > M || total > N {
            return Err(Fault::Capacity.into());
        }
        self.clear();
        scratch.clear();
        let result = (|| {
            let mut nonce = [0; 24];
            entropy.fill(&mut nonce).map_err(|_| Fault::Entropy)?;
            scratch.len = padded_short(body, profiles, 0, &mut *scratch.bytes, entropy)?;
            self.bytes[72..total].copy_from_slice(scratch.expose());
            let mac =
                aead::xchacha20poly1305_seal(&key.0, &nonce, &[], &mut self.bytes[72..total])?;
            self.bytes[..32].copy_from_slice(identifier);
            self.bytes[32..56].copy_from_slice(&nonce);
            self.bytes[56..72].copy_from_slice(&mac);
            self.len = total;
            Ok(())
        })();
        scratch.clear();
        if result.is_err() {
            self.clear();
        }
        result
    }
    /// Check the original expected epoch identifier, actual AEAD tag and carried
    /// short hash before publishing decrypted fields. Empty AAD follows C; the
    /// outer signature/state must bind the public identifier and sender context.
    pub fn open_secret<'a>(
        &'a mut self,
        message: Message<'_>,
        expected_identifier: &[u8; 32],
        key: &AeadKey,
        profile: Profile,
    ) -> Result<signature::HashCheckedShort<'a>, Error> {
        self.open_secret_with_profiles(message, expected_identifier, key, profile, profile)
    }
    /// Actual original plaintext body/padding profiles; neither is the relay
    /// outer-padding decoder. AEAD and carried short hash remain mandatory.
    pub fn open_secret_with_profiles<'a>(
        &'a mut self,
        message: Message<'_>,
        expected_identifier: &[u8; 32],
        key: &AeadKey,
        body_profile: Profile,
        padding_profile: Profile,
    ) -> Result<signature::HashCheckedShort<'a>, Error> {
        let Body::Secret {
            identifier,
            nonce,
            mac,
            data,
        } = message.body()
        else {
            return Err(Fault::InvalidInput.into());
        };
        body_profile.validate()?;
        padding_profile.validate()?;
        if data.len() < envelope::SHORT_PREFIX {
            return Err(Fault::Truncated.into());
        }
        if !bool::from(identifier.ct_eq(expected_identifier)) {
            return Err(Fault::Authentication.into());
        }
        if data.len() > N {
            return Err(Fault::Capacity.into());
        }
        self.clear();
        self.bytes[..data.len()].copy_from_slice(data.expose());
        if let Err(error) =
            aead::xchacha20poly1305_open(&key.0, nonce, &[], &mut self.bytes[..data.len()], mac)
        {
            self.clear();
            return Err(error.into());
        }
        self.finish_open(data.len(), body_profile, padding_profile)
    }
    // Validate once without returning a borrow, allowing error erasure. The
    // final cheap body view is reparsed without a second SHA512/ciphertext copy.
    // Both actual encrypted producers always pad their short payload; require
    // that footer rather than ambiguously guessing an unpadded binary suffix.
    fn finish_open(
        &mut self,
        n: usize,
        body_profile: Profile,
        padding_profile: Profile,
    ) -> Result<signature::HashCheckedShort<'_>, Error> {
        let result = signature::decode_short_with_profiles(
            &self.bytes[..n],
            body_profile,
            padding_profile,
            padding::Decode::Required,
        )
        .map(|_| ());
        if let Err(error) = result {
            self.clear();
            return Err(error);
        }
        self.len = n;
        let short = Short::decode_with_profiles(
            self.expose(),
            body_profile,
            padding_profile,
            padding::Decode::Required,
        )?;
        Ok(signature::HashCheckedShort { short })
    }
    /// Create an exact outgoing TRANSCRIPT body, including real hashed unpadded
    /// short bytes. original_hash identifies the linked sent message; its link,
    /// recipient and sender remain an actual room/history authorization concern.
    pub fn encode_transcript(
        &mut self,
        original_hash: &[u8; 64],
        recipient: PublicKey<'_>,
        body: Body<'_>,
        profile: Profile,
    ) -> Result<(), Error> {
        if !permits_private(body.kind()) {
            return Err(Fault::InvalidInput.into());
        }
        let short = envelope::SHORT_PREFIX
            .checked_add(body.encoded_len(profile)?)
            .ok_or(Fault::Overflow)?;
        let n = 100usize.checked_add(short).ok_or(Fault::Overflow)?;
        u16::try_from(n).map_err(|_| Fault::TooLarge)?;
        outer_fits(n)?;
        if n > N {
            return Err(Fault::Capacity.into());
        }
        self.clear();
        let result = (|| {
            wire::message::encode_short(
                &[0; 64],
                body,
                profile,
                padding::Encode::Absent,
                &mut self.bytes[100..n],
            )?;
            let digest = hash512(&self.bytes[164..n]);
            self.bytes[100..164].copy_from_slice(&digest);
            self.bytes[..64].copy_from_slice(original_hash);
            self.bytes[64..100].copy_from_slice(recipient.as_bytes());
            self.len = n;
            Ok(())
        })();
        if result.is_err() {
            self.clear();
        }
        result
    }
}
/// Read the actual TRANSCRIPT short payload with real hash verification. It is
/// plaintext; this is not a decryption or proof that the linked message exists.
/// The actual transcript producer emits an unpadded short payload, so meaningful
/// binary/text suffixes are preserved instead of C's ambiguous footer heuristic.
pub fn read_transcript(
    message: Message<'_>,
    profile: Profile,
) -> Result<signature::HashCheckedShort<'_>, Error> {
    let Body::Transcript { data, .. } = message.body() else {
        return Err(Fault::InvalidInput.into());
    };
    signature::decode_short(data.expose(), profile, padding::Decode::Absent)
}
/// Borrow an encoded PRIVATE owner for the original body codec, without an
/// extra ciphertext copy. This view itself carries no cryptographic proof.
pub fn private_body<const N: usize>(owner: &SensitiveBuffer<N>) -> Body<'_> {
    Body::Private {
        data: SensitiveBytes::new(owner.expose()),
    }
}
