//! Peer Ed25519 seed keys and exact GNUnet signature-purpose regions.
//!
//! Reference: GNUnet v0.29.1 `src/lib/util/crypto_ecc.c`, functions
//! `GNUNET_CRYPTO_eddsa_key_get_public`, `GNUNET_CRYPTO_eddsa_sign_` and
//! `GNUNET_CRYPTO_eddsa_verify_`. These use ordinary Ed25519 over the entire
//! region beginning at `GNUNET_CRYPTO_SignaturePurpose`, not Ed25519ph or a
//! separately hashed/private envelope. Signature validity alone does not grant
//! a contact, service capability, lifetime or protocol authorization.

use crate::Entropy;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use gnunet_types::Error;
use gnunet_wire::official::{SIGNATURE_PURPOSE_LEN, SignaturePurpose};
use zeroize::{Zeroize, Zeroizing};

/// An owner-held 32-byte peer Ed25519 seed, erased on drop.
///
/// No cloning, debug formatting, serialization or seed export is provided.
/// `ed25519-dalek`'s workspace `zeroize` feature erases its secret on drop.
///
/// ```compile_fail
/// let key = gnunet_crypto::EddsaPrivateKey::from_seed([0; 32]);
/// let _copy = key.clone();
/// ```
///
/// ```compile_fail
/// let key = gnunet_crypto::EddsaPrivateKey::from_seed([0; 32]);
/// let _printed = format!("{key:?}");
/// ```
pub struct EddsaPrivateKey(SigningKey);

impl EddsaPrivateKey {
    /// Derive an official peer key from a persisted Ed25519 seed.
    ///
    /// This function erases its local input copy. The caller must erase any
    /// separately retained seed bytes and control access to persistent storage.
    #[must_use]
    pub fn from_seed(mut seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self(key)
    }

    /// Generate an unclamped Ed25519 seed from caller-supplied fresh entropy.
    /// All temporary seed bytes are erased on success and on entropy failure.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0; 32]);
        fill_seed(entropy, &mut seed)?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    /// Derive the 32 public identity bytes; this does not authenticate a peer.
    #[must_use]
    pub fn public_key(&self) -> EddsaPublicKey {
        EddsaPublicKey(self.0.verifying_key().to_bytes())
    }

    /// Sign arbitrary bytes without a GNUnet purpose header, as required by
    /// the active REST `/sign` raw EdDSA contract. The caller must authorize
    /// this raw-signing operation and choose exactly which bytes may be signed.
    /// This signature alone grants no protocol-purpose or identity authority.
    #[must_use]
    pub fn sign_raw(&self, bytes: &[u8]) -> EddsaSignature {
        EddsaSignature(self.0.sign(bytes).to_bytes())
    }

    /// Sign exactly one complete, expected-purpose GNUnet signed region.
    ///
    /// Its eight-byte header must advertise exactly `signed_region.len()`;
    /// truncated prefixes, trailing data and purpose mismatches are rejected.
    /// The protocol owner chooses and authorizes `expected_purpose`.
    pub fn sign(
        &self,
        expected_purpose: u32,
        signed_region: &[u8],
    ) -> Result<EddsaSignature, Error> {
        validate_region(expected_purpose, signed_region)?;
        Ok(EddsaSignature(self.0.sign(signed_region).to_bytes()))
    }
}

/// Unauthenticated public Ed25519 identity bytes, not an admitted peer contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EddsaPublicKey([u8; 32]);

impl EddsaPublicKey {
    /// Retain untrusted wire bytes. Curve/signature validation occurs in `verify`.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact official public-key representation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verify an expected-purpose region and its ordinary Ed25519 signature.
    ///
    /// Requires exact signed size, canonical public-key/R/S encodings and
    /// rejects small-order keys/R. Service-specific identity binding, expiry,
    /// authorization and replay checks remain the protocol owner's work.
    pub fn verify(
        self,
        expected_purpose: u32,
        signed_region: &[u8],
        signature: &EddsaSignature,
    ) -> Result<(), Error> {
        validate_region(expected_purpose, signed_region)?;
        let key = VerifyingKey::from_bytes(&self.0).map_err(|_| Error::Authentication)?;
        if key.to_edwards().compress().to_bytes() != self.0 {
            return Err(Error::Authentication);
        }
        key.verify_strict(
            signed_region,
            &ed25519_dalek::Signature::from_bytes(&signature.0),
        )
        .map_err(|_| Error::Authentication)
    }
}

/// Unverified 64-byte Ed25519 signature in the official wire representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EddsaSignature([u8; 64]);

impl EddsaSignature {
    /// Retain untrusted signature bytes without giving them authority.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact signature bytes for an official message or record.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

fn validate_region(expected_purpose: u32, signed_region: &[u8]) -> Result<(), Error> {
    let prefix = signed_region
        .get(..SIGNATURE_PURPOSE_LEN)
        .ok_or(Error::Truncated)?;
    let header = SignaturePurpose::decode(prefix)?;
    header.validate_signed_size(signed_region.len())?;
    if header.purpose() != expected_purpose {
        return Err(Error::Authentication);
    }
    Ok(())
}

fn fill_seed(entropy: &mut impl Entropy, output: &mut [u8; 32]) -> Result<(), Error> {
    if entropy.fill(output).is_err() {
        output.zeroize();
        return Err(Error::Entropy);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Fallible tests compare published/independent signatures and malformed input boundaries."
    )]
    use super::*;
    use crate::test_support::hex;

    #[test]
    fn rfc8032_seed_public_and_unprehashed_ed25519_vector() -> Result<(), Error> {
        let key = EddsaPrivateKey::from_seed(hex(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )?);
        assert_eq!(
            key.public_key().as_bytes(),
            &hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")?
        );
        // RFC 8032's empty-message test validates the underlying ordinary
        // Ed25519 algorithm. The public API requires a GNUnet purpose region.
        assert_eq!(
            key.0.sign(b"").to_bytes(),
            hex::<64>(
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            )?
        );
        Ok(())
    }

    #[test]
    fn openssl_signature_covers_the_complete_official_region() -> Result<(), Error> {
        let key = EddsaPrivateKey::from_seed(core::array::from_fn(|i| i as u8));
        let region = include_bytes!("../tests/fixtures/peer-purpose.bin");
        let signature =
            EddsaSignature::from_bytes(*include_bytes!("../tests/fixtures/peer-purpose.sig"));
        assert_eq!(
            key.public_key().as_bytes(),
            include_bytes!("../tests/fixtures/peer-public.bin")
        );
        assert_eq!(key.sign(7, region)?, signature);
        key.public_key().verify(7, region, &signature)?;
        assert_eq!(key.sign(8, region), Err(Error::Authentication));
        assert_eq!(
            key.public_key().verify(8, region, &signature),
            Err(Error::Authentication)
        );
        let mut tampered = *region;
        tampered[8] ^= 1;
        assert_eq!(
            key.public_key().verify(7, &tampered, &signature),
            Err(Error::Authentication)
        );
        let prehashed = EddsaSignature(key.0.sign(&crate::hash512(region)).to_bytes());
        assert_eq!(
            key.public_key().verify(7, region, &prehashed),
            Err(Error::Authentication)
        );
        Ok(())
    }

    #[test]
    fn prefixes_exact_size_and_noncanonical_signatures_are_rejected() -> Result<(), Error> {
        let key = EddsaPrivateKey::from_seed([1; 32]);
        let region = include_bytes!("../tests/fixtures/peer-purpose.bin");
        let signature = key.sign(7, region)?;
        for size in 0..SIGNATURE_PURPOSE_LEN {
            assert_eq!(key.sign(7, &region[..size]), Err(Error::Truncated));
            assert_eq!(
                key.public_key().verify(7, &region[..size], &signature),
                Err(Error::Truncated)
            );
        }
        for size in [
            0,
            7,
            8,
            region.len() - 1,
            region.len() + 1,
            u32::MAX as usize,
        ] {
            let mut changed = *region;
            changed[..4].copy_from_slice(&(size as u32).to_be_bytes());
            assert_eq!(key.sign(7, &changed), Err(Error::InvalidInput));
            assert_eq!(
                key.public_key().verify(7, &changed, &signature),
                Err(Error::InvalidInput)
            );
        }
        assert_eq!(
            key.sign(7, &region[..region.len() - 1]),
            Err(Error::InvalidInput)
        );
        let mut noncanonical = *signature.as_bytes();
        noncanonical[63] |= 0x80;
        assert_eq!(
            key.public_key()
                .verify(7, region, &EddsaSignature::from_bytes(noncanonical)),
            Err(Error::Authentication)
        );
        for public in [[0; 32], [0xff; 32]] {
            assert_eq!(
                EddsaPublicKey::from_bytes(public).verify(7, region, &signature),
                Err(Error::Authentication)
            );
        }
        Ok(())
    }

    #[test]
    fn header_only_region_is_valid_and_entropy_failures_erase_partial_seed() -> Result<(), Error> {
        struct Source(bool);
        impl Entropy for Source {
            fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
                output.fill(0xa5);
                if self.0 { Ok(()) } else { Err(Error::Io) }
            }
        }
        let mut seed = [0x12; 32];
        assert_eq!(
            fill_seed(&mut Source(false), &mut seed),
            Err(Error::Entropy)
        );
        assert_eq!(seed, [0; 32]);
        assert!(matches!(
            EddsaPrivateKey::generate(&mut Source(false)),
            Err(Error::Entropy)
        ));
        let key = EddsaPrivateKey::generate(&mut Source(true))?;
        assert_eq!(
            key.public_key(),
            EddsaPrivateKey::from_seed([0xa5; 32]).public_key()
        );
        let mut region = [0; SIGNATURE_PURPOSE_LEN];
        SignaturePurpose::new(0xffff_ffff, 0)?.encode(&mut region)?;
        let signature = key.sign(0xffff_ffff, &region)?;
        key.public_key().verify(0xffff_ffff, &region, &signature)?;
        Ok(())
    }
}
