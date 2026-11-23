//! Quinn endpoint authentication keys that do not depend on its TLS provider.

use aes_gcm::{AeadInOut, Aes256Gcm};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use quinn::crypto::{AeadKey, CryptoError, HandshakeTokenKey, HmacKey};
use sha2::Sha256;
use std::{io, sync::Arc};
use zeroize::Zeroizing;

const TAG_LEN: usize = 16;
const RESET_SIGNATURE_LEN: usize = 32;
const ZERO_NONCE: [u8; 12] = [0; 12];

pub(super) fn endpoint_config() -> io::Result<quinn::EndpointConfig> {
    let seed = random_seed()?;
    let reset = ResetKey(Hmac::new((&*seed).into()));
    Ok(quinn::EndpointConfig::new(Arc::new(reset)))
}

pub(super) fn handshake_token_key() -> io::Result<Arc<dyn HandshakeTokenKey>> {
    let seed = random_seed()?;
    Ok(Arc::new(TokenKey::new(&seed)))
}

fn random_seed() -> io::Result<Zeroizing<[u8; 64]>> {
    let mut seed = Zeroizing::new([0; 64]);
    getrandom::fill(seed.as_mut())?;
    Ok(seed)
}

struct ResetKey(Hmac<Sha256>);

impl HmacKey for ResetKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        let mut mac = self.0.clone();
        mac.update(data);
        let tag = Zeroizing::new(mac.finalize().into_bytes());
        // Quinn sizes the destination using signature_len().
        signature_out.copy_from_slice(tag.as_ref());
    }

    fn signature_len(&self) -> usize {
        RESET_SIGNATURE_LEN
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let mut mac = self.0.clone();
        mac.update(data);
        mac.verify_slice(signature).map_err(|_| CryptoError)
    }
}

struct TokenKey(Hkdf<Sha256>);

impl TokenKey {
    fn new(seed: &[u8; 64]) -> Self {
        let (prk, hkdf) = Hkdf::<Sha256>::extract(None, seed);
        let _prk = Zeroizing::new(prk);
        Self(hkdf)
    }
}

impl HandshakeTokenKey for TokenKey {
    #[expect(
        clippy::expect_used,
        reason = "the AES key is exactly one HKDF-SHA256 output block"
    )]
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn AeadKey> {
        // Quinn stores a fresh random 128-bit value with each token. It is the
        // HKDF info for this individual AES-256-GCM key, so the nonce is zero.
        let mut key = Zeroizing::new([0u8; 32]);
        self.0
            .expand(random_bytes, key.as_mut())
            .expect("32-byte HKDF output");
        Box::new(TokenCipher(Aes256Gcm::new((&*key).into())))
    }
}

struct TokenCipher(Aes256Gcm);

impl AeadKey for TokenCipher {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError> {
        data.try_reserve(TAG_LEN).map_err(|_| CryptoError)?;
        let tag = self
            .0
            .encrypt_inout_detached(
                (&ZERO_NONCE).into(),
                additional_data,
                data.as_mut_slice().into(),
            )
            .map_err(|_| CryptoError)?;
        data.extend_from_slice(&tag);
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError> {
        let data_len = data.len().checked_sub(TAG_LEN).ok_or(CryptoError)?;
        let (body, tag) = data.split_at_mut(data_len);
        let tag = <&[u8; TAG_LEN]>::try_from(&*tag).map_err(|_| CryptoError)?;
        self.0
            .decrypt_inout_detached(
                (&ZERO_NONCE).into(),
                additional_data,
                (&mut *body).into(),
                tag.into(),
            )
            .map_err(|_| CryptoError)?;
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert checksum and token interoperability"
    )]
    fn handshake_token_authenticates_entropy_and_aad() -> Result<(), CryptoError> {
        let key = TokenKey::new(&[1; 64]);
        let salt = [2; 16];
        let cipher = key.aead_from_hkdf(&salt);
        let mut body = b"address and expiry".to_vec();
        cipher.seal(&mut body, b"associated data")?;
        let other = key.aead_from_hkdf(&[3; 16]);
        assert!(other.open(&mut body, b"associated data").is_err());
        assert!(cipher.open(&mut body, b"wrong data").is_err());
        let restored = key.aead_from_hkdf(&salt);
        assert_eq!(
            restored.open(&mut body, b"associated data")?,
            b"address and expiry"
        );
        Ok(())
    }
}
