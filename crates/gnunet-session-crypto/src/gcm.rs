//! AES256-GCM with the official UDP communicator's nonce12 and full tag16.
//!
//! The existing AES backend supplies the block cipher; approved RustCrypto
//! GHASH supplies field arithmetic. This primitive accepts explicit AAD, while
//! the separate official UDP payload methods always supply empty AAD.
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use ghash::{GHash, universal_hash::UniversalHash};
use gnunet_types::Error;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Official AES256 key width.
pub const KEY_BYTES: usize = 32;
/// Official `AES_IV_SIZE = 96/8`, not16.
pub const NONCE_BYTES: usize = 12;
/// Official full GCM authentication tag width.
pub const TAG_BYTES: usize = 16;
/// NIST SP800-38D payload limit:2^32-2 blocks, including a partial final block.
pub const MAX_PLAINTEXT_BYTES: u64 = (1_u64 << 36) - 32;
/// Maximum whole-byte AAD whose bit length fits the64-bit GHASH length field.
pub const MAX_ASSOCIATED_BYTES: u64 = (1_u64 << 61) - 1;

/// Check logical byte counts without allocating/scanning an enormous buffer.
/// This is a standard primitive bound, not a claim of huge C-buffer execution.
pub fn validate_lengths(plaintext_len: u64, aad_len: u64) -> Result<(), Error> {
    if plaintext_len > MAX_PLAINTEXT_BYTES || aad_len > MAX_ASSOCIATED_BYTES {
        return Err(Error::TooLarge);
    }
    Ok(())
}
fn preflight(plaintext_len: usize, aad_len: usize) -> Result<(), Error> {
    validate_lengths(
        u64::try_from(plaintext_len).map_err(|_| Error::Overflow)?,
        u64::try_from(aad_len).map_err(|_| Error::Overflow)?,
    )
}
/// Exclusive cipher and GHASH subkey owner. No Clone/Debug or key byte view.
/// AES member Drop erases the expanded key; the explicit H owner is Zeroizing.
/// Per-operation GHash owns Polyval, whose enabled zeroize Drop erases its state.
/// Dependency-internal conversion temporaries/registers are not covered by an
/// all-copies erasure promise; no post-drop memory inspection is performed.
pub struct Aes256Gcm {
    cipher: aes::Aes256,
    h: Zeroizing<[u8; 16]>,
}
impl Aes256Gcm {
    /// Import exactly one explicit key and erase this local input copy.
    /// Any other copies retained by the caller remain its responsibility.
    #[must_use]
    pub fn from_bytes(mut key: [u8; KEY_BYTES]) -> Self {
        let cipher = aes::Aes256::new((&key).into());
        key.zeroize();
        let mut h = Zeroizing::new([0; 16]);
        cipher.encrypt_block((&mut *h).into());
        Self { cipher, h }
    }
    /// Encrypt caller bytes in place and return a detached tag. Length refusal
    /// precedes all output mutation; nonce uniqueness belongs to the caller.
    pub fn seal(
        &self,
        nonce: &[u8; NONCE_BYTES],
        aad: &[u8],
        bytes: &mut [u8],
    ) -> Result<[u8; TAG_BYTES], Error> {
        preflight(bytes.len(), aad.len())?;
        self.apply(nonce, bytes);
        Ok(self.tag(nonce, aad, bytes))
    }
    /// Authenticate ciphertext before decryption. Invalid authentication erases
    /// the complete mutable range; resource refusal leaves it unchanged.
    pub fn open(
        &self,
        nonce: &[u8; NONCE_BYTES],
        aad: &[u8],
        bytes: &mut [u8],
        tag: &[u8; TAG_BYTES],
    ) -> Result<(), Error> {
        preflight(bytes.len(), aad.len())?;
        let expected = self.tag(nonce, aad, bytes);
        if !bool::from(expected.ct_eq(tag)) {
            bytes.zeroize();
            return Err(Error::Authentication);
        }
        self.apply(nonce, bytes);
        Ok(())
    }
    fn tag(&self, nonce: &[u8; NONCE_BYTES], aad: &[u8], ciphertext: &[u8]) -> [u8; TAG_BYTES] {
        let mut hash = GHash::new((&*self.h).into());
        hash.update_padded(aad);
        hash.update_padded(ciphertext);
        let mut lengths = [0_u8; 16];
        // preflight proved both byte-to-bit multiplications fit u64.
        lengths[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        lengths[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
        hash.update(&[lengths.into()]);
        let mut result = hash.finalize();
        let mut mask = Zeroizing::new(j0(nonce));
        self.cipher.encrypt_block((&mut *mask).into());
        for (byte, key) in result.iter_mut().zip(mask.iter()) {
            *byte ^= *key;
        }
        result.into()
    }
    fn apply(&self, nonce: &[u8; NONCE_BYTES], bytes: &mut [u8]) {
        let mut counter = Zeroizing::new(j0(nonce));
        let mut block = Zeroizing::new([0; 16]);
        // J0's counter1 masks the tag. Actual data starts at inc32(J0)=2.
        // At most2^32-2 blocks are processed, so data never reuses counter1/0.
        for chunk in bytes.chunks_mut(16) {
            inc32(&mut counter);
            block.copy_from_slice(counter.as_ref());
            self.cipher.encrypt_block((&mut *block).into());
            for (byte, key) in chunk.iter_mut().zip(block.iter()) {
                *byte ^= *key;
            }
        }
    }
}
fn j0(nonce: &[u8; NONCE_BYTES]) -> [u8; 16] {
    let mut block = [0; 16];
    block[..NONCE_BYTES].copy_from_slice(nonce);
    block[15] = 1;
    block
}
fn inc32(counter: &mut [u8; 16]) {
    let next =
        u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]).wrapping_add(1);
    counter[12..].copy_from_slice(&next.to_be_bytes());
}

#[cfg(test)]
mod nist_vectors;
#[cfg(test)]
mod tests;
