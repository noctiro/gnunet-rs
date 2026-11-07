//! Standard hashes/KDF and version-pinned GNUnet peer/GNS cryptography.
//!
//! This crate never obtains entropy from an operating system or allocates heap memory.
//! Peer signatures follow GNUnet v0.29.1 `src/lib/util/crypto_ecc.c`: the private
//! key is a 32-byte Ed25519 seed, and the complete purpose-prefixed region is
//! signed directly, without a private domain or an extra prehash. GNS PKEY and
//! EDKEY key blinding/signatures and symmetric ciphers are provided here;
//! `gnunet-gnscrypto` owns label normalization and complete encrypted blocks.
//! CORE and communicator handshakes require their own protocol state machines.
#![no_std]
#![forbid(unsafe_code)]

mod crc32;
pub use crc32::crc32_n;
pub mod eddsa;
pub mod gns;
mod kdf;
#[cfg(feature = "pow")]
pub mod pow;
pub mod symmetric;
pub use kdf::hkdf_gnunet;

pub use eddsa::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature};
use gnunet_types::Error;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

/// Fallible entropy belonging to one live process instance. Implementations must fill
/// every byte or return an error; callers erase partial output before propagating failure.
pub trait Entropy {
    /// Fill `output` with fresh cryptographic random bytes, returning an error if unready.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error>;
}

/// Standard HMAC-SHA512 over exact ordered message parts. Key pads and the
/// returned tag retain the existing KDF primitive's zeroizing ownership. This
/// primitive grants no JWT issuer, audience, source or algorithm authorization.
#[must_use]
pub fn hmac512_parts(key: &[u8], parts: &[&[u8]]) -> zeroize::Zeroizing<[u8; 64]> {
    kdf::hmac512(key, parts)
}

/// SHA-256 with no hidden domain framing; callers supply canonical, domain-separated bytes.
#[must_use]
pub fn hash256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Incremental standard SHA-256 with fixed storage and no hidden domain framing.
/// Cloning preserves a public hashing checkpoint; this type must not hold secret keys.
#[derive(Clone, Default)]
pub struct Hash256State(Sha256);
impl Hash256State {
    /// Start an empty SHA-256 message.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Append the next canonical message bytes.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    /// Consume this checkpoint and return its standard digest.
    #[must_use]
    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// SHA-512 with no hidden domain framing; callers supply canonical, domain-separated bytes.
#[must_use]
pub fn hash512(input: &[u8]) -> [u8; 64] {
    Sha512::digest(input).into()
}

/// Incremental standard SHA-512 with fixed storage and no hidden domain framing.
/// Cloning retains a public hashing checkpoint, never a secret-key capability.
#[derive(Clone, Default)]
pub struct Hash512State(Sha512);
impl Hash512State {
    /// Start an empty standard SHA-512 message.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Append the next exact message bytes without buffering the complete input.
    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
    /// Consume this checkpoint and return its standard digest.
    #[must_use]
    pub fn finish(self) -> [u8; 64] {
        self.0.finalize().into()
    }
}

/// SHA-256 over ordered, concatenated slices, avoiding an intermediate allocation.
#[must_use]
pub fn hash256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

/// SHA-512 over ordered, concatenated slices, avoiding an intermediate allocation.
#[must_use]
pub fn hash512_parts(parts: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha512::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

/// Standard HKDF-SHA256; output is erased on an invalid output length.
pub fn hkdf256(salt: &[u8], ikm: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), Error> {
    kdf::hkdf256(salt, ikm, info, output)
}

#[cfg(test)]
pub(crate) mod test_support {
    use gnunet_types::Error;
    pub(crate) fn hex<const N: usize>(text: &str) -> Result<[u8; N], Error> {
        if text.len() != N.checked_mul(2).ok_or(Error::Overflow)? {
            return Err(Error::InvalidInput);
        }
        let mut bytes = [0; N];
        for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let nibble = |value: u8| match value {
                b'0'..=b'9' => Ok(value - b'0'),
                b'a'..=b'f' => Ok(value - b'a' + 10),
                _ => Err(Error::InvalidInput),
            };
            bytes[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Assertions compare published SHA and HKDF vectors in fallible tests."
    )]
    use super::*;
    use test_support::hex;
    #[test]
    fn published_incremental_sha256_vectors() -> Result<(), Error> {
        assert_eq!(
            Hash256State::new().finish(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?
        );
        let mut hash = Hash256State::new();
        hash.update(b"a");
        let mut checkpoint = hash.clone();
        hash.update(b"bc");
        checkpoint.update(b"b");
        checkpoint.update(b"c");
        let expected = hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")?;
        assert_eq!(hash.finish(), expected);
        assert_eq!(checkpoint.finish(), expected);
        Ok(())
    }
    #[test]
    fn published_hash_and_hkdf_vectors() -> Result<(), Error> {
        assert_eq!(
            hash256(b"abc"),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")?
        );
        assert_eq!(
            hash512(b"abc"),
            hex(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )?
        );
        let salt = hex::<13>("000102030405060708090a0b0c")?;
        let info = hex::<10>("f0f1f2f3f4f5f6f7f8f9")?;
        let mut output = [0; 42];
        hkdf256(&salt, &[0x0b; 22], &info, &mut output)?;
        assert_eq!(
            output,
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
            )?
        );
        Ok(())
    }

    #[test]
    fn standard_hash_parts_and_hkdf_failure_have_no_private_framing() -> Result<(), Error> {
        assert_eq!(hash256_parts(&[b"a", b"", b"bc"]), hash256(b"abc"));
        assert_eq!(hash512_parts(&[b"ab", b"c"]), hash512(b"abc"));
        let mut hash = Hash512State::new();
        hash.update(b"a");
        let mut checkpoint = hash.clone();
        hash.update(b"bc");
        checkpoint.update(b"b");
        checkpoint.update(b"c");
        assert_eq!(hash.finish(), hash512(b"abc"));
        assert_eq!(checkpoint.finish(), hash512(b"abc"));
        assert_eq!(Hash512State::new().finish(), hash512(b""));
        let mut oversized = [0xa5; 255 * 32 + 1];
        assert_eq!(
            hkdf256(b"salt", b"input", b"info", &mut oversized),
            Err(Error::InvalidInput)
        );
        assert_eq!(oversized, [0; 255 * 32 + 1]);
        let mut scratch = [0xa5; 17];
        erase(&mut scratch);
        assert_eq!(scratch, [0; 17]);
        Ok(())
    }
}

/// Erase caller-owned plaintext/scratch with compiler-resistant zeroization.
/// This does not erase copies retained by applications, devices, backups or compiler spills.
pub fn erase(bytes: &mut [u8]) {
    bytes.zeroize();
}
