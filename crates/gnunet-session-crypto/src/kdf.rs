//! Standard HMAC-SHA256 extract/expand and erased temporary key pads.
use gnunet_types::Error;
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

// Standard HMAC orchestration over RustCrypto SHA-2. Keep the padded key in an
// explicitly erased owner: hmac 0.13's get_der_key temporary has no drop erasure.
// SHA-2's enabled zeroize feature also erases the hash state and block buffers.
macro_rules! hmac {
    ($name:ident, $hash:ty, $block:literal, $digest:literal) => {
        fn $name<'a>(
            key: &[u8],
            parts: impl IntoIterator<Item = &'a [u8]>,
        ) -> Zeroizing<[u8; $digest]> {
            let mut pad = Zeroizing::new([0_u8; $block]);
            if key.len() > pad.len() {
                let mut hashed = <$hash>::digest(key);
                pad[..$digest].copy_from_slice(&hashed);
                hashed.zeroize();
            } else {
                pad[..key.len()].copy_from_slice(key);
            }
            for byte in pad.iter_mut() {
                *byte ^= 0x36;
            }
            let mut inner = <$hash>::new();
            inner.update(pad.as_ref());
            for part in parts {
                inner.update(part);
            }
            let mut inner_digest = inner.finalize();
            for byte in pad.iter_mut() {
                *byte ^= 0x36 ^ 0x5c;
            }
            let mut outer = <$hash>::new();
            outer.update(pad.as_ref());
            outer.update(&inner_digest);
            inner_digest.zeroize();
            let mut digest = outer.finalize();
            let mut result = Zeroizing::new([0_u8; $digest]);
            result.copy_from_slice(&digest);
            digest.zeroize();
            result
        }
    };
}
hmac!(hmac_sha512, Sha512, 128, 64);
hmac!(hmac_sha256, Sha256, 64, 32);

pub(crate) fn hmac512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    hmac_sha512(key, parts.iter().copied())
}

/// Exact `GNUNET_CRYPTO_hkdf_gnunet`: concatenate info slices without lengths
/// or NUL terminators. This differs from standard HKDF-SHA256's extract step.
/// Output is erased if its size exceeds 255 SHA-256 blocks.
#[cfg(test)]
pub fn hkdf_gnunet(
    salt: &[u8],
    ikm: &[u8],
    info: &[&[u8]],
    output: &mut [u8],
) -> Result<(), Error> {
    if output.len() > 255 * 32 {
        output.zeroize();
        return Err(Error::InvalidInput);
    }
    let prk = hmac512(salt, &[ikm]);
    expand256(prk.as_ref(), info, output)
}

#[cfg(test)]
pub(crate) fn hkdf256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<(), Error> {
    if output.len() > 255 * 32 {
        output.zeroize();
        return Err(Error::InvalidInput);
    }
    let prk = hmac_sha256(salt, [ikm]);
    expand256(prk.as_ref(), &[info], output)
}

// GNUNET's C expand preflights the concatenated context and the previous
// digest + context + counter buffer size before hashing or writing output.
// The explicit ceiling also lets tests prove the 32-bit size_t boundary without
// allocating or scanning multi-GiB contexts on a 64-bit host.
fn check_context_lengths(
    lengths: impl IntoIterator<Item = usize>,
    maximum: usize,
) -> Result<(), Error> {
    let mut total = 0_usize;
    for length in lengths {
        total = total
            .checked_add(length)
            .filter(|sum| *sum <= maximum)
            .ok_or(Error::Overflow)?;
    }
    total
        .checked_add(32 + 1)
        .filter(|sum| *sum <= maximum)
        .ok_or(Error::Overflow)?;
    Ok(())
}

pub(crate) fn expand256(prk: &[u8], info: &[&[u8]], output: &mut [u8]) -> Result<(), Error> {
    if let Err(error) = check_context_lengths(info.iter().map(|part| part.len()), usize::MAX) {
        output.zeroize();
        return Err(error);
    }
    let mut previous = Zeroizing::new([0_u8; 32]);
    let mut previous_len = 0;
    for (index, chunk) in output.chunks_mut(32).enumerate() {
        let counter = [u8::try_from(index + 1).map_err(|_| Error::Overflow)?];
        let next = hmac_sha256(
            prk,
            core::iter::once(&previous[..previous_len])
                .chain(info.iter().copied())
                .chain(core::iter::once(counter.as_slice())),
        );
        previous.copy_from_slice(next.as_ref());
        chunk.copy_from_slice(&previous[..chunk.len()]);
        previous_len = 32;
    }
    Ok(())
}

/// Owner-held standard HKDF-SHA256 pseudorandom key, erased on drop.
/// It is distinct from the 64-byte legacy GNUnet KDF material.
pub struct Prk(pub(crate) Zeroizing<[u8; 32]>);
impl Prk {
    /// Consume this owner for an explicit protocol secret transfer (such as PILS).
    /// The receiving buffer remains secret and must be erased by its owner.
    #[must_use]
    pub fn into_secret_bytes(self) -> Zeroizing<[u8; 32]> {
        self.0
    }
    /// Import exactly one caller-owned PRK; erase this local input copy.
    #[must_use]
    pub fn from_bytes(mut bytes: [u8; 32]) -> Self {
        let result = Self(Zeroizing::new(bytes));
        bytes.zeroize();
        result
    }
    /// Expand ordered context slices with no hidden lengths/NULs.
    pub fn expand(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), Error> {
        hkdf_expand(&self.0, info, output)
    }
    pub(crate) fn derive(&self, info: &[&[u8]]) -> Result<Self, Error> {
        let mut next = Zeroizing::new([0; 32]);
        self.expand(info, next.as_mut())?;
        Ok(Self(next))
    }
}
/// Official standard HMAC-SHA256 extract over ordered IKM bytes.
#[must_use]
pub fn hkdf_extract(salt: &[u8], ikm: &[&[u8]]) -> Prk {
    Prk(hmac_sha256(salt, ikm.iter().copied()))
}
/// Official standard HKDF-SHA256 expand, maximum 255 blocks.
/// Output is erased on excessive output size or C size_t context-size overflow.
pub fn hkdf_expand(prk: &[u8; 32], info: &[&[u8]], output: &mut [u8]) -> Result<(), Error> {
    if output.len() > 255 * 32 {
        output.zeroize();
        return Err(Error::InvalidInput);
    }
    expand256(prk, info, output)
}

#[cfg(test)]
mod context_length_tests {
    use super::check_context_lengths;
    use gnunet_types::Error;

    #[test]
    fn native_size_t_preflight_rejects_sum_and_digest_counter_overflow() {
        assert_eq!(check_context_lengths([], usize::MAX), Ok(()));
        assert_eq!(check_context_lengths([usize::MAX - 33], usize::MAX), Ok(()));
        assert_eq!(
            check_context_lengths([usize::MAX - 32], usize::MAX),
            Err(Error::Overflow)
        );
        assert_eq!(
            check_context_lengths([usize::MAX, 1], usize::MAX),
            Err(Error::Overflow)
        );
        assert_eq!(
            check_context_lengths([usize::MAX - 40, 7], usize::MAX),
            Ok(())
        );
        assert_eq!(
            check_context_lengths([usize::MAX - 40, 8], usize::MAX),
            Err(Error::Overflow)
        );
    }

    #[test]
    fn exact_32_bit_size_t_boundary_uses_the_same_checked_kernel_without_hashing() {
        let maximum = u32::MAX as usize;
        assert_eq!(check_context_lengths([maximum - 33], maximum), Ok(()));
        assert_eq!(
            check_context_lengths([maximum - 32], maximum),
            Err(Error::Overflow)
        );
        assert_eq!(
            check_context_lengths([maximum, 1], maximum),
            Err(Error::Overflow)
        );
        // A ~512 KiB reference table can exceed 32-bit size_t with repeated
        // slices sharing only one 65535-byte allocation. Test lengths only.
        assert_eq!(
            check_context_lengths(core::iter::repeat_n(65535, 65538), maximum),
            Err(Error::Overflow)
        );
        assert_eq!(
            check_context_lengths(core::iter::repeat_n(65535, 65536), maximum),
            Ok(())
        );
    }
}
