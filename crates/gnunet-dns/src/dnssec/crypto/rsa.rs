//! DNSKEY public components and RFC 8017 RSA signature verification.
use super::MAX_RSA_BYTES;
use crate::Error;
use crypto_bigint::{
    MontyForm, MontyMultiplier, Odd, Uint,
    modular::{FixedMontyForm, FixedMontyParams},
    nlimbs,
};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

const MAX_EXPONENT: u64 = (1 << 33) - 1;

// RFC 8017 section 9.2 DigestInfo prefixes, including the NULL parameters.
const SHA1_PREFIX: &[u8] = b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14";
const SHA256_PREFIX: &[u8] =
    b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20";
const SHA512_PREFIX: &[u8] =
    b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40";

pub(super) enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

pub(super) fn verify(
    algorithm: Algorithm,
    key: &[u8],
    message: &[u8],
    signed: &[u8],
) -> Result<(), Error> {
    let (modulus, exponent) = components(key, signed.len())?;
    // The equal-length big-endian encodings are ordered as unsigned integers.
    if signed >= modulus {
        return Err(Error::Authentication);
    }
    if modulus.last().is_none_or(|byte| byte & 1 == 0) {
        return Err(Error::Authentication);
    }
    let original = PublicRsa {
        modulus,
        exponent,
        signed,
    };
    match algorithm {
        Algorithm::Sha1 => original.verify_digest(SHA1_PREFIX, &Sha1::digest(message)),
        Algorithm::Sha256 => original.verify_digest(SHA256_PREFIX, &Sha256::digest(message)),
        Algorithm::Sha512 => original.verify_digest(SHA512_PREFIX, &Sha512::digest(message)),
    }
}

struct PublicRsa<'a> {
    modulus: &'a [u8],
    exponent: u64,
    signed: &'a [u8],
}

impl PublicRsa<'_> {
    fn verify_digest(&self, prefix: &[u8], digest: &[u8]) -> Result<(), Error> {
        // Backing widths cover every accepted modulus length, including
        // values between the usual key sizes. Most keys use a smaller array.
        match self.modulus.len() {
            ..=128 => self.verify_width::<{ nlimbs(1024) }>(prefix, digest),
            129..=256 => self.verify_width::<{ nlimbs(2048) }>(prefix, digest),
            257..=384 => self.verify_width::<{ nlimbs(3072) }>(prefix, digest),
            385..=512 => self.verify_width::<{ nlimbs(4096) }>(prefix, digest),
            513..=768 => self.verify_width::<{ nlimbs(6144) }>(prefix, digest),
            769..=MAX_RSA_BYTES => self.verify_width::<{ nlimbs(8192) }>(prefix, digest),
            _ => Err(Error::TooLarge),
        }
    }

    fn verify_width<const LIMBS: usize>(&self, prefix: &[u8], digest: &[u8]) -> Result<(), Error> {
        let bits = Uint::<LIMBS>::BITS;
        let modulus = Odd::new(Uint::<LIMBS>::from_be_slice_truncated(self.modulus, bits))
            .into_option()
            .ok_or(Error::Authentication)?;
        let params = FixedMontyParams::new_vartime(modulus);
        let integer = Uint::<LIMBS>::from_be_slice_truncated(self.signed, bits);
        let base = FixedMontyForm::new(&integer, &params);
        let mut result = base;
        let mut arithmetic: <FixedMontyForm<LIMBS> as MontyForm>::Multiplier<'_> = (&params).into();
        // The exponent is public and bounded. Starting at its leading one
        // avoids a window table of large intermediates on the device stack.
        let remaining = u64::BITS - self.exponent.leading_zeros() - 1;
        for bit in (0..remaining).rev() {
            arithmetic.square_assign(&mut result);
            if (self.exponent >> bit) & 1 != 0 {
                arithmetic.mul_assign(&mut result, &base);
            }
        }
        let recovered = result.retrieve().to_be_bytes();
        let skip = recovered
            .len()
            .checked_sub(self.signed.len())
            .ok_or(Error::Authentication)?;
        verify_emsa(&recovered[skip..], prefix, digest)
    }
}

fn components(key: &[u8], signature_bytes: usize) -> Result<(&[u8], u64), Error> {
    let (&first, body) = key.split_first().ok_or(Error::Truncated)?;
    let (exponent_len, body) = if first == 0 {
        let (length, body) = body.split_first_chunk::<2>().ok_or(Error::Truncated)?;
        let length = usize::from(u16::from_be_bytes(*length));
        if length <= usize::from(u8::MAX) {
            return Err(Error::Malformed);
        }
        (length, body)
    } else {
        (usize::from(first), body)
    };
    if exponent_len > MAX_RSA_BYTES {
        return Err(Error::TooLarge);
    }
    let (exponent, modulus) = body
        .split_at_checked(exponent_len)
        .ok_or(Error::Truncated)?;
    let leading = *modulus.first().ok_or(Error::Truncated)?;
    if exponent[0] == 0 || leading == 0 {
        return Err(Error::Malformed);
    }
    if modulus.len() > MAX_RSA_BYTES {
        return Err(Error::TooLarge);
    }
    let modulus_bits = modulus.len() * 8 - leading.leading_zeros() as usize;
    if !(1024..=8192).contains(&modulus_bits) {
        return Err(Error::Unsupported);
    }
    if signature_bytes != modulus.len() {
        return Err(Error::Malformed);
    }
    let mut bytes = [0; size_of::<u64>()];
    let skip = bytes
        .len()
        .checked_sub(exponent_len)
        .ok_or(Error::Authentication)?;
    bytes[skip..].copy_from_slice(exponent);
    let exponent = u64::from_be_bytes(bytes);
    if !(3..=MAX_EXPONENT).contains(&exponent) || exponent & 1 == 0 {
        return Err(Error::Authentication);
    }
    Ok((modulus, exponent))
}

fn verify_emsa(block: &[u8], prefix: &[u8], digest: &[u8]) -> Result<(), Error> {
    let header_end = block
        .len()
        .checked_sub(prefix.len() + digest.len())
        .ok_or(Error::Authentication)?;
    let (header, digest_info) = block.split_at(header_end);
    let [0, 1, padding @ .., 0] = header else {
        return Err(Error::Authentication);
    };
    let (encoded_prefix, encoded_digest) = digest_info.split_at(prefix.len());
    if padding.len() < 8
        || padding.iter().any(|&byte| byte != 0xff)
        || encoded_prefix != prefix
        || encoded_digest != digest
    {
        return Err(Error::Authentication);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_components_keep_wire_width_and_bound_the_exponent() {
        let modulus = [0xff; 128];
        let mut key = [0; 6 + 128];
        key[..6].copy_from_slice(&[5, 1, 0xff, 0xff, 0xff, 0xff]);
        key[6..].copy_from_slice(&modulus);
        assert_eq!(components(&key, 128), Ok((&modulus[..], MAX_EXPONENT)));
        assert_eq!(components(&key, 127), Err(Error::Malformed));
        key[1] = 2;
        assert_eq!(components(&key, 128), Err(Error::Authentication));
        key[1] = 1;
        key[5] = 0xfe;
        assert_eq!(components(&key, 128), Err(Error::Authentication));
        key[6] = 0x7f;
        assert_eq!(components(&key, 128), Err(Error::Unsupported));
        assert_eq!(components(&[0, 0, 1, 3], 128), Err(Error::Malformed));
    }

    #[test]
    fn pkcs1_requires_the_complete_canonical_block() {
        let digest = [42; 32];
        let mut block = [0xff; 11 + 19 + 32];
        block[..2].copy_from_slice(&[0, 1]);
        block[10] = 0;
        block[11..30].copy_from_slice(SHA256_PREFIX);
        block[30..].copy_from_slice(&digest);
        assert_eq!(verify_emsa(&block, SHA256_PREFIX, &digest), Ok(()));
        for offset in [2, 9, 10, 26, 30, block.len() - 1] {
            let mut changed = block;
            changed[offset] ^= 1;
            assert_eq!(
                verify_emsa(&changed, SHA256_PREFIX, &digest),
                Err(Error::Authentication)
            );
        }
        let mut short_padding = [0; 10 + 19 + 32];
        short_padding[..2].copy_from_slice(&block[..2]);
        short_padding[2..].copy_from_slice(&block[3..]);
        assert_eq!(
            verify_emsa(&short_padding, SHA256_PREFIX, &digest),
            Err(Error::Authentication)
        );
    }
}
