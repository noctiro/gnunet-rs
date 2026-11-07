//! Actual DNSSEC verification/digests via the installed aws-lc-rs provider.
//! DNSKEY inputs below are only the public-key field, without flags/protocol/
//! algorithm. This verifier neither signs, creates keys nor supplies trust.
use aws_lc_rs::{digest, signature};
use gnunet_dns::dnssec::{Crypto, denial::Sha1};
use gnunet_types::Error;

// Canonical signed RRsets may expand compressed DNS names beyond a 65535-byte
// packet. Keep a separate bounded canonical-message/digest profile; do not
// incorrectly apply the wire packet size to the expanded signed message.
const MAX_INPUT: usize = 8 * 1024 * 1024;
const MAX_PARTS: usize = 64;
const MAX_RSA_BYTES: usize = 1024;
const MAX_RSA_KEY: usize = 3 + 2 * MAX_RSA_BYTES;

pub(super) struct Backend;
impl Crypto for Backend {
    fn verify(
        &self,
        algorithm: u8,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        // Unsupported algorithms never acquire acceptance by sharing a key shape
        // with another algorithm. MD5/DSA/GOST and unknown values are excluded.
        match algorithm {
            5 | 7 | 8 | 10 | 13 | 14 | 15 => {}
            _ => return Err(Error::Unsupported),
        }
        if message.len() > MAX_INPUT || key.len() > MAX_RSA_KEY || signature.len() > MAX_RSA_BYTES {
            return Err(Error::TooLarge);
        }
        match algorithm {
            // Legacy SHA-1 is verification-only here, including its NSEC3 alias.
            5 | 7 => rsa(
                &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                key,
                message,
                signature,
            ),
            8 => rsa(
                &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                key,
                message,
                signature,
            ),
            10 => rsa(
                &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
                key,
                message,
                signature,
            ),
            13 => ec_fixed(
                &signature::ECDSA_P256_SHA256_FIXED,
                64,
                key,
                message,
                signature,
            ),
            14 => ec_fixed(
                &signature::ECDSA_P384_SHA384_FIXED,
                96,
                key,
                message,
                signature,
            ),
            15 => {
                if key.len() != 32 || signature.len() != 64 {
                    return Err(Error::Malformed);
                }
                signature::UnparsedPublicKey::new(&signature::ED25519, key)
                    .verify(message, signature)
                    .map_err(|_| Error::Authentication)
            }
            _ => Err(Error::Unsupported),
        }
    }
    fn digest(&self, algorithm: u8, parts: &[&[u8]], output: &mut [u8]) -> Result<usize, Error> {
        let algorithm = match algorithm {
            1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            2 => &digest::SHA256,
            4 => &digest::SHA384,
            _ => return Err(Error::Unsupported),
        };
        digest_parts(algorithm, parts, output)
    }
}
impl Sha1 for Backend {
    fn hash(&mut self, input: &[u8], output: &mut [u8; 20]) -> Result<(), Error> {
        // Denial/NSEC3 hashing is the same real SHA-1 primitive, without a
        // separate parser, implicit salt, iterations or substitute algorithm.
        digest_parts(&digest::SHA1_FOR_LEGACY_USE_ONLY, &[input], output)?;
        Ok(())
    }
}

fn rsa(
    algorithm: &signature::RsaParameters,
    key: &[u8],
    message: &[u8],
    signed: &[u8],
) -> Result<(), Error> {
    let first = *key.first().ok_or(Error::Truncated)?;
    let (offset, exponent_len): (usize, usize) = if first == 0 {
        let length = key.get(1..3).ok_or(Error::Truncated)?;
        (3, usize::from(u16::from_be_bytes([length[0], length[1]])))
    } else {
        (1, usize::from(first))
    };
    if exponent_len == 0 {
        return Err(Error::Malformed);
    }
    if exponent_len > MAX_RSA_BYTES {
        return Err(Error::TooLarge);
    }
    let end = offset.checked_add(exponent_len).ok_or(Error::Overflow)?;
    let exponent = key.get(offset..end).ok_or(Error::Truncated)?;
    let modulus = key.get(end..).ok_or(Error::Truncated)?;
    let leading = *modulus.first().ok_or(Error::Truncated)?;
    if exponent[0] == 0 || leading == 0 {
        return Err(Error::Malformed);
    }
    if modulus.len() > MAX_RSA_BYTES {
        return Err(Error::TooLarge);
    }
    let bits = (modulus.len() - 1)
        .checked_mul(8)
        .and_then(|n| n.checked_add((u8::BITS - leading.leading_zeros()) as usize))
        .ok_or(Error::Overflow)?;
    if !(1024..=8192).contains(&bits) {
        return Err(Error::Unsupported);
    }
    // DNSSEC RSA signatures have the exact unsigned modulus extent. They are
    // not DER integers and are not resized/zero-padded by this adapter.
    if signed.len() != modulus.len() {
        return Err(Error::Malformed);
    }
    signature::RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    }
    .verify(algorithm, message, signed)
    .map_err(|_| Error::Authentication)
}
fn ec_fixed(
    algorithm: &'static dyn signature::VerificationAlgorithm,
    extent: usize,
    key: &[u8],
    message: &[u8],
    signed: &[u8],
) -> Result<(), Error> {
    if key.len() != extent || signed.len() != extent {
        return Err(Error::Malformed);
    }
    // RFC6605 DNSKEY contains x||y and RRSIG contains fixed r||s. AWS-LC's
    // fixed verifier accepts the SEC1 uncompressed point 04||x||y directly.
    let mut point = [0u8; 97];
    point[0] = 4;
    let used = extent.checked_add(1).ok_or(Error::Overflow)?;
    let destination = point.get_mut(1..used).ok_or(Error::TooLarge)?;
    destination.copy_from_slice(key);
    signature::UnparsedPublicKey::new(algorithm, &point[..used])
        .verify(message, signed)
        .map_err(|_| Error::Authentication)
}
fn digest_parts(
    algorithm: &'static digest::Algorithm,
    parts: &[&[u8]],
    output: &mut [u8],
) -> Result<usize, Error> {
    if parts.len() > MAX_PARTS {
        return Err(Error::TooLarge);
    }
    let total = parts.iter().try_fold(0usize, |n, part| {
        n.checked_add(part.len()).ok_or(Error::Overflow)
    })?;
    if total > MAX_INPUT {
        return Err(Error::TooLarge);
    }
    let length = algorithm.output_len();
    if output.len() < length {
        return Err(Error::Capacity);
    }
    // Public Context is streaming: no concatenated message or unbounded output
    // allocation is introduced. The bounded total is far below its native
    // maximum; provider initialization/finalization retain AWS-LC's documented
    // fatal-resource panic boundary rather than fabricating a digest on failure.
    let mut context = digest::Context::new(algorithm);
    for part in parts {
        context.update(part);
    }
    let actual = context.finish();
    let bytes = actual.as_ref();
    if bytes.len() != length {
        return Err(Error::Io);
    }
    output[..length].copy_from_slice(bytes);
    Ok(length)
}
