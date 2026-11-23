//! Bounded, allocation-free DNSSEC hashing and public signature verification.
mod rsa;
#[cfg(test)]
mod tests;

use super::{Crypto, denial::Sha1};
use crate::Error;
use ed448_goldilocks::{PUBLIC_KEY_LENGTH as ED448_POINT_BYTES, Signature, VerifyingKey};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use p256::ecdsa::signature::Verifier;
use sha2::{Digest, Sha256, Sha384};

// Canonical signed RRsets can expand compressed DNS names past the DNS wire
// packet limit. Bound the expanded message independently of packet size.
const MAX_INPUT: usize = 8 * 1024 * 1024;
const MAX_PARTS: usize = 64;
const MAX_RSA_BYTES: usize = 1024;
const MAX_RSA_KEY: usize = 3 + 2 * MAX_RSA_BYTES;

/// Validate RSASHA1, RSASHA1-NSEC3-SHA1, RSASHA256/512,
/// ECDSAP256SHA256, ECDSAP384SHA384, Ed25519, and Ed448 using the original DNSKEY
/// bytes. DS digests support SHA-1, SHA-256 and SHA-384. NSEC3 uses SHA-1.
/// Every check uses fixed workspace with no heap, I/O or implicit trust.
pub struct Backend;

enum SignatureAlgorithm {
    Rsa(rsa::Algorithm),
    EcdsaP256,
    EcdsaP384,
    Ed25519,
    Ed448,
}

impl SignatureAlgorithm {
    fn from_wire(algorithm: u8) -> Option<Self> {
        Some(match algorithm {
            5 | 7 => Self::Rsa(rsa::Algorithm::Sha1),
            8 => Self::Rsa(rsa::Algorithm::Sha256),
            10 => Self::Rsa(rsa::Algorithm::Sha512),
            13 => Self::EcdsaP256,
            14 => Self::EcdsaP384,
            15 => Self::Ed25519,
            16 => Self::Ed448,
            _ => return None,
        })
    }
}

enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
}

impl DigestAlgorithm {
    fn from_wire(algorithm: u8) -> Option<Self> {
        Some(match algorithm {
            1 => Self::Sha1,
            2 => Self::Sha256,
            4 => Self::Sha384,
            _ => return None,
        })
    }
}

impl Crypto for Backend {
    fn supports_signature(&self, algorithm: u8) -> bool {
        SignatureAlgorithm::from_wire(algorithm).is_some()
    }

    fn supports_digest(&self, algorithm: u8) -> bool {
        DigestAlgorithm::from_wire(algorithm).is_some()
    }

    fn verify(
        &self,
        algorithm: u8,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        use SignatureAlgorithm::{EcdsaP256, EcdsaP384, Ed448, Ed25519, Rsa};
        let algorithm = SignatureAlgorithm::from_wire(algorithm).ok_or(Error::Unsupported)?;
        if message.len() > MAX_INPUT || key.len() > MAX_RSA_KEY || signature.len() > MAX_RSA_BYTES {
            return Err(Error::TooLarge);
        }
        match algorithm {
            Rsa(algorithm) => rsa::verify(algorithm, key, message, signature),
            EcdsaP256 => {
                let point = sec1_point::<65>(key, signature)?;
                let public = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map_err(|_| Error::Authentication)?;
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| Error::Authentication)?;
                public
                    .verify(message, &signature)
                    .map_err(|_| Error::Authentication)
            }
            EcdsaP384 => {
                let point = sec1_point::<97>(key, signature)?;
                let public = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point)
                    .map_err(|_| Error::Authentication)?;
                let signature = p384::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| Error::Authentication)?;
                public
                    .verify(message, &signature)
                    .map_err(|_| Error::Authentication)
            }
            Ed25519 => {
                let key = key.try_into().map_err(|_| Error::Malformed)?;
                let signature = signature.try_into().map_err(|_| Error::Malformed)?;
                EddsaPublicKey::from_bytes(key)
                    .verify_message(message, &EddsaSignature::from_bytes(signature))
            }
            Ed448 => verify_ed448(key, message, signature),
        }
    }

    fn digest(&self, algorithm: u8, parts: &[&[u8]], output: &mut [u8]) -> Result<usize, Error> {
        match DigestAlgorithm::from_wire(algorithm).ok_or(Error::Unsupported)? {
            DigestAlgorithm::Sha1 => digest_parts::<sha1::Sha1>(parts, output),
            DigestAlgorithm::Sha256 => digest_parts::<Sha256>(parts, output),
            DigestAlgorithm::Sha384 => digest_parts::<Sha384>(parts, output),
        }
    }
}

fn verify_ed448(key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    let key = key.try_into().map_err(|_| Error::Malformed)?;
    let signature = Signature::from_slice(signature).map_err(|_| Error::Malformed)?;
    if !canonical_ed448_point(key) || !canonical_ed448_point(signature.r_bytes()) {
        return Err(Error::Authentication);
    }
    let public = VerifyingKey::from_bytes(key).map_err(|_| Error::Authentication)?;
    public
        .verify_raw(&signature, message)
        .map_err(|_| Error::Authentication)
}

fn canonical_ed448_point(point: &[u8; ED448_POINT_BYTES]) -> bool {
    // RFC 8032 §5.2.3. Only the sign bit may be set in the final byte.
    // The remaining little-endian coordinate must be below p = 2^448 - 2^224 - 1.
    const FIELD_MODULUS: [u8; ED448_POINT_BYTES - 1] = {
        let mut modulus = [0xff; ED448_POINT_BYTES - 1];
        modulus[28] = 0xfe;
        modulus
    };
    let [coordinate @ .., sign] = point;
    sign & 0x7f == 0
        && coordinate
            .iter()
            .rev()
            .cmp(FIELD_MODULUS.iter().rev())
            .is_lt()
}

impl Sha1 for Backend {
    fn hash(&mut self, input: &[u8], output: &mut [u8; 20]) -> Result<(), Error> {
        digest_parts::<sha1::Sha1>(&[input], output).map(|_| ())
    }
}

// RFC 6605 DNSKEY and RRSIG use fixed x||y and r||s encodings. Add only the
// SEC1 uncompressed point prefix before the curve backend validates the point.
fn sec1_point<const SIZE: usize>(key: &[u8], signature: &[u8]) -> Result<[u8; SIZE], Error> {
    if key.len() != SIZE - 1 || signature.len() != SIZE - 1 {
        return Err(Error::Malformed);
    }
    let mut point = [0; SIZE];
    point[0] = 4;
    point[1..].copy_from_slice(key);
    Ok(point)
}

fn digest_parts<D: Digest>(parts: &[&[u8]], output: &mut [u8]) -> Result<usize, Error> {
    if parts.len() > MAX_PARTS {
        return Err(Error::TooLarge);
    }
    let length = parts.iter().try_fold(0usize, |n, part| {
        n.checked_add(part.len()).ok_or(Error::Overflow)
    })?;
    if length > MAX_INPUT {
        return Err(Error::TooLarge);
    }
    let written = <D as Digest>::output_size();
    let output = output.get_mut(..written).ok_or(Error::Capacity)?;
    let mut context = D::new();
    for part in parts {
        context.update(part);
    }
    output.copy_from_slice(&context.finalize());
    Ok(written)
}
