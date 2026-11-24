//! Portable ML-DSA for targets without rscrypto, with the same RFC 9881 checks.

use super::{KeyEncoding, Profile, bind_public, matches_expanded};
use macula_mldsa::{ML_DSA_44, ML_DSA_65, ML_DSA_87, ParameterSet, PrivateKey};
use rustls::pki_types::{InvalidSignature, SubjectPublicKeyInfoDer};
use zeroize::Zeroizing;

pub(super) fn verify(
    profile: Profile,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    match macula_mldsa::verify(parameters(profile), public, message, signature, &[]) {
        Ok(true) => Ok(()),
        _ => Err(InvalidSignature),
    }
}

pub(super) struct Key {
    profile: Profile,
    expanded: Zeroizing<Vec<u8>>,
}

impl Key {
    pub(super) fn load(
        profile: Profile,
        encoding: KeyEncoding<'_>,
        expected: Option<&[u8]>,
    ) -> Option<(Self, SubjectPublicKeyInfoDer<'static>)> {
        let parameters = parameters(profile);
        let (public, expanded) = match encoding {
            KeyEncoding::Expanded(bytes) => {
                if !canonical_secret_coefficients(parameters, bytes) {
                    return None;
                }
                let public =
                    macula_mldsa::public_key(parameters, PrivateKey::Expanded(bytes)).ok()?;
                (public, Zeroizing::new(bytes.to_vec()))
            }
            KeyEncoding::Seed { seed, expanded } => {
                if expanded.is_some_and(|bytes| bytes.len() != parameters.private_key_len()) {
                    return None;
                }
                // Expand an already stored private seed once. Signing still
                // gets fresh OS randomness from the public backend API.
                let (public, generated) = macula_mldsa::internal::key_gen(parameters, seed);
                if !matches_expanded(&generated, expanded) {
                    return None;
                }
                (public, generated)
            }
        };
        let public = bind_public(profile, &public, expected)?;
        Some((Self { profile, expanded }, public))
    }

    pub(super) const fn profile(&self) -> Profile {
        self.profile
    }

    pub(super) fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        macula_mldsa::sign(
            parameters(self.profile),
            PrivateKey::Expanded(&self.expanded),
            message,
            &[],
        )
        .ok()
    }
}

const fn parameters(profile: Profile) -> ParameterSet {
    match profile {
        Profile::MlDsa44 => ML_DSA_44,
        Profile::MlDsa65 => ML_DSA_65,
        Profile::MlDsa87 => ML_DSA_87,
    }
}

fn canonical_secret_coefficients(parameters: ParameterSet, bytes: &[u8]) -> bool {
    if bytes.len() != parameters.private_key_len() {
        return false;
    }
    // FIPS 204 skEncode: rho, K, tr, followed by the packed s1 and s2
    // coefficients. Public-key regeneration checks t0 and tr separately.
    const PREFIX: usize = 32 + 32 + 64;
    const BYTES_PER_COEFFICIENT_BIT: usize = 256 / 8;
    let maximum = (2 * parameters.eta) as u16;
    let bits = maximum.ilog2() + 1;
    let mask = (1 << bits) - 1;
    let end = PREFIX + (parameters.l + parameters.k) * BYTES_PER_COEFFICIENT_BIT * bits as usize;
    let mut pending = 0u16;
    let mut held = 0;
    let mut invalid = 0;
    for &byte in &bytes[PREFIX..end] {
        pending |= u16::from(byte) << held;
        held += 8;
        while held >= bits {
            invalid |= maximum.wrapping_sub(pending & mask);
            pending >>= bits;
            held -= bits;
        }
    }
    (invalid as i16) >= 0
}

#[cfg(test)]
pub(super) fn test_material(profile: Profile, seed: &[u8; 32]) -> super::TestMaterial {
    let (public, expanded) = macula_mldsa::internal::key_gen(parameters(profile), seed);
    (expanded, public)
}
