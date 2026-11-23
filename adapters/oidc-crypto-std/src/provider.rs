//! Bounded RSA key ownership and RS256 operations.
use crypto_bigint::CtEq;
use getrandom::SysRng;
use gnunet_types::Error;
use rsa::{
    BoxedUint, PrivateKey, PublicKey,
    pkcs1::{self, RsaPrivateKeyRef},
    pkcs8::{
        self, EncodePrivateKey, PrivateKeyInfoRef,
        der::{Decode, SecretDocument, asn1::Null},
    },
    sha2::Sha256,
    traits::{PrivateKeyParts, PublicKeyParts},
};
use std::{mem, ops::RangeInclusive};
use zeroize::Zeroizing;

const MODULUS_BITS: RangeInclusive<usize> = 2048..=8192;
const EXPONENT_BYTES: usize = 5;

pub(super) struct Components<'a> {
    pub(super) n: &'a [u8],
    pub(super) e: &'a [u8],
    pub(super) d: &'a [u8],
    pub(super) p: &'a [u8],
    pub(super) q: &'a [u8],
    pub(super) dp: &'a [u8],
    pub(super) dq: &'a [u8],
    pub(super) qi: &'a [u8],
}

pub(super) struct SigningKey(Box<PrivateKey>);

impl SigningKey {
    pub(super) fn generate(bits: usize) -> Result<Self, Error> {
        PrivateKey::new(&mut SysRng, bits)
            .map(|key| Self(Box::new(key)))
            .map_err(|_| Error::Entropy)
    }

    pub(super) fn from_pkcs8(input: &[u8], maximum: usize) -> Result<Self, Error> {
        let info = PrivateKeyInfoRef::from_der(input).map_err(|_| Error::Authentication)?;
        if info.version() != pkcs8::Version::V1
            || info.algorithm.oid != pkcs1::ALGORITHM_OID
            || info.algorithm.parameters.is_some_and(|p| p != Null.into())
        {
            return Err(Error::Authentication);
        }
        let key = RsaPrivateKeyRef::from_der(info.private_key.as_bytes())
            .map_err(|_| Error::Authentication)?;
        if key.version() != pkcs1::Version::TwoPrime {
            return Err(Error::Authentication);
        }
        Self::from_components(
            Components {
                n: key.modulus.as_bytes(),
                e: key.public_exponent.as_bytes(),
                d: key.private_exponent.as_bytes(),
                p: key.prime1.as_bytes(),
                q: key.prime2.as_bytes(),
                dp: key.exponent1.as_bytes(),
                dq: key.exponent2.as_bytes(),
                qi: key.coefficient.as_bytes(),
            },
            maximum,
        )
    }

    pub(super) fn from_components(parts: Components<'_>, maximum: usize) -> Result<Self, Error> {
        let n = modulus(parts.n, maximum)?;
        let e = exponent(parts.e)?;
        let precision = n.bits_precision();
        let mut d = secret(parts.d, precision)?;
        let mut p = secret(parts.p, precision)?;
        let mut q = secret(parts.q, precision)?;
        let dp = secret(parts.dp, precision)?;
        let dq = secret(parts.dq, precision)?;
        let qi = secret(parts.qi, precision)?;

        // Imported two-prime keys use one width derived from the public modulus.
        // This also supports unbalanced factors with the same import policy.
        let key = PrivateKey::from_components_with_wide_primes(
            n,
            e,
            mem::take(&mut *d),
            vec![mem::take(&mut *p), mem::take(&mut *q)],
        )
        .map_err(|_| Error::Authentication)?;
        let (Some(actual_dp), Some(actual_dq), Some(actual_qi)) = (key.dp(), key.dq(), key.qinv())
        else {
            return Err(Error::Authentication);
        };
        let actual_qi = Zeroizing::new(actual_qi.retrieve());
        let matches = actual_dp.ct_eq(&*dp) & actual_dq.ct_eq(&*dq) & actual_qi.ct_eq(&*qi);
        if !matches.to_bool() {
            return Err(Error::Authentication);
        }
        Ok(Self(Box::new(key)))
    }

    pub(super) fn export_pkcs8(&self) -> Result<SecretDocument, Error> {
        self.0.to_pkcs8_der().map_err(|_| Error::NotReady)
    }

    pub(super) fn signature_bytes(&self) -> usize {
        self.0.size()
    }

    pub(super) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signature = self
            .0
            .pkcs1v15_sign_with_rng::<Sha256, _>(&mut SysRng, message)
            .map_err(|error| match error {
                rsa::Error::Rng => Error::Entropy,
                _ => Error::NotReady,
            })?;
        if signature.len() != self.signature_bytes() {
            return Err(Error::NotReady);
        }
        Ok(signature)
    }

    pub(super) fn public(&self) -> VerificationKey {
        VerificationKey(self.0.to_public_key())
    }
}

pub(super) struct VerificationKey(PublicKey);

impl VerificationKey {
    pub(super) fn from_components(n: &[u8], e: &[u8], maximum: usize) -> Result<Self, Error> {
        PublicKey::new_with_size_limits(modulus(n, maximum)?, exponent(e)?, MODULUS_BITS)
            .map(Self)
            .map_err(|_| Error::Authentication)
    }

    pub(super) fn components(&self) -> (Box<[u8]>, Box<[u8]>) {
        (self.0.n_bytes(), self.0.e_bytes())
    }

    pub(super) fn signature_bytes(&self) -> usize {
        self.0.size()
    }

    pub(super) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.0
            .pkcs1v15_verify::<Sha256>(message, signature)
            .map_err(|_| Error::Authentication)
    }
}

fn modulus(input: &[u8], maximum: usize) -> Result<BoxedUint, Error> {
    if input.len() > maximum {
        return Err(Error::Capacity);
    }
    if !(MODULUS_BITS.start() / 8..=MODULUS_BITS.end() / 8).contains(&input.len()) {
        return Err(Error::Authentication);
    }
    let n = BoxedUint::from_be_slice_vartime(input);
    if !MODULUS_BITS.contains(&(n.bit_width_vartime() as usize)) {
        return Err(Error::Authentication);
    }
    Ok(n)
}

fn exponent(input: &[u8]) -> Result<BoxedUint, Error> {
    if input.is_empty() || input.len() > EXPONENT_BYTES {
        return Err(Error::Authentication);
    }
    Ok(BoxedUint::from_be_slice_vartime(input))
}

fn secret(bytes: &[u8], precision: u32) -> Result<Zeroizing<BoxedUint>, Error> {
    BoxedUint::from_be_slice(bytes, precision)
        .map(Zeroizing::new)
        .map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::der::asn1::OctetStringRef;

    #[test]
    fn pkcs8_import_checks_the_serialized_crt_values() -> Result<(), Error> {
        let signer = SigningKey::generate(2048)?;
        let der = signer.export_pkcs8()?;
        SigningKey::from_pkcs8(der.as_bytes(), 256)?;

        let outer = PrivateKeyInfoRef::from_der(der.as_bytes()).map_err(|_| Error::Malformed)?;
        let mut inner = RsaPrivateKeyRef::from_der(outer.private_key.as_bytes())
            .map_err(|_| Error::Malformed)?;
        let mut exponent = Zeroizing::new(inner.exponent1.as_bytes().to_vec());
        *exponent.last_mut().ok_or(Error::Malformed)? ^= 1;
        inner.exponent1 = pkcs1::UintRef::new(&exponent).map_err(|_| Error::Malformed)?;
        let altered_inner = SecretDocument::encode_msg(&inner).map_err(|_| Error::Malformed)?;
        let altered = PrivateKeyInfoRef::new(
            outer.algorithm,
            OctetStringRef::new(altered_inner.as_bytes()).map_err(|_| Error::Malformed)?,
        );
        let altered_der = SecretDocument::encode_msg(&altered).map_err(|_| Error::Malformed)?;
        if matches!(
            SigningKey::from_pkcs8(altered_der.as_bytes(), 256),
            Err(Error::Authentication)
        ) {
            Ok(())
        } else {
            Err(Error::Conflict)
        }
    }
}
