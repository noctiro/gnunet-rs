//! TLS RSA key bounds and private operations with OS-backed blinding.
use super::signing_failed;
use ::rsa::{
    BoxedUint, PrivateKey, PublicKey,
    pkcs1::{self, RsaPrivateKeyRef, RsaPublicKeyRef},
    pkcs8::{
        EncodePublicKey, PrivateKeyInfoRef,
        der::{Decode, asn1::Null},
    },
    traits::{PrivateKeyParts, PublicKeyParts},
};
use crypto_bigint::CtEq;
use getrandom::SysRng;
use rustls::{
    Error, SignatureScheme,
    pki_types::{InvalidSignature, SubjectPublicKeyInfoDer},
};
use sha2::{Sha256, Sha384, Sha512};
use std::{mem, ops::RangeInclusive};
use zeroize::Zeroizing;

const MODULUS_BITS: RangeInclusive<usize> = 2048..=8192;
const MODULUS_BYTES: RangeInclusive<usize> = 256..=1024;

pub(super) const SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

pub(super) fn load_pkcs8(info: PrivateKeyInfoRef<'_>) -> Option<PrivateKey> {
    if info.algorithm.oid != pkcs1::ALGORITHM_OID
        || info
            .algorithm
            .parameters
            .is_some_and(|parameter| parameter != Null.into())
    {
        return None;
    }
    load_pkcs1(info.private_key.as_bytes())
}

pub(super) fn load_pkcs1(der: &[u8]) -> Option<PrivateKey> {
    let key = RsaPrivateKeyRef::from_der(der).ok()?;
    if key.version() != pkcs1::Version::TwoPrime {
        return None;
    }
    let n = modulus(key.modulus.as_bytes())?;
    let e = exponent(key.public_exponent.as_bytes())?;
    let precision = n.bits_precision();
    let mut d = secret(key.private_exponent.as_bytes(), precision)?;
    let mut p = secret(key.prime1.as_bytes(), precision)?;
    let mut q = secret(key.prime2.as_bytes(), precision)?;
    let dp = secret(key.exponent1.as_bytes(), precision)?;
    let dq = secret(key.exponent2.as_bytes(), precision)?;
    let qi = secret(key.coefficient.as_bytes(), precision)?;

    // Derive the private-operation width from n instead of the lengths of p and q.
    let key = PrivateKey::from_components_with_wide_primes(
        n,
        e,
        mem::take(&mut *d),
        vec![mem::take(&mut *p), mem::take(&mut *q)],
    )
    .ok()?;
    let actual_qi = Zeroizing::new(key.qinv()?.retrieve());
    let matches = key.dp()?.ct_eq(&*dp) & key.dq()?.ct_eq(&*dq) & actual_qi.ct_eq(&*qi);
    matches.to_bool().then_some(key)
}

pub(super) fn public(key: &PrivateKey) -> Result<SubjectPublicKeyInfoDer<'static>, Error> {
    key.to_public_key()
        .to_public_key_der()
        .map(|document| SubjectPublicKeyInfoDer::from(document.into_vec()))
        .map_err(|_| super::invalid_key())
}

pub(super) fn sign(
    key: &PrivateKey,
    scheme: SignatureScheme,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    match scheme {
        SignatureScheme::RSA_PSS_SHA256 => key.pss_sign_with_rng::<Sha256, _>(&mut SysRng, message),
        SignatureScheme::RSA_PSS_SHA384 => key.pss_sign_with_rng::<Sha384, _>(&mut SysRng, message),
        SignatureScheme::RSA_PSS_SHA512 => key.pss_sign_with_rng::<Sha512, _>(&mut SysRng, message),
        SignatureScheme::RSA_PKCS1_SHA256 => {
            key.pkcs1v15_sign_with_rng::<Sha256, _>(&mut SysRng, message)
        }
        SignatureScheme::RSA_PKCS1_SHA384 => {
            key.pkcs1v15_sign_with_rng::<Sha384, _>(&mut SysRng, message)
        }
        SignatureScheme::RSA_PKCS1_SHA512 => {
            key.pkcs1v15_sign_with_rng::<Sha512, _>(&mut SysRng, message)
        }
        _ => return Err(signing_failed()),
    }
    .map_err(|_| signing_failed())
}

pub(super) fn verify(
    scheme: SignatureScheme,
    der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    let parts = RsaPublicKeyRef::from_der(der).map_err(|_| InvalidSignature)?;
    let n = modulus(parts.modulus.as_bytes()).ok_or(InvalidSignature)?;
    let e = exponent(parts.public_exponent.as_bytes()).ok_or(InvalidSignature)?;
    let key = PublicKey::new_with_size_limits(n, e, MODULUS_BITS).map_err(|_| InvalidSignature)?;
    if signature.len() != key.size() {
        return Err(InvalidSignature);
    }
    match scheme {
        SignatureScheme::RSA_PSS_SHA256 => key.pss_verify::<Sha256>(message, signature),
        SignatureScheme::RSA_PSS_SHA384 => key.pss_verify::<Sha384>(message, signature),
        SignatureScheme::RSA_PSS_SHA512 => key.pss_verify::<Sha512>(message, signature),
        SignatureScheme::RSA_PKCS1_SHA256 => key.pkcs1v15_verify::<Sha256>(message, signature),
        SignatureScheme::RSA_PKCS1_SHA384 => key.pkcs1v15_verify::<Sha384>(message, signature),
        SignatureScheme::RSA_PKCS1_SHA512 => key.pkcs1v15_verify::<Sha512>(message, signature),
        _ => return Err(InvalidSignature),
    }
    .map_err(|_| InvalidSignature)
}

fn modulus(bytes: &[u8]) -> Option<BoxedUint> {
    if !MODULUS_BYTES.contains(&bytes.len()) {
        return None;
    }
    let n = BoxedUint::from_be_slice_vartime(bytes);
    MODULUS_BITS
        .contains(&(n.bit_width_vartime() as usize))
        .then_some(n)
}

fn exponent(bytes: &[u8]) -> Option<BoxedUint> {
    (1..=5)
        .contains(&bytes.len())
        .then(|| BoxedUint::from_be_slice_vartime(bytes))
}

fn secret(bytes: &[u8], precision: u32) -> Option<Zeroizing<BoxedUint>> {
    BoxedUint::from_be_slice(bytes, precision)
        .ok()
        .map(Zeroizing::new)
}
