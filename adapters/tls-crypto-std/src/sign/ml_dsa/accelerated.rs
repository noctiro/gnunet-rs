//! Prepared rscrypto signers on supported architectures.

use super::{KeyEncoding, Profile, bind_public, matches_expanded};
use rscrypto::{
    MlDsa44, MlDsa44PreparedSecretKey, MlDsa44PreparedSecretKeyStorage, MlDsa44PublicKey,
    MlDsa44SecretKey, MlDsa44Signature, MlDsa65, MlDsa65PreparedSecretKey,
    MlDsa65PreparedSecretKeyStorage, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, MlDsa87,
    MlDsa87PreparedSecretKey, MlDsa87PreparedSecretKeyStorage, MlDsa87PublicKey, MlDsa87SecretKey,
    MlDsa87Signature, MlDsaError,
};
use rustls::pki_types::{InvalidSignature, SubjectPublicKeyInfoDer};
use std::alloc::Global;

pub(super) fn verify(
    profile: Profile,
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    macro_rules! verify {
        ($key:ident, $sig:ident) => {{
            let key = $key::try_from_slice(public).map_err(|_| InvalidSignature)?;
            let signature = $sig::try_from_slice(signature).map_err(|_| InvalidSignature)?;
            key.verify(message, &signature)
                .map_err(|_| InvalidSignature)
        }};
    }
    match profile {
        Profile::MlDsa44 => verify!(MlDsa44PublicKey, MlDsa44Signature),
        Profile::MlDsa65 => verify!(MlDsa65PublicKey, MlDsa65Signature),
        Profile::MlDsa87 => verify!(MlDsa87PublicKey, MlDsa87Signature),
    }
}

pub(super) enum Key {
    MlDsa44(MlDsa44PreparedSecretKey<Box<MlDsa44PreparedSecretKeyStorage>>),
    MlDsa65(MlDsa65PreparedSecretKey<Box<MlDsa65PreparedSecretKeyStorage>>),
    MlDsa87(MlDsa87PreparedSecretKey<Box<MlDsa87PreparedSecretKeyStorage>>),
}

impl Key {
    pub(super) fn load(
        profile: Profile,
        encoding: KeyEncoding<'_>,
        expected: Option<&[u8]>,
    ) -> Option<(Self, SubjectPublicKeyInfoDer<'static>)> {
        macro_rules! import {
            ($variant:ident, $secret:ident) => {{
                let key = match encoding {
                    KeyEncoding::Expanded(expanded) => {
                        $secret::try_from_slice_in(expanded, Global).ok()?
                    }
                    KeyEncoding::Seed { seed, expanded } => {
                        if expanded.is_some_and(|bytes| bytes.len() != $secret::LENGTH) {
                            return None;
                        }
                        let key = $variant::keypair_from_seed_in(seed, Global).ok()?.1;
                        if !matches_expanded(key.expose_secret().as_bytes(), expanded) {
                            return None;
                        }
                        key
                    }
                };
                let public = bind_public(profile, key.public_key().as_bytes(), expected)?;
                Some((Self::$variant(key.prepare_in(Global).ok()?), public))
            }};
        }
        match profile {
            Profile::MlDsa44 => import!(MlDsa44, MlDsa44SecretKey),
            Profile::MlDsa65 => import!(MlDsa65, MlDsa65SecretKey),
            Profile::MlDsa87 => import!(MlDsa87, MlDsa87SecretKey),
        }
    }

    pub(super) const fn profile(&self) -> Profile {
        match self {
            Self::MlDsa44(_) => Profile::MlDsa44,
            Self::MlDsa65(_) => Profile::MlDsa65,
            Self::MlDsa87(_) => Profile::MlDsa87,
        }
    }

    pub(super) fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        let random = |output: &mut [u8]| {
            getrandom::fill(output).map_err(|_| MlDsaError::RandomGenerationFailed)
        };
        macro_rules! sign {
            ($key:expr) => {
                $key.sign_with(message, &[], random)
                    .ok()
                    .map(|signature| signature.as_bytes().to_vec())
            };
        }
        match self {
            Self::MlDsa44(key) => sign!(key),
            Self::MlDsa65(key) => sign!(key),
            Self::MlDsa87(key) => sign!(key),
        }
    }
}
