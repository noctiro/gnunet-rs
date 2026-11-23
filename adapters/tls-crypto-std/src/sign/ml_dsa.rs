//! ML-DSA signing, verification, and RFC 9881 private-key loading for rustls.
use ::rsa::pkcs8::{
    ObjectIdentifier, PrivateKeyInfoRef,
    der::{Decode, Reader, Tag, TagNumber, Tagged, asn1::AnyRef, asn1::OctetStringRef},
};
use crypto_bigint::CtEq;
use rscrypto::{
    MlDsa44, MlDsa44PreparedSecretKey, MlDsa44PreparedSecretKeyStorage, MlDsa44PublicKey,
    MlDsa44SecretKey, MlDsa44Signature, MlDsa65, MlDsa65PreparedSecretKey,
    MlDsa65PreparedSecretKeyStorage, MlDsa65PublicKey, MlDsa65SecretKey, MlDsa65Signature, MlDsa87,
    MlDsa87PreparedSecretKey, MlDsa87PreparedSecretKeyStorage, MlDsa87PublicKey, MlDsa87SecretKey,
    MlDsa87Signature, MlDsaError,
};
use rustls::{
    SignatureScheme,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SubjectPublicKeyInfoDer, alg_id},
    sign::public_key_to_spki,
};
use std::alloc::Global;

#[derive(Clone, Copy, Debug)]
pub(super) enum Profile {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl Profile {
    const OID_44: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");
    const OID_65: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");
    const OID_87: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

    fn from_oid(oid: ObjectIdentifier) -> Option<Self> {
        match oid {
            Self::OID_44 => Some(Self::MlDsa44),
            Self::OID_65 => Some(Self::MlDsa65),
            Self::OID_87 => Some(Self::MlDsa87),
            _ => None,
        }
    }

    pub(super) const fn algorithm(self) -> AlgorithmIdentifier {
        match self {
            Self::MlDsa44 => alg_id::ML_DSA_44,
            Self::MlDsa65 => alg_id::ML_DSA_65,
            Self::MlDsa87 => alg_id::ML_DSA_87,
        }
    }

    pub(super) const fn scheme(self) -> SignatureScheme {
        match self {
            Self::MlDsa44 => SignatureScheme::ML_DSA_44,
            Self::MlDsa65 => SignatureScheme::ML_DSA_65,
            Self::MlDsa87 => SignatureScheme::ML_DSA_87,
        }
    }

    pub(super) fn verify(
        self,
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
        match self {
            Self::MlDsa44 => verify!(MlDsa44PublicKey, MlDsa44Signature),
            Self::MlDsa65 => verify!(MlDsa65PublicKey, MlDsa65Signature),
            Self::MlDsa87 => verify!(MlDsa87PublicKey, MlDsa87Signature),
        }
    }
}

pub(super) enum SigningKey {
    MlDsa44(MlDsa44PreparedSecretKey<Box<MlDsa44PreparedSecretKeyStorage>>),
    MlDsa65(MlDsa65PreparedSecretKey<Box<MlDsa65PreparedSecretKeyStorage>>),
    MlDsa87(MlDsa87PreparedSecretKey<Box<MlDsa87PreparedSecretKeyStorage>>),
}

impl SigningKey {
    pub(super) fn scheme(&self) -> SignatureScheme {
        let profile = match self {
            Self::MlDsa44(_) => Profile::MlDsa44,
            Self::MlDsa65(_) => Profile::MlDsa65,
            Self::MlDsa87(_) => Profile::MlDsa87,
        };
        profile.scheme()
    }

    pub(super) fn sign(&self, message: &[u8]) -> Result<Vec<u8>, MlDsaError> {
        let random = |output: &mut [u8]| {
            getrandom::fill(output).map_err(|_| MlDsaError::RandomGenerationFailed)
        };
        macro_rules! sign {
            ($key:expr) => {
                $key.sign_with(message, &[], random)
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

enum KeyEncoding<'a> {
    Seed {
        seed: &'a [u8; 32],
        expanded: Option<&'a [u8]>,
    },
    Expanded(&'a [u8]),
}

impl<'a> KeyEncoding<'a> {
    fn from_der(der: &'a [u8]) -> Option<Self> {
        let private = AnyRef::from_der(der).ok()?;
        match private.tag() {
            Tag::ContextSpecific {
                constructed: false,
                number: TagNumber(0),
            } => Some(Self::Seed {
                seed: private.value().try_into().ok()?,
                expanded: None,
            }),
            Tag::OctetString => Some(Self::Expanded(private.value())),
            Tag::Sequence => {
                let (seed, expanded) = private
                    .sequence(|reader| {
                        let seed: &OctetStringRef = reader.decode()?;
                        let expanded: &OctetStringRef = reader.decode()?;
                        Ok::<_, ::rsa::pkcs8::der::Error>((seed.as_bytes(), expanded.as_bytes()))
                    })
                    .ok()?;
                Some(Self::Seed {
                    seed: seed.try_into().ok()?,
                    expanded: Some(expanded),
                })
            }
            _ => None,
        }
    }
}

impl SigningKey {
    pub(super) fn from_pkcs8(
        info: PrivateKeyInfoRef<'_>,
    ) -> Option<(Self, SubjectPublicKeyInfoDer<'static>)> {
        // The shared RFC 5958 parser accepts attributes that rscrypto's
        // container parser rejects. Import only the parsed key material.
        if info.algorithm.parameters.is_some() {
            return None;
        }
        let profile = Profile::from_oid(info.algorithm.oid)?;
        let encoding = KeyEncoding::from_der(info.private_key.as_bytes())?;
        macro_rules! import {
            ($variant:ident, $secret:ident) => {{
                let key = match encoding {
                    KeyEncoding::Expanded(expanded) => {
                        $secret::try_from_slice_in(expanded, Global).ok()?
                    }
                    KeyEncoding::Seed { seed, expanded } => {
                        if expanded.is_some_and(|expanded| expanded.len() != $secret::LENGTH) {
                            return None;
                        }
                        let key = $variant::keypair_from_seed_in(seed, Global).ok()?.1;
                        if let Some(expanded) = expanded
                            && !key
                                .expose_secret()
                                .as_bytes()
                                .as_slice()
                                .ct_eq(expanded)
                                .to_bool()
                        {
                            return None;
                        }
                        key
                    }
                };
                let public = key.public_key().as_bytes();
                if let Some(encoded_public) = info.public_key
                    && encoded_public.as_bytes()? != public
                {
                    return None;
                }
                let prepared = key.prepare_in(Global).ok()?;
                let public = public_key_to_spki(&profile.algorithm(), public);
                Some((Self::$variant(prepared), public))
            }};
        }
        match profile {
            Profile::MlDsa44 => import!(MlDsa44, MlDsa44SecretKey),
            Profile::MlDsa65 => import!(MlDsa65, MlDsa65SecretKey),
            Profile::MlDsa87 => import!(MlDsa87, MlDsa87SecretKey),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::KEY_PROVIDER;
    use super::*;
    use ::rsa::pkcs8::{
        der::{Encode, SecretDocument, asn1::BitStringRef},
        spki::AlgorithmIdentifierRef,
    };
    use rustls::{pki_types::PrivatePkcs8KeyDer, sign::SigningKey as RustlsSigningKey};
    use std::io;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    fn load(der: &[u8]) -> Result<Arc<dyn RustlsSigningKey>, rustls::Error> {
        KEY_PROVIDER.load_private_key(PrivatePkcs8KeyDer::from(der.to_vec()).into())
    }

    fn container(
        oid: ObjectIdentifier,
        private: &impl Encode,
        public: Option<&[u8]>,
    ) -> Result<SecretDocument, ::rsa::pkcs8::der::Error> {
        let private = Zeroizing::new(private.to_der()?);
        let mut info = PrivateKeyInfoRef::new(
            AlgorithmIdentifierRef {
                oid,
                parameters: None,
            },
            OctetStringRef::new(&private)?,
        );
        info.public_key = public
            .map(|public| BitStringRef::new(0, public))
            .transpose()?;
        SecretDocument::encode_msg(&info)
    }

    fn check_encodings(
        profile: Profile,
        oid: ObjectIdentifier,
        seed: &[u8; 32],
        expanded: &[u8],
        public: &[u8],
        s1_length: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let seed_tag = Tag::ContextSpecific {
            constructed: false,
            number: TagNumber(0),
        };
        let seed_der = AnyRef::new(seed_tag, seed)?;
        let expanded_der = OctetStringRef::new(expanded)?;
        let mut both = Zeroizing::new(OctetStringRef::new(seed)?.to_der()?);
        let expanded_octets = Zeroizing::new(expanded_der.to_der()?);
        both.extend_from_slice(&expanded_octets);
        let mut documents = [
            container(oid, &seed_der, None)?,
            container(oid, &expanded_der, Some(public))?,
            container(oid, &AnyRef::new(Tag::Sequence, &both)?, None)?,
        ];
        let expected = public_key_to_spki(&profile.algorithm(), public);
        let message = b"TLS ML-DSA signing";
        for document in &documents {
            let key = load(document.as_bytes())?;
            if key.public_key().as_ref() != Some(&expected) {
                return Err(io::Error::other("import changed the public key").into());
            }
            let signer = key
                .choose_scheme(&[profile.scheme()])
                .ok_or_else(|| io::Error::other("ML-DSA scheme rejected"))?;
            drop(key);
            let signature = signer.sign(message)?;
            if profile.verify(public, message, &signature).is_err()
                || profile.verify(public, b"wrong message", &signature).is_ok()
            {
                return Err(
                    io::Error::other("signature verification did not match the message").into(),
                );
            }
        }

        let mut other_public = public.to_vec();
        other_public[0] ^= 1;
        documents[1] = container(oid, &expanded_der, Some(&other_public))?;
        documents[2] = {
            let mut inconsistent = both;
            *inconsistent
                .last_mut()
                .ok_or_else(|| io::Error::other("empty key encoding"))? ^= 1;
            container(oid, &AnyRef::new(Tag::Sequence, &inconsistent)?, None)?
        };
        for document in &documents[1..] {
            if load(document.as_bytes()).is_ok() {
                return Err(io::Error::other("accepted inconsistent private key fields").into());
            }
        }

        for (offset, mask) in [
            (64, 1),
            (128, 0xff),
            (128 + s1_length, 0xff),
            (expanded.len() - 1, 1),
        ] {
            let mut invalid = Zeroizing::new(expanded.to_vec());
            if mask == 0xff {
                invalid[offset] = mask;
            } else {
                invalid[offset] ^= mask;
            }
            let document = container(oid, &OctetStringRef::new(&invalid)?, None)?;
            if load(document.as_bytes()).is_ok() {
                return Err(io::Error::other("accepted invalid expanded private key").into());
            }
        }
        let short = OctetStringRef::new(&expanded[..expanded.len() - 1])?;
        if load(container(oid, &short, None)?.as_bytes()).is_ok() {
            return Err(io::Error::other("accepted truncated expanded private key").into());
        }
        Ok(())
    }

    #[test]
    fn private_key_encodings_and_signatures_preserve_all_profiles()
    -> Result<(), Box<dyn std::error::Error>> {
        let seed = Zeroizing::new([0x42; 32]);
        macro_rules! check {
            ($profile:ident, $oid:ident, $s1_length:expr) => {{
                let (public, key) = $profile::keypair_from_seed_in(&seed, Global)?;
                let expanded = key.expose_secret();
                check_encodings(
                    Profile::$profile,
                    Profile::$oid,
                    &seed,
                    expanded.as_bytes(),
                    public.as_bytes(),
                    $s1_length,
                )?;
            }};
        }
        check!(MlDsa44, OID_44, 4 * 96);
        check!(MlDsa65, OID_65, 5 * 128);
        check!(MlDsa87, OID_87, 7 * 96);
        Ok(())
    }
}
