//! ML-DSA signing, verification, and RFC 9881 private-key loading for rustls.
use ::rsa::pkcs8::{
    ObjectIdentifier, PrivateKeyInfoRef,
    der::{Decode, Reader, Tag, TagNumber, Tagged, asn1::AnyRef, asn1::OctetStringRef},
};
use crypto_bigint::CtEq;
use rustls::{
    SignatureScheme,
    pki_types::{AlgorithmIdentifier, InvalidSignature, SubjectPublicKeyInfoDer, alg_id},
    sign::public_key_to_spki,
};

#[cfg(not(target_arch = "x86"))]
mod accelerated;
#[cfg(any(target_arch = "x86", test))]
mod portable;
#[cfg(not(target_arch = "x86"))]
use accelerated as backend;
#[cfg(target_arch = "x86")]
use portable as backend;

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
        backend::verify(self, public, message, signature)
    }
}

pub(super) struct SigningKey(backend::Key);

impl SigningKey {
    pub(super) fn scheme(&self) -> SignatureScheme {
        self.0.profile().scheme()
    }

    pub(super) fn sign(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.0.sign(message)
    }

    pub(super) fn from_pkcs8(
        info: PrivateKeyInfoRef<'_>,
    ) -> Option<(Self, SubjectPublicKeyInfoDer<'static>)> {
        if info.algorithm.parameters.is_some() {
            return None;
        }
        let profile = Profile::from_oid(info.algorithm.oid)?;
        let encoding = KeyEncoding::from_der(info.private_key.as_bytes())?;
        let expected = match info.public_key {
            Some(key) => Some(key.as_bytes()?),
            None => None,
        };
        let (key, public) = backend::Key::load(profile, encoding, expected)?;
        Some((Self(key), public))
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

fn matches_expanded(derived: &[u8], expected: Option<&[u8]>) -> bool {
    expected.is_none_or(|bytes| derived.len() == bytes.len() && derived.ct_eq(bytes).to_bool())
}

fn bind_public(
    profile: Profile,
    actual: &[u8],
    expected: Option<&[u8]>,
) -> Option<SubjectPublicKeyInfoDer<'static>> {
    expected
        .is_none_or(|bytes| bytes == actual)
        .then(|| public_key_to_spki(&profile.algorithm(), actual))
}

#[cfg(test)]
type TestMaterial = (zeroize::Zeroizing<Vec<u8>>, Vec<u8>);

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

    const PROFILES: [(Profile, ObjectIdentifier, usize); 3] = [
        (Profile::MlDsa44, Profile::OID_44, 4 * 96),
        (Profile::MlDsa65, Profile::OID_65, 5 * 128),
        (Profile::MlDsa87, Profile::OID_87, 7 * 96),
    ];

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

        for invalid in malformed_expansions(expanded, s1_length) {
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

    fn malformed_expansions(
        expanded: &[u8],
        s1_length: usize,
    ) -> impl Iterator<Item = Zeroizing<Vec<u8>>> {
        [
            (64, 1),
            (128, 0xff),
            (128 + s1_length, 0xff),
            (expanded.len() - 1, 1),
        ]
        .into_iter()
        .map(move |(offset, mask)| {
            let mut invalid = Zeroizing::new(expanded.to_vec());
            if mask == 0xff {
                invalid[offset] = mask;
            } else {
                invalid[offset] ^= mask;
            }
            invalid
        })
    }

    #[test]
    fn private_key_encodings_and_signatures_preserve_all_profiles()
    -> Result<(), Box<dyn std::error::Error>> {
        let seed = Zeroizing::new([0x42; 32]);
        for (profile, oid, s1_length) in PROFILES {
            let (expanded, public) = portable::test_material(profile, &seed);
            check_encodings(profile, oid, &seed, &expanded, &public, s1_length)?;
        }
        Ok(())
    }

    #[cfg(not(target_arch = "x86"))]
    #[test]
    fn accelerated_and_portable_backends_accept_the_same_keys_and_signatures()
    -> Result<(), Box<dyn std::error::Error>> {
        let seed = Zeroizing::new([0x35; 32]);
        let message = b"ML-DSA between providers";
        for (profile, _, s1_length) in PROFILES {
            let (expanded, public) = portable::test_material(profile, &seed);
            let both = KeyEncoding::Seed {
                seed: &seed,
                expanded: Some(&expanded),
            };
            let (accelerated, accelerated_public) =
                backend::Key::load(profile, both, Some(&public)).ok_or_else(|| {
                    io::Error::other("accelerated key does not match portable key")
                })?;
            let (portable, portable_public) =
                portable::Key::load(profile, KeyEncoding::Expanded(&expanded), Some(&public))
                    .ok_or_else(|| io::Error::other("portable expanded key rejected"))?;
            if accelerated_public != portable_public
                || portable.profile().scheme() != profile.scheme()
            {
                return Err(io::Error::other("the backend changed the public identity").into());
            }
            let from_portable = portable
                .sign(message)
                .ok_or_else(|| io::Error::other("portable signing failed"))?;
            let from_accelerated = accelerated
                .sign(message)
                .ok_or_else(|| io::Error::other("accelerated signing failed"))?;
            if profile.verify(&public, message, &from_portable).is_err()
                || portable::verify(profile, &public, message, &from_accelerated).is_err()
                || portable::verify(profile, &public, b"wrong message", &from_accelerated).is_ok()
            {
                return Err(io::Error::other("signatures did not interoperate").into());
            }
            for invalid in malformed_expansions(&expanded, s1_length) {
                if portable::Key::load(profile, KeyEncoding::Expanded(&invalid), None).is_some() {
                    return Err(io::Error::other("portable backend accepted malformed key").into());
                }
            }
        }
        Ok(())
    }
}
