//! Certificate-bound ML-KEM recipient opening (RFCs 9629, 9935 and 9936).

use std::borrow::Cow;

use hkdf::{GenericHkdf, HmacImpl};
use ml_kem::{
    Decapsulate, DecapsulationKey512, DecapsulationKey768, DecapsulationKey1024, KeyExport, Seed,
    kem::Decapsulator,
};
use p256::elliptic_curve::pkcs8::{PrivateKeyInfoRef, der::Decode};
use sha2::{Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;
use x509_parser::x509::SubjectPublicKeyInfo;
use zeroize::{Zeroize, Zeroizing};

use super::{
    Ber, IMPLICIT_OCTETS, Item, OCTETS, RecipientId, SEQUENCE, algorithm, asn1::Der, kem_recipient,
    key_wrap::Algorithm as WrapAlgorithm,
};

const ML_KEM_OID: &[u8] = b"\x60\x86\x48\x01\x65\x03\x04\x04";
const HKDF_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    MlKem512,
    MlKem768,
    MlKem1024,
}

impl Algorithm {
    fn parse(oid: &[u8]) -> Option<Self> {
        match oid.strip_prefix(ML_KEM_OID)? {
            [1] => Some(Self::MlKem512),
            [2] => Some(Self::MlKem768),
            [3] => Some(Self::MlKem1024),
            _ => None,
        }
    }

    const fn ciphertext_bytes(self) -> usize {
        match self {
            Self::MlKem512 => 768,
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    fn allows_wrap(self, wrap: WrapAlgorithm) -> bool {
        let minimum = match self {
            Self::MlKem512 => 16,
            Self::MlKem768 => 24,
            Self::MlKem1024 => 32,
        };
        wrap.is_aes() && wrap.key_bytes() >= minimum
    }
}

pub(super) fn supports(oid: &[u8]) -> bool {
    Algorithm::parse(oid).is_some()
}

pub(super) struct Key(KeyMaterial);

enum KeyMaterial {
    MlKem512(Box<DecapsulationKey512>),
    MlKem768(Box<DecapsulationKey768>),
    MlKem1024(Box<DecapsulationKey1024>),
}

impl Key {
    pub(super) fn parse(certificate: &SubjectPublicKeyInfo<'_>, pkcs8: &[u8]) -> Option<Self> {
        let oid = certificate.algorithm.algorithm.as_bytes();
        if certificate.algorithm.parameters.is_some()
            || certificate.subject_public_key.unused_bits != 0
        {
            return None;
        }
        let algorithm = Algorithm::parse(oid)?;
        let pkcs8 = PrivateKeyInfoRef::from_der(pkcs8).ok()?;
        if pkcs8.algorithm.oid.as_bytes() != oid || pkcs8.algorithm.parameters.is_some() {
            return None;
        }
        let public = certificate.subject_public_key.data.as_ref();
        if let Some(embedded) = pkcs8.public_key
            && embedded.as_bytes()? != public
        {
            return None;
        }
        let private = PrivateEncoding::parse(pkcs8.private_key.as_bytes())?;
        let key = match algorithm {
            Algorithm::MlKem512 => KeyMaterial::MlKem512(Box::new(private.bind(public)?)),
            Algorithm::MlKem768 => KeyMaterial::MlKem768(Box::new(private.bind(public)?)),
            Algorithm::MlKem1024 => KeyMaterial::MlKem1024(Box::new(private.bind(public)?)),
        };
        Some(Self(key))
    }

    fn algorithm(&self) -> Algorithm {
        match self.0 {
            KeyMaterial::MlKem512(_) => Algorithm::MlKem512,
            KeyMaterial::MlKem768(_) => Algorithm::MlKem768,
            KeyMaterial::MlKem1024(_) => Algorithm::MlKem1024,
        }
    }

    fn with_shared<T>(
        &self,
        ciphertext: &[u8],
        use_secret: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Option<T> {
        let mut secret = match &self.0 {
            KeyMaterial::MlKem512(key) => key.decapsulate_slice(ciphertext).ok()?,
            KeyMaterial::MlKem768(key) => key.decapsulate_slice(ciphertext).ok()?,
            KeyMaterial::MlKem1024(key) => key.decapsulate_slice(ciphertext).ok()?,
        };
        let result = use_secret(secret.as_slice());
        secret.as_mut_slice().zeroize();
        result
    }
}

enum PrivateEncoding<'a> {
    Seed(&'a Seed),
    Expanded(&'a [u8]),
    Both { seed: &'a Seed, expanded: &'a [u8] },
}

impl<'a> PrivateEncoding<'a> {
    fn parse(encoded: &'a [u8]) -> Option<Self> {
        match encoded.first().copied()? {
            IMPLICIT_OCTETS => {
                let seed = Der::single(encoded, IMPLICIT_OCTETS)?
                    .data
                    .try_into()
                    .ok()?;
                Some(Self::Seed(seed))
            }
            OCTETS => Some(Self::Expanded(Der::single(encoded, OCTETS)?.data)),
            SEQUENCE => {
                let mut fields = Ber::der_sequence(encoded)?;
                let seed = fields.take(OCTETS)?.data.try_into().ok()?;
                let expanded = fields.take(OCTETS)?.data;
                fields.finish()?;
                Some(Self::Both { seed, expanded })
            }
            _ => None,
        }
    }

    #[expect(
        deprecated,
        reason = "RFC 9935 requires importing expanded ML-KEM decapsulation keys"
    )]
    fn bind<Key>(self, expected: &[u8]) -> Option<Key>
    where
        Key: Decapsulator + From<Seed> + ml_kem::ExpandedKeyEncoding,
    {
        let key = match self {
            Self::Seed(seed) => Key::from(*seed),
            // RustCrypto checks the FIPS 203 public key hash during import.
            Self::Expanded(expanded) => Key::from_expanded_bytes(expanded.try_into().ok()?).ok()?,
            Self::Both { seed, expanded } => {
                let key = Key::from(*seed);
                let mut actual = key.to_expanded_bytes();
                let consistent = bool::from(actual.as_slice().ct_eq(expanded));
                actual.as_mut_slice().zeroize();
                if !consistent {
                    return None;
                }
                key
            }
        };
        (key.encapsulation_key().to_bytes().as_slice() == expected).then_some(key)
    }
}

enum Kdf {
    Sha256,
    Sha384,
    Sha512,
}

impl Kdf {
    fn parse(oid: &[u8]) -> Option<Self> {
        match oid.strip_prefix(HKDF_OID)? {
            [28] => Some(Self::Sha256),
            [29] => Some(Self::Sha384),
            [30] => Some(Self::Sha512),
            _ => None,
        }
    }

    fn derive(self, secret: &[u8], info: &[u8], kek: &mut [u8]) -> Option<()> {
        match self {
            Self::Sha256 => hkdf::<hmac::Hmac<Sha256>>(secret, info, kek),
            Self::Sha384 => hkdf::<hmac::Hmac<Sha384>>(secret, info, kek),
            Self::Sha512 => hkdf::<hmac::Hmac<Sha512>>(secret, info, kek),
        }
    }
}

fn hkdf<H: HmacImpl>(secret: &[u8], info: &[u8], kek: &mut [u8]) -> Option<()> {
    let (mut prk, derivation) = GenericHkdf::<H>::extract(None, secret);
    prk.as_mut_slice().zeroize();
    derivation.expand(info, kek).ok()
}

pub(super) struct Recipient<'a> {
    key: &'a Key,
    ciphertext: Cow<'a, [u8]>,
    kdf: Kdf,
    wrap: kem_recipient::Wrap<'a>,
}

impl Recipient<'_> {
    pub(super) fn open(self) -> Option<Zeroizing<Vec<u8>>> {
        self.key.with_shared(&self.ciphertext, |secret| {
            self.wrap.open(secret, |secret, info, kek| {
                self.kdf.derive(secret, info, kek)
            })
        })
    }
}

pub(super) fn select<'a>(
    key: &'a Key,
    rid: &RecipientId,
    entry: Item<'a>,
) -> Option<Option<Recipient<'a>>> {
    let Some(info) = kem_recipient::select(rid, entry)? else {
        return Some(None);
    };
    let (oid, params) = algorithm(info.algorithm)?;
    let kem = Algorithm::parse(oid)?;
    if kem != key.algorithm() || params.is_some() || !kem.allows_wrap(info.wrap.algorithm()) {
        return None;
    }
    let size = kem.ciphertext_bytes();
    let ciphertext = info.ciphertext.octets(OCTETS, size)?;
    if ciphertext.len() != size {
        return None;
    }
    let (oid, params) = algorithm(info.kdf)?;
    if params.is_some() {
        return None;
    }
    let kdf = Kdf::parse(oid)?;
    Some(Some(Recipient {
        key,
        ciphertext,
        kdf,
        wrap: info.wrap,
    }))
}

#[cfg(test)]
mod tests;
