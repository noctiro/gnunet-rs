//! RSA key transport for CMS recipient information.

use getrandom::SysRng;
use rsa::{
    Oaep, PrivateKey,
    pkcs1::{self, RsaPrivateKeyRef},
    pkcs8::{
        AlgorithmIdentifierRef, PrivateKeyInfoRef, SubjectPublicKeyInfoRef,
        der::{
            Decode, Reader, SliceReader, Tag, TagMode, TagNumber, Tagged,
            asn1::{AnyRef, OctetStringRef},
        },
    },
    traits::PublicKeyParts,
};
use sha1::Sha1;
use sha2::{
    Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256,
    digest::{Digest, FixedOutputReset},
};
use std::borrow::Cow;
use x509_parser::x509::SubjectPublicKeyInfo;
use zeroize::Zeroizing;

use super::{Ber, IMPLICIT_OCTETS, INTEGER, Item, OCTETS, RecipientId, SEQUENCE, algorithm};

pub(super) const RSA_ENCRYPTION: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
pub(super) const RSA_OAEP: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x07";
const MGF1: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08";
const P_SPECIFIED: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x09";
const MAX_LABEL_BYTES: usize = 1024;

pub(super) struct Key {
    private: PrivateKey,
    restriction: Restriction<'static>,
}

impl Key {
    pub(super) fn parse(certificate: &SubjectPublicKeyInfo<'_>, pkcs8: &[u8]) -> Option<Self> {
        let (private, restriction) = bind_rsa(certificate, pkcs8, |spki, pkcs8| {
            Some(
                Restriction::parse(spki)?
                    .intersect(Restriction::parse(pkcs8)?)?
                    .into_owned(),
            )
        })?;
        Some(Self {
            private,
            restriction,
        })
    }
}

pub(super) fn bind_rsa<T>(
    certificate: &SubjectPublicKeyInfo<'_>,
    pkcs8: &[u8],
    profiles: impl FnOnce(AlgorithmIdentifierRef<'_>, AlgorithmIdentifierRef<'_>) -> Option<T>,
) -> Option<(PrivateKey, T)> {
    let spki = SubjectPublicKeyInfoRef::from_der(certificate.raw).ok()?;
    let (modulus, exponent) = public_components(spki.subject_public_key.as_bytes()?)?;
    let info = PrivateKeyInfoRef::from_der(pkcs8).ok()?;
    let profile = profiles(spki.algorithm, info.algorithm)?;
    if let Some(public_key) = info.public_key
        && public_components(public_key.as_bytes()?)? != (modulus, exponent)
    {
        return None;
    }
    let encoded = RsaPrivateKeyRef::from_der(info.private_key.as_bytes()).ok()?;
    if encoded.version() != pkcs1::Version::TwoPrime
        || encoded.modulus.as_bytes() != modulus
        || encoded.public_exponent.as_bytes() != exponent
        || !(128..=1024).contains(&modulus.len())
        || exponent.len() > 5
        || [
            encoded.private_exponent,
            encoded.prime1,
            encoded.prime2,
            encoded.exponent1,
            encoded.exponent2,
            encoded.coefficient,
        ]
        .iter()
        .any(|number| number.as_bytes().len() > modulus.len())
    {
        return None;
    }
    let private = PrivateKey::try_from(encoded).ok()?;
    (1024..=8192)
        .contains(&private.n().bit_width_vartime())
        .then_some((private, profile))
}

fn public_components(public_key: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut public_key = Ber::der_sequence(public_key)?;
    let modulus = public_key.take(INTEGER)?.positive_integer()?;
    let exponent = public_key.take(INTEGER)?.positive_integer()?;
    public_key.finish()?;
    Some((modulus, exponent))
}

enum Restriction<'a> {
    Unrestricted,
    Oaep,
    Fixed(OaepParams<'a>),
}

impl<'a> Restriction<'a> {
    fn parse(algorithm: AlgorithmIdentifierRef<'a>) -> Option<Self> {
        match algorithm.oid.as_bytes() {
            RSA_ENCRYPTION if algorithm.parameters == Some(AnyRef::NULL) => {
                Some(Self::Unrestricted)
            }
            // RFC 4055 §4.1 permits absent parameters for an OAEP-only key.
            RSA_OAEP => Some(match algorithm.parameters {
                None => Self::Oaep,
                Some(parameters) => Self::Fixed(OaepParams::parse_der(parameters)?),
            }),
            _ => None,
        }
    }

    fn intersect(self, other: Self) -> Option<Self> {
        match (self, other) {
            (Self::Fixed(left), Self::Fixed(right)) if left != right => None,
            (fixed @ Self::Fixed(_), _) | (_, fixed @ Self::Fixed(_)) => Some(fixed),
            (Self::Oaep, _) | (_, Self::Oaep) => Some(Self::Oaep),
            _ => Some(Self::Unrestricted),
        }
    }

    fn into_owned(self) -> Restriction<'static> {
        match self {
            Self::Unrestricted => Restriction::Unrestricted,
            Self::Oaep => Restriction::Oaep,
            Self::Fixed(params) => Restriction::Fixed(OaepParams {
                hash: params.hash,
                mask: params.mask,
                label: Cow::Owned(params.label.into_owned()),
            }),
        }
    }

    fn permits(&self, scheme: &Scheme<'_>) -> bool {
        match (self, scheme) {
            (Self::Unrestricted, _) | (Self::Oaep, Scheme::Oaep(_)) => true,
            (Self::Fixed(expected), Scheme::Oaep(actual)) => expected == actual,
            _ => false,
        }
    }
}

enum Scheme<'a> {
    Pkcs1,
    Oaep(OaepParams<'a>),
}

impl<'a> Scheme<'a> {
    fn parse(item: Item<'a>) -> Option<Self> {
        let (oid, params) = algorithm(item)?;
        match oid {
            RSA_ENCRYPTION if absent_or_null(params) => Some(Self::Pkcs1),
            RSA_OAEP => Some(Self::Oaep(OaepParams::parse(params?)?)),
            _ => None,
        }
    }
}

pub(super) struct Recipient<'a> {
    scheme: Scheme<'a>,
    ciphertext: Cow<'a, [u8]>,
}

pub(super) fn select<'a>(
    key: &Key,
    rid: &RecipientId,
    entry: Item<'a>,
) -> Option<Option<Recipient<'a>>> {
    let mut fields = Ber(entry.data);
    let version = fields.take(INTEGER)?.uint()?;
    let identity = fields.read()?;
    let matches = match version {
        0 => rid.issuer_and_serial(identity)?,
        2 => rid.key_identifier(identity, IMPLICIT_OCTETS)?,
        _ => return None,
    };
    let algorithm = fields.take(SEQUENCE)?;
    let encrypted = fields.read()?;
    fields.finish()?;
    if !matches {
        return Some(None);
    }
    let scheme = Scheme::parse(algorithm)?;
    let ciphertext = encrypted.octets(OCTETS, key.private.size())?;
    if ciphertext.len() != key.private.size() {
        return None;
    }
    Some(Some(Recipient { scheme, ciphertext }))
}

impl Recipient<'_> {
    pub(super) fn open(self, key: &Key) -> Option<Zeroizing<Vec<u8>>> {
        if !key.restriction.permits(&self.scheme) {
            return None;
        }
        let plaintext = match self.scheme {
            Scheme::Pkcs1 => key
                .private
                .pkcs1v15_decrypt_with_rng(&mut SysRng, &self.ciphertext)
                .ok()?,
            Scheme::Oaep(params) => params.decrypt(&key.private, &self.ciphertext).ok()?,
        };
        Some(Zeroizing::new(plaintext))
    }
}

fn absent_or_null(params: Option<Item<'_>>) -> bool {
    params.is_none_or(|item| item.tag == 0x05 && item.data.is_empty())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
}

impl Hash {
    fn parse(algorithm_id: Item<'_>) -> Option<Self> {
        let (oid, params) = algorithm(algorithm_id)?;
        if !absent_or_null(params) {
            return None;
        }
        Self::from_oid(oid)
    }

    fn parse_der(algorithm: AlgorithmIdentifierRef<'_>) -> Option<Self> {
        if algorithm
            .parameters
            .is_some_and(|params| params != AnyRef::NULL)
        {
            return None;
        }
        Self::from_oid(algorithm.oid.as_bytes())
    }

    fn from_oid(oid: &[u8]) -> Option<Self> {
        match oid {
            b"\x2b\x0e\x03\x02\x1a" => Some(Self::Sha1),
            b"\x60\x86\x48\x01\x65\x03\x04\x02\x04" => Some(Self::Sha224),
            b"\x60\x86\x48\x01\x65\x03\x04\x02\x01" => Some(Self::Sha256),
            b"\x60\x86\x48\x01\x65\x03\x04\x02\x02" => Some(Self::Sha384),
            b"\x60\x86\x48\x01\x65\x03\x04\x02\x03" => Some(Self::Sha512),
            b"\x60\x86\x48\x01\x65\x03\x04\x02\x05" => Some(Self::Sha512_224),
            b"\x60\x86\x48\x01\x65\x03\x04\x02\x06" => Some(Self::Sha512_256),
            _ => None,
        }
    }
}

#[derive(Eq, PartialEq)]
struct OaepParams<'a> {
    hash: Hash,
    mask: Hash,
    label: Cow<'a, [u8]>,
}

impl Default for OaepParams<'_> {
    fn default() -> Self {
        Self {
            hash: Hash::Sha1,
            mask: Hash::Sha1,
            label: Cow::Borrowed(&[]),
        }
    }
}

impl<'a> OaepParams<'a> {
    fn parse_der(input: AnyRef<'a>) -> Option<Self> {
        if input.tag() != Tag::Sequence {
            return None;
        }
        let mut reader = SliceReader::new(input.value()).ok()?;
        let mut field = |number| {
            reader
                .context_specific::<AlgorithmIdentifierRef<'a>>(
                    TagNumber(number),
                    TagMode::Explicit,
                )
                .ok()
        };
        let mut params = Self::default();
        if let Some(hash) = field(0)? {
            params.hash = Hash::parse_der(hash)?;
        }
        if let Some(mask) = field(1)? {
            if mask.oid.as_bytes() != MGF1 {
                return None;
            }
            params.mask = Hash::parse_der(mask.parameters?.decode_as().ok()?)?;
        }
        if let Some(source) = field(2)? {
            if source.oid.as_bytes() != P_SPECIFIED {
                return None;
            }
            let label: &'a OctetStringRef = source.parameters?.decode_as().ok()?;
            let label = label.as_bytes();
            (label.len() <= MAX_LABEL_BYTES).then_some(())?;
            params.label = Cow::Borrowed(label);
        }
        reader.finish().ok()?;
        Some(params)
    }

    fn parse(item: Item<'a>) -> Option<Self> {
        if item.tag != SEQUENCE {
            return None;
        }
        let mut fields = Ber(item.data);
        let mut params = Self::default();
        if let Some(item) = fields.optional(0xa0)? {
            params.hash = Hash::parse(explicit_parameter(item)?)?;
        }
        if let Some(item) = fields.optional(0xa1)? {
            let (oid, hash) = algorithm(explicit_parameter(item)?)?;
            if oid != MGF1 {
                return None;
            }
            params.mask = Hash::parse(hash?)?;
        }
        if let Some(item) = fields.optional(0xa2)? {
            let (oid, label) = algorithm(explicit_parameter(item)?)?;
            if oid != P_SPECIFIED {
                return None;
            }
            params.label = label?.octets(OCTETS, MAX_LABEL_BYTES)?;
        }
        fields.finish()?;
        Some(params)
    }

    fn decrypt(&self, key: &PrivateKey, body: &[u8]) -> rsa::Result<Vec<u8>> {
        match self.hash {
            Hash::Sha1 => self.with_hash::<Sha1>(key, body),
            Hash::Sha224 => self.with_hash::<Sha224>(key, body),
            Hash::Sha256 => self.with_hash::<Sha256>(key, body),
            Hash::Sha384 => self.with_hash::<Sha384>(key, body),
            Hash::Sha512 => self.with_hash::<Sha512>(key, body),
            Hash::Sha512_224 => self.with_hash::<Sha512_224>(key, body),
            Hash::Sha512_256 => self.with_hash::<Sha512_256>(key, body),
        }
    }

    fn with_hash<D: Digest + FixedOutputReset>(
        &self,
        key: &PrivateKey,
        body: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        match self.mask {
            Hash::Sha1 => self.with_digests::<D, Sha1>(key, body),
            Hash::Sha224 => self.with_digests::<D, Sha224>(key, body),
            Hash::Sha256 => self.with_digests::<D, Sha256>(key, body),
            Hash::Sha384 => self.with_digests::<D, Sha384>(key, body),
            Hash::Sha512 => self.with_digests::<D, Sha512>(key, body),
            Hash::Sha512_224 => self.with_digests::<D, Sha512_224>(key, body),
            Hash::Sha512_256 => self.with_digests::<D, Sha512_256>(key, body),
        }
    }

    fn with_digests<D: Digest + FixedOutputReset, M: Digest + FixedOutputReset>(
        &self,
        key: &PrivateKey,
        body: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        key.decrypt_blinded(
            &mut SysRng,
            Oaep::<D, M>::new_with_mgf_hash_and_label(self.label.as_ref()),
            body,
        )
    }
}

fn explicit_parameter(field: Item<'_>) -> Option<Item<'_>> {
    let mut input = Ber(field.data);
    let identifier = input.take(SEQUENCE)?;
    input.finish()?;
    Some(identifier)
}

#[cfg(test)]
mod tests {
    use super::super::{PdfCertificateRecipient, PdfRecipientContent};
    use super::*;
    use rsa::pkcs8::der::Encode;
    use x509_parser::prelude::parse_x509_certificate;

    const CERT: &[u8] = include_bytes!("tests/fixtures/rsa-certificate.der");
    const RESTRICTED_CERT: &[u8] = include_bytes!("tests/fixtures/rsa-oaep-restricted-cert.der");
    const KEY: &[u8] = include_bytes!("tests/fixtures/rsa-test-key.der");
    const PKCS1: &[u8] = include_bytes!("tests/fixtures/issuer-aes128.der");
    const OAEP: &[u8] = include_bytes!("tests/fixtures/key-id-oaep-aes256.der");
    const ABSENT: &[u8] = b"\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x07";
    const DEFAULT: &[u8] = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x07\x30\x00";
    const EXPLICIT_SHA1: &[u8] = b"\x30\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x07\x30\x0d\xa0\x0b\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00";

    #[test]
    fn restricted_rsa_oaep_recipient_refuses_other_schemes_and_conflicting_keys() {
        let fixtures = (
            PdfCertificateRecipient::from_der(RESTRICTED_CERT, KEY),
            encode_test_key(false),
            encode_test_key(true),
        );
        let (Ok(certificate), Some(restricted_key), Some(conflicting_key)) = fixtures else {
            assert!(fixtures.0.is_ok() && fixtures.1.is_some() && fixtures.2.is_some());
            return;
        };
        let certificate = certificate.into_authorization();
        assert!(matches!(
            certificate.open(OAEP),
            Some(PdfRecipientContent::Document { .. })
        ));
        assert!(certificate.open(PKCS1).is_none());

        let restriction_from_key = PdfCertificateRecipient::from_der(CERT, &restricted_key);
        let Ok(restriction_from_key) = restriction_from_key else {
            assert!(restriction_from_key.is_ok());
            return;
        };
        let restriction_from_key = restriction_from_key.into_authorization();
        assert!(restriction_from_key.open(OAEP).is_some());
        assert!(restriction_from_key.open(PKCS1).is_none());

        let oaep_default = PdfCertificateRecipient::from_der(CERT, &conflicting_key);
        let Ok(oaep_default) = oaep_default else {
            assert!(oaep_default.is_ok());
            return;
        };
        assert!(oaep_default.into_authorization().open(OAEP).is_none());
        assert!(PdfCertificateRecipient::from_der(RESTRICTED_CERT, &conflicting_key).is_err());
    }

    fn encode_test_key(use_default: bool) -> Option<Zeroizing<Vec<u8>>> {
        let (_, certificate) = parse_x509_certificate(RESTRICTED_CERT).ok()?;
        let spki = SubjectPublicKeyInfoRef::from_der(certificate.public_key().raw).ok()?;
        let mut key = PrivateKeyInfoRef::from_der(KEY).ok()?;
        key.algorithm = spki.algorithm;
        if use_default {
            key.algorithm.parameters = Some(AnyRef::new(Tag::Sequence, &[]).ok()?);
        }
        key.to_der().ok().map(Zeroizing::new)
    }

    #[test]
    fn absent_key_parameters_and_effective_defaults_are_distinct() {
        let restricted = AlgorithmIdentifierRef::from_der(ABSENT)
            .ok()
            .and_then(Restriction::parse);
        assert!(matches!(restricted, Some(Restriction::Oaep)));
        assert!(Ber(ABSENT).take(SEQUENCE).and_then(Scheme::parse).is_none());
        let same_policy = AlgorithmIdentifierRef::from_der(DEFAULT)
            .ok()
            .and_then(Restriction::parse)
            .zip(
                AlgorithmIdentifierRef::from_der(EXPLICIT_SHA1)
                    .ok()
                    .and_then(Restriction::parse),
            )
            .and_then(|(left, right)| left.intersect(right));
        assert!(matches!(same_policy, Some(Restriction::Fixed(_))));
    }
}
