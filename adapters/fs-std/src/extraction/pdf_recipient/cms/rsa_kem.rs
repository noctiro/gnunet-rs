//! Certificate-bound RSA-KEM recipients for CMS (RFC 9690 and RFC 5990).

use std::borrow::Cow;

use getrandom::SysRng;
use rsa::{
    BoxedUint, PrivateKey,
    hazmat::rsa_decrypt_and_check,
    pkcs8::{
        AlgorithmIdentifierRef,
        der::{Decode, Encode, Reader, SliceReader, Tag, Tagged, asn1::AnyRef},
    },
    traits::PublicKeyParts,
};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use x509_parser::x509::SubjectPublicKeyInfo;
use zeroize::{Zeroize, Zeroizing};

use super::{
    Ber, IMPLICIT_OCTETS, INTEGER, Item, OCTETS, RecipientId, SEQUENCE, algorithm,
    asn1::Der,
    kem_recipient,
    key_wrap::{self, Algorithm as WrapAlgorithm, WrappedKey},
    transport,
};

const RSA_KEM_SPKI: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x0e";
const KEM_RSA: &[u8] = b"\x28\x81\x8c\x71\x02\x02\x04";
const KDF2: &[u8] = b"\x2b\x81\x05\x10\x86\x48\x09\x2c\x01\x01";
const KDF3: &[u8] = b"\x2b\x81\x05\x10\x86\x48\x09\x2c\x01\x02";
const SHA1: &[u8] = b"\x2b\x0e\x03\x02\x1a";
const SHA2: &[u8] = b"\x60\x86\x48\x01\x65\x03\x04\x02";

pub(super) fn supports(oid: &[u8]) -> bool {
    oid == RSA_KEM_SPKI
}

pub(super) struct Key {
    private: PrivateKey,
    restriction: Option<Profile>,
}

impl Key {
    pub(super) fn parse(certificate: &SubjectPublicKeyInfo<'_>, pkcs8: &[u8]) -> Option<Self> {
        let (private, restriction) = transport::bind_rsa(certificate, pkcs8, |public, private| {
            let public = profile(public)?;
            let private = profile(private)?;
            match (public, private) {
                (Some(public), Some(private)) if public != private => None,
                (Some(profile), _) | (_, Some(profile)) => Some(Some(profile)),
                (None, None) => Some(None),
            }
        })?;
        Some(Self {
            private,
            restriction,
        })
    }

    pub(super) fn identity(&self, certificate: &[u8]) -> [u8; 32] {
        let domain = b"GNUnet FS CMS RSA-KEM credential\0";
        let Some(restriction) = self.restriction else {
            return gnunet_crypto::hash256_parts(&[domain, certificate]);
        };
        let (kdf, hash) = restriction.kdf.algorithms();
        gnunet_crypto::hash256_parts(&[
            domain,
            certificate,
            kdf,
            hash,
            &[restriction.key_bytes],
            restriction.wrap_der,
        ])
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Profile {
    kdf: Kdf,
    key_bytes: u8,
    wrap_der: &'static [u8],
}

fn profile(algorithm: AlgorithmIdentifierRef<'_>) -> Option<Option<Profile>> {
    match algorithm.oid.as_bytes() {
        transport::RSA_ENCRYPTION if algorithm.parameters == Some(AnyRef::NULL) => Some(None),
        RSA_KEM_SPKI => {
            let Some(parameters) = algorithm.parameters else {
                return Some(None);
            };
            if parameters.tag() != Tag::Sequence {
                return None;
            }
            // The public-key and private-key AlgorithmIdentifiers are DER.
            let mut reader = SliceReader::new(parameters.value()).ok()?;
            let kem = AlgorithmIdentifierRef::decode(&mut reader).ok()?;
            let dem = AlgorithmIdentifierRef::decode(&mut reader).ok()?;
            reader.finish().ok()?;
            if kem.oid.as_bytes() != KEM_RSA {
                return None;
            }

            let parameters = kem.parameters?;
            if parameters.tag() != Tag::Sequence {
                return None;
            }
            let mut reader = SliceReader::new(parameters.value()).ok()?;
            let kdf = AlgorithmIdentifierRef::decode(&mut reader).ok()?;
            let key_bytes = u8::decode(&mut reader).ok()?;
            reader.finish().ok()?;
            let kdf = Kdf::parse_der(kdf)?;

            let mut der = [0; 32];
            let dem = dem.encode_to_slice(&mut der).ok()?;
            let wrap = WrapAlgorithm::parse(Der::single(dem, SEQUENCE)?)?;
            if !allowed_wrap(wrap) || wrap.key_bytes() != key_bytes {
                return None;
            }
            Some(Some(Profile {
                kdf,
                key_bytes,
                wrap_der: wrap.key_info(),
            }))
        }
        _ => None,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum DigestOrder {
    SecretThenCounter,
    CounterThenSecret,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Hash {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Kdf {
    order: DigestOrder,
    hash: Hash,
}

impl Kdf {
    const DEFAULT: Self = Self {
        order: DigestOrder::CounterThenSecret,
        hash: Hash::Sha256,
    };

    fn algorithms(self) -> (&'static [u8], &'static [u8]) {
        let kdf = match self.order {
            DigestOrder::SecretThenCounter => KDF2,
            DigestOrder::CounterThenSecret => KDF3,
        };
        let hash: &[u8] = match self.hash {
            Hash::Sha1 => SHA1,
            Hash::Sha224 => b"\x60\x86\x48\x01\x65\x03\x04\x02\x04",
            Hash::Sha256 => b"\x60\x86\x48\x01\x65\x03\x04\x02\x01",
            Hash::Sha384 => b"\x60\x86\x48\x01\x65\x03\x04\x02\x02",
            Hash::Sha512 => b"\x60\x86\x48\x01\x65\x03\x04\x02\x03",
        };
        (kdf, hash)
    }

    fn parse(item: Item<'_>) -> Option<Self> {
        let (oid, parameters) = algorithm(item)?;
        let (hash, hash_parameters) = algorithm(parameters?)?;
        if hash_parameters
            .is_some_and(|parameters| parameters.tag != 0x05 || !parameters.data.is_empty())
        {
            return None;
        }
        Self::from_oids(oid, hash)
    }

    fn parse_der(algorithm: AlgorithmIdentifierRef<'_>) -> Option<Self> {
        let hash: AlgorithmIdentifierRef<'_> = algorithm.parameters?.decode_as().ok()?;
        if hash.parameters.is_some_and(|value| value != AnyRef::NULL) {
            return None;
        }
        Self::from_oids(algorithm.oid.as_bytes(), hash.oid.as_bytes())
    }

    fn from_oids(kdf: &[u8], hash: &[u8]) -> Option<Self> {
        let order = match kdf {
            KDF2 => DigestOrder::SecretThenCounter,
            KDF3 => DigestOrder::CounterThenSecret,
            _ => return None,
        };
        let hash = if hash == SHA1 {
            Hash::Sha1
        } else {
            match hash.strip_prefix(SHA2)? {
                [4] => Hash::Sha224,
                [1] => Hash::Sha256,
                [2] => Hash::Sha384,
                [3] => Hash::Sha512,
                _ => return None,
            }
        };
        Some(Self { order, hash })
    }

    fn derive(self, secret: &[u8], info: &[u8], output: &mut [u8]) -> Option<()> {
        match self.hash {
            Hash::Sha1 => self.expand::<Sha1>(secret, info, output),
            Hash::Sha224 => self.expand::<Sha224>(secret, info, output),
            Hash::Sha256 => self.expand::<Sha256>(secret, info, output),
            Hash::Sha384 => self.expand::<Sha384>(secret, info, output),
            Hash::Sha512 => self.expand::<Sha512>(secret, info, output),
        }
    }

    fn expand<D: Digest>(self, secret: &[u8], info: &[u8], output: &mut [u8]) -> Option<()> {
        for (index, block) in output.chunks_mut(<D as Digest>::output_size()).enumerate() {
            let counter = u32::try_from(index + 1).ok()?.to_be_bytes();
            let mut digest = D::new();
            let parts: [&[u8]; 2] = match self.order {
                DigestOrder::SecretThenCounter => [secret, &counter],
                DigestOrder::CounterThenSecret => [&counter, secret],
            };
            for part in parts {
                digest.update(part);
            }
            digest.update(info);
            let mut derived = digest.finalize();
            block.copy_from_slice(&derived[..block.len()]);
            derived.as_mut_slice().zeroize();
        }
        Some(())
    }
}

pub(super) struct Recipient<'a> {
    key: &'a Key,
    ciphertext: Cow<'a, [u8]>,
    inner: Kdf,
    wrap: KeyWrap<'a>,
}

enum KeyWrap<'a> {
    RecipientInfo {
        wrap: kem_recipient::Wrap<'a>,
        kdf: Kdf,
    },
    KeyTransport(WrappedKey<'a>),
}

impl KeyWrap<'_> {
    fn key_bytes(&self) -> u8 {
        match self {
            Self::RecipientInfo { wrap, .. } => wrap.algorithm().key_bytes(),
            Self::KeyTransport(wrap) => wrap.algorithm().key_bytes(),
        }
    }

    fn open(self, shared: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        match self {
            Self::RecipientInfo { wrap, kdf } => {
                wrap.open(shared, |secret, info, kek| kdf.derive(secret, info, kek))
            }
            Self::KeyTransport(wrap) => wrap.open(shared),
        }
    }
}

impl Recipient<'_> {
    pub(super) fn open(self) -> Option<Zeroizing<Vec<u8>>> {
        let private = &self.key.private;
        let ciphertext =
            BoxedUint::from_be_slice(&self.ciphertext, private.n_bits_precision()).ok()?;
        if ciphertext >= *private.n().as_ref() {
            return None;
        }
        let representative =
            Zeroizing::new(rsa_decrypt_and_check(private, Some(&mut SysRng), &ciphertext).ok()?);
        let padded = Zeroizing::new(representative.to_be_bytes());
        // The integer's storage precision may include padding to a whole limb.
        // Convert to the modulus width using only the public key width.
        let secret = padded.get(padded.len().checked_sub(private.size())?..)?;
        let mut shared = Zeroizing::new([0; 32]);
        let shared = shared.get_mut(..usize::from(self.wrap.key_bytes()))?;
        self.inner.derive(secret, &[], shared)?;
        self.wrap.open(shared)
    }
}

fn rsa_kem_parameters(parameters: Item<'_>) -> Option<(Kdf, u64)> {
    if parameters.tag != SEQUENCE {
        return None;
    }
    let mut fields = Ber(parameters.data);
    let kdf = Kdf::parse(fields.take(SEQUENCE)?)?;
    let length = fields.take(INTEGER)?.uint()?;
    fields.finish()?;
    Some((kdf, length))
}

fn allowed_wrap(wrap: WrapAlgorithm) -> bool {
    matches!(
        wrap,
        WrapAlgorithm::Aes128
            | WrapAlgorithm::Aes192
            | WrapAlgorithm::Aes256
            | WrapAlgorithm::TripleDes
    )
}

impl Profile {
    fn permits(configured: Option<Self>, kdf: Kdf, wrap: WrapAlgorithm) -> bool {
        configured.is_none_or(|profile| {
            profile
                == Self {
                    kdf,
                    key_bytes: wrap.key_bytes(),
                    wrap_der: wrap.key_info(),
                }
        })
    }
}

pub(super) fn select<'a>(
    key: &'a Key,
    rid: &RecipientId,
    entry: Item<'a>,
) -> Option<Option<Recipient<'a>>> {
    if entry.tag == SEQUENCE {
        return select_legacy(key, rid, entry);
    }
    let Some(info) = kem_recipient::select(rid, entry)? else {
        return Some(None);
    };
    let (oid, parameters) = algorithm(info.algorithm)?;
    if oid != KEM_RSA {
        return None;
    }

    let wrap = info.wrap.algorithm();
    let outer = Kdf::parse(info.kdf)?;
    if !allowed_wrap(wrap)
        || outer.hash == Hash::Sha1
        || !Profile::permits(key.restriction, outer, wrap)
    {
        return None;
    }
    let inner = match parameters {
        Some(parameters) => {
            let (kdf, length) = rsa_kem_parameters(parameters)?;
            if kdf.hash == Hash::Sha1 || length != u64::from(wrap.key_bytes()) {
                return None;
            }
            kdf
        }
        None => Kdf::DEFAULT,
    };
    let ciphertext = info.ciphertext.octets(OCTETS, key.private.size())?;
    if ciphertext.len() != key.private.size() {
        return None;
    }
    Some(Some(Recipient {
        key,
        ciphertext,
        inner,
        wrap: KeyWrap::RecipientInfo {
            wrap: info.wrap,
            kdf: outer,
        },
    }))
}

// RFC 5990 stores the RSA representative and symmetric wrap together in
// encryptedKey and derives the KEK directly, with no CMS OtherInfo.
fn select_legacy<'a>(
    key: &'a Key,
    rid: &RecipientId,
    entry: Item<'a>,
) -> Option<Option<Recipient<'a>>> {
    let mut fields = Ber(entry.data);
    let version = fields.take(INTEGER)?.uint()?;
    let identity = fields.read()?;
    let selected = match version {
        0 => rid.issuer_and_serial(identity)?,
        2 => rid.key_identifier(identity, IMPLICIT_OCTETS)?,
        _ => return None,
    };
    let key_algorithm = fields.take(SEQUENCE)?;
    let encrypted = fields.read()?;
    fields.finish()?;
    if !selected {
        return Some(None);
    }
    let (oid, parameters) = algorithm(key_algorithm)?;
    if oid != RSA_KEM_SPKI {
        return Some(None);
    }
    let parameters = parameters?;
    if parameters.tag != SEQUENCE {
        return None;
    }
    let mut parameters = Ber(parameters.data);
    let (oid, kem) = algorithm(parameters.take(SEQUENCE)?)?;
    let dem = parameters.take(SEQUENCE)?;
    parameters.finish()?;
    if oid != KEM_RSA {
        return None;
    }
    let (inner, length) = rsa_kem_parameters(kem?)?;
    let width = key.private.size();
    let encrypted = encrypted.octets(OCTETS, width.checked_add(key_wrap::MAX_WRAPPED_BYTES)?)?;
    if encrypted.len() <= width {
        return None;
    }
    let (ciphertext, wrapped) = match encrypted {
        Cow::Borrowed(bytes) => {
            let (ciphertext, wrapped) = bytes.split_at(width);
            (Cow::Borrowed(ciphertext), Cow::Borrowed(wrapped))
        }
        Cow::Owned(mut bytes) => {
            let wrapped = bytes.split_off(width);
            (Cow::Owned(bytes), Cow::Owned(wrapped))
        }
    };
    let wrapped = WrappedKey::parse(dem, wrapped)?;
    let wrap = wrapped.algorithm();
    if !allowed_wrap(wrap)
        || u64::from(wrap.key_bytes()) != length
        || !Profile::permits(key.restriction, inner, wrap)
    {
        return None;
    }
    Some(Some(Recipient {
        key,
        ciphertext,
        inner,
        wrap: KeyWrap::KeyTransport(wrapped),
    }))
}

#[cfg(test)]
mod tests;
