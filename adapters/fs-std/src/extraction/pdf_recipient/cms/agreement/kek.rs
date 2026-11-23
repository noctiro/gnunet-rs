//! Content-key derivation for CMS ephemeral-static ECDH.

use hkdf::{GenericHkdf, HmacImpl};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use zeroize::{Zeroize, Zeroizing};

use super::super::key_wrap::{Algorithm, WrappedKey};

pub(super) const MAX_UKM_BYTES: usize = 1024;

pub(super) struct Scheme<'a> {
    digest: Kdf,
    wrapped: WrappedKey<'a>,
}

enum Kdf {
    X963Sha1,
    X963Sha224,
    X963Sha256,
    X963Sha384,
    X963Sha512,
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
}

#[derive(Clone, Copy)]
pub(super) enum Method {
    Ecdh,
    Montgomery,
    Mqv,
}

impl Method {
    pub(super) fn is_mqv(oid: &[u8]) -> bool {
        matches!(
            oid,
            b"\x2b\x81\x05\x10\x86\x48\x3f\x00\x10" | [0x2b, 0x81, 0x04, 0x01, 0x0f, 0..=3]
        )
    }
}

impl<'a> Scheme<'a> {
    pub(super) fn parse(kdf: &[u8], wrapped: WrappedKey<'a>, method: Method) -> Option<Self> {
        if matches!(wrapped.algorithm(), Algorithm::Rc2(_))
            || Self::wrong_method(kdf, method)
            || matches!(method, Method::Montgomery) && !wrapped.algorithm().is_aes()
        {
            return None;
        }
        let montgomery = matches!(method, Method::Montgomery);
        let digest = match kdf {
            b"\x2b\x81\x05\x10\x86\x48\x3f\x00\x02" | b"\x2b\x81\x05\x10\x86\x48\x3f\x00\x03"
                if !montgomery =>
            {
                Kdf::X963Sha1
            }
            [0x2b, 0x81, 0x04, 0x01, 0x0b | 0x0e, 0] if !montgomery => Kdf::X963Sha224,
            [0x2b, 0x81, 0x04, 0x01, 0x0b, 1] => Kdf::X963Sha256,
            [0x2b, 0x81, 0x04, 0x01, 0x0b, 2] => Kdf::X963Sha384,
            [0x2b, 0x81, 0x04, 0x01, 0x0b, 3] => Kdf::X963Sha512,
            // The admitted NIST prime curves have cofactor one.
            [0x2b, 0x81, 0x04, 0x01, 0x0e, 1] if !montgomery => Kdf::X963Sha256,
            [0x2b, 0x81, 0x04, 0x01, 0x0e, 2] if !montgomery => Kdf::X963Sha384,
            [0x2b, 0x81, 0x04, 0x01, 0x0e, 3] if !montgomery => Kdf::X963Sha512,
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x13" if montgomery => Kdf::HkdfSha256,
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x14" if montgomery => Kdf::HkdfSha384,
            b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x15" if montgomery => Kdf::HkdfSha512,
            b"\x2b\x81\x05\x10\x86\x48\x3f\x00\x10" if matches!(method, Method::Mqv) => {
                Kdf::X963Sha1
            }
            [0x2b, 0x81, 0x04, 0x01, 0x0f, 0] if matches!(method, Method::Mqv) => Kdf::X963Sha224,
            [0x2b, 0x81, 0x04, 0x01, 0x0f, 1] if matches!(method, Method::Mqv) => Kdf::X963Sha256,
            [0x2b, 0x81, 0x04, 0x01, 0x0f, 2] if matches!(method, Method::Mqv) => Kdf::X963Sha384,
            [0x2b, 0x81, 0x04, 0x01, 0x0f, 3] if matches!(method, Method::Mqv) => Kdf::X963Sha512,
            _ => return None,
        };
        Some(Self { digest, wrapped })
    }

    fn wrong_method(kdf: &[u8], method: Method) -> bool {
        Method::is_mqv(kdf) != matches!(method, Method::Mqv)
    }

    pub(super) fn unwrap(self, ukm: Option<&[u8]>, secret: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let wrap = self.wrapped.algorithm();
        let info = SharedInfo::new(wrap, ukm)?;
        let mut key = Zeroizing::new([0; 32]);
        let kek = &mut key[..usize::from(wrap.key_bytes())];
        match self.digest {
            Kdf::X963Sha1 => info.derive::<Sha1>(secret, kek),
            Kdf::X963Sha224 => info.derive::<Sha224>(secret, kek),
            Kdf::X963Sha256 => info.derive::<Sha256>(secret, kek),
            Kdf::X963Sha384 => info.derive::<Sha384>(secret, kek),
            Kdf::X963Sha512 => info.derive::<Sha512>(secret, kek),
            // RFC 8418 §2.2 uses UKM both as salt and in DER SharedInfo.
            Kdf::HkdfSha256 => info
                .with_der(|fields| expand_hkdf::<hmac::Hmac<Sha256>>(ukm, secret, fields, kek))
                .ok()?,
            Kdf::HkdfSha384 => info
                .with_der(|fields| expand_hkdf::<hmac::Hmac<Sha384>>(ukm, secret, fields, kek))
                .ok()?,
            Kdf::HkdfSha512 => info
                .with_der(|fields| expand_hkdf::<hmac::Hmac<Sha512>>(ukm, secret, fields, kek))
                .ok()?,
        }
        self.wrapped.open(kek)
    }
}

fn expand_hkdf<H: HmacImpl>(
    salt: Option<&[u8]>,
    secret: &[u8],
    fields: &[&[u8]],
    kek: &mut [u8],
) -> Result<(), hkdf::InvalidLength> {
    let (mut prk, derivation) = GenericHkdf::<H>::extract(salt, secret);
    prk.as_mut_slice().zeroize();
    derivation.expand_multi_info(fields, kek)
}

struct DerHeader {
    bytes: [u8; 4],
    size: u16,
}

impl DerHeader {
    const fn new(tag: u8, length: u16) -> Self {
        let [high, low] = length.to_be_bytes();
        let (bytes, size) = match length {
            0..=127 => ([tag, low, 0, 0], 2),
            128..=255 => ([tag, 0x81, low, 0], 3),
            _ => ([tag, 0x82, high, low], 4),
        };
        Self { bytes, size }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.size)]
    }
}

struct EntityInfo<'a> {
    ukm: &'a [u8],
    explicit: DerHeader,
    octets: DerHeader,
}

struct SharedInfo<'a> {
    key_wrap: Algorithm,
    sequence: DerHeader,
    entity: Option<EntityInfo<'a>>,
}

impl<'a> SharedInfo<'a> {
    fn new(key_wrap: Algorithm, ukm: Option<&'a [u8]>) -> Option<Self> {
        let mut sequence_length = u16::try_from(key_wrap.key_info().len()).ok()? + 8;
        let entity = if let Some(ukm) = ukm {
            if ukm.len() > MAX_UKM_BYTES {
                return None;
            }
            let ukm_length = u16::try_from(ukm.len()).ok()?;
            let octets = DerHeader::new(0x04, ukm_length);
            let explicit = DerHeader::new(0xa0, octets.size + ukm_length);
            sequence_length += explicit.size + octets.size + ukm_length;
            Some(EntityInfo {
                ukm,
                explicit,
                octets,
            })
        } else {
            None
        };
        let sequence = DerHeader::new(0x30, sequence_length);
        Some(Self {
            key_wrap,
            sequence,
            entity,
        })
    }

    fn with_der<T>(&self, accept: impl FnOnce(&[&[u8]]) -> T) -> T {
        let key_info = self.key_wrap.key_info();
        let key_bits = (u32::from(self.key_wrap.key_bytes()) * 8).to_be_bytes();
        let key_length = [
            0xa2,
            0x06,
            0x04,
            0x04,
            key_bits[0],
            key_bits[1],
            key_bits[2],
            key_bits[3],
        ];
        let sequence = self.sequence.as_bytes();
        match &self.entity {
            Some(entity) => accept(&[
                sequence,
                key_info,
                entity.explicit.as_bytes(),
                entity.octets.as_bytes(),
                entity.ukm,
                &key_length,
            ]),
            None => accept(&[sequence, key_info, &key_length]),
        }
    }

    fn derive<D: Digest>(&self, secret: &[u8], key: &mut [u8]) {
        // SEC 1 §3.6.1 hashes Z || Counter || DER(ECC-CMS-SharedInfo).
        for (counter, destination) in (1_u32..).zip(key.chunks_mut(<D as Digest>::output_size())) {
            let mut digest = D::new();
            digest.update(secret);
            digest.update(counter.to_be_bytes());
            self.with_der(|fields| {
                for field in fields {
                    digest.update(field);
                }
            });
            let mut output = digest.finalize();
            destination.copy_from_slice(&output[..destination.len()]);
            output.as_mut_slice().zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;

    fn unwrap(
        kdf: &[u8],
        wrap: &[u8],
        ukm: Option<&[u8]>,
        secret: &[u8],
        data: &[u8],
    ) -> Option<zeroize::Zeroizing<Vec<u8>>> {
        let encoded = [b"\x30\x0b\x06\x09", wrap].concat();
        let identifier = super::super::super::Ber(&encoded).read()?;
        let wrapped = WrappedKey::parse(identifier, Cow::Borrowed(data))?;
        Scheme::parse(kdf, wrapped, Method::Ecdh)?.unwrap(ukm, secret)
    }

    #[test]
    fn cms_aes_key_unwrap_derives_both_sha1_blocks_with_long_ukm() {
        // OpenSSL X963KDF and AES-256, with a 130-byte user-keying value.
        let secret: [u8; 32] = std::array::from_fn(|index| index as u8);
        let ukm = [0x42; 130];
        let sha1_kdf = b"\x2b\x81\x05\x10\x86\x48\x3f\x00\x02";
        let aes256_wrap = b"\x60\x86\x48\x01\x65\x03\x04\x01\x2d";
        let mut wrapped = *b"\x50\xf9\xcd\xa9\xa0\xfc\x31\xfb\x1a\x04\xb7\x8a\x18\x34\x4e\xb8\x87\xbd\x83\x6e\x4e\xca\xf3\xd6";
        let expected = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
        let actual = unwrap(sha1_kdf, aes256_wrap, Some(&ukm), &secret, &wrapped);
        assert_eq!(
            actual.as_deref().map(Vec::as_slice),
            Some(expected.as_slice())
        );
        assert!(unwrap(sha1_kdf, aes256_wrap, None, &secret, &wrapped).is_none());
        wrapped[0] ^= 1;
        assert!(unwrap(sha1_kdf, aes256_wrap, Some(&ukm), &secret, &wrapped).is_none());
    }
}
