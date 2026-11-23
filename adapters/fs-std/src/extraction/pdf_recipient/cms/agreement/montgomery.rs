//! Certificate-bound Montgomery key agreement for CMS (RFCs 8410 and 8418).

use p256::elliptic_curve::pkcs8::{PrivateKeyInfoRef, der::Decode};
use subtle::ConstantTimeEq;
use x509_parser::x509::SubjectPublicKeyInfo;

use super::super::{OCTETS, asn1::Der};

pub(in super::super) const X25519: &[u8] = b"\x2b\x65\x6e";
pub(in super::super) const X448: &[u8] = b"\x2b\x65\x6f";

pub(super) enum Key {
    X25519(x25519_dalek::StaticSecret),
    X448(x448::StaticSecret),
}

impl Key {
    pub(super) fn parse(certificate: &SubjectPublicKeyInfo<'_>, pkcs8: &[u8]) -> Option<Self> {
        let oid = certificate.algorithm.algorithm.as_bytes();
        if certificate.algorithm.parameters.is_some()
            || certificate.subject_public_key.unused_bits != 0
        {
            return None;
        }

        let private = PrivateKeyInfoRef::from_der(pkcs8).ok()?;
        if private.algorithm.oid.as_bytes() != oid || private.algorithm.parameters.is_some() {
            return None;
        }
        let private_bytes = Der::single(private.private_key.as_bytes(), OCTETS)?.data;
        let certificate_public = certificate.subject_public_key.data.as_ref();
        if let Some(public) = private.public_key
            && public.as_bytes()? != certificate_public
        {
            return None;
        }

        match oid {
            X25519 => {
                let scalar: &[u8; 32] = private_bytes.try_into().ok()?;
                let secret = x25519_dalek::StaticSecret::from(*scalar);
                if x25519_dalek::PublicKey::from(&secret).as_bytes() != certificate_public {
                    return None;
                }
                Some(Self::X25519(secret))
            }
            X448 => {
                let scalar: &[u8; 56] = private_bytes.try_into().ok()?;
                let secret = x448::StaticSecret::from(*scalar);
                if x448::PublicKey::from(&secret).as_bytes() != certificate_public {
                    return None;
                }
                Some(Self::X448(secret))
            }
            _ => None,
        }
    }

    pub(super) fn oid(&self) -> &'static [u8] {
        match self {
            Self::X25519(_) => X25519,
            Self::X448(_) => X448,
        }
    }

    pub(super) fn with_shared<T>(
        &self,
        peer: &[u8],
        use_secret: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Option<T> {
        match self {
            Self::X25519(key) => {
                let peer = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(peer).ok()?);
                let shared = key.diffie_hellman(&peer);
                if !shared.was_contributory() {
                    return None;
                }
                use_secret(shared.as_bytes())
            }
            Self::X448(key) => {
                let peer = x448::PublicKey::from_bytes(peer)?;
                let shared = key.diffie_hellman(&peer);
                let bytes = shared.as_bytes();
                if bool::from(bytes.ct_eq(&[0; 56])) {
                    return None;
                }
                use_secret(bytes)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use x509_parser::prelude::FromDer;

    use super::*;

    // RFC 7748 section 6.1 keys in the RFC 8410 X.509 and PKCS#8 encodings.
    const ALICE_SPKI: &[u8] = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x6e\x03\x21\x00\
        \x85\x20\xf0\x09\x89\x30\xa7\x54\x74\x8b\x7d\xdc\xb4\x3e\xf7\x5a\
        \x0d\xbf\x3a\x0d\x26\x38\x1a\xf4\xeb\xa4\xa9\x8e\xaa\x9b\x4e\x6a";
    const ALICE_PKCS8: &[u8] = b"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20\
        \x77\x07\x6d\x0a\x73\x18\xa5\x7d\x3c\x16\xc1\x72\x51\xb2\x66\x45\
        \xdf\x4c\x2f\x87\xeb\xc0\x99\x2a\xb1\x77\xfb\xa5\x1d\xb9\x2c\x2a";
    const BOB_PUBLIC: &[u8] = b"\xde\x9e\xdb\x7d\x7b\x7d\xc1\xb4\xd3\x5b\x61\xc2\xec\xe4\x35\x37\
        \x3f\x83\x43\xc8\x5b\x78\x67\x4d\xad\xfc\x7e\x14\x6f\x88\x2b\x4f";
    const SHARED: &[u8] = b"\x4a\x5d\x9d\x5b\xa4\xce\x2d\xe1\x72\x8e\x3b\xf4\x80\x35\x0f\x25\
        \xe0\x7e\x21\xc9\x47\xd1\x9e\x33\x76\xf0\x9b\x3c\x1e\x16\x17\x42";

    // RFC 7748 section 6.2.
    const ALICE_448_SPKI: &[u8] = b"\x30\x42\x30\x05\x06\x03\x2b\x65\x6f\x03\x39\x00\
        \x9b\x08\xf7\xcc\x31\xb7\xe3\xe6\x7d\x22\xd5\xae\xa1\x21\x07\x4a\
        \x27\x3b\xd2\xb8\x3d\xe0\x9c\x63\xfa\xa7\x3d\x2c\x22\xc5\xd9\xbb\
        \xc8\x36\x64\x72\x41\xd9\x53\xd4\x0c\x5b\x12\xda\x88\x12\x0d\x53\
        \x17\x7f\x80\xe5\x32\xc4\x1f\xa0";
    const ALICE_448_PKCS8: &[u8] =
        b"\x30\x46\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6f\x04\x3a\x04\x38\
        \x9a\x8f\x49\x25\xd1\x51\x9f\x57\x75\xcf\x46\xb0\x4b\x58\x00\xd4\
        \xee\x9e\xe8\xba\xe8\xbc\x55\x65\xd4\x98\xc2\x8d\xd9\xc9\xba\xf5\
        \x74\xa9\x41\x97\x44\x89\x73\x91\x00\x63\x82\xa6\xf1\x27\xab\x1d\
        \x9a\xc2\xd8\xc0\xa5\x98\x72\x6b";
    const BOB_448_PUBLIC: &[u8] =
        b"\x3e\xb7\xa8\x29\xb0\xcd\x20\xf5\xbc\xfc\x0b\x59\x9b\x6f\xec\xcf\
        \x6d\xa4\x62\x71\x07\xbd\xb0\xd4\xf3\x45\xb4\x30\x27\xd8\xb9\x72\
        \xfc\x3e\x34\xfb\x42\x32\xa1\x3c\xa7\x06\xdc\xb5\x7a\xec\x3d\xae\
        \x07\xbd\xc1\xc6\x7b\xf3\x36\x09";
    const SHARED_448: &[u8] = b"\x07\xff\xf4\x18\x1a\xc6\xcc\x95\xec\x1c\x16\xa9\x4a\x0f\x74\xd1\
        \x2d\xa2\x32\xce\x40\xa7\x75\x52\x28\x1d\x28\x2b\xb6\x0c\x0b\x56\
        \xfd\x24\x64\xc3\x35\x54\x39\x36\x52\x1c\x24\x40\x30\x85\xd5\x9a\
        \x44\x9a\x50\x37\x51\x4a\x87\x9d";

    fn parse(spki: &[u8], pkcs8: &[u8]) -> Option<Key> {
        let ([], spki) = SubjectPublicKeyInfo::from_der(spki).ok()? else {
            return None;
        };
        Key::parse(&spki, pkcs8)
    }

    #[test]
    fn x25519_opens_with_the_bound_key_and_rejects_zero_agreement() {
        let key = parse(ALICE_SPKI, ALICE_PKCS8);
        assert_eq!(key.as_ref().map(Key::oid), Some(X25519));
        let Some(key) = key else { return };
        assert_eq!(
            key.with_shared(BOB_PUBLIC, |secret| Some(secret == SHARED)),
            Some(true)
        );
        assert_eq!(key.with_shared(&[0; 32], |_| Some(())), None);
        assert_eq!(key.with_shared(&BOB_PUBLIC[..31], |_| Some(())), None);
    }

    #[test]
    fn x448_opens_with_the_bound_key_and_rejects_zero_agreement() {
        let key = parse(ALICE_448_SPKI, ALICE_448_PKCS8);
        assert_eq!(key.as_ref().map(Key::oid), Some(X448));
        let Some(key) = key else { return };
        assert_eq!(
            key.with_shared(BOB_448_PUBLIC, |secret| Some(secret == SHARED_448)),
            Some(true)
        );
        assert_eq!(key.with_shared(&[0; 56], |_| Some(())), None);
        assert_eq!(key.with_shared(BOB_PUBLIC, |_| Some(())), None);
    }

    #[test]
    fn x25519_requires_absent_parameters_and_exact_public_key_binding() {
        let mut spki = ALICE_SPKI.to_vec();
        spki[12..].copy_from_slice(BOB_PUBLIC);
        assert!(parse(&spki, ALICE_PKCS8).is_none());

        let mut spki = ALICE_SPKI.to_vec();
        spki[1] += 2;
        spki[3] += 2;
        drop(spki.splice(9..9, [0x05, 0x00]));
        assert!(parse(&spki, ALICE_PKCS8).is_none());

        let mut pkcs8 = ALICE_PKCS8.to_vec();
        pkcs8[1] += 2;
        pkcs8[6] += 2;
        drop(pkcs8.splice(12..12, [0x05, 0x00]));
        assert!(parse(ALICE_SPKI, &pkcs8).is_none());

        let mut pkcs8 = ALICE_PKCS8.to_vec();
        pkcs8[1] += 35;
        pkcs8[4] = 1;
        pkcs8.extend_from_slice(&[0x81, 0x21, 0x00]);
        pkcs8.extend_from_slice(&ALICE_SPKI[12..]);
        assert!(parse(ALICE_SPKI, &pkcs8).is_some());
        pkcs8[ALICE_PKCS8.len() + 3..].copy_from_slice(BOB_PUBLIC);
        assert!(parse(ALICE_SPKI, &pkcs8).is_none());
    }
}
