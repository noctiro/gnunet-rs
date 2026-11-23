//! CMS key-encryption-key recipient credentials and selection (RFC 5652 §6.2.3).

use std::borrow::Cow;

use x509_parser::asn1_rs::GeneralizedTime;
use zeroize::Zeroizing;

use crate::extraction::Error;

use super::asn1::valid_oid;
use super::{
    Ber, Envelope, INTEGER, Item, MAX_KEY_ID, OCTETS, OID, OpenContentKey,
    PdfRecipientAuthorization, PdfRecipientContent, SEQUENCE, key_wrap,
};

const KEK_RECIPIENT: u8 = 0xa2;
const GENERALIZED_TIME: u8 = 0x18;
const MAX_IDENTIFIER_BYTES: usize = 4096;

/// A locally supplied key-encryption key for a CMS KEK recipient.
pub struct PdfKekRecipient {
    selector: Identifier<'static>,
    key: Zeroizing<Vec<u8>>,
}

impl PdfKekRecipient {
    /// Bind a key to a public CMS key identifier without a date or other attribute.
    /// Use a different identifier when rotating the key.
    ///
    /// # Errors
    ///
    /// Returns a limit error for an oversized identifier and a binding error for
    /// an empty identifier or a key length other than 16, 24 or 32 bytes.
    pub fn from_key(identifier: &[u8], key: &[u8]) -> Result<Self, Error> {
        if identifier.len() > MAX_KEY_ID {
            return Err(Error::Limit);
        }
        if identifier.is_empty() {
            return Err(Error::Binding);
        }
        Self::bind(
            Identifier {
                key_id: Cow::Borrowed(identifier),
                date: None,
                other: None,
            },
            key,
        )
    }

    /// Bind a key to a BER-encoded CMS `KEKIdentifier` sequence.
    /// Use this for senders that distinguish keys by the optional date or
    /// other key attribute. Date and open attribute values match by their
    /// encoded values. Use a different selector when rotating the key.
    ///
    /// # Errors
    ///
    /// Returns a limit error for an oversized identifier and a binding error for
    /// malformed identifiers or a key length other than 16, 24 or 32 bytes.
    pub fn from_identifier_ber(identifier: &[u8], key: &[u8]) -> Result<Self, Error> {
        if identifier.len() > MAX_IDENTIFIER_BYTES {
            return Err(Error::Limit);
        }
        let identifier = Identifier::parse(Ber::sequence(identifier).ok_or(Error::Binding)?)
            .ok_or(Error::Binding)?;
        Self::bind(identifier, key)
    }

    fn bind(selector: Identifier<'_>, key: &[u8]) -> Result<Self, Error> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(Error::Binding);
        }
        Ok(Self {
            selector: selector.into_owned(),
            key: Zeroizing::new(key.to_vec()),
        })
    }

    /// Transfer the key to a local PDF extraction authorization. The public
    /// binding identity commits to the selector's public fields.
    #[must_use]
    pub fn into_authorization(self) -> PdfRecipientAuthorization {
        PdfRecipientAuthorization::new(self.selector.fingerprint(), move |bytes| self.open(bytes))
    }

    fn open<'a>(&'a self, bytes: &'a [u8]) -> Option<PdfRecipientContent> {
        Envelope::parse(bytes)?.open(|entry, _| self.select(entry))
    }

    fn select<'a>(&'a self, entry: Item<'a>) -> Option<Option<Selected<'a>>> {
        if entry.tag != KEK_RECIPIENT {
            return Some(None);
        }
        let mut fields = Ber(entry.data);
        if fields.take(INTEGER)?.uint()? != 4 {
            return None;
        }
        let selector = Identifier::parse(Ber(fields.take(SEQUENCE)?.data))?;
        let wrapping = fields.take(SEQUENCE)?;
        let encrypted = fields.read()?;
        fields.finish()?;
        if selector != self.selector {
            return Some(None);
        }

        let wrapped = key_wrap::WrappedKey::read(wrapping, encrypted)?;
        let algorithm = wrapped.algorithm();
        // An AES KEK can wrap a CEK no larger than itself (RFC 3565 §6).
        // RFC 3370 §4.3.2 requires RC2 version 58 for a pre-shared KEK.
        if usize::from(algorithm.key_bytes()) != self.key.len()
            || algorithm.is_aes() && wrapped.wrapped_bytes().checked_sub(8)? > self.key.len()
            || matches!(
                algorithm,
                key_wrap::Algorithm::Rc2(
                    key_wrap::Rc2Version::Bits40 | key_wrap::Rc2Version::Bits64
                )
            )
        {
            return None;
        }
        Some(Some(Selected {
            wrapped,
            key: &self.key,
        }))
    }
}

struct Selected<'a> {
    wrapped: key_wrap::WrappedKey<'a>,
    key: &'a [u8],
}

impl OpenContentKey for Selected<'_> {
    fn content_key(self) -> Option<Zeroizing<Vec<u8>>> {
        self.wrapped.open(self.key)
    }
}

#[derive(PartialEq, Eq)]
struct Identifier<'a> {
    key_id: Cow<'a, [u8]>,
    date: Option<Cow<'a, [u8]>>,
    other: Option<OtherKeyAttribute<'a>>,
}

impl<'a> Identifier<'a> {
    fn parse(mut fields: Ber<'a>) -> Option<Self> {
        if fields.0.len() > MAX_IDENTIFIER_BYTES {
            return None;
        }
        let key_id = fields.read()?.octets(OCTETS, MAX_KEY_ID)?;
        if key_id.is_empty() {
            return None;
        }
        let date = match fields.optional(GENERALIZED_TIME)? {
            Some(item) => {
                let _validated = GeneralizedTime::from_bytes(item.data).ok()?;
                Some(Cow::Borrowed(item.data))
            }
            None => None,
        };
        let other = match fields.optional(SEQUENCE)? {
            Some(item) => Some(OtherKeyAttribute::parse(item)?),
            None => None,
        };
        fields.finish()?;
        Some(Self {
            key_id,
            date,
            other,
        })
    }

    fn into_owned(self) -> Identifier<'static> {
        Identifier {
            key_id: Cow::Owned(self.key_id.into_owned()),
            date: self.date.map(|value| Cow::Owned(value.into_owned())),
            other: self.other.map(OtherKeyAttribute::into_owned),
        }
    }

    fn fingerprint(&self) -> [u8; 32] {
        let date = self.date.as_deref().unwrap_or_default();
        let (oid, value) = self
            .other
            .as_ref()
            .map_or((b"".as_slice(), b"".as_slice()), |other| {
                (&*other.oid, other.value.as_deref().unwrap_or_default())
            });
        // Each field's bounded length is encoded independently before hashing.
        gnunet_crypto::hash256_parts(&[
            b"GNUnet PDF CMS KEK recipient v1\0",
            &(self.key_id.len() as u16).to_be_bytes(),
            &self.key_id,
            &(date.len() as u16).to_be_bytes(),
            date,
            &(oid.len() as u16).to_be_bytes(),
            oid,
            &(value.len() as u16).to_be_bytes(),
            value,
        ])
    }
}

#[derive(PartialEq, Eq)]
struct OtherKeyAttribute<'a> {
    oid: Cow<'a, [u8]>,
    value: Option<Cow<'a, [u8]>>,
}

impl<'a> OtherKeyAttribute<'a> {
    fn parse(item: Item<'a>) -> Option<Self> {
        let mut fields = Ber(item.data);
        let oid = fields.take(OID)?.data;
        if !valid_oid(oid) {
            return None;
        }
        let value = if fields.0.is_empty() {
            None
        } else {
            Some(Cow::Borrowed(fields.read()?.encoded))
        };
        fields.finish()?;
        Some(Self {
            oid: Cow::Borrowed(oid),
            value,
        })
    }

    fn into_owned(self) -> OtherKeyAttribute<'static> {
        OtherKeyAttribute {
            oid: Cow::Owned(self.oid.into_owned()),
            value: self.value.map(|value| Cow::Owned(value.into_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OpenSSL CMS AES-128-CBC with a distinct AES-128 key-encryption key.
    const KEY: &[u8; 16] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
    const SEED: &[u8; 20] = b"recipient-seed-bytes";
    const IDENTIFIER: &[u8] = b"pdf-kek-1";
    const ENVELOPE: &[u8] = b"\
        \x30\x81\x9d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03\xa0\x81\
        \x8f\x30\x81\x8c\x02\x01\x02\x31\x39\xa2\x37\x02\x01\x04\x30\x0b\
        \x04\x09\x70\x64\x66\x2d\x6b\x65\x6b\x2d\x31\x30\x0b\x06\x09\x60\
        \x86\x48\x01\x65\x03\x04\x01\x05\x04\x18\x18\xa0\x75\xa1\xa2\x06\
        \x4b\x6a\x0d\x50\xdb\xd3\x21\x4e\xea\x0f\x10\x23\xe8\x0f\x45\xa7\
        \x43\x24\x30\x4c\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01\x30\
        \x1d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x02\x04\x10\x63\x53\
        \x84\xa9\xbd\x33\x42\x7e\xdf\x90\xba\xb1\x89\x28\xee\xb0\x80\x20\
        \x4e\x27\x67\xd5\x80\x7a\x26\x54\x6d\xcd\xfa\x55\xf2\xf7\xe8\xf3\
        \x9b\xab\xe6\xf4\x18\x77\x7e\xd4\xd0\x75\x7f\x1c\xb2\xc0\xef\x31";

    #[test]
    fn opens_an_openssl_kek_recipient() {
        let recipient = PdfKekRecipient::from_key(IDENTIFIER, KEY);
        let Ok(recipient) = recipient else {
            assert!(recipient.is_ok());
            return;
        };
        let auth = recipient.into_authorization();
        assert!(matches!(
            auth.open(ENVELOPE),
            Some(PdfRecipientContent::Document { seed, permissions })
                if *seed == *SEED && permissions == [0xff, 0xff, 0xf2, 0xd0]
        ));
        assert_ne!(auth.identity(), &[0; 32]);

        for (id, key) in [(b"other".as_slice(), KEY), (IDENTIFIER, &[0; 16])] {
            assert!(
                PdfKekRecipient::from_key(id, key)
                    .is_ok_and(|wrong| wrong.into_authorization().open(ENVELOPE).is_none())
            );
        }
    }

    #[test]
    fn opens_rc2_kek_recipient_with_rfc3370_parameter_version() {
        let key = b"\xfd\x04\xfd\x08\x06\x07\x07\xfb\x00\x03\xfe\xff\xfd\x02\xfe\x05";
        let rc2 =
            PdfKekRecipient::from_key(b"pdf-rc2-1", key).map(PdfKekRecipient::into_authorization);
        let Ok(auth) = rc2 else {
            assert!(rc2.is_ok());
            return;
        };
        let wrapped_128 = b"\xf4\xd8\x02\x1c\x1e\xa4\x63\xd2\x17\xa9\xeb\x69\x29\xff\xa5\x77\x36\xd3\xe2\x03\x86\xc9\x09\x93\x83\x5b\x4b\xe4\xad\x8d\x8a\x1b\xc6\x3b\x25\xde\x2b\xf7\x79\x93";
        let wrapped_40 = b"\x70\xe6\x99\xfb\x57\x01\xf7\x83\x33\x30\xfb\x71\xe8\x7c\x85\xa4\x20\xbd\xc9\x9a\xf0\x5d\x22\xaf\x5a\x0e\x48\xd3\x5f\x31\x38\x98\x6c\xba\xaf\xb4\xb2\x8d\x4f\x35";
        let algorithm_128 =
            b"\x30\x10\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x07\x02\x01\x3a";
        let algorithm_40 =
            b"\x30\x11\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x07\x02\x02\x00\xa0";
        assert!(matches!(
            auth.open(&rc2_envelope(algorithm_128, wrapped_128)),
            Some(PdfRecipientContent::Document { seed, permissions })
                if *seed == *SEED && permissions == [0xff, 0xff, 0xf2, 0xd0]
        ));
        assert!(auth.open(&rc2_envelope(algorithm_40, wrapped_40)).is_none());
        let mut changed = *wrapped_128;
        changed[0] ^= 1;
        assert!(auth.open(&rc2_envelope(algorithm_128, &changed)).is_none());
    }

    fn rc2_envelope(identifier: &[u8], wrapped: &[u8; 40]) -> Vec<u8> {
        // The CEK comes from the RFC 3217 erratum 639 vector. The RC2-CBC
        // encrypted recipient payload was generated with OpenSSL.
        let recipient = b"\x30\x80\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x03\xa0\x80\x30\x80\x02\x01\x02\x31\x80\xa2\x80\x02\x01\x04\x30\x0b\x04\x09pdf-rc2-1";
        let content = b"\x00\x00\x00\x00\x30\x48\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01\x30\x19\x06\x08\x2a\x86\x48\x86\xf7\x0d\x03\x02\x30\x0d\x02\x01\x3a\x04\x08\x00\x01\x02\x03\x04\x05\x06\x07\x80\x20\x37\x74\x77\xed\x9e\xc7\xc7\x92\x28\xe5\x40\x1a\x74\x1d\x72\x0b\x6d\x00\x00\xf8\x27\x21\x5c\x3e\xd3\xa5\x21\x20\x7a\x1c\x10\x9a\x00\x00\x00\x00\x00\x00";
        [
            recipient.as_slice(),
            identifier,
            b"\x04\x28",
            wrapped,
            content,
        ]
        .concat()
    }

    #[test]
    fn public_binding_keeps_the_optional_selector() {
        let bare = b"\x30\x0b\x04\x09pdf-kek-1";
        let dated = b"\x30\x1c\x04\x09pdf-kek-1\x18\x0f20261120000000Z";
        let plain = PdfKekRecipient::from_key(IDENTIFIER, KEY);
        let from_bare = PdfKekRecipient::from_identifier_ber(bare, KEY);
        let from_dated = PdfKekRecipient::from_identifier_ber(dated, KEY);
        assert!(plain.is_ok() && from_bare.is_ok() && from_dated.is_ok());
        let (Ok(plain), Ok(from_bare), Ok(from_dated)) = (plain, from_bare, from_dated) else {
            return;
        };
        let plain = plain.into_authorization();
        let from_bare = from_bare.into_authorization();
        let from_dated = from_dated.into_authorization();
        assert_eq!(plain.identity(), from_bare.identity());
        assert_ne!(plain.identity(), from_dated.identity());
        assert!(from_dated.open(ENVELOPE).is_none());

        // Replace KEKIdentifier while preserving the wrapped key and content.
        let mut extended = ENVELOPE.to_vec();
        for length_byte in [2, 16, 19, 24, 26] {
            extended[length_byte] += 17;
        }
        drop(extended.splice(30..43, dated.iter().copied()));
        assert!(plain.open(&extended).is_none());
        assert!(from_dated.open(&extended).is_some());
    }
}
