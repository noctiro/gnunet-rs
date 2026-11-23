//! Common CMS KEMRecipientInfo framing and canonical key derivation context.

use std::borrow::Cow;

use p256::elliptic_curve::pkcs8::der::{
    Encode, Header, Length, SliceWriter, Tag, TagMode, TagNumber, Writer,
    asn1::{ContextSpecific, OctetStringRef},
};
use zeroize::Zeroizing;

use super::{
    Ber, CONTEXT_0, IMPLICIT_OCTETS, INTEGER, Item, OCTETS, OID, RecipientId, SEQUENCE,
    key_agreement,
    key_wrap::{Algorithm, WrappedKey},
};

const ID_ORI_KEM: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x0d\x03";
const MAX_UKM_BYTES: usize = 1024;
const MAX_OTHER_INFO_BYTES: usize = MAX_UKM_BYTES + 64;

pub(super) struct Information<'a> {
    pub(super) algorithm: Item<'a>,
    pub(super) ciphertext: Item<'a>,
    pub(super) kdf: Item<'a>,
    pub(super) wrap: Wrap<'a>,
}

pub(super) struct Wrap<'a> {
    ukm: Option<Cow<'a, [u8]>>,
    key: WrappedKey<'a>,
}

impl Wrap<'_> {
    pub(super) const fn algorithm(&self) -> Algorithm {
        self.key.algorithm()
    }

    pub(super) fn open(
        self,
        secret: &[u8],
        derive: impl FnOnce(&[u8], &[u8], &mut [u8]) -> Option<()>,
    ) -> Option<Zeroizing<Vec<u8>>> {
        let algorithm = self.algorithm();
        let mut info = [0; MAX_OTHER_INFO_BYTES];
        let info = other_info(algorithm, self.ukm.as_deref(), &mut info)?;
        let mut kek = Zeroizing::new([0; 32]);
        let kek = kek.get_mut(..usize::from(algorithm.key_bytes()))?;
        derive(secret, info, kek)?;
        self.key.open(kek)
    }
}

pub(super) fn select<'a>(rid: &RecipientId, entry: Item<'a>) -> Option<Option<Information<'a>>> {
    let mut ori = Ber(entry.data);
    let oid = ori.take(OID)?.data;
    let info = ori.read()?;
    ori.finish()?;
    if oid != ID_ORI_KEM {
        return Some(None);
    }
    if info.tag != SEQUENCE {
        return None;
    }
    let mut fields = Ber(info.data);
    if fields.take(INTEGER)?.uint()? != 0 {
        return None;
    }
    let identifier = fields.read()?;
    let selected = match identifier.tag {
        SEQUENCE => rid.issuer_and_serial(identifier)?,
        IMPLICIT_OCTETS | CONTEXT_0 => rid.key_identifier(identifier, IMPLICIT_OCTETS)?,
        _ => return None,
    };
    if !selected {
        return Some(None);
    }
    let algorithm = fields.take(SEQUENCE)?;
    let ciphertext = fields.read()?;
    let kdf = fields.take(SEQUENCE)?;
    let kek_length = fields.take(INTEGER)?.uint()?;
    let ukm = match fields.optional(CONTEXT_0)? {
        Some(context) => Some(key_agreement::explicit(context)?.octets(OCTETS, MAX_UKM_BYTES)?),
        None => None,
    };
    let wrap = fields.take(SEQUENCE)?;
    let encrypted_key = fields.read()?;
    fields.finish()?;
    let key = WrappedKey::read(wrap, encrypted_key)?;
    if kek_length != u64::from(key.algorithm().key_bytes()) {
        return None;
    }
    Some(Some(Information {
        algorithm,
        ciphertext,
        kdf,
        wrap: Wrap { ukm, key },
    }))
}

// RFC 9629 requires canonical DER even when the originating envelope uses BER.
fn other_info<'a>(wrap: Algorithm, ukm: Option<&[u8]>, output: &'a mut [u8]) -> Option<&'a [u8]> {
    let key_length = wrap.key_bytes();
    let wrap_der = wrap.key_info();
    let tagged_ukm = match ukm {
        Some(data) => Some(ContextSpecific {
            tag_number: TagNumber(0),
            tag_mode: TagMode::Explicit,
            value: OctetStringRef::new(data).ok()?,
        }),
        None => None,
    };
    let length = (Length::try_from(wrap_der.len()).ok()? + key_length.encoded_len().ok()?).ok()?;
    let length = (length + tagged_ukm.encoded_len().ok()?).ok()?;
    let mut writer = SliceWriter::new(output);
    Header::new(Tag::Sequence, length)
        .encode(&mut writer)
        .ok()?;
    writer.write(wrap_der).ok()?;
    key_length.encode(&mut writer).ok()?;
    tagged_ukm.encode(&mut writer).ok()?;
    writer.finish().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_info_uses_canonical_der_and_binds_the_ukm() {
        let mut output = [0; 64];
        let der = other_info(Algorithm::Aes128, None, &mut output);
        // RFC 9936 Appendix C.1.
        assert_eq!(
            der,
            Some(
                b"\x30\x10\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x05\x02\x01\x10"
                    .as_slice()
            )
        );
        let der = other_info(Algorithm::Aes128, Some(b"UKM"), &mut output);
        assert_eq!(
        der,
        Some(b"\x30\x17\x30\x0b\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x05\x02\x01\x10\xa0\x05\x04\x03UKM".as_slice())
    );
    }
}
