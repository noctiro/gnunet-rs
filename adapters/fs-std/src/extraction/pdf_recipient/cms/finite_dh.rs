//! X9.42 finite-field Diffie-Hellman CMS recipients (RFC 2631 and RFC 3370).

use crypto_bigint::{
    BoxedUint, CtEq, CtGt, CtLt, NonZero, Odd,
    modular::{BoxedMontyForm, BoxedMontyParams},
};
use crypto_primes::{Flavor, is_prime};
use rsa::pkcs8::{
    PrivateKeyInfoRef,
    der::{
        Decode, Reader, SliceReader, Tag, Tagged,
        asn1::{AnyRef, BitStringRef, UintRef},
    },
    spki::SubjectPublicKeyInfoRef,
};
use sha1::{Digest, Sha1};
use x509_parser::x509::SubjectPublicKeyInfo;
use zeroize::{Zeroize, Zeroizing};

use super::{
    Ber, CONTEXT_1, INTEGER, Item, OCTETS, RecipientId, SEQUENCE, algorithm, asn1::Der, key_wrap,
    originator::Certificates,
};

const DH_PUBLIC_NUMBER: &[u8] = b"\x2a\x86\x48\xce\x3e\x02\x01";
const EPHEMERAL_STATIC: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x05";
const STATIC_STATIC: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x0a";
const MAX_FIELD_BYTES: usize = 1024;
const MIN_FIELD_BITS: u32 = 512;
const MIN_SUBGROUP_BITS: u32 = 160;
const UKM_BYTES: usize = 64;

pub(super) fn supports(oid: &[u8]) -> bool {
    oid == DH_PUBLIC_NUMBER
}

pub(super) struct Key {
    domain: Domain,
    exponent: Zeroizing<BoxedUint>,
}

impl Key {
    pub(super) fn parse(spki: &SubjectPublicKeyInfo<'_>, pkcs8: &[u8]) -> Option<Self> {
        let (public, parameters) = public_key(spki)?;
        let pkcs8 = PrivateKeyInfoRef::from_der(pkcs8).ok()?;
        if !supports(pkcs8.algorithm.oid.as_bytes()) {
            return None;
        }

        let private_parameters = Parameters::parse(pkcs8.algorithm.parameters?)?;
        let domain = Domain::parse(&parameters)?;
        if !domain.matches(&private_parameters) {
            return None;
        }

        let x = UintRef::from_der(pkcs8.private_key.as_bytes()).ok()?;
        let exponent = Zeroizing::new(uint(x.as_bytes(), domain.subgroup_bits)?);
        if !in_range(&exponent, &domain.q) {
            return None;
        }

        let generator = BoxedMontyForm::new(domain.generator.clone(), &domain.field);
        let expected = Zeroizing::new(generator.pow_bounded_exp(&exponent, domain.subgroup_bits));
        let computed = Zeroizing::new(expected.retrieve());
        if !bool::from(computed.ct_eq(&domain.public_element(public)?)) {
            return None;
        }
        if let Some(embedded) = pkcs8.public_key {
            let embedded = Der::single(embedded.as_bytes()?, INTEGER)?.positive_integer()?;
            if embedded != public {
                return None;
            }
        }
        Some(Self { domain, exponent })
    }
}

struct Parameters<'a> {
    p: &'a [u8],
    g: &'a [u8],
    q: &'a [u8],
    j: Option<&'a [u8]>,
}

impl<'a> Parameters<'a> {
    fn parse(raw: AnyRef<'a>) -> Option<Self> {
        if raw.tag() != Tag::Sequence {
            return None;
        }
        let mut fields = SliceReader::new(raw.value()).ok()?;
        let p = UintRef::decode(&mut fields).ok()?.as_bytes();
        let g = UintRef::decode(&mut fields).ok()?.as_bytes();
        let q = UintRef::decode(&mut fields).ok()?.as_bytes();
        let j = Option::<UintRef>::decode(&mut fields)
            .ok()?
            .map(|j| j.as_bytes());
        if let Some(validation) = Option::<AnyRef>::decode(&mut fields).ok()? {
            if validation.tag() != Tag::Sequence {
                return None;
            }
            let mut values = SliceReader::new(validation.value()).ok()?;
            let seed = BitStringRef::decode(&mut values).ok()?;
            let counter = UintRef::decode(&mut values).ok()?;
            if seed.raw_bytes().is_empty()
                || seed.raw_bytes().len() > MAX_FIELD_BYTES
                || counter.as_bytes().len() > MAX_FIELD_BYTES
            {
                return None;
            }
            values.finish().ok()?;
        }
        fields.finish().ok()?;
        Some(Self { p, g, q, j })
    }
}

fn public_key<'a>(spki: &SubjectPublicKeyInfo<'a>) -> Option<(&'a [u8], Parameters<'a>)> {
    let spki = SubjectPublicKeyInfoRef::from_der(spki.raw).ok()?;
    if !supports(spki.algorithm.oid.as_bytes()) {
        return None;
    }
    let integer = Der::single(spki.subject_public_key.as_bytes()?, INTEGER)?.positive_integer()?;
    Some((integer, Parameters::parse(spki.algorithm.parameters?)?))
}

struct Domain {
    field: BoxedMontyParams,
    field_bytes: usize,
    generator: BoxedUint,
    q: BoxedUint,
    j: BoxedUint,
    subgroup_bits: u32,
}

impl Domain {
    fn parse(parameters: &Parameters<'_>) -> Option<Self> {
        let p_bits = width(parameters.p)?;
        let p = uint(parameters.p, p_bits)?;
        if p.bit_width_vartime() < MIN_FIELD_BITS {
            return None;
        }
        let q = uint(parameters.q, width(parameters.q)?)?;
        let subgroup_bits = q.bit_width_vartime();
        if subgroup_bits < MIN_SUBGROUP_BITS || q >= p {
            return None;
        }
        let g = uint(parameters.g, p_bits)?;
        if !in_range(&g, &p) {
            return None;
        }

        let p_minus_one = &p - BoxedUint::one();
        let (j, remainder) = p_minus_one.div_rem_vartime(&Option::from(NonZero::new(q.clone()))?);
        if !bool::from(remainder.is_zero())
            || j <= BoxedUint::one()
            || !same_cofactor(parameters.j, &j)
            || !is_prime(Flavor::Any, &q)
            || !is_prime(Flavor::Any, &p)
        {
            return None;
        }

        let field = BoxedMontyParams::new_vartime(Option::from(Odd::new(p))?);
        let generator = BoxedMontyForm::new(g.clone(), &field);
        if generator.pow_bounded_exp(&q, subgroup_bits) != BoxedMontyForm::one(&field) {
            return None;
        }
        Some(Self {
            field,
            field_bytes: parameters.p.len(),
            generator: g,
            q,
            j,
            subgroup_bits,
        })
    }

    fn matches(&self, parameters: &Parameters<'_>) -> bool {
        uint(parameters.p, self.field.bits_precision())
            .is_some_and(|p| p == *self.field.modulus().as_ref())
            && uint(parameters.g, self.field.bits_precision()).is_some_and(|g| g == self.generator)
            && uint(parameters.q, self.subgroup_bits).is_some_and(|q| q == self.q)
            && same_cofactor(parameters.j, &self.j)
    }

    fn public_element(&self, bytes: &[u8]) -> Option<BoxedUint> {
        let value = uint(bytes, self.field.bits_precision())?;
        in_range(&value, self.field.modulus().as_ref()).then_some(value)
    }

    fn with_shared<T>(
        &self,
        peer: BoxedUint,
        exponent: &BoxedUint,
        use_secret: impl FnOnce(&[u8]) -> T,
    ) -> Option<T> {
        let peer = BoxedMontyForm::new(peer, &self.field);
        if peer.pow_bounded_exp(&self.q, self.subgroup_bits) != BoxedMontyForm::one(&self.field) {
            return None;
        }
        let shared = Zeroizing::new(peer.pow_bounded_exp(exponent, self.subgroup_bits));
        let shared = Zeroizing::new(shared.retrieve());
        let bytes = Zeroizing::new(shared.to_be_bytes());
        // Keep the leading octets required by RFC 2631, excluding limb-alignment padding.
        Some(use_secret(
            bytes.get(bytes.len().checked_sub(self.field_bytes)?..)?,
        ))
    }
}

fn width(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > MAX_FIELD_BYTES {
        return None;
    }
    u32::try_from(bytes.len()).ok()?.checked_mul(8)
}

fn uint(bytes: &[u8], bit_width: u32) -> Option<BoxedUint> {
    width(bytes)?;
    BoxedUint::from_be_slice(bytes, bit_width).ok()
}

fn same_cofactor(encoded: Option<&[u8]>, expected: &BoxedUint) -> bool {
    encoded.is_none_or(|j| uint(j, expected.bits_precision()).is_some_and(|j| j == *expected))
}

fn in_range(value: &BoxedUint, upper_bound: &BoxedUint) -> bool {
    let one = BoxedUint::one();
    let upper = upper_bound - &one;
    bool::from(value.ct_gt(&one) & value.ct_lt(&upper))
}

pub(super) struct Recipient<'a> {
    public: BoxedUint,
    ukm: Option<[u8; UKM_BYTES]>,
    wrapped: key_wrap::WrappedKey<'a>,
}

impl Recipient<'_> {
    pub(super) fn open(self, key: &Key) -> Option<Zeroizing<Vec<u8>>> {
        key.domain
            .with_shared(self.public, &key.exponent, |shared| {
                let wrap = self.wrapped.algorithm();
                let mut kek = Zeroizing::new([0; 32]);
                let kek = kek.get_mut(..usize::from(wrap.key_bytes()))?;
                derive(shared, self.ukm.as_ref(), wrap.oid(), kek)?;
                self.wrapped.open(kek)
            })?
    }
}

pub(super) fn select<'a>(
    key: &Key,
    rid: &RecipientId,
    entry: Item<'a>,
    budget: &mut usize,
    originators: Certificates<'a>,
) -> Option<Option<Recipient<'a>>> {
    let Some(fields) = super::key_agreement::select(rid, entry, budget)? else {
        return Some(None);
    };
    let mut originator = Ber(fields.originator.data);
    let originator = {
        let choice = originator.read()?;
        originator.finish()?;
        choice
    };
    let (scheme, wrapping) = algorithm(fields.algorithm)?;
    if !matches!(scheme, STATIC_STATIC | EPHEMERAL_STATIC) {
        return None;
    }
    let ukm = fields.ukm;
    let ukm = if let Some(field) = ukm {
        let mut explicit = Ber(field.data);
        let octets = explicit.read()?.octets(OCTETS, UKM_BYTES)?;
        explicit.finish()?;
        Some(<[u8; UKM_BYTES]>::try_from(octets.as_ref()).ok()?)
    } else if scheme == STATIC_STATIC {
        return None;
    } else {
        None
    };

    let public = if scheme == EPHEMERAL_STATIC {
        ephemeral_public(originator, &key.domain)?
    } else {
        let certificate = originators.find(originator)?;
        let usage = certificate.key_usage().ok()?;
        if usage.is_some_and(|usage| !usage.value.key_agreement() || usage.value.decipher_only()) {
            return None;
        }
        let (peer, parameters) = public_key(certificate.public_key())?;
        if !key.domain.matches(&parameters) {
            return None;
        }
        key.domain.public_element(peer)?
    };
    let wrapped = key_wrap::WrappedKey::read(wrapping?, fields.encrypted)?;
    Some(Some(Recipient {
        public,
        ukm,
        wrapped,
    }))
}

fn ephemeral_public(originator: Item<'_>, domain: &Domain) -> Option<BoxedUint> {
    if originator.tag != CONTEXT_1 {
        return None;
    }
    let mut key = Ber(originator.data);
    let (oid, params) = algorithm(key.take(SEQUENCE)?)?;
    if !supports(oid) || params.is_some() {
        return None;
    }

    let bits = key.read()?.byte_aligned_bits(domain.field_bytes + 5)?;
    key.finish()?;
    let public = Der::single(&bits, INTEGER)?.positive_integer()?;
    domain.public_element(public)
}

fn derive(
    shared: &[u8],
    ukm: Option<&[u8; UKM_BYTES]>,
    algorithm_oid: &[u8],
    kek: &mut [u8],
) -> Option<()> {
    // OtherInfo is DER. Its longest supported layout is 97 bytes after the
    // outer header, so every length in the sequence has a short form.
    let oid_bytes = u8::try_from(algorithm_oid.len()).ok()?;
    let info_bytes = oid_bytes.checked_add(8)?;
    let other_bytes = info_bytes.checked_add(if ukm.is_some() { 78 } else { 10 })?;
    if other_bytes >= 128 {
        return None;
    }
    let length = (u32::try_from(kek.len()).ok()?.checked_mul(8)?).to_be_bytes();
    for (counter, block) in (1u32..).zip(kek.chunks_mut(20)) {
        let mut digest = Sha1::new();
        digest.update(shared);
        digest.update([0x30, other_bytes, 0x30, info_bytes, 0x06, oid_bytes]);
        digest.update(algorithm_oid);
        digest.update([0x04, 0x04]);
        digest.update(counter.to_be_bytes());
        if let Some(ukm) = ukm {
            digest.update([0xa0, 0x42, 0x04, 0x40]);
            digest.update(ukm);
        }
        digest.update([0xa2, 0x06, 0x04, 0x04]);
        digest.update(length);
        let mut output = digest.finalize();
        block.copy_from_slice(&output[..block.len()]);
        output.as_mut_slice().zeroize();
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::super::{PdfCertificateRecipient, PdfRecipientContent};
    use super::*;

    const CERTIFICATE: &[u8] = include_bytes!("finite_dh/fixtures/recipient-cert.der");
    const PRIVATE_KEY: &[u8] = include_bytes!("finite_dh/fixtures/recipient-key.der");
    const ORIGINATOR: &[u8] = include_bytes!("finite_dh/fixtures/originator-cert.der");
    const EPHEMERAL: &[u8] = include_bytes!("finite_dh/fixtures/esdh.der");
    const STATIC_EMBEDDED: &[u8] = include_bytes!("finite_dh/fixtures/ssdh.der");
    const STATIC_LOCAL: &[u8] = include_bytes!("finite_dh/fixtures/ssdh-detached.der");
    #[test]
    fn rfc2631_derives_two_blocks_for_tdes_and_includes_rc2_ukm() {
        let zz: [u8; 20] = std::array::from_fn(|i| i as u8);
        let mut tdes = [0; 24];
        assert!(derive(&zz, None, key_wrap::CMS3DES_WRAP_OID, &mut tdes).is_some());
        assert_eq!(
            &tdes,
            b"\xa0\x96\x61\x39\x23\x76\xf7\x04\x4d\x90\x52\xa3\x97\x88\x32\x46\xb6\x7f\x5f\x1e\xf6\x3e\xb5\xfb"
        );
        let pattern = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x01";
        let ukm = std::array::from_fn(|i| pattern[i % pattern.len()]);
        let mut rc2 = [0; 16];
        assert!(derive(&zz, Some(&ukm), key_wrap::RC2_WRAP_OID, &mut rc2).is_some());
        assert_eq!(
            &rc2,
            b"\x48\x95\x0c\x46\xe0\x53\x00\x75\x40\x3c\xce\x72\x88\x96\x04\xe0"
        );
    }

    #[test]
    fn opens_openssl_dhx_cms_with_ephemeral_and_static_originators()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::extraction::Error;
        use x509_parser::prelude::parse_x509_certificate;

        let expected = std::array::from_fn::<_, 20, _>(|i| (i + 1) as u8);
        let matches_payload = |content| {
            matches!(
                content,
                Some(PdfRecipientContent::Document { seed, permissions })
                    if *seed == expected && permissions == [0xff, 0xff, 0xff, 0xc4]
            )
        };

        let recipient = PdfCertificateRecipient::from_der(CERTIFICATE, PRIVATE_KEY)?;
        let authorization = recipient.into_authorization();
        for (envelope, error) in [
            (EPHEMERAL, "unexpected OpenSSL ephemeral-static payload"),
            (
                STATIC_EMBEDDED,
                "unexpected embedded static-originator payload",
            ),
        ] {
            matches_payload(authorization.open(envelope))
                .then_some(())
                .ok_or(error)?;
        }
        authorization
            .open(STATIC_LOCAL)
            .is_none()
            .then_some(())
            .ok_or("accepted a detached static originator without its certificate")?;

        let recipient = PdfCertificateRecipient::from_der(CERTIFICATE, PRIVATE_KEY)?
            .with_originator_der(ORIGINATOR)?;
        let authorization = recipient.into_authorization();
        matches_payload(authorization.open(STATIC_LOCAL))
            .then_some(())
            .ok_or("unexpected detached static-originator payload")?;
        PdfCertificateRecipient::from_der(ORIGINATOR, PRIVATE_KEY)
            .is_err()
            .then_some(())
            .ok_or("accepted a certificate with a mismatching private key")?;

        let (_, certificate) = parse_x509_certificate(CERTIFICATE).map_err(|_| Error::Binding)?;
        let key = Key::parse(certificate.public_key(), PRIVATE_KEY).ok_or(Error::Binding)?;
        // In this group 2 is in range but does not belong to the subgroup.
        let unrelated = key.domain.public_element(&[2]).ok_or(Error::Binding)?;
        key.domain
            .with_shared(unrelated, &key.exponent, |_| ())
            .is_none()
            .then_some(())
            .ok_or("derived a shared value for an unrelated subgroup")?;
        Ok(())
    }
}
