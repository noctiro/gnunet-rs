//! CMS issuer matching across BER wrappers of an X.509 Name.

use super::{Ber, Item, OID, SEQUENCE, SET, asn1::valid_oid};

/// Match the ordered sequence of unordered RDNs. Attribute values use their
/// exact ASN.1 identifiers and contents. The certificate owns the expected
/// issuer Name, which the credential admission has already parsed.
pub(super) fn matches(candidate: Item<'_>, certificate_name: &[u8]) -> Option<bool> {
    if candidate.tag != SEQUENCE || candidate.data.is_empty() {
        return None;
    }
    if candidate.encoded == certificate_name {
        return Some(true);
    }

    // The CMS envelope and certificate each bound the borrowed input. Reuse
    // scratch storage proportional to the largest single RDN in each Name.
    let mut candidate_name = Ber(candidate.data);
    let mut expected_name = Ber::sequence(certificate_name)?;
    let mut candidate_values = Vec::new();
    let mut expected_values = Vec::new();
    let mut equal = true;
    while !candidate_name.0.is_empty() {
        rdn(candidate_name.take(SET)?, &mut candidate_values)?;
        if expected_name.0.is_empty() {
            equal = false;
            continue;
        }
        rdn(expected_name.take(SET)?, &mut expected_values)?;
        if equal && candidate_values.len() == expected_values.len() {
            candidate_values.sort_unstable();
            expected_values.sort_unstable();
            equal = candidate_values == expected_values;
        } else {
            equal = false;
        }
    }
    Some(equal && expected_name.finish().is_some())
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Attribute<'a> {
    oid: &'a [u8],
    identifier: &'a [u8],
    value: &'a [u8],
}

fn rdn<'a>(item: Item<'a>, attributes: &mut Vec<Attribute<'a>>) -> Option<()> {
    attributes.clear();
    let mut rdn = Ber(item.data);
    while !rdn.0.is_empty() {
        let mut field = Ber(rdn.take(SEQUENCE)?.data);
        let oid = field.take(OID)?.data;
        if !valid_oid(oid) {
            return None;
        }
        let value = field.read()?;
        field.finish()?;
        attributes.try_reserve(1).ok()?;
        attributes.push(Attribute {
            oid,
            identifier: identifier(value)?,
            value: value.data,
        });
    }
    (!attributes.is_empty()).then_some(())
}

fn identifier(item: Item<'_>) -> Option<&[u8]> {
    let width = if item.tag & 0x1f == 0x1f {
        2 + item
            .encoded
            .get(1..)?
            .iter()
            .position(|&byte| byte & 0x80 == 0)?
    } else {
        1
    };
    item.encoded.get(..width)
}

#[cfg(test)]
mod tests {
    use super::{Ber, matches};

    // The first RDN has a commonName and an organizationName, and the
    // second RDN has a commonName. RDN order is significant.
    const DER: &[u8] = b"\x30\x22\x31\x14\x30\x08\x06\x03\x55\x04\x03\x0c\x01x\
        \x30\x08\x06\x03\x55\x04\x0a\x0c\x01y\x31\x0a\x30\x08\x06\x03\x55\x04\x03\x0c\x01z";
    const BER: &[u8] = b"\x30\x80\x31\x80\x30\x80\x06\x81\x03\x55\x04\x0a\x0c\x81\x01y\
        \x00\x00\x30\x08\x06\x03\x55\x04\x03\x0c\x01x\x00\x00\
        \x31\x0a\x30\x08\x06\x03\x55\x04\x03\x0c\x01z\x00\x00";

    fn compare(candidate: &[u8], expected: &[u8]) -> Option<bool> {
        let mut input = Ber(candidate);
        let candidate = input.read()?;
        input.finish()?;
        matches(candidate, expected)
    }

    #[test]
    fn compares_ber_name_structure_and_unordered_rdn_members() {
        assert_eq!(compare(DER, DER), Some(true));
        assert_eq!(compare(BER, DER), Some(true));

        let mut other = DER.to_vec();
        other[13] = b'w';
        assert_eq!(compare(BER, &other), Some(false));
        let mut reversed = DER[..2].to_vec();
        reversed.extend_from_slice(&DER[24..]);
        reversed.extend_from_slice(&DER[2..24]);
        assert_eq!(compare(BER, &reversed), Some(false));
    }

    #[test]
    fn checks_attribute_framing_oids_and_full_identifiers() {
        let mut invalid = DER.to_vec();
        invalid[8] = 0x80;
        assert_eq!(compare(&invalid, DER), None);
        let mut invalid_tail = DER.to_vec();
        invalid_tail[13] = b'w';
        invalid_tail[25] = 0;
        assert_eq!(compare(&invalid_tail, DER), None);
        assert_eq!(compare(b"\x30\x02\x31\x00", DER), None);

        let tagged = b"\x30\x0d\x31\x0b\x30\x09\x06\x03\x55\x04\x03\x9f\x1f\x01x";
        let mut other_identifier = tagged.to_vec();
        other_identifier[12] = 0x20;
        assert_eq!(compare(&other_identifier, tagged), Some(false));
    }
}
