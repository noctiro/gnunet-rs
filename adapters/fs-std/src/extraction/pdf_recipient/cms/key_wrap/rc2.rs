//! CMS RC2 key wrapping (RFC 3217 §4).

use ::rc2::Rc2;
use zeroize::Zeroizing;

use super::{Rc2Version, cbc_unwrap, checksum_matches};

pub(super) const MAX_WRAPPED_BYTES: usize = 272;

pub(super) fn admits_wrapped_bytes(length: usize) -> bool {
    (24..=MAX_WRAPPED_BYTES).contains(&length) && length.is_multiple_of(8)
}

pub(super) fn unwrap(
    kek: &[u8; 16],
    version: Rc2Version,
    encoded: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    let cipher = Rc2::new_with_eff_key_len(kek, version.effective_bits());
    let mut bytes = Zeroizing::new(encoded.to_vec());
    let (key_and_padding, checksum) = cbc_unwrap(&cipher, &mut bytes)?.split_last_chunk::<8>()?;
    if !bool::from(checksum_matches(key_and_padding, checksum)) {
        return None;
    }
    let (&size, key_and_padding) = key_and_padding.split_first()?;
    let (key, padding) = key_and_padding.split_at_checked(usize::from(size))?;
    (!key.is_empty() && padding.len() < 8).then(|| Zeroizing::new(key.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::super::super::Ber;
    use super::super::{Algorithm, WrappedKey};
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn rfc3217_wrap_uses_the_signaled_rc2_effective_key_size() {
        let kek = b"\xfd\x04\xfd\x08\x06\x07\x07\xfb\x00\x03\xfe\xff\xfd\x02\xfe\x05";
        // RFC 3217 erratum 639 identifies the original vector as 40 bits
        // and supplies a vector for the same 16-byte KEK at 128 bits.
        let forty = b"\x70\xe6\x99\xfb\x57\x01\xf7\x83\x33\x30\xfb\x71\xe8\x7c\x85\xa4\x20\xbd\xc9\x9a\xf0\x5d\x22\xaf\x5a\x0e\x48\xd3\x5f\x31\x38\x98\x6c\xba\xaf\xb4\xb2\x8d\x4f\x35";
        let one_twenty_eight = b"\xf4\xd8\x02\x1c\x1e\xa4\x63\xd2\x17\xa9\xeb\x69\x29\xff\xa5\x77\x36\xd3\xe2\x03\x86\xc9\x09\x93\x83\x5b\x4b\xe4\xad\x8d\x8a\x1b\xc6\x3b\x25\xde\x2b\xf7\x79\x93";
        let expected = b"\xb7\x0a\x25\xfb\xc9\xd8\x6a\x86\x05\x0c\xe0\xd7\x11\xea\xd4\xd9";
        for (version, bytes) in [
            (Rc2Version::Bits40, forty),
            (Rc2Version::Bits128, one_twenty_eight),
        ] {
            let algorithm = Algorithm::Rc2(version);
            let identifier = Ber(algorithm.key_info()).read();
            let parsed = identifier.and_then(|item| WrappedKey::parse(item, Cow::Borrowed(bytes)));
            assert!(
                parsed
                    .as_ref()
                    .is_some_and(|key| key.algorithm() == algorithm)
            );
            assert_eq!(
                parsed
                    .and_then(|key| key.open(kek))
                    .as_deref()
                    .map(Vec::as_slice),
                Some(expected.as_slice())
            );
            let mut changed = *bytes;
            changed[12] ^= 1;
            assert!(unwrap(kek, version, &changed).is_none());
        }
    }
}
