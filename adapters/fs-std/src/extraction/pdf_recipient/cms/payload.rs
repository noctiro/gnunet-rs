//! Content ciphers for CMS-encoded PDF recipient seeds.

use aes::cipher::{Block, BlockCipherDecrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use des::{Des, TdesEde2, TdesEde3};
use rc2::Rc2;
use std::borrow::Cow;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

use super::super::super::pdf_rc4;
use super::{Ber, INTEGER, Item, OCTETS, PdfRecipientContent, SEQUENCE};

const AES128_CBC: &[u8] = b"\x60\x86\x48\x01\x65\x03\x04\x01\x02";
const AES192_CBC: &[u8] = b"\x60\x86\x48\x01\x65\x03\x04\x01\x16";
const AES256_CBC: &[u8] = b"\x60\x86\x48\x01\x65\x03\x04\x01\x2a";
const DES_CBC: &[u8] = b"\x2b\x0e\x03\x02\x07";
const TDES_CBC: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x03\x07";
const RC2_CBC: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x03\x02";
const RC4: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x03\x04";

const SEED_BYTES: usize = 20;
const SEED_AND_PERMISSIONS_BYTES: usize = 24;
const PLAINTEXT_WIDTHS: [usize; 2] = [SEED_BYTES, SEED_AND_PERMISSIONS_BYTES];
const MAX_CIPHERTEXT_BYTES: usize = 32;

pub(super) fn decrypt(
    oid: &[u8],
    params: Option<Item<'_>>,
    key: &[u8],
    body: &[u8],
) -> Option<PdfRecipientContent> {
    match oid {
        AES128_CBC => decrypt_pkcs7::<Aes128>(params, key, body),
        AES192_CBC => decrypt_pkcs7::<Aes192>(params, key, body),
        AES256_CBC => decrypt_pkcs7::<Aes256>(params, key, body),
        DES_CBC => decrypt_pkcs7::<Des>(params, key, body),
        TDES_CBC => match key.len() {
            16 => decrypt_pkcs7::<TdesEde2>(params, key, body),
            24 => decrypt_pkcs7::<TdesEde3>(params, key, body),
            _ => None,
        },
        RC2_CBC => {
            let (effective_bits, iv) = rc2_parameters(params?)?;
            if !(1..=128).contains(&key.len()) {
                return None;
            }
            decrypt_cbc(&Rc2::new_with_eff_key_len(key, effective_bits), &iv, body)
        }
        RC4 => {
            if params.is_some_and(|param| param.tag != 0x05 || !param.data.is_empty())
                || !(1..=256).contains(&key.len())
                || !PLAINTEXT_WIDTHS.contains(&body.len())
            {
                return None;
            }
            let mut plaintext = Zeroizing::new([0; SEED_AND_PERMISSIONS_BYTES]);
            let plaintext = plaintext.get_mut(..body.len())?;
            plaintext.copy_from_slice(body);
            pdf_rc4::apply(plaintext, key);
            PdfRecipientContent::from_bytes(plaintext)
        }
        _ => None,
    }
}

fn decrypt_pkcs7<C: BlockCipherDecrypt + KeyInit>(
    params: Option<Item<'_>>,
    key: &[u8],
    body: &[u8],
) -> Option<PdfRecipientContent> {
    let iv = params?.octets(OCTETS, 16)?;
    decrypt_cbc(&C::new_from_slice(key).ok()?, &iv, body)
}

fn decrypt_cbc<C: BlockCipherDecrypt>(
    cipher: &C,
    iv: &[u8],
    body: &[u8],
) -> Option<PdfRecipientContent> {
    let iv: &Block<C> = iv.try_into().ok()?;
    let width = iv.len();
    if !matches!(width, 8 | 16)
        || !PLAINTEXT_WIDTHS
            .iter()
            .any(|length| body.len() == (length + 1).next_multiple_of(width))
    {
        return None;
    }
    let mut plaintext = Zeroizing::new([0; MAX_CIPHERTEXT_BYTES]);
    let plaintext = plaintext.get_mut(..body.len())?;
    let mut previous = iv.as_slice();
    for (ciphertext, block) in body
        .chunks_exact(width)
        .zip(plaintext.chunks_exact_mut(width))
    {
        cipher.decrypt_block_b2b(ciphertext.try_into().ok()?, (&mut *block).try_into().ok()?);
        for (byte, previous) in block.iter_mut().zip(previous) {
            *byte ^= previous;
        }
        previous = ciphertext;
    }

    // RFC 5652 §6.3. Test the complete suffix at both permitted plaintext widths.
    let seed = padding_matches(plaintext, SEED_BYTES, width);
    let seed_and_permissions = padding_matches(plaintext, SEED_AND_PERMISSIONS_BYTES, width);
    let length = if bool::from(seed) {
        SEED_BYTES
    } else if bool::from(seed_and_permissions) {
        SEED_AND_PERMISSIONS_BYTES
    } else {
        return None;
    };
    PdfRecipientContent::from_bytes(&plaintext[..length])
}

fn padding_matches(plaintext: &[u8], content_bytes: usize, width: usize) -> Choice {
    let Some(padding) = plaintext.get(content_bytes..) else {
        return Choice::from(0);
    };
    if !(1..=width).contains(&padding.len()) {
        return Choice::from(0);
    }
    padding.ct_eq(&[padding.len() as u8; 16][..padding.len()])
}

fn rc2_parameters(params: Item<'_>) -> Option<(usize, Cow<'_, [u8]>)> {
    // RFC 3370 §5.2 uses SEQUENCE { version, iv }. RFC 2268 §6 and
    // PKCS #5 also allow the version to be omitted for 32 effective key bits.
    let (bits, iv) = if params.tag == SEQUENCE {
        let mut sequence = Ber(params.data);
        let first = sequence.read()?;
        let parameters = if first.tag == INTEGER {
            (rc2_effective_bits(first.uint()?)?, sequence.read()?)
        } else {
            (32, first)
        };
        sequence.finish()?;
        parameters
    } else {
        (32, params)
    };
    let iv = iv.octets(OCTETS, 8)?;
    (iv.len() == 8).then_some((bits, iv))
}

fn rc2_effective_bits(version: u64) -> Option<usize> {
    match version {
        0..=255 => RC2_VERSIONS
            .iter()
            .position(|&found| u64::from(found) == version)
            .filter(|&bits| bits != 0),
        256..=1024 => usize::try_from(version).ok(),
        _ => None,
    }
}

// RFC 2268 §6 maps effective key bits to an RC2ParameterVersion.
const RC2_VERSIONS: [u8; 256] = [
    0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
    0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
    0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
    0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
    0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17, 0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
    0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
    0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
    0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
    0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
    0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
    0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
    0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
    0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
    0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97, 0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
    0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
    0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,
];

#[cfg(test)]
mod tests {
    use super::{
        AES192_CBC, Ber, DES_CBC, PdfRecipientContent, RC2_CBC, RC4, TDES_CBC, decrypt,
        rc2_effective_bits,
    };

    const SEED: &[u8; 20] = b"01234567890123456789";
    const SEED_AND_PERMISSIONS: &[u8; 24] = b"01234567890123456789PDF!";
    const IV8: &[u8] = b"\x04\x08\x01\x01\x01\x01\x01\x01\x01\x01";
    const IV16: &[u8] = b"\x04\x10\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
    const RC2_PARAMS: &[u8] = b"\x30\x0d\x02\x01\x3a\x04\x08\x01\x01\x01\x01\x01\x01\x01\x01";
    const AES192_KEY: [u8; 24] = [2; 24];
    const AES192_BODY: &[u8; 32] = b"\x20\xbc\x3e\x38\x2e\x47\xbf\x9a\x4e\x22\xd5\x24\xe8\x39\x65\x35\
                                      \x36\x2d\xc9\x75\xf9\x6c\xfb\xd8\x85\x8e\x64\x9a\x77\x16\x97\x4e";

    fn matches_content(content: Option<PdfRecipientContent>, expected: &[u8]) -> bool {
        match content {
            Some(PdfRecipientContent::Document { seed, permissions }) => {
                expected.split_at_checked(20) == Some((seed.as_slice(), permissions.as_slice()))
            }
            Some(PdfRecipientContent::Stream(seed)) => seed.as_slice() == expected,
            None => false,
        }
    }

    #[test]
    fn cms_cbc_decrypts_openssl_vectors_at_both_payload_widths() {
        let keys = *b"\x01\x02\x03\x04\x05\x06\x07\x08\x11\x12\x13\x14\x15\x16\x17\x18\x21\x22\x23\x24\x25\x26\x27\x28";
        let fixtures: [(_, _, &[u8], &[u8], &[u8]); 5] = [
            (AES192_CBC, IV16, &AES192_KEY, AES192_BODY, SEED_AND_PERMISSIONS),
            (DES_CBC, IV8, &keys[..8], b"\xc9\x1a\x58\x02\x0d\x6e\x22\x3d\x11\x19\x25\xd2\x27\xd7\x4d\xee\x50\xf8\x17\x09\xee\x7c\xfd\xfe", SEED),
            (TDES_CBC, IV8, &keys[..16], b"\x0b\xf1\xc1\xa8\xa1\x88\x3e\x92\xad\x68\x5c\xd5\x92\x9f\x27\x35\x1b\xe0\x1d\x30\x53\xfe\xd2\x8a", SEED),
            (TDES_CBC, IV8, &keys, b"\x3c\x16\x69\x7d\xf5\xbd\x05\x78\x86\xb3\x3f\x86\x04\x40\xa7\xe5\x53\x9f\xdb\x0f\x9b\x44\x3c\xe0", SEED),
            (RC2_CBC, RC2_PARAMS, b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", b"\x41\x00\x87\xcb\x9a\xc0\xcb\xb5\xc4\xc5\xd7\xad\xc7\xad\x44\x43\x9a\xcb\x86\x6a\xe9\x90\xc2\x58\xd0\xa7\xaf\x53\xe8\x84\x2f\xdc", SEED_AND_PERMISSIONS),
        ];
        for (algorithm, params, key, body, expected) in fixtures {
            let result = decrypt(algorithm, Ber(params).read(), key, body);
            assert!(matches_content(result, expected));
        }
    }

    #[test]
    fn cms_cbc_rejects_inexact_padding_and_unsupported_geometry() {
        let mut damaged = *AES192_BODY;
        // CBC flips the corresponding byte in the final plaintext block.
        // The last padding byte remains valid, but the interior one changes.
        damaged[12] ^= 1;
        assert!(decrypt(AES192_CBC, Ber(IV16).read(), &AES192_KEY, &damaged).is_none());
        assert!(decrypt(AES192_CBC, Ber(IV8).read(), &AES192_KEY, AES192_BODY).is_none());
        assert!(decrypt(AES192_CBC, Ber(IV16).read(), &AES192_KEY, &[0; 48]).is_none());
        assert!(decrypt(AES192_CBC, Ber(IV16).read(), &[0; 16], AES192_BODY).is_none());
    }

    #[test]
    fn cms_rc2_decodes_parameter_versions_and_rc4_uses_its_unpadded_width() {
        for (version, bits) in [(160, 40), (120, 64), (58, 128), (0, 93), (1024, 1024)] {
            assert_eq!(rc2_effective_bits(version), Some(bits));
        }
        assert_eq!(rc2_effective_bits(0xbd), None);
        assert_eq!(rc2_effective_bits(1025), None);

        // RFC 6229 §2, the first 20 octets of the 40-bit keystream.
        let key = [1, 2, 3, 4, 5];
        let result = decrypt(RC4, Ber(b"\x05\0").read(), &key, &[0; 20]);
        assert!(matches_content(
            result,
            b"\xb2\x39\x63\x05\xf0\x3d\xc0\x27\xcc\xc3\x52\x4a\x0a\x11\x18\xa8\x69\x82\x94\x4f",
        ));
        assert!(decrypt(RC4, Ber(IV8).read(), &key, &[0; 20]).is_none());
        assert!(decrypt(RC4, None, &key, &[0; 32]).is_none());
    }
}
