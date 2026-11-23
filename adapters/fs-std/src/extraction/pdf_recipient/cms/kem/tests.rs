use crate::extraction::{PdfCertificateRecipient, PdfRecipientContent};

const CERT_512: &[u8] = include_bytes!("../tests/fixtures/mlkem-512-cert.der");
const KEY_512: &[u8] = include_bytes!("../tests/fixtures/mlkem-512-test-key.der");
const CMS_512: &[u8] = include_bytes!("../tests/fixtures/mlkem-512-cms.der");
const CERT_768: &[u8] = include_bytes!("../tests/fixtures/mlkem-768-cert.der");
const KEY_768: &[u8] = include_bytes!("../tests/fixtures/mlkem-768-test-key.der");
const CMS_768: &[u8] = include_bytes!("../tests/fixtures/mlkem-768-cms.der");
const CERT_1024: &[u8] = include_bytes!("../tests/fixtures/mlkem-1024-cert.der");
const KEY_1024: &[u8] = include_bytes!("../tests/fixtures/mlkem-1024-test-key.der");
const CMS_1024: &[u8] = include_bytes!("../tests/fixtures/mlkem-1024-cms.der");

#[test]
fn opens_all_openssl_ml_kem_parameter_sets_and_private_key_forms() {
    // OpenSSL produced the issuer-and-serial (512), key identifier and UKM
    // (768), and streamed BER (1024) envelopes. Its imported private keys
    // are the RFC 9935 seed, expanded and both formats respectively.
    for (cert, private, cms) in [
        (CERT_512, KEY_512, CMS_512),
        (CERT_768, KEY_768, CMS_768),
        (CERT_1024, KEY_1024, CMS_1024),
    ] {
        let credential = PdfCertificateRecipient::from_der(cert, private)
            .map(PdfCertificateRecipient::into_authorization);
        let Ok(credential) = credential else {
            assert!(credential.is_ok(), "ML-KEM credential import failed");
            return;
        };
        assert!(matches!(
            credential.open(cms),
            Some(PdfRecipientContent::Document { seed, permissions })
                if seed.iter().copied().eq(0u8..20) && permissions == [0xff, 0xff, 0xf2, 0xd0]
        ));
        assert!(credential.open(&cms[..cms.len() - 1]).is_none());
    }
}

#[test]
fn requires_matching_ml_kem_certificate_and_consistent_private_fields() {
    assert!(PdfCertificateRecipient::from_der(CERT_512, KEY_768).is_err());

    let mut dual_form = KEY_1024.to_vec();
    let Some(last) = dual_form.last_mut() else {
        return;
    };
    *last ^= 1;
    assert!(PdfCertificateRecipient::from_der(CERT_1024, &dual_form).is_err());

    let mut expanded = KEY_768.to_vec();
    // The final 32 bytes are z, immediately after the 32-byte public-key hash.
    let size = expanded.len();
    expanded[size - 33] ^= 1;
    assert!(PdfCertificateRecipient::from_der(CERT_768, &expanded).is_err());
}

#[test]
fn requires_exact_kek_length_and_refuses_modification_to_kem_ciphertext() {
    let credential = PdfCertificateRecipient::from_der(CERT_512, KEY_512)
        .map(PdfCertificateRecipient::into_authorization);
    let Ok(credential) = credential else {
        assert!(credential.is_ok(), "ML-KEM credential import failed");
        return;
    };

    let mut wrong_length = CMS_512.to_vec();
    let kek_length = b"\x03\x1c\x02\x01\x10";
    let length_index = wrong_length
        .windows(kek_length.len())
        .position(|window| window == kek_length)
        .map(|start| start + kek_length.len() - 1);
    let Some(length_index) = length_index else {
        assert!(
            length_index.is_some(),
            "expected RFC 9936 HKDF and KEK length"
        );
        return;
    };
    wrong_length[length_index] += 1;
    assert!(credential.open(&wrong_length).is_none());

    let mut tampered = CMS_512.to_vec();
    let ciphertext_header = b"\x04\x82\x03\x00";
    let ciphertext_index = tampered
        .windows(ciphertext_header.len())
        .position(|window| window == ciphertext_header)
        .map(|start| start + ciphertext_header.len());
    let Some(ciphertext_index) = ciphertext_index else {
        assert!(
            ciphertext_index.is_some(),
            "expected 768-byte ML-KEM ciphertext"
        );
        return;
    };
    tampered[ciphertext_index] ^= 1;
    assert!(credential.open(&tampered).is_none());
}
