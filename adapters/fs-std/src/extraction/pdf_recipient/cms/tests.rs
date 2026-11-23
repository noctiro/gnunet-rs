use super::{PdfCertificateRecipient, PdfRecipientContent};
use crate::extraction::Error;

// Synthetic OpenSSL certificate, test-only key and independently authored envelopes.
const CERT: &[u8] = include_bytes!("tests/fixtures/rsa-certificate.der");
const KEY: &[u8] = include_bytes!("tests/fixtures/rsa-test-key.der");
const ISSUER_AES128: &[u8] = include_bytes!("tests/fixtures/issuer-aes128.der");
const KEY_ID_OAEP_AES256: &[u8] = include_bytes!("tests/fixtures/key-id-oaep-aes256.der");
const RSA_STREAM_BER: &[u8] = include_bytes!("tests/fixtures/rsa-stream-ber.der");
const CONTENT: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\xff\xff\xf2\xd0";

#[test]
fn opens_rsa_cms_by_issuer_and_key_id() {
    assert_opens(
        CERT,
        KEY,
        &[ISSUER_AES128, KEY_ID_OAEP_AES256, RSA_STREAM_BER],
    );
}

#[test]
fn opens_ecdh_cms_on_each_named_curve() {
    let rsa = PdfCertificateRecipient::from_der(CERT, KEY)
        .map(PdfCertificateRecipient::into_authorization);
    for (cert, key, cms) in [
        (
            include_bytes!("tests/fixtures/ec-256-cert.der").as_slice(),
            include_bytes!("tests/fixtures/ec-256-test-key.der").as_slice(),
            include_bytes!("tests/fixtures/ec-256-cms.der").as_slice(),
        ),
        (
            include_bytes!("tests/fixtures/ec-384-cert.der").as_slice(),
            include_bytes!("tests/fixtures/ec-384-test-key.der").as_slice(),
            include_bytes!("tests/fixtures/ec-384-cms.der").as_slice(),
        ),
        (
            include_bytes!("tests/fixtures/ec-521-cert.der").as_slice(),
            include_bytes!("tests/fixtures/ec-521-test-key.der").as_slice(),
            include_bytes!("tests/fixtures/ec-521-cms.der").as_slice(),
        ),
    ] {
        assert_opens(cert, key, &[cms]);
        assert!(rsa.as_ref().is_ok_and(|rsa| rsa.open(cms).is_none()));
    }
}

#[test]
fn ecdh_binds_restricted_key_and_requires_deciphering_usage() {
    assert_opens(
        include_bytes!("tests/fixtures/ec-256-restricted-cert.der"),
        include_bytes!("tests/fixtures/ec-256-restricted-test-key.der"),
        &[include_bytes!(
            "tests/fixtures/ec-256-wrapped-point-cms.der"
        )],
    );
    assert!(matches!(
        PdfCertificateRecipient::from_der(
            include_bytes!("tests/fixtures/ec-256-encipher-only-cert.der"),
            include_bytes!("tests/fixtures/ec-256-test-key.der"),
        ),
        Err(Error::Binding)
    ));
}

#[test]
fn opens_rfc8418_with_hkdf_and_x963() {
    // OpenSSL ECDH, KDF and AES vectors assembled as RFC 8418 envelopes.
    assert_opens(
        include_bytes!("tests/fixtures/x25519-cert.der"),
        include_bytes!("tests/fixtures/x25519-test-key.der"),
        &[include_bytes!("tests/fixtures/x25519-cms.der")],
    );
    assert_opens(
        include_bytes!("tests/fixtures/x448-cert.der"),
        include_bytes!("tests/fixtures/x448-test-key.der"),
        &[include_bytes!("tests/fixtures/x448-cms.der")],
    );
}

#[test]
fn opens_one_pass_mqv_with_embedded_or_separately_bound_originators() {
    const RECIPIENT: &[u8] = include_bytes!("tests/fixtures/ec-256-cert.der");
    const KEY: &[u8] = include_bytes!("tests/fixtures/ec-256-test-key.der");
    const EMBEDDED: &[u8] = include_bytes!("tests/fixtures/mqv-256-embedded.der");
    const DETACHED: &[u8] = include_bytes!("tests/fixtures/mqv-256-detached.der");
    const ORIGINATOR: &[u8] = include_bytes!("tests/fixtures/mqv-256-originator.der");

    // The sender-side one-pass vectors use OpenSSL EC multiplication,
    // X9.63 derivation and AES independently of the receiving code.
    assert_opens(RECIPIENT, KEY, &[EMBEDDED]);
    assert_opens(
        include_bytes!("tests/fixtures/ec-521-cert.der"),
        include_bytes!("tests/fixtures/ec-521-test-key.der"),
        &[include_bytes!("tests/fixtures/mqv-521-embedded.der")],
    );
    let standalone = PdfCertificateRecipient::from_der(RECIPIENT, KEY)
        .map(PdfCertificateRecipient::into_authorization);
    assert!(
        standalone
            .as_ref()
            .is_ok_and(|authorization| authorization.open(DETACHED).is_none())
    );
    let local = PdfCertificateRecipient::from_der(RECIPIENT, KEY)
        .and_then(|credential| credential.with_originator_der(ORIGINATOR))
        .map(PdfCertificateRecipient::into_authorization);
    assert!(matches!(
        local.as_ref().ok().and_then(|authorization| authorization.open(DETACHED)),
        Some(PdfRecipientContent::Document { seed, permissions })
            if CONTENT.split_at_checked(20) == Some((seed.as_slice(), permissions.as_slice()))
    ));
    assert_ne!(
        standalone.as_ref().ok().map(|value| value.identity()),
        local.as_ref().ok().map(|value| value.identity())
    );
}

#[track_caller]
fn assert_opens(certificate: &[u8], key: &[u8], envelopes: &[&[u8]]) {
    let authorized = PdfCertificateRecipient::from_der(certificate, key)
        .map(PdfCertificateRecipient::into_authorization);
    let Ok(authorized) = authorized else {
        assert!(authorized.is_ok());
        return;
    };
    for envelope in envelopes {
        assert!(matches!(
            authorized.open(envelope),
            Some(PdfRecipientContent::Document { seed, permissions })
                if CONTENT.split_at_checked(20) == Some((seed.as_slice(), permissions.as_slice()))
        ));
        assert!(authorized.open(&envelope[..envelope.len() - 1]).is_none());
    }
}

#[test]
fn credential_import_checks_certificate_and_key_shape() {
    assert!(matches!(
        PdfCertificateRecipient::from_der(KEY, CERT),
        Err(Error::Binding)
    ));
    let mut certificate = CERT.to_vec();
    certificate.push(0);
    assert!(matches!(
        PdfCertificateRecipient::from_der(&certificate, KEY),
        Err(Error::Binding)
    ));
    let mut wrong_key = KEY.to_vec();
    // OpenSSL PKCS#8 has the RSA modulus after the PKCS#1 version.
    wrong_key[64] ^= 1;
    assert!(matches!(
        PdfCertificateRecipient::from_der(CERT, &wrong_key),
        Err(Error::Binding)
    ));
}
