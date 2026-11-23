use super::super::{PdfCertificateRecipient, PdfRecipientContent};

const GENERIC_CERT: &[u8] = include_bytes!("../tests/fixtures/rsa-certificate.der");
const GENERIC_KEY: &[u8] = include_bytes!("../tests/fixtures/rsa-test-key.der");
const RESTRICTED_CERT: &[u8] = include_bytes!("../tests/fixtures/rsa-kem-default-cert.der");
const HYBRID_CERT: &[u8] = include_bytes!("../tests/fixtures/rsa-kem-hybrid-cert.der");
const HYBRID_KEY: &[u8] = include_bytes!("../tests/fixtures/rsa-kem-hybrid-key.der");
const OAEP_CERT: &[u8] = include_bytes!("../tests/fixtures/rsa-oaep-restricted-cert.der");
const CURRENT: &[u8] = include_bytes!("../tests/fixtures/rsa-kem-default-envelope.der");
const HYBRID: &[u8] = include_bytes!("../tests/fixtures/rsa-kem-hybrid-envelope.der");
const LEGACY: &[u8] = include_bytes!("../tests/fixtures/rsa-kem-legacy-envelope.der");

fn expected(content: Option<PdfRecipientContent>) -> bool {
    let expected: [u8; 20] = std::array::from_fn(|index| index as u8);
    matches!(
        content,
        Some(PdfRecipientContent::Document { seed, permissions })
            if *seed == expected && permissions == [0xff, 0xff, 0xf2, 0xd0]
    )
}

#[test]
fn opens_rfc9690_ori_and_rfc5990_ktri_with_the_rsa_kem_credential()
-> Result<(), Box<dyn std::error::Error>> {
    // OpenSSL 4.1 produced the RSASVE, KDF, wrap and ciphertext components.
    let automatic =
        PdfCertificateRecipient::from_der(RESTRICTED_CERT, GENERIC_KEY)?.into_authorization();
    let explicit =
        PdfCertificateRecipient::from_rsa_kem_der(GENERIC_CERT, GENERIC_KEY)?.into_authorization();
    let transport =
        PdfCertificateRecipient::from_der(GENERIC_CERT, GENERIC_KEY)?.into_authorization();
    for envelope in [CURRENT, HYBRID, LEGACY] {
        if !expected(automatic.open(envelope)) || !expected(explicit.open(envelope)) {
            return Err("RSA-KEM credential did not open the expected CMS payload".into());
        }
        if transport.open(envelope).is_some() {
            return Err("RSA transport credential accepted an RSA-KEM envelope".into());
        }
    }
    if transport.identity() == explicit.identity() {
        return Err("credential identity omitted the selected RSA mode".into());
    }
    if PdfCertificateRecipient::from_rsa_kem_der(OAEP_CERT, GENERIC_KEY).is_ok() {
        return Err("RSA-KEM accepted an OAEP-only certificate".into());
    }
    Ok(())
}

#[test]
fn enforces_hybrid_parameters_from_either_side_of_the_key_binding()
-> Result<(), Box<dyn std::error::Error>> {
    for (certificate, private_key) in [
        (HYBRID_CERT, GENERIC_KEY),
        (GENERIC_CERT, HYBRID_KEY),
        (HYBRID_CERT, HYBRID_KEY),
    ] {
        let bound =
            PdfCertificateRecipient::from_der(certificate, private_key)?.into_authorization();
        if !expected(bound.open(HYBRID)) {
            return Err("hybrid restriction rejected its matching key wrapping profile".into());
        }
        if bound.open(CURRENT).is_some() || bound.open(LEGACY).is_some() {
            return Err("hybrid restriction accepted an incompatible wrapping profile".into());
        }
    }
    let bound = PdfCertificateRecipient::from_der(GENERIC_CERT, HYBRID_KEY)?.into_authorization();
    let unrestricted =
        PdfCertificateRecipient::from_rsa_kem_der(GENERIC_CERT, GENERIC_KEY)?.into_authorization();
    if bound.identity() == unrestricted.identity() {
        return Err("credential identity omitted the effective hybrid restriction".into());
    }
    Ok(())
}

#[test]
fn rejects_an_out_of_range_fixed_width_ciphertext() -> Result<(), Box<dyn std::error::Error>> {
    let bound =
        PdfCertificateRecipient::from_der(RESTRICTED_CERT, GENERIC_KEY)?.into_authorization();
    let mut envelope = CURRENT.to_vec();
    let offset = envelope
        .windows(4)
        .position(|window| window == b"\x04\x82\x01\x00")
        .ok_or("RSA ciphertext field was absent")?
        + 4;
    envelope
        .get_mut(offset..offset + 256)
        .ok_or("RSA ciphertext field was truncated")?
        .fill(0xff);
    if bound.open(&envelope).is_some() {
        return Err("accepted a representative larger than the RSA modulus".into());
    }
    Ok(())
}
