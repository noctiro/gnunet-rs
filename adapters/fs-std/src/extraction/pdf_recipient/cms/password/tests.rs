use super::{CONTEXT_0, *};

const VECTOR_PASSWORD: &[u8] = b"gnunet-test-passphrase";
const VECTOR_SEED: [u8; 20] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
];

fn expected_seed(content: Option<PdfRecipientContent>) -> bool {
    matches!(
        content,
        Some(PdfRecipientContent::Document { seed, permissions })
            if *seed == VECTOR_SEED && permissions == [0xff, 0xff, 0xf2, 0xd0]
    )
}

fn check(condition: bool, message: &'static str) -> Result<(), &'static str> {
    condition.then_some(()).ok_or(message)
}

#[test]
fn opens_aes_and_triple_des_password_recipients() -> Result<(), &'static str> {
    let credential = PdfPasswordRecipient::from_password([0x19; 32], VECTOR_PASSWORD)
        .map_err(|_| "valid credential refused")?
        .into_authorization();
    let wrong = PdfPasswordRecipient::from_password([0x29; 32], b"wrong password")
        .map_err(|_| "valid credential refused")?
        .into_authorization();
    check(
        credential.identity() == &[0x19; 32],
        "public credential identity mismatch",
    )?;

    // OpenSSL generated and decrypted both full CMS envelopes.
    for cms in [
        include_bytes!("fixtures/openssl-aes256.der").as_slice(),
        include_bytes!("fixtures/openssl-tdes.der").as_slice(),
    ] {
        check(expected_seed(credential.open(cms)), "CMS seed mismatch")?;
        check(wrong.open(cms).is_none(), "wrong password accepted")?;
        check(
            credential.open(&cms[..cms.len() - 1]).is_none(),
            "truncated envelope accepted",
        )?;
    }
    Ok(())
}

#[test]
fn tries_a_later_password_recipient_within_the_envelope() -> Result<(), &'static str> {
    let credential = PdfPasswordRecipient::from_password([7; 32], VECTOR_PASSWORD)
        .map_err(|_| "valid credential refused")?;
    // The first recipient has the original DER fields and a damaged wrapped
    // key. The second recipient retains the OpenSSL-issued content key.
    let cms = include_bytes!("fixtures/openssl-aes256-second-recipient.der");
    check(
        expected_seed(credential.open(cms)),
        "valid later recipient skipped",
    )
}

#[test]
fn a_prederived_key_requires_absence_of_derivation_parameters() -> Result<(), &'static str> {
    let raw = b"\x06\xa7\x86\x54\x15\xe1\xea\x7b\xd1\x14\x55\x7a\xa6\x59\x49\x65\xc0\xe5\x99\x46\x8c\x6a\xd6\xcc\xa1\x5d\xcb\xac\x5b\x2e\x75\x33";
    let direct = PdfPasswordRecipient::from_wrapping_key([0x13; 32], raw)
        .map_err(|_| "valid raw key refused")?;
    let password = PdfPasswordRecipient::from_password([0x16; 32], VECTOR_PASSWORD)
        .map_err(|_| "valid credential refused")?;
    // Same OpenSSL wrapping and payload bytes with the optional KDF removed.
    let external = include_bytes!("fixtures/openssl-aes256-out-of-band.der");
    let original = include_bytes!("fixtures/openssl-aes256.der");
    check(
        expected_seed(direct.open(external)),
        "raw-key CMS seed mismatch",
    )?;
    check(
        direct.open(original).is_none(),
        "raw key accepted the PBKDF2 entry",
    )?;
    check(
        password.open(external).is_none(),
        "password accepted the raw-key entry",
    )
}

#[test]
fn pbkdf2_counts_each_digest_block_and_honors_an_explicit_prf() -> Result<(), &'static str> {
    const SHA1: &[u8] = b"\xa0\x1a\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c\x30\x0d\x04\x08\x12\x34\x56\x78\x78\x56\x34\x12\x02\x01\x05";
    const SHA256: &[u8] = b"\xa0\x2b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c\x30\x1e\x04\x08\x12\x34\x56\x78\x78\x56\x34\x12\x02\x01\x05\x02\x01\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x09\x05\x00";
    let mut output = [0; 32];
    let work = Cell::new(9);
    let sha1_item = Ber(SHA1).take(CONTEXT_0).ok_or("default parameter tag")?;
    let sha1 = Pbkdf2::parse(sha1_item, output.len()).ok_or("default PRF")?;
    check(
        sha1.derive(b"password", &work, &mut output).is_none(),
        "budget overrun accepted",
    )?;
    check(work.get() == 9, "refused attempt changed work budget")?;

    work.set(15);
    sha1.derive(b"password", &work, &mut output)
        .ok_or("SHA-1 derivation")?;
    check(work.get() == 5, "SHA-1 work accounting mismatch")?;
    check(
        &output == b"\xd1\xda\xa7\x86\x15\xf2\x87\xe6\xa1\xc8\xb1\x20\xd7\x06\x2a\x49\x3f\x98\xd2\x03\xe6\xbe\x49\xa6\xad\xf4\xfa\x57\x4b\x6e\x64\xee",
        "SHA-1 output mismatch",
    )?;

    let sha256_item = Ber(SHA256)
        .take(CONTEXT_0)
        .ok_or("explicit parameter tag")?;
    check(
        Pbkdf2::parse(sha256_item, 24).is_none(),
        "wrong explicit key length accepted",
    )?;
    let sha256 = Pbkdf2::parse(sha256_item, output.len()).ok_or("explicit PRF")?;
    sha256
        .derive(b"password", &work, &mut output)
        .ok_or("SHA-256 derivation")?;
    check(work.get() == 0, "SHA-256 work accounting mismatch")?;
    check(
        &output == b"\x74\xe9\x8b\x2e\x9e\xed\xda\xab\x31\x13\xc1\xef\xc6\xd8\x2b\x07\x3c\x48\x60\x19\x5b\x3e\x07\x37\xfa\x21\xa4\x77\x8f\x37\x63\x21",
        "SHA-256 output mismatch",
    )
}

#[test]
fn unwraps_the_rfc3211_single_des_vector() -> Result<(), &'static str> {
    // RFC 3211 §3 generated the full vector with PBKDF2-HMAC-SHA-1.
    const WRAP: &[u8] = b"\x30\x20\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\x09\x30\x11\x06\x05\x2b\x0e\x03\x02\x07\x04\x08\xef\xe5\x98\xef\x21\xb3\x3d\x6d";
    const CIPHERTEXT: &[u8] =
        b"\x04\x10\xb8\x1b\x25\x65\xee\x37\x3c\xa6\xde\xdc\xa2\x6a\x17\x8b\x0c\x10";
    let algorithm = Ber(WRAP).read().ok_or("wrap algorithm")?;
    let ciphertext = Ber(CIPHERTEXT).read().ok_or("ciphertext")?;
    let wrap = wrap::Key::parse(algorithm, ciphertext).ok_or("DES wrap")?;
    let key = wrap
        .open(b"\xd1\xda\xa7\x86\x15\xf2\x87\xe6")
        .ok_or("DES unwrap")?;
    check(
        key.as_slice() == b"\x8c\x62\x7c\x89\x73\x23\xa2\xf8",
        "DES output mismatch",
    )
}
