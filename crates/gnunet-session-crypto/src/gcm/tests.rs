//! Standard data, explicit bounds and failed-output tests for GCM12.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Exact NIST and state assertions are the finite cryptographic oracle."
)]
use super::*;
use crate::test_support::hex;
use crate::{
    Prk,
    udp::{BoxView, CONFIRMATION_BYTES, DatagramKey, InitialView, PREFIX_BYTES},
};
use std::vec::Vec;
fn bytes(text: &str) -> Result<Vec<u8>, Error> {
    if !text.len().is_multiple_of(2) {
        return Err(Error::InvalidInput);
    }
    let mut out = Vec::new();
    for i in (0..text.len()).step_by(2) {
        out.push(u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| Error::InvalidInput)?);
    }
    Ok(out)
}
#[test]
fn fifty_literal_nist_gcmvs_vectors_cover_all25_full_and_partial_aad_payload_shapes()
-> Result<(), Error> {
    assert_eq!(super::nist_vectors::VECTORS.len(), 50);
    for &(key, nonce, plain, aad, cipher, tag) in super::nist_vectors::VECTORS {
        let key = Aes256Gcm::from_bytes(hex(key)?);
        let nonce = hex(nonce)?;
        let aad = bytes(aad)?;
        let original = bytes(plain)?;
        let expected = bytes(cipher)?;
        let mut actual = original.clone();
        let actual_tag = key.seal(&nonce, &aad, &mut actual)?;
        assert_eq!(actual, expected);
        assert_eq!(actual_tag, hex(tag)?);
        key.open(&nonce, &aad, &mut actual, &actual_tag)?;
        assert_eq!(actual, original);
    }
    Ok(())
}
#[test]
fn j0_counter_mask_and_inc32_do_not_modify_the_nonce_prefix() {
    let nonce = [0xff; 12];
    let mut counter = j0(&nonce);
    assert_eq!(&counter[..12], &nonce);
    assert_eq!(&counter[12..], &[0, 0, 0, 1]);
    inc32(&mut counter);
    assert_eq!(&counter[..12], &nonce);
    assert_eq!(&counter[12..], &[0, 0, 0, 2]);
    counter[12..].copy_from_slice(&u32::MAX.to_be_bytes());
    inc32(&mut counter);
    assert_eq!(&counter[..12], &nonce);
    assert_eq!(&counter[12..], &[0; 4]);
    assert_eq!(MAX_PLAINTEXT_BYTES, ((u32::MAX as u64) - 1) * 16);
    assert_eq!(
        validate_lengths(MAX_PLAINTEXT_BYTES, MAX_ASSOCIATED_BYTES),
        Ok(())
    );
    assert_eq!(
        validate_lengths(MAX_PLAINTEXT_BYTES + 1, 0),
        Err(Error::TooLarge)
    );
    assert_eq!(
        validate_lengths(0, MAX_ASSOCIATED_BYTES + 1),
        Err(Error::TooLarge)
    );
    assert_eq!(validate_lengths(u64::MAX, 0), Err(Error::TooLarge));
    assert_eq!(validate_lengths(0, u64::MAX), Err(Error::TooLarge));
}
#[test]
fn all_authenticated_domains_reject_before_decryption_and_erase_only_the_range() -> Result<(), Error>
{
    for length in [0, 1, 15, 16, 17, 63, 64, 65, 255, 65535] {
        let plain = std::vec![7;length];
        let key = Aes256Gcm::from_bytes([0x39; 32]);
        let nonce = [11; 12];
        let aad = b"aad\0bytes";
        let mut cipher = plain.clone();
        let tag = key.seal(&nonce, aad, &mut cipher)?;
        for field in 0..5 {
            let mut changed = cipher.clone();
            let mut nonce = nonce;
            let mut aad = aad.to_vec();
            let mut tag = tag;
            match field {
                0 => nonce[0] ^= 1,
                1 => aad[0] ^= 1,
                2 => {
                    if changed.is_empty() {
                        continue;
                    }
                    changed[0] ^= 1;
                }
                3 => tag[15] ^= 1,
                _ => {}
            }
            let wrong_key = Aes256Gcm::from_bytes([0x38; 32]);
            let use_key = if field == 4 { &wrong_key } else { &key };
            assert_eq!(
                use_key.open(&nonce, &aad, &mut changed, &tag),
                Err(Error::Authentication)
            );
            assert!(changed.iter().all(|b| *b == 0));
        }
        key.open(&nonce, aad, &mut cipher, &tag)?;
        assert_eq!(cipher, plain);
    }
    Ok(())
}
#[test]
fn source_udp12_empty_aad_and_box_key_selection_are_separate_from_gcm_tag() -> Result<(), Error> {
    let master = Prk::from_bytes([17; 32]);
    let key = DatagramKey::derive(&master, 1)?;
    let data = b"\0\x08\0\x04data";
    let mut packet = [0xa5; 80];
    let written = key.seal_box(data, &mut packet)?;
    assert_eq!(written, PREFIX_BYTES + data.len());
    assert_eq!(&packet[..32], key.kid());
    assert_eq!(
        BoxView::parse(&packet[..written])?.ciphertext.len(),
        data.len()
    );
    let mut plain = [0xa5; 12];
    assert_eq!(key.open_box(&packet[..written], &mut plain)?, data.len());
    assert_eq!(&plain[..data.len()], data);
    assert_eq!(&plain[data.len()..], &[0xa5; 4]);
    packet[0] ^= 1;
    assert_eq!(
        key.open_box(&packet[..written], &mut plain),
        Err(Error::Authentication)
    );
    assert_eq!(&plain[..data.len()], &[0; 8]);
    // Source does not feed the external KID to gcry_cipher_authenticate.
    // Correctly selected primitive key/tag still authenticate the unchanged
    // body; the independent expected-selector check above performs routing.
    let view = BoxView::parse(&packet[..written])?;
    let mut body = view.ciphertext.to_vec();
    key.open_body(&mut body, view.tag)?;
    assert_eq!(body, data);
    assert_eq!(
        DatagramKey::derive(&master, 0)?.seal_box(data, &mut packet),
        Err(Error::InvalidInput)
    );
    assert!(matches!(BoxView::parse(&[0; 48]), Err(Error::Truncated)));
    Ok(())
}
#[test]
fn initial_enc_prefix_is_not_fake_authenticated_without_the_pending_kem_signature_owner()
-> Result<(), Error> {
    let key = DatagramKey::derive(&Prk::from_bytes([23; 32]), 0)?;
    let enc = [0x39; 32];
    let body = [7; CONFIRMATION_BYTES + 8];
    let mut packet = [0; PREFIX_BYTES + CONFIRMATION_BYTES + 8];
    key.seal_initial_payload(&enc, &body, &mut packet)?;
    let mut out = [0; CONFIRMATION_BYTES + 8];
    let (seen, n) = key.open_initial_payload(&packet, &mut out)?;
    assert_eq!(seen, &enc);
    assert_eq!(n, body.len());
    assert_eq!(out, body);
    packet[0] ^= 1;
    let (changed, n) = key.open_initial_payload(&packet, &mut out)?;
    assert_eq!(n, body.len());
    assert_ne!(changed, &enc);
    assert_eq!(out, body);
    // This is the actual empty-AAD payload contract, not a complete accepted
    // initial handshake. Elligator and purpose-signature checks are separate.
    assert!(matches!(
        InitialView::parse(&packet[..PREFIX_BYTES + CONFIRMATION_BYTES - 1]),
        Err(Error::Truncated)
    ));
    assert_eq!(
        DatagramKey::derive(&Prk::from_bytes([23; 32]), 1)?.seal_initial_payload(
            &enc,
            &body,
            &mut packet
        ),
        Err(Error::InvalidInput)
    );
    Ok(())
}
#[test]
fn udp_prefix_capacity_rejection_is_atomic_and_authenticated_failure_erases_body()
-> Result<(), Error> {
    let key = DatagramKey::derive(&Prk::from_bytes([7; 32]), 1)?;
    let body = [17; 17];
    let mut packet = [0xa5; 70];
    for capacity in 0..65 {
        assert_eq!(
            key.seal_box(&body, &mut packet[..capacity]),
            Err(Error::Capacity)
        );
        assert_eq!(packet, [0xa5; 70]);
    }
    key.seal_box(&body, &mut packet)?;
    assert_eq!(&packet[65..], &[0xa5; 5]);
    let mut out = [0xa5; 25];
    for capacity in 0..17 {
        assert_eq!(
            key.open_box(&packet[..65], &mut out[..capacity]),
            Err(Error::Capacity)
        );
        assert_eq!(out, [0xa5; 25]);
    }
    packet[32] ^= 1;
    assert_eq!(
        key.open_box(&packet[..65], &mut out),
        Err(Error::Authentication)
    );
    assert_eq!(&out[..17], &[0; 17]);
    assert_eq!(&out[17..], &[0xa5; 8]);
    Ok(())
}

#[test]
#[ignore = "Requires fresh exact-source UDP/gcrypt component observations; never counted as a default passing test."]
fn normal_c_gcrypt_and_exact_udp_source_components_accept_actual_rust_ciphertexts()
-> Result<(), std::boxed::Box<dyn std::error::Error>> {
    use std::{fmt::Write, fs, string::String};
    fn fixed<const N: usize>(text: &str) -> Result<[u8; N], Error> {
        bytes(text)?.try_into().map_err(|_| Error::InvalidInput)
    }
    fn raw(text: &str) -> Result<Vec<u8>, Error> {
        if text == "-" {
            Ok(Vec::new())
        } else {
            bytes(text)
        }
    }
    fn encoded(data: &[u8]) -> String {
        if data.is_empty() {
            return String::from("-");
        }
        let mut result = String::new();
        for byte in data {
            result.push_str(&std::format!("{byte:02x}"));
        }
        result
    }
    fn field(out: &mut String, data: &[u8]) {
        out.push(' ');
        out.push_str(&encoded(data));
    }
    let inputs = fs::read_to_string(
        std::env::var_os("GNUNET_GCM_INPUTS").ok_or("missing component inputs")?,
    )?;
    let outputs = fs::read_to_string(
        std::env::var_os("GNUNET_GCM_OUTPUTS").ok_or("missing real C outputs")?,
    )?;
    let inputs: Vec<_> = inputs.lines().collect();
    let outputs: Vec<_> = outputs.lines().collect();
    assert_eq!(inputs.len(), outputs.len());
    assert!(inputs.len() > 200);
    let mut accept = String::new();
    let mut expected = String::new();
    let mut checked = 0;
    for (line, want) in inputs.into_iter().zip(outputs) {
        let v: Vec<_> = line.split_whitespace().collect();
        let mut actual = String::new();
        match v[0] {
            "META" => {
                let meta: Vec<_> = want.split_whitespace().collect();
                assert_eq!(
                    &meta[..12],
                    &[
                        "META", "32", "12", "16", "48", "104", "72", "48", "32", "96", "8", "32"
                    ]
                );
                assert_eq!(meta.len(), 13);
                assert!(!meta[12].is_empty());
                continue;
            }
            "GCM" => {
                let key = Aes256Gcm::from_bytes(fixed(v[1])?);
                let nonce = fixed(v[2])?;
                let aad = raw(v[3])?;
                let plain = raw(v[4])?;
                let mut cipher = plain.clone();
                let tag = key.seal(&nonce, &aad, &mut cipher)?;
                actual.push_str("GCM 1");
                field(&mut actual, &cipher);
                field(&mut actual, &tag);
                assert_eq!(actual, want, "actual C raw GCM: {line}");
                writeln!(
                    &mut accept,
                    "GCM_OPEN {} {} {} {} {}",
                    v[1],
                    v[2],
                    v[3],
                    encoded(&cipher),
                    encoded(&tag)
                )?;
                writeln!(&mut expected, "GCM_OPEN 1 {}", encoded(&plain))?;
                key.open(&nonce, &aad, &mut cipher, &tag)?;
                assert_eq!(cipher, plain);
            }
            "GCM_OPEN" => {
                let key = Aes256Gcm::from_bytes(fixed(v[1])?);
                let nonce = fixed(v[2])?;
                let aad = raw(v[3])?;
                let mut cipher = raw(v[4])?;
                let tag = fixed(v[5])?;
                let result = key.open(&nonce, &aad, &mut cipher, &tag);
                write!(&mut actual, "GCM_OPEN {}", u8::from(result.is_ok()))?;
                if result.is_ok() {
                    field(&mut actual, &cipher);
                } else {
                    assert!(cipher.iter().all(|b| *b == 0));
                }
                assert_eq!(actual, want);
            }
            "UDP" => {
                let master = Prk::from_bytes(fixed(v[1])?);
                let serial = v[2].parse::<u32>()?;
                let plaintext = raw(v[3])?;
                let key = DatagramKey::derive(&master, serial)?;
                let mut cipher = plaintext.clone();
                let tag = key.seal_body(&mut cipher)?;
                let mut rawkey = [0; 32];
                let mut nonce = [0; 12];
                crate::session::udp_key_iv(&master, serial, &mut rawkey, &mut nonce)?;
                assert_eq!(key.nonce(), &nonce);
                let mut packet = std::vec![0;PREFIX_BYTES+plaintext.len()];
                if v[6] == "BOX" {
                    key.seal_box(&plaintext, &mut packet)?;
                } else {
                    key.seal_initial_payload(&fixed(v[7])?, &plaintext, &mut packet)?;
                }
                actual.push_str("UDP 1");
                for data in [
                    rawkey.as_slice(),
                    nonce.as_slice(),
                    key.kid().as_slice(),
                    crate::session::udp_cmac(&master)?.as_slice(),
                    cipher.as_slice(),
                    tag.as_slice(),
                    packet.as_slice(),
                    plaintext.as_slice(),
                ] {
                    field(&mut actual, data);
                }
                assert_eq!(actual, want, "exact-source UDP crypto/layout: {line}");
                writeln!(
                    &mut accept,
                    "UDP_OPEN {} {} {} {}",
                    v[1],
                    v[2],
                    encoded(&cipher),
                    encoded(&tag)
                )?;
                writeln!(&mut expected, "UDP_OPEN 1 {}", encoded(&plaintext))?;
                key.open_body(&mut cipher, &tag)?;
                assert_eq!(cipher, plaintext);
            }
            "UDP_OPEN" => {
                let master = Prk::from_bytes(fixed(v[1])?);
                let key = DatagramKey::derive(&master, v[2].parse::<u32>()?)?;
                let mut cipher = raw(v[3])?;
                let result = key.open_body(&mut cipher, &fixed(v[4])?);
                write!(&mut actual, "UDP_OPEN {}", u8::from(result.is_ok()))?;
                if result.is_ok() {
                    field(&mut actual, &cipher);
                } else {
                    assert!(cipher.iter().all(|b| *b == 0));
                }
                assert_eq!(actual, want);
            }
            _ => return Err("unknown component operation".into()),
        }
        checked += 1;
    }
    assert!(checked > 200);
    assert!(accept.lines().count() > 200);
    let path = std::path::PathBuf::from(
        std::env::var_os("GNUNET_GCM_ACCEPT").ok_or("missing reverse output path")?,
    );
    fs::write(&path, accept)?;
    fs::write(path.with_extension("expected"), expected)?;
    Ok(())
}
