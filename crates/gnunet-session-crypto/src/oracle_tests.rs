//! Independent standard vectors and normal-library fixtures are added here.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Cryptographic standard/vector tests compare exact bytes and rejection erasure."
)]
use crate::test_support::hex;
use crate::{Prk, aead, exchange::*, session};
use gnunet_types::Error;
use std::boxed::Box;
#[test]
fn rfc7748_x25519_and_hchacha_standard_vectors() -> Result<(), Error> {
    let alice = EcdheSecret::from_bytes(hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    )?);
    let bob = EcdheSecret::from_bytes(hex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    )?);
    assert_eq!(
        *alice.public_key().as_bytes(),
        hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")?
    );
    assert_eq!(
        *bob.public_key().as_bytes(),
        hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")?
    );
    assert_eq!(
        *alice.exchange_raw(bob.public_key())?.0,
        hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")?
    );
    assert_eq!(
        *aead::hchacha(
            &hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")?,
            &hex("000000090000004a0000000031415927")?
        ),
        hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")?
    );
    Ok(())
}
#[test]
fn kem_and_cake_chain_and_aead_tamper_are_distinct() -> Result<(), Error> {
    let recipient = EcdheSecret::from_eddsa_seed([9; 32]);
    let ephemeral = EcdheSecret::from_bytes([17; 32]);
    let (enc, shared) = kem_encapsulate(recipient.public_key(), &ephemeral)?;
    let received = kem_decapsulate(&recipient, enc)?;
    assert_eq!(*shared.0, *received.0);
    let (es, _ets) = session::early(&shared, &[0x55; 64])?;
    let hs = session::handshake(&es, &received)?;
    let ms = session::master(&hs, &shared)?;
    let traffic = session::application_traffic(&ms, &[0x33; 64], session::Role::Initiator)?;
    let m = session::record_material(&traffic, 0x0102030405060708)?;
    let mut bytes = *b"native GNUnet bytes";
    let original = bytes;
    let tag = m.seal(b"exact-ad", &mut bytes)?;
    assert_ne!(bytes, original);
    m.open(b"exact-ad", &mut bytes, &tag)?;
    assert_eq!(bytes, original);
    let tag = m.seal(b"exact-ad", &mut bytes)?;
    assert_eq!(
        m.open(b"wrong-ad", &mut bytes, &tag),
        Err(Error::Authentication)
    );
    assert!(bytes.iter().all(|b| *b == 0));
    let mut old = [0; 1];
    crate::kdf::hkdf_gnunet(b"s", b"i", &[], &mut old)?;
    crate::kdf::hkdf256(b"s", b"i", b"", &mut old)?;
    let prk = Prk::from_bytes([1; 32]);
    let mut excessive = [0xa5; 8161];
    assert_eq!(prk.expand(&[], &mut excessive), Err(Error::InvalidInput));
    assert_eq!(excessive, [0; 8161]);
    Ok(())
}
#[test]
#[ignore = "Requires current unmodified normal C utility-library corpus from tools/compare.py; never counted as a default passing oracle."]
fn normal_c_library_vectors() -> Result<(), Box<dyn std::error::Error>> {
    use std::{fmt::Write, fs};
    let input = fs::read_to_string(
        std::env::var_os("GNUNET_SESSION_CRYPTO_CASES").ok_or("missing real C corpus path")?,
    )?;
    let expected = fs::read_to_string(
        std::env::var_os("GNUNET_SESSION_CRYPTO_RESULTS").ok_or("missing real C outputs path")?,
    )?;
    let mut accept = std::string::String::new();
    let mut accept_expected = std::string::String::new();
    let bytes = |s: &str| -> Result<std::vec::Vec<u8>, Box<dyn std::error::Error>> {
        if s == "-" {
            return Ok(std::vec::Vec::new());
        }
        if !s.len().is_multiple_of(2) {
            return Err("odd hex".into());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
            .collect()
    };
    let fixed = |s: &str| -> Result<[u8; 32], Box<dyn std::error::Error>> {
        Ok(bytes(s)?.try_into().map_err(|_| "not32 bytes")?)
    };
    let enc = |b: &[u8]| {
        if b.is_empty() {
            return std::string::String::from("-");
        }
        let mut s = std::string::String::new();
        for byte in b {
            s.push_str(&std::format!("{byte:02x}"));
        }
        s
    };
    let mut count = 0;
    for (line, want) in input.lines().zip(expected.lines()) {
        let v = line.split_whitespace().collect::<std::vec::Vec<_>>();
        let mut actual = std::format!("{} ", v[0]);
        let mut add = |b: &[u8]| {
            actual.push(' ');
            actual.push_str(&enc(b));
        };
        match v[0] {
            "DH" => {
                let secret = EcdheSecret::from_bytes(fixed(v[1])?);
                let peer = EcdhePublic::from_bytes(fixed(v[2])?);
                let raw = secret.exchange_raw(peer);
                let hash = secret.exchange_hashed(peer);
                add(secret.public_key().as_bytes());
                if let (Ok(raw), Ok(hash)) = (&raw, &hash) {
                    add(raw.0.as_ref());
                    add(hash.0.as_ref());
                }
                actual.insert(v[0].len() + 1, if raw.is_ok() { '1' } else { '0' });
            }
            "CONV" => {
                let key = EcdhePublic::from_edwards(&fixed(v[1])?);
                if let Ok(key) = &key {
                    add(key.as_bytes());
                }
                actual.insert(v[0].len() + 1, if key.is_ok() { '1' } else { '0' });
            }
            "ED" | "PKEY" => {
                let seed = fixed(v[1])?;
                let (edwards, secret) = if v[0] == "ED" {
                    (
                        *gnunet_crypto::EddsaPrivateKey::from_seed(seed)
                            .public_key()
                            .as_bytes(),
                        EcdheSecret::from_eddsa_seed(seed),
                    )
                } else {
                    (
                        gnunet_crypto::gns::PkeySecret::from_bytes(seed)?.public_key(),
                        EcdheSecret::from_bytes(seed),
                    )
                };
                let public = EcdhePublic::from_edwards(&edwards)?;
                let peer = EcdheSecret::from_bytes(fixed(v[2])?);
                let left = secret.exchange_hashed(peer.public_key())?;
                let right = peer.exchange_edwards_hashed(&edwards)?;
                add(&edwards);
                add(secret.0.as_ref());
                add(public.as_bytes());
                add(left.0.as_ref());
                add(right.0.as_ref());
                actual.insert(v[0].len() + 1, '1');
            }
            "KEM" | "KEMP" => {
                let e = EcdheSecret::from_bytes(fixed(v[1])?);
                let r = EcdheSecret::from_bytes(fixed(v[2])?);
                let recipient = if v[0] == "KEM" {
                    r.public_key()
                } else {
                    EcdhePublic::from_bytes(fixed(v[2])?)
                };
                let result = kem_encapsulate(recipient, &e);
                if let Ok((encap, ss)) = &result {
                    add(encap.as_bytes());
                    add(ss.0.as_ref());
                    if v[0] == "KEM" {
                        let recv = kem_decapsulate(&r, *encap)?;
                        add(recv.0.as_ref());
                        writeln!(&mut accept, "DECAP {} {}", v[2], enc(encap.as_bytes()))?;
                        writeln!(&mut accept_expected, "DECAP 1 {}", enc(ss.0.as_ref()))?;
                    }
                }
                actual.insert(v[0].len() + 1, if result.is_ok() { '1' } else { '0' });
            }
            "DECAP" => {
                let r = EcdheSecret::from_bytes(fixed(v[1])?);
                let result = kem_decapsulate(&r, EcdhePublic::from_bytes(fixed(v[2])?));
                if let Ok(ss) = &result {
                    add(ss.0.as_ref());
                }
                actual.insert(v[0].len() + 1, if result.is_ok() { '1' } else { '0' });
            }
            "EDKEM" => {
                let seed = fixed(v[1])?;
                let recipient = EcdheSecret::from_eddsa_seed(seed);
                let fields = want.split_whitespace().collect::<std::vec::Vec<_>>();
                let encap = EcdhePublic::from_bytes(fixed(fields[2])?);
                let ss = kem_decapsulate(&recipient, encap)?;
                add(encap.as_bytes());
                add(ss.0.as_ref());
                add(ss.0.as_ref());
                actual.insert(v[0].len() + 1, '1');
                let ephemeral = EcdheSecret::from_bytes([83; 32]);
                let (sent, derived) = kem_encapsulate(recipient.public_key(), &ephemeral)?;
                writeln!(&mut accept, "EDDECAP {} {}", v[1], enc(sent.as_bytes()))?;
                writeln!(
                    &mut accept_expected,
                    "EDDECAP 1 {}",
                    enc(derived.0.as_ref())
                )?;
            }
            "EDDECAP" => {
                let recipient = EcdheSecret::from_eddsa_seed(fixed(v[1])?);
                let result = kem_decapsulate(&recipient, EcdhePublic::from_bytes(fixed(v[2])?));
                if let Ok(ss) = &result {
                    add(ss.0.as_ref());
                }
                actual.insert(v[0].len() + 1, if result.is_ok() { '1' } else { '0' });
            }
            "DERIVE" => {
                let ikm = bytes(v[1])?;
                let key = EcdheSecret::derive_hpke(&ikm)?;
                add(key.0.as_ref());
                add(key.public_key().as_bytes());
                actual.insert(v[0].len() + 1, '1');
            }
            "HASH" => {
                let message = bytes(v[1])?;
                let mut h = crate::transcript::Hash512State::new();
                h.update(&message[..message.len() / 2]);
                let mut copy = h.clone();
                h.update(&message[message.len() / 2..]);
                for byte in &message[message.len() / 2..] {
                    copy.update(core::slice::from_ref(byte));
                }
                add(&gnunet_crypto::hash512(&message));
                add(&h.finish());
                add(&copy.finish());
                actual.insert(v[0].len() + 1, '1');
            }
            "MAC" => {
                let key = bytes(v[1])?;
                let message = bytes(v[2])?;
                let middle = message.len() / 2;
                add(&crate::transcript::hmac512(
                    &key,
                    &[&message[..middle], &[], &message[middle..]],
                ));
                actual.insert(v[0].len() + 1, '1');
            }
            "PUBKEY" => {
                let public = EcdhePublic::from_bytes(fixed(v[1])?);
                let mut wire = [0; 36];
                public.encode_hpke(&mut wire)?;
                let (decoded, n) = EcdhePublic::decode_hpke(&wire)?;
                assert_eq!(n, 36);
                add(&wire);
                add(decoded.as_bytes());
                actual.insert(v[0].len() + 1, '1');
            }
            "HKDF" => {
                let salt = bytes(v[1])?;
                let ikm = bytes(v[2])?;
                let info = bytes(v[3])?;
                let n: usize = v[4].parse()?;
                let p = crate::hkdf_extract(&salt, &[&ikm]);
                let mut out = std::vec![0xa5;n];
                let result = p.expand(&[&info], &mut out);
                add(p.0.as_ref());
                if result.is_ok() {
                    add(&out);
                } else {
                    assert_eq!(out, std::vec![0;n]);
                }
                actual.insert(v[0].len() + 1, if result.is_ok() { '1' } else { '0' });
            }
            "AEAD" | "CHACHA12" => {
                let key = fixed(v[1])?;
                let nonce = bytes(v[2])?;
                let aad = bytes(v[3])?;
                let original = bytes(v[4])?;
                let mut ciphertext = original.clone();
                let tag = if v[0] == "AEAD" {
                    aead::xchacha20poly1305_seal(
                        &key,
                        nonce.as_slice().try_into()?,
                        &aad,
                        &mut ciphertext,
                    )?
                } else {
                    aead::chacha20poly1305_seal(
                        &key,
                        nonce.as_slice().try_into()?,
                        &aad,
                        &mut ciphertext,
                    )?
                };
                add(&ciphertext);
                add(&tag);
                actual.insert(v[0].len() + 1, '1');
                if v[0] == "AEAD" {
                    writeln!(
                        &mut accept,
                        "OPEN {} {} {} {} {}",
                        v[1],
                        v[2],
                        v[3],
                        enc(&ciphertext),
                        enc(&tag)
                    )?;
                    writeln!(&mut accept_expected, "OPEN 1 {}", enc(&original))?;
                    aead::xchacha20poly1305_open(
                        &key,
                        nonce.as_slice().try_into()?,
                        &aad,
                        &mut ciphertext,
                        &tag,
                    )?;
                    assert_eq!(ciphertext, original);
                }
            }
            "OPEN" => {
                let key = fixed(v[1])?;
                let nonce = bytes(v[2])?;
                let aad = bytes(v[3])?;
                let mut ciphertext = bytes(v[4])?;
                let tag = bytes(v[5])?;
                let result = aead::xchacha20poly1305_open(
                    &key,
                    nonce.as_slice().try_into()?,
                    &aad,
                    &mut ciphertext,
                    tag.as_slice().try_into()?,
                );
                if result.is_ok() {
                    add(&ciphertext);
                } else {
                    assert!(ciphertext.iter().all(|b| *b == 0));
                }
                actual.insert(v[0].len() + 1, if result.is_ok() { '1' } else { '0' });
            }
            "CAKE" => {
                let r = Prk::from_bytes(fixed(v[1])?);
                let e = Prk::from_bytes(fixed(v[2])?);
                let i = Prk::from_bytes(fixed(v[3])?);
                let transcript: [u8; 64] = bytes(v[4])?.try_into().map_err(|_| "bad transcript")?;
                let seq: u64 = v[5].parse()?;
                let (es, ets) = session::early(&r, &transcript)?;
                let hs = session::handshake(&es, &e)?;
                let ihts = session::handshake_traffic(&hs, &transcript, session::Role::Initiator)?;
                let rhts = session::handshake_traffic(&hs, &transcript, session::Role::Responder)?;
                let ms = session::master(&hs, &i)?;
                let iats =
                    session::application_traffic(&ms, &transcript, session::Role::Initiator)?;
                let rats =
                    session::application_traffic(&ms, &transcript, session::Role::Responder)?;
                let next = session::next_application(&iats)?;
                for key in [&es, &ets, &hs, &ihts, &rhts, &ms, &iats, &rats, &next] {
                    add(key.0.as_ref());
                }
                add(&session::finished(
                    &ms,
                    &transcript,
                    session::Role::Initiator,
                )?);
                add(&session::finished(
                    &ms,
                    &transcript,
                    session::Role::Responder,
                )?);
                let chosen = if v[6] == "r" { &rats } else { &iats };
                let material = session::record_material(chosen, seq)?;
                add(material.key.as_ref());
                add(material.nonce());
                let mut mask = [0; 8];
                session::sequence_protection(chosen, &mut mask)?;
                add(&mask);
                actual.insert(v[0].len() + 1, '1');
            }
            "SEQ" => {
                let p = Prk::from_bytes(fixed(v[1])?);
                let tag: [u8; 16] = bytes(v[2])?.try_into().map_err(|_| "tag length")?;
                let seq: u64 = v[3].parse()?;
                let mut key = [0; 32];
                session::sequence_protection(&p, &mut key)?;
                let masked = session::protect_sequence(&p, &tag, &seq.to_be_bytes())?;
                add(&key);
                add(&masked);
                assert_eq!(
                    session::protect_sequence(&p, &tag, &masked)?,
                    seq.to_be_bytes()
                );
                actual.insert(v[0].len() + 1, '1');
            }
            "TCP" => {
                let p = Prk::from_bytes(fixed(v[1])?);
                let original = bytes(v[2])?;
                let m = session::tcp_material(&p)?;
                add(m.key.as_ref());
                add(m.counter.as_ref());
                add(m.hmac.as_ref());
                let mut stream = m.into_stream();
                let mut ciphertext = original.clone();
                for chunk in ciphertext.chunks_mut(7) {
                    stream.crypt(chunk)?;
                }
                add(&ciphertext);
                add(&stream.hmac(&[&original]));
                actual.insert(v[0].len() + 1, '1');
            }
            "UDP" => {
                let p = Prk::from_bytes(fixed(v[1])?);
                let serial: u32 = v[2].parse()?;
                let mut key = [0; 32];
                let mut iv = [0; session::UDP_IV_BYTES];
                session::udp_key_iv(&p, serial, &mut key, &mut iv)?;
                add(&key);
                add(&iv);
                add(&session::udp_key_id(&p, serial)?);
                add(&session::udp_cmac(&p)?);
                actual.insert(v[0].len() + 1, '1');
            }
            _ => return Err("unsupported fixture operation".into()),
        }
        assert_eq!(
            actual.trim_end(),
            want,
            "real normal C case {}: {}",
            count,
            line
        );
        count += 1;
    }
    assert_eq!(count, input.lines().count());
    assert_eq!(count, expected.lines().count());
    assert!(count > 100);
    if let Some(path) = std::env::var_os("GNUNET_SESSION_CRYPTO_ACCEPT") {
        fs::write(&path, accept)?;
        fs::write(
            std::path::PathBuf::from(path).with_extension("expected"),
            accept_expected,
        )?;
    }
    Ok(())
}
#[test]
fn low_order_and_off_subgroup_inputs_never_return_secret_owners() -> Result<(), Error> {
    use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};
    let secret = EcdheSecret::from_bytes([7; 32]);
    for point in EIGHT_TORSION {
        assert!(EcdhePublic::from_edwards(&point.compress().to_bytes()).is_err());
    }
    for (index, point) in EIGHT_TORSION.iter().enumerate() {
        let mixed = (ED25519_BASEPOINT_POINT + point).compress().to_bytes();
        assert_eq!(EcdhePublic::from_edwards(&mixed).is_ok(), index == 0);
    }
    for value in [
        [0; 32],
        {
            let mut b = [0; 32];
            b[0] = 1;
            b
        },
        {
            let mut b = [0xff; 32];
            b[0] = 0xec;
            b[31] = 0x7f;
            b
        },
        {
            let mut b = [0xff; 32];
            b[0] = 0xed;
            b[31] = 0x7f;
            b
        },
        {
            let mut b = [0xff; 32];
            b[0] = 0xee;
            b[31] = 0x7f;
            b
        },
    ] {
        for high in [0, 128] {
            let mut bytes = value;
            bytes[31] ^= high;
            assert!(secret.exchange_raw(EcdhePublic::from_bytes(bytes)).is_err());
            assert!(kem_encapsulate(EcdhePublic::from_bytes(bytes), &secret).is_err());
        }
    }
    Ok(())
}
#[test]
fn entropy_failure_erases_partial_seed_and_hpke_generation_draws_exact64_bytes() -> Result<(), Error>
{
    struct Source {
        fail: bool,
        lengths: std::vec::Vec<usize>,
    }
    impl gnunet_crypto::Entropy for Source {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
            self.lengths.push(out.len());
            out.fill(7);
            if self.fail { Err(Error::Io) } else { Ok(()) }
        }
    }
    let mut source = Source {
        fail: true,
        lengths: std::vec::Vec::new(),
    };
    let mut partial = [0xa5; 32];
    assert_eq!(
        crate::exchange::fill_secret(&mut source, &mut partial),
        Err(Error::Entropy)
    );
    assert_eq!(partial, [0; 32]);
    assert!(EcdheSecret::generate(&mut source).is_err());
    assert!(EcdheSecret::generate_hpke(&mut source).is_err());
    source.fail = false;
    let raw = EcdheSecret::generate(&mut source)?;
    assert_eq!(*raw.0, [7; 32]);
    let hpke = EcdheSecret::generate_hpke(&mut source)?;
    let derived = EcdheSecret::derive_hpke(&[7; 64])?;
    assert_eq!(*hpke.0, *derived.0);
    assert_eq!(source.lengths, std::vec![32, 32, 64, 32, 64]);
    let mut erased = raw;
    use zeroize::Zeroize;
    erased.0.zeroize();
    assert_eq!(*erased.0, [0; 32]);
    Ok(())
}
#[test]
fn hpke_public_codec_capacity_is_atomic_and_keytype_is_not_private_negotiation() -> Result<(), Error>
{
    let key = EcdheSecret::from_bytes([3; 32]).public_key();
    for n in 0..36 {
        let mut bytes = [0xa5; 37];
        assert_eq!(key.encode_hpke(&mut bytes[..n]), Err(Error::Capacity));
        assert_eq!(bytes, [0xa5; 37]);
    }
    let mut bytes = [0xa5; 37];
    assert_eq!(key.encode_hpke(&mut bytes)?, 36);
    assert_eq!(bytes[36], 0xa5);
    let (parsed, n) = EcdhePublic::decode_hpke(&bytes)?;
    assert_eq!((parsed, n), (key, 36));
    for n in 0..36 {
        assert!(EcdhePublic::decode_hpke(&bytes[..n]).is_err());
    }
    bytes[3] = 1;
    assert_eq!(EcdhePublic::decode_hpke(&bytes), Err(Error::Unsupported));
    Ok(())
}
#[test]
fn every_aead_boundary_authenticates_before_decryption_and_erases_tampered_ranges()
-> Result<(), Error> {
    let key = [0x31; 32];
    let nonce = [0x73; 24];
    for n in [0, 1, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 129] {
        for a in [0, 1, 15, 16, 17, 33] {
            let original = std::vec![0x5c;n];
            let ad = std::vec![0xa5;a];
            let mut ciphertext = original.clone();
            let tag = aead::xchacha20poly1305_seal(&key, &nonce, &ad, &mut ciphertext)?;
            let mut valid = ciphertext.clone();
            aead::xchacha20poly1305_open(&key, &nonce, &ad, &mut valid, &tag)?;
            assert_eq!(valid, original);
            for field in 0..5 {
                let mut k = key;
                let mut iv = nonce;
                let mut aad = ad.clone();
                let mut ct = ciphertext.clone();
                let mut mac = tag;
                match field {
                    0 => k[0] ^= 1,
                    1 => iv[0] ^= 1,
                    2 => aad.push(1),
                    3 => {
                        if ct.is_empty() {
                            ct.push(1);
                        } else {
                            ct[0] ^= 1;
                        }
                    }
                    _ => mac[0] ^= 1,
                }
                assert_eq!(
                    aead::xchacha20poly1305_open(&k, &iv, &aad, &mut ct, &mac),
                    Err(Error::Authentication)
                );
                assert!(ct.iter().all(|b| *b == 0));
            }
        }
    }
    Ok(())
}
#[test]
fn record_sequence_xor_and_tcp_partial_stream_positions_match_source_rules() -> Result<(), Error> {
    let secret = Prk::from_bytes([9; 32]);
    let zero = session::record_material(&secret, 0)?;
    for seq in [1, 255, 256, 65535, 1 << 32, u64::MAX] {
        let material = session::record_material(&secret, seq)?;
        assert_eq!(zero.key.as_ref(), material.key.as_ref());
        assert_eq!(&zero.nonce()[..16], &material.nonce()[..16]);
        for i in 0..8 {
            assert_eq!(
                zero.nonce()[16 + i] ^ material.nonce()[16 + i],
                seq.to_be_bytes()[i]
            );
        }
    }
    let plain = std::vec![0x55;257];
    let mut together = plain.clone();
    session::tcp_material(&secret)?
        .into_stream()
        .crypt(&mut together)?;
    for chunk in [1, 7, 15, 16, 17, 63, 64, 65, 128] {
        let mut split = plain.clone();
        let mut stream = session::tcp_material(&secret)?.into_stream();
        for part in split.chunks_mut(chunk) {
            stream.crypt(part)?;
        }
        assert_eq!(split, together);
    }
    let mut key0 = [0; 32];
    let mut key1 = [0; 32];
    let mut iv0 = [0; session::UDP_IV_BYTES];
    let mut iv1 = [0; session::UDP_IV_BYTES];
    session::udp_key_iv(&secret, 0, &mut key0, &mut iv0)?;
    session::udp_key_iv(&secret, 1, &mut key1, &mut iv1)?;
    assert_ne!(key0, key1);
    assert_ne!(iv0, iv1);
    Ok(())
}

#[test]
fn cake_records_authenticate_sequence_and_payload_and_counter_preflight_is_exact()
-> Result<(), Error> {
    let p = Prk::from_bytes([0xa3; 32]);
    for seq in [0, 1, 255, 256, 1 << 32, u64::MAX] {
        let mut data = *b"official empty AAD";
        let plain = data;
        let (tag, number) = session::seal_record(&p, seq, &mut data)?;
        let ct = data;
        assert_eq!(session::open_record(&p, &tag, &number, &mut data)?, seq);
        assert_eq!(data, plain);
        let mut bad = number;
        bad[7] ^= 1;
        data = ct;
        assert_eq!(
            session::open_record(&p, &tag, &bad, &mut data),
            Err(Error::Authentication)
        );
        assert_eq!(data, [0; 18]);
    }
    if let Ok(max) = usize::try_from(aead::MAX_PLAINTEXT_BYTES) {
        assert_eq!(aead::preflight(max, 0), Ok(()));
        if let Some(over) = max.checked_add(1) {
            assert_eq!(aead::preflight(over, 0), Err(Error::TooLarge));
        }
    }
    Ok(())
}
