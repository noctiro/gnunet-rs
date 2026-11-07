//! Actual context-state regressions, not another primitive-only wrapper test.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Exact context state and error-path assertions form the source-derived tests."
)]
use super::*;
use crate::{
    exchange::{EcdhePublic, EcdheSecret},
    test_support::hex,
};
fn pair(parameters: &Parameters<'_>) -> Result<(Context, Context), Error> {
    let sk_r = EcdheSecret::from_bytes([5; 32]);
    let sk_e = EcdheSecret::from_bytes([7; 32]);
    let (enc, s) = sender_setup2(&sk_e, None, sk_r.public_key(), parameters)?;
    Ok((s, receiver_setup2(enc, &sk_r, None, parameters)?))
}
#[test]
fn rfc9180_context_base_key_nonce_and_256_sequential_operations() -> Result<(), Error> {
    let sk_e = EcdheSecret::derive_hpke(&hex::<32>(
        "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
    )?)?;
    let sk_r = EcdheSecret::from_bytes(hex(
        "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb",
    )?);
    let info = hex::<20>("4f6465206f6e2061204772656369616e2055726e")?;
    let (enc, mut sender) =
        sender_setup2(&sk_e, None, sk_r.public_key(), &Parameters::base(&info))?;
    let mut receiver = receiver_setup(enc, &sk_r, &info)?;
    assert_eq!(
        *enc.as_bytes(),
        hex("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a")?
    );
    assert_eq!(
        *sender.key,
        hex("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91")?
    );
    assert_eq!(sender.base_nonce, hex("5c4d98150661b848853b547f")?);
    let plaintext = hex::<29>("4265617574792069732074727574682c20747275746820626561757479")?;
    for sequence in 0..=255 {
        let aad = std::format!("Count-{sequence}").into_bytes();
        let mut ct = [0; 45];
        let mut pt = [0; 29];
        assert_eq!(sender.seal(&aad, &plaintext, &mut ct)?, 45);
        if sequence == 0 {
            assert_eq!(
                ct,
                hex(
                    "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
                )?
            );
        }
        if sequence == 1 {
            assert_eq!(
                ct,
                hex(
                    "6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c"
                )?
            );
        }
        if sequence == 255 {
            assert_eq!(
                ct,
                hex(
                    "18ab939d63ddec9f6ac2b60d61d36a7375d2070c9b683861110757062c52b8880a5f6b3936da9cd6c23ef2a95c"
                )?
            );
        }
        assert_eq!(receiver.open(&aad, &ct, &mut pt)?, 29);
        assert_eq!(pt, plaintext);
        assert_eq!(sender.sequence(), sequence + 1);
        assert_eq!(receiver.sequence_be(), (sequence + 1).to_be_bytes());
    }
    Ok(())
}
#[test]
fn psk_presence_rules_auth_modes_and_distinct_suite_entries_are_explicit() -> Result<(), Error> {
    for mode in [Mode::Base, Mode::Psk, Mode::Auth, Mode::AuthPsk] {
        for psk in [b"".as_slice(), b"secret\0key".as_slice()] {
            for id in [b"".as_slice(), b"identifier\0".as_slice()] {
                let parameters = Parameters {
                    kem: Kem::X25519,
                    mode,
                    info: b"info\0context",
                    psk,
                    psk_id: id,
                };
                let result = pair(&parameters);
                let expected = (mode == Mode::Base && psk.is_empty() && id.is_empty())
                    || (mode == Mode::Psk && !psk.is_empty() && !id.is_empty());
                assert_eq!(result.is_ok(), expected);
            }
        }
    }
    assert!(matches!(
        pair(&Parameters {
            kem: Kem::X25519Elligator,
            ..Parameters::base(b"")
        }),
        Err(Error::Unsupported)
    ));
    assert_eq!(Mode::try_from(4), Err(Error::Unsupported));
    assert_eq!(Kem::try_from(0x21), Err(Error::Unsupported));
    Ok(())
}
#[test]
fn role_and_capacity_refusal_are_atomic_and_do_not_advance() -> Result<(), Error> {
    let (mut sender, mut receiver) = pair(&Parameters::base(b"capacity"))?;
    let mut bytes = [0xa5; 40];
    assert_eq!(
        receiver.seal(b"", b"plaintext", &mut bytes),
        Err(Error::InvalidInput)
    );
    assert_eq!(bytes, [0xa5; 40]);
    assert_eq!(
        sender.open(b"", &[0; 25], &mut bytes),
        Err(Error::InvalidInput)
    );
    assert_eq!(bytes, [0xa5; 40]);
    for cap in 0..25 {
        assert_eq!(
            sender.seal(b"", b"plaintext", &mut bytes[..cap]),
            Err(Error::Capacity)
        );
        assert_eq!(bytes, [0xa5; 40]);
    }
    let mut ct = [0; 25];
    sender.seal(b"", b"plaintext", &mut ct)?;
    for cap in 0..9 {
        assert_eq!(
            receiver.open(b"", &ct, &mut bytes[..cap]),
            Err(Error::Capacity)
        );
        assert_eq!(bytes, [0xa5; 40]);
    }
    for short in 0..16 {
        assert_eq!(
            receiver.open(b"", &ct[..short], &mut bytes),
            Err(Error::Truncated)
        );
        assert_eq!(bytes, [0xa5; 40]);
    }
    assert_eq!(receiver.sequence(), 0);
    assert_eq!(sender.sequence(), 1);
    receiver.open(b"", &ct, &mut bytes)?;
    assert_eq!(&bytes[..9], b"plaintext");
    assert_eq!(&bytes[9..], &[0xa5; 31]);
    Ok(())
}
#[test]
fn failed_authentication_erases_plaintext_and_can_retry_same_sequence() -> Result<(), Error> {
    let parameters = Parameters {
        kem: Kem::X25519,
        mode: Mode::Psk,
        info: b"info\0",
        psk: b"secret",
        psk_id: b"key-id",
    };
    let (mut sender, mut receiver) = pair(&parameters)?;
    let mut ciphertext = [0; 23];
    sender.seal(b"aad\0", b"message", &mut ciphertext)?;
    for field in 0..3 {
        let mut changed = ciphertext;
        let aad = if field == 0 {
            b"bad\0".as_slice()
        } else {
            b"aad\0".as_slice()
        };
        if field == 1 {
            changed[0] ^= 1;
        }
        if field == 2 {
            changed[22] ^= 1;
        }
        let mut output = [0xa5; 10];
        assert_eq!(
            receiver.open(aad, &changed, &mut output),
            Err(Error::Authentication)
        );
        assert_eq!(&output[..7], &[0; 7]);
        assert_eq!(&output[7..], &[0xa5; 3]);
        assert_eq!(receiver.sequence(), 0);
    }
    let mut output = [0; 7];
    receiver.open(b"aad\0", &ciphertext, &mut output)?;
    assert_eq!(&output, b"message");
    assert_eq!(receiver.sequence(), 1);
    Ok(())
}
#[test]
fn in_place_and_separate_operations_have_identical_bytes_and_tail_ownership() -> Result<(), Error> {
    for len in [0, 1, 15, 16, 17, 63, 64, 65, 255] {
        let (mut separate_s, mut separate_r) = pair(&Parameters::base(b"in-place"))?;
        let (mut inplace_s, mut inplace_r) = pair(&Parameters::base(b"in-place"))?;
        let mut plain = [7; 255];
        for (i, byte) in plain.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let mut separate = [0xa5; 280];
        let mut inplace = [0xa5; 280];
        inplace[..len].copy_from_slice(&plain[..len]);
        assert_eq!(
            separate_s.seal(b"a", &plain[..len], &mut separate)?,
            len + 16
        );
        assert_eq!(inplace_s.seal_in_place(b"a", &mut inplace, len)?, len + 16);
        assert_eq!(inplace, separate);
        let mut out = [0xa5; 280];
        assert_eq!(separate_r.open(b"a", &separate[..len + 16], &mut out)?, len);
        assert_eq!(inplace_r.open_in_place(b"a", &mut inplace, len + 16)?, len);
        assert_eq!(&inplace[..len], &out[..len]);
        assert_eq!(&inplace[len..], &separate[len..]);
    }
    Ok(())
}
#[test]
fn sequence_nbo_carries_and_exhaustion_never_release_failed_output() -> Result<(), Error> {
    for sequence in [
        255,
        256,
        u32::MAX as u64,
        (u32::MAX as u64) + 1,
        u64::MAX - 1,
    ] {
        let (mut sender, mut receiver) = pair(&Parameters::base(b"seq"))?;
        sender.sequence = sequence;
        receiver.sequence = sequence;
        assert_eq!(sender.sequence_be(), sequence.to_be_bytes());
        let mut nonce = sender.base_nonce;
        for (b, s) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
            *b ^= s;
        }
        assert_eq!(sender.nonce(), nonce);
        let mut ct = [0; 19];
        let mut out = [0; 3];
        sender.seal(b"", b"seq", &mut ct)?;
        receiver.open(b"", &ct, &mut out)?;
        assert_eq!(&out, b"seq");
        assert_eq!(sender.sequence(), sequence + 1);
        assert_eq!(receiver.sequence(), sequence + 1);
    }
    let (mut sender, mut receiver) = pair(&Parameters::base(b"limit"))?;
    sender.sequence = u64::MAX;
    receiver.sequence = u64::MAX;
    let mut failed = [0xa5; 20];
    assert_eq!(sender.seal(b"", b"seq", &mut failed), Err(Error::TooLarge));
    assert_eq!(&failed[..19], &[0; 19]);
    assert_eq!(failed[19], 0xa5);
    assert_eq!(sender.sequence(), u64::MAX);
    // Generate a valid sequenceMAX ciphertext with the primitive, rather than
    // treating any failed C/Rust seal output as a valid message.
    let mut ciphertext = *b"seq";
    let tag = aead::chacha20poly1305_seal(&sender.key, &sender.nonce(), b"", &mut ciphertext)?;
    let mut full = [0; 19];
    full[..3].copy_from_slice(&ciphertext);
    full[3..].copy_from_slice(&tag);
    let mut out = [0xa5; 5];
    assert_eq!(receiver.open(b"", &full, &mut out), Err(Error::TooLarge));
    assert_eq!(&out[..3], &[0; 3]);
    assert_eq!(&out[3..], &[0xa5; 2]);
    assert_eq!(receiver.sequence(), u64::MAX);
    full[18] ^= 1;
    assert_eq!(
        receiver.open(b"", &full, &mut out),
        Err(Error::Authentication)
    );
    assert_eq!(receiver.sequence(), u64::MAX);
    Ok(())
}
#[test]
fn oneshot_lengths_explicit_entropy_and_safe_short_input_contracts() -> Result<(), Error> {
    struct Source {
        draws: usize,
        fail: bool,
    }
    impl Entropy for Source {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
            assert_eq!(out.len(), 32);
            self.draws += 1;
            out.fill(7);
            if self.fail {
                Err(Error::Entropy)
            } else {
                Ok(())
            }
        }
    }
    let recipient = EcdheSecret::from_bytes([5; 32]);
    let mut source = Source {
        draws: 0,
        fail: false,
    };
    let mut full = [0xa5; 56];
    let lengths = seal_oneshot(
        recipient.public_key(),
        b"info",
        b"aad",
        b"payload",
        &mut full,
        &mut source,
    )?;
    assert_eq!(
        lengths,
        OneshotLengths {
            total_written: 55,
            c_reported_ciphertext_len: 23
        }
    );
    assert_eq!(source.draws, 1);
    assert_eq!(full[55], 0xa5);
    let mut pt = [0; 7];
    open_oneshot(&recipient, b"info", b"aad", &full[..55], &mut pt)?;
    assert_eq!(&pt, b"payload");
    for len in 0..48 {
        let mut unchanged = [0xa5; 10];
        assert_eq!(
            open_oneshot(&recipient, b"", b"", &full[..len], &mut unchanged),
            Err(Error::Truncated)
        );
        assert_eq!(unchanged, [0xa5; 10]);
    }
    let mut small = [0xa5; 54];
    assert_eq!(
        seal_oneshot(
            recipient.public_key(),
            b"info",
            b"aad",
            b"payload",
            &mut small,
            &mut source
        ),
        Err(Error::Capacity)
    );
    assert_eq!(source.draws, 1);
    assert_eq!(small, [0xa5; 54]);
    source.fail = true;
    let mut unchanged = [0xa5; 55];
    assert_eq!(
        seal_oneshot(
            recipient.public_key(),
            b"info",
            b"aad",
            b"payload",
            &mut unchanged,
            &mut source
        ),
        Err(Error::Entropy)
    );
    assert_eq!(unchanged, [0xa5; 55]);
    assert_eq!(source.draws, 2);
    Ok(())
}
#[test]
fn private_codec_preserves_imported_unclamped_bytes_and_capacity_is_atomic() -> Result<(), Error> {
    let raw = [0xff; 32];
    let secret = EcdheSecret::from_bytes(raw);
    let mut encoded = [0xa5; 39];
    assert_eq!(secret.hpke_encoded_length(), 36);
    secret.encode_hpke_private(&mut encoded)?;
    assert_eq!(&encoded[..4], &[0; 4]);
    assert_eq!(&encoded[4..36], &raw);
    assert_eq!(&encoded[36..], &[0xa5; 3]);
    for len in 0..36 {
        assert!(matches!(
            EcdheSecret::decode_hpke_private(&encoded[..len]),
            Err(Error::Truncated)
        ));
        let mut too_small = [0xa5; 35];
        assert_eq!(
            secret.encode_hpke_private(&mut too_small[..len.min(35)]),
            Err(Error::Capacity)
        );
        assert_eq!(too_small, [0xa5; 35]);
    }
    let (decoded, read) = EcdheSecret::decode_hpke_private(&encoded)?;
    assert_eq!(read, 36);
    let mut again = [0; 36];
    decoded.encode_hpke_private(&mut again)?;
    assert_eq!(&again, &encoded[..36]);
    assert_eq!(decoded.public_key(), secret.public_key());
    decoded.clear();
    encoded[3] = 1;
    assert!(matches!(
        EcdheSecret::decode_hpke_private(&encoded),
        Err(Error::Unsupported)
    ));
    assert_eq!(EcdhePublic::from_bytes([0; 32]).hpke_encoded_length(), 36);
    assert_eq!(seal_length(usize::MAX), Err(Error::Overflow));
    assert_eq!(open_length(15), Err(Error::Truncated));
    Ok(())
}

#[test]
#[ignore = "Requires fresh unchanged normal-C HPKE contexts from tools/hpke_verify.py; absence is never a passing oracle."]
fn normal_c_public_contexts_and_rust_ciphertexts_accepted_by_c()
-> Result<(), std::boxed::Box<dyn std::error::Error>> {
    use std::{fmt::Write, fs, string::String, vec::Vec};
    let cases = fs::read_to_string(std::env::var_os("GNUNET_HPKE_CASES").ok_or("missing cases")?)?;
    let results =
        fs::read_to_string(std::env::var_os("GNUNET_HPKE_RESULTS").ok_or("missing C results")?)?;
    let lines: Vec<_> = cases.lines().collect();
    let expected: Vec<_> = results.lines().collect();
    assert_eq!(lines.len(), expected.len());
    assert!(lines.len() > 30);
    fn raw(text: &str) -> Result<Vec<u8>, std::boxed::Box<dyn std::error::Error>> {
        if text == "-" {
            return Ok(Vec::new());
        }
        if !text.len().is_multiple_of(2) {
            return Err("odd hex".into());
        }
        Ok((0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16))
            .collect::<Result<Vec<_>, _>>()?)
    }
    fn fixed(text: &str) -> Result<[u8; 32], std::boxed::Box<dyn std::error::Error>> {
        raw(text)?.try_into().map_err(|_| "not32".into())
    }
    fn encode(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return String::from("-");
        }
        let mut s = String::new();
        for byte in bytes {
            s.push_str(&std::format!("{byte:02x}"));
        }
        s
    }
    fn add(out: &mut String, bytes: &[u8]) {
        out.push(' ');
        out.push_str(&encode(bytes));
    }
    fn state(out: &mut String, ctx: &Context, role: Role) {
        out.push_str(&std::format!(" {}", role as u8));
        add(out, ctx.key.as_ref());
        add(out, &ctx.base_nonce);
        add(out, &ctx.sequence_be());
        add(out, ctx.exporter.0.as_ref());
    }
    let mut accepted = String::new();
    let mut accepted_results = String::new();
    let mut checked = 0;
    for (line, want) in lines.into_iter().zip(expected) {
        let v: Vec<_> = line.split_whitespace().collect();
        let w: Vec<_> = want.split_whitespace().collect();
        let mut actual = String::new();
        match v[0] {
            "META" => {
                assert_eq!(w[0], "META");
                assert_eq!(w.len(), 8);
                assert_eq!(w[7], "8");
                continue;
            }
            "KEY" => {
                let secret = EcdheSecret::from_bytes(fixed(v[1])?);
                let mut bytes = [0; 36];
                let n = secret.encode_hpke_private(&mut bytes)?;
                let (decoded, read) = EcdheSecret::decode_hpke_private(&bytes)?;
                let mut public = [0; 36];
                decoded.public_key().encode_hpke(&mut public)?;
                write!(&mut actual, "KEY {n} {read}")?;
                add(&mut actual, &bytes);
                add(&mut actual, &public);
                decoded.clear();
                secret.clear();
                assert_eq!(w[5], encode(&[0; 32]));
                assert_eq!(actual, w[..5].join(" "));
                checked += 1;
                continue;
            }
            "ONESHOT" | "DEFAULT" => {
                let recipient = EcdheSecret::from_bytes(fixed(v[1])?);
                let info = raw(v[2])?;
                let aad = raw(v[3])?;
                let plain = raw(v[4])?;
                if v[0] == "ONESHOT" {
                    assert_eq!(w[1], "1");
                    let ciphertext = raw(w[3])?;
                    assert_eq!(w[2].parse::<usize>()?, plain.len() + 16);
                    assert_eq!(ciphertext.len(), plain.len() + 48);
                    let mut out = std::vec![0xa5;plain.len()];
                    assert_eq!(
                        open_oneshot(&recipient, &info, &aad, &ciphertext, &mut out)?,
                        plain.len()
                    );
                    assert_eq!(out, plain);
                    assert_eq!(w[4], encode(&out));
                } else {
                    assert_eq!(w[1], "1");
                    let enc = EcdhePublic::from_bytes(fixed(w[2])?);
                    let mut receiver = receiver_setup(enc, &recipient, &info)?;
                    let ciphertext = raw(w[13])?;
                    let mut out = std::vec![0xa5;plain.len()];
                    receiver.open(&aad, &ciphertext, &mut out)?;
                    assert_eq!(out, plain);
                    actual.push_str("DEFAULT 1");
                    add(&mut actual, enc.as_bytes());
                    state(&mut actual, &receiver, Role::Sender);
                    state(&mut actual, &receiver, Role::Receiver);
                    add(&mut actual, &ciphertext);
                    add(&mut actual, &out);
                    assert_eq!(actual, want);
                }
                let ephemeral = EcdheSecret::from_bytes([0x39; 32]);
                let mut ciphertext = std::vec![0;plain.len()+48];
                seal_oneshot_with_ephemeral(
                    recipient.public_key(),
                    &ephemeral,
                    &info,
                    &aad,
                    &plain,
                    &mut ciphertext,
                )?;
                writeln!(
                    &mut accepted,
                    "OPEN_ONESHOT {} {} {} {}",
                    v[1],
                    v[2],
                    v[3],
                    encode(&ciphertext)
                )?;
                writeln!(&mut accepted_results, "OPEN_ONESHOT 1 {}", encode(&plain))?;
            }
            "SETUP" | "ROUND" | "OPEN" | "WRONG" | "LIMIT_OPEN" => {
                let ephemeral = EcdheSecret::from_bytes(fixed(v[2])?);
                let recipient = EcdheSecret::from_bytes(fixed(v[3])?);
                let info = raw(v[4])?;
                let psk = raw(v[5])?;
                let id = raw(v[6])?;
                let parameters = Parameters {
                    kem: Kem::X25519,
                    mode: Mode::try_from(v[1].parse::<u8>()?)?,
                    info: &info,
                    psk: &psk,
                    psk_id: &id,
                };
                let s = sender_setup2(
                    &ephemeral,
                    Some(&recipient),
                    recipient.public_key(),
                    &parameters,
                );
                let r = receiver_setup2(
                    ephemeral.public_key(),
                    &recipient,
                    Some(recipient.public_key()),
                    &parameters,
                );
                if v[0] == "SETUP" {
                    write!(
                        &mut actual,
                        "SETUP {} {}",
                        u8::from(s.is_ok()),
                        u8::from(r.is_ok())
                    )?;
                    if let Ok((enc, ctx)) = &s {
                        add(&mut actual, enc.as_bytes());
                        state(&mut actual, ctx, Role::Sender);
                    }
                    if let Ok(ctx) = &r {
                        state(&mut actual, ctx, Role::Receiver);
                    }
                    assert_eq!(actual, want);
                    checked += 1;
                    continue;
                }
                let (_, mut sender) = s?;
                let mut receiver = r?;
                let sequence = v[7].parse::<u64>()?;
                sender.sequence = sequence;
                receiver.sequence = sequence;
                let aad = raw(v[8])?;
                let input = raw(v[9])?;
                match v[0] {
                    "ROUND" => {
                        let mut ciphertext = std::vec![0xa5;input.len()+16];
                        let sealed = sender.seal(&aad, &input, &mut ciphertext);
                        write!(&mut actual, "ROUND {}", u8::from(sealed.is_ok()))?;
                        add(&mut actual, &sender.sequence_be());
                        if sealed.is_ok() {
                            let mut out = std::vec![0xa5;input.len()];
                            let opened = receiver.open(&aad, &ciphertext, &mut out);
                            write!(&mut actual, " {}", u8::from(opened.is_ok()))?;
                            add(&mut actual, &receiver.sequence_be());
                            add(&mut actual, &ciphertext);
                            if opened.is_ok() {
                                add(&mut actual, &out);
                            }
                            writeln!(
                                &mut accepted,
                                "OPEN {} {} {} {} {} {} {} {} {}",
                                v[1],
                                v[2],
                                v[3],
                                v[4],
                                v[5],
                                v[6],
                                v[7],
                                v[8],
                                encode(&ciphertext)
                            )?;
                            writeln!(
                                &mut accepted_results,
                                "OPEN 1 {} {}",
                                encode(&receiver.sequence_be()),
                                encode(&input)
                            )?;
                        } else {
                            assert!(ciphertext.iter().all(|b| *b == 0));
                        }
                    }
                    "OPEN" => {
                        let length = input.len().saturating_sub(16);
                        let mut out = std::vec![0xa5;length];
                        let opened = receiver.open(&aad, &input, &mut out);
                        write!(&mut actual, "OPEN {}", u8::from(opened.is_ok()))?;
                        add(&mut actual, &receiver.sequence_be());
                        if opened.is_ok() {
                            add(&mut actual, &out);
                        } else if input.len() >= 16 {
                            assert!(out.iter().all(|b| *b == 0));
                        }
                    }
                    "WRONG" => {
                        let mut out = [0xa5; 8];
                        assert_eq!(
                            receiver.seal(&aad, &input, &mut out),
                            Err(Error::InvalidInput)
                        );
                        assert_eq!(
                            sender.open(&aad, &input, &mut out),
                            Err(Error::InvalidInput)
                        );
                        assert_eq!(out, [0xa5; 8]);
                        assert_eq!(&w[..4], &["WRONG", "0", "0", "4660"]);
                        assert_eq!(w[4], encode(&out));
                        assert_eq!(w[5], encode(&out));
                        assert_eq!(w[6], encode(&sender.sequence_be()));
                        assert_eq!(w[7], encode(&receiver.sequence_be()));
                        actual = String::from(want);
                    }
                    "LIMIT_OPEN" => {
                        let mut ciphertext = input.clone();
                        let tag = aead::chacha20poly1305_seal(
                            &receiver.key,
                            &receiver.nonce(),
                            &aad,
                            &mut ciphertext,
                        )?;
                        ciphertext.extend_from_slice(&tag);
                        let mut out = std::vec![0xa5;input.len()];
                        let opened = receiver.open(&aad, &ciphertext, &mut out);
                        assert!(out.iter().all(|b| *b == 0));
                        write!(&mut actual, "LIMIT_OPEN {}", u8::from(opened.is_ok()))?;
                        add(&mut actual, &receiver.sequence_be());
                    }
                    _ => return Err("unrecognized command".into()),
                }
                assert_eq!(actual, want, "actual C context row: {line}");
            }
            _ => return Err("unexpected fixture opcode".into()),
        }
        checked += 1;
    }
    assert!(checked > 30);
    assert!(accepted.lines().count() > 10);
    let path = std::path::PathBuf::from(
        std::env::var_os("GNUNET_HPKE_ACCEPT").ok_or("missing reverse path")?,
    );
    fs::write(&path, accepted)?;
    fs::write(path.with_extension("expected"), accepted_results)?;
    Ok(())
}

fn representable_secret() -> Result<elligator::Secret, Error> {
    // Existing Elligator source policy: a bounded caller search, no fixed-key
    // representability assumption or unbounded test RNG.
    for byte in 1..=255 {
        let secret = elligator::Secret::from_bytes([byte; 32]);
        if secret.public(0).is_ok() {
            return Ok(secret);
        }
    }
    Err(Error::Capacity)
}

#[test]
fn typed_elligator_base_psk_contexts_bind_full_representative_and_real_aead() -> Result<(), Error> {
    let recipient = EcdheSecret::from_bytes([9; 32]);
    let ephemeral = representable_secret()?;
    for mode in [Mode::Base, Mode::Psk] {
        let parameters = Parameters {
            mode,
            psk: if mode == Mode::Psk {
                b"secret\0bytes"
            } else {
                &[]
            },
            psk_id: if mode == Mode::Psk { b"id\0bytes" } else { &[] },
            ..Parameters::base_elligator(b"info\0bytes")
        };
        let (enc, mut sender) =
            sender_setup2_elligator(&ephemeral, 6, recipient.public_key(), &parameters)?;
        let mut receiver = receiver_setup2_elligator(enc, &recipient, &parameters)?;
        assert_eq!(sender.role(), Role::Sender);
        assert_eq!(receiver.role(), Role::Receiver);
        assert_eq!(sender.sequence(), 0);
        assert_eq!(sender.key.as_ref(), receiver.key.as_ref());
        assert_eq!(sender.base_nonce, receiver.base_nonce);
        assert_eq!(sender.exporter.0.as_ref(), receiver.exporter.0.as_ref());
        let mut ciphertext = [0; TAG_BYTES];
        assert_eq!(sender.seal(b"", b"", &mut ciphertext)?, TAG_BYTES);
        // The top bits do not change decoded DH, but do belong to the exact
        // representative KEM transcript. A fresh context must reject this tag.
        let mut alias = *enc.as_bytes();
        alias[31] ^= 128;
        let mut changed = receiver_setup2_elligator(
            elligator::Representative::from_bytes(alias),
            &recipient,
            &parameters,
        )?;
        assert_eq!(
            changed.open(b"", &ciphertext, &mut []),
            Err(Error::Authentication)
        );
        assert_eq!(changed.sequence(), 0);
        assert_eq!(receiver.open(b"", &ciphertext, &mut [])?, 0);
        let mut ciphertext = [0; 24];
        let mut plaintext = [0xa5; 8];
        assert_eq!(sender.seal(b"aad\0", b"payload\0", &mut ciphertext)?, 24);
        assert_eq!(
            receiver.open(b"wrong", &ciphertext, &mut plaintext),
            Err(Error::Authentication)
        );
        assert_eq!(plaintext, [0; 8]);
        assert_eq!(receiver.sequence(), 1);
        assert_eq!(receiver.open(b"aad\0", &ciphertext, &mut plaintext)?, 8);
        assert_eq!(&plaintext, b"payload\0");
        assert_eq!(receiver.sequence(), 2);
    }
    Ok(())
}

struct SetupEntropy {
    calls: usize,
    fail: bool,
}
impl Entropy for SetupEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.calls += 1;
        out.fill(0);
        if self.fail {
            Err(Error::Entropy)
        } else {
            Ok(())
        }
    }
}

#[test]
fn typed_elligator_refusals_precede_kem_and_entropy_and_attempts_remain_bounded()
-> Result<(), Error> {
    let invalid_ephemeral = elligator::Secret::from_bytes([0; 32]);
    let invalid_recipient = EcdhePublic::from_bytes([0; 32]);
    let recipient = EcdheSecret::from_bytes([9; 32]);
    let attempts = core::num::NonZeroUsize::new(3).ok_or(Error::InvalidInput)?;
    for (kem, mode, psk, psk_id, expected) in [
        (
            Kem::X25519,
            Mode::Base,
            b"".as_slice(),
            b"".as_slice(),
            Error::Unsupported,
        ),
        (
            Kem::X25519Elligator,
            Mode::Auth,
            b"".as_slice(),
            b"".as_slice(),
            Error::Unsupported,
        ),
        (
            Kem::X25519Elligator,
            Mode::AuthPsk,
            b"key".as_slice(),
            b"id".as_slice(),
            Error::Unsupported,
        ),
        (
            Kem::X25519Elligator,
            Mode::Psk,
            b"".as_slice(),
            b"id".as_slice(),
            Error::InvalidInput,
        ),
        (
            Kem::X25519Elligator,
            Mode::Base,
            b"key".as_slice(),
            b"id".as_slice(),
            Error::InvalidInput,
        ),
    ] {
        let parameters = Parameters {
            kem,
            mode,
            info: b"",
            psk,
            psk_id,
        };
        let mut entropy = SetupEntropy {
            calls: 0,
            fail: true,
        };
        assert!(
            matches!(sender_setup2_elligator(&invalid_ephemeral, 0, invalid_recipient, &parameters), Err(e) if e == expected)
        );
        assert!(
            matches!(receiver_setup2_elligator(elligator::Representative::from_bytes([0; 32]), &recipient, &parameters), Err(e) if e == expected)
        );
        assert!(
            matches!(sender_setup2_elligator_random(invalid_recipient, &parameters, &mut entropy, attempts), Err(e) if e == expected)
        );
        assert_eq!(entropy.calls, 0);
    }
    let parameters = Parameters::base_elligator(b"");
    let mut entropy = SetupEntropy {
        calls: 0,
        fail: true,
    };
    assert!(matches!(
        sender_setup2_elligator_random(recipient.public_key(), &parameters, &mut entropy, attempts),
        Err(Error::Entropy)
    ));
    assert_eq!(entropy.calls, 1);
    let mut entropy = SetupEntropy {
        calls: 0,
        fail: false,
    };
    assert!(matches!(
        sender_setup2_elligator_random(recipient.public_key(), &parameters, &mut entropy, attempts),
        Err(Error::Capacity)
    ));
    assert_eq!(entropy.calls, 1 + 2 * attempts.get());
    Ok(())
}
