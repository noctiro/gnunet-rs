//! Official semantic, authority, resource and malformed-input boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible boundary tests assert complete refusal and independent C semantics."
)]
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature};
use gnunet_hello::{
    AbsoluteTime, AddAddress, Hello, HelloBuilder, Limits, SignatureCoverage, SignatureProfile,
    address_to_prefix, default_expiration, message_expiration,
};
use gnunet_types::Error;
const LIMITS: Limits = Limits {
    maximum_input_bytes: 8192,
    maximum_address_bytes: 4096,
    maximum_addresses: 32,
};
const BLOCK: &[u8] = include_bytes!("fixtures/normal.block");
const URL: &[u8] = include_bytes!("fixtures/normal.url");
fn unsigned<'a>(builder: &'a HelloBuilder<'_>, expiry: u64) -> Hello<'a> {
    builder.with_signature(
        EddsaPublicKey::from_bytes([0; 32]),
        EddsaSignature::from_bytes([0; 64]),
        AbsoluteTime::from_micros(expiry),
    )
}

#[test]
fn builder_set_order_removal_subset_and_failed_add_are_transactional() -> Result<(), Error> {
    let limits = Limits {
        maximum_address_bytes: 32,
        maximum_addresses: 3,
        ..LIMITS
    };
    let mut bytes = [0; 32];
    let mut builder = HelloBuilder::new(&mut bytes, limits);
    for a in [b"b://2".as_slice(), b"a://1", b"z://3"] {
        assert_eq!(builder.add_address(a)?, AddAddress::Added);
    }
    assert_eq!(builder.address_bytes(), b"z://3\0b://2\0a://1\0");
    assert_eq!(builder.add_address(b"b://2")?, AddAddress::AlreadyPresent);
    assert_eq!(builder.add_address(b"new://four"), Err(Error::Capacity));
    assert_eq!(builder.add_address(b"4udp://x"), Err(Error::Malformed));
    assert_eq!(builder.add_address(b"a://x\0hidden"), Err(Error::Malformed));
    assert_eq!(builder.address_count(), 3);
    assert!(!builder.remove_address(b"missing://x")?);
    assert!(builder.remove_address(b"b://2")?);
    assert_eq!(builder.address_bytes(), b"z://3\0a://1\0");
    let mut other_bytes = [0; 128];
    let mut other = HelloBuilder::new(&mut other_bytes, LIMITS);
    for a in [b"a://1".as_slice(), b"z://3", b"c://extra"] {
        other.add_address(a)?;
    }
    assert!(builder.is_subset_of(&other));
    assert!(!other.is_subset_of(&builder));
    let mut copy_bytes = [0; 128];
    let copy = unsigned(&builder, 5).to_builder(&mut copy_bytes, LIMITS)?;
    assert_eq!(copy.address_bytes(), builder.address_bytes());
    assert_eq!(
        address_to_prefix(b"udp://host-name"),
        Some(b"udp://host".as_slice())
    );
    assert_eq!(address_to_prefix(b"udp://localhost"), None);
    assert_eq!(address_to_prefix(b"-x"), Some(b"".as_slice()));
    Ok(())
}

#[test]
fn default_signature_does_not_bind_addresses_and_conditional_profile_does() -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([42; 32]);
    let mut bytes = [0; 128];
    let mut builder = HelloBuilder::new(&mut bytes, LIMITS);
    builder.add_address(b"a://first")?;
    let mut encoded = [0; 256];
    let default = builder.sign(
        &key,
        AbsoluteTime::from_micros(5),
        SignatureProfile::Gnunet029,
    )?;
    let n = default.encode_block(&mut encoded)?;
    let checked = default.verify_at(SignatureProfile::Gnunet029, AbsoluteTime::from_micros(5))?;
    assert_eq!(checked.coverage(), SignatureCoverage::MetadataOnly);
    assert_eq!(checked.checked_at().as_micros(), 5);
    assert_eq!(
        default.verify_at(SignatureProfile::Gnunet029, AbsoluteTime::from_micros(6)),
        Err(Error::Timeout)
    );
    let mut scratch = [0; 128];
    encoded[108] ^= 1;
    let changed = Hello::parse_block(&encoded[..n], &mut scratch, LIMITS)?;
    changed.verify_signature(SignatureProfile::Gnunet029)?;
    let bound = builder.sign(
        &key,
        AbsoluteTime::from_micros(5),
        SignatureProfile::DeterministicPidDerivation,
    )?;
    assert_eq!(
        bound.verify_signature(SignatureProfile::DeterministicPidDerivation)?,
        SignatureCoverage::MetadataAndAddresses
    );
    assert_eq!(
        bound.verify_signature(SignatureProfile::Gnunet029),
        Err(Error::Authentication)
    );
    let n = bound.encode_block(&mut encoded)?;
    encoded[108] ^= 1;
    let changed = Hello::parse_block(&encoded[..n], &mut scratch, LIMITS)?;
    assert_eq!(
        changed.verify_signature(SignatureProfile::DeterministicPidDerivation),
        Err(Error::Authentication)
    );
    for index in [0, 32, 96] {
        let n = bound.encode_block(&mut encoded)?;
        encoded[index] ^= 1;
        let changed = Hello::parse_block(&encoded[..n], &mut scratch, LIMITS)?;
        assert_eq!(
            changed.verify_signature(SignatureProfile::DeterministicPidDerivation),
            Err(Error::Authentication)
        );
    }
    assert_eq!(
        default_expiration(AbsoluteTime::from_micros(7)).as_micros(),
        172_800_000_007
    );
    assert_eq!(default_expiration(AbsoluteTime::NEVER), AbsoluteTime::NEVER);
    Ok(())
}

#[test]
fn binary_short_duplicate_and_resource_limits_fail_without_publication() -> Result<(), Error> {
    let mut scratch = [0; 4096];
    for size in 0..104 {
        assert_eq!(
            Hello::parse_block(&BLOCK[..size], &mut scratch, LIMITS),
            Err(Error::Truncated)
        );
    }
    assert_eq!(
        Hello::parse_block(&BLOCK[..BLOCK.len() - 1], &mut scratch, LIMITS),
        Err(Error::Truncated)
    );
    let mut duplicate = BLOCK.to_vec();
    duplicate.extend_from_slice(b"z://Z\0");
    assert_eq!(
        Hello::parse_block(&duplicate, &mut scratch, LIMITS),
        Err(Error::Malformed)
    );
    assert_eq!(
        Hello::parse_block(
            BLOCK,
            &mut scratch,
            Limits {
                maximum_input_bytes: 0,
                ..LIMITS
            }
        ),
        Err(Error::Capacity)
    );
    assert_eq!(
        Hello::parse_block(
            BLOCK,
            &mut scratch,
            Limits {
                maximum_addresses: 2,
                ..LIMITS
            }
        ),
        Err(Error::Capacity)
    );
    assert_eq!(
        Hello::parse_block(
            BLOCK,
            &mut scratch,
            Limits {
                maximum_address_bytes: 1,
                ..LIMITS
            }
        ),
        Err(Error::Capacity)
    );
    let message = include_bytes!("fixtures/normal.message");
    for size in 0..message.len() {
        assert!(Hello::parse_message(&message[..size], None, &mut scratch, LIMITS).is_err());
    }
    assert_eq!(
        Hello::parse_message(
            include_bytes!("fixtures/normal.dht"),
            None,
            &mut scratch,
            LIMITS
        ),
        Err(Error::InvalidInput)
    );
    let mut wrong = *message;
    wrong[2..4].copy_from_slice(&999_u16.to_be_bytes());
    assert_eq!(
        Hello::parse_message(&wrong, None, &mut scratch, LIMITS),
        Err(Error::Unsupported)
    );
    let mut extra = message.to_vec();
    extra.push(0);
    assert!(Hello::parse_message(&extra, None, &mut scratch, LIMITS).is_err());
    Ok(())
}

#[test]
fn complete_output_preflight_and_exact_message_width_boundary() -> Result<(), Error> {
    let mut scratch = [0; 4096];
    let hello = Hello::parse_block(BLOCK, &mut scratch, LIMITS)?;
    let mut output = [0xa5; 4096];
    for (size, kind) in [
        (hello.block_len()?, 0),
        (hello.message_len()?, 1),
        (hello.dht_message_len()?, 2),
        (hello.url_len()?, 3),
    ] {
        let r = match kind {
            0 => hello.encode_block(&mut output[..size - 1]),
            1 => hello.encode_message(&mut output[..size - 1]),
            2 => hello.encode_dht_message(&mut output[..size - 1]),
            _ => hello.write_url(&mut output[..size - 1]).map(str::len),
        };
        assert_eq!(r, Err(Error::Capacity));
        assert!(output.iter().all(|b| *b == 0xa5));
    }
    let mut uri = std::vec![b'x';65535-112-1];
    uri[..4].copy_from_slice(b"a://");
    let mut storage = std::vec![0;uri.len()+2];
    let huge = Limits {
        maximum_input_bytes: usize::MAX,
        maximum_address_bytes: usize::MAX,
        maximum_addresses: 2,
    };
    let mut builder = HelloBuilder::new(&mut storage, huge);
    builder.add_address(&uri)?;
    let hello = unsigned(&builder, 1);
    assert_eq!(hello.message_len()?, 65535);
    let mut exact = std::vec![0;65535];
    assert_eq!(hello.encode_message(&mut exact)?, 65535);
    assert!(builder.remove_address(&uri)?);
    uri.push(b'x');
    builder.add_address(&uri)?;
    let hello = unsigned(&builder, 1);
    let mut output = [0xa5; 8];
    assert!(hello.encode_message(&mut output).is_err());
    assert_eq!(output, [0xa5; 8]);
    Ok(())
}

#[test]
fn empty_sets_and_expiration_helper_match_c_persistence_semantics() -> Result<(), Error> {
    let mut bytes = [];
    let builder = HelloBuilder::new(&mut bytes, LIMITS);
    let hello = unsigned(&builder, u64::MAX);
    let mut message = [0; 112];
    hello.encode_message(&mut message)?;
    assert_eq!(message_expiration(&message)?, AbsoluteTime::UNIX_EPOCH);
    let mut dht = [0; 80];
    hello.encode_dht_message(&mut dht)?;
    assert_eq!(message_expiration(&dht)?, AbsoluteTime::NEVER);
    let mut scratch = [];
    assert_eq!(
        Hello::parse_message(&message, None, &mut scratch, LIMITS)?.address_count(),
        0
    );
    let mut text = [0; 256];
    let url = hello.write_url(&mut text)?;
    assert_eq!(
        Hello::parse_url(url.as_bytes(), &mut scratch, LIMITS)?.address_count(),
        0
    );
    let mut bytes = [0; 32];
    let mut builder = HelloBuilder::new(&mut bytes, LIMITS);
    builder.add_address(b"test://")?;
    let hello = unsigned(&builder, 1);
    let url = hello.write_url(&mut text)?;
    assert_eq!(
        Hello::parse_url(url.as_bytes(), &mut scratch, LIMITS),
        Err(Error::Malformed)
    );
    Ok(())
}

#[test]
fn textual_c_quirks_and_malformed_boundaries_are_explicit() -> Result<(), Error> {
    let bare = URL.split(|b| *b == b'?').next().ok_or(Error::Malformed)?;
    let mut scratch = [0; 4096];
    for (encoded, decoded) in [
        (b"x+y".as_slice(), b"x+y".as_slice()),
        (b"x%2By", b"x+y"),
        (b"x%20y", b"x y"),
        (b"x%2Zy", b"x\x02y"),
        (b"x%GGy", b"x%GGy"),
        (b"x%00suffix", b"x"),
    ] {
        let mut url = bare.to_vec();
        url.extend_from_slice(b"?test=");
        url.extend_from_slice(encoded);
        let hello = Hello::parse_url(&url, &mut scratch, LIMITS)?;
        let address = hello.addresses().next().ok_or(Error::Malformed)?;
        assert_eq!(address.scheme(), b"test");
        assert_eq!(address.body(), decoded);
        hello.verify_signature(SignatureProfile::Gnunet029)?;
    }
    for query in [
        b"?".as_slice(),
        b"?test=",
        b"?=x",
        b"?test=x&test=x",
        b"?test=x&",
        b"?test=%",
        b"?test=%0",
        b"?test=%00x",
    ] {
        let mut url = bare.to_vec();
        url.extend_from_slice(query);
        assert!(Hello::parse_url(&url, &mut scratch, LIMITS).is_err());
    }
    for bad in [
        b"gnunet://hello/".as_slice(),
        b"not://hello/x",
        b"gnunet://hello/A/B/1",
        b"gnunet://hello/A/B/",
    ] {
        assert!(Hello::parse_url(bad, &mut scratch, LIMITS).is_err());
    }
    let mut lower = URL.to_ascii_lowercase();
    assert_eq!(
        Hello::parse_url(&lower, &mut scratch, LIMITS)?
            .peer()
            .as_bytes(),
        include_bytes!("fixtures/normal.peer")
    );
    lower[0] = 0;
    assert_eq!(
        Hello::parse_url(&lower, &mut scratch, LIMITS),
        Err(Error::Malformed)
    );
    let mut overflow = bare[..bare.len() - 20].to_vec();
    overflow.extend_from_slice(b"18446744073709551616");
    assert_eq!(
        Hello::parse_url(&overflow, &mut scratch, LIMITS),
        Err(Error::Overflow)
    );
    Ok(())
}

#[test]
fn c_url_width_encoding_keeps_opaque_binary_addresses() -> Result<(), Error> {
    let mut bytes = [0; 256];
    let mut builder = HelloBuilder::new(&mut bytes, LIMITS);
    for a in [
        b"test://\xc0A".as_slice(),
        b"test://\xf8BBBB",
        b"other://caf\xc3\xa9",
        b"space://x y",
    ] {
        builder.add_address(a)?;
    }
    let hello = unsigned(&builder, 1);
    let mut text = [0; 1024];
    let url = hello.write_url(&mut text)?;
    assert!(url.contains("%C0%41"));
    assert!(url.contains("%F8%42%42%42%42"));
    assert!(url.contains("caf%C3%A9"));
    assert!(url.contains("space=x+y"));
    let mut scratch = [0; 256];
    let parsed = Hello::parse_url(url.as_bytes(), &mut scratch, LIMITS)?;
    assert!(parsed.addresses().any(|a| a.as_bytes() == b"space://x+y"));
    let mut bytes = [0; 32];
    let mut bad = HelloBuilder::new(&mut bytes, LIMITS);
    bad.add_address(b"a://\x80")?;
    let mut output = [0xa5; 512];
    assert_eq!(
        unsigned(&bad, 1).write_url(&mut output),
        Err(Error::Malformed)
    );
    assert!(output.iter().all(|b| *b == 0xa5));
    Ok(())
}

#[test]
fn storage_byte_limits_are_independent_of_count_and_duplicate_budget() -> Result<(), Error> {
    for (capacity, maximum_address_bytes) in [(6, 64), (64, 6)] {
        let mut storage = [0; 64];
        let mut builder = HelloBuilder::new(
            &mut storage[..capacity],
            Limits {
                maximum_address_bytes,
                maximum_addresses: 10,
                ..LIMITS
            },
        );
        builder.add_address(b"a://x")?;
        let before = builder.address_bytes().to_vec();
        assert_eq!(builder.add_address(b"b://y"), Err(Error::Capacity));
        assert_eq!(builder.address_bytes(), before);
        assert_eq!(builder.address_count(), 1);
        assert_eq!(builder.add_address(b"a://x")?, AddAddress::AlreadyPresent);
        assert_eq!(builder.block_len()?, 110);
    }
    let mut storage = [0; 6];
    let mut builder = HelloBuilder::new(
        &mut storage,
        Limits {
            maximum_addresses: 1,
            ..LIMITS
        },
    );
    builder.add_address(b"a://x")?;
    assert_eq!(builder.add_address(b"a://x")?, AddAddress::AlreadyPresent);
    assert_eq!(builder.add_address(b"b://y"), Err(Error::Capacity));
    Ok(())
}

#[test]
fn oversized_raw_blocks_remain_distinct_from_bounded_wire_frames() -> Result<(), Error> {
    let limits = Limits {
        maximum_input_bytes: 100_000,
        maximum_address_bytes: 100_000,
        maximum_addresses: 1,
    };
    let mut address = std::vec![b'x'; 65_536];
    address[..4].copy_from_slice(b"a://");
    let mut storage = std::vec![0; address.len() + 1];
    let mut builder = HelloBuilder::new(&mut storage, limits);
    builder.add_address(&address)?;
    let hello = unsigned(&builder, 1);
    let n = hello.block_len()?;
    assert_eq!(builder.block_len()?, 65_641);
    let mut block = std::vec![0; n];
    assert_eq!(hello.encode_block(&mut block)?, n);
    let mut scratch = std::vec![0; address.len() + 1];
    let parsed = Hello::parse_block(&block, &mut scratch, limits)?;
    assert_eq!(
        parsed
            .addresses()
            .next()
            .ok_or(Error::Malformed)?
            .as_bytes(),
        address
    );
    let mut output = std::vec![0xa5; n + 8];
    assert!(hello.encode_message(&mut output).is_err());
    assert!(hello.encode_dht_message(&mut output).is_err());
    assert!(output.iter().all(|b| *b == 0xa5));
    Ok(())
}

#[test]
fn nonempty_expiration_helper_and_typed_short_frames() -> Result<(), Error> {
    use gnunet_wire::official::message_type;
    assert_eq!(
        message_expiration(include_bytes!("fixtures/normal.message"))?,
        AbsoluteTime::NEVER
    );
    assert_eq!(
        message_expiration(include_bytes!("fixtures/normal.dht"))?,
        AbsoluteTime::NEVER
    );
    let mut scratch = [0; 128];
    for (kind, minimum) in [
        (message_type::HELLO_URI, 112),
        (message_type::DHT_P2P_HELLO, 80),
    ] {
        for length in 4..minimum {
            let mut frame = std::vec![0; length];
            frame[..2].copy_from_slice(&(length as u16).to_be_bytes());
            frame[2..4].copy_from_slice(&kind.value().to_be_bytes());
            assert_eq!(
                Hello::parse_message(&frame, None, &mut scratch, LIMITS),
                Err(Error::Truncated)
            );
            assert_eq!(message_expiration(&frame), Err(Error::Truncated));
        }
    }
    Ok(())
}

#[test]
fn six_byte_c_encoding_and_signature_tail_bits() -> Result<(), Error> {
    let mut bytes = [0; 64];
    let mut builder = HelloBuilder::new(&mut bytes, LIMITS);
    for address in [b"four://\xf0ABC".as_slice(), b"six://\xfcABCDE"] {
        builder.add_address(address)?;
    }
    let mut encoded = [0; 1024];
    let text = unsigned(&builder, 1).write_url(&mut encoded)?;
    assert!(text.contains("%F0%41%42%43"));
    assert!(text.contains("%FC%41%42%43%44%45"));
    let mut scratch = [0; 64];
    let hello = Hello::parse_url(text.as_bytes(), &mut scratch, LIMITS)?;
    assert_eq!(hello.address_bytes(), builder.address_bytes());
    // The last signature digit has two significant bits and three ignored tail bits.
    let mut alias = URL.to_vec();
    let signature_end = alias
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'/')
        .nth(4)
        .ok_or(Error::Malformed)?
        .0;
    let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let last = alias[signature_end - 1];
    let index = alphabet
        .iter()
        .position(|b| *b == last)
        .ok_or(Error::Malformed)?;
    alias[signature_end - 1] = alphabet[index | 7];
    let mut scratch = [0; 4096];
    Hello::parse_url(&alias, &mut scratch, LIMITS)?
        .verify_signature(SignatureProfile::Gnunet029)?;
    Ok(())
}

#[test]
fn copied_builder_and_peer_outlive_parser_and_its_input() -> Result<(), Error> {
    let mut copied_storage = [0; 4096];
    let (copied, peer, signature, expiry) = {
        let input = BLOCK.to_vec();
        let mut scratch = [0; 4096];
        let parsed = Hello::parse_block(&input, &mut scratch, LIMITS)?;
        let builder = parsed.to_builder(&mut copied_storage, LIMITS)?;
        (
            builder,
            parsed.peer(),
            parsed.signature(),
            parsed.expiration(),
        )
    };
    assert_eq!(peer.as_bytes(), include_bytes!("fixtures/normal.peer"));
    let restored = copied.with_signature(peer, signature, expiry);
    restored.verify_at(SignatureProfile::Gnunet029, AbsoluteTime::NEVER)?;
    let mut block = [0; 4096];
    let length = restored.encode_block(&mut block)?;
    assert_eq!(&block[..length], BLOCK);
    Ok(())
}

#[test]
fn official_http3_and_uri_scheme_suffixes_keep_real_signed_wire_roundtrips() -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([73; 32]);
    let mut storage = [0; 512];
    let mut builder = HelloBuilder::new(&mut storage, LIMITS);
    for uri in [
        b"http3://127.0.0.1:4433".as_slice(),
        b"h3+quic://opaque",
        b"v1.2-test://opaque",
    ] {
        assert_eq!(builder.add_address(uri)?, AddAddress::Added);
    }
    let original = builder.address_bytes().to_vec();
    for uri in [
        b"3http://bad".as_slice(),
        b"+http://bad",
        b".http://bad",
        b"-http://bad",
        b"http_3://bad",
        b"http\x80://bad",
    ] {
        assert_eq!(builder.add_address(uri), Err(Error::Malformed));
        assert_eq!(builder.address_bytes(), original);
    }
    let hello = builder.sign(
        &key,
        AbsoluteTime::from_micros(10_000_000),
        SignatureProfile::Gnunet029,
    )?;
    let mut block = [0; 1024];
    let length = hello.encode_block(&mut block)?;
    let mut scratch = [0; 512];
    let parsed = Hello::parse_block(&block[..length], &mut scratch, LIMITS)?;
    parsed.verify_at(SignatureProfile::Gnunet029, AbsoluteTime::from_micros(1))?;
    assert_eq!(parsed.address_bytes(), original);
    let mut text = [0; 2048];
    let url = parsed.write_url(&mut text)?;
    let mut url_scratch = [0; 512];
    let decoded = Hello::parse_url(url.as_bytes(), &mut url_scratch, LIMITS)?;
    decoded.verify_at(SignatureProfile::Gnunet029, AbsoluteTime::from_micros(1))?;
    assert_eq!(decoded.address_bytes(), original);
    assert!(
        decoded
            .addresses()
            .any(|address| address.scheme() == b"http3" && address.body() == b"127.0.0.1:4433")
    );
    Ok(())
}
