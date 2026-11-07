//! Literal and pinned-C HELLO framing, resource and unverified-state checks.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible codec tests assert independent C wire bytes and malformed input behavior."
)]
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    hello::{
        BLOCK_HEADER_LEN, HelloLimits, MESSAGE_FIXED_LEN, UnverifiedHello, encode_addresses,
        encode_signed_payload,
    },
};

const LIMITS: HelloLimits = HelloLimits {
    maximum_addresses: 8,
    maximum_bytes: 65535,
};
const MESSAGE: &[u8] = include_bytes!("fixtures/hello_message.bin");
const BLOCK: &[u8] = include_bytes!("fixtures/hello_block.bin");
const DHT: &[u8] = include_bytes!("fixtures/hello_dht.bin");

#[test]
fn pinned_c_hello_forms_decode_and_encode_without_authentication() -> Result<(), Error> {
    let peer: [u8; 32] = core::array::from_fn(|i| i as u8);
    let signature: [u8; 64] = core::array::from_fn(|i| 64 + i as u8);
    let full = UnverifiedHello::decode_message(MESSAGE, LIMITS)?;
    let block = UnverifiedHello::decode_block(BLOCK, LIMITS)?;
    let dht = UnverifiedHello::decode_dht_message(DHT, &peer, LIMITS)?;
    assert_eq!(full, block);
    assert_eq!(full, dht);
    assert_eq!(full.claimed_peer(), &peer);
    assert_eq!(full.signature(), &signature);
    assert_eq!(full.expiration().as_micros(), 0x0102030405060708);
    assert_eq!(full.address_count(), 2);
    let addresses: Result<Vec<_>, _> = full.addresses().collect();
    let addresses = addresses?;
    assert_eq!(addresses[0].uri(), b"tcp://127.0.0.1:2086");
    assert_eq!(addresses[0].scheme(), b"tcp");
    assert_eq!(addresses[1].as_utf8()?, "udp://example:2086");
    let mut output = [0xa5; 256];
    let size = full.encode_message(&mut output)?;
    assert_eq!(&output[..size], MESSAGE);
    assert_eq!(output[size], 0xa5);
    let size = full.encode_block(&mut output)?;
    assert_eq!(&output[..size], BLOCK);
    let size = full.encode_dht_message(&mut output)?;
    assert_eq!(&output[..size], DHT);
    assert_eq!(&MESSAGE[..8], &[0, 152, 0, 16, 0, 0, 0, 2]);
    assert_eq!(&DHT[..8], &[0, 120, 0, 157, 0, 0, 0, 2]);
    Ok(())
}

#[test]
fn every_fixed_prefix_and_exact_frame_suffix_are_checked() -> Result<(), Error> {
    let peer = [0; 32];
    for length in 0..MESSAGE.len() {
        assert_eq!(
            UnverifiedHello::decode_message(&MESSAGE[..length], LIMITS),
            Err(Error::Truncated)
        );
    }
    for length in 0..DHT.len() {
        assert_eq!(
            UnverifiedHello::decode_dht_message(&DHT[..length], &peer, LIMITS),
            Err(Error::Truncated)
        );
    }
    for length in 0..BLOCK_HEADER_LEN {
        assert_eq!(
            UnverifiedHello::decode_block(&BLOCK[..length], LIMITS),
            Err(Error::Truncated)
        );
    }
    let mut trailing = MESSAGE.to_vec();
    trailing.push(0);
    assert_eq!(
        UnverifiedHello::decode_message(&trailing, LIMITS),
        Err(Error::InvalidInput)
    );
    let mut missing_terminator = MESSAGE.to_vec();
    missing_terminator.pop();
    let len = u16::try_from(missing_terminator.len()).map_err(|_| Error::Overflow)?;
    missing_terminator[..2].copy_from_slice(&len.to_be_bytes());
    assert_eq!(
        UnverifiedHello::decode_message(&missing_terminator, LIMITS),
        Err(Error::Truncated)
    );
    let mut wrong_count = MESSAGE.to_vec();
    wrong_count[7] = 3;
    assert_eq!(
        UnverifiedHello::decode_message(&wrong_count, LIMITS),
        Err(Error::Malformed)
    );
    wrong_count[7] = 2;
    wrong_count[5] = 1;
    assert_eq!(
        UnverifiedHello::decode_message(&wrong_count, LIMITS),
        Err(Error::Unsupported)
    );
    wrong_count[5] = 0;
    wrong_count[3] = 17;
    assert_eq!(
        UnverifiedHello::decode_message(&wrong_count, LIMITS),
        Err(Error::Unsupported)
    );
    Ok(())
}

#[test]
fn explicit_input_caps_and_encoder_failure_do_not_change_output() -> Result<(), Error> {
    let hello = UnverifiedHello::decode_message(MESSAGE, LIMITS)?;
    assert_eq!(
        UnverifiedHello::decode_message(
            MESSAGE,
            HelloLimits {
                maximum_addresses: 1,
                ..LIMITS
            }
        ),
        Err(Error::Capacity)
    );
    assert_eq!(
        UnverifiedHello::decode_message(
            MESSAGE,
            HelloLimits {
                maximum_bytes: MESSAGE.len() - 1,
                ..LIMITS
            }
        ),
        Err(Error::Capacity)
    );
    let mut output = [0xa5; 79];
    assert_eq!(hello.encode_message(&mut output), Err(Error::Capacity));
    assert_eq!(hello.encode_dht_message(&mut output), Err(Error::Capacity));
    assert_eq!(hello.encode_block(&mut output), Err(Error::Capacity));
    assert_eq!(output, [0xa5; 79]);
    assert_eq!(
        encode_signed_payload(hello.expiration(), &[0; 64], &mut output),
        Err(Error::Capacity)
    );
    assert_eq!(output, [0xa5; 79]);
    let mut addresses = [0xa5; 8];
    assert_eq!(encode_addresses(&[b"udp://a"], &mut addresses, LIMITS)?, 8);
    let before = addresses;
    assert_eq!(
        encode_addresses(&[b"udp://a\0hidden"], &mut addresses, LIMITS),
        Err(Error::Malformed)
    );
    assert_eq!(addresses, before);
    Ok(())
}

#[test]
fn empty_unexpired_claim_is_structurally_valid_but_no_contact_is_inferred() -> Result<(), Error> {
    let hello =
        UnverifiedHello::decode_message(include_bytes!("fixtures/hello_empty.bin"), LIMITS)?;
    assert_eq!(hello.address_count(), 0);
    assert!(hello.address_bytes().is_empty());
    assert_eq!(hello.addresses().len(), 0);
    assert_eq!(hello.addresses().next(), None);
    let mut output = [0; MESSAGE_FIXED_LEN];
    assert_eq!(hello.encode_message(&mut output)?, MESSAGE_FIXED_LEN);
    assert_eq!(output, *include_bytes!("fixtures/hello_empty.bin"));
    Ok(())
}

#[test]
fn opaque_schemes_and_paths_are_preserved_but_bad_uris_and_duplicates_fail() -> Result<(), Error> {
    let peer = [7; 32];
    let signature = [9; 64];
    let mut region = [0; 128];
    // Unsorted input is accepted by the C parser; sorting is a builder/hash-owner concern.
    let size = encode_addresses(&[b"z+unknown://\xffopaque", b"tcp://"], &mut region, LIMITS)?;
    let hello = UnverifiedHello::new(
        &peer,
        &signature,
        AbsoluteTime::UNIX_EPOCH,
        &region[..size],
        LIMITS,
    )?;
    let first = hello.addresses().next().ok_or(Error::NotFound)??;
    assert_eq!(first.scheme(), b"z+unknown");
    assert_eq!(first.uri(), b"z+unknown://\xffopaque");
    assert_eq!(first.as_utf8(), Err(Error::Malformed));
    for invalid in [
        &b"udp://a\0udp://a\0"[..],
        b"no-separator\0",
        b"://a\0",
        b"tcp4://a\0",
        b"tcp-x://a\0",
        b"\0",
    ] {
        assert_eq!(
            UnverifiedHello::new(&peer, &signature, AbsoluteTime::NEVER, invalid, LIMITS),
            Err(Error::Malformed)
        );
    }
    assert_eq!(
        UnverifiedHello::new(&peer, &signature, AbsoluteTime::NEVER, b"udp://a", LIMITS),
        Err(Error::Truncated)
    );
    Ok(())
}

#[test]
fn signature_region_is_official_purpose_and_microseconds_without_verifying_it() -> Result<(), Error>
{
    let mut output = [0xa5; 81];
    let hash = core::array::from_fn(|i| 128 + i as u8);
    assert_eq!(
        encode_signed_payload(
            AbsoluteTime::from_micros(0x0102030405060708),
            &hash,
            &mut output
        )?,
        80
    );
    assert_eq!(
        &output[..80],
        include_bytes!("fixtures/hello_signed_payload.bin")
    );
    assert_eq!(output[80], 0xa5);
    assert_eq!(&output[..8], &[0, 0, 0, 80, 0, 0, 0, 7]);
    Ok(())
}

#[test]
fn complete_frame_size_is_limited_to_u16_without_truncating_lengths() -> Result<(), Error> {
    let peer = [1; 32];
    let signature = [2; 64];
    let mut region = vec![b'a'; 65535 - MESSAGE_FIXED_LEN];
    region[..4].copy_from_slice(b"x://");
    let last = region.len() - 1;
    region[last] = 0;
    let hello = UnverifiedHello::new(&peer, &signature, AbsoluteTime::NEVER, &region, LIMITS)?;
    let mut output = vec![0xa5; 65538];
    let size = hello.encode_message(&mut output)?;
    assert_eq!(size, 65535);
    assert_eq!(&output[..2], &[0xff, 0xff]);
    assert_eq!(&output[size..], &[0xa5; 3]);
    assert_eq!(
        UnverifiedHello::decode_message(&output[..size], LIMITS)?,
        hello
    );
    let mut oversized = vec![b'a'; 65536];
    oversized[..4].copy_from_slice(b"x://");
    oversized[65535] = 0;
    let block_only = UnverifiedHello::new(
        &peer,
        &signature,
        AbsoluteTime::NEVER,
        &oversized,
        HelloLimits {
            maximum_bytes: 70000,
            ..LIMITS
        },
    )?;
    let mut untouched = [0xa5; 1];
    assert_eq!(
        block_only.encode_message(&mut untouched),
        Err(Error::TooLarge)
    );
    assert_eq!(
        block_only.encode_dht_message(&mut untouched),
        Err(Error::TooLarge)
    );
    assert_eq!(untouched, [0xa5; 1]);
    Ok(())
}
