//! Independent C-layout and adversarial-boundary checks for official GNUnet wire bytes.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Tests assert independent wire vectors while propagating fixture codec errors"
)]
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, Frame, Frames, MAX_MESSAGE_SIZE, MessageHeader, MessageType, RelativeTime,
    SignaturePurpose,
    dht::{GetMessage, Path, PutMessage, ResultMessage, RouteOptions},
    message_type,
};

#[test]
fn c_preprocessed_message_registry_matches_every_pinned_assignment() -> Result<(), Error> {
    let rows = include_str!("official_vectors/message-registry.tsv");
    assert_eq!(message_type::REGISTRY.len(), 677);
    assert_eq!(rows.lines().count(), 677);
    for (line, &(name, value)) in rows.lines().zip(message_type::REGISTRY) {
        let (c_name, c_value) = line.split_once('\t').ok_or(Error::Malformed)?;
        assert_eq!(c_name, name);
        assert_eq!(
            c_value.parse::<u16>().map_err(|_| Error::Malformed)?,
            value.value()
        );
    }
    // Independent literal protocol numbers, rather than only regenerated names.
    assert_eq!(message_type::DHT_P2P_PUT.value(), 146);
    assert_eq!(message_type::DHT_P2P_GET.value(), 147);
    assert_eq!(message_type::DHT_P2P_RESULT.value(), 148);
    assert_eq!(message_type::STATISTICS_GET.value(), 169);
    assert_eq!(message_type::GNS_LOOKUP.value(), 500);
    Ok(())
}

#[test]
fn header_frame_and_unknown_types_use_exact_c_size_type_order() -> Result<(), Error> {
    let wire = [0, 7, 0xf1, 0x23, 0xab, 0xcd, 0xef];
    let frame = Frame::decode(&wire)?;
    assert_eq!(frame.header().size(), 7);
    assert_eq!(frame.header().payload_len(), 3);
    assert_eq!(frame.header().message_type(), MessageType::new(0xf123));
    assert_eq!(frame.payload(), &[0xab, 0xcd, 0xef]);
    assert_eq!(frame.payload().as_ptr(), wire[4..].as_ptr());
    let mut output = [0; 7];
    assert_eq!(frame.encode(&mut output)?, 7);
    assert_eq!(output, wire);
    let mut short = [0xa5; 6];
    assert_eq!(frame.encode(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0xa5; 6]);
    for length in 0..wire.len() {
        assert_eq!(Frame::decode(&wire[..length]), Err(Error::Truncated));
    }
    for size in 0..4 {
        assert_eq!(
            MessageHeader::decode(&[0, size, 0, 1]),
            Err(Error::InvalidInput)
        );
    }
    assert_eq!(
        MessageHeader::from_total_size(MessageType::new(1), 65536),
        Err(Error::TooLarge)
    );
    assert_eq!(
        MessageHeader::new(MessageType::new(1), usize::MAX),
        Err(Error::Overflow)
    );
    Ok(())
}

#[test]
fn framed_stream_preserves_incomplete_and_invalid_suffix_without_false_eof() -> Result<(), Error> {
    let input = [0, 4, 0, 1, 0, 5, 0, 2, 0xaa, 0, 9, 0, 3, 0xbb];
    assert_eq!(Frame::decode(&input), Err(Error::InvalidInput));
    let mut stream = Frames::new(&input);
    assert_eq!(
        stream
            .next()
            .ok_or(Error::NotFound)??
            .header()
            .message_type()
            .value(),
        1
    );
    assert_eq!(stream.next().ok_or(Error::NotFound)??.payload(), &[0xaa]);
    assert_eq!(stream.next(), Some(Err(Error::Truncated)));
    assert_eq!(stream.remaining(), &input[9..]);
    assert_eq!(stream.next(), None);
    assert_eq!(stream.next(), None);
    let mut malformed = Frames::new(&[0, 3, 0, 1, 0, 4, 0, 2]);
    assert_eq!(malformed.next(), Some(Err(Error::InvalidInput)));
    assert_eq!(malformed.remaining(), &[0, 3, 0, 1, 0, 4, 0, 2]);
    assert_eq!(malformed.next(), None);
    assert_eq!(Frames::new(&[]).next(), None);
    Ok(())
}

#[test]
fn maximum_frame_size_is_supported_without_wrapping_65536_to_zero() -> Result<(), Error> {
    let payload = [0x5a; MAX_MESSAGE_SIZE - 4];
    let frame = Frame::new(MessageType::new(0xffff), &payload)?;
    let mut encoded = [0; MAX_MESSAGE_SIZE];
    assert_eq!(frame.encode(&mut encoded)?, 65535);
    assert_eq!(&encoded[..4], &[0xff, 0xff, 0xff, 0xff]);
    assert_eq!(Frame::decode(&encoded)?.payload(), &payload);
    let oversized = [0; MAX_MESSAGE_SIZE - 3];
    assert_eq!(
        Frame::new(MessageType::new(1), &oversized),
        Err(Error::TooLarge)
    );
    Ok(())
}

#[test]
fn purpose_header_and_microseconds_match_c_and_preserve_forever() -> Result<(), Error> {
    let bytes = include_bytes!("official_vectors/signature-purpose.bin");
    assert_eq!(bytes, &[0, 0, 0, 16, 1, 2, 3, 4]);
    let purpose = SignaturePurpose::decode(bytes)?;
    assert_eq!(purpose, SignaturePurpose::new(0x01020304, 8)?);
    purpose.validate_signed_size(16)?;
    assert_eq!(purpose.validate_signed_size(15), Err(Error::InvalidInput));
    let mut output = [0; 8];
    purpose.encode(&mut output)?;
    assert_eq!(&output, bytes);
    let mut short = [0xa5; 7];
    assert_eq!(purpose.encode(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0xa5; 7]);
    assert_eq!(
        SignaturePurpose::decode(&[0, 0, 0, 7, 0, 0, 0, 1]),
        Err(Error::InvalidInput)
    );
    assert_eq!(SignaturePurpose::decode(&[0; 7]), Err(Error::Truncated));
    assert_eq!(SignaturePurpose::decode(&[0; 9]), Err(Error::InvalidInput));
    let time = AbsoluteTime::decode(&[1, 2, 3, 4, 5, 6, 7, 8])?;
    assert_eq!(time.as_micros(), 0x0102030405060708);
    assert_eq!(time.to_be_bytes(), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(AbsoluteTime::decode(&[0xff; 8])?, AbsoluteTime::NEVER);
    assert!(AbsoluteTime::NEVER.is_never());
    assert!(RelativeTime::decode(&[0xff; 8])?.is_forever());
    assert_eq!(RelativeTime::decode(&[0; 8])?, RelativeTime::ZERO);
    assert_eq!(AbsoluteTime::decode(&[0; 9]), Err(Error::InvalidInput));
    assert_eq!(AbsoluteTime::decode(&[0; 7]), Err(Error::Truncated));
    Ok(())
}

#[test]
fn c_get_vector_decodes_32_bit_block_type_and_distinct_variable_fields() -> Result<(), Error> {
    let bytes = include_bytes!("official_vectors/dht-get.bin");
    assert_eq!(bytes.len(), 215);
    assert_eq!(
        &bytes[..16],
        &[0, 215, 0, 147, 1, 2, 3, 4, 0, 0x47, 0, 9, 0, 11, 0, 3]
    );
    let get = GetMessage::decode(bytes)?;
    assert_eq!(get.block_type, 0x01020304);
    assert_eq!(get.options.bits(), 0x47);
    assert_eq!(get.hop_count, 9);
    assert_eq!(get.desired_replication_level, 11);
    assert_eq!(get.peer_bloom, &[0xa5; 128]);
    assert_eq!(get.key, &[0xb6; 64]);
    assert_eq!(get.result_filter, &[0xab, 0xcd, 0xef]);
    assert_eq!(get.extended_query, b"abc?");
    assert_eq!(get.result_filter.as_ptr(), bytes[208..].as_ptr());
    let mut encoded = [0; 215];
    get.encode(&mut encoded)?;
    assert_eq!(&encoded, bytes);
    let mut short = [7; 214];
    assert_eq!(get.encode(&mut short), Err(Error::Capacity));
    assert_eq!(short, [7; 214]);
    for length in 0..bytes.len() {
        assert_eq!(GetMessage::decode(&bytes[..length]), Err(Error::Truncated));
    }
    let mut bad = *bytes;
    bad[14..16].copy_from_slice(&[0xff; 2]);
    assert_eq!(GetMessage::decode(&bad), Err(Error::Truncated));
    bad = *bytes;
    bad[3] = 146;
    assert_eq!(GetMessage::decode(&bad), Err(Error::Unsupported));
    Ok(())
}

#[test]
fn c_put_vectors_preserve_microseconds_bloom_path_and_sender_signature_order() -> Result<(), Error>
{
    let plain = include_bytes!("official_vectors/dht-put.bin");
    assert_eq!(
        &plain[..16],
        &[0, 220, 0, 146, 1, 2, 3, 4, 0, 0x41, 0, 9, 0, 11, 0, 0]
    );
    let put = PutMessage::decode(plain)?;
    assert_eq!(put.block_type, 0x01020304);
    assert_eq!(put.expiration.as_micros(), 0x0102030405060708);
    assert_eq!(put.options.bits(), 0x41);
    assert!(put.put_path.is_empty());
    assert_eq!(put.truncated_peer, None);
    assert_eq!(put.sender_signature, None);
    assert_eq!(put.payload, &[0xde, 0xad, 0xbe, 0xef]);
    let mut encoded = [0; 220];
    put.encode(&mut encoded)?;
    assert_eq!(&encoded, plain);
    let tracked = include_bytes!("official_vectors/dht-put-tracked.bin");
    let put = PutMessage::decode(tracked)?;
    assert_eq!(
        put.options,
        RouteOptions::DEMULTIPLEX_EVERYWHERE | RouteOptions::RECORD_ROUTE | RouteOptions::TRUNCATED
    );
    assert_eq!(put.truncated_peer, Some(&[0xc7; 32]));
    assert_eq!(put.sender_signature, Some(&[0x9a; 64]));
    assert_eq!(put.put_path.len(), 1);
    let element = put.put_path.elements().next().ok_or(Error::NotFound)?;
    assert_eq!(element.signature(), &[0xd8; 64]);
    assert_eq!(element.predecessor(), &[0xe9; 32]);
    let mut encoded = [0; 412];
    put.encode(&mut encoded)?;
    assert_eq!(&encoded, tracked);
    let mut short = [0xa5; 411];
    assert_eq!(put.encode(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0xa5; 411]);
    let inconsistent = PutMessage {
        sender_signature: None,
        ..put
    };
    assert_eq!(inconsistent.encode(&mut encoded), Err(Error::InvalidInput));
    assert_eq!(&encoded, tracked);
    let mut zero_type = *plain;
    zero_type[4..8].fill(0);
    assert_eq!(PutMessage::decode(&zero_type), Err(Error::InvalidInput));
    for length in 0..tracked.len() {
        assert!(PutMessage::decode(&tracked[..length]).is_err());
    }
    Ok(())
}

#[test]
fn c_result_vector_preserves_opaque_reserved_and_rejects_impossible_path_counts()
-> Result<(), Error> {
    let bytes = include_bytes!("official_vectors/dht-result-tracked.bin");
    assert_eq!(bytes.len(), 380);
    assert_eq!(
        &bytes[..16],
        &[1, 0x7c, 0, 148, 1, 2, 3, 4, 0, 0, 0, 11, 0, 1, 0, 1]
    );
    let result = ResultMessage::decode(bytes)?;
    assert_eq!(result.expiration.as_micros(), 0x0102030405060708);
    assert_eq!(result.put_path.len(), 1);
    assert_eq!(result.get_path.len(), 1);
    assert_eq!(
        result
            .put_path
            .elements()
            .next()
            .ok_or(Error::NotFound)?
            .predecessor(),
        &[0xe9; 32]
    );
    assert_eq!(
        result
            .get_path
            .elements()
            .next()
            .ok_or(Error::NotFound)?
            .signature(),
        &[0xea; 64]
    );
    assert_eq!(
        result
            .get_path
            .elements()
            .next()
            .ok_or(Error::NotFound)?
            .predecessor(),
        &[0xfb; 32]
    );
    assert_eq!(result.payload, &[0xde, 0xad, 0xbe, 0xef]);
    let mut encoded = [0; 380];
    result.encode(&mut encoded)?;
    assert_eq!(&encoded, bytes);
    for length in 0..bytes.len() {
        assert_eq!(
            ResultMessage::decode(&bytes[..length]),
            Err(Error::Truncated)
        );
    }
    let mut bad = *bytes;
    bad[8] = 1;
    // The reference receiver checks path extents, not this reserved value.
    // Keep Rust's existing opaque-field policy without changing originators.
    let preserved = ResultMessage::decode(&bad)?;
    assert_eq!(preserved.reserved, 0x0100);
    preserved.encode(&mut encoded)?;
    assert_eq!(encoded, bad);
    bad = *bytes;
    bad[12..14].copy_from_slice(&[0xff; 2]);
    assert_eq!(ResultMessage::decode(&bad), Err(Error::Truncated));
    bad = *bytes;
    bad[14..16].copy_from_slice(&[0xff; 2]);
    assert_eq!(ResultMessage::decode(&bad), Err(Error::Truncated));
    assert_eq!(Path::new(&[0; 95]), Err(Error::InvalidInput));
    Ok(())
}

#[test]
fn dht_size_quotes_refuse_oversized_messages_before_any_output_change() -> Result<(), Error> {
    let bytes = include_bytes!("official_vectors/dht-get.bin");
    let get = GetMessage::decode(bytes)?;
    let oversized = [0; 65535];
    let get = GetMessage {
        extended_query: &oversized,
        ..get
    };
    assert_eq!(get.encoded_len(), Err(Error::TooLarge));
    let mut destination = [0xa5; 32];
    assert_eq!(get.encode(&mut destination), Err(Error::TooLarge));
    assert_eq!(destination, [0xa5; 32]);
    let put = PutMessage::decode(include_bytes!("official_vectors/dht-put.bin"))?;
    assert_eq!(
        PutMessage {
            payload: &oversized,
            ..put
        }
        .encode(&mut destination),
        Err(Error::TooLarge)
    );
    assert_eq!(destination, [0xa5; 32]);
    let result = ResultMessage::decode(include_bytes!("official_vectors/dht-result-tracked.bin"))?;
    assert_eq!(
        ResultMessage {
            payload: &oversized,
            ..result
        }
        .encode(&mut destination),
        Err(Error::TooLarge)
    );
    assert_eq!(destination, [0xa5; 32]);
    Ok(())
}

#[test]
fn complete_frame_sizes_cannot_hide_truncated_dht_metadata() -> Result<(), Error> {
    // Rewrite the advertised size as well, so the common frame is complete and
    // rejection is owned by each DHT codec rather than only the framing layer.
    let mut get = *include_bytes!("official_vectors/dht-get.bin");
    for size in 4..211 {
        get[..2].copy_from_slice(
            &u16::try_from(size)
                .map_err(|_| Error::Overflow)?
                .to_be_bytes(),
        );
        assert_eq!(GetMessage::decode(&get[..size]), Err(Error::Truncated));
    }
    let mut put = *include_bytes!("official_vectors/dht-put-tracked.bin");
    for size in 4..408 {
        put[..2].copy_from_slice(
            &u16::try_from(size)
                .map_err(|_| Error::Overflow)?
                .to_be_bytes(),
        );
        assert_eq!(PutMessage::decode(&put[..size]), Err(Error::Truncated));
    }
    let mut result = *include_bytes!("official_vectors/dht-result-tracked.bin");
    for size in 4..376 {
        result[..2].copy_from_slice(
            &u16::try_from(size)
                .map_err(|_| Error::Overflow)?
                .to_be_bytes(),
        );
        assert_eq!(
            ResultMessage::decode(&result[..size]),
            Err(Error::Truncated)
        );
    }
    Ok(())
}

fn communicator_string_fixture(kind: u16, prefix: usize, field: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; prefix + field.len()];
    let length = bytes.len() as u16;
    bytes[..2].copy_from_slice(&length.to_be_bytes());
    bytes[2..4].copy_from_slice(&kind.to_be_bytes());
    if kind == 1204 {
        bytes[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    }
    bytes[prefix..].copy_from_slice(field);
    bytes
}

#[test]
fn communicator_string_checks_follow_each_c_handler_contract() -> Result<(), Error> {
    use gnunet_wire::official::communicator::{Request, Response};
    // Fixed reference handlers all use GNUNET_MQ_check_zero_termination:
    // the first NUL must be the final byte. No UTF-8 policy is implied.
    for (kind, prefix) in [
        (1211u16, 12usize),
        (1200, 20),
        (1204, 64),
        (1206, 40),
        (1253, 44),
    ] {
        let decode = |bytes: &[u8]| -> Result<(), Error> {
            if matches!(kind, 1206 | 1253) {
                Response::decode(bytes).map(|_| ())
            } else {
                Request::decode(bytes).map(|_| ())
            }
        };
        for field in [b"\0".as_slice(), b"unix\0", &[0xff, 0]] {
            decode(&communicator_string_fixture(kind, prefix, field))?;
        }
        for field in [b"unix".as_slice(), b"unix\0tail\0", b"\0\0", b"unix\0tail"] {
            assert!(decode(&communicator_string_fixture(kind, prefix, field)).is_err());
        }
        let empty = communicator_string_fixture(kind, prefix, &[]);
        assert_eq!(decode(&empty).is_ok(), kind == 1211);
        let mut maximum = vec![b'x'; usize::from(u16::MAX) - prefix];
        *maximum.last_mut().ok_or(Error::Capacity)? = 0;
        let maximum = communicator_string_fixture(kind, prefix, &maximum);
        assert_eq!(maximum.len(), usize::from(u16::MAX));
        decode(&maximum)?;
    }
    Ok(())
}

#[test]
fn communicator_backchannel_retains_first_byte_string_without_utf8_or_unique_nul_policy()
-> Result<(), Error> {
    use gnunet_wire::official::communicator::Request;
    let inner = [0, 4, 0, 71];
    // Unlike the strict field macro, check_communicator_backchannel checks only
    // the final NUL; the handler consumes the first byte string with strlen.
    for name in [b"unix\0tail\0".as_slice(), &[0xff, 0, 0xfe, 0], b"\0\0"] {
        let mut bytes = communicator_string_fixture(1212, 44, name);
        bytes[40..44].copy_from_slice(&inner);
        let Request::Backchannel {
            message,
            communicator,
            ..
        } = Request::decode(&bytes)?
        else {
            return Err(Error::Malformed);
        };
        let end = name.iter().position(|b| *b == 0).ok_or(Error::Malformed)?;
        assert_eq!(message, inner);
        assert_eq!(message.as_ptr(), bytes[40..].as_ptr());
        assert_eq!(communicator, &name[..end]);
        assert_eq!(communicator.as_ptr(), bytes[44..].as_ptr());
        *bytes.last_mut().ok_or(Error::Capacity)? = b'x';
        assert!(Request::decode(&bytes).is_err());
    }
    Ok(())
}

#[test]
fn communicator_fixed_callbacks_preserve_raw_bits_and_refuse_extended_frames() -> Result<(), Error>
{
    use gnunet_wire::official::communicator::Request;
    for status in [i32::MIN, -1, 0, 1, i32::MAX] {
        let request = Request::Sent {
            message_id: [0xa5; 8],
            queue: u32::MAX,
            peer: [0xe3; 32],
            status,
        };
        let mut bytes = vec![0; request.encoded_len()?];
        request.encode(&mut bytes)?;
        assert_eq!(Request::decode(&bytes)?, request);
        assert_eq!(&bytes[4..8], &status.to_be_bytes());
        bytes.push(0);
        let length = bytes.len() as u16;
        bytes[..2].copy_from_slice(&length.to_be_bytes());
        assert_eq!(Request::decode(&bytes), Err(Error::Malformed));
    }
    for request in [
        Request::Created([0x91; 4], true),
        Request::Created([0x82; 4], false),
        Request::BurstFinished,
    ] {
        let mut bytes = vec![0; request.encoded_len()?];
        request.encode(&mut bytes)?;
        assert_eq!(Request::decode(&bytes)?, request);
        bytes.push(0);
        let length = bytes.len() as u16;
        bytes[..2].copy_from_slice(&length.to_be_bytes());
        assert_eq!(Request::decode(&bytes), Err(Error::Malformed));
    }
    Ok(())
}
