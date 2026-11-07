//! Exact official datastore layouts and complete operation coverage.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check fixed layouts and atomic refusal"
)]
use gnunet_wire::official::{AbsoluteTime, MessageHeader, datastore::*, message_type as mt};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn all_service_requests_have_the_original_layout_and_roundtrip() -> TestResult {
    let key = [0xa7; 64];
    let data = Data {
        reservation: 7,
        kind: 5,
        priority: 11,
        anonymity: 13,
        replication: 17,
        uid: 0,
        expiration: AbsoluteTime::from_micros(0x0102_0304_0506_0708),
        key: &key,
        value: b"raw\0value",
    };
    let requests = [
        (
            Request::Reserve {
                amount: 0x0102_0304_0506_0708,
                entries: 0x1122_3344,
            },
            mt::DATASTORE_RESERVE,
            16,
        ),
        (
            Request::Release {
                reservation: 0x1122_3344,
            },
            mt::DATASTORE_RELEASE_RESERVE,
            8,
        ),
        (
            Request::Put(data),
            mt::DATASTORE_PUT,
            DATA_LEN + data.value.len(),
        ),
        (
            Request::Get {
                key: None,
                kind: 0,
                next_uid: 123,
                random: false,
            },
            mt::DATASTORE_GET,
            20,
        ),
        (
            Request::Get {
                key: Some(&key),
                kind: 5,
                next_uid: u64::MAX,
                random: true,
            },
            mt::DATASTORE_GET_KEY,
            84,
        ),
        (Request::Replication, mt::DATASTORE_GET_REPLICATION, 4),
        (
            Request::ZeroAnonymity {
                kind: 5,
                next_uid: 123,
            },
            mt::DATASTORE_GET_ZERO_ANONYMITY,
            16,
        ),
        (
            Request::Remove {
                key: &key,
                value: b"raw\0value",
            },
            mt::DATASTORE_REMOVE,
            DATA_LEN + 9,
        ),
        (Request::Drop, mt::DATASTORE_DROP, 4),
    ];
    for (request, kind, size) in requests {
        let mut output = [0xcc; 512];
        assert_eq!(request.encoded_len()?, size);
        assert_eq!(request.encode(&mut output)?, size);
        let header = MessageHeader::decode(&output)?;
        assert_eq!(header.message_type(), kind);
        assert_eq!(header.size(), size);
        assert_eq!(Request::decode(&output[..size])?, request);
        assert!(output[size..].iter().all(|b| *b == 0xcc));
        if let Request::Put(_) = request {
            assert_eq!(&output[4..12], &[0, 0, 0, 7, 0, 0, 0, 9]);
            assert_eq!(&output[28..40], &[0; 12]);
            assert_eq!(&output[40..48], &[1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(&output[48..112], key);
        }
    }
    // Existing C host-endian true is still accepted as a nonzero bool.
    let mut query = [0; GET_LEN];
    Request::Get {
        key: None,
        kind: 0,
        next_uid: 0,
        random: true,
    }
    .encode(&mut query)?;
    query[16..20].copy_from_slice(&[1, 0, 0, 0]);
    assert!(matches!(
        Request::decode(&query)?,
        Request::Get { random: true, .. }
    ));
    Ok(())
}

#[test]
fn status_data_and_no_result_are_single_exact_terminal_frames() -> TestResult {
    let mut bytes = [0; 256];
    let status = Status {
        code: -1,
        min_expiration: AbsoluteTime::from_micros(u64::MAX),
        message: Some(b"\xfferror\0"),
    };
    let count = Response::Status(status).encode(&mut bytes)?;
    assert_eq!(&bytes[4..8], &[255; 4]);
    assert_eq!(Response::decode(&bytes[..count])?, Response::Status(status));
    bytes[count - 1] = 1;
    assert!(Response::decode(&bytes[..count]).is_err());
    let key = [17; 64];
    let data = Data {
        reservation: 0,
        kind: 99,
        priority: 3,
        anonymity: 2,
        replication: 1,
        uid: 0x1122_3344_5566_7788,
        expiration: AbsoluteTime::from_micros(42),
        key: &key,
        value: b"body",
    };
    let count = Response::Data(data).encode(&mut bytes)?;
    assert_eq!(Response::decode(&bytes[..count])?, Response::Data(data));
    bytes[11] ^= 1;
    assert!(Response::decode(&bytes[..count]).is_err());
    assert_eq!(Response::End.encode(&mut bytes)?, 4);
    assert_eq!(Response::decode(&bytes[..4])?, Response::End);
    assert!(Response::decode(&bytes[..5]).is_err());
    let mut unchanged = [0xa7; 32];
    assert!(
        Status {
            message: None,
            ..status
        }
        .encode(&mut unchanged)
        .is_err()
    );
    assert_eq!(unchanged, [0xa7; 32]);
    Ok(())
}

#[test]
fn frame_value_boundary_and_capacity_refusals_are_atomic() -> TestResult {
    let key = [0; 64];
    let mut value = vec![3; MAX_VALUE_BYTES];
    let mut output = vec![0xa7; 65535];
    let request = Request::Remove {
        key: &key,
        value: &value,
    };
    assert_eq!(request.encode(&mut output)?, 65535);
    assert_eq!(Request::decode(&output)?, request);
    value.push(3);
    output.fill(0xa7);
    assert_eq!(
        Request::Remove {
            key: &key,
            value: &value
        }
        .encode(&mut output),
        Err(gnunet_types::Error::TooLarge)
    );
    assert!(output.iter().all(|byte| *byte == 0xa7));
    let mut tiny = [0xa7; 15];
    assert_eq!(
        Request::Reserve {
            amount: 1,
            entries: 1
        }
        .encode(&mut tiny),
        Err(gnunet_types::Error::Capacity)
    );
    assert_eq!(tiny, [0xa7; 15]);
    assert!(
        Request::ZeroAnonymity {
            kind: 0,
            next_uid: 0
        }
        .encode(&mut output)
        .is_err()
    );
    assert!(output.iter().all(|byte| *byte == 0xa7));
    Ok(())
}
