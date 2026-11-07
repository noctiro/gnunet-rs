//! Independent literal and pinned upstream-C fixtures for official GNS records.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible tests use assertions against independent official wire vectors."
)]
use gnunet_gnsrecord::{
    RecordData, RecordFlags, RecordSet, RecordType, ZoneKey, ZoneKeyType, serialize,
    serialize_to_size, serialized_len,
};
use gnunet_types::Error;

fn address() -> RecordData<'static> {
    RecordData {
        expiration_time: 0x0102030405060708,
        record_type: RecordType::A,
        flags: RecordFlags::CRITICAL.union(RecordFlags::SUPPLEMENTAL),
        data: &[192, 0, 2, 1],
    }
}

#[test]
fn record_header_is_official_microseconds_flags_and_u32_type() -> Result<(), Error> {
    let literal = [1, 2, 3, 4, 5, 6, 7, 8, 0, 4, 0, 5, 0, 0, 0, 1, 192, 0, 2, 1];
    let mut actual = [0x55; 22];
    assert_eq!(address().encode(&mut actual)?, 20);
    assert_eq!(&actual[..20], literal);
    assert_eq!(&actual[20..], [0x55; 2]);
    let (decoded, suffix) = RecordData::decode_prefix(&literal)?;
    assert_eq!(decoded, address());
    assert!(suffix.is_empty());
    assert!(!decoded.has_relative_expiration());
    Ok(())
}

#[test]
fn pinned_c_serialization_fixtures_match_exactly() -> Result<(), Error> {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let ten = [b'a'; 10];
    let twenty = [b'b'; 20];
    let a = address();
    let txt = [
        RecordData {
            expiration_time: 0,
            record_type: RecordType::TXT,
            flags: RecordFlags::NONE,
            data: &[],
        },
        RecordData {
            expiration_time: 0x11223344,
            record_type: RecordType::TXT,
            flags: RecordFlags::RELATIVE_EXPIRATION,
            data: &ten,
        },
        RecordData {
            expiration_time: u64::MAX,
            record_type: RecordType::TXT,
            flags: RecordFlags::PRIVATE,
            data: &twenty,
        },
    ];
    let pkey = RecordData {
        expiration_time: 9,
        record_type: RecordType::PKEY,
        flags: RecordFlags::NONE,
        data: &key,
    };
    let edkey = RecordData {
        record_type: RecordType::EDKEY,
        ..pkey
    };
    for (records, expected) in [
        (&[a][..], &include_bytes!("fixtures/a.bin")[..]),
        (&txt[..], &include_bytes!("fixtures/txt.bin")[..]),
        (
            &[pkey, a][..],
            &include_bytes!("fixtures/pkey_first.bin")[..],
        ),
        (&[edkey][..], &include_bytes!("fixtures/edkey.bin")[..]),
        (
            &[a, edkey][..],
            &include_bytes!("fixtures/edkey_second.bin")[..],
        ),
        (&[][..], &include_bytes!("fixtures/empty.bin")[..]),
    ] {
        let mut output = [0xa5; 256];
        assert_eq!(serialized_len(records)?, expected.len());
        let size = serialize(records, &mut output)?;
        assert_eq!(&output[..size], expected);
        assert!(output[size..].iter().all(|byte| *byte == 0xa5));
        let set = RecordSet::parse(&output[..size], records.len(), 3)?;
        let found: Result<Vec<_>, _> = set.iter().collect();
        assert_eq!(found?, records);
        assert_eq!(RecordSet::parse_padded(&output[..size], 3)?, set);
    }
    assert_eq!(serialized_len(&[pkey, a])?, 68);
    assert_eq!(serialized_len(&[a, edkey])?, 128);
    Ok(())
}

#[test]
fn destination_selected_padding_matches_c_and_refusal_is_atomic() -> Result<(), Error> {
    let mut output = [0x44; 23];
    assert_eq!(serialize_to_size(&[address()], &mut output)?, 23);
    assert_eq!(&output[..20], &include_bytes!("fixtures/a.bin")[..20]);
    assert_eq!(&output[20..], [0; 3]);
    let before = [0x44; 19];
    let mut too_short = before;
    assert_eq!(address().encode(&mut too_short), Err(Error::Capacity));
    assert_eq!(too_short, before);
    assert_eq!(
        serialize_to_size(&[address()], &mut too_short),
        Err(Error::Capacity)
    );
    assert_eq!(too_short, before);
    let mut canonical_short = [0x66; 31];
    assert_eq!(
        serialize(&[address()], &mut canonical_short),
        Err(Error::Capacity)
    );
    assert_eq!(canonical_short, [0x66; 31]);
    Ok(())
}

#[test]
fn malicious_lengths_padding_and_record_work_are_bounded() -> Result<(), Error> {
    let fixture = include_bytes!("fixtures/a.bin");
    for length in 0..20 {
        assert_eq!(
            RecordData::decode_prefix(&fixture[..length]),
            Err(Error::Truncated)
        );
        assert_eq!(
            RecordSet::parse(&fixture[..length], 1, 1),
            Err(Error::Truncated)
        );
    }
    assert_eq!(RecordSet::parse(fixture, 1, 0), Err(Error::Capacity));
    assert_eq!(RecordSet::parse_padded(fixture, 0), Err(Error::Capacity));
    assert_eq!(RecordSet::parse(fixture, 2, 2), Err(Error::Truncated));
    let mut nonzero_padding = *fixture;
    nonzero_padding[31] = 1;
    assert_eq!(
        RecordSet::parse(&nonzero_padding, 1, 1),
        Err(Error::Malformed)
    );
    assert_eq!(
        RecordSet::parse_padded(&nonzero_padding, 1),
        Err(Error::Truncated)
    );
    let mut zero_header_then_garbage = [0; 17];
    zero_header_then_garbage[16] = 1;
    assert_eq!(
        RecordSet::parse_padded(&zero_header_then_garbage, 1),
        Err(Error::Malformed)
    );
    let huge = [0; 65536];
    let record = RecordData {
        data: &huge,
        ..address()
    };
    let mut output = [0xa5; 64];
    assert_eq!(
        serialize_to_size(&[address(), record], &mut output),
        Err(Error::TooLarge)
    );
    assert_eq!(output, [0xa5; 64]);
    assert!(RecordSet::parse(&[], 0, 0)?.is_empty());
    Ok(())
}

#[test]
fn zero_header_requires_explicit_count_and_extensions_are_preserved() -> Result<(), Error> {
    let zeros = [0; 16];
    assert_eq!(RecordSet::parse_padded(&zeros, 1)?.len(), 0);
    let set = RecordSet::parse(&zeros, 1, 1)?;
    assert_eq!(set.len(), 1);
    let zero_record = set.iter().next().ok_or(Error::NotFound)??;
    assert_eq!(zero_record.record_type, RecordType::new(0));
    let extension = RecordData {
        expiration_time: u64::MAX,
        record_type: RecordType::new(0x12345678),
        flags: RecordFlags::from_bits_preserve(0x1234),
        data: &[4, 5, 6],
    };
    let mut output = [0; 19];
    extension.encode(&mut output)?;
    assert_eq!(RecordData::decode_prefix(&output)?.0, extension);
    assert_eq!(extension.flags.unknown_bits(), 0x1230);
    assert_eq!(RecordType::REDIRECT.value(), 65551);
    assert_eq!(RecordType::GNS2DNS.value(), 65540);
    assert_eq!(RecordType::EDKEY.value(), 65556);
    assert_eq!(RecordFlags::MAINTENANCE.bits(), 0x2000);
    assert_eq!(RecordFlags::RELATIVE_EXPIRATION.bits(), 0x4000);
    assert_eq!(RecordFlags::PRIVATE.bits(), 0x8000);
    assert_eq!(address().validate_fixed_size(), Ok(()));
    assert_eq!(
        RecordData {
            data: &[0; 3],
            ..address()
        }
        .validate_fixed_size(),
        Err(Error::Malformed)
    );
    Ok(())
}

#[test]
fn official_typed_ztld_c_fixtures_match_and_never_use_private_prefix() -> Result<(), Error> {
    let key = core::array::from_fn(|i| i as u8);
    for (kind, expected) in [
        (ZoneKeyType::Pkey, include_bytes!("fixtures/pkey_zone.bin")),
        (
            ZoneKeyType::Edkey,
            include_bytes!("fixtures/edkey_zone.bin"),
        ),
    ] {
        let zone = ZoneKey::new(kind, key);
        let mut output = [0xaa; 60];
        assert_eq!(zone.write_ztld(&mut output)?.as_bytes(), expected);
        assert_eq!(&output[58..], [0xaa; 2]);
        let text = core::str::from_utf8(expected).map_err(|_| Error::Malformed)?;
        assert_eq!(ZoneKey::from_ztld(text)?, zone);
        assert_eq!(ZoneKey::from_wire(&zone.to_wire())?, zone);
        assert_eq!(
            zone.to_wire()[..4],
            kind.record_type().value().to_be_bytes()
        );
        assert!(!text.starts_with("z1-"));
        let lower = text.to_ascii_lowercase();
        assert_eq!(ZoneKey::from_ztld(&lower)?, zone);
        let aliased = text.replace('0', "o").replace('1', "l");
        assert_eq!(ZoneKey::from_ztld(&aliased)?, zone);
        let mut discarded_padding = *expected;
        discarded_padding[57] = b'X';
        assert_eq!(
            ZoneKey::from_ztld(
                core::str::from_utf8(&discarded_padding).map_err(|_| Error::Malformed)?
            )?,
            zone
        );
    }
    Ok(())
}

#[test]
fn malformed_ztld_and_delegation_lengths_are_rejected() -> Result<(), Error> {
    let zone = ZoneKey::new(ZoneKeyType::Edkey, [0xff; 32]);
    let mut short = [0x44; 57];
    assert_eq!(zone.write_ztld(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0x44; 57]);
    let mut text = [0; 58];
    zone.write_ztld(&mut text)?;
    for len in 0..58 {
        assert_eq!(
            ZoneKey::from_ztld(core::str::from_utf8(&text[..len]).map_err(|_| Error::Malformed)?),
            Err(Error::Malformed)
        );
    }
    text[5] = b'!';
    assert_eq!(
        ZoneKey::from_ztld(core::str::from_utf8(&text).map_err(|_| Error::Malformed)?),
        Err(Error::Malformed)
    );
    let mut wire = zone.to_wire();
    wire[..4].copy_from_slice(&123_u32.to_be_bytes());
    assert_eq!(ZoneKey::from_wire(&wire), Err(Error::Unsupported));
    assert_eq!(ZoneKey::from_wire(&[0; 35]), Err(Error::Truncated));
    assert_eq!(ZoneKey::from_wire(&[0; 37]), Err(Error::Malformed));
    assert_eq!(
        ZoneKey::from_record(&RecordData {
            record_type: RecordType::EDKEY,
            data: &[0; 31],
            ..address()
        }),
        Err(Error::Malformed)
    );
    assert_eq!(ZoneKey::from_record(&address()), Err(Error::Unsupported));
    Ok(())
}
