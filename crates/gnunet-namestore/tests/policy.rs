//! One pure policy model; all addresses/bytes are published non-secret data.
#![forbid(unsafe_code)]
use gnunet_namestore::*;
use gnunet_types::Error;
fn record(kind: RecordType, expiry: u64, flags: u16) -> RecordData<'static> {
    RecordData {
        expiration_time: expiry,
        record_type: kind,
        flags: RecordFlags::from_bits_preserve(flags),
        data: &[],
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "One pure aggregate model asserts canonical text and source-time policy with public mock values"
)]
fn nfc_case_255_shadow_and_private_replacement_floor() -> Result<(), Error> {
    let mut input = [0; 1020];
    let mut normalized = [0; 1020];
    let mut ordering = [0; 1020];
    let mut text = [0; 255];
    let n = normalize_label(
        "E\u{301}".as_bytes(),
        &mut text,
        &mut input,
        &mut normalized,
        &mut ordering,
        255,
    )?;
    assert_eq!(&text[..n], "É".as_bytes());
    let n = normalize_label(
        b"MiXeD",
        &mut text,
        &mut input,
        &mut normalized,
        &mut ordering,
        255,
    )?;
    assert_eq!(&text[..n], b"MiXeD");
    let labels = [b'A'; 255];
    let n = normalize_label(
        &labels,
        &mut text,
        &mut input,
        &mut normalized,
        &mut ordering,
        255,
    )?;
    assert_eq!(n, 255);
    assert_eq!(text, labels);
    let mut indices = [0; 8];
    let rd = [
        record(RecordType::A, 5, 0),
        record(RecordType::A, 20, RecordFlags::SHADOW.bits()),
        record(RecordType::AAAA, 10, 0),
    ];
    assert_eq!(expiration_time(&rd, 0, 0, &mut indices)?, 10);
    let mut slots = [record(RecordType::A, 0, 0); 8];
    let private = [record(RecordType::A, 5000, RecordFlags::PRIVATE.bits())];
    let prepared = prepare_store(
        b"www",
        &private,
        1000,
        100,
        &mut slots,
        &mut indices,
        |_| false,
    )?;
    assert_eq!(prepared.records().len(), 2);
    assert_eq!(prepared.expires(), 1000);
    assert_eq!(prepared.records()[1].record_type, RecordType::TOMBSTONE);
    let mut returned = [record(RecordType::A, 0, 0); 8];
    let hidden = normalize_records(
        b"www",
        prepared.records(),
        100,
        Filter::OMIT_PRIVATE,
        &mut returned,
        &mut indices,
        |_| false,
    )?;
    assert_eq!(hidden.records().len(), 0);
    assert_eq!(hidden.expires(), 1000);
    let mutually_exclusive = [private[0], record(RecordType::PKEY, 5000, 0)];
    assert!(
        normalize_records(
            b"www",
            &mutually_exclusive,
            100,
            Filter::OMIT_PRIVATE,
            &mut returned,
            &mut indices,
            |_| false
        )
        .is_err()
    );
    let ordinary = [record(RecordType::A, 500, 0)];
    let nickname = record(RecordType::NICK, 2000, RecordFlags::PRIVATE.bits());
    let published = append_nickname(b"www", &ordinary, Some(nickname), 100, &mut returned)?;
    assert_eq!(published.len(), 2);
    assert_eq!(published[1].expiration_time, 500);
    assert!(published[1].flags.contains(RecordFlags::SUPPLEMENTAL));
    assert!(!published[1].flags.contains(RecordFlags::PRIVATE));
    for kind in [RecordType::PKEY, RecordType::REDIRECT, RecordType::GNS2DNS] {
        let supplied = [record(kind, 5000, 0), record(RecordType::NICK, 5000, 0)];
        let stored = prepare_store(b"www", &supplied, 0, 100, &mut slots, &mut indices, |_| {
            false
        })?;
        assert_eq!(stored.records().len(), 1);
        assert_eq!(stored.records()[0].record_type, kind);
        assert!(
            normalize_records(
                b"www",
                &supplied,
                100,
                Filter::NONE,
                &mut returned,
                &mut indices,
                |_| false,
            )
            .is_err()
        );
    }
    Ok(())
}
