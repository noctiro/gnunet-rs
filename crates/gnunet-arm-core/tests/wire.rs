//! Literal independent packed-byte checks; no C/OS/process execution.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact literal wire bytes and atomic errors."
)]
use gnunet_arm_core::wire::*;
use gnunet_types::Error;
#[test]
fn all_request_assignments_have_exact_packed_layout_and_c_string_rules() -> Result<(), Error> {
    let id = WireId(0x0102030405060708);
    let mut out = [0xa5; 64];
    let n = Request::Start {
        reserved: 0,
        id,
        service: b"svc\0ignored",
    }
    .encode(&mut out)?;
    assert_eq!(
        &out[..n],
        &[
            0, 20, 0, 8, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, b's', b'v', b'c', 0
        ]
    );
    assert_eq!(
        Request::decode(&out[..n])?,
        Request::Start {
            reserved: 0,
            id,
            service: b"svc"
        }
    );
    let n = Request::Stop {
        reserved: 0x12131415,
        id,
        service: b"",
    }
    .encode(&mut out)?;
    assert_eq!(n, 17);
    assert_eq!(&out[..8], &[0, 17, 0, 9, 0x12, 0x13, 0x14, 0x15]);
    assert!(matches!(
        Request::decode(&out[..n])?,
        Request::Stop { service: b"", .. }
    ));
    assert_eq!(Request::List { reserved: 1, id }.encode(&mut out)?, 16);
    assert_eq!(&out[..4], &[0, 16, 0, 12]);
    assert_eq!(Request::Monitor.encode(&mut out)?, 4);
    assert_eq!(&out[..4], &[0, 4, 0, 14]);
    assert_eq!(Request::Test.encode(&mut out)?, 4);
    assert_eq!(&out[..4], &[0, 4, 0, 15]);
    let frame = [
        0, 20, 0, 8, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, b'a', 0, b'x', 0,
    ];
    assert_eq!(
        Request::decode(&frame)?,
        Request::Start {
            reserved: 0x01020304,
            id: WireId(0),
            service: b"a"
        }
    );
    Ok(())
}
#[test]
fn service_request_total65535_legal65536_and_short_buffer_atomic() -> Result<(), Error> {
    let name = vec![b'a'; 65518];
    let req = Request::Start {
        reserved: 0,
        id: WireId(1),
        service: &name,
    };
    let mut out = vec![0xa5; 65535];
    assert_eq!(req.encode(&mut out)?, 65535);
    assert_eq!(&out[..4], &[255, 255, 0, 8]);
    assert!(matches!(Request::decode(&out)?,Request::Start{service,..}if service.len()==65518));
    let long = vec![b'a'; 65519];
    let req = Request::Stop {
        reserved: 0,
        id: WireId(2),
        service: &long,
    };
    let before = out.clone();
    assert_eq!(req.encode(&mut out), Err(Error::TooLarge));
    assert_eq!(out, before);
    let mut tiny = [0xa5; 17];
    assert_eq!(
        Request::Start {
            reserved: 0,
            id: WireId(3),
            service: b"ab"
        }
        .encode(&mut tiny),
        Err(Error::Capacity)
    );
    assert_eq!(tiny, [0xa5; 17]);
    Ok(())
}
#[test]
fn result_and_status_retain_unknown_values_reserved_and_nonutf8() -> Result<(), Error> {
    let bytes = [
        0, 24, 0, 10, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8, 255, 254, 253, 252, 0xaa, 0xbb, 0xcc,
        0xdd,
    ];
    let reply = ResultReply::decode(ArmAbi::U64Align8, &bytes)?;
    assert_eq!(reply.reserved, 0x01020304);
    assert_eq!(reply.result, ResultCode(0xfffefdfc));
    let mut out = [0xa5; 32];
    assert_eq!(reply.encode(ArmAbi::U64Align8, &mut out)?, 24);
    assert_eq!(&out[..20], &bytes[..20]);
    assert_eq!(&out[20..24], &[0; 4]);
    let bytes = [0, 12, 0, 11, 255, 255, 255, 255, 0xff, 0, b'x', 0];
    let s = Status::decode(&bytes)?;
    assert_eq!(s.status, MonitorStatus(u32::MAX));
    assert_eq!(s.service, b"\xff");
    assert_eq!(s.encode(&mut out)?, 10);
    assert_eq!(&out[..10], &[0, 10, 0, 11, 255, 255, 255, 255, 255, 0]);
    Ok(())
}
#[test]
fn list_literal_28_byte_rows_offset_pool_and_unsigned_public_exit() -> Result<(), Error> {
    let bytes = [
        0, 59, 0, 13, 9, 8, 7, 6, 1, 2, 3, 4, 5, 6, 7, 8, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0, 0, 0, 4, 255, 255, 0xaa, 0xbb, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0,
        10, b's', b'v', b'c', 0, b'b', b'n', 0,
    ];
    let list = List::decode(ArmAbi::U64Align8, &bytes)?;
    assert_eq!(list.len(), 1);
    assert_eq!(list.id()?, WireId(0x0102030405060708));
    assert_eq!(list.reserved()?, 0x09080706);
    let row = list.get(0)?.ok_or(Error::NotFound)?;
    assert_eq!(
        row,
        ServiceInfo {
            name: b"svc",
            binary: b"bn",
            status: ServiceStatus::FAILED,
            last_exit_status: 65535,
            restart_at: 9,
            last_started_at: 10
        }
    );
    assert_eq!(row.public_exit_status(), 65535);
    assert_eq!(list.get(1)?, None);
    let mut out = [0; 59];
    assert_eq!(list.encode(&mut out)?, 59);
    assert_eq!(out, bytes);
    Ok(())
}
#[test]
fn list_accepts_middle_string_shared_pool_unused_bytes_and_zero_count() -> Result<(), Error> {
    let mut bytes = [0u8; 60];
    bytes[..4].copy_from_slice(&[0, 60, 0, 13]);
    bytes[17] = 1;
    bytes[25] = 1;
    bytes[27] = 1;
    bytes[52..].copy_from_slice(b"abc\0tail");
    let l = List::decode(ArmAbi::U64Align8, &bytes)?;
    let row = l.get(0)?.ok_or(Error::NotFound)?;
    assert_eq!(row.name, b"bc");
    assert_eq!(row.binary, b"bc");
    let bytes = [
        0, 26, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xff, 0xfe,
    ];
    assert!(List::decode(ArmAbi::U64Align8, &bytes)?.is_empty());
    Ok(())
}
#[test]
fn list_encoder_is_packed_canonical_and_preflights_all_rows() -> Result<(), Error> {
    let rows = [ServiceInfo {
        name: b"a",
        binary: b"b",
        status: ServiceStatus(99),
        last_exit_status: 0xabcd,
        restart_at: u64::MAX,
        last_started_at: 0,
    }];
    let mut out = [0xa5; 56];
    assert_eq!(
        encode_list(ArmAbi::U64Align8, WireId(3), &rows, &mut out)?,
        56
    );
    assert_eq!(
        &out[..24],
        &[
            0, 56, 0, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 0, 0, 0
        ]
    );
    assert_eq!(&out[24..36], &[0, 0, 0, 2, 0xab, 0xcd, 0, 0, 0, 0, 0, 99]);
    assert_eq!(&out[52..], b"a\0b\0");
    assert_eq!(
        List::decode(ArmAbi::U64Align8, &out)?.get(0)?,
        Some(rows[0])
    );
    let mut short = [0xa5; 55];
    assert_eq!(
        encode_list(ArmAbi::U64Align8, WireId(3), &rows, &mut short),
        Err(Error::Capacity)
    );
    assert_eq!(short, [0xa5; 55]);
    Ok(())
}
#[test]
fn malformed_registered_frames_are_refused_before_exposing_list_rows() -> Result<(), Error> {
    assert!(Request::decode(&[0, 16, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_err());
    assert!(Request::decode(&[0, 17, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]).is_err());
    assert!(Status::decode(&[0, 9, 0, 11, 0, 0, 0, 0, 1]).is_err());
    let mut l = [0u8; 54];
    l[..4].copy_from_slice(&[0, 54, 0, 13]);
    l[17] = 1;
    l[25] = 2;
    assert!(List::decode(ArmAbi::U64Align8, &l).is_err());
    l[25] = 0;
    l[52] = 1;
    l[53] = 1;
    assert!(List::decode(ArmAbi::U64Align8, &l).is_err());
    l[17] = 2;
    assert!(List::decode(ArmAbi::U64Align8, &l).is_err());
    let r = [
        0, 25, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0,
    ];
    assert_eq!(
        ResultReply::decode(ArmAbi::U64Align8, &r),
        Err(Error::Malformed)
    );
    Ok(())
}
#[test]
fn aggregate_abi_is_explicit_and_does_not_follow_rust_pointer_width() -> Result<(), Error> {
    let r = ResultReply {
        reserved: 0,
        id: WireId(1),
        result: ResultCode::STARTING,
    };
    let mut a = [0xa5; 24];
    assert_eq!(r.encode(ArmAbi::U64Align4, &mut a)?, 20);
    assert_eq!(&a[..4], &[0, 20, 0, 10]);
    assert_eq!(ResultReply::decode(ArmAbi::U64Align4, &a[..20])?, r);
    assert!(ResultReply::decode(ArmAbi::U64Align8, &a[..20]).is_err());
    assert_eq!(encode_list(ArmAbi::U64Align4, WireId(1), &[], &mut a)?, 20);
    assert_eq!(&a[..4], &[0, 20, 0, 13]);
    assert_eq!(&a[18..20], &[0; 2]);
    assert!(List::decode(ArmAbi::U64Align4, &a[..20])?.is_empty());
    assert!(List::decode(ArmAbi::U64Align8, &a[..20]).is_err());
    Ok(())
}
