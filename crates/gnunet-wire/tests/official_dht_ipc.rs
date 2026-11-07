//! Local DHT IPC boundaries, distinct from block/path validation.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible regressions assert independent protocol bytes and original-owner transitions."
)]
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    dht::{Path, ipc::*},
};

#[test]
fn get_and_put_keep_original_widths_and_id_bytes() -> Result<(), Error> {
    let key = [0x42; 64];
    let id = RequestId([1, 2, 3, 4, 5, 6, 7, 8]);
    let mut out = [0; 256];
    let get = Get {
        options: 0xFEDC_BA98,
        replication: u32::MAX,
        block_type: 0,
        key: &key,
        id,
        extended_query: b"x",
    };
    let n = get.encode(&mut out)?;
    assert_eq!(n, 89);
    assert_eq!(&out[4..8], &0xFEDC_BA98u32.to_be_bytes());
    assert_eq!(&out[80..88], &id.0);
    assert_eq!(Request::decode(&out[..n])?, Request::Get(get));
    let put = Put {
        block_type: 8,
        options: 3,
        replication: 7,
        expiration: AbsoluteTime::from_micros(0x0102_0304_0506_0708),
        key: &key,
        payload: b"abc",
    };
    let n = put.encode(&mut out)?;
    assert_eq!(n, 91);
    assert_eq!(&out[16..24], &0x0102_0304_0506_0708u64.to_be_bytes());
    assert_eq!(&out[24..88], &key);
    assert_eq!(Request::decode(&out[..n])?, Request::Put(put));
    Ok(())
}
#[test]
fn stop_and_known_have_different_original_field_order() -> Result<(), Error> {
    let key = [2; 64];
    let id = RequestId([9; 8]);
    let hashes = [3; 128];
    let mut out = [0; 256];
    let stop = Stop { id, key: &key };
    let n = stop.encode(&mut out)?;
    assert_eq!(&out[8..16], &id.0);
    assert_eq!(&out[16..80], &key);
    assert_eq!(Request::decode(&out[..n])?, Request::Stop(stop));
    let known = Known {
        key: &key,
        id,
        hashes: Hashes::new(&hashes)?,
    };
    let n = known.encode(&mut out)?;
    assert_eq!(&out[8..72], &key);
    assert_eq!(&out[72..80], &id.0);
    assert_eq!(known.hashes.iter().len(), 2);
    assert_eq!(Request::decode(&out[..n])?, Request::Known(known));
    Ok(())
}
#[test]
fn known_hash_tail_and_reserved_are_checked() -> Result<(), Error> {
    assert_eq!(Hashes::new(&[0; 63]), Err(Error::Malformed));
    let key = [0; 64];
    let mut out = [0; 81];
    Stop {
        id: RequestId([0; 8]),
        key: &key,
    }
    .encode(&mut out)?;
    out[4] = 1;
    assert_eq!(Request::decode(&out[..80]), Err(Error::InvalidInput));
    out[4] = 0;
    out[..2].copy_from_slice(&81u16.to_be_bytes());
    out[2..4].copy_from_slice(&156u16.to_be_bytes());
    assert_eq!(Request::decode(&out), Err(Error::Malformed));
    Ok(())
}
#[test]
fn monitor_filter_zero_key_is_not_absent() -> Result<(), Error> {
    let key = [0; 64];
    let mut out = [0; 80];
    let m = Monitor {
        block_type: 0,
        get: 0x0102,
        get_response: 1,
        put: 0,
        key: Some(&key),
    };
    m.encode(false, &mut out)?;
    assert_eq!(&out[14..16], &[0, 1]);
    assert_eq!(Request::decode(&out)?, Request::MonitorStart(m));
    m.encode(true, &mut out)?;
    assert_eq!(Request::decode(&out)?, Request::MonitorStop(m));
    Ok(())
}
#[test]
fn empty_hello_reply_is_distinct_from_empty_offered_url() -> Result<(), Error> {
    let mut out = [0; 128];
    let n = encode_hello(None, true, &mut out)?;
    assert_eq!(Request::decode(&out[..n])?, Request::HelloGet);
    let n = encode_hello(None, false, &mut out)?;
    assert_eq!(n, 4);
    assert_eq!(Request::decode(&out[..n])?, Request::HelloUrl(None));
    let n = encode_hello(Some(b""), false, &mut out)?;
    assert_eq!(n, 5);
    assert_eq!(Request::decode(&out[..n])?, Request::HelloUrl(Some(b"")));
    Ok(())
}
#[test]
fn no_put_ack_or_private_type_is_invented() {
    assert_eq!(Request::decode(&[0, 4, 0, 152]), Err(Error::Unsupported));
    assert_eq!(Request::decode(&[0, 4, 0, 145]), Err(Error::Unsupported));
}
#[test]
fn result_keeps_query_id_and_complete_signed_paths() -> Result<(), Error> {
    let key = [7; 64];
    let peer = [9; 32];
    let path = [4; 96];
    let id = RequestId([0xAA; 8]);
    let msg = ResultMessage {
        block_type: 13,
        options: 10,
        put_path: Path::new(&path)?,
        get_path: Path::new(&path)?,
        id,
        expiration: AbsoluteTime::from_micros(15),
        key: &key,
        truncated_peer: Some(&peer),
        payload: b"block",
    };
    let mut out = [0; 512];
    let n = msg.encode(&mut out)?;
    assert_eq!(n, 333);
    assert_eq!(&out[24..32], &id.0);
    assert_eq!(ResultMessage::decode(&out[..n])?, msg);
    Ok(())
}
#[test]
fn invalid_result_metadata_refuses_before_output_mutation() -> Result<(), Error> {
    let key = [0; 64];
    let msg = ResultMessage {
        block_type: 8,
        options: 8,
        put_path: Path::empty(),
        get_path: Path::empty(),
        id: RequestId([0; 8]),
        expiration: AbsoluteTime::from_micros(1),
        key: &key,
        truncated_peer: None,
        payload: b"x",
    };
    let mut out = [0xA5; 128];
    assert_eq!(msg.encode(&mut out), Err(Error::InvalidInput));
    assert!(out.iter().all(|x| *x == 0xA5));
    Ok(())
}
#[test]
fn short_output_refuses_atomically() -> Result<(), Error> {
    let key = [0; 64];
    let msg = Put {
        block_type: 8,
        options: 0,
        replication: 1,
        expiration: AbsoluteTime::from_micros(1),
        key: &key,
        payload: b"x",
    };
    let mut out = [0xA5; 88];
    assert_eq!(msg.encode(&mut out), Err(Error::Capacity));
    assert!(out.iter().all(|x| *x == 0xA5));
    Ok(())
}
#[test]
fn oversized_hello_is_not_silently_truncated() {
    let url = [b'x'; 65531];
    let mut out = [0xA5; 12];
    assert_eq!(
        encode_hello(Some(&url), false, &mut out),
        Err(Error::TooLarge)
    );
    assert!(out.iter().all(|x| *x == 0xA5));
}
#[test]
fn malformed_hello_terminator_is_not_accepted() {
    assert_eq!(
        Request::decode(&[0, 6, 0, 159, b'x', b'y']),
        Err(Error::Malformed)
    );
    assert_eq!(
        Request::decode(&[0, 7, 0, 159, 0, b'x', 0]),
        Err(Error::Malformed)
    );
}
#[test]
fn every_fixed_control_truncation_is_refused() -> Result<(), Error> {
    let key = [0; 64];
    let mut out = [0; 80];
    Stop {
        id: RequestId([0; 8]),
        key: &key,
    }
    .encode(&mut out)?;
    for n in 0..80 {
        assert!(Request::decode(&out[..n]).is_err());
    }
    Ok(())
}
#[test]
fn actual_monitor_get_is_fixed_without_a_private_path() -> Result<(), Error> {
    let key = [4; 64];
    let m = MonitorGet {
        options: 3,
        block_type: 8,
        hop_count: 4,
        replication: 5,
        key: &key,
    };
    let mut out = [0; 89];
    let n = m.encode(&mut out)?;
    assert_eq!(n, 88);
    assert_eq!(MonitorGet::decode(&out[..n])?, m);
    out[..2].copy_from_slice(&89u16.to_be_bytes());
    assert_eq!(MonitorGet::decode(&out), Err(Error::InvalidInput));
    Ok(())
}
#[test]
fn monitor_put_and_result_metadata_round_trip() -> Result<(), Error> {
    let key = [1; 64];
    let peer = [2; 32];
    let path = [3; 96];
    let mut out = [0; 512];
    let p = MonitorPut {
        options: 10,
        block_type: 8,
        hop_count: 1,
        replication: 2,
        expiration: AbsoluteTime::from_micros(90),
        key: &key,
        truncated_peer: Some(&peer),
        put_path: Path::new(&path)?,
        payload: b"abc",
    };
    let n = p.encode(&mut out)?;
    assert_eq!(n, 227);
    assert_eq!(MonitorPut::decode(&out[..n])?, p);
    let r = MonitorResult {
        block_type: 8,
        options: 10,
        put_path: Path::new(&path)?,
        get_path: Path::new(&path)?,
        expiration: p.expiration,
        key: &key,
        truncated_peer: Some(&peer),
        payload: b"abc",
    };
    let n = r.encode(&mut out)?;
    assert_eq!(n, 323);
    assert_eq!(MonitorResult::decode(&out[..n])?, r);
    Ok(())
}

#[test]
fn core_wrapper_adds_only_the_official_header_and_has_no_peer_authority() -> Result<(), Error> {
    use gnunet_wire::official::dht::CoreEnvelope;
    let inner = [0, 4, 0, 157];
    let wrapped = CoreEnvelope::new(&inner)?;
    let mut output = [0; 8];
    assert_eq!(wrapped.encode(&mut output)?, 8);
    assert_eq!(output, [0, 8, 0, 158, 0, 4, 0, 157]);
    assert_eq!(CoreEnvelope::decode(&output)?.inner(), inner);
    assert!(CoreEnvelope::new(&[0, 4, 0, 157, 0]).is_err());
    let mut short = [0xa5; 7];
    assert_eq!(wrapped.encode(&mut short), Err(Error::Capacity));
    assert_eq!(short, [0xa5; 7]);
    assert!(CoreEnvelope::decode(&[0, 4, 0, 158]).is_err());
    let mut big = vec![0; 65535];
    big[..4].copy_from_slice(&[255, 255, 0, 157]);
    assert_eq!(CoreEnvelope::new(&big), Err(Error::TooLarge));
    Ok(())
}
