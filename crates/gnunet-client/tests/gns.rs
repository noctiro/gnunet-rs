//! Official lookup framing and logical/physical query boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Independent wire and ownership assertions reject malformed or stale observations"
)]
use gnunet_client::gns::{
    self, Client, Instance, LocalOptions, Lookup, LookupResult, Parameters, Received, WireId,
};
use gnunet_gnsrecord::{RecordData, RecordFlags, RecordType, ZoneKey, ZoneKeyType};
use gnunet_types::Error;
fn parameters() -> Parameters {
    Parameters {
        zone: ZoneKey::new(ZoneKeyType::Edkey, [42; 32]),
        options: LocalOptions::LOCAL_MASTER,
        recursion_depth: 512,
        record_type: RecordType::new(0xfedc_ba98),
    }
}
fn reply(id: WireId) -> Result<Vec<u8>, Error> {
    let record = RecordData {
        expiration_time: 0x1234_5678_90ab_cdef,
        record_type: RecordType::new(0xabcd_1234),
        flags: RecordFlags::from_bits_preserve(0x8123),
        data: b"original-record",
    };
    let mut bytes = vec![0; 256];
    let n = gns::encode_result(id, &[record], &mut bytes)?;
    bytes.truncate(n);
    Ok(bytes)
}
#[test]
fn exact_lookup_extents_full_bits_and_original_name_without_normalization() -> Result<(), Error> {
    let mut p = parameters();
    p.options = LocalOptions::from_bits(0xfedc);
    let name = "MiXeD.cafe\u{301}".as_bytes();
    let q = Lookup::new(WireId([0, 0, 0, 0]), p, name)?;
    let mut bytes = [0xa5; 512];
    let n = q.encode(&mut bytes)?;
    assert_eq!(&bytes[..4], &[(n >> 8) as u8, n as u8, 1, 244]);
    assert_eq!(&bytes[4..8], &[0; 4]);
    assert_eq!(&bytes[8..10], &0xfedc_u16.to_be_bytes());
    assert_eq!(&bytes[10..12], &512_u16.to_be_bytes());
    assert_eq!(&bytes[12..16], &0xfedc_ba98_u32.to_be_bytes());
    assert_eq!(&bytes[16..20], &36_u32.to_be_bytes());
    assert_eq!(&bytes[20..56], &p.zone.to_wire());
    assert_eq!(&bytes[56..n - 1], name);
    assert_eq!(bytes[n - 1], 0);
    assert!(bytes[n..].iter().all(|b| *b == 0xa5));
    assert_eq!(Lookup::decode(&bytes[..n])?, q);
    let mut too_small = vec![0xa5; n - 1];
    assert_eq!(q.encode(&mut too_small), Err(Error::Capacity));
    assert!(too_small.iter().all(|b| *b == 0xa5));
    Ok(())
}
#[test]
fn malformed_zone_name_and_lengths_are_bounded_before_access() -> Result<(), Error> {
    let q = Lookup::new(WireId::from_counter(u32::MAX), parameters(), b"label")?;
    let mut bytes = vec![0; q.encoded_len()];
    q.encode(&mut bytes)?;
    for n in 0..bytes.len() {
        assert!(Lookup::decode(&bytes[..n]).is_err());
    }
    let mut bad = bytes.clone();
    bad[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(Lookup::decode(&bad).is_err());
    let mut bad = bytes.clone();
    bad[16..20].copy_from_slice(&0_u32.to_be_bytes());
    assert!(Lookup::decode(&bad).is_err());
    let mut bad = bytes.clone();
    let end = bad.len() - 1;
    bad[end] = 1;
    assert!(Lookup::decode(&bad).is_err());
    let mut bad = bytes.clone();
    bad[57] = 0;
    assert!(Lookup::decode(&bad).is_err());
    assert!(Lookup::new(WireId([0; 4]), parameters(), &[b'a'; 252]).is_ok());
    assert_eq!(
        Lookup::new(WireId([0; 4]), parameters(), &[b'a'; 253]),
        Err(Error::TooLarge)
    );
    assert!(Lookup::new(WireId([0; 4]), parameters(), b"a\0b").is_err());
    Ok(())
}
#[test]
fn records_are_structural_counted_and_canonically_padded() -> Result<(), Error> {
    let bytes = reply(WireId([0xff, 0, 1, 2]))?;
    let result = LookupResult::decode(&bytes, 1)?;
    assert_eq!(result.id(), WireId([0xff, 0, 1, 2]));
    assert_eq!(result.records().len(), 1);
    let r = result.records().iter().next().ok_or(Error::NotFound)??;
    assert_eq!(r.flags.bits(), 0x8123);
    assert_eq!(r.record_type.value(), 0xabcd_1234);
    assert_eq!(r.data, b"original-record");
    assert_eq!(LookupResult::decode(&bytes, 0), Err(Error::Capacity));
    let mut bad = bytes.clone();
    bad[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(LookupResult::decode(&bad, 4096), Err(Error::Capacity));
    let mut bad = bytes.clone();
    let end = bad.len() - 1;
    bad[end] = 1;
    assert!(LookupResult::decode(&bad, 1).is_err());
    let mut empty = [0xa5; 16];
    let n = gns::encode_result(WireId([0; 4]), &[], &mut empty)?;
    assert_eq!(n, 12);
    assert!(LookupResult::decode(&empty[..n], 0)?.records().is_empty());
    Ok(())
}
#[test]
fn interleaved_original_queries_settle_only_after_full_local_writing() -> Result<(), Error> {
    let mut storage = Instance::new();
    let mut client = Client::<4, 32>::new(&mut storage)?;
    let a = client.lookup(parameters(), b"alpha")?;
    let b = client.lookup(parameters(), b"beta")?;
    let epoch = client.begin_connection()?;
    let out_a = client.outbound(epoch)?.ok_or(Error::NotReady)?;
    let out_b = client.outbound(epoch)?.ok_or(Error::NotReady)?;
    assert_eq!(out_a.query(), a);
    assert_eq!(out_b.query(), b);
    assert_eq!(Lookup::decode(out_a.bytes())?.id(), WireId([0; 4]));
    let first_reply = reply(Lookup::decode(out_a.bytes())?.id())?;
    assert_eq!(client.receive(epoch, &first_reply, 4)?, Received::Unmatched);
    client.written(out_a.attempt())?;
    client.written(out_b.attempt())?;
    let second_reply = reply(Lookup::decode(out_b.bytes())?.id())?;
    assert!(
        matches!(client.receive(epoch,&second_reply,4)?,Received::Answer {query,..} if query==b)
    );
    assert!(!client.live(b));
    assert!(client.live(a));
    assert!(
        matches!(client.receive(epoch,&first_reply,4)?,Received::Answer {query,..} if query==a)
    );
    assert_eq!(client.pending_queries(), 0);
    assert_eq!(client.receive(epoch, &first_reply, 4)?, Received::Unmatched);
    Ok(())
}
#[test]
fn cancel_of_original_admitted_frame_retains_debt_without_inventing_cancel_wire()
-> Result<(), Error> {
    let mut storage = Instance::new();
    let mut client = Client::<1, 32>::new(&mut storage)?;
    let query = client.lookup(parameters(), b"original")?;
    let epoch = client.begin_connection()?;
    let frame = client.outbound(epoch)?.ok_or(Error::NotReady)?;
    let original = frame.bytes().to_vec();
    client.cancel(query)?;
    assert!(!client.live(query));
    assert_eq!(client.pending_queries(), 0);
    assert_eq!(client.pending_writes(), 1);
    assert_eq!(client.lookup(parameters(), b"next"), Err(Error::WouldBlock));
    assert!(client.outbound(epoch)?.is_none());
    let response = reply(Lookup::decode(frame.bytes())?.id())?;
    assert_eq!(client.receive(epoch, &response, 4)?, Received::Unmatched);
    client.written(frame.attempt())?;
    assert_eq!(frame.bytes(), original);
    assert_eq!(client.pending_writes(), 0);
    assert!(client.lookup(parameters(), b"next").is_ok());
    assert_eq!(client.written(frame.attempt()), Err(Error::Stale));
    Ok(())
}
#[test]
fn lost_mq_reconstructs_only_live_queries_and_retires_original_attempts() -> Result<(), Error> {
    let mut storage = Instance::new();
    let mut client = Client::<3, 32>::new(&mut storage)?;
    let a = client.lookup(parameters(), b"live")?;
    let canceled = client.lookup(parameters(), b"canceled")?;
    let old = client.begin_connection()?;
    let one = client.outbound(old)?.ok_or(Error::NotReady)?;
    let two = client.outbound(old)?.ok_or(Error::NotReady)?;
    client.cancel(canceled)?;
    client.lost(old)?;
    let next = client.begin_connection()?;
    assert_ne!(old, next);
    assert_eq!(client.written(one.attempt()), Err(Error::Stale));
    assert_eq!(client.written(two.attempt()), Err(Error::Stale));
    let replacement = client.outbound(next)?.ok_or(Error::NotReady)?;
    assert_eq!(replacement.query(), a);
    assert_eq!(replacement.bytes(), one.bytes());
    assert!(client.outbound(next)?.is_none());
    let response = reply(Lookup::decode(one.bytes())?.id())?;
    assert_eq!(client.receive(old, &response, 1), Err(Error::Stale));
    client.written(replacement.attempt())?;
    assert!(matches!(client.receive(next,&response,1)?,Received::Answer {query,..}if query==a));
    assert_eq!(client.pending_queries(), 0);
    Ok(())
}
#[test]
fn foreign_tokens_and_bad_record_counts_cannot_settle_current_query() -> Result<(), Error> {
    let mut sa = Instance::new();
    let mut sb = Instance::new();
    let mut a = Client::<1, 16>::new(&mut sa)?;
    let mut b = Client::<1, 16>::new(&mut sb)?;
    let qa = a.lookup(parameters(), b"same")?;
    let qb = b.lookup(parameters(), b"same")?;
    let ea = a.begin_connection()?;
    let eb = b.begin_connection()?;
    let oa = a.outbound(ea)?.ok_or(Error::NotReady)?;
    let ob = b.outbound(eb)?.ok_or(Error::NotReady)?;
    assert_eq!(a.cancel(qb), Err(Error::Stale));
    assert_eq!(a.written(ob.attempt()), Err(Error::Stale));
    assert_eq!(a.lost(eb), Err(Error::Stale));
    a.written(oa.attempt())?;
    let response = reply(Lookup::decode(oa.bytes())?.id())?;
    assert_eq!(a.receive(eb, &response, 1), Err(Error::Stale));
    assert_eq!(a.receive(ea, &response, 0), Err(Error::Capacity));
    assert!(a.live(qa));
    assert!(matches!(a.receive(ea,&response,1)?,Received::Answer {query,..}if query==qa));
    b.close();
    assert_eq!(b.pending_queries(), 0);
    assert_eq!(b.pending_writes(), 0);
    assert_eq!(b.begin_connection(), Err(Error::Closed));
    Ok(())
}
