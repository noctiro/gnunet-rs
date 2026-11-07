//! Exact source-derived cache policy; no system/native lookup is performed.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Pure cache fixtures assert literal source ordering, TTL and storage contracts."
)]
use gnunet_dns::AbsoluteTime;
mod support;
use gnunet_types::Error;
use support::{CacheMemory, Hit, StoredRecord};
type R = StoredRecord<32, 16>;
fn raw(name: &[u8], value: u8, expiry: u64) -> Result<R, Error> {
    R::raw(name, 1, 7, expiry, &[value; 4])
}
#[test]
fn section_prepend_keeps_duplicates_class_and_reverse_section_order() -> Result<(), Error> {
    let mut memory = CacheMemory::<0, 8, 16, 32, 16>::new()?;
    let mut c = memory.view()?;
    c.begin_batch()?;
    for value in [1, 2, 3, 4] {
        c.insert(b"query", raw(b"query", value, 100)?)?;
    }
    let mut rows = Vec::new();
    assert_eq!(
        c.lookup(b"query", 255, AbsoluteTime::from_micros(1), |r| {
            rows.push((r.raw_bytes()[0], r.class()));
            Ok(())
        })?,
        Hit::Rows
    );
    assert_eq!(rows, vec![(4, 7), (3, 7), (2, 7), (1, 7)]);
    c.insert(b"query", raw(b"query", 4, 100)?)?;
    assert_eq!(c.record_count(), 5);
    Ok(())
}
#[test]
fn bucket_insertion_ignores_ascii_case_while_lookup_and_owner_remain_exact() -> Result<(), Error> {
    let mut memory = CacheMemory::<0, 4, 8, 32, 16>::new()?;
    let mut c = memory.view()?;
    c.insert(b"Query", raw(b"Query", 1, 100)?)?;
    c.insert(b"query", raw(b"query", 2, 100)?)?;
    assert_eq!(c.bucket_count(), 1);
    let mut rows = Vec::new();
    assert_eq!(
        c.lookup(b"query", 1, AbsoluteTime::from_micros(0), |r| {
            rows.push(r.raw_bytes()[0]);
            Ok(())
        })?,
        Hit::Miss
    );
    assert!(rows.is_empty());
    assert_eq!(
        c.lookup(b"Query", 1, AbsoluteTime::from_micros(0), |r| {
            rows.push(r.raw_bytes()[0]);
            Ok(())
        })?,
        Hit::Rows
    );
    assert_eq!(rows, vec![1]);
    Ok(())
}
#[test]
fn ttl_equality_is_valid_expiry_prunes_visited_buckets_only() -> Result<(), Error> {
    let mut memory = CacheMemory::<0, 8, 8, 32, 16>::new()?;
    let mut c = memory.view()?;
    c.insert(b"old", raw(b"old", 1, 0)?)?;
    c.insert(b"wanted", raw(b"wanted", 2, 5)?)?;
    assert_eq!(
        c.lookup(b"wanted", 1, AbsoluteTime::from_micros(5), |_| Ok(()))?,
        Hit::Rows
    );
    assert_eq!(c.bucket_count(), 2); // expired lower bucket not visited
    assert_eq!(
        c.lookup(b"missing", 1, AbsoluteTime::from_micros(6), |_| Ok(()))?,
        Hit::Miss
    );
    assert_eq!((c.bucket_count(), c.record_count()), (0, 0));
    Ok(())
}
#[test]
fn hosts_last_alias_wins_wrong_family_blocks_dynamic_bucket_and_no_ptr_is_synthesized()
-> Result<(), Error> {
    let mut memory = CacheMemory::<4, 4, 8, 32, 16>::new()?;
    let mut c = memory.view()?;
    c.load_hosts(b"127.0.0.1 same\n::1 same\n")?;
    c.insert(b"same", raw(b"same", 9, u64::MAX)?)?;
    assert_eq!(c.host_count(), 2);
    let mut lengths = Vec::new();
    assert_eq!(
        c.lookup(b"same", 255, AbsoluteTime::from_micros(0), |r| {
            lengths.push(r.raw_bytes().len());
            Ok(())
        })?,
        Hit::Rows
    );
    assert_eq!(lengths, vec![16]);
    assert_eq!(
        c.lookup(b"same", 1, AbsoluteTime::from_micros(0), |_| Ok(()))?,
        Hit::Miss
    );
    assert_eq!(
        c.lookup(b"Same", 255, AbsoluteTime::from_micros(0), |_| Ok(()))?,
        Hit::Miss
    );
    assert_eq!(
        c.lookup(
            b"1.0.0.127.in-addr.arpa",
            12,
            AbsoluteTime::from_micros(0),
            |_| Ok(())
        )?,
        Hit::Miss
    );
    Ok(())
}
#[test]
fn cname_precedes_owner_filter_only_until_first_direct_row() -> Result<(), Error> {
    let mut memory = CacheMemory::<0, 4, 8, 32, 16>::new()?;
    let mut c = memory.view()?;
    c.insert(b"q", raw(b"q", 1, 100)?)?;
    c.insert(b"q", R::hostname(b"unrelated", 5, 3, 100, b"target")?)?;
    let mut rows = Vec::new();
    let hit = c.lookup(b"q", 1, AbsoluteTime::from_micros(0), |r| {
        rows.push(r.raw_bytes()[0]);
        Ok(())
    })?;
    assert!(matches!(hit,Hit::Follow(n)if n.bytes()==b"target"));
    assert!(rows.is_empty());
    c.insert(b"q", raw(b"q", 2, 100)?)?;
    assert_eq!(
        c.lookup(b"q", 1, AbsoluteTime::from_micros(0), |r| {
            rows.push(r.raw_bytes()[0]);
            Ok(())
        })?,
        Hit::Rows
    );
    assert_eq!(rows, vec![2, 1]);
    Ok(())
}
#[test]
fn source_1025_bucket_overshoot_and_lru_hit_even_wrong_type_are_exact() -> Result<(), Error> {
    let mut memory = CacheMemory::<0, 1026, 1026, 16, 4>::new()?;
    let mut c = memory.view()?;
    for n in 0..1025 {
        let name = format!("k{n}");
        c.begin_batch()?;
        c.insert(
            name.as_bytes(),
            StoredRecord::raw(name.as_bytes(), 1, 1, u64::MAX, &[1; 4])?,
        )?;
    }
    assert_eq!(c.bucket_count(), 1025);
    assert_eq!(
        c.lookup(b"k0", 28, AbsoluteTime::from_micros(0), |_| Ok(()))?,
        Hit::Miss
    ); // still promoted to LRU head
    c.begin_batch()?;
    assert_eq!(c.bucket_count(), 1024);
    c.insert(b"new", StoredRecord::raw(b"new", 1, 1, u64::MAX, &[2; 4])?)?;
    assert_eq!(c.bucket_count(), 1025);
    assert_eq!(
        c.lookup(b"k1", 1, AbsoluteTime::from_micros(0), |_| Ok(()))?,
        Hit::Miss
    );
    assert_eq!(
        c.lookup(b"k0", 1, AbsoluteTime::from_micros(0), |_| Ok(()))?,
        Hit::Rows
    );
    Ok(())
}
#[test]
fn unsupported_records_survive_without_becoming_address_or_negative_results() -> Result<(), Error> {
    let mut memory = CacheMemory::<0, 2, 4, 32, 16>::new()?;
    let mut c = memory.view()?;
    c.insert(b"q", R::raw(b"q", 65000, 0, 10, b"opaque")?)?;
    assert_eq!(c.record_count(), 1);
    assert_eq!(
        c.lookup(b"q", 255, AbsoluteTime::from_micros(0), |_| Ok(()))?,
        Hit::Miss
    );
    assert_eq!(c.record_count(), 1);
    c.clear()?;
    assert_eq!(c.bucket_count(), 0);
    Ok(())
}
