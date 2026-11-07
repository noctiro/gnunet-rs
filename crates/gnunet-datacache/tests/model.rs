//! One pure local model with openly fabricated opaque data/path metadata.
//! No key generation/import/hash, signature, native I/O or runtime actor.
#![cfg(feature = "alloc")]
use core::ops::ControlFlow;
use gnunet_datacache::{
    ANY, AbsoluteTime as Time, Block, Cache, Evicted, Key, Limits, Memory, PathElement, PutKind,
    PutOutcome, Stats, Storage,
};
use gnunet_types::Error;
fn key(byte: u8) -> Key {
    [byte; 64]
}
fn block<'a>(byte: u8, data: &'a [u8], expiry: u64, path: &'a [PathElement]) -> Block<'a> {
    Block {
        key: key(byte),
        expiration: Time::from_micros(expiry),
        truncation_peer: [0; 32],
        put_path: path,
        data,
        block_type: 5,
        route_options: 0,
    }
}
struct Failing;
impl Storage for Failing {
    type Matches<'a> = core::iter::Empty<Result<Block<'a>, Error>>;
    fn put(&mut self, _: u32, _: Block<'_>, _: Time) -> Result<PutOutcome, Error> {
        Err(Error::Storage)
    }
    fn get(&self, _: Key, _: u32, _: Time) -> Result<Self::Matches<'_>, Error> {
        Err(Error::Io)
    }
    fn get_closest(&self, _: Key, _: u32, _: usize, _: Time) -> Result<Self::Matches<'_>, Error> {
        Err(Error::Io)
    }
    fn expire_before(&mut self, _: Time) -> Result<usize, Error> {
        Err(Error::Storage)
    }
    fn evict_one(&mut self, _: Time) -> Result<Option<Evicted>, Error> {
        Err(Error::Storage)
    }
    fn clear(&mut self) -> Result<usize, Error> {
        Err(Error::Storage)
    }
    fn stats(&self) -> Stats {
        Stats::default()
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The local cache model asserts its public quota, ordering and failure contracts"
)]
fn public_local_cache_contract() -> Result<(), Error> {
    let now = Time::from_micros(50);
    let mut cache = Cache::memory(Limits {
        entries: 8,
        bytes: 16384,
        value_bytes: 256,
        path_elements: 4,
    })?;
    cache.put(9, block(10, b"old", 100, &[]), now)?;
    cache.put(9, block(10, b"fresh", 200, &[]), now)?;
    assert_eq!(cache.count(key(10), ANY, now)?, 2);
    let first = cache
        .get(key(10), 5, now)?
        .next()
        .ok_or(Error::NotFound)??;
    assert_eq!(first.data, b"fresh");
    assert_eq!(
        cache.visit(key(10), ANY, now, |_| ControlFlow::Break(()))?,
        1
    );
    let path = [PathElement {
        signature: [0; 64],
        predecessor: [0; 32],
    }];
    let mut duplicate = block(10, b"old", 80, &path);
    duplicate.truncation_peer = [7; 32];
    duplicate.route_options = 0x80000004;
    assert_eq!(cache.put(3, duplicate, now)?.kind, PutKind::Duplicate);
    let rows: Vec<_> = cache.get(key(10), ANY, now)?.collect::<Result<_, _>>()?;
    assert_eq!(rows[1].expiration, Time::from_micros(100));
    assert!(rows[1].put_path.is_empty());
    assert_eq!(rows[1].truncation_peer, [0; 32]);
    assert_eq!(rows[1].route_options, 0);
    drop(rows);
    assert_eq!(cache.count(key(10), ANY, Time::from_micros(100))?, 2);
    assert_eq!(cache.count(key(10), ANY, Time::from_micros(101))?, 1);
    assert_eq!(cache.expire_before(Time::from_micros(101))?, 1);
    cache.put(9, block(20, b"next", 200, &[]), now)?;
    cache.put(9, block(30, b"last", 200, &[]), now)?;
    let closest: Vec<_> = cache
        .get_closest(key(15), ANY, 3, now)?
        .map(|v| v.map(|b| b.key))
        .collect::<Result<_, _>>()?;
    assert_eq!(closest, vec![key(20), key(30), key(10)]);
    assert_eq!(cache.get_closest(key(20), ANY, 0, now)?.count(), 0);
    let before = cache.stats();
    assert_eq!(
        cache.put(0, block(1, b"expired", 49, &[]), now),
        Err(Error::Timeout)
    );
    assert_eq!(cache.stats(), before);
    let large = [0; 257];
    assert_eq!(
        cache.put(0, block(1, &large, 300, &[]), now),
        Err(Error::TooLarge)
    );
    assert_eq!(cache.stats(), before);

    let policy = Limits {
        entries: 2,
        bytes: 8192,
        value_bytes: 256,
        path_elements: 0,
    };
    let fixed = Memory::new(policy)?.stats().metadata_bytes;
    let mut bounded = Cache::memory(Limits {
        bytes: fixed + 2,
        ..policy
    })?;
    bounded.put(7, block(1, b"a", 100, &[]), now)?;
    bounded.put(2, block(2, b"b", 200, &[]), now)?;
    let admitted = bounded.put(9, block(3, b"c", 200, &[]), now)?;
    assert_eq!(admitted.evicted, 1);
    assert_eq!(bounded.count(key(2), ANY, now)?, 0);
    assert_eq!(bounded.count(key(1), ANY, now)?, 1);
    bounded.put(1, block(4, b"d", 200, &[]), Time::from_micros(101))?;
    assert_eq!(bounded.count(key(1), ANY, now)?, 0);
    assert_eq!(bounded.stats().expired, 1);
    assert!(bounded.stats().accounted_bytes() <= fixed + 2);
    assert_eq!(bounded.clear()?, 2);
    assert_eq!(bounded.stats().data_bytes, 0);
    assert_eq!(bounded.stats().entries, 0);
    // A replaceable backend failure cannot become a fabricated cache miss.
    let failure = Cache::new(Failing);
    assert_eq!(failure.count(key(0), ANY, now), Err(Error::Io));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Opaque metadata sequence asserts one coherent original context"
)]
fn duplicate_selects_one_complete_expiry_and_path_context() -> Result<(), Error> {
    let now = Time::from_micros(50);
    let mut cache = Cache::memory(Limits {
        entries: 2,
        bytes: 8192,
        value_bytes: 64,
        path_elements: 4,
    })?;
    // Public opaque tags only; these are not cryptographic signatures or keys.
    let original_path = [PathElement {
        signature: [11; 64],
        predecessor: [12; 32],
    }];
    let replacement_path = [PathElement {
        signature: [21; 64],
        predecessor: [22; 32],
    }; 2];
    let mut original = block(31, b"same", 100, &original_path);
    original.truncation_peer = [13; 32];
    original.route_options = 0x80000004;
    cache.put(1, original, now)?;
    let before = cache.stats();
    let mut incoming = block(31, b"same", 80, &replacement_path);
    incoming.truncation_peer = [23; 32];
    incoming.route_options = 0x40000004;
    let outcome = cache.put(2, incoming, now)?;
    assert_eq!(outcome.kind, PutKind::Duplicate);
    assert_eq!(outcome.evicted, 0);
    let retained = cache
        .get(key(31), ANY, now)?
        .next()
        .ok_or(Error::NotFound)??;
    assert_eq!(retained.expiration, Time::from_micros(100));
    assert_eq!(retained.put_path, &original_path);
    assert_eq!(retained.truncation_peer, [13; 32]);
    assert_eq!(retained.route_options, 0x80000004);
    assert_eq!(cache.stats().path_bytes, before.path_bytes);
    assert_eq!(cache.stats().data_bytes, before.data_bytes);
    assert_eq!(cache.stats().entries, 1);
    incoming.expiration = Time::from_micros(100);
    assert_eq!(cache.put(2, incoming, now)?.kind, PutKind::Duplicate);
    let equal = cache
        .get(key(31), ANY, now)?
        .next()
        .ok_or(Error::NotFound)??;
    assert_eq!(equal.expiration, Time::from_micros(100));
    assert_eq!(equal.put_path, &replacement_path);
    assert_eq!(equal.truncation_peer, [23; 32]);
    assert_eq!(equal.route_options, 0x40000004);
    original.expiration = Time::from_micros(120);
    assert_eq!(cache.put(3, original, now)?.kind, PutKind::Duplicate);
    let newer = cache
        .get(key(31), ANY, now)?
        .next()
        .ok_or(Error::NotFound)??;
    assert_eq!(newer.expiration, Time::from_micros(120));
    assert_eq!(newer.put_path, &original_path);
    assert_eq!(newer.truncation_peer, [13; 32]);
    assert_eq!(newer.route_options, 0x80000004);
    assert_eq!(cache.stats().duplicates, 3);
    Ok(())
}
