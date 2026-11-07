//! One actual-filesystem reservation model; no C/node interoperability claim.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible disk model asserts actual lock, committed ranges, restart rollback, original uncertainty and exact public-peer ownership"
)]
use super::*;
use gnunet_types::Error as ProtocolError;
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gnrs-cadet-monotime-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn identity_namespaces_restore_original_floor_and_hold_original_range_lock()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = Directory::new()?;
    let stem = dir.0.join("monotime");
    let mut first = Store::open_for_peer(&stem, [1; 32])?;
    let mut original = first.reserve(100, 4)?;
    assert_eq!(original.take_next()?, 100);
    drop(first);
    // A live original range still holds its actual writer lease, even after
    // its Store owner drops. Another PID neither steals nor resets that fence.
    assert!(Store::open_for_peer(&stem, [1; 32]).is_err());
    let mut second = Store::open_for_peer(&stem, [2; 32])?;
    assert_eq!(second.next(3)?, 3);
    drop(second);
    drop(original);
    let mut restored = Store::open_for_peer(&stem, [1; 32])?;
    assert_eq!(restored.high_water()?, Some(103));
    assert_eq!(restored.next(1)?, 104);
    drop(restored);
    let mut second = Store::open_for_peer(&stem, [2; 32])?;
    assert_eq!(second.next(0)?, 4);
    Ok(())
}

#[test]
fn durable_reservations_survive_rollback_burn_unknown_and_refuse_foreign_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = Directory::new()?;
    let path = dir.0.join("monotime");
    let local = [7; 32];
    let mut store = Store::open(path.clone(), local)?;
    assert_eq!(store.local(), local);
    assert_eq!(store.high_water()?, None);
    assert!(Store::open(path.clone(), local).is_err());
    let mut reserved = store.reserve(100, 4)?;
    assert_eq!(reserved.local(), local);
    assert_eq!(reserved.remaining(), 4);
    assert_eq!(reserved.take_next()?, 100);
    assert_eq!(store.high_water()?, Some(103));
    // Unused101..103 stay burned even though their owner is dropped.
    drop(reserved);
    drop(store);
    let mut store = Store::open(path.clone(), local)?;
    assert_eq!(store.next(2)?, 104);
    let mut range = store.reserve(1, 2)?;
    assert_eq!(range.take_next()?, 105);
    assert_eq!(range.take_next()?, 106);
    assert_eq!(range.remaining(), 0);
    assert_eq!(range.take_next(), Err(ProtocolError::NotReady));
    // Actual rename happened; inject the observation boundary failure before
    // its directory durability call. No range/timestamp escapes this failure.
    let failed = store.reserve_observed(0, 3, || {
        Err(io::Error::other("after-rename observation failure"))
    });
    assert!(matches!(
        failed,
        Err(Error {
            outcome: Outcome::Unknown,
            ..
        })
    ));
    assert!(matches!(
        store.high_water(),
        Err(Error {
            outcome: Outcome::Unknown,
            ..
        })
    ));
    assert!(matches!(
        store.reserve(0, 1),
        Err(Error {
            outcome: Outcome::Unknown,
            ..
        })
    ));
    store.reconcile()?;
    assert_eq!(store.high_water()?, Some(109));
    assert_eq!(store.next(0)?, 110);
    drop(store);
    assert!(Store::open(path.clone(), [8; 32]).is_err());
    let mut store = Store::open(path.clone(), local)?;
    // The final u64 value may be committed once, never wraps on the next call.
    assert_eq!(store.next(u64::MAX)?, u64::MAX);
    assert!(matches!(
        store.next(0),
        Err(Error {
            stage: Stage::Reserve,
            outcome: Outcome::NotCommitted,
            ..
        })
    ));
    assert_eq!(store.high_water()?, Some(u64::MAX));
    drop(store);
    let mut file = OpenOptions::new().append(true).open(&path)?;
    file.write_all(&[0])?;
    file.sync_all()?;
    drop(file);
    assert!(Store::open(path, local).is_err());
    // Outstanding in-memory ranges keep the actual writer fence alive. A
    // newer range cannot make an older range emit a descending timestamp.
    let ordered_path = dir.0.join("ordered");
    let mut ordered = Store::open(ordered_path.clone(), local)?;
    let mut older = ordered.reserve(10, 2)?;
    let mut newer = ordered.reserve(20, 1)?;
    assert_eq!(newer.take_next()?, 20);
    assert_eq!(older.take_next(), Err(ProtocolError::StaleGeneration));
    assert_eq!(older.remaining(), 0);
    let mut retained = ordered.reserve(21, 2)?;
    drop(ordered);
    assert!(Store::open(ordered_path.clone(), local).is_err());
    assert_eq!(retained.take_next()?, 21);
    assert_eq!(retained.take_next()?, 22);
    let mut reopened = Store::open(ordered_path, local)?;
    assert_eq!(reopened.next(0)?, 23);
    Ok(())
}
