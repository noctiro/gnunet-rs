#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible disk tests assert durable state and native commit boundaries"
)]
use super::*;
use gnunet_wire::official::AbsoluteTime;
use std::{
    fs,
    io::{Seek, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-datastore-disk-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn policy() -> PutPolicy {
    PutPolicy {
        ceiling_bytes: 1024 * 1024,
        target_bytes: 1024 * 1024,
        now: AbsoluteTime::UNIX_EPOCH,
        max_evictions: 128,
        random: 7,
    }
}
fn input<'a>(
    key: &'a [u8; 64],
    value: &'a [u8],
    kind: u32,
    anonymity: u32,
    priority: u32,
    replication: u32,
    expiration: u64,
) -> Put<'a> {
    Put {
        key,
        value,
        kind,
        anonymity,
        priority,
        replication,
        expiration: AbsoluteTime::from_micros(expiration),
    }
}
fn get(key: &[u8; 64], kind: u32, uid: u64) -> Selection<'_> {
    Selection::Get {
        key: Some(key),
        kind,
        next_uid: uid,
        random: false,
    }
}

#[test]
fn arbitrary_values_merge_original_identity_and_stable_uid_restart() -> TestResult {
    let directory = Directory::new()?;
    let key = [0x71; 64]; // Deliberately unrelated to the value's content digest.
    let value = b"\0arbitrary native value\xff";
    let mut store = Store::open(&directory.0, Limits::default())?;
    assert!(
        store
            .put(input(&key, value, 123, 7, 4, 3, 100), policy())?
            .inserted
    );
    let first = store
        .select(get(&key, 0, 0), 0)?
        .ok_or(ProtocolError::NotFound)?
        .meta;
    assert_eq!(first.uid, 1);
    assert!(
        !store
            .put(
                input(&key, value, u32::MAX, 0, u32::MAX, u32::MAX, 200),
                policy()
            )?
            .inserted
    );
    let record = store
        .select(get(&key, 123, 0), 0)?
        .ok_or(ProtocolError::NotFound)?;
    assert_eq!(record.value, value);
    assert_eq!(record.meta.uid, first.uid);
    assert_eq!(record.meta.kind, 123);
    assert_eq!(record.meta.anonymity, 7);
    assert_eq!(record.meta.priority, u32::MAX);
    assert_eq!(record.meta.replication, u32::MAX);
    assert_eq!(record.meta.expiration, AbsoluteTime::from_micros(200));
    let selected = store
        .select(Selection::Replication, 3)?
        .ok_or(ProtocolError::NotFound)?
        .meta;
    assert_eq!(selected.replication, u32::MAX); // Old score is returned, decrement is durable.
    drop(store);
    let mut store = Store::open(&directory.0, Limits::default())?;
    let meta = store
        .select(get(&key, 123, 1), 0)?
        .ok_or(ProtocolError::NotFound)?
        .meta;
    assert_eq!(meta.uid, first.uid);
    assert_eq!(meta.replication, u32::MAX - 1);
    assert!(store.select(get(&key, 0, first.uid + 1), 0)?.is_none());
    assert!(
        store
            .select(
                Selection::ZeroAnonymity {
                    kind: 123,
                    next_uid: 0
                },
                0
            )?
            .is_none()
    );
    let second_value = b"same key, different bytes";
    store.put(input(&key, second_value, u32::MAX, 0, 1, 0, 300), policy())?;
    let second = store
        .select(
            Selection::ZeroAnonymity {
                kind: u32::MAX,
                next_uid: 0,
            },
            0,
        )?
        .ok_or(ProtocolError::NotFound)?
        .meta;
    assert!(second.uid > first.uid);
    assert!(
        store
            .select(
                Selection::Get {
                    key: Some(&key),
                    kind: 0,
                    next_uid: u64::MAX,
                    random: true
                },
                u64::MAX
            )?
            .is_some()
    );
    assert!(store.remove(&key, value)?);
    store.put(input(&key, b"third", 42, 0, 0, 0, 400), policy())?;
    let third = store
        .select(get(&key, 42, 0), 0)?
        .ok_or(ProtocolError::NotFound)?
        .meta;
    assert!(third.uid > second.uid);
    assert_eq!(store.usage().entries, 2);
    Ok(())
}

#[test]
fn quota_is_atomic_expiry_and_low_priority_reclaim_and_writer_fence() -> TestResult {
    let directory = Directory::new()?;
    let mut store = Store::open(&directory.0, Limits::default())?;
    assert!(Store::open(&directory.0, Limits::default()).is_err());
    for (key, priority, expiry) in [(1_u8, 0, 10), (2, 100, 1000), (3, 1, 1000)] {
        store.put(
            input(&[key; 64], &[key; 8], 9, 0, priority, 0, expiry),
            policy(),
        )?;
    }
    let before = store.usage();
    let one = 8 + gnunet_datastore::backend::ENTRY_OVERHEAD;
    let refused = store.maintain(MaintenancePolicy {
        now: AbsoluteTime::from_micros(20),
        ceiling_bytes: 2 * one,
        target_bytes: 0,
        max_evictions: 0,
    });
    assert_eq!(
        refused
            .err()
            .ok_or(ProtocolError::InvalidInput)?
            .certainty(),
        Failure::BeforeCommit
    );
    assert_eq!(store.usage(), before);
    assert!(store.select(get(&[1; 64], 0, 0), 0)?.is_some()); // Ordinary GET includes expired records.
    let expired = store.maintain(MaintenancePolicy {
        now: AbsoluteTime::from_micros(20),
        ceiling_bytes: 1024 * 1024,
        target_bytes: 2 * one,
        max_evictions: 128,
    })?;
    assert_eq!(expired.removed_entries, 1);
    assert_eq!(expired.min_expiration, Some(AbsoluteTime::from_micros(20)));
    let low = store.maintain(MaintenancePolicy {
        now: AbsoluteTime::from_micros(20),
        ceiling_bytes: one,
        target_bytes: one,
        max_evictions: 128,
    })?;
    assert_eq!(low.removed_entries, 1);
    assert_eq!(low.min_expiration, Some(AbsoluteTime::NEVER));
    assert!(store.select(get(&[2; 64], 9, 0), 0)?.is_some());
    assert!(store.select(get(&[3; 64], 9, 0), 0)?.is_none());
    let before = store.usage();
    let tight = PutPolicy {
        ceiling_bytes: one,
        target_bytes: one,
        max_evictions: 0,
        ..policy()
    };
    assert!(
        store
            .put(input(&[4; 64], &[4; 512], 7, 0, 0, 0, 1000), tight)
            .is_err()
    );
    assert_eq!(store.usage(), before);
    store.checkpoint()?;
    drop(store);
    let mut store = Store::open(&directory.0, Limits::default())?;
    assert_eq!(store.usage(), before);
    assert!(store.select(get(&[2; 64], 9, 0), 0)?.is_some());
    // Start a bounded directory pass, then create a new value. DROP must not
    // reuse an iterator that could miss the later directory entry.
    store.limits.garbage_entries = 1;
    assert!(store.collect_garbage()?.1);
    store.put(input(&[5; 64], b"newvalue", 9, 0, 0, 0, 1000), policy())?;
    store.drop_all()?;
    assert_eq!(store.usage(), Usage::default());
    assert!(fs::read_dir(directory.0.join("values"))?.next().is_none());
    Ok(())
}

#[test]
fn uncertain_wal_is_fenced_until_explicit_recovery_and_complete_corruption_is_not_torn()
-> TestResult {
    let directory = Directory::new()?;
    let limits = Limits {
        checkpoint_bytes: 80,
        ..Limits::default()
    };
    let mut store = Store::open(&directory.0, limits)?;
    store.put(input(&[1; 64], b"base", 77, 0, 0, 0, 100), policy())?;
    let before = store.usage();
    store.test_fault = Some(TestFault::BeforeWal);
    assert_eq!(
        store
            .put(
                input(&[2; 64], b"not committed", 88, 0, 0, 0, 100),
                policy()
            )
            .err()
            .ok_or(ProtocolError::InvalidInput)?
            .certainty(),
        Failure::BeforeCommit
    );
    assert_eq!(store.usage(), before);
    store.test_fault = Some(TestFault::AfterWal);
    let original = store
        .put(input(&[3; 64], b"candidate", 99, 0, 0, 0, 100), policy())
        .err()
        .ok_or(ProtocolError::InvalidInput)?;
    assert_eq!(original.certainty(), Failure::Unknown);
    assert_eq!(store.usage(), before); // Last known usage is not a readiness claim.
    assert_eq!(
        store
            .select(get(&[1; 64], 0, 0), 0)
            .err()
            .ok_or(ProtocolError::InvalidInput)?
            .certainty(),
        Failure::Unknown
    );
    assert!(store.checkpoint().is_err());
    assert!(store.drop_all().is_err());
    let recovered = store.recover()?;
    assert_eq!(recovered.candidate_committed, Some(true));
    assert_eq!(
        store
            .last_uncertainty()
            .ok_or(ProtocolError::NotFound)?
            .stage,
        original.stage
    );
    assert!(store.select(get(&[2; 64], 0, 0), 0)?.is_none());
    let candidate = store
        .select(get(&[3; 64], 99, 0), 0)?
        .ok_or(ProtocolError::NotFound)?;
    assert_eq!(candidate.value, b"candidate");
    assert_eq!(candidate.meta.uid, 2);
    // A swapped temporary name must never be published and followed by WAL
    // truncation. The original owned inode and replacement are kept distinct.
    let before_wal = fs::metadata(directory.0.join(files::WAL))?.len();
    let mut temporary = store.files.temporary(false)?;
    codec::write_snapshot(
        &mut temporary.file,
        &store.index.rows,
        store.index.sequence,
        store.index.highwater,
    )?;
    temporary.file.sync_all()?;
    let mut temporary_path = None;
    for entry in fs::read_dir(&directory.0)? {
        let entry = entry?;
        if entry.file_name().as_encoded_bytes().starts_with(b".tmp-") {
            temporary_path = Some(entry.path());
            break;
        }
    }
    let temporary_path = temporary_path.ok_or(ProtocolError::NotFound)?;
    let held = directory.0.join("retained-candidate-sentinel");
    fs::rename(&temporary_path, &held)?;
    let sentinel = fs::read(&held)?;
    fs::write(&temporary_path, b"replacement must not become snapshot")?;
    assert!(store.files.install_snapshot(&mut temporary).is_err());
    assert_eq!(
        fs::metadata(directory.0.join(files::WAL))?.len(),
        before_wal
    );
    assert_eq!(fs::read(&held)?, sentinel);
    assert_eq!(
        fs::read(&temporary_path)?,
        b"replacement must not become snapshot"
    );
    fs::remove_file(&temporary_path)?;
    fs::remove_file(&held)?;
    drop(temporary);
    store.checkpoint()?; // Snapshot can be larger than its WAL checkpoint trigger.
    drop(store);
    // An incomplete final header is an uncommitted tail, distinct from the
    // complete corrupt footer checked below.
    let mut partial = fs::OpenOptions::new()
        .append(true)
        .open(directory.0.join(files::WAL))?;
    partial.write_all(b"GDWAL00")?;
    partial.sync_all()?;
    drop(partial);
    let mut store = Store::open(&directory.0, limits)?;
    assert_eq!(fs::metadata(directory.0.join(files::WAL))?.len(), 0);
    assert!(store.select(get(&[3; 64], 99, 0), 0)?.is_some());
    store.put(input(&[4; 64], b"tail", 100, 0, 0, 0, 100), policy())?;
    drop(store);
    let wal = directory.0.join(files::WAL);
    let mut file = fs::OpenOptions::new().write(true).open(&wal)?;
    file.seek(SeekFrom::End(-1))?;
    file.write_all(b"!")?;
    file.sync_all()?;
    assert!(Store::open(&directory.0, limits).is_err()); // Complete bad footer is corruption.
    Ok(())
}
