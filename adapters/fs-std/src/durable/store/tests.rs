//! Focused drafts; not runtime evidence until Root executes them.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible durable-store tests assert exact recovered bytes, original fences and physical file lengths"
)]
use super::*;
use std::os::unix::fs::DirBuilderExt;
use std::sync::atomic::{AtomicU64, Ordering};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Temporary(std::path::PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-wal-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}
fn frame(sequence: u64, kind: u16, body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; format::record_size(body.len())?];
    format::frame(sequence, kind, body, &mut bytes)?;
    Ok(bytes)
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn exact_restart_lock_and_independently_checked_incomplete_tail_repair() -> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("task");
    let mut store = Store::create(&path, Limits::default())?;
    let id = *store.task_id();
    assert_eq!(store.append(9, b"\0native\xffbytes")?, 1);
    assert_eq!(store.append(0, b"")?, 2);
    let locked = match Store::open(&path, Limits::default()) {
        Err(error) => error,
        Ok(_) => return Err("second store acquired the live stable lock".into()),
    };
    assert_eq!(locked.failure().kind, FailureKind::Locked);
    let committed_length = store.wal.metadata()?.len();
    drop(store);
    let candidate = frame(3, 41, b"interrupted record")?;
    // Full independently checked header, but incomplete body/checksum at EOF.
    let torn = &candidate[..format::RECORD_HEADER + 2];
    let mut disk = fs::OpenOptions::new().append(true).open(path.join(WAL))?;
    disk.write_all(torn)?;
    disk.sync_all()?;
    drop(disk);
    let mut reopened = Store::open(&path, Limits::default())?;
    assert_eq!(reopened.task_id(), &id);
    assert_eq!(
        reopened.read_record(0)?,
        Some(RecordView {
            sequence: 1,
            kind: 9,
            bytes: b"\0native\xffbytes"
        })
    );
    assert_eq!(
        reopened.read_record(1)?,
        Some(RecordView {
            sequence: 2,
            kind: 0,
            bytes: b""
        })
    );
    assert!(reopened.read_record(2)?.is_none());
    assert_eq!(reopened.repaired_tail_bytes(), torn.len() as u64);
    assert_eq!(reopened.wal.metadata()?.len(), committed_length);
    assert_eq!(reopened.record_count(), 2);
    assert_eq!(reopened.append(12, b"explicit new append")?, 3);
    drop(reopened);
    let mut reopened = Store::open(&path, Limits::default())?;
    assert_eq!(
        reopened
            .read_record(2)?
            .map(|r| (r.sequence, r.kind, r.bytes)),
        Some((3, 12, b"explicit new append".as_slice()))
    );
    Ok(())
}

#[test]
fn complete_corruption_never_repairs_and_write_error_retains_original_unknown_fence() -> TestResult
{
    let temp = Temporary::new()?;
    let corrupt_path = temp.0.join("corrupt");
    let mut store = Store::create(&corrupt_path, Limits::default())?;
    store.append(1, b"complete")?;
    drop(store);
    let mut disk = fs::OpenOptions::new()
        .write(true)
        .open(corrupt_path.join(WAL))?;
    disk.seek(SeekFrom::Start(
        (format::HEADER + format::RECORD_HEADER) as u64,
    ))?;
    disk.write_all(b"X")?;
    disk.sync_all()?;
    let length = disk.metadata()?.len();
    drop(disk);
    let error = match Store::open(&corrupt_path, Limits::default()) {
        Err(error) => error,
        Ok(_) => return Err("complete damaged frame was treated as an incomplete tail".into()),
    };
    assert_eq!(error.failure().kind, FailureKind::Checksum);
    assert_eq!(fs::metadata(corrupt_path.join(WAL))?.len(), length);

    let path = temp.0.join("fence");
    let mut store = Store::create(&path, Limits::default())?;
    store.append(2, b"known prefix")?;
    let length = store.wal.metadata()?.len();
    // Private test seam: the SAME actual WAL inode is now held readonly.
    // Identity/length checks succeed, but its real write syscall fails.
    store.wal = File::from(openat(
        &store.root,
        WAL,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?);
    let first = match store.append(3, b"uncertain original") {
        Err(error) => error,
        Ok(_) => return Err("readonly WAL accepted a write".into()),
    };
    assert!(store.fenced());
    assert_eq!(first.failure().certainty, Certainty::Unknown);
    assert!(
        first
            .failure()
            .io
            .as_ref()
            .and_then(|e| e.raw_os_error())
            .is_some()
    );
    assert_eq!(
        store.pending_record(),
        Some(RecordView {
            sequence: 2,
            kind: 3,
            bytes: b"uncertain original"
        })
    );
    assert_eq!(store.record_count(), 1);
    assert_eq!(store.scratch.capacity(), 0);
    let read = store
        .read_record(0)
        .err()
        .ok_or("fenced store read performed new I/O")?;
    assert!(Arc::ptr_eq(&first.0, &read.0));
    let next = match store.append(4, b"must not write") {
        Err(error) => error,
        Ok(_) => return Err("fenced owner admitted another write".into()),
    };
    assert!(Arc::ptr_eq(&first.0, &next.0));
    assert_eq!(store.wal.metadata()?.len(), length);
    drop(store);
    let reopened = Store::open(&path, Limits::default())?;
    assert!(!reopened.fenced());
    assert!(reopened.pending_record().is_none());
    assert_eq!(reopened.record_count(), 1); // No automatic replay on reopen.
    Ok(())
}

#[test]
fn same_inode_self_consistent_rewrites_cannot_replace_accepted_record_or_task_identity()
-> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("record-rewrite");
    let mut store = Store::create(&path, Limits::default())?;
    store.append(7, b"original")?;
    store.append(8, b"known second record")?;
    let disk = fs::OpenOptions::new().write(true).open(path.join(WAL))?;
    let original_length = disk.metadata()?.len();
    assert!(identity(&disk, "test-wal-identity")? == store.wal_id);
    // This is a complete, internally valid replacement with the same shape,
    // inode and length. The old accepted digest must remain authoritative.
    let replacement = frame(1, 7, b"tampered")?;
    disk.write_all_at(&replacement, format::HEADER as u64)?;
    disk.sync_all()?;
    assert_eq!(disk.metadata()?.len(), original_length);
    assert_eq!(
        store.read_record(1)?.map(|record| record.bytes),
        Some(b"known second record".as_slice())
    );
    let refused = store
        .read_record(0)
        .err()
        .ok_or("accepted record digest was replaced by a later checksum")?;
    assert_eq!(refused.failure().stage, "read-record-original-digest");
    assert_eq!(refused.failure().kind, FailureKind::Checksum);
    assert_eq!(refused.failure().certainty, Certainty::NotWritten);
    assert_eq!(store.record_count(), 2);
    assert!(store.pending_record().is_none());
    let append = store
        .append(9, b"must not append after changed record")
        .err()
        .ok_or("changed record did not fence append")?;
    assert!(Arc::ptr_eq(&refused.0, &append.0));
    assert_eq!(disk.metadata()?.len(), original_length);

    let path = temp.0.join("header-rewrite");
    let mut store = Store::create(&path, Limits::default())?;
    store.append(7, b"accepted")?;
    let disk = fs::OpenOptions::new().write(true).open(path.join(WAL))?;
    let original_length = disk.metadata()?.len();
    let mut foreign = *store.task_id();
    foreign[0] ^= 1;
    disk.write_all_at(&format::header(&foreign), 0)?;
    disk.sync_all()?;
    assert!(identity(&disk, "test-header-identity")? == store.wal_id);
    assert_eq!(disk.metadata()?.len(), original_length);
    let refused = store
        .append(8, b"must not extend a replaced task identity")
        .err()
        .ok_or("changed task header authorized append")?;
    assert_eq!(refused.failure().stage, "header-authority-changed");
    assert_eq!(refused.failure().kind, FailureKind::Authority);
    assert_eq!(refused.failure().certainty, Certainty::NotWritten);
    assert!(store.pending_record().is_none());
    let read = store
        .read_record(0)
        .err()
        .ok_or("changed header did not fence reads")?;
    assert!(Arc::ptr_eq(&refused.0, &read.0));
    assert_eq!(disk.metadata()?.len(), original_length);
    Ok(())
}

#[test]
fn long_journal_reopens_with_only_bounded_metadata_and_one_reused_record_buffer() -> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("streamed");
    let count = 256usize;
    let body_bytes = 16 * 1024usize;
    let limits = Limits {
        max_records: count,
        max_body_bytes: body_bytes,
        max_index_bytes: 2 * count * std::mem::size_of::<Record>(),
        max_scratch_bytes: format::record_size(body_bytes)?,
        max_file_bytes: 8 * 1024 * 1024,
    };
    let mut store = Store::create(&path, limits)?;
    let mut body = vec![0x42; body_bytes];
    let mut original_buffer = None;
    for sequence in 1..=count {
        body[..8].copy_from_slice(&(sequence as u64).to_be_bytes());
        assert_eq!(store.append(23, &body)?, sequence as u64);
        let buffer = store.scratch.as_ptr();
        if let Some(original) = original_buffer {
            assert_eq!(buffer, original);
        }
        original_buffer = Some(buffer);
        assert!(store.pending.is_none());
    }
    let original_length = store.wal.metadata()?.len();
    assert_eq!(store.record_count(), count);
    let limit = store
        .append(24, b"record beyond the original bound")
        .err()
        .ok_or("record cap did not refuse append")?;
    assert_eq!(limit.failure().kind, FailureKind::Limit);
    assert_eq!(limit.failure().certainty, Certainty::NotWritten);
    assert!(!store.fenced());
    assert_eq!(store.wal.metadata()?.len(), original_length);
    drop(store);
    let mut store = Store::open(&path, limits)?;
    assert_eq!(store.record_count(), count);
    let indexed_bytes = store.rows.capacity() * std::mem::size_of::<Record>();
    assert!(indexed_bytes <= limits.max_index_bytes);
    assert!(store.scratch.capacity() <= limits.max_scratch_bytes);
    assert!(((indexed_bytes + store.scratch.capacity()) as u64) < original_length / 8);
    let original_buffer = store.scratch.as_ptr();
    // Reverse reads exercise real offset lookup rather than a forward cursor
    // or retained history. Each view expires before the next buffer is reused.
    for index in (0..count).rev() {
        body[..8].copy_from_slice(&((index + 1) as u64).to_be_bytes());
        let record = store.read_record(index)?.ok_or("accepted offset missing")?;
        assert_eq!((record.sequence, record.kind), ((index + 1) as u64, 23));
        assert_eq!(record.bytes, body.as_slice());
        assert_eq!(store.scratch.as_ptr(), original_buffer);
    }
    assert!(store.read_record(count)?.is_none());
    assert!(store.pending_record().is_none());
    assert_eq!(store.repaired_tail_bytes(), 0);
    Ok(())
}

/// Actual replacement journal/lock observation, not a projected path-stat test.
#[cfg(feature = "network")]
#[test]
fn registered_open_refuses_replacement_before_lock_or_partial_wal_repair() -> TestResult {
    let temp = Temporary::new()?;
    let path = temp.0.join("registered");
    let original = Store::create(&path, Limits::default())?;
    let expected = crate::FileIdentity::of(original.directory())?;
    drop(original);
    fs::rename(&path, temp.0.join("original"))?;
    let mut foreign = Store::create(&path, Limits::default())?;
    foreign.append(9, b"foreign durable sentinel")?;
    let foreign_lock = crate::FileIdentity::of(&foreign.lock)?;
    let wal_path = path.join(WAL);
    let lock_path = path.join(LOCK);
    let torn = frame(2, 41, b"foreign incomplete tail")?;
    let mut disk = fs::OpenOptions::new().append(true).open(&wal_path)?;
    disk.write_all(&torn[..format::RECORD_HEADER + 2])?;
    disk.sync_all()?;
    drop(disk);
    let before = fs::read(&wal_path)?;
    let lock_before = fs::read(&lock_path)?;
    // The held foreign lock must not mask the earlier identity refusal.
    let refused = match Store::open_registered(&path, Limits::default(), expected) {
        Err(error) => error,
        Ok(_) => return Err("registered open accepted a replacement directory".into()),
    };
    assert_eq!(refused.failure().stage, "registered-directory-identity");
    assert_eq!(refused.failure().kind, FailureKind::Authority);
    assert_eq!(refused.failure().certainty, Certainty::NotWritten);
    assert_eq!(fs::read(&wal_path)?, before);
    drop(foreign);
    // With the lock free, an ordinary open would repair this provably partial
    // tail. Registered open must still refuse before even opening that WAL.
    let refused = match Store::open_registered(&path, Limits::default(), expected) {
        Err(error) => error,
        Ok(_) => return Err("registered open repaired a foreign journal".into()),
    };
    assert_eq!(refused.failure().kind, FailureKind::Authority);
    assert_eq!(refused.failure().certainty, Certainty::NotWritten);
    assert_eq!(fs::read(&wal_path)?, before);
    assert_eq!(fs::metadata(&wal_path)?.len(), before.len() as u64);
    assert_eq!(fs::read(&lock_path)?, lock_before);
    assert_eq!(
        crate::FileIdentity::of(&File::open(&lock_path)?)?,
        foreign_lock
    );
    Ok(())
}
