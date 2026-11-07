//! Real database round trips, bounded replay and publication failures.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible filesystem tests assert actual data and failure outcomes"
)]

use gnunet_statistics::{Reply, Selector, Set, Statistics};
use gnunet_statistics_store::{
    Cause, CommitBackend, CommitOutcome, Limits, LoadSource, NativeCommit, SaveOutcome, Stage,
    Store,
};
use gnunet_types::Error;
use std::{
    error::Error as StdError,
    fs, io,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

type Core = Statistics<4, 32, 1, 2, 4>;
const NAME: Selector<'static> = Selector {
    subsystem: b"s",
    name: b"n",
};
const LIMITS: Limits = Limits {
    max_file_bytes: 1024,
    max_records: 8,
    max_frame_bytes: 64,
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let ordinal = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| io::Error::other("test directory sequence exhausted"))?;
        let path = std::env::temp_dir().join(format!(
            "gnunet-statistics-store-{}-{ordinal}",
            std::process::id()
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn file(&self) -> PathBuf {
        self.0.join("statistics.db")
    }
    fn store(&self) -> Result<Store, Box<dyn StdError>> {
        Ok(Store::new(self.file(), LIMITS)?)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        match fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
fn update(core: &mut Core, selector: Selector<'_>, value: u64, flags: u32) -> Result<(), Error> {
    let client = core.connect()?;
    core.set(
        client,
        Set {
            selector,
            flags,
            value,
        },
    )?;
    core.disconnect(client)
}
fn value(core: &mut Core, selector: Selector<'_>) -> Result<(u64, bool), Error> {
    let client = core.connect()?;
    let result = match core.get(client, selector)?.next() {
        Some(Reply::Value(value)) => Ok((value.value, value.persistent())),
        _ => Err(Error::NotFound),
    };
    core.disconnect(client)?;
    result
}
fn frame(selector: Selector<'_>, flags: u32, value: u64) -> Result<Vec<u8>, Error> {
    let mut bytes = [0; 64];
    let size = Set {
        selector,
        flags,
        value,
    }
    .encode(&mut bytes)?;
    Ok(bytes[..size].to_vec())
}

#[test]
fn durable_restart_uses_only_official_set_bytes_and_preserves_private_file_mode()
-> Result<(), Box<dyn StdError>> {
    use std::os::unix::fs::PermissionsExt;
    let directory = Directory::new()?;
    let store = directory.store()?;
    let (mut core, loaded) = store.load::<4, 32, 1, 2, 4>()?;
    assert_eq!(loaded.source, LoadSource::Missing);
    update(&mut core, NAME, 0x0102_0304_0506_0708, 2)?;
    update(
        &mut core,
        Selector {
            subsystem: b"s",
            name: b"transient",
        },
        99,
        0,
    )?;
    let saved = store.save(&core, &mut [0; 64])?;
    assert_eq!(
        (saved.outcome, saved.bytes, saved.records),
        (SaveOutcome::Stored, 20, 1)
    );
    assert_eq!(
        fs::read(directory.file())?,
        b"\0\x14\0\xa8\0\0\0\x02\x01\x02\x03\x04\x05\x06\x07\x08s\0n\0"
    );
    assert_eq!(
        fs::metadata(directory.file())?.permissions().mode() & 0o777,
        0o600
    );
    let (mut restarted, loaded) = store.load::<4, 32, 1, 2, 4>()?;
    assert_eq!(
        (loaded.source, loaded.bytes, loaded.records, loaded.rows),
        (LoadSource::Present, 20, 1, 1)
    );
    assert_eq!(value(&mut restarted, NAME)?, (0x0102_0304_0506_0708, true));
    assert_eq!(
        value(
            &mut restarted,
            Selector {
                subsystem: b"s",
                name: b"transient"
            }
        ),
        Err(Error::NotFound)
    );
    assert_eq!(fs::read_dir(&directory.0)?.count(), 1);
    Ok(())
}

#[test]
fn load_replays_duplicate_relative_and_persistence_changes_like_official_set()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let mut bytes = frame(NAME, 2, 9)?;
    bytes.extend_from_slice(&frame(NAME, 1, (-4i64) as u64)?);
    bytes.extend_from_slice(&frame(NAME, 3 | 0x8000_0000, 2)?);
    fs::write(directory.file(), bytes)?;
    let (mut core, report) = directory.store()?.load::<4, 32, 1, 2, 4>()?;
    assert_eq!((report.records, report.rows, report.bytes), (3, 1, 60));
    assert_eq!(value(&mut core, NAME)?, (7, true));
    directory.store()?.save(&core, &mut [0; 64])?;
    assert_eq!(fs::read(directory.file())?, frame(NAME, 2, 7)?);
    Ok(())
}

#[test]
fn actual_snapshot_matches_original_c_save_and_exports_for_c_inject()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let destination = std::env::var_os("GNUNET_STATISTICS_SNAPSHOT")
        .map_or_else(|| directory.file(), PathBuf::from);
    if destination.exists() {
        return Err("snapshot evidence path already exists".into());
    }
    let store = Store::new(destination.clone(), LIMITS)?;
    let mut core = Core::new();
    let a = Selector {
        subsystem: b"s",
        name: b"a",
    };
    let b = Selector {
        subsystem: b"s",
        name: b"b",
    };
    update(&mut core, a, 0x0102_0304_0506_0708, 2)?;
    update(&mut core, b, 7, 2)?;
    update(&mut core, a, (-8i64) as u64, 3)?;
    update(
        &mut core,
        Selector {
            subsystem: b"s",
            name: b"z",
        },
        99,
        0,
    )?;
    update(
        &mut core,
        Selector {
            subsystem: b"x",
            name: b"n",
        },
        0,
        2,
    )?;
    update(&mut core, a, 5, 3)?;
    assert_eq!(store.save(&core, &mut [0; 64])?.records, 3);
    assert_eq!(
        fs::read(destination)?,
        include_bytes!("fixtures/snapshot.bin")
    );
    Ok(())
}

#[test]
fn empty_input_is_explicit_and_empty_snapshot_removes_old_database() -> Result<(), Box<dyn StdError>>
{
    let directory = Directory::new()?;
    let store = directory.store()?;
    let core = Core::new();
    assert_eq!(store.save(&core, &mut [])?.outcome, SaveOutcome::Absent);
    fs::write(directory.file(), [])?;
    let (core, loaded) = store.load::<4, 32, 1, 2, 4>()?;
    assert_eq!(loaded.source, LoadSource::Empty);
    assert_eq!(store.save(&core, &mut [])?.outcome, SaveOutcome::Removed);
    assert!(!directory.file().exists());
    let missing_parent = Store::new(directory.0.join("missing/sub/statistics.db"), LIMITS)?;
    assert_eq!(
        missing_parent.save(&core, &mut [])?.outcome,
        SaveOutcome::Absent
    );
    assert!(!directory.0.join("missing").exists());
    Ok(())
}

#[test]
fn truncation_corruption_foreign_types_and_work_capacity_never_load_as_success()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let store = directory.store()?;
    let valid = frame(NAME, 2, 9)?;
    for length in 1..valid.len() {
        fs::write(directory.file(), &valid[..length])?;
        assert!(store.load::<4, 32, 1, 2, 4>().is_err());
    }
    for bad in [
        b"\0\x03\0\xa8".as_slice(),
        b"\0\x04\0\xab",
        b"\0\x14\0\xa8\0\0\0\x02\0\0\0\0\0\0\0\x09s\0nx",
    ] {
        fs::write(directory.file(), bad)?;
        assert!(store.load::<4, 32, 1, 2, 4>().is_err());
    }
    let mut truncated_suffix = valid.clone();
    truncated_suffix.extend_from_slice(b"\0\x14\0");
    fs::write(directory.file(), truncated_suffix)?;
    let error = match store.load::<4, 32, 1, 2, 4>() {
        Err(error) => error,
        Ok(_) => return Err("partial suffix unexpectedly loaded".into()),
    };
    assert_eq!(error.offset(), Some(20));
    assert_eq!(error.outcome(), CommitOutcome::DestinationUnchanged);
    fs::write(directory.file(), [&valid[..], &valid[..]].concat())?;
    let one_record = Store::new(
        directory.file(),
        Limits {
            max_records: 1,
            ..LIMITS
        },
    )?;
    let error = match one_record.load::<4, 32, 1, 2, 4>() {
        Err(error) => error,
        Ok(_) => return Err("record bound unexpectedly accepted".into()),
    };
    assert_eq!(error.offset(), Some(20));
    assert!(matches!(error.cause(), Cause::Protocol(Error::Capacity)));
    let one_byte = Store::new(
        directory.file(),
        Limits {
            max_file_bytes: 1,
            ..LIMITS
        },
    )?;
    assert!(one_byte.load::<4, 32, 1, 2, 4>().is_err());
    fs::write(directory.file(), &valid)?;
    assert!(store.load::<0, 32, 0, 0, 0>().is_err());
    assert!(store.load::<1, 3, 0, 0, 0>().is_err());
    Ok(())
}

#[test]
fn refused_save_does_not_replace_existing_file_or_leave_temporary_data()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let store = directory.store()?;
    let mut core = Core::new();
    update(&mut core, NAME, 9, 2)?;
    fs::write(directory.file(), b"previous database")?;
    assert!(store.save(&core, &mut [0; 19]).is_err());
    assert_eq!(fs::read(directory.file())?, b"previous database");
    let small = Store::new(
        directory.file(),
        Limits {
            max_file_bytes: 19,
            ..LIMITS
        },
    )?;
    let error = match small.save(&core, &mut [0; 64]) {
        Err(error) => error,
        Ok(_) => return Err("oversized save unexpectedly admitted".into()),
    };
    assert_eq!(error.outcome(), CommitOutcome::DestinationUnchanged);
    assert_eq!(error.stage(), Stage::Preflight);
    let client = core.connect()?;
    assert!(store.save(&core, &mut [0; 64]).is_err());
    core.disconnect(client)?;
    assert_eq!(fs::read_dir(&directory.0)?.count(), 1);
    Ok(())
}

#[test]
fn missing_parent_directories_are_created_and_synchronized_before_commit()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let path = directory.0.join("new/nested/statistics.db");
    let store = Store::new(path.clone(), LIMITS)?;
    let mut core = Core::new();
    update(&mut core, NAME, 9, 2)?;
    assert_eq!(
        store.save(&core, &mut [0; 64])?.outcome,
        SaveOutcome::Stored
    );
    assert_eq!(fs::read(path)?, frame(NAME, 2, 9)?);
    Ok(())
}

#[test]
fn a_long_valid_database_basename_does_not_exceed_temporary_filename_limits()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let path = directory.0.join("d".repeat(240));
    let store = Store::new(path.clone(), LIMITS)?;
    let mut core = Core::new();
    update(&mut core, NAME, 9, 2)?;
    assert_eq!(
        store.save(&core, &mut [0; 64])?.outcome,
        SaveOutcome::Stored
    );
    assert_eq!(fs::read(path)?, frame(NAME, 2, 9)?);
    Ok(())
}

enum Failure {
    RenameBefore,
    RenameAfter,
    DirectorySync,
    RemoveAfter,
}
struct FailingCommit(Failure);
impl CommitBackend for FailingCommit {
    fn rename(&mut self, source: &Path, destination: &Path) -> io::Result<()> {
        if matches!(self.0, Failure::RenameBefore) {
            return Err(io::Error::other("injected rename transport error"));
        }
        fs::rename(source, destination)?;
        if matches!(self.0, Failure::RenameAfter) {
            return Err(io::Error::other("injected response loss after rename"));
        }
        Ok(())
    }
    fn remove(&mut self, destination: &Path) -> io::Result<()> {
        fs::remove_file(destination)?;
        if matches!(self.0, Failure::RemoveAfter) {
            return Err(io::Error::other("injected response loss after unlink"));
        }
        Ok(())
    }
    fn sync_directory(&mut self, directory: &Path) -> io::Result<()> {
        if matches!(self.0, Failure::DirectorySync) {
            return Err(io::Error::other("injected directory sync failure"));
        }
        NativeCommit.sync_directory(directory)
    }
}

#[test]
fn rename_or_directory_sync_failure_reports_unknown_and_real_namespace_outcome()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let store = directory.store()?;
    let mut old = Core::new();
    update(&mut old, NAME, 1, 2)?;
    let mut new = Core::new();
    update(&mut new, NAME, 99, 2)?;
    for (failure, expected_value, expected_stage) in [
        (Failure::RenameBefore, 1, Stage::Rename),
        (Failure::RenameAfter, 99, Stage::Rename),
        (Failure::DirectorySync, 99, Stage::SyncDirectory),
    ] {
        store.save(&old, &mut [0; 64])?;
        let error = match store.save_with(&new, &mut [0; 64], &mut FailingCommit(failure)) {
            Err(error) => error,
            Ok(_) => return Err("injected failure became success".into()),
        };
        assert_eq!(error.outcome(), CommitOutcome::Unknown);
        assert_eq!(error.stage(), expected_stage);
        let (mut actual, _) = store.load::<4, 32, 1, 2, 4>()?;
        assert_eq!(value(&mut actual, NAME)?.0, expected_value);
        if let Some(path) = error.temporary_path().filter(|path| path.exists()) {
            assert_eq!(fs::read(path)?, frame(NAME, 2, 99)?);
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[test]
fn removal_that_happens_before_an_error_is_never_reported_as_durable_success()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    fs::write(directory.file(), frame(NAME, 2, 9)?)?;
    let error = match directory.store()?.save_with(
        &Core::new(),
        &mut [],
        &mut FailingCommit(Failure::RemoveAfter),
    ) {
        Err(error) => error,
        Ok(_) => return Err("failed removal was reported successful".into()),
    };
    assert_eq!(error.outcome(), CommitOutcome::Unknown);
    assert_eq!(error.stage(), Stage::Remove);
    assert!(!directory.file().exists());
    Ok(())
}

struct ChildProcess(Child);
impl Drop for ChildProcess {
    fn drop(&mut self) {
        match self.0.kill() {
            Ok(()) | Err(_) => {}
        }
        match self.0.wait() {
            Ok(_) | Err(_) => {}
        }
    }
}
struct PausingCommit {
    marker: PathBuf,
    after: bool,
}
impl PausingCommit {
    fn ready_and_park(&self) -> io::Result<()> {
        // File creation is visible before fs::write finishes. Publish the
        // completed checkpoint atomically so the parent cannot observe an
        // empty marker and mistake it for the real publication boundary.
        let pending = self.marker.with_extension("pending");
        fs::write(&pending, b"ready")?;
        fs::rename(pending, &self.marker)?;
        loop {
            std::thread::park();
        }
    }
}
impl CommitBackend for PausingCommit {
    fn rename(&mut self, source: &Path, destination: &Path) -> io::Result<()> {
        if !self.after {
            return self.ready_and_park();
        }
        fs::rename(source, destination)?;
        self.ready_and_park()
    }
    fn remove(&mut self, destination: &Path) -> io::Result<()> {
        NativeCommit.remove(destination)
    }
    fn sync_directory(&mut self, directory: &Path) -> io::Result<()> {
        NativeCommit.sync_directory(directory)
    }
}

#[test]
fn process_termination_exposes_only_complete_old_or_new_snapshots() -> Result<(), Box<dyn StdError>>
{
    // Re-enter this same meaningful test in an isolated child. The parent kills
    // only its owned process at the observed real filesystem publication stage.
    if let Some(mode) = std::env::var_os("GNUNET_STATISTICS_CRASH_CHILD") {
        let path = PathBuf::from(
            std::env::var_os("GNUNET_STATISTICS_CRASH_DATABASE").ok_or("missing child database")?,
        );
        let marker = PathBuf::from(
            std::env::var_os("GNUNET_STATISTICS_CRASH_MARKER").ok_or("missing child marker")?,
        );
        let after = if mode == "before" {
            false
        } else if mode == "after" {
            true
        } else {
            return Err("invalid crash phase".into());
        };
        let mut core = Core::new();
        update(&mut core, NAME, 99, 2)?;
        Store::new(path, LIMITS)?.save_with(
            &core,
            &mut [0; 64],
            &mut PausingCommit { marker, after },
        )?;
        return Err("child publication pause unexpectedly returned".into());
    }
    let directory = Directory::new()?;
    let store = directory.store()?;
    let mut old = Core::new();
    update(&mut old, NAME, 1, 2)?;
    for (mode, expected) in [("before", 1), ("after", 99)] {
        store.save(&old, &mut [0; 64])?;
        let marker = directory.0.join(format!("ready-{mode}"));
        let mut child = ChildProcess(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "process_termination_exposes_only_complete_old_or_new_snapshots",
                ])
                .env("GNUNET_STATISTICS_CRASH_CHILD", mode)
                .env("GNUNET_STATISTICS_CRASH_DATABASE", directory.file())
                .env("GNUNET_STATISTICS_CRASH_MARKER", &marker)
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !marker.exists() {
            if child.0.try_wait()?.is_some() {
                return Err("child exited before its publication checkpoint".into());
            }
            if Instant::now() >= deadline {
                return Err("child did not reach publication checkpoint".into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(fs::read(&marker)?, b"ready");
        child.0.kill()?;
        let status = child.0.wait()?;
        assert!(!status.success());
        let (mut restarted, report) = store.load::<4, 32, 1, 2, 4>()?;
        assert_eq!((report.bytes, report.records), (20, 1));
        assert_eq!(value(&mut restarted, NAME)?.0, expected);
        assert_eq!(fs::read(directory.file())?, frame(NAME, 2, expected)?);
    }
    Ok(())
}
