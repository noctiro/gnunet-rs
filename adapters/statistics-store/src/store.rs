use crate::{Stage, StoreError};
use gnunet_statistics::Statistics;
use gnunet_types::Error;
use gnunet_wire::official::MessageHeader;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// Explicit file and work bounds for loading and saving a database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum complete file bytes. Zero admits only an absent/empty database.
    pub max_file_bytes: u64,
    /// Maximum replayed/saved SET frames, including duplicate names on load.
    pub max_records: usize,
    /// Maximum complete frame, between 18 (empty names) and 65535 bytes.
    pub max_frame_bytes: usize,
}

/// Which database input was observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoadSource {
    /// No file existed at the explicit path.
    Missing,
    /// An existing regular file had zero bytes.
    Empty,
    /// Complete official SET messages were replayed from an existing file.
    Present,
}

/// Actual successfully loaded input and bounded service state counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoadReport {
    /// Whether the input was absent, empty or a SET stream.
    pub source: LoadSource,
    /// Bytes actually decoded/replayed.
    pub bytes: u64,
    /// Complete SET frames replayed, including duplicates.
    pub records: usize,
    /// Resulting distinct statistic rows, including nonpersistent SETs.
    pub rows: usize,
}

/// Namespace outcome after the requested synchronization operations succeeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaveOutcome {
    /// A complete snapshot replaced the destination atomically.
    Stored,
    /// An existing database entry was removed for an empty persistent set.
    Removed,
    /// An empty persistent set already had no database entry; no file was made.
    Absent,
}

/// Counts of the actual committed official SET snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SaveReport {
    /// Replacement, removal or already-absent outcome.
    pub outcome: SaveOutcome,
    /// Sum of official SET frame bytes; zero for removal/absence.
    pub bytes: u64,
    /// Number of persistent statistic rows written.
    pub records: usize,
}

/// Namespace publication and directory synchronization boundary.
///
/// File creation, writing and `sync_all` always use the actual filesystem.
/// This narrow interface permits a platform backend or fault-injection test to
/// report a namespace operation that may have happened before an I/O error.
/// Implementations must perform the named operation and propagate real errors;
/// returning success without it invalidates the save's durability contract.
pub trait CommitBackend {
    /// Replace the destination entry with the complete same-directory source.
    fn rename(&mut self, source: &Path, destination: &Path) -> io::Result<()>;
    /// Remove an obsolete destination entry.
    fn remove(&mut self, destination: &Path) -> io::Result<()>;
    /// Synchronize this existing directory's namespace updates.
    fn sync_directory(&mut self, directory: &Path) -> io::Result<()>;
}

/// Actual Unix namespace operations and directory `sync_all`.
///
/// Other targets return `Unsupported` before native saving starts: standard Rust
/// does not expose a portable directory-synchronization primitive there. A
/// suitable platform may instead supply a real [`CommitBackend`].
#[derive(Default)]
pub struct NativeCommit;
impl CommitBackend for NativeCommit {
    fn rename(&mut self, source: &Path, destination: &Path) -> io::Result<()> {
        fs::rename(source, destination)
    }
    fn remove(&mut self, destination: &Path) -> io::Result<()> {
        fs::remove_file(destination)
    }
    fn sync_directory(&mut self, directory: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            File::open(directory)?.sync_all()
        }
        #[cfg(not(unix))]
        {
            let _ = directory;
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }
}

/// An explicit official `[STATISTICS] DATABASE` path and finite work limits.
///
/// The application resolves configuration/filename expansion and serializes its
/// writers. Loading opens one file descriptor, so this adapter's atomic saves
/// allow a loader to see a complete old or new snapshot. Concurrent in-place
/// external writes are outside that ownership contract; length changes are
/// detected and rejected. There is no hidden fallback database or migration.
pub struct Store {
    path: PathBuf,
    parent: PathBuf,
    limits: Limits,
}
impl Store {
    /// Validate the explicit path and limits without performing filesystem I/O.
    pub fn new(path: impl Into<PathBuf>, limits: Limits) -> Result<Self, StoreError> {
        let path = path.into();
        if path.file_name().is_none() || !(18..=65535).contains(&limits.max_frame_bytes) {
            return Err(StoreError::protocol(
                Stage::Preflight,
                None,
                Error::InvalidInput,
            ));
        }
        let parent = parent_of(&path).to_path_buf();
        Ok(Self {
            path,
            parent,
            limits,
        })
    }

    /// Original explicit destination path, without implicit expansion.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Decode/replay a complete database into a fresh fixed-capacity core.
    ///
    /// Failure drops the candidate rather than publishing a partially loaded
    /// service. Missing/empty files return an explicitly empty state, matching
    /// service startup. Every SET flag combination uses official SET arithmetic;
    /// the canonical output remains absolute persistent SET. Foreign types and
    /// any truncated final header/body are errors, never silently successful EOF.
    pub fn load<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize>(
        &self,
    ) -> Result<(Statistics<R, N, C, W, E>, LoadReport), StoreError> {
        self.load_with(|| Ok(Statistics::new()))
    }

    /// Load into one fresh core created with the caller's resource limits.
    ///
    /// The factory is called exactly once before filesystem access. Its error
    /// retains the original protocol/resource cause at [`Stage::Preflight`].
    /// The returned core must have no rows, clients, watches or queued effects;
    /// it remains unpublished until the complete bounded input has replayed.
    /// A failure drops that candidate, never publishing a partial or empty
    /// replacement for invalid existing data. Missing/empty files still return
    /// the caller's fresh configured core with their actual [`LoadSource`].
    pub fn load_with<
        const R: usize,
        const N: usize,
        const C: usize,
        const W: usize,
        const E: usize,
    >(
        &self,
        new: impl FnOnce() -> Result<Statistics<R, N, C, W, E>, Error>,
    ) -> Result<(Statistics<R, N, C, W, E>, LoadReport), StoreError> {
        let mut core =
            new().map_err(|error| StoreError::protocol(Stage::Preflight, None, error))?;
        if core.row_count() != 0
            || core.client_count() != 0
            || core.watch_count() != 0
            || core.notification_count_queued() != 0
        {
            return Err(StoreError::protocol(
                Stage::Preflight,
                None,
                Error::Conflict,
            ));
        }
        // Reject named pipes/devices before a blocking open. The caller owns
        // namespace writers; descriptor metadata below still validates the
        // actual regular file that was opened.
        match fs::metadata(&self.path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return Err(StoreError::protocol(
                    Stage::Inspect,
                    None,
                    Error::InvalidInput,
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok((
                    core,
                    LoadReport {
                        source: LoadSource::Missing,
                        bytes: 0,
                        records: 0,
                        rows: 0,
                    },
                ));
            }
            Err(error) => return Err(StoreError::io(Stage::Inspect, None, error)),
        }
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok((
                    core,
                    LoadReport {
                        source: LoadSource::Missing,
                        bytes: 0,
                        records: 0,
                        rows: 0,
                    },
                ));
            }
            Err(error) => return Err(StoreError::io(Stage::Open, None, error)),
        };
        let metadata = file
            .metadata()
            .map_err(|error| StoreError::io(Stage::Inspect, None, error))?;
        if !metadata.is_file() {
            return Err(StoreError::protocol(
                Stage::Inspect,
                None,
                Error::InvalidInput,
            ));
        }
        let expected = metadata.len();
        if expected > self.limits.max_file_bytes {
            return Err(StoreError::protocol(Stage::Inspect, None, Error::TooLarge));
        }
        if expected == 0 {
            return Ok((
                core,
                LoadReport {
                    source: LoadSource::Empty,
                    bytes: 0,
                    records: 0,
                    rows: 0,
                },
            ));
        }
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(self.limits.max_frame_bytes)
            .map_err(|_| StoreError::protocol(Stage::Preflight, None, Error::Capacity))?;
        let external = core.external_retained_bytes();
        let retained = external
            .checked_add(frame.capacity())
            .ok_or_else(|| StoreError::protocol(Stage::Preflight, None, Error::Overflow))?;
        core.set_external_retained_bytes(retained)
            .map_err(|error| StoreError::protocol(Stage::Preflight, None, error))?;
        frame.resize(self.limits.max_frame_bytes, 0);
        let mut offset = 0;
        let mut records = 0;
        while offset < expected {
            if records == self.limits.max_records {
                return Err(StoreError::protocol(
                    Stage::Replay,
                    Some(offset),
                    Error::Capacity,
                ));
            }
            if expected - offset < 4 {
                return Err(StoreError::protocol(
                    Stage::Read,
                    Some(offset),
                    Error::Truncated,
                ));
            }
            file.read_exact(&mut frame[..4])
                .map_err(|error| StoreError::io(Stage::Read, Some(offset), error))?;
            let header = MessageHeader::decode(&frame[..4])
                .map_err(|error| StoreError::protocol(Stage::Replay, Some(offset), error))?;
            if header.size() > self.limits.max_frame_bytes {
                return Err(StoreError::protocol(
                    Stage::Replay,
                    Some(offset),
                    Error::Capacity,
                ));
            }
            let size = u64::try_from(header.size())
                .map_err(|_| StoreError::protocol(Stage::Replay, Some(offset), Error::Overflow))?;
            if size > expected - offset {
                return Err(StoreError::protocol(
                    Stage::Read,
                    Some(offset),
                    Error::Truncated,
                ));
            }
            file.read_exact(&mut frame[4..header.size()])
                .map_err(|error| StoreError::io(Stage::Read, Some(offset), error))?;
            core.replay(&frame[..header.size()])
                .map_err(|error| StoreError::protocol(Stage::Replay, Some(offset), error))?;
            offset += size;
            records += 1;
        }
        if file
            .metadata()
            .map_err(|error| StoreError::io(Stage::Inspect, None, error))?
            .len()
            != expected
        {
            return Err(StoreError::protocol(Stage::Inspect, None, Error::Conflict));
        }
        drop(frame);
        core.set_external_retained_bytes(external)
            .map_err(|error| StoreError::protocol(Stage::Preflight, None, error))?;
        let rows = core.row_count();
        Ok((
            core,
            LoadReport {
                source: LoadSource::Present,
                bytes: offset,
                records,
                rows,
            },
        ))
    }

    /// Save after all clients and pending notification effects have been released.
    ///
    /// Accepted bytes are exactly the official concatenated SET dump format.
    /// Nonempty saves write a private-mode same-directory temporary file,
    /// synchronize it, atomically rename it and synchronize the parent directory.
    /// Empty snapshots remove the old database like the reference service.
    /// Synchronization success means the OS accepted those requests, not an
    /// independent guarantee about a device or remote filesystem's persistence.
    pub fn save<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize>(
        &self,
        core: &Statistics<R, N, C, W, E>,
        scratch: &mut [u8],
    ) -> Result<SaveReport, StoreError> {
        #[cfg(unix)]
        {
            self.save_with(core, scratch, &mut NativeCommit)
        }
        #[cfg(not(unix))]
        {
            let _ = (core, scratch);
            Err(StoreError::io(
                Stage::Preflight,
                None,
                io::Error::from(io::ErrorKind::Unsupported),
            ))
        }
    }

    /// Save using an explicit, real namespace/directory-sync implementation.
    ///
    /// This method still creates, writes and syncs an actual temporary file.
    /// Before rename/removal is attempted failures preserve the destination;
    /// thereafter errors conservatively report [`crate::CommitOutcome::Unknown`].
    /// A failed rename retains any remaining candidate file for inspection.
    pub fn save_with<
        const R: usize,
        const N: usize,
        const C: usize,
        const W: usize,
        const E: usize,
    >(
        &self,
        core: &Statistics<R, N, C, W, E>,
        scratch: &mut [u8],
        commit: &mut impl CommitBackend,
    ) -> Result<SaveReport, StoreError> {
        if core.client_count() != 0 || core.notification_count_queued() != 0 {
            return Err(StoreError::protocol(
                Stage::Preflight,
                None,
                Error::Conflict,
            ));
        }
        // One immutable, ordered view supplies both admission and writing.
        // It owns only actual row indices, sharing the original row/name data.
        let snapshot = core
            .persistent_snapshot()
            .map_err(|error| StoreError::protocol(Stage::Preflight, None, error))?;
        let capacity = scratch.len().min(self.limits.max_frame_bytes);
        let scratch = &mut scratch[..capacity];
        let mut records = 0usize;
        let mut bytes = 0u64;
        for update in snapshot.iter() {
            if records == self.limits.max_records {
                return Err(StoreError::protocol(
                    Stage::Preflight,
                    None,
                    Error::Capacity,
                ));
            }
            let size = update
                .encode(scratch)
                .map_err(|error| StoreError::protocol(Stage::Preflight, None, error))?;
            bytes =
                bytes
                    .checked_add(u64::try_from(size).map_err(|_| {
                        StoreError::protocol(Stage::Preflight, None, Error::Overflow)
                    })?)
                    .ok_or_else(|| StoreError::protocol(Stage::Preflight, None, Error::Overflow))?;
            if bytes > self.limits.max_file_bytes {
                return Err(StoreError::protocol(
                    Stage::Preflight,
                    None,
                    Error::TooLarge,
                ));
            }
            records += 1;
        }
        if records == 0 {
            return self.remove_empty(commit);
        }
        prepare_parent(&self.parent, commit)?;
        let (mut candidate, mut file) = temporary(&self.path)?;
        for update in snapshot.iter() {
            let size = update
                .encode(scratch)
                .map_err(|error| StoreError::protocol(Stage::Write, None, error))?;
            file.write_all(&scratch[..size])
                .map_err(|error| StoreError::io(Stage::Write, None, error))?;
        }
        file.sync_all()
            .map_err(|error| StoreError::io(Stage::SyncFile, None, error))?;
        drop(file);
        candidate.retain = true;
        commit
            .rename(&candidate.path, &self.path)
            .map_err(|error| {
                StoreError::io(Stage::Rename, None, error).unknown(Some(candidate.path.clone()))
            })?;
        commit
            .sync_directory(&self.parent)
            .map_err(|error| StoreError::io(Stage::SyncDirectory, None, error).unknown(None))?;
        Ok(SaveReport {
            outcome: SaveOutcome::Stored,
            bytes,
            records,
        })
    }

    fn remove_empty(&self, commit: &mut impl CommitBackend) -> Result<SaveReport, StoreError> {
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(SaveReport {
                    outcome: SaveOutcome::Absent,
                    bytes: 0,
                    records: 0,
                });
            }
            Err(error) => return Err(StoreError::io(Stage::Inspect, None, error)),
            Ok(_) => {}
        }
        let outcome = match commit.remove(&self.path) {
            Ok(()) => SaveOutcome::Removed,
            Err(error) if error.kind() == io::ErrorKind::NotFound => SaveOutcome::Absent,
            Err(error) => return Err(StoreError::io(Stage::Remove, None, error).unknown(None)),
        };
        commit
            .sync_directory(&self.parent)
            .map_err(|error| StoreError::io(Stage::SyncDirectory, None, error).unknown(None))?;
        Ok(SaveReport {
            outcome,
            bytes: 0,
            records: 0,
        })
    }
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn prepare_parent(parent: &Path, commit: &mut impl CommitBackend) -> Result<(), StoreError> {
    let mut missing = Vec::new();
    let mut cursor = parent;
    loop {
        match fs::metadata(cursor) {
            Ok(metadata) if metadata.is_dir() => break,
            Ok(_) => {
                return Err(StoreError::protocol(
                    Stage::Prepare,
                    None,
                    Error::InvalidInput,
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                let next = parent_of(cursor);
                if next == cursor {
                    return Err(StoreError::protocol(
                        Stage::Prepare,
                        None,
                        Error::InvalidInput,
                    ));
                }
                cursor = next;
            }
            Err(error) => return Err(StoreError::io(Stage::Prepare, None, error)),
        }
    }
    fs::create_dir_all(parent).map_err(|error| StoreError::io(Stage::Prepare, None, error))?;
    for created in missing.iter().rev() {
        commit
            .sync_directory(created)
            .map_err(|error| StoreError::io(Stage::Prepare, None, error))?;
        commit
            .sync_directory(parent_of(created))
            .map_err(|error| StoreError::io(Stage::Prepare, None, error))?;
    }
    Ok(())
}

struct Temporary {
    path: PathBuf,
    retain: bool,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.retain {
            // Cleanup is best effort and never turns a failed save into success.
            match fs::remove_file(&self.path) {
                Ok(()) | Err(_) => {}
            }
        }
    }
}
fn temporary(destination: &Path) -> Result<(Temporary, File), StoreError> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    for _ in 0..64 {
        let ordinal = NEXT
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| StoreError::protocol(Stage::CreateTemporary, None, Error::Overflow))?;
        // A NAME_MAX-byte destination must still admit a temporary sibling.
        let temporary_name = format!(".gnunet-statistics-{}-{ordinal}.tmp", std::process::id());
        let path = parent_of(destination).join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                return Ok((
                    Temporary {
                        path,
                        retain: false,
                    },
                    file,
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(StoreError::io(Stage::CreateTemporary, None, error)),
        }
    }
    Err(StoreError::protocol(
        Stage::CreateTemporary,
        None,
        Error::Capacity,
    ))
}
