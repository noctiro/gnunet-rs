use crate::{
    CommitBackend, DirectorySync, NativeCommit, Stage, StoreError, commit::Candidate, namespace,
};
use gnunet_native::filesystem::{Directory, EntryInfo, FileIdentity};
use gnunet_statistics::Statistics;
use gnunet_types::Error;
use gnunet_wire::official::MessageHeader;
use std::{
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
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

/// Actual namespace outcome, independent of the directory barrier receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SaveOutcome {
    /// A complete snapshot replaced the destination atomically.
    Stored,
    /// An existing database entry was removed for an empty persistent set.
    Removed,
    /// An empty persistent set already had no database entry; no file was made.
    Absent,
}

/// Counts and directory barrier receipt of an actual official SET snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SaveReport {
    /// Replacement, removal or already-absent outcome.
    pub outcome: SaveOutcome,
    /// Sum of official SET frame bytes; zero for removal/absence.
    pub bytes: u64,
    /// Number of persistent statistic rows written.
    pub records: usize,
    /// Combined directory barrier result for every changed parent. None means
    /// the already-absent database required no namespace mutation. File data was
    /// synchronized independently before any nonempty snapshot publication.
    pub directory_sync: Option<DirectorySync>,
}

const ALREADY_ABSENT: SaveReport = SaveReport {
    outcome: SaveOutcome::Absent,
    bytes: 0,
    records: 0,
    directory_sync: None,
};

/// An explicit official `[STATISTICS] DATABASE` path and finite work limits.
///
/// The application resolves configuration/filename expansion and serializes its
/// writers. Loading opens one file descriptor, so this adapter's atomic saves
/// allow a loader to see a complete old or new snapshot. Concurrent in-place
/// external writes are outside that ownership contract; length changes are
/// detected and rejected. There is no hidden fallback database or migration.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    parent: PathBuf,
    name: OsString,
    limits: Limits,
}
impl Store {
    /// Validate the explicit path and limits without performing filesystem I/O.
    pub fn new(path: impl Into<PathBuf>, limits: Limits) -> Result<Self, StoreError> {
        let path = path.into();
        let invalid = || StoreError::protocol(Stage::Preflight, None, Error::InvalidInput);
        let name = path.file_name().ok_or_else(invalid)?;
        if !path
            .as_os_str()
            .as_encoded_bytes()
            .ends_with(name.as_encoded_bytes())
            || !(18..=65535).contains(&limits.max_frame_bytes)
        {
            return Err(StoreError::protocol(
                Stage::Preflight,
                None,
                Error::InvalidInput,
            ));
        }
        #[cfg(windows)]
        gnunet_native::paths::validate_file_path(&path)
            .map_err(|error| StoreError::io(Stage::Preflight, None, error))?;
        Directory::validate_name(name)
            .map_err(|error| StoreError::io(Stage::Preflight, None, error))?;
        let name = name.to_os_string();
        let parent = parent_of(&path).to_path_buf();
        Ok(Self {
            path,
            parent,
            name,
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
        // Windows std metadata classifies AF_UNIX reparse nodes as files. Inspect
        // the native tag first, including alternate case spellings of a live
        // endpoint, rather than opening it as a database candidate.
        #[cfg(windows)]
        match gnunet_native::local_path::is_socket(&self.path) {
            Ok(true) => {
                return Err(StoreError::protocol(
                    Stage::Inspect,
                    None,
                    Error::InvalidInput,
                ));
            }
            Ok(false) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::io(Stage::Inspect, None, error)),
        }
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
        #[cfg(windows)]
        let opened = gnunet_native::paths::open_regular_file(&self.path);
        #[cfg(not(windows))]
        let opened = fs::File::open(&self.path);
        let mut file = match opened {
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
    /// Nonempty saves stage private bytes and replace the destination relative
    /// to the same original directory handle. The directory barrier
    /// result is reported independently in [`SaveReport::directory_sync`].
    /// Empty snapshots remove the old database like the reference service.
    /// Synchronization success means the OS accepted those requests, not an
    /// independent guarantee about a device or remote filesystem's persistence.
    pub fn save<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize>(
        &self,
        core: &Statistics<R, N, C, W, E>,
        scratch: &mut [u8],
    ) -> Result<SaveReport, StoreError> {
        #[cfg(any(unix, windows))]
        {
            self.save_with(core, scratch, &mut NativeCommit)
        }
        #[cfg(not(any(unix, windows)))]
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
        let (directory, prepared) = namespace::prepare(&self.parent, commit)?;
        let mut candidate = Candidate::create(&directory, &self.name)?;
        let written = (|| {
            for update in snapshot.iter() {
                let size = update
                    .encode(scratch)
                    .map_err(|error| StoreError::protocol(Stage::Write, None, error))?;
                candidate
                    .writer()
                    .write_all(&scratch[..size])
                    .map_err(|error| StoreError::io(Stage::Write, None, error))?;
            }
            Ok(())
        })();
        if let Err(error) = written {
            return Err(candidate.failed(error));
        }
        let directory_sync = candidate.publish(bytes, &self.name, &self.parent, commit)?;
        Ok(SaveReport {
            outcome: SaveOutcome::Stored,
            bytes,
            records,
            directory_sync: Some(prepared.combine(directory_sync)),
        })
    }

    fn remove_empty(&self, commit: &mut impl CommitBackend) -> Result<SaveReport, StoreError> {
        let directory = match namespace::open(&self.parent) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(ALREADY_ABSENT),
            Err(error) => return Err(StoreError::io(Stage::Inspect, None, error)),
        };
        let selected = match directory.entry_info(&self.name) {
            Ok(EntryInfo::File(info)) => info.identity,
            Ok(_) => {
                return Err(StoreError::protocol(
                    Stage::Inspect,
                    None,
                    Error::InvalidInput,
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(ALREADY_ABSENT),
            Err(error) => return Err(StoreError::io(Stage::Inspect, None, error)),
        };
        let original = match directory.open_file(&self.name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(ALREADY_ABSENT),
            Err(error) => return Err(StoreError::io(Stage::Open, None, error)),
        };
        if FileIdentity::of(&original)
            .map_err(|error| StoreError::io(Stage::Inspect, None, error))?
            != selected
        {
            return Err(StoreError::io(
                Stage::Inspect,
                None,
                io::Error::other("original STATISTICS database changed before removal"),
            ));
        }
        let outcome = match commit.remove(&directory, &self.name, &original) {
            Ok(()) => SaveOutcome::Removed,
            Err(error) if error.kind() == io::ErrorKind::NotFound => SaveOutcome::Absent,
            Err(error) => return Err(StoreError::io(Stage::Remove, None, error).unknown(None)),
        };
        let directory_sync = commit
            .sync_directory(&directory)
            .map_err(|error| StoreError::io(Stage::SyncDirectory, None, error).unknown(None))?;
        match directory.entry_info(&self.name) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(StoreError::io(Stage::Inspect, None, error).unknown(None)),
            Ok(_) => {
                return Err(StoreError::io(
                    Stage::Inspect,
                    None,
                    io::Error::other("STATISTICS database name remains after removal"),
                )
                .unknown(None));
            }
        }
        Ok(SaveReport {
            outcome,
            bytes: 0,
            records: 0,
            directory_sync: Some(directory_sync),
        })
    }
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
