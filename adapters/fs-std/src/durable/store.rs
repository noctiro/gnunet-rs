//! Bounded durable task records, exclusive physical writer and uncertain append fence.
//! These private Rust bytes are not a GNUnet wire or C-persistence format.
mod format;
#[cfg(test)]
mod tests;
use nix::{
    errno::Errno,
    fcntl::{AtFlags, Flock, FlockArg, OFlag, open, openat},
    sys::stat::{FileStat, Mode, SFlag, fstat, fstatat, mkdirat},
};
use std::{
    error,
    ffi::{OsStr, OsString},
    fmt,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::FileExt,
    path::Path,
    sync::Arc,
};
const LOCK: &str = ".lock";
const WAL: &str = "records.wal";
const DIRECTORY: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
const REGULAR: OFlag = OFlag::O_RDWR
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC)
    .union(OFlag::O_NONBLOCK);

/// Explicit retained-memory and on-disk limits, checked before append I/O.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum number of complete record index entries.
    pub max_records: usize,
    /// Maximum body length of any one record.
    pub max_body_bytes: usize,
    /// Index allocation bytes, including old plus replacement allocation during
    /// growth. This does not account for typed task state held by consumers.
    pub max_index_bytes: usize,
    /// Maximum actual capacity of the sole reusable complete-record buffer.
    /// An uncertain append owns that buffer exclusively until this owner drops.
    pub max_scratch_bytes: usize,
    /// Complete WAL bytes, including header, record headers and checksums.
    pub max_file_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_records: 65536,
            max_body_bytes: 8 * 1024 * 1024,
            max_index_bytes: 16 * 1024 * 1024,
            max_scratch_bytes: 8 * 1024 * 1024 + format::RECORD_HEADER + format::DIGEST,
            max_file_bytes: 64 * 1024 * 1024,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.max_records == 0
            || self.max_body_bytes > u32::MAX as usize
            || self.max_index_bytes < std::mem::size_of::<Record>()
            || self.max_scratch_bytes < format::RECORD_HEADER + format::DIGEST
            || self.max_file_bytes < format::HEADER as u64
        {
            return Err(Error::before("limits", FailureKind::Limit));
        }
        Ok(())
    }
}
/// Certainty of this requested record, not an assertion that no directory exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Certainty {
    /// No append bytes were exposed by this operation.
    NotWritten,
    /// Header/record/truncation or a naming barrier may have taken effect.
    Unknown,
}
/// Stable classification; never recover certainty by parsing display strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureKind {
    /// Original native I/O refusal.
    Io,
    /// Explicit caller byte/record bound refused.
    Limit,
    /// Bounded allocation could not be reserved.
    Allocation,
    /// Fixed private framing fields are invalid.
    Malformed,
    /// The stored format version is unsupported.
    Version,
    /// A complete checksum or present checksum prefix is invalid.
    Checksum,
    /// The next record number is not contiguous.
    Sequence,
    /// Another physical writer retains the original lock.
    Locked,
    /// An anchored name, original inode or physical length changed.
    Authority,
}
/// Original failure shared by the returned error and retained writer fence.
#[derive(Debug)]
pub struct Failure {
    /// Exact native/recovery stage.
    pub stage: &'static str,
    /// Stable classification.
    pub kind: FailureKind,
    /// Original requested-record certainty.
    pub certainty: Certainty,
    /// Original native cause, including errno; absent for structural refusals.
    pub io: Option<Arc<io::Error>>,
}
/// Clone keeps the same original native cause; a later append does not replace it.
#[derive(Clone, Debug)]
pub struct Error(Arc<Failure>);
impl Error {
    fn new(
        stage: &'static str,
        kind: FailureKind,
        certainty: Certainty,
        io: Option<io::Error>,
    ) -> Self {
        Self(Arc::new(Failure {
            stage,
            kind,
            certainty,
            io: io.map(Arc::new),
        }))
    }
    fn before(stage: &'static str, kind: FailureKind) -> Self {
        Self::new(stage, kind, Certainty::NotWritten, None)
    }
    fn native(stage: &'static str, certainty: Certainty, error: impl Into<io::Error>) -> Self {
        Self::new(stage, FailureKind::Io, certainty, Some(error.into()))
    }
    fn with_certainty(&self, certainty: Certainty) -> Self {
        Self(Arc::new(Failure {
            stage: self.0.stage,
            kind: self.0.kind,
            certainty,
            io: self.0.io.clone(),
        }))
    }
    /// Original immutable failure fields.
    #[must_use]
    pub fn failure(&self) -> &Failure {
        &self.0
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FS task store {}: {:?} ({:?})",
            self.0.stage, self.0.kind, self.0.certainty
        )?;
        if let Some(error) = &self.0.io {
            write!(f, ": {error}")?;
        }
        Ok(())
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.0
            .io
            .as_ref()
            .map(|e| e.as_ref() as &(dyn error::Error + 'static))
    }
}
/// One exact complete record. A view does not authenticate its typed task meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordView<'a> {
    /// Strictly contiguous record number starting at one.
    pub sequence: u64,
    /// Caller-owned bounded record type; zero is not specially interpreted.
    pub kind: u16,
    /// Exact body, including arbitrary NUL/non-UTF8 bytes.
    pub bytes: &'a [u8],
}
#[derive(Clone, Copy)]
struct Record {
    sequence: u64,
    kind: u16,
    offset: u64,
    body_len: usize,
    digest: [u8; format::DIGEST],
}
struct Pending {
    sequence: u64,
    kind: u16,
    frame: Vec<u8>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Identity {
    dev: nix::libc::dev_t,
    ino: nix::libc::ino_t,
}
impl Identity {
    fn of(stat: &FileStat) -> Self {
        Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
        }
    }
}
/// One stable lock FD owns this anchored WAL until drop. It is never unlinked.
/// Accepted metadata and one reusable frame remain bounded by Limits; historical
/// bodies stay on the WAL. These are store limits, not a task-wide RAM budget.
/// Appends are synchronous
/// barriers: place this owner on a host worker if fsync must not block an executor.
pub struct Store {
    parent: File,
    name: OsString,
    root: File,
    root_id: Identity,
    lock: Flock<File>,
    lock_id: Identity,
    wal: File,
    wal_id: Identity,
    task_id: [u8; 32],
    limits: Limits,
    scratch: Vec<u8>,
    rows: Vec<Record>,
    end: u64,
    repaired_tail: u64,
    pending: Option<Pending>,
    failure: Option<Error>,
}
impl Store {
    /// Borrow the original anchored directory for crate-owned child stores.
    /// This is not a new naming or durability receipt.
    pub(crate) fn directory(&self) -> &File {
        &self.root
    }

    /// Create a NEW task directory below an existing caller-selected parent.
    /// A failed create leaves its original directory/files for inspection.
    pub fn create(path: impl AsRef<Path>, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let (parent, name) = parent(path.as_ref())?;
        Self::create_named(parent, name, limits)
    }
    /// Create one child under the caller's original directory descriptor.
    /// The parent pathname is never resolved again and existing children refuse.
    pub(crate) fn create_at(parent: &File, name: &OsStr, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let (parent, name) = child(parent, name)?;
        Self::create_named(parent, name, limits)
    }
    fn create_named(parent: File, name: OsString, limits: Limits) -> Result<Self, Error> {
        let mut id = [0; 32];
        File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut id))
            .map_err(|e| Error::native("task-id-entropy", Certainty::NotWritten, e))?;
        mkdirat(&parent, name.as_os_str(), Mode::S_IRWXU).map_err(|e| {
            Error::native(
                "create-directory",
                Certainty::NotWritten,
                io::Error::from(e),
            )
        })?;
        let root = File::from(
            openat(&parent, name.as_os_str(), DIRECTORY, Mode::empty()).map_err(|e| {
                Error::native(
                    "open-created-directory",
                    Certainty::NotWritten,
                    io::Error::from(e),
                )
            })?,
        );
        let lock = regular(&root, LOCK, true)?;
        let lock = lock_file(lock)?;
        let mut wal = regular(&root, WAL, true)?;
        wal.write_all(&format::header(&id))
            .map_err(|e| Error::native("create-header-write", Certainty::Unknown, e))?;
        wal.sync_all()
            .map_err(|e| Error::native("create-header-sync", Certainty::Unknown, e))?;
        lock.sync_all()
            .map_err(|e| Error::native("create-lock-sync", Certainty::Unknown, e))?;
        root.sync_all()
            .map_err(|e| Error::native("create-root-sync", Certainty::Unknown, e))?;
        parent
            .sync_all()
            .map_err(|e| Error::native("create-parent-sync", Certainty::Unknown, e))?;
        Self::assembled(parent, name, root, lock, wal, id, limits)
    }
    /// Reopen under the stable original lock, validate every complete record,
    /// repair only a provably incomplete final frame, and refresh durability.
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self, Error> {
        Self::open_inner(path, limits, None)
    }
    /// Open only the registered physical directory. Its actual root descriptor
    /// is checked before any lock/WAL open, recovery write or sync barrier.
    #[cfg(feature = "network")]
    pub(crate) fn open_registered(
        path: impl AsRef<Path>,
        limits: Limits,
        expected: crate::FileIdentity,
    ) -> Result<Self, Error> {
        Self::open_inner(path, limits, Some(expected))
    }
    fn open_inner(
        path: impl AsRef<Path>,
        limits: Limits,
        expected: Option<crate::FileIdentity>,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let (parent, name) = parent(path.as_ref())?;
        Self::open_named(parent, name, limits, expected)
    }
    /// Open a child of the original caller-owned directory, preserving its
    /// physical naming/lock/recovery checks without another parent resolution.
    pub(crate) fn open_at(parent: &File, name: &OsStr, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let (parent, name) = child(parent, name)?;
        Self::open_named(parent, name, limits, None)
    }
    fn open_named(
        parent: File,
        name: OsString,
        limits: Limits,
        expected: Option<crate::FileIdentity>,
    ) -> Result<Self, Error> {
        let root = File::from(
            openat(&parent, name.as_os_str(), DIRECTORY, Mode::empty()).map_err(|e| {
                Error::native("open-directory", Certainty::NotWritten, io::Error::from(e))
            })?,
        );
        if let Some(expected) = expected {
            let actual = crate::FileIdentity::of(&root).map_err(|error| {
                Error::native("registered-directory-stat", Certainty::NotWritten, error)
            })?;
            if actual != expected {
                return Err(Error::before(
                    "registered-directory-identity",
                    FailureKind::Authority,
                ));
            }
        }
        let lock = lock_file(regular(&root, LOCK, false)?)?;
        let mut wal = regular(&root, WAL, false)?;
        let mut header = [0; format::HEADER];
        wal.read_exact(&mut header)
            .map_err(|e| Error::native("read-header", Certainty::NotWritten, e))?;
        let id = format::decode_header(&header)?;
        let mut store = Self::assembled(parent, name, root, lock, wal, id, limits)?;
        store.load()?;
        store.verify()?;
        store
            .wal
            .sync_all()
            .map_err(|e| Error::native("open-wal-sync", Certainty::Unknown, e))?;
        store
            .root
            .sync_all()
            .map_err(|e| Error::native("open-root-sync", Certainty::Unknown, e))?;
        store
            .parent
            .sync_all()
            .map_err(|e| Error::native("open-parent-sync", Certainty::Unknown, e))?;
        store.verify()?;
        Ok(store)
    }
    fn assembled(
        parent: File,
        name: OsString,
        root: File,
        lock: Flock<File>,
        wal: File,
        task_id: [u8; 32],
        limits: Limits,
    ) -> Result<Self, Error> {
        let root_id = identity(&root, "root-identity")?;
        let lock_id = identity(&lock, "lock-identity")?;
        let wal_id = identity(&wal, "wal-identity")?;
        let store = Self {
            parent,
            name,
            root,
            root_id,
            lock,
            lock_id,
            wal,
            wal_id,
            task_id,
            limits,
            scratch: Vec::new(),
            rows: Vec::new(),
            end: format::HEADER as u64,
            repaired_tail: 0,
            pending: None,
            failure: None,
        };
        store.verify()?;
        Ok(store)
    }
    /// Secure-random persistent task identity; not a wire identifier or authority.
    #[must_use]
    pub const fn task_id(&self) -> &[u8; 32] {
        &self.task_id
    }
    /// Exactly known accepted records, excluding an uncertain append candidate.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.rows.len()
    }

    /// Read one accepted record through the original FD into the sole reusable
    /// buffer. Missing indices are distinct from real I/O/authority failures.
    /// A later self-consistent rewrite is refused against the original digest.
    /// Failure fences this owner; a previous unknown append keeps its sole frame
    /// and returns its original fence without allocating a second record buffer.
    pub fn read_record(&mut self, index: usize) -> Result<Option<RecordView<'_>>, Error> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let Some(row) = self.rows.get(index).copied() else {
            return Ok(None);
        };
        let result = (|| {
            self.verify()?;
            self.check_length(self.end)?;
            let total = format::record_size(row.body_len)?;
            self.prepare_scratch(total, "read-record-buffer")?;
            self.wal
                .read_exact_at(&mut self.scratch, row.offset)
                .map_err(|error| Error::native("read-record", Certainty::NotWritten, error))?;
            let metadata = format::prefix(
                &self.scratch[..format::RECORD_HEADER],
                row.sequence,
                self.limits,
            )?;
            if metadata != Some((row.kind, row.body_len)) {
                return Err(Error::before(
                    "read-record-metadata-changed",
                    FailureKind::Authority,
                ));
            }
            if format::verify_frame(&self.scratch)? != row.digest {
                return Err(Error::before(
                    "read-record-original-digest",
                    FailureKind::Checksum,
                ));
            }
            self.verify()?;
            self.check_length(self.end)
        })();
        if let Err(error) = result {
            return self.fence(error);
        }
        Ok(Some(RecordView {
            sequence: row.sequence,
            kind: row.kind,
            bytes: &self.scratch[format::RECORD_HEADER..format::RECORD_HEADER + row.body_len],
        }))
    }
    /// The original uncertain candidate, never an implicit successful record.
    #[must_use]
    pub fn pending_record(&self) -> Option<RecordView<'_>> {
        self.pending.as_ref().map(|p| RecordView {
            sequence: p.sequence,
            kind: p.kind,
            bytes: &p.frame[format::RECORD_HEADER..p.frame.len() - format::DIGEST],
        })
    }
    /// A failed append cannot issue any further write on this owner.
    #[must_use]
    pub const fn fenced(&self) -> bool {
        self.failure.is_some()
    }
    /// First original fence cause, shared unchanged with subsequent refusals.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.failure.as_ref()
    }
    /// Bytes removed from the sole provably incomplete final frame on reopen.
    #[must_use]
    pub const fn repaired_tail_bytes(&self) -> u64 {
        self.repaired_tail
    }
    /// Check retained-writer and numeric append bounds without allocating or
    /// performing I/O. Physical authority and durability are checked by append.
    pub fn check_append(&self, body_bytes: usize) -> Result<(), Error> {
        self.append_layout(body_bytes).map(|_| ())
    }
    fn append_layout(&self, body_bytes: usize) -> Result<(u64, u64), Error> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if body_bytes > self.limits.max_body_bytes || self.rows.len() == self.limits.max_records {
            return Err(Error::before("append-limits", FailureKind::Limit));
        }
        let sequence = u64::try_from(self.rows.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| Error::before("append-sequence", FailureKind::Limit))?;
        let frame_length = format::record_size(body_bytes)?;
        if frame_length > self.limits.max_scratch_bytes
            || self
                .rows
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(std::mem::size_of::<Record>()))
                .is_none_or(|bytes| bytes > self.limits.max_index_bytes)
        {
            return Err(Error::before("append-memory-limit", FailureKind::Limit));
        }
        let next = self
            .end
            .checked_add(frame_length as u64)
            .filter(|n| *n <= self.limits.max_file_bytes)
            .ok_or_else(|| Error::before("append-file-limit", FailureKind::Limit))?;
        Ok((sequence, next))
    }
    /// Append once, exposing the record only after its actual fsync and physical
    /// authority checks succeed. No retry/replay occurs after an uncertain write.
    pub fn append(&mut self, kind: u16, body: &[u8]) -> Result<u64, Error> {
        let (sequence, next) = self.append_layout(body.len())?;
        self.reserve_record("append-index-allocation")?;
        self.prepare_scratch(format::record_size(body.len())?, "append-frame-allocation")?;
        let digest = format::frame(sequence, kind, body, &mut self.scratch)?;
        if let Err(error) = self.verify().and_then(|()| self.check_length(self.end)) {
            return self.fence(error);
        }
        if let Err(error) = self.wal.seek(SeekFrom::Start(self.end)) {
            return self.fence(Error::native("append-seek", Certainty::NotWritten, error));
        }
        self.pending = Some(Pending {
            sequence,
            kind,
            frame: std::mem::take(&mut self.scratch),
        });
        let result = (|| {
            let frame = &self
                .pending
                .as_ref()
                .ok_or_else(|| Error::before("append-original", FailureKind::Authority))?
                .frame;
            self.wal
                .write_all(frame)
                .map_err(|e| Error::native("append-write", Certainty::Unknown, e))?;
            self.wal
                .sync_all()
                .map_err(|e| Error::native("append-sync", Certainty::Unknown, e))?;
            self.verify()
                .map_err(|e| e.with_certainty(Certainty::Unknown))?;
            self.check_length(next)
                .map_err(|e| e.with_certainty(Certainty::Unknown))?;
            Ok(())
        })();
        if let Err(error) = result {
            return self.fence(error);
        }
        self.rows.push(Record {
            sequence,
            kind,
            offset: self.end,
            body_len: body.len(),
            digest,
        });
        self.end = next;
        if let Some(pending) = self.pending.take() {
            self.scratch = pending.frame;
        }
        Ok(sequence)
    }
    fn fence<T>(&mut self, error: Error) -> Result<T, Error> {
        if let Some(original) = &self.failure {
            return Err(original.clone());
        }
        self.failure = Some(error.clone());
        Err(error)
    }
    fn prepare_scratch(&mut self, total: usize, stage: &'static str) -> Result<(), Error> {
        if total > self.limits.max_scratch_bytes {
            return Err(Error::before(stage, FailureKind::Limit));
        }
        if self.scratch.capacity() < total {
            // No view can coexist with this mutable call. Release the old
            // buffer first, avoiding a hidden old+replacement frame peak.
            self.scratch = Vec::new();
            self.scratch
                .try_reserve_exact(total)
                .map_err(|_| Error::before(stage, FailureKind::Allocation))?;
            if self.scratch.capacity() > self.limits.max_scratch_bytes {
                self.scratch = Vec::new();
                return Err(Error::before(stage, FailureKind::Limit));
            }
        }
        self.scratch.resize(total, 0);
        Ok(())
    }
    fn reserve_record(&mut self, stage: &'static str) -> Result<(), Error> {
        if self.rows.len() < self.rows.capacity() {
            return Ok(());
        }
        let size = std::mem::size_of::<Record>();
        let old = self
            .rows
            .capacity()
            .checked_mul(size)
            .ok_or_else(|| Error::before(stage, FailureKind::Limit))?;
        let available = self
            .limits
            .max_index_bytes
            .checked_sub(old)
            .ok_or_else(|| Error::before(stage, FailureKind::Limit))?;
        let target = self
            .rows
            .capacity()
            .max(2)
            .saturating_mul(2)
            .min(self.limits.max_records)
            .min(available / size);
        if target <= self.rows.len() {
            return Err(Error::before(stage, FailureKind::Limit));
        }
        let mut replacement = Vec::new();
        replacement
            .try_reserve_exact(target)
            .map_err(|_| Error::before(stage, FailureKind::Allocation))?;
        if replacement
            .capacity()
            .checked_mul(size)
            .is_none_or(|bytes| bytes > available)
        {
            return Err(Error::before(stage, FailureKind::Limit));
        }
        replacement.extend_from_slice(&self.rows);
        self.rows = replacement;
        Ok(())
    }
    fn check_length(&self, expected: u64) -> Result<(), Error> {
        let actual = self
            .wal
            .metadata()
            .map_err(|e| Error::native("wal-length", Certainty::NotWritten, e))?
            .len();
        if actual != expected {
            return Err(Error::before("wal-length-changed", FailureKind::Authority));
        }
        Ok(())
    }
    fn verify(&self) -> Result<(), Error> {
        for (directory, name, file, original) in [
            (
                &self.parent,
                self.name.as_os_str(),
                &self.root,
                self.root_id,
            ),
            (
                &self.root,
                std::ffi::OsStr::new(LOCK),
                &*self.lock,
                self.lock_id,
            ),
            (
                &self.root,
                std::ffi::OsStr::new(WAL),
                &self.wal,
                self.wal_id,
            ),
        ] {
            let current = fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW).map_err(|e| {
                Error::native("name-authority", Certainty::NotWritten, io::Error::from(e))
            })?;
            if Identity::of(&current) != original
                || identity(file, "retained-authority")? != original
            {
                return Err(Error::before("replaced-authority", FailureKind::Authority));
            }
        }
        let mut header = [0; format::HEADER];
        self.wal.read_exact_at(&mut header, 0).map_err(|error| {
            Error::native("header-authority-read", Certainty::NotWritten, error)
        })?;
        if header != format::header(&self.task_id) {
            return Err(Error::before(
                "header-authority-changed",
                FailureKind::Authority,
            ));
        }
        Ok(())
    }
    fn load(&mut self) -> Result<(), Error> {
        let length = self
            .wal
            .metadata()
            .map_err(|e| Error::native("load-length", Certainty::NotWritten, e))?
            .len();
        if length < format::HEADER as u64 || length > self.limits.max_file_bytes {
            return Err(Error::before("load-file-limit", FailureKind::Limit));
        }
        while self.end < length {
            self.verify()?;
            self.check_length(length)?;
            let remaining = length - self.end;
            let sequence = u64::try_from(self.rows.len())
                .ok()
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| Error::before("load-sequence", FailureKind::Limit))?;
            let head_len = usize::try_from(remaining.min(format::RECORD_HEADER as u64))
                .map_err(|_| Error::before("load-header-length", FailureKind::Limit))?;
            let mut head = [0; format::RECORD_HEADER];
            self.wal
                .read_exact_at(&mut head[..head_len], self.end)
                .map_err(|e| Error::native("load-record-header", Certainty::NotWritten, e))?;
            let Some((kind, body_len)) = format::prefix(&head[..head_len], sequence, self.limits)?
            else {
                return self.repair_tail(length);
            };
            let total = format::record_size(body_len)?;
            if self
                .end
                .checked_add(total as u64)
                .is_none_or(|end| end > self.limits.max_file_bytes)
            {
                return Err(Error::before(
                    "load-declared-file-limit",
                    FailureKind::Limit,
                ));
            }
            if remaining < total as u64 {
                let present = usize::try_from(remaining)
                    .map_err(|_| Error::before("load-partial-length", FailureKind::Limit))?;
                self.prepare_scratch(present, "load-partial-allocation")?;
                self.scratch[..format::RECORD_HEADER].copy_from_slice(&head);
                self.wal
                    .read_exact_at(
                        &mut self.scratch[format::RECORD_HEADER..],
                        self.end + format::RECORD_HEADER as u64,
                    )
                    .map_err(|e| Error::native("load-partial-body", Certainty::NotWritten, e))?;
                format::verify_incomplete_frame(&self.scratch, body_len)?;
                return self.repair_tail(length);
            }
            if self.rows.len() == self.limits.max_records {
                return Err(Error::before("load-record-limit", FailureKind::Limit));
            }
            self.reserve_record("load-index-allocation")?;
            self.prepare_scratch(total, "load-frame-allocation")?;
            self.scratch[..format::RECORD_HEADER].copy_from_slice(&head);
            self.wal
                .read_exact_at(
                    &mut self.scratch[format::RECORD_HEADER..],
                    self.end + format::RECORD_HEADER as u64,
                )
                .map_err(|e| Error::native("load-record-body", Certainty::NotWritten, e))?;
            let digest = format::verify_frame(&self.scratch)?;
            self.verify()?;
            self.check_length(length)?;
            self.rows.push(Record {
                sequence,
                kind,
                offset: self.end,
                body_len,
                digest,
            });
            self.end += total as u64;
        }
        self.check_length(length)
    }
    fn repair_tail(&mut self, original_length: u64) -> Result<(), Error> {
        self.verify()?;
        self.check_length(original_length)?;
        self.wal
            .set_len(self.end)
            .map_err(|e| Error::native("repair-truncate", Certainty::Unknown, e))?;
        self.wal
            .sync_all()
            .map_err(|e| Error::native("repair-sync", Certainty::Unknown, e))?;
        self.repaired_tail = original_length - self.end;
        Ok(())
    }
}
fn child(parent: &File, name: &OsStr) -> Result<(File, OsString), Error> {
    let raw = name.as_encoded_bytes();
    if raw.is_empty() || raw.contains(&0) || raw.contains(&b'/') || matches!(raw, b"." | b"..") {
        return Err(Error::before("task-child-name", FailureKind::Malformed));
    }
    let parent = parent
        .try_clone()
        .map_err(|error| Error::native("task-child-parent", Certainty::NotWritten, error))?;
    Ok((parent, name.to_os_string()))
}
fn parent(path: &Path) -> Result<(File, OsString), Error> {
    let name = path
        .file_name()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| Error::before("task-directory-name", FailureKind::Malformed))?
        .to_os_string();
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(Error::before("task-directory-nul", FailureKind::Malformed));
    }
    let selected = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let selected = fs::canonicalize(selected)
        .map_err(|e| Error::native("parent-resolve", Certainty::NotWritten, e))?;
    let parent =
        File::from(open(&selected, DIRECTORY, Mode::empty()).map_err(|e| {
            Error::native("parent-open", Certainty::NotWritten, io::Error::from(e))
        })?);
    Ok((parent, name))
}
fn regular(root: &File, name: &str, create: bool) -> Result<File, Error> {
    let flags = if create {
        REGULAR | OFlag::O_CREAT | OFlag::O_EXCL
    } else {
        REGULAR
    };
    let file = File::from(
        openat(root, name, flags, Mode::S_IRUSR | Mode::S_IWUSR).map_err(|e| {
            Error::native("regular-open", Certainty::NotWritten, io::Error::from(e))
        })?,
    );
    let stat = fstat(&file)
        .map_err(|e| Error::native("regular-stat", Certainty::NotWritten, io::Error::from(e)))?;
    if (stat.st_mode & SFlag::S_IFMT.bits()) != SFlag::S_IFREG.bits() || stat.st_nlink != 1 {
        return Err(Error::before("regular-file-shape", FailureKind::Authority));
    }
    Ok(file)
}
fn lock_file(file: File) -> Result<Flock<File>, Error> {
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, error)| {
        Error::new(
            "writer-lock",
            if error == Errno::EWOULDBLOCK {
                FailureKind::Locked
            } else {
                FailureKind::Io
            },
            Certainty::NotWritten,
            Some(io::Error::from(error)),
        )
    })
}
fn identity(file: &File, stage: &'static str) -> Result<Identity, Error> {
    fstat(file)
        .map(|stat| Identity::of(&stat))
        .map_err(|e| Error::native(stage, Certainty::NotWritten, io::Error::from(e)))
}
