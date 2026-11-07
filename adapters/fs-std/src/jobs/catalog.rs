//! Durable explicit discovery of existing FS tasks and local scheduling intent.
//!
//! Catalog facts never authorize a mutation retry or establish task completion.
//! Runners must open the original typed task, compare its random identity and
//! apply its original ACK/Unknown and lifecycle rules. Reopen lists missing or
//! changed paths without adopting replacements; execution revalidates bindings.

#[cfg(test)]
mod tests;
use crate::durable::store::{self, Store};
use gnunet_types::Error as ProtocolError;
use nix::{
    fcntl::{OFlag, open},
    sys::stat::Mode,
};
use std::{
    collections::HashSet,
    ffi::OsString,
    fmt,
    fs::File,
    io,
    mem::size_of,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
};

const MANIFEST: u16 = 0x4a00;
const REGISTER: u16 = 0x4a01;
const ENABLE: u16 = 0x4a02;
const POLICY: u16 = 0x4a03;
const MAGIC: &[u8; 8] = b"FSJCAT01";

/// Explicit private catalog bounds, separate from every original task's limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original private WAL record/body/file budgets.
    pub storage: store::Limits,
    /// Number of distinct registered task identities.
    pub max_entries: usize,
    /// Maximum raw bytes in each canonical absolute directory path.
    pub max_path_bytes: usize,
    /// Logical owned record/path bytes; the WAL has independent storage limits.
    pub max_retained_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            storage: store::Limits::default(),
            max_entries: 1024,
            max_path_bytes: 4096,
            max_retained_bytes: 16 * 1024 * 1024,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.max_entries == 0
            || self.max_path_bytes == 0
            || self.max_path_bytes > u32::MAX as usize
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        Ok(())
    }
}

/// Original catalog refusal. A storage failure preserves its native certainty.
#[derive(Debug)]
pub enum Error {
    /// Original physical WAL/lock/authority failure or uncertain append fence.
    Storage(store::Error),
    /// Original canonicalization or directory-open failure.
    Io(io::Error),
    /// Checked resource, shape, identity or generation refusal.
    Protocol(ProtocolError),
    /// The directory no longer has the captured physical identity.
    Authority,
    /// An existing identity, path or directory is already registered.
    Conflict,
    /// A complete private catalog record has an invalid shape or sequence.
    Malformed,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Authority => f.write_str("catalog directory authority changed"),
            Self::Conflict => f.write_str("catalog task binding already registered"),
            Self::Malformed => f.write_str("malformed catalog record"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Authority | Self::Conflict | Self::Malformed => None,
        }
    }
}
impl From<store::Error> for Error {
    fn from(value: store::Error) -> Self {
        Self::Storage(value)
    }
}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<ProtocolError> for Error {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

/// Canonical raw-byte directory path and captured device/inode. This is local
/// configuration, not a content receipt or permission to replace the directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Directory {
    path: PathBuf,
    device: u64,
    inode: u64,
}
impl Directory {
    /// Canonicalize a caller-selected existing directory and capture its actual
    /// no-follow final descriptor identity. No task or service is opened here.
    pub fn capture(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = std::fs::canonicalize(path)?;
        let file = open_directory(&path)?;
        let metadata = file.metadata()?;
        Ok(Self {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    /// Original canonical absolute directory name, retaining arbitrary OS bytes.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Captured native device and inode for diagnostics only.
    #[must_use]
    pub const fn identity(&self) -> crate::FileIdentity {
        crate::FileIdentity {
            device: self.device,
            inode: self.inode,
        }
    }
    /// Refuse a replacement or symlink without changing the selected path.
    /// Runners must still compare their opened typed task's random identity.
    pub fn revalidate(&self) -> Result<(), Error> {
        drop(self.open()?);
        Ok(())
    }
    /// Open the original captured directory, checking the actual descriptor's
    /// identity before returning it. Callers should build their output/cache
    /// owner from this descriptor rather than stat a path before reopening it.
    pub fn open(&self) -> Result<File, Error> {
        let file = open_directory(&self.path)?;
        if crate::FileIdentity::of(&file)? != self.identity() {
            return Err(Error::Authority);
        }
        Ok(file)
    }
    fn bytes(&self) -> usize {
        self.path.as_os_str().as_bytes().len()
    }
}
fn open_directory(path: &Path) -> Result<File, Error> {
    Ok(File::from(
        open(
            path,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?,
    ))
}

/// Existing typed task owner, never inferred from a filename or a bare WAL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Durable directory or selected regular-file download and anchored output.
    Download,
    /// Durable authenticated search observations.
    Search,
    /// Durable prepared publication over exact original mutation receipts.
    Publication,
    /// Durable actual selected-range availability observations.
    Probe,
    /// Durable exact-file unindex with original mutation receipts.
    Unindex,
}

/// Local scheduling intent. It cannot clear task failure, refusal or uncertainty.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Positive finite logical budget for one run in the worker's source domain.
    pub slice_us: u64,
    /// Positive new-file/result/ACK quota, or None for only the time bound.
    pub quota: Option<usize>,
    /// Positive delay after a safely resumable pause; None means one dispatch.
    pub repeat_delay_us: Option<u64>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            slice_us: 30_000_000,
            quota: Some(64),
            repeat_delay_us: None,
        }
    }
}
impl Policy {
    /// Check only local scheduling representation and nonzero bounds.
    pub fn validate(self) -> Result<(), Error> {
        if self.slice_us == 0
            || self.slice_us == u64::MAX
            || self.quota == Some(0)
            || matches!(self.repeat_delay_us, Some(0 | u64::MAX))
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        Ok(())
    }
}

/// Original task and required host bindings. A caller registers this only after
/// opening the typed task and reading its actual identity. Execution must repeat
/// those checks; catalog registration alone cannot establish typed task meaning.
#[derive(Clone, Debug)]
pub struct Registration {
    /// Actual secure-random identity read from the original typed task.
    pub task_id: [u8; 32],
    /// Caller-selected typed task owner, checked again during execution.
    pub kind: Kind,
    /// Original task directory and its physical identity.
    pub task: Directory,
    /// Download output parent; required only for downloads.
    pub output_parent: Option<Directory>,
    /// Download block repository; required only for downloads.
    pub cache: Option<Directory>,
    /// Original managed namespace graph, when required by the publication.
    pub graph: Option<Directory>,
    /// Local scheduling intention, without task completion or retry authority.
    pub policy: Policy,
}
impl Registration {
    fn directories(&self) -> impl Iterator<Item = &Directory> {
        std::iter::once(&self.task)
            .chain(self.output_parent.iter())
            .chain(self.cache.iter())
            .chain(self.graph.iter())
    }
    /// Check every captured path identity without opening a typed task or socket.
    pub fn revalidate(&self) -> Result<(), Error> {
        for directory in self.directories() {
            directory.revalidate()?;
        }
        Ok(())
    }
    fn validate(&self, limits: Limits) -> Result<(), Error> {
        self.policy.validate()?;
        let valid = match self.kind {
            Kind::Download => {
                self.output_parent.is_some() && self.cache.is_some() && self.graph.is_none()
            }
            Kind::Search | Kind::Probe | Kind::Unindex => {
                self.output_parent.is_none() && self.cache.is_none() && self.graph.is_none()
            }
            Kind::Publication => self.output_parent.is_none() && self.cache.is_none(),
        };
        if !valid {
            return Err(ProtocolError::InvalidInput.into());
        }
        for directory in self.directories() {
            validate_path(&directory.path, limits.max_path_bytes)?;
        }
        Ok(())
    }
    fn retained(&self) -> Result<usize, Error> {
        self.directories()
            .try_fold(
                size_of::<Owned>()
                    + size_of::<[u8; 32]>()
                    + size_of::<PathBuf>()
                    + size_of::<(u64, u64)>(),
                |total, directory| {
                    total
                        .checked_add(directory.bytes())
                        .ok_or(Error::Protocol(ProtocolError::Overflow))
                },
            )?
            .checked_add(self.task.bytes())
            .ok_or(Error::Protocol(ProtocolError::Overflow))
    }
}

/// Persistent coordinate scoped to this original catalog, valid across reopen.
/// Its index is diagnostic and cannot grant another catalog's task authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryId {
    catalog: [u8; 32],
    index: usize,
}
impl EntryId {
    /// Stable zero-based registration position in this catalog only.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }
}
/// Borrowed historical registration and local enabled intent.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    /// Original catalog-scoped entry coordinate.
    pub id: EntryId,
    /// Original task identity and physical host configuration.
    pub registration: &'a Registration,
    /// Whether dispatch is requested; not whether any task is currently running.
    pub enabled: bool,
}
struct Owned {
    registration: Registration,
    enabled: bool,
}

/// One exclusively locked catalog. It stores no running/success marker and never
/// replays a native request; original typed task WALs own all effect certainty.
pub struct Catalog {
    store: Store,
    entries: Vec<Owned>,
    ids: HashSet<[u8; 32]>,
    paths: HashSet<PathBuf>,
    directories: HashSet<(u64, u64)>,
    retained: usize,
    limits: Limits,
}
impl Catalog {
    /// Create a new catalog directory and sync its private manifest.
    pub fn create(path: impl AsRef<Path>, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let mut store = Store::create(path, limits.storage)?;
        store.append(MANIFEST, MAGIC)?;
        Ok(Self {
            store,
            entries: Vec::new(),
            ids: HashSet::new(),
            paths: HashSet::new(),
            directories: HashSet::new(),
            retained: 0,
            limits,
        })
    }
    /// Lock/replay an existing catalog without opening task/service/output owners.
    /// Unavailable task paths remain discoverable and are refused by execution.
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let store = Store::open(path, limits.storage)?;
        let mut catalog = Self {
            store,
            entries: Vec::new(),
            ids: HashSet::new(),
            paths: HashSet::new(),
            directories: HashSet::new(),
            retained: 0,
            limits,
        };
        let record_count = catalog.store.record_count();
        for index in 0..record_count {
            let record = catalog.store.read_record(index)?.ok_or(Error::Malformed)?;
            if index == 0 {
                if record.kind != MANIFEST || record.bytes != MAGIC {
                    return Err(Error::Malformed);
                }
                continue;
            }
            match record.kind {
                REGISTER => {
                    let registration = decode_registration(record.bytes, limits)?;
                    catalog.check_new(&registration)?;
                    let indexed_path = catalog.prepare_index(&registration)?;
                    catalog.commit_index(&registration, indexed_path);
                    catalog.retained += registration.retained()?;
                    catalog.entries.push(Owned {
                        registration,
                        enabled: true,
                    });
                }
                ENABLE => {
                    let mut r = Reader::new(record.bytes);
                    let (index, id) = r.coordinate()?;
                    let enabled = r.boolean()?;
                    r.end()?;
                    let entry = catalog.entries.get_mut(index).ok_or(Error::Malformed)?;
                    if entry.registration.task_id != id {
                        return Err(Error::Malformed);
                    }
                    entry.enabled = enabled;
                }
                POLICY => {
                    let mut r = Reader::new(record.bytes);
                    let (index, id) = r.coordinate()?;
                    let policy = r.policy()?;
                    r.end()?;
                    policy.validate()?;
                    let entry = catalog.entries.get_mut(index).ok_or(Error::Malformed)?;
                    if entry.registration.task_id != id {
                        return Err(Error::Malformed);
                    }
                    entry.registration.policy = policy;
                }
                _ => return Err(Error::Malformed),
            }
        }
        if catalog.store.record_count() == 0 {
            return Err(Error::Malformed);
        }
        Ok(catalog)
    }
    /// Original persistent catalog identity, never a network identifier.
    #[must_use]
    pub fn task_id(&self) -> &[u8; 32] {
        self.store.task_id()
    }
    /// Original first append/authority refusal, including unknown certainty.
    #[must_use]
    pub fn storage_failure(&self) -> Option<&store::Error> {
        self.store.failure()
    }
    /// Original writer has an unresolved append and permits no further mutation.
    #[must_use]
    pub fn fenced(&self) -> bool {
        self.store.fenced()
    }
    /// Discover every registration, without claiming live task status.
    pub fn entries(&self) -> impl ExactSizeIterator<Item = Record<'_>> {
        self.entries
            .iter()
            .enumerate()
            .map(|(index, entry)| self.record(index, entry))
    }
    /// Resolve only a coordinate belonging to this original catalog.
    #[must_use]
    pub fn entry(&self, id: EntryId) -> Option<Record<'_>> {
        if id.catalog != *self.store.task_id() {
            return None;
        }
        self.entry_at(id.index)
    }
    /// Interpret a diagnostic CLI index within this explicitly selected catalog.
    #[must_use]
    pub fn entry_at(&self, index: usize) -> Option<Record<'_>> {
        self.entries
            .get(index)
            .map(|entry| self.record(index, entry))
    }
    fn record<'a>(&self, index: usize, entry: &'a Owned) -> Record<'a> {
        Record {
            id: EntryId {
                catalog: *self.store.task_id(),
                index,
            },
            registration: &entry.registration,
            enabled: entry.enabled,
        }
    }
    fn check_new(&self, registration: &Registration) -> Result<(), Error> {
        registration.validate(self.limits)?;
        if self.entries.len() >= self.limits.max_entries {
            return Err(ProtocolError::Capacity.into());
        }
        if registration.task_id == *self.store.task_id()
            || self.ids.contains(&registration.task_id)
            || self.paths.contains(&registration.task.path)
            || self
                .directories
                .contains(&(registration.task.device, registration.task.inode))
        {
            return Err(Error::Conflict);
        }
        if self
            .retained
            .checked_add(registration.retained()?)
            .is_none_or(|n| n > self.limits.max_retained_bytes)
        {
            return Err(ProtocolError::Capacity.into());
        }
        Ok(())
    }
    fn prepare_index(&mut self, registration: &Registration) -> Result<PathBuf, Error> {
        reserve(&mut self.entries, 1)?;
        self.ids
            .try_reserve(1)
            .map_err(|_| ProtocolError::Capacity)?;
        self.paths
            .try_reserve(1)
            .map_err(|_| ProtocolError::Capacity)?;
        self.directories
            .try_reserve(1)
            .map_err(|_| ProtocolError::Capacity)?;
        let raw = registration.task.path.as_os_str().as_bytes();
        let mut bytes = Vec::new();
        reserve(&mut bytes, raw.len())?;
        bytes.extend_from_slice(raw);
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }
    fn commit_index(&mut self, registration: &Registration, path: PathBuf) {
        let _new_id = self.ids.insert(registration.task_id);
        let _new_path = self.paths.insert(path);
        let _new_directory = self
            .directories
            .insert((registration.task.device, registration.task.inode));
    }
    /// Register original typed-task facts after rechecking every directory. No
    /// task is run, unlocked, cancelled, completed or authorized for retry here.
    pub fn register(&mut self, registration: Registration) -> Result<EntryId, Error> {
        self.store.check_append(0)?;
        self.check_new(&registration)?;
        registration.revalidate()?;
        let body = encode_registration(&registration)?;
        let indexed_path = self.prepare_index(&registration)?;
        self.store.append(REGISTER, &body)?;
        let index = self.entries.len();
        self.commit_index(&registration, indexed_path);
        self.retained += registration.retained()?;
        self.entries.push(Owned {
            registration,
            enabled: true,
        });
        Ok(EntryId {
            catalog: *self.store.task_id(),
            index,
        })
    }
    /// Persist enabled intent only. Disabling does not cancel a separately owned
    /// live task; the worker must request and settle its original operation.
    pub fn set_enabled(&mut self, id: EntryId, enabled: bool) -> Result<(), Error> {
        let index = self.index(id)?;
        if self.entries[index].enabled == enabled {
            self.store.check_append(0)?;
            return Ok(());
        }
        let mut body = coordinate(index, self.entries[index].registration.task_id)?;
        put(&mut body, &[u8::from(enabled)])?;
        self.store.append(ENABLE, &body)?;
        self.entries[index].enabled = enabled;
        Ok(())
    }
    /// Persist a new local policy without altering original task effect/lifecycle.
    pub fn set_policy(&mut self, id: EntryId, policy: Policy) -> Result<(), Error> {
        let index = self.index(id)?;
        policy.validate()?;
        if self.entries[index].registration.policy == policy {
            self.store.check_append(0)?;
            return Ok(());
        }
        let mut body = coordinate(index, self.entries[index].registration.task_id)?;
        encode_policy(policy, &mut body)?;
        self.store.append(POLICY, &body)?;
        self.entries[index].registration.policy = policy;
        Ok(())
    }
    fn index(&self, id: EntryId) -> Result<usize, Error> {
        if id.catalog != *self.store.task_id() || id.index >= self.entries.len() {
            return Err(ProtocolError::Stale.into());
        }
        Ok(id.index)
    }
}

fn validate_path(path: &Path, limit: usize) -> Result<(), Error> {
    let raw = path.as_os_str().as_bytes();
    if raw.is_empty() || raw.len() > limit || raw.contains(&0) || !path.is_absolute() {
        return Err(ProtocolError::InvalidInput.into());
    }
    let mut rebuilt = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => rebuilt.push(name),
            _ => return Err(ProtocolError::InvalidInput.into()),
        }
    }
    if rebuilt.as_os_str().as_bytes() != raw {
        return Err(ProtocolError::InvalidInput.into());
    }
    Ok(())
}
fn reserve<T>(v: &mut Vec<T>, n: usize) -> Result<(), Error> {
    v.try_reserve_exact(n)
        .map_err(|_| ProtocolError::Capacity.into())
}
fn put(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    reserve(out, bytes.len())?;
    out.extend_from_slice(bytes);
    Ok(())
}
fn coordinate(index: usize, id: [u8; 32]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    put(
        &mut out,
        &u64::try_from(index)
            .map_err(|_| ProtocolError::Overflow)?
            .to_be_bytes(),
    )?;
    put(&mut out, &id)?;
    Ok(out)
}
fn encode_policy(policy: Policy, out: &mut Vec<u8>) -> Result<(), Error> {
    put(out, &policy.slice_us.to_be_bytes())?;
    match policy.quota {
        None => put(out, &[0])?,
        Some(value) => {
            put(out, &[1])?;
            put(
                out,
                &u64::try_from(value)
                    .map_err(|_| ProtocolError::Overflow)?
                    .to_be_bytes(),
            )?;
        }
    }
    match policy.repeat_delay_us {
        None => put(out, &[0])?,
        Some(value) => {
            put(out, &[1])?;
            put(out, &value.to_be_bytes())?;
        }
    }
    Ok(())
}
fn encode_directory(directory: &Directory, out: &mut Vec<u8>) -> Result<(), Error> {
    let path = directory.path.as_os_str().as_bytes();
    put(
        out,
        &u32::try_from(path.len())
            .map_err(|_| ProtocolError::Overflow)?
            .to_be_bytes(),
    )?;
    put(out, path)?;
    put(out, &directory.device.to_be_bytes())?;
    put(out, &directory.inode.to_be_bytes())?;
    Ok(())
}
fn encode_registration(value: &Registration) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    put(&mut out, &value.task_id)?;
    put(
        &mut out,
        &[match value.kind {
            Kind::Download => 0,
            Kind::Search => 1,
            Kind::Publication => 2,
            Kind::Probe => 4,
            Kind::Unindex => 5,
        }],
    )?;
    encode_directory(&value.task, &mut out)?;
    for directory in [&value.output_parent, &value.cache, &value.graph] {
        match directory {
            None => put(&mut out, &[0])?,
            Some(directory) => {
                put(&mut out, &[1])?;
                encode_directory(directory, &mut out)?;
            }
        }
    }
    encode_policy(value.policy, &mut out)?;
    Ok(out)
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.at.checked_add(n).ok_or(Error::Malformed)?;
        let value = self.bytes.get(self.at..end).ok_or(Error::Malformed)?;
        self.at = end;
        Ok(value)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn boolean(&mut self) -> Result<bool, Error> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Malformed),
        }
    }
    fn word(&mut self) -> Result<u64, Error> {
        let mut word = [0; 8];
        word.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(word))
    }
    fn id(&mut self) -> Result<[u8; 32], Error> {
        let mut id = [0; 32];
        id.copy_from_slice(self.take(32)?);
        Ok(id)
    }
    fn coordinate(&mut self) -> Result<(usize, [u8; 32]), Error> {
        let index = usize::try_from(self.word()?).map_err(|_| ProtocolError::Overflow)?;
        Ok((index, self.id()?))
    }
    fn policy(&mut self) -> Result<Policy, Error> {
        let slice_us = self.word()?;
        let quota = if self.boolean()? {
            Some(usize::try_from(self.word()?).map_err(|_| ProtocolError::Overflow)?)
        } else {
            None
        };
        let repeat_delay_us = if self.boolean()? {
            Some(self.word()?)
        } else {
            None
        };
        Ok(Policy {
            slice_us,
            quota,
            repeat_delay_us,
        })
    }
    fn directory(&mut self, limits: Limits) -> Result<Directory, Error> {
        let mut word = [0; 4];
        word.copy_from_slice(self.take(4)?);
        let len = u32::from_be_bytes(word) as usize;
        if len > limits.max_path_bytes {
            return Err(ProtocolError::Capacity.into());
        }
        let raw = self.take(len)?;
        let mut bytes = Vec::new();
        reserve(&mut bytes, len)?;
        bytes.extend_from_slice(raw);
        let path = PathBuf::from(OsString::from_vec(bytes));
        validate_path(&path, limits.max_path_bytes)?;
        Ok(Directory {
            path,
            device: self.word()?,
            inode: self.word()?,
        })
    }
    fn maybe_directory(&mut self, limits: Limits) -> Result<Option<Directory>, Error> {
        if self.boolean()? {
            Ok(Some(self.directory(limits)?))
        } else {
            Ok(None)
        }
    }
    fn end(self) -> Result<(), Error> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Malformed)
        }
    }
}
fn decode_registration(bytes: &[u8], limits: Limits) -> Result<Registration, Error> {
    let mut r = Reader::new(bytes);
    let task_id = r.id()?;
    let kind = match r.byte()? {
        0 => Kind::Download,
        1 => Kind::Search,
        2 => Kind::Publication,
        4 => Kind::Probe,
        5 => Kind::Unindex,
        _ => return Err(Error::Malformed),
    };
    let task = r.directory(limits)?;
    let output_parent = r.maybe_directory(limits)?;
    let cache = r.maybe_directory(limits)?;
    let graph = r.maybe_directory(limits)?;
    let policy = r.policy()?;
    r.end()?;
    let registration = Registration {
        task_id,
        kind,
        task,
        output_parent,
        cache,
        graph,
        policy,
    };
    registration.validate(limits)?;
    Ok(registration)
}
