//! Durable native FS index registrations and actual type6 on-demand DBLOCKs.
//!
//! All methods perform synchronous filesystem work and belong on the enclosing
//! service's serialized worker. The private metadata store reuses the Rust WAL
//! backend; its values are never public DATASTORE blocks or a wire extension.
use gnunet_crypto::Hash512State;
use gnunet_datastore::backend::{
    Backend, BackendError, ENTRY_OVERHEAD, Failure, Put, PutPolicy, Selection,
};
use gnunet_datastore_host::backend::{self, Store};
use gnunet_fs::content::{self, BLOCK_BYTES, BlockKey};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::{AbsoluteTime, datastore::MAX_VALUE_BYTES};
use std::{
    fmt,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    slice,
};

const MAGIC: &[u8; 8] = b"RFSIDX01";
const HEADER: usize = 12;
const KIND: u32 = 0; // Internal metadata only, never an advertised block type.

/// Finite metadata and source-reading bounds, separate from public block quota.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum registered whole-file identities.
    pub max_entries: usize,
    /// Maximum stored expanded OS filename bytes, excluding a terminating NUL.
    pub max_path_bytes: usize,
    /// Sum of stored filename lengths across the complete private index.
    pub max_total_path_bytes: usize,
    /// Maximum source length accepted for registration or on-demand reads.
    pub max_file_bytes: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 16_384,
            max_path_bytes: 16 * 1024,
            max_total_path_bytes: 64 * 1024 * 1024,
            max_file_bytes: 256 * 1024 * 1024 * 1024,
        }
    }
}

/// Original source, format, capacity or persistent-backend refusal.
#[derive(Debug)]
pub enum Error {
    /// Original OS source-file/path failure.
    Io(io::Error),
    /// Original Rust backend failure with its actual commit certainty.
    Storage(backend::Error),
    /// Exact local resource or protocol refusal.
    Protocol(ProtocolError),
    /// Whole-file content failed the requested registration hash.
    HashMismatch,
    /// Original opened source changed while it was being read or validated.
    SourceChanged,
    /// No registration exists for this on-demand whole-file identity.
    NotIndexed,
    /// The datastore's type6 body does not have the exact official72-byte layout.
    MalformedRecord,
    /// Actual re-encoding did not match the requested ciphertext query.
    BlockMismatch,
}
impl Error {
    /// Only the actual backend can report an uncertain index mutation.
    #[must_use]
    pub fn certainty(&self) -> Failure {
        match self {
            Self::Storage(error) => error.certainty(),
            _ => Failure::BeforeCommit,
        }
    }
    /// Fixed NUL-free public registration diagnostic; the owned error retains
    /// its complete original source independently of this small wire message.
    #[must_use]
    pub fn message(&self) -> &'static [u8] {
        match self {
            Self::HashMismatch => b"hash mismatch",
            Self::SourceChanged => b"source file changed",
            Self::NotIndexed => b"file is not indexed",
            Self::MalformedRecord => b"invalid on-demand record",
            Self::BlockMismatch => b"indexed block changed",
            Self::Protocol(ProtocolError::Capacity | ProtocolError::TooLarge) => {
                b"index capacity exceeded"
            }
            Self::Protocol(ProtocolError::Cancelled) => b"index validation cancelled",
            Self::Storage(_) => b"index storage failed",
            Self::Io(_) => b"cannot read indexed file",
            Self::Protocol(_) => b"invalid index request",
        }
    }
    /// When resolving a type6 record, these failures prove its stored source
    /// body is unusable and permit removing that exact key/value record. Resource
    /// refusal, cancellation, absent registration and backend uncertainty do not.
    #[must_use]
    pub fn remove_on_demand_record(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::SourceChanged | Self::MalformedRecord | Self::BlockMismatch
        )
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "FS index source: {error}"),
            Self::Storage(error) => write!(f, "FS index storage: {error}"),
            Self::Protocol(error) => write!(f, "FS index: {error}"),
            Self::HashMismatch => f.write_str("FS index whole-file hash mismatch"),
            Self::SourceChanged => f.write_str("FS index original source changed"),
            Self::NotIndexed => f.write_str("FS on-demand whole-file identity is not indexed"),
            Self::MalformedRecord => f.write_str(
                "FS on-demand record must contain file hash64 and network-order offset8",
            ),
            Self::BlockMismatch => f.write_str("FS on-demand ciphertext does not match its query"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Storage(error) => Some(error),
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}
impl From<backend::Error> for Error {
    fn from(error: backend::Error) -> Self {
        Self::Storage(error)
    }
}

/// Official FS_ONDEMAND value, independent of a datastore DataMessage header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnDemand {
    /// SHA-512 over the complete original plaintext file.
    pub file_id: [u8; 64],
    /// Original plaintext byte offset in network byte order on disk/the wire.
    pub offset: u64,
}
impl OnDemand {
    /// Exact public value length (`block_fs.h:OnDemandBlock`).
    pub const BYTES: usize = 72;
    /// Parse only an exact public value; trailing or truncated bytes are refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != Self::BYTES {
            return Err(Error::MalformedRecord);
        }
        let mut file_id = [0; 64];
        file_id.copy_from_slice(&bytes[..64]);
        let mut offset = [0; 8];
        offset.copy_from_slice(&bytes[64..]);
        Ok(Self {
            file_id,
            offset: u64::from_be_bytes(offset),
        })
    }
    /// Write exactly the public body; no Rust storage marker is added.
    #[must_use]
    pub fn encode(self) -> [u8; Self::BYTES] {
        let mut bytes = [0; Self::BYTES];
        bytes[..64].copy_from_slice(&self.file_id);
        bytes[64..].copy_from_slice(&self.offset.to_be_bytes());
        bytes
    }
}

/// Actual registration validation used for this source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verification {
    /// Matching original descriptor filesystem ID and inode, the official fast path.
    Identifiers,
    /// Complete streamed standard SHA-512 matched the requested whole-file ID.
    WholeFileHash,
}
/// A known complete registration result. Existing identity retains its first path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Registered {
    /// Whether a new identity was durably added rather than already registered.
    pub added: bool,
    /// Validation of the caller's actual requested file, including duplicates.
    pub verification: Verification,
    /// Actual stable source length validated by this operation.
    pub bytes: u64,
}
struct OwnedEntry {
    file_id: [u8; 64],
    filename: PathBuf,
}
/// One registration lent from the actual current private index.
#[derive(Clone, Copy, Debug)]
pub struct Entry<'a> {
    /// Whole-file plaintext identity for this bounded list entry.
    pub file_id: [u8; 64],
    /// Expanded original OS filename bytes, excluding a terminating NUL.
    pub filename: &'a [u8],
}
impl OwnedEntry {
    fn borrowed(&self) -> Entry<'_> {
        Entry {
            file_id: self.file_id,
            filename: self.filename.as_os_str().as_bytes(),
        }
    }
}
/// Borrowed sorted index iteration; no list snapshot or file payload is copied.
pub struct Entries<'a> {
    inner: slice::Iter<'a, OwnedEntry>,
}
impl<'a> Iterator for Entries<'a> {
    type Item = Entry<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(OwnedEntry::borrowed)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}
impl ExactSizeIterator for Entries<'_> {}
/// Actual checked DBLOCK bytes; constructors remain private to successful resolve.
#[derive(Debug)]
pub struct Resolved<'a> {
    bytes: &'a [u8],
    key: BlockKey,
    source: OnDemand,
}
impl Resolved<'_> {
    /// Exact raw official ciphertext plus its16-byte tag; no private prefix.
    #[must_use]
    pub const fn bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Actual plaintext/ciphertext hashes from this re-encoding.
    #[must_use]
    pub const fn key(&self) -> BlockKey {
        self.key
    }
    /// Original indexed identity and requested plaintext offset.
    #[must_use]
    pub const fn source(&self) -> OnDemand {
        self.source
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Stamp {
    device: u64,
    inode: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}
impl Stamp {
    fn new(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

/// Bounded registrations over one private, fenced, single-writer Rust WAL store.
/// No C INDEXDB file, service, plugin ABI or whole-file buffer is used.
pub struct Index {
    store: Store,
    entries: Vec<OwnedEntry>,
    path_bytes: usize,
    limits: Limits,
    quota: u64,
    scratch: Vec<u8>,
}
impl Index {
    /// Open/create the selected private metadata directory beneath an existing
    /// parent. Recovery/format/fence errors are preserved; source files are opened
    /// only for registration or a selected actual on-demand block.
    pub fn open(directory: impl AsRef<Path>, limits: Limits) -> Result<Self, Error> {
        if limits.max_entries == 0
            || limits.max_path_bytes == 0
            || limits.max_path_bytes > MAX_VALUE_BYTES - HEADER
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let quota = (limits.max_entries as u128)
            .checked_mul((HEADER as u64 + ENTRY_OVERHEAD).into())
            .and_then(|v| v.checked_add(limits.max_total_path_bytes as u128))
            .and_then(|v| u64::try_from(v).ok())
            .ok_or(ProtocolError::Overflow)?;
        let mut store = Store::open(
            directory,
            backend::Limits {
                max_records: limits.max_entries,
                ..backend::Limits::default()
            },
        )?;
        let mut entries: Vec<OwnedEntry> = Vec::new();
        let mut path_bytes = 0_usize;
        let mut next_uid = 0;
        while let Some(record) = store.select(
            Selection::Get {
                key: None,
                kind: 0,
                next_uid,
                random: false,
            },
            0,
        )? {
            if record.meta.kind != KIND
                || record.meta.anonymity != 0
                || record.meta.replication != 0
                || record.meta.priority != u32::MAX
                || record.meta.expiration != AbsoluteTime::NEVER
            {
                return Err(ProtocolError::Malformed.into());
            }
            let filename = decode(record.value, limits)?;
            path_bytes = path_bytes
                .checked_add(filename.as_os_str().as_bytes().len())
                .ok_or(ProtocolError::Overflow)?;
            if path_bytes > limits.max_total_path_bytes || entries.len() == limits.max_entries {
                return Err(ProtocolError::Capacity.into());
            }
            entries
                .try_reserve(1)
                .map_err(|_| ProtocolError::Capacity)?;
            entries.push(OwnedEntry {
                file_id: record.meta.key,
                filename,
            });
            let uid = record.meta.uid;
            if uid == u64::MAX {
                break;
            }
            next_uid = uid + 1;
        }
        entries.sort_unstable_by_key(|entry| entry.file_id);
        if entries
            .windows(2)
            .any(|pair| pair[0].file_id == pair[1].file_id)
        {
            return Err(ProtocolError::Malformed.into());
        }
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(BLOCK_BYTES)
            .map_err(|_| ProtocolError::Capacity)?;
        scratch.resize(BLOCK_BYTES, 0);
        Ok(Self {
            store,
            entries,
            path_bytes,
            limits,
            quota,
            scratch,
        })
    }
    fn ready(&mut self) -> Result<(), Error> {
        // A non-random read has no logical side effect and verifies the original
        // store's directory/WAL/writer authority even for a memory-only list.
        let _check = self.store.select(
            Selection::Get {
                key: None,
                kind: 0,
                next_uid: u64::MAX,
                random: false,
            },
            0,
        )?;
        Ok(())
    }
    /// Original active uncertain index mutation, if any. Reopen explicitly to
    /// settle it; the service must not send a false failed/empty response.
    #[must_use]
    pub fn failure(&self) -> Option<&backend::Error> {
        self.store.failure()
    }
    /// Separate physical cleanup trouble after a known successful logical commit.
    #[must_use]
    pub fn cleanup_failure(&self) -> Option<&backend::CleanupFailure> {
        self.store.cleanup_failure()
    }
    /// Streamed private metadata checkpoint, never an implicit Drop action.
    pub fn checkpoint(&mut self) -> Result<(), Error> {
        self.store.checkpoint().map_err(Into::into)
    }
    /// Bounded private orphan cleanup for the worker's explicit maintenance cadence.
    pub fn collect_garbage(&mut self) -> Result<(usize, bool), Error> {
        self.store.collect_garbage().map_err(Into::into)
    }
    /// Lend the complete sorted list after checking the actual store authority.
    pub fn entries(&mut self) -> Result<Entries<'_>, Error> {
        self.ready()?;
        Ok(Entries {
            inner: self.entries.iter(),
        })
    }
    /// First file identity greater than `after`, or the first when None. Uses
    /// binary partitioning; a native list owner can serialize mutations and emit
    /// one bounded frame without cloning the complete metadata list.
    pub fn entry_after(&mut self, after: Option<&[u8; 64]>) -> Result<Option<Entry<'_>>, Error> {
        self.ready()?;
        let position = after.map_or(0, |after| {
            self.entries
                .partition_point(|entry| entry.file_id <= *after)
        });
        Ok(self.entries.get(position).map(OwnedEntry::borrowed))
    }
    /// Validate and durably register the requested path. Relative paths are
    /// anchored to the current working directory; caller shell/config expansion
    /// is otherwise explicit. Symlinks follow normal official source semantics.
    pub fn register(
        &mut self,
        file_id: [u8; 64],
        filename: &Path,
        device: u64,
        inode: u64,
    ) -> Result<Registered, Error> {
        self.register_with(file_id, filename, device, inode, |_| true)
    }
    /// Same registration with an explicit between-chunk continuation decision.
    /// False preserves all index state and returns Cancelled, including after a
    /// source has validated but before any durable metadata publication.
    pub fn register_with(
        &mut self,
        file_id: [u8; 64],
        filename: &Path,
        device: u64,
        inode: u64,
        mut keep_going: impl FnMut(u64) -> bool,
    ) -> Result<Registered, Error> {
        self.ready()?;
        if filename.as_os_str().as_bytes().len() > self.limits.max_path_bytes {
            return Err(ProtocolError::TooLarge.into());
        }
        let filename = if filename.is_absolute() {
            copy_path(filename)?
        } else {
            std::env::current_dir()?.join(filename)
        };
        let raw = filename.as_os_str().as_bytes();
        if raw.len() > self.limits.max_path_bytes || raw.contains(&0) {
            return Err(ProtocolError::TooLarge.into());
        }
        let position = self
            .entries
            .binary_search_by_key(&file_id, |entry| entry.file_id);
        let path_bytes = if position.is_err() {
            self.path_bytes
                .checked_add(raw.len())
                .ok_or(ProtocolError::Overflow)?
        } else {
            self.path_bytes
        };
        if position.is_err()
            && (self.entries.len() == self.limits.max_entries
                || path_bytes > self.limits.max_total_path_bytes)
        {
            return Err(ProtocolError::Capacity.into());
        }
        let mut source = open_source(&filename)?;
        let before = Stamp::new(&source.metadata()?);
        if before.bytes > self.limits.max_file_bytes {
            return Err(ProtocolError::TooLarge.into());
        }
        if !keep_going(0) {
            return Err(ProtocolError::Cancelled.into());
        }
        let fast = (device != 0 || inode != 0)
            && inode == before.inode
            && nix::sys::statvfs::fstatvfs(&source)
                .is_ok_and(|v| u128::from(v.filesystem_id()) == u128::from(device));
        let verification = if fast {
            Verification::Identifiers
        } else {
            let mut hash = Hash512State::new();
            let mut read = 0_u64;
            while read < before.bytes {
                let amount = (before.bytes - read).min(self.scratch.len() as u64) as usize;
                source.read_exact(&mut self.scratch[..amount])?;
                hash.update(&self.scratch[..amount]);
                read += amount as u64;
                if !keep_going(read) {
                    return Err(ProtocolError::Cancelled.into());
                }
            }
            let mut extra = [0];
            loop {
                match source.read(&mut extra) {
                    Ok(0) => break,
                    Ok(_) => return Err(Error::SourceChanged),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if hash.finish() != file_id {
                return Err(Error::HashMismatch);
            }
            Verification::WholeFileHash
        };
        if Stamp::new(&source.metadata()?) != before
            || Stamp::new(&fs::metadata(&filename)?) != before
        {
            return Err(Error::SourceChanged);
        }
        if !keep_going(before.bytes) {
            return Err(ProtocolError::Cancelled.into());
        }
        if position.is_ok() {
            return Ok(Registered {
                added: false,
                verification,
                bytes: before.bytes,
            });
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| ProtocolError::Capacity)?;
        let value = encode(&filename)?;
        let _report = self.store.put(
            Put {
                key: &file_id,
                kind: KIND,
                priority: u32::MAX,
                anonymity: 0,
                replication: 0,
                expiration: AbsoluteTime::NEVER,
                value: &value,
            },
            PutPolicy {
                ceiling_bytes: self.quota,
                target_bytes: self.quota,
                now: AbsoluteTime::UNIX_EPOCH,
                max_evictions: 0,
                random: 0,
            },
        )?;
        let position = match position {
            Ok(position) | Err(position) => position,
        };
        self.entries
            .insert(position, OwnedEntry { file_id, filename });
        self.path_bytes = path_bytes;
        Ok(Registered {
            added: true,
            verification,
            bytes: before.bytes,
        })
    }
    /// Durably remove one registration; false is an already-absent identity,
    /// which still permits the official UNINDEX_OK. Public DATASTORE block
    /// removal is a separate operation and is not fabricated here.
    pub fn remove(&mut self, file_id: &[u8; 64]) -> Result<bool, Error> {
        self.ready()?;
        let Ok(position) = self
            .entries
            .binary_search_by_key(file_id, |entry| entry.file_id)
        else {
            return Ok(false);
        };
        let value = encode(&self.entries[position].filename)?;
        if !self.store.remove(file_id, &value)? {
            return Err(ProtocolError::Conflict.into());
        }
        let removed = self.entries.remove(position);
        self.path_bytes -= removed.filename.as_os_str().as_bytes().len();
        Ok(true)
    }
    /// Resolve one actual FS_ONDEMAND value into the official DBLOCK. The file
    /// is read through its original regular descriptor at the requested offset;
    /// original metadata stability and the ciphertext query must both match.
    /// Complete source payloads and unrelated tree nodes are never buffered.
    pub fn resolve<'a>(
        &mut self,
        query: &[u8; 64],
        record: &[u8],
        output: &'a mut [u8],
    ) -> Result<Resolved<'a>, Error> {
        let record = OnDemand::decode(record)?;
        self.ready()?;
        let position = self
            .entries
            .binary_search_by_key(&record.file_id, |entry| entry.file_id)
            .map_err(|_| Error::NotIndexed)?;
        let mut source = open_source(&self.entries[position].filename)?;
        let before = Stamp::new(&source.metadata()?);
        if before.bytes > self.limits.max_file_bytes {
            return Err(ProtocolError::TooLarge.into());
        }
        source.seek(SeekFrom::Start(record.offset))?;
        let mut bytes = 0;
        while bytes < self.scratch.len() {
            match source.read(&mut self.scratch[bytes..]) {
                Ok(0) => break,
                Ok(read) => bytes += read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        if Stamp::new(&source.metadata()?) != before {
            return Err(Error::SourceChanged);
        }
        let (key, length) = {
            let encoded = content::encode_data(&self.scratch[..bytes], output)?;
            (encoded.key(), encoded.bytes().len())
        };
        if key.query != *query {
            output[..length].fill(0);
            return Err(Error::BlockMismatch);
        }
        Ok(Resolved {
            bytes: &output[..length],
            key,
            source: record,
        })
    }
}
fn copy_path(path: &Path) -> Result<PathBuf, Error> {
    let raw = path.as_os_str().as_bytes();
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(raw.len())
        .map_err(|_| ProtocolError::Capacity)?;
    bytes.extend_from_slice(raw);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}
fn open_source(path: &Path) -> io::Result<File> {
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits() | nix::fcntl::OFlag::O_CLOEXEC.bits())
        .open(path)?;
    if !source.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FS indexed source must be a regular file",
        ));
    }
    Ok(source)
}
fn encode(path: &Path) -> Result<Vec<u8>, Error> {
    let raw = path.as_os_str().as_bytes();
    let length = HEADER
        .checked_add(raw.len())
        .ok_or(ProtocolError::Overflow)?;
    let mut value = Vec::new();
    value
        .try_reserve_exact(length)
        .map_err(|_| ProtocolError::Capacity)?;
    value.extend_from_slice(MAGIC);
    value.extend_from_slice(
        &u32::try_from(raw.len())
            .map_err(|_| ProtocolError::TooLarge)?
            .to_be_bytes(),
    );
    value.extend_from_slice(raw);
    Ok(value)
}
fn decode(value: &[u8], limits: Limits) -> Result<PathBuf, Error> {
    if value.len() < HEADER || &value[..8] != MAGIC {
        return Err(ProtocolError::Malformed.into());
    }
    let mut length = [0; 4];
    length.copy_from_slice(&value[8..HEADER]);
    let length = u32::from_be_bytes(length) as usize;
    let raw = &value[HEADER..];
    if raw.len() != length || raw.len() > limits.max_path_bytes || raw.contains(&0) {
        return Err(ProtocolError::Malformed.into());
    }
    let path = Path::new(std::ffi::OsStr::from_bytes(raw));
    if !path.is_absolute() {
        return Err(ProtocolError::Malformed.into());
    }
    copy_path(path)
}

#[cfg(test)]
#[path = "index/tests.rs"]
mod tests;
