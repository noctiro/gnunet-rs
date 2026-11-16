//! UDP-only local-identity/remote-peer monotime journal, with a real OS writer fence.
//! An unknown original replacement remains quiescent until exact original-file readback.
use gnunet_types::Error;
use gnunet_udp_communicator_core::{PeerId, receive::ReplayStore};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
};
mod fence;
mod format;
use format::{Record, Snapshot};
mod staging;
use gnunet_native::{
    DirectorySync,
    filesystem::{EntryInfo, file_info, private_single_file_identity},
};
use staging::Staging;
use std::ffi::OsStr;
mod namespace;
use fence::Fence;
pub use namespace::Namespace;
const LOCK: &str = ".gnunet-udp-replay-owner.lock";
const DATA: &str = ".gnunet-udp-replay-v1";
const TEMP: &str = ".gnunet-udp-replay-new-";
const MAX_PEERS: usize = 4096;
const HEADER: usize = 48;
const CHECKSUM: usize = 32;
/// Exact native persistence boundary of the original failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Acquire or validate the original exclusive OS writer fence.
    Fence,
    /// Read and validate the bounded identity-bound snapshot.
    Read,
    /// Create a fresh caller-owned temporary snapshot.
    Create,
    /// Write the complete snapshot.
    Write,
    /// Synchronize the complete original temporary file.
    FileSync,
    /// Atomically replace the original database path.
    Rename,
    /// Synchronize the original parent directory.
    DirectorySync,
    /// Settle the same uncertain replacement by exact readback.
    Recovery,
}
/// Whether this operation could have replaced the canonical snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// No replacement was observed; no pending state can authorize admission.
    NotCommitted,
    /// The original replacement or writer authority must be resolved first.
    Unknown,
}
/// Original native error, retained separately from the pure-core error category.
#[derive(Debug)]
pub struct Failure {
    /// Original failing operation.
    pub stage: Stage,
    /// Actual replacement certainty.
    pub outcome: Outcome,
    /// Original OS cause; never replaced with a successful token.
    pub cause: io::Error,
    /// Independent original-stage cleanup failure.
    pub cleanup: Option<io::Error>,
}
/// Semantic refusal or the original native persistence failure.
#[derive(Debug)]
pub enum JournalError {
    /// Identity, strictly-newer replay, capacity or checked-size refusal.
    Core(Error),
    /// Actual original file/fence failure.
    Native(Failure),
}
impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(error) => write!(f, "UDP replay: {error}"),
            Self::Native(error) => {
                write!(
                    f,
                    "UDP replay {:?}/{:?}: {}",
                    error.stage, error.outcome, error.cause
                )?;
                if let Some(cleanup) = &error.cleanup {
                    write!(f, "; cleanup: {cleanup}")?;
                }
                Ok(())
            }
        }
    }
}
impl std::error::Error for JournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Native(failure) => Some(&failure.cause),
            Self::Core(_) => None,
        }
    }
}
impl From<Error> for JournalError {
    fn from(error: Error) -> Self {
        Self::Core(error)
    }
}
fn native(stage: Stage, outcome: Outcome, cause: io::Error) -> JournalError {
    JournalError::Native(Failure {
        stage,
        outcome,
        cause,
        cleanup: None,
    })
}
fn invalid(stage: Stage, outcome: Outcome, why: &'static str) -> JournalError {
    native(stage, outcome, io::Error::other(why))
}
struct Pending {
    snapshot: Snapshot,
    bytes_hash: [u8; 32],
    file: File,
}
/// Single synchronous native journal owner. The stable fence inode is never
/// unlinked or replaced. No detached worker can complete after this owner drops.
/// A directory contains one local identity namespace; another local identity
/// requires another state directory and cannot adopt this file as empty state.
pub struct Journal {
    owner: Arc<Fence>,
    namespace: Option<Arc<Fence>>,
    local: PeerId,
    maximum: usize,
    snapshot: Snapshot,
    pending: Option<Pending>,
    current: Option<File>,
    commits: u64,
    last_failure: Option<Failure>,
}
impl Journal {
    /// Open one existing private directory, retain its real cross-process writer
    /// lock, then synchronize and validate any prior complete snapshot.
    pub fn open(
        directory: impl AsRef<Path>,
        local: PeerId,
        maximum_peers: usize,
    ) -> Result<Self, JournalError> {
        if maximum_peers == 0 || maximum_peers > MAX_PEERS {
            return Err(Error::InvalidInput.into());
        }
        Self::from_fence(Fence::open(directory.as_ref())?, local, maximum_peers)
    }
    fn from_fence(owner: Fence, local: PeerId, maximum: usize) -> Result<Self, JournalError> {
        let fresh = owner.fresh;
        let mut journal = Self {
            owner: Arc::new(owner),
            namespace: None,
            local,
            maximum,
            snapshot: Snapshot {
                highwater: 0,
                records: Vec::new(),
            },
            pending: None,
            current: None,
            commits: 0,
            last_failure: None,
        };
        journal.fence()?;
        let loaded = journal.read()?;
        match loaded {
            Some(mut original) => {
                original
                    .file
                    .sync_all()
                    .map_err(|cause| native(Stage::FileSync, Outcome::Unknown, cause))?;
                journal
                    .sync_directory()
                    .map_err(|cause| native(Stage::DirectorySync, Outcome::Unknown, cause))?;
                let verified = journal.read_original(&mut original.file)?;
                if original.snapshot != verified.0 || original.bytes_hash != verified.1 {
                    return Err(invalid(
                        Stage::Read,
                        Outcome::Unknown,
                        "UDP synchronized original snapshot changed",
                    ));
                }
                journal.snapshot = original.snapshot;
                journal.current = Some(original.file);
            }
            None if fresh => {
                // Establish canonical state before any packet or stamp can use
                // this namespace. An old fence without it is never an empty DB.
                journal.persist(
                    Snapshot {
                        highwater: 0,
                        records: Vec::new(),
                    },
                    || {},
                )?;
                journal.commits = 0;
            }
            None => {
                return Err(invalid(
                    Stage::Read,
                    Outcome::Unknown,
                    "UDP canonical state missing behind an existing writer fence",
                ));
            }
        }
        Ok(journal)
    }
    fn fence(&self) -> Result<(), JournalError> {
        if let Some(root) = &self.namespace {
            namespace::Namespace::check_root(root)?;
        }
        self.owner.check()
    }
    fn sync_directory(&self) -> io::Result<DirectorySync> {
        self.owner.sync()
    }
    /// Naming-barrier capability independently of successful file synchronization.
    /// Windows reports Unavailable; that is not a directory durability receipt.
    pub fn directory_sync(&self) -> DirectorySync {
        self.owner.barrier
    }
    fn read(&self) -> Result<Option<Pending>, JournalError> {
        self.fence()?;
        let mut file = match self.owner.parent.open_file_for_sync(OsStr::new(DATA)) {
            Ok(file) => file,
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(cause) => return Err(native(Stage::Read, Outcome::NotCommitted, cause)),
        };
        let (snapshot, bytes_hash) = self.read_original(&mut file)?;
        Ok(Some(Pending {
            snapshot,
            bytes_hash,
            file,
        }))
    }
    fn read_original(&self, file: &mut File) -> Result<(Snapshot, [u8; 32]), JournalError> {
        self.fence()?;
        let identity = private_single_file_identity(file)
            .map_err(|cause| native(Stage::Read, Outcome::Unknown, cause))?;
        let before =
            match file_info(file).map_err(|cause| native(Stage::Read, Outcome::Unknown, cause))? {
                EntryInfo::File(info)
                    if info.identity == identity && identity != self.owner.identity =>
                {
                    info
                }
                _ => {
                    return Err(invalid(
                        Stage::Read,
                        Outcome::Unknown,
                        "UDP replay object is not an independent private file",
                    ));
                }
            };
        let bound = HEADER + CHECKSUM + self.maximum * 40;
        if before.bytes > bound as u64
            || !self
                .owner
                .parent
                .same_file(OsStr::new(DATA), file)
                .map_err(|cause| native(Stage::Read, Outcome::Unknown, cause))?
        {
            return Err(invalid(
                Stage::Read,
                Outcome::Unknown,
                "UDP bounded original snapshot name changed",
            ));
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|cause| native(Stage::Read, Outcome::Unknown, cause))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(before.bytes as usize)
            .map_err(|_| Error::Capacity)?;
        bytes.resize(before.bytes as usize, 0);
        file.read_exact(&mut bytes)
            .map_err(|cause| native(Stage::Read, Outcome::Unknown, cause))?;
        let mut trailing = [0];
        if file
            .read(&mut trailing)
            .map_err(|cause| native(Stage::Read, Outcome::Unknown, cause))?
            != 0
            || file_info(file).map_err(|cause| native(Stage::Read, Outcome::Unknown, cause))?
                != EntryInfo::File(before)
            || !self
                .owner
                .parent
                .same_file(OsStr::new(DATA), file)
                .map_err(|cause| native(Stage::Read, Outcome::Unknown, cause))?
        {
            return Err(invalid(
                Stage::Read,
                Outcome::Unknown,
                "UDP original snapshot changed during read",
            ));
        }
        Ok((
            Snapshot::decode(&bytes, self.local, self.maximum)?,
            gnunet_crypto::hash256(&bytes),
        ))
    }
    fn ready(&self) -> Result<(), JournalError> {
        if self.pending.is_some() {
            return Err(invalid(
                Stage::Recovery,
                Outcome::Unknown,
                "original UDP replacement is unresolved",
            ));
        }
        self.fence()?;
        if let Some(file) = &self.current {
            private_single_file_identity(file)
                .map_err(|cause| native(Stage::Read, Outcome::Unknown, cause))?;
            if !self
                .owner
                .parent
                .same_file(OsStr::new(DATA), file)
                .map_err(|cause| native(Stage::Read, Outcome::Unknown, cause))?
            {
                return Err(invalid(
                    Stage::Read,
                    Outcome::Unknown,
                    "UDP committed snapshot identity changed",
                ));
            }
        }
        Ok(())
    }
    /// Read the committed strictly-newer remote-peer bound under the original
    /// active namespace/fence. Unknown outcomes expose no ready admission state.
    pub fn latest(&self, peer: PeerId) -> Result<Option<u64>, JournalError> {
        self.ready()?;
        Ok(self
            .snapshot
            .records
            .binary_search_by_key(&peer, |r| r.peer)
            .ok()
            .map(|at| self.snapshot.records[at].monotonic))
    }
    /// Check actual writer authority and the original pending replacement.
    pub fn quiescent(&self) -> Result<bool, JournalError> {
        self.fence()?;
        Ok(self.pending.is_none())
    }
    /// Durably commit a strictly greater authenticated timestamp for this exact
    /// local identity and remote peer. Equality is a replay, including after restart.
    pub fn commit_time(
        &mut self,
        local: PeerId,
        peer: PeerId,
        monotonic: u64,
    ) -> Result<(), JournalError> {
        self.commit_time_observed(local, peer, monotonic, || {})
    }
    fn commit_time_observed(
        &mut self,
        local: PeerId,
        peer: PeerId,
        monotonic: u64,
        after_rename: impl FnOnce(),
    ) -> Result<(), JournalError> {
        self.ready()?;
        if local != self.local {
            return Err(Error::Authentication.into());
        }
        let mut next = self.snapshot.duplicate(self.maximum)?;
        match next.records.binary_search_by_key(&peer, |r| r.peer) {
            Ok(at) => {
                if monotonic <= next.records[at].monotonic {
                    return Err(Error::Replay.into());
                }
                next.records[at].monotonic = monotonic;
            }
            Err(at) => {
                if next.records.len() == self.maximum {
                    return Err(Error::Capacity.into());
                }
                next.records.insert(at, Record { peer, monotonic });
            }
        }
        self.persist(next, after_rename)
    }
    /// Reserve a never-reused local outgoing monotime interval under this same
    /// writer fence. Values unused before process exit remain permanently skipped.
    pub fn reserve_monotime(
        &mut self,
        minimum: u64,
        span: u64,
    ) -> Result<(u64, u64), JournalError> {
        self.ready()?;
        if span == 0 {
            return Err(Error::InvalidInput.into());
        }
        let first = minimum.max(
            self.snapshot
                .highwater
                .checked_add(1)
                .ok_or(Error::Overflow)?,
        );
        let end = first.checked_add(span - 1).ok_or(Error::Overflow)?;
        let mut next = self.snapshot.duplicate(self.maximum)?;
        next.highwater = end;
        self.persist(next, || {})?;
        Ok((first, end))
    }
    fn persist(&mut self, next: Snapshot, after_rename: impl FnOnce()) -> Result<(), JournalError> {
        self.ready()?;
        let commits = self.commits.checked_add(1).ok_or(Error::Overflow)?;
        let bytes = next.encode(self.local)?;
        let bytes_hash = gnunet_crypto::hash256(&bytes);
        let mut stage = Staging::new(self.owner.clone())?;
        let prepared = (|| {
            let file = stage.file.as_mut().ok_or(Error::Stale)?;
            let mut offset = 0;
            while offset < bytes.len() {
                let count = file
                    .write(&bytes[offset..])
                    .map_err(|cause| native(Stage::Write, Outcome::NotCommitted, cause))?;
                if count == 0 {
                    return Err(native(
                        Stage::Write,
                        Outcome::NotCommitted,
                        io::ErrorKind::WriteZero.into(),
                    ));
                }
                offset += count;
            }
            file.sync_all()
                .map_err(|cause| native(Stage::FileSync, Outcome::NotCommitted, cause))?;
            self.fence()
        })();
        if let Err(mut failure) = prepared {
            if let JournalError::Native(original) = &mut failure {
                original.cleanup = stage.discard().err();
            }
            return Err(failure);
        }
        let publication = stage.publish(OsStr::new(DATA));
        let file = stage.into_file()?;
        self.pending = Some(Pending {
            snapshot: next,
            bytes_hash,
            file,
        });
        publication.map_err(|cause| native(Stage::Rename, Outcome::Unknown, cause))?;
        after_rename();
        self.sync_directory()
            .map_err(|e| native(Stage::DirectorySync, Outcome::Unknown, e))?;
        self.settle()?;
        self.commits = commits;
        Ok(())
    }
    fn settle(&mut self) -> Result<(), JournalError> {
        self.fence()?;
        if self.pending.is_none() {
            return Ok(());
        }
        // Temporarily move the original pending file out only for the read;
        // every error restores that exact owner before returning.
        let mut pending = self.pending.take().ok_or(Error::Stale)?;
        let observed = self.read_original(&mut pending.file);
        let valid = match observed {
            Ok((actual, hash)) if actual == pending.snapshot && hash == pending.bytes_hash => {
                Ok(())
            }
            Ok(_) => Err(invalid(
                Stage::Recovery,
                Outcome::Unknown,
                "UDP original replacement differs from expected snapshot",
            )),
            Err(JournalError::Native(mut failure)) => {
                failure.outcome = Outcome::Unknown;
                Err(JournalError::Native(failure))
            }
            Err(JournalError::Core(_)) => Err(invalid(
                Stage::Recovery,
                Outcome::Unknown,
                "UDP unresolved original snapshot is malformed",
            )),
        };
        self.pending = Some(pending);
        valid?;
        let original = self.pending.take().ok_or(Error::Stale)?;
        self.snapshot = original.snapshot;
        self.current = Some(original.file);
        Ok(())
    }
    /// Settle exactly the original unknown replacement through directory sync and
    /// exact full snapshot/hash readback. It never creates or substitutes a write.
    pub fn recover(&mut self) -> Result<bool, JournalError> {
        self.fence()?;
        if self.pending.is_none() {
            return Ok(false);
        }
        let commits = self.commits.checked_add(1).ok_or(Error::Overflow)?;
        self.sync_directory()
            .map_err(|e| native(Stage::Recovery, Outcome::Unknown, e))?;
        self.settle()?;
        self.commits = commits;
        Ok(true)
    }
    /// Public local identity namespace of this exact journal owner. Reading this
    /// diagnostic does not settle a pending replacement or prove writer authority.
    #[must_use]
    pub const fn local_peer(&self) -> PeerId {
        self.local
    }
    /// Settled business commits in this owner lifetime; initial canonical state
    /// installation is excluded. Observe directory-sync capability separately.
    #[must_use]
    pub fn commits(&self) -> u64 {
        self.commits
    }
    /// Original native cause retained when the pure replay trait had to return
    /// its portable Storage/OutcomeUnknown category. Taking it does not recover.
    pub fn take_failure(&mut self) -> Option<Failure> {
        self.last_failure.take()
    }
}
impl ReplayStore for Journal {
    fn commit(&mut self, local: PeerId, peer: PeerId, monotonic: u64) -> Result<(), Error> {
        match self.commit_time(local, peer, monotonic) {
            Ok(()) => Ok(()),
            Err(JournalError::Core(error)) => Err(error),
            Err(JournalError::Native(failure)) => {
                let category = match failure.outcome {
                    Outcome::NotCommitted => Error::Storage,
                    Outcome::Unknown => Error::OutcomeUnknown,
                };
                self.last_failure = Some(failure);
                Err(category)
            }
        }
    }
}
#[cfg(test)]
mod tests;
