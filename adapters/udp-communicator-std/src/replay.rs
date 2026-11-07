//! UDP-only local-identity/remote-peer monotime journal, with a real OS writer fence.
//! An unknown original replacement remains quiescent until exact durable readback.
use gnunet_types::Error;
use gnunet_udp_communicator_core::{PeerId, receive::ReplayStore};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
mod fence;
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
/// Whether this operation could have replaced the durable snapshot.
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
            Self::Native(error) => write!(
                f,
                "UDP replay {:?}/{:?}: {}",
                error.stage, error.outcome, error.cause
            ),
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
    })
}
fn invalid(stage: Stage, outcome: Outcome, why: &'static str) -> JournalError {
    native(stage, outcome, io::Error::other(why))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Record {
    peer: PeerId,
    monotonic: u64,
}
#[derive(Debug, Eq, PartialEq)]
struct Snapshot {
    highwater: u64,
    records: Vec<Record>,
}
impl Snapshot {
    fn duplicate(&self, maximum: usize) -> Result<Self, JournalError> {
        let mut records = Vec::new();
        records
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        records.extend_from_slice(&self.records);
        Ok(Self {
            highwater: self.highwater,
            records,
        })
    }
    fn encode(&self, local: PeerId) -> Result<Vec<u8>, JournalError> {
        let size = HEADER
            .checked_add(self.records.len().checked_mul(40).ok_or(Error::Overflow)?)
            .and_then(|n| n.checked_add(CHECKSUM))
            .ok_or(Error::Overflow)?;
        let mut out = Vec::new();
        out.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
        out.extend_from_slice(b"GUR1");
        out.extend_from_slice(&local);
        out.extend_from_slice(&self.highwater.to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(self.records.len())
                .map_err(|_| Error::TooLarge)?
                .to_be_bytes(),
        );
        for record in &self.records {
            out.extend_from_slice(&record.peer);
            out.extend_from_slice(&record.monotonic.to_be_bytes());
        }
        let checksum = gnunet_crypto::hash256(&out);
        out.extend_from_slice(&checksum);
        Ok(out)
    }
    fn decode(input: &[u8], local: PeerId, maximum: usize) -> Result<Self, JournalError> {
        if input.len() < HEADER + CHECKSUM || input.get(..4) != Some(b"GUR1") {
            return Err(Error::Storage.into());
        }
        if input.get(4..36) != Some(local.as_slice()) {
            return Err(Error::Authentication.into());
        }
        let count =
            u32::from_be_bytes(input[44..48].try_into().map_err(|_| Error::Truncated)?) as usize;
        let length = HEADER
            .checked_add(count.checked_mul(40).ok_or(Error::Overflow)?)
            .and_then(|n| n.checked_add(CHECKSUM))
            .ok_or(Error::Overflow)?;
        if count > maximum || input.len() != length {
            return Err(Error::Storage.into());
        }
        if input[length - CHECKSUM..] != gnunet_crypto::hash256(&input[..length - CHECKSUM]) {
            return Err(Error::Storage.into());
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        for raw in input[HEADER..length - CHECKSUM].as_chunks::<40>().0 {
            let peer = raw[..32].try_into().map_err(|_| Error::Truncated)?;
            if records
                .last()
                .is_some_and(|previous: &Record| previous.peer >= peer)
            {
                return Err(Error::Storage.into());
            }
            records.push(Record {
                peer,
                monotonic: u64::from_be_bytes(raw[32..].try_into().map_err(|_| Error::Truncated)?),
            });
        }
        Ok(Self {
            highwater: u64::from_be_bytes(input[36..44].try_into().map_err(|_| Error::Truncated)?),
            records,
        })
    }
}
struct Pending {
    snapshot: Snapshot,
    bytes_hash: [u8; 32],
}
/// Single synchronous native journal owner. The stable fence inode is never
/// unlinked or replaced. No detached worker can complete after this owner drops.
/// A directory contains one local identity namespace; another local identity
/// requires another state directory and cannot adopt this file as empty state.
pub struct Journal {
    owner: Fence,
    namespace: Option<Arc<Fence>>,
    local: PeerId,
    maximum: usize,
    snapshot: Snapshot,
    pending: Option<Pending>,
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
        let owner = Fence::open(directory.as_ref())?;
        let mut journal = Self {
            owner,
            namespace: None,
            local,
            maximum: maximum_peers,
            snapshot: Snapshot {
                highwater: 0,
                records: Vec::new(),
            },
            pending: None,
            commits: 0,
            last_failure: None,
        };
        journal.fence()?;
        let loaded = journal.read()?;
        // Settle the visible snapshot after any previous process died without a
        // reply. No packet from this owner is admitted until these syncs succeed.
        if loaded.is_some() {
            File::open(journal.owner.directory.join(DATA))
                .and_then(|file| file.sync_all())
                .map_err(|e| native(Stage::FileSync, Outcome::Unknown, e))?;
        }
        journal
            .directory_sync()
            .map_err(|e| native(Stage::DirectorySync, Outcome::Unknown, e))?;
        if let Some((snapshot, bytes_hash)) = loaded {
            let Some((verified, verified_hash)) = journal.read()? else {
                return Err(invalid(
                    Stage::Read,
                    Outcome::Unknown,
                    "snapshot vanished during recovery",
                ));
            };
            if snapshot != verified || bytes_hash != verified_hash {
                return Err(invalid(
                    Stage::Read,
                    Outcome::Unknown,
                    "snapshot changed during recovery",
                ));
            }
            journal.snapshot = snapshot;
        }
        Ok(journal)
    }
    fn fence(&self) -> Result<(), JournalError> {
        if let Some(root) = &self.namespace {
            namespace::Namespace::check_root(root)?;
        }
        self.owner.check()
    }
    fn directory_sync(&self) -> io::Result<()> {
        self.owner.sync()
    }
    fn read(&self) -> Result<Option<(Snapshot, [u8; 32])>, JournalError> {
        self.fence()?;
        let path = self.owner.directory.join(DATA);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(native(Stage::Read, Outcome::NotCommitted, e)),
        };
        let bound = HEADER + CHECKSUM + self.maximum * 40;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.len() > bound as u64
            || (metadata.dev(), metadata.ino()) == self.owner.identity
        {
            return Err(invalid(
                Stage::Read,
                Outcome::NotCommitted,
                "UDP snapshot is not a bounded independent regular file",
            ));
        }
        let mut file =
            File::open(&path).map_err(|e| native(Stage::Read, Outcome::NotCommitted, e))?;
        let opened = file
            .metadata()
            .map_err(|e| native(Stage::Read, Outcome::NotCommitted, e))?;
        if (opened.dev(), opened.ino(), opened.len())
            != (metadata.dev(), metadata.ino(), metadata.len())
        {
            return Err(invalid(
                Stage::Read,
                Outcome::Unknown,
                "UDP snapshot changed during open",
            ));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(bound)
            .map_err(|_| Error::Capacity)?;
        // Bounded even if an external actor extends the opened regular file.
        (&mut file)
            .take((bound + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| native(Stage::Read, Outcome::NotCommitted, e))?;
        if bytes.len() != metadata.len() as usize {
            return Err(invalid(
                Stage::Read,
                Outcome::Unknown,
                "UDP snapshot changed during read",
            ));
        }
        let snapshot = Snapshot::decode(&bytes, self.local, self.maximum)?;
        Ok(Some((snapshot, gnunet_crypto::hash256(&bytes))))
    }
    fn ready(&self) -> Result<(), JournalError> {
        if self.pending.is_some() {
            return Err(invalid(
                Stage::Recovery,
                Outcome::Unknown,
                "original UDP replacement is unresolved",
            ));
        }
        self.fence()
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
        let (mut file, mut temporary) = temporary(&self.owner.directory)?;
        file.write_all(&bytes)
            .map_err(|e| native(Stage::Write, Outcome::NotCommitted, e))?;
        file.sync_all()
            .map_err(|e| native(Stage::FileSync, Outcome::NotCommitted, e))?;
        self.fence()?;
        fs::rename(&temporary.path, self.owner.directory.join(DATA))
            .map_err(|e| native(Stage::Rename, Outcome::NotCommitted, e))?;
        temporary.renamed = true;
        self.pending = Some(Pending {
            snapshot: next,
            bytes_hash,
        });
        after_rename();
        self.directory_sync()
            .map_err(|e| native(Stage::DirectorySync, Outcome::Unknown, e))?;
        self.settle()?;
        self.commits = commits;
        Ok(())
    }
    fn settle(&mut self) -> Result<(), JournalError> {
        self.fence()?;
        let Some(pending) = self.pending.as_ref() else {
            return Ok(());
        };
        let Some((actual, hash)) = self.read().map_err(|error| match error {
            JournalError::Native(mut failure) => {
                failure.outcome = Outcome::Unknown;
                JournalError::Native(failure)
            }
            JournalError::Core(_) => invalid(
                Stage::Recovery,
                Outcome::Unknown,
                "unresolved UDP snapshot is malformed",
            ),
        })?
        else {
            return Err(invalid(
                Stage::Recovery,
                Outcome::Unknown,
                "unresolved UDP snapshot is missing",
            ));
        };
        if actual != pending.snapshot || hash != pending.bytes_hash {
            return Err(invalid(
                Stage::Recovery,
                Outcome::Unknown,
                "unresolved UDP snapshot differs from original replacement",
            ));
        }
        let original = self.pending.take().ok_or(Error::Stale)?;
        self.snapshot = original.snapshot;
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
        self.directory_sync()
            .map_err(|e| native(Stage::Recovery, Outcome::Unknown, e))?;
        self.settle()?;
        self.commits = commits;
        Ok(true)
    }
    /// Public local identity namespace of this exact durable owner. Reading this
    /// diagnostic does not settle a pending replacement or prove writer authority.
    #[must_use]
    pub const fn local_peer(&self) -> PeerId {
        self.local
    }
    /// Number of fully settled durable commits in this owner lifetime.
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
struct Temporary {
    path: PathBuf,
    identity: (u64, u64),
    renamed: bool,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.renamed
            && let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.is_file()
            && (metadata.dev(), metadata.ino()) == self.identity
        {
            let _removed = fs::remove_file(&self.path);
        }
    }
}
fn temporary(directory: &Path) -> Result<(File, Temporary), JournalError> {
    for _ in 0..16 {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce)
            .map_err(|e| native(Stage::Create, Outcome::NotCommitted, io::Error::other(e)))?;
        let path = directory.join(format!("{TEMP}{:032x}", u128::from_be_bytes(nonce)));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => {
                let metadata = file
                    .metadata()
                    .map_err(|e| native(Stage::Create, Outcome::NotCommitted, e))?;
                return Ok((
                    file,
                    Temporary {
                        path,
                        identity: (metadata.dev(), metadata.ino()),
                        renamed: false,
                    },
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(native(Stage::Create, Outcome::NotCommitted, e)),
        }
    }
    Err(Error::Capacity.into())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Finite filesystem/receiver witnesses assert actual durable state and original IO boundaries."
    )]
    use super::*;
    use gnunet_crypto::Entropy;
    use gnunet_udp_communicator_core::{
        Identity,
        receive::{Policy as RxPolicy, Receiver},
        send::{Policy as TxPolicy, Sender},
    };
    use std::{
        io::{BufRead, BufReader},
        process::{Command, Stdio},
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    type Test = Result<(), Box<dyn std::error::Error>>;
    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> io::Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "udp-replay-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }
    struct Random;
    impl Entropy for Random {
        fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
            getrandom::fill(output).map_err(|_| Error::Entropy)
        }
    }
    fn message(n: u32) -> [u8; 8] {
        let mut m = [0; 8];
        m[..2].copy_from_slice(&8u16.to_be_bytes());
        m[4..].copy_from_slice(&n.to_be_bytes());
        m
    }
    #[test]
    fn durable_receiver_restart_rejects_captured_kx_and_binds_both_identities() -> Test {
        let scratch = Scratch::new()?;
        let a = Identity::from_seed([3; 32]);
        let b = Identity::from_seed([5; 32]);
        let mut sender = Sender::new(
            a.peer(),
            b.peer(),
            TxPolicy {
                datagram_bytes: 192,
                secrets: 4,
                ..TxPolicy::default()
            },
            100,
        )?;
        let first = sender.initial(&a, &message(1), 7, 100, &mut Random)?;
        let next = sender.initial(&a, &message(2), 8, 101, &mut Random)?;
        let mut journal = Journal::open(&scratch.0, b.peer(), 2)?;
        let mut receiver = Receiver::new(b.peer(), a.peer(), RxPolicy::default())?;
        let mut plain = [0xa5; 160];
        let accepted = receiver.initial(&b, first.bytes(), &mut plain, &mut journal)?;
        assert_eq!(accepted.message(), Some(message(1).as_slice()));
        assert_eq!(receiver.available(), 128);
        assert_eq!(journal.latest(a.peer())?, Some(7));
        let written = fs::read(scratch.0.join(DATA))?;
        assert_eq!(written.len(), 120);
        assert_eq!(journal.commits(), 1);
        assert!(matches!(
            journal.commit_time(b.peer(), a.peer(), 7),
            Err(JournalError::Core(Error::Replay))
        ));
        assert!(matches!(
            journal.commit_time(a.peer(), a.peer(), 9),
            Err(JournalError::Core(Error::Authentication))
        ));
        drop(journal);
        drop(receiver);
        assert!(matches!(
            Journal::open(&scratch.0, a.peer(), 2),
            Err(JournalError::Core(Error::Authentication))
        ));
        let mut journal = Journal::open(&scratch.0, b.peer(), 2)?;
        let mut receiver = Receiver::new(b.peer(), a.peer(), RxPolicy::default())?;
        assert!(matches!(
            receiver.initial(&b, first.bytes(), &mut plain, &mut journal),
            Err(Error::Replay)
        ));
        assert_eq!(receiver.available(), 0);
        assert_eq!(receiver.secrets(), 0);
        assert_eq!(fs::read(scratch.0.join(DATA))?, written);
        let accepted = receiver.initial(&b, next.bytes(), &mut plain, &mut journal)?;
        assert_eq!(accepted.message(), Some(message(2).as_slice()));
        assert_eq!(journal.latest(a.peer())?, Some(8));
        assert!(journal.quiescent()?);
        Ok(())
    }
    #[test]
    fn bounded_peer_namespace_and_monotime_reservations_survive_restart() -> Test {
        let scratch = Scratch::new()?;
        let local = [2; 32];
        let mut journal = Journal::open(&scratch.0, local, 1)?;
        journal.commit_time(local, [1; 32], 0)?;
        assert!(matches!(
            journal.commit_time(local, [1; 32], 0),
            Err(JournalError::Core(Error::Replay))
        ));
        assert!(matches!(
            journal.commit_time(local, [3; 32], 1),
            Err(JournalError::Core(Error::Capacity))
        ));
        assert_eq!(journal.reserve_monotime(10, 64)?, (10, 73));
        let state = fs::read(scratch.0.join(DATA))?;
        assert!(matches!(
            journal.reserve_monotime(u64::MAX, 2),
            Err(JournalError::Core(Error::Overflow))
        ));
        assert_eq!(fs::read(scratch.0.join(DATA))?, state);
        drop(journal);
        let mut journal = Journal::open(&scratch.0, local, 1)?;
        assert_eq!(journal.latest([1; 32])?, Some(0));
        assert_eq!(journal.reserve_monotime(1, 2)?, (74, 75));
        Ok(())
    }
    #[test]
    fn real_postrename_parent_loss_blocks_all_admission_until_original_recovered() -> Test {
        let scratch = Scratch::new()?;
        let live = scratch.0.join("live");
        let moved = scratch.0.join("moved");
        fs::create_dir(&live)?;
        let local = [2; 32];
        let peer = [3; 32];
        let mut journal = Journal::open(&live, local, 2)?;
        journal.commit_time(local, peer, 10)?;
        let result = journal.commit_time_observed(local, peer, 11, || {
            assert!(fs::rename(&live, &moved).is_ok());
        });
        assert!(matches!(
            result,
            Err(JournalError::Native(Failure {
                stage: Stage::Fence,
                outcome: Outcome::Unknown,
                ..
            }))
        ));
        let pending = fs::read(moved.join(DATA))?;
        assert!(journal.quiescent().is_err());
        assert!(journal.latest(peer).is_err());
        assert!(matches!(
            ReplayStore::commit(&mut journal, local, peer, 12),
            Err(Error::OutcomeUnknown)
        ));
        let failure = journal.take_failure().ok_or(Error::Stale)?;
        assert_eq!(failure.stage, Stage::Recovery);
        assert_eq!(failure.outcome, Outcome::Unknown);
        assert!(journal.recover().is_err());
        fs::rename(&moved, &live)?;
        assert!(!journal.quiescent()?);
        // Replacing the on-disk target with a different valid older snapshot must
        // not let recovery adopt it as the original pending transaction.
        let older = Snapshot {
            highwater: 0,
            records: vec![Record {
                peer,
                monotonic: 10,
            }],
        }
        .encode(local)?;
        fs::write(live.join(DATA), older)?;
        assert!(journal.recover().is_err());
        assert!(!journal.quiescent()?);
        fs::write(live.join(DATA), &pending)?;
        File::open(live.join(DATA))?.sync_all()?;
        assert!(journal.recover()?);
        assert!(journal.quiescent()?);
        assert_eq!(journal.latest(peer)?, Some(11));
        assert!(matches!(
            journal.commit_time(local, peer, 11),
            Err(JournalError::Core(Error::Replay))
        ));
        journal.commit_time(local, peer, 12)?;
        assert_eq!(journal.latest(peer)?, Some(12));
        assert_eq!(journal.commits(), 3);
        Ok(())
    }
    #[test]
    fn corrupted_snapshot_alias_and_replaced_writer_fence_never_adopt_empty_history() -> Test {
        let scratch = Scratch::new()?;
        let local = [2; 32];
        let mut journal = Journal::open(&scratch.0, local, 2)?;
        journal.commit_time(local, [3; 32], 10)?;
        drop(journal);
        let path = scratch.0.join(DATA);
        let valid = fs::read(&path)?;
        let mut corrupt = valid.clone();
        corrupt[87] ^= 1;
        fs::write(&path, &corrupt)?;
        assert!(matches!(
            Journal::open(&scratch.0, local, 2),
            Err(JournalError::Core(Error::Storage))
        ));
        assert_eq!(fs::read(&path)?, corrupt);
        fs::write(&path, valid)?;
        let mut journal = Journal::open(&scratch.0, local, 2)?;
        fs::rename(scratch.0.join(LOCK), scratch.0.join("original-lock"))?;
        fs::write(scratch.0.join(LOCK), [])?;
        assert!(journal.quiescent().is_err());
        assert!(matches!(
            journal.commit_time(local, [3; 32], 11),
            Err(JournalError::Native(Failure {
                stage: Stage::Fence,
                outcome: Outcome::Unknown,
                ..
            }))
        ));
        drop(journal);
        fs::remove_file(&path)?;
        fs::hard_link(scratch.0.join(LOCK), &path)?;
        assert!(matches!(
            Journal::open(&scratch.0, local, 2),
            Err(JournalError::Native(Failure {
                stage: Stage::Fence,
                ..
            }))
        ));
        Ok(())
    }
    #[test]
    fn original_pre_rename_os_failure_never_claims_durability_or_loses_peer_history() -> Test {
        let scratch = Scratch::new()?;
        let local = [2; 32];
        let mut journal = Journal::open(&scratch.0, local, 2)?;
        fs::create_dir(scratch.0.join(DATA))?;
        assert!(matches!(
            ReplayStore::commit(&mut journal, local, [3; 32], 10),
            Err(Error::Storage)
        ));
        let failure = journal.take_failure().ok_or(Error::Stale)?;
        assert_eq!(failure.stage, Stage::Rename);
        assert_eq!(failure.outcome, Outcome::NotCommitted);
        assert!(journal.quiescent()?);
        assert_eq!(journal.latest([3; 32])?, None);
        assert_eq!(journal.commits(), 0);
        fs::remove_dir(scratch.0.join(DATA))?;
        journal.commit_time(local, [3; 32], 10)?;
        assert_eq!(journal.latest([3; 32])?, Some(10));
        Ok(())
    }
    #[test]
    fn subprocess_commit_probe() -> Test {
        let Some(directory) = std::env::var_os("GNUNET_UDP_REPLAY_CHILD_DIRECTORY") else {
            return Ok(());
        };
        let mut journal = Journal::open(directory, [2; 32], 2)?;
        journal.commit_time([2; 32], [3; 32], 100)?;
        if std::env::var_os("GNUNET_UDP_REPLAY_CHILD_HOLD").is_some() {
            let mut output = io::stdout().lock();
            output.write_all(b"UDP_FENCE_HELD\n")?;
            output.flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
        }
        Ok(())
    }
    #[test]
    fn actual_process_writer_fence_survives_socket_absence_and_releases_on_process_exit() -> Test {
        let scratch = Scratch::new()?;
        let executable = std::env::current_exe()?;
        let args = [
            "--exact",
            "replay::tests::subprocess_commit_probe",
            "--nocapture",
        ];
        let mut child = Command::new(&executable)
            .args(args)
            .env("GNUNET_UDP_REPLAY_CHILD_DIRECTORY", &scratch.0)
            .env("GNUNET_UDP_REPLAY_CHILD_HOLD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut output = BufReader::new(child.stdout.take().ok_or(Error::Stale)?);
        let mut held = false;
        loop {
            let mut line = String::new();
            if output.read_line(&mut line)? == 0 {
                break;
            }
            if line.contains("UDP_FENCE_HELD") {
                held = true;
                break;
            }
        }
        assert!(held);
        assert!(Journal::open(&scratch.0, [2; 32], 2).is_err());
        let second = Command::new(&executable)
            .args(args)
            .env("GNUNET_UDP_REPLAY_CHILD_DIRECTORY", &scratch.0)
            .output()?;
        assert!(!second.status.success());
        child.kill()?;
        let _status = child.wait()?;
        let mut journal = Journal::open(&scratch.0, [2; 32], 2)?;
        assert_eq!(journal.latest([3; 32])?, Some(100));
        assert!(matches!(
            journal.commit_time([2; 32], [3; 32], 100),
            Err(JournalError::Core(Error::Replay))
        ));
        journal.commit_time([2; 32], [3; 32], 101)?;
        Ok(())
    }
}
