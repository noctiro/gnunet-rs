//! One fenced snapshot, explicit publication certainty and managed origins.
use super::Record;
use gnunet_crypto::EddsaPublicKey;
use gnunet_transport::{PeerId, own::CommitOutcome, own_wire};
use gnunet_types::Error;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

const MAX_RECORDS: usize = 4096;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const HEADER: usize = 24;
const OWNER_FILE: &str = ".gnunet-peerstore-owner.lock";
const TEMP_PREFIX: &str = ".gnunet-peerstore-tmp-";

/// Independent verification policies for local managed HELLOs and remote hints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloProfiles {
    /// Local producer's HELLO policy, also used when reopening managed records.
    pub managed: gnunet_hello::SignatureProfile,
    /// Remote HELLO discovery policy; it does not authorize local key derivation.
    pub discovery: gnunet_hello::SignatureProfile,
}
impl Default for HelloProfiles {
    fn default() -> Self {
        Self {
            managed: gnunet_hello::SignatureProfile::Gnunet029,
            discovery: gnunet_hello::SignatureProfile::Gnunet029,
        }
    }
}

/// Reserved managed storage is unavailable to generic public STORE traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagedQuota {
    /// Maximum complete managed records, including an optional aggregate HELLO.
    pub records: usize,
    /// Maximum complete record bytes plus their four-byte private origin tags.
    pub bytes: usize,
}

/// Borrowed verified-producer input. The backend independently verifies the
/// original canonical purpose29 value against its expected peer.
pub struct ManagedAddress<'a> {
    /// Canonical public value, including its final NUL.
    pub value: &'a [u8],
    /// Original unsigned cache expiry; zero/tiny forecasts are not inflated.
    pub expiry: u64,
}

/// Actual native failure retained beside its original transaction result.
#[derive(Debug)]
pub struct JournalFailure {
    /// Native publication/recovery stage where the refusal was observed.
    pub stage: &'static str,
    /// Pure classification returned to the caller's lifecycle state machine.
    pub classification: Error,
    /// Original OS error, including its original kind/raw errno when available.
    pub io: Option<io::Error>,
}
impl JournalFailure {
    fn protocol(stage: &'static str, classification: Error) -> Self {
        Self {
            stage,
            classification,
            io: None,
        }
    }
    fn io(stage: &'static str, error: io::Error) -> Self {
        Self {
            stage,
            classification: Error::Storage,
            io: Some(error),
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Origin {
    Public = 0,
    Address = 1,
    Hello = 2,
}
struct Stored {
    origin: Origin,
    record: Record,
}
struct Snapshot {
    generation: u64,
    highwater: u64,
    rows: Vec<Stored>,
    raw: Vec<u8>,
}

#[derive(Clone)]
struct Id {
    scope: Arc<()>,
    serial: u64,
}
impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.scope, &other.scope) && self.serial == other.serial
    }
}
impl Eq for Id {}

/// Original explicit transaction handle. It retains the physical writer fence
/// even if its Journal is dropped; another owner cannot silently supersede it.
#[must_use = "Retain the original transaction through its known outcome or explicit recovery."]
pub struct Transaction {
    id: Id,
    _authority: Arc<Authority>,
    outcome: Option<CommitOutcome>,
    failure: Option<JournalFailure>,
    recovery_failure: Option<JournalFailure>,
}
impl Transaction {
    /// A diagnostic number; it is not a wire id or reconstructed authority.
    pub fn number(&self) -> u64 {
        self.id.serial
    }
    /// Last actual certainty; None means prepared without publication I/O.
    pub fn outcome(&self) -> Option<CommitOutcome> {
        self.outcome
    }
    /// Original actual failure is retained across later recovery attempts.
    pub fn failure(&self) -> Option<&JournalFailure> {
        self.failure.as_ref()
    }
    /// Move the original cause to its supervising owner without copying or
    /// reconstructing an OS error. Recovery normally retains it until known.
    pub fn take_failure(&mut self) -> Option<JournalFailure> {
        self.failure.take()
    }
    /// Latest recovery refusal, independently from the original failure.
    pub fn recovery_failure(&self) -> Option<&JournalFailure> {
        self.recovery_failure.as_ref()
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Prepared,
    Unknown,
}
struct Pending {
    id: Id,
    candidate: Snapshot,
    predecessor: Option<(Vec<u8>, Inode)>,
    phase: Phase,
    temporary: Option<Temporary>,
    renamed: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum TestStep {
    BeforeRename,
    AfterRename,
}

/// One synchronous fenced writer. Unknown publication retains the original
/// candidate/predecessor and blocks all writes/timestamp reservations.
/// Public IPC values stay ordinary GNUnet records; origin tags exist only on disk.
pub struct Journal {
    hello_profiles: HelloProfiles,
    path: PathBuf,
    authority: Arc<Authority>,
    scope: Arc<()>,
    snapshot: Snapshot,
    published_inode: Option<Inode>,
    commits: u64,
    last_transaction: u64,
    pending: Option<Pending>,
    quota: Option<ManagedQuota>,
    deferred: Option<Transaction>,
    authority_lost: bool,
    #[cfg(test)]
    test_hook: Option<fn(&Journal, TestStep) -> io::Result<()>>,
}
impl Journal {
    /// Open the current Rust snapshot format under a real cross-process file
    /// lock. Old/future/corrupt formats are rejected without being overwritten.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::open_with_profiles(path, HelloProfiles::default())
    }
    /// Open with separate local-managed and remote-discovery HELLO policies.
    /// There is no alternate-profile fallback or on-disk profile migration.
    pub fn open_with_profiles(
        path: impl AsRef<Path>,
        hello_profiles: HelloProfiles,
    ) -> Result<Self, Error> {
        let requested = path.as_ref();
        let name = requested.file_name().ok_or(Error::InvalidInput)?;
        if name
            .as_encoded_bytes()
            .eq_ignore_ascii_case(OWNER_FILE.as_bytes())
            || name
                .as_encoded_bytes()
                .get(..TEMP_PREFIX.len())
                .is_some_and(|p| p.eq_ignore_ascii_case(TEMP_PREFIX.as_bytes()))
        {
            return Err(Error::InvalidInput);
        }
        let parent = requested
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent = fs::canonicalize(parent).map_err(|_| Error::Storage)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&parent)
            .map_err(|_| Error::Storage)?;
        let directory_id = Inode::of(&directory.metadata().map_err(|_| Error::Storage)?);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(parent.join(OWNER_FILE))
            .map_err(|_| Error::Storage)?;
        lock.try_lock().map_err(|_| Error::Conflict)?;
        let lock_meta = lock.metadata().map_err(|_| Error::Storage)?;
        if !lock_meta.is_file() {
            return Err(Error::InvalidInput);
        }
        let authority = Arc::new(Authority {
            parent: parent.clone(),
            directory,
            directory_id,
            lock,
            lock_id: Inode::of(&lock_meta),
        });
        authority.verify().map_err(|f| f.classification)?;
        let path = parent.join(name);
        let (snapshot, published_inode) = match open_data(&path) {
            Ok(mut file) => {
                let metadata = file.metadata().map_err(|_| Error::Storage)?;
                if !metadata.is_file() || Inode::of(&metadata) == authority.lock_id {
                    return Err(Error::InvalidInput);
                }
                let raw = read_bounded(&mut file).map_err(|f| f.classification)?;
                (
                    decode_snapshot(raw, hello_profiles.managed)?,
                    Some(Inode::of(&metadata)),
                )
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (
                Snapshot {
                    generation: 0,
                    highwater: 0,
                    rows: Vec::new(),
                    raw: Vec::new(),
                },
                None,
            ),
            Err(_) => return Err(Error::Storage),
        };
        authority.verify().map_err(|f| f.classification)?;
        Ok(Self {
            hello_profiles,
            path,
            authority,
            scope: Arc::new(()),
            snapshot,
            published_inode,
            commits: 0,
            last_transaction: 0,
            pending: None,
            quota: None,
            deferred: None,
            authority_lost: false,
            #[cfg(test)]
            test_hook: None,
        })
    }
    /// Immutable HELLO policies selected when the original writer was opened.
    pub fn hello_profiles(&self) -> HelloProfiles {
        self.hello_profiles
    }
    pub(super) fn records(&self) -> impl Iterator<Item = &Record> {
        self.snapshot.rows.iter().map(|s| &s.record)
    }
    /// Number of known durable commits in this writer lifetime.
    pub fn commits(&self) -> u64 {
        self.commits
    }
    /// Actual retained timestamp highwater, including unused reservation gaps.
    pub fn highwater(&self) -> u64 {
        self.snapshot.highwater
    }
    /// An unresolved prepared/unknown operation blocks fresh writes.
    pub fn transaction_pending(&self) -> bool {
        self.pending.is_some()
    }
    /// A detected physical-directory/fence loss never becomes a fresh authority.
    pub fn authority_lost(&self) -> bool {
        self.authority_lost
    }
    fn verify_authority(&mut self) -> Result<(), JournalFailure> {
        if self.authority_lost {
            return Err(JournalFailure::protocol(
                "retired-authority",
                Error::Conflict,
            ));
        }
        if let Err(failure) = self.authority.verify() {
            self.authority_lost = true;
            return Err(failure);
        }
        Ok(())
    }
    fn ready(&mut self) -> Result<(), Error> {
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        self.verify_authority().map_err(|f| f.classification)
    }
    /// Reserve managed capacity before exposing a publisher or public STORE.
    /// Existing records must fit; no record is silently discarded to make room.
    pub fn reserve_managed(&mut self, quota: ManagedQuota) -> Result<(), Error> {
        self.ready()?;
        if quota.records > MAX_RECORDS || quota.bytes > MAX_BYTES - HEADER {
            return Err(Error::Capacity);
        }
        check_partitions(&self.snapshot.rows, Some(quota))?;
        self.quota = Some(quota);
        Ok(())
    }
    fn prepare(&mut self, rows: Vec<Stored>, highwater: u64) -> Result<Transaction, Error> {
        self.ready()?;
        if highwater < self.snapshot.highwater {
            return Err(Error::Replay);
        }
        let generation = self
            .snapshot
            .generation
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let serial = self
            .last_transaction
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        check_partitions(&rows, self.quota)?;
        let raw = encode_snapshot(generation, highwater, &rows)?;
        let predecessor = self
            .published_inode
            .map(|inode| copy_bytes(&self.snapshot.raw).map(|raw| (raw, inode)))
            .transpose()?;
        let id = Id {
            scope: self.scope.clone(),
            serial,
        };
        let transaction = Transaction {
            id: id.clone(),
            _authority: self.authority.clone(),
            outcome: None,
            failure: None,
            recovery_failure: None,
        };
        self.pending = Some(Pending {
            id,
            candidate: Snapshot {
                generation,
                highwater,
                rows,
                raw,
            },
            predecessor,
            phase: Phase::Prepared,
            temporary: None,
            renamed: false,
        });
        self.last_transaction = serial;
        Ok(transaction)
    }
    /// Stage a complete replacement of this writer's managed origin partition.
    /// Public/foreign records are retained even if they use the same namespaces.
    pub fn prepare_managed(
        &mut self,
        peer: PeerId,
        addresses: &[ManagedAddress<'_>],
        hello: Option<&[u8]>,
        now: u64,
    ) -> Result<Transaction, Error> {
        self.ready()?;
        let quota = self.quota.ok_or(Error::Unavailable)?;
        if addresses
            .len()
            .checked_add(usize::from(hello.is_some()))
            .ok_or(Error::Capacity)?
            > quota.records
        {
            return Err(Error::Capacity);
        }
        // Bound every borrowed input as a whole before parsing, cryptographic
        // hashing, scratch allocation or cloning any retained public row.
        let mut managed_bytes = 0usize;
        for address in addresses {
            managed_bytes = managed_bytes
                .checked_add(input_record_bytes(
                    address.value.len(),
                    own_wire::SUBSYSTEM.len(),
                    own_wire::KEY.len(),
                )?)
                .ok_or(Error::Capacity)?;
        }
        if let Some(value) = hello {
            managed_bytes = managed_bytes
                .checked_add(input_record_bytes(
                    value.len(),
                    b"peerstore".len(),
                    b"peerstore-peer-hello-uri".len(),
                )?)
                .ok_or(Error::Capacity)?;
        }
        if managed_bytes > quota.bytes {
            return Err(Error::Capacity);
        }
        let mut rows = clone_rows(
            self.snapshot
                .rows
                .iter()
                .filter(|s| s.origin == Origin::Public),
        )?;
        rows.try_reserve_exact(
            addresses
                .len()
                .checked_add(usize::from(hello.is_some()))
                .ok_or(Error::Capacity)?,
        )
        .map_err(|_| Error::Capacity)?;
        for address in addresses {
            let parsed = own_wire::AddressRecord::parse(address.value)?;
            parsed.verify(EddsaPublicKey::from_bytes(peer.0))?;
            if parsed.generated > self.snapshot.highwater {
                return Err(Error::Replay);
            }
            rows.push(Stored {
                origin: Origin::Address,
                record: Record {
                    peer,
                    subsystem: copy_bytes(own_wire::SUBSYSTEM)?,
                    key: copy_bytes(own_wire::KEY)?,
                    value: copy_bytes(address.value)?,
                    expiry: address.expiry,
                },
            });
        }
        if let Some(value) = hello {
            let expiry = validate_hello(peer, value, now, self.hello_profiles.managed)?;
            rows.push(Stored {
                origin: Origin::Hello,
                record: Record {
                    peer,
                    subsystem: copy_bytes(b"peerstore")?,
                    key: copy_bytes(b"peerstore-peer-hello-uri")?,
                    value: copy_bytes(value)?,
                    expiry,
                },
            });
        }
        self.prepare(rows, self.snapshot.highwater)
    }
    /// Prepare a monotonic range before any caller may issue its timestamp.
    pub fn prepare_monotime(
        &mut self,
        minimum: u64,
        span: u64,
    ) -> Result<(Transaction, u64, u64), Error> {
        self.ready()?;
        if span == 0 {
            return Err(Error::InvalidInput);
        }
        let first = minimum.max(
            self.snapshot
                .highwater
                .checked_add(1)
                .ok_or(Error::Overflow)?,
        );
        let end = first.checked_add(span - 1).ok_or(Error::Overflow)?;
        let rows = clone_rows(self.snapshot.rows.iter())?;
        Ok((self.prepare(rows, end)?, first, end))
    }
    /// Synchronous legacy caller shape for an actual known durable reservation.
    /// Unknown stays quarantined and is never reported as a usable timestamp.
    pub fn reserve_monotime(&mut self, minimum: u64, span: u64) -> Result<(u64, u64), Error> {
        let (mut transaction, first, end) = self.prepare_monotime(minimum, span)?;
        match self.commit(&mut transaction) {
            CommitOutcome::Committed => Ok((first, end)),
            CommitOutcome::NotCommitted(cause) => Err(cause),
            CommitOutcome::Unknown(_) => {
                self.deferred = Some(transaction);
                Err(Error::OutcomeUnknown)
            }
        }
    }
    pub(super) fn store(&mut self, record: Record, replace: bool) -> Result<(), Error> {
        self.ready()?;
        if record.subsystem == b"transport_tcp_communicator" {
            if record.value.len() != 8 {
                return Err(Error::Malformed);
            }
            let new = u64::from_be_bytes(
                record
                    .value
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Malformed)?,
            );
            for old in self.records() {
                if old.peer == record.peer
                    && old.subsystem == record.subsystem
                    && old.key == record.key
                    && (old.value.len() != 8
                        || u64::from_be_bytes(
                            old.value
                                .as_slice()
                                .try_into()
                                .map_err(|_| Error::Malformed)?,
                        ) > new)
                {
                    return Err(Error::Replay);
                }
            }
        }
        let mut rows = clone_rows(self.snapshot.rows.iter().filter(|s| {
            !replace
                || !(s.record.peer == record.peer
                    && s.record.subsystem == record.subsystem
                    && s.record.key == record.key)
        }))?;
        rows.try_reserve(1).map_err(|_| Error::Capacity)?;
        rows.push(Stored {
            origin: Origin::Public,
            record,
        });
        let mut transaction = self.prepare(rows, self.snapshot.highwater)?;
        match self.commit(&mut transaction) {
            CommitOutcome::Committed => Ok(()),
            CommitOutcome::NotCommitted(cause) => Err(cause),
            CommitOutcome::Unknown(_) => {
                self.deferred = Some(transaction);
                Err(Error::OutcomeUnknown)
            }
        }
    }
    /// Transfer the actual original unknown handle retained by a synchronous
    /// convenience call. This never reconstructs a transaction or adopts a new
    /// authority. Fresh writes remain blocked until that original is recovered.
    pub fn take_deferred(&mut self) -> Option<Transaction> {
        self.deferred.take()
    }
    fn matches(&self, transaction: &Transaction) -> bool {
        self.pending
            .as_ref()
            .is_some_and(|p| p.id == transaction.id)
            && Arc::ptr_eq(&self.authority, &transaction._authority)
    }
    fn not_committed(
        &mut self,
        transaction: &mut Transaction,
        failure: JournalFailure,
    ) -> CommitOutcome {
        let outcome = CommitOutcome::NotCommitted(failure.classification);
        if transaction.failure.is_none() {
            transaction.failure = Some(failure);
        }
        self.pending = None;
        transaction.outcome = Some(outcome);
        outcome
    }
    fn unknown(&mut self, transaction: &mut Transaction, failure: JournalFailure) -> CommitOutcome {
        let outcome = CommitOutcome::Unknown(failure.classification);
        if transaction.failure.is_none() {
            transaction.failure = Some(failure);
        } else {
            transaction.recovery_failure = Some(failure);
        }
        if let Some(p) = self.pending.as_mut() {
            p.phase = Phase::Unknown;
        }
        transaction.outcome = Some(outcome);
        outcome
    }
    fn committed(&mut self, transaction: &mut Transaction) -> CommitOutcome {
        let Some(pending) = self.pending.take() else {
            return CommitOutcome::Unknown(Error::Stale);
        };
        let Some(commits) = self.commits.checked_add(1) else {
            self.pending = Some(pending);
            return self.unknown(
                transaction,
                JournalFailure::protocol("commit-counter", Error::Overflow),
            );
        };
        self.published_inode = pending.temporary.as_ref().map(|temporary| temporary.inode);
        self.snapshot = pending.candidate;
        self.commits = commits;
        transaction.outcome = Some(CommitOutcome::Committed);
        CommitOutcome::Committed
    }
    /// Cancel this exact prepared original before any publication I/O starts.
    /// Unknown can only be resolved by recovery; abort never assumes rollback.
    pub fn abort_prepared(
        &mut self,
        transaction: &mut Transaction,
    ) -> Result<CommitOutcome, Error> {
        if !self.matches(transaction) {
            return Err(Error::Stale);
        }
        let pending = self.pending.as_ref().ok_or(Error::Stale)?;
        if pending.phase == Phase::Unknown
            || matches!(transaction.outcome, Some(CommitOutcome::Unknown(_)))
        {
            return Err(Error::OutcomeUnknown);
        }
        if pending.phase != Phase::Prepared
            || transaction.outcome.is_some()
            || pending.temporary.is_some()
        {
            return Err(Error::Conflict);
        }
        Ok(self.not_committed(
            transaction,
            JournalFailure::protocol("prepared-abort", Error::Cancelled),
        ))
    }
    /// Attempt one prepared original. Committed requires file sync, rename,
    /// parent sync, exact readback and the retained physical-authority checks.
    pub fn commit(&mut self, transaction: &mut Transaction) -> CommitOutcome {
        if !self.matches(transaction) || transaction.outcome.is_some() {
            return CommitOutcome::NotCommitted(Error::Stale);
        }
        if self.commits == u64::MAX {
            return self.not_committed(
                transaction,
                JournalFailure::protocol("commit-counter", Error::Overflow),
            );
        }
        if let Err(f) = self.verify_authority() {
            return self.not_committed(transaction, f);
        }
        let current = match self.read_current() {
            Ok(current) => current,
            Err(failure) => return self.not_committed(transaction, failure),
        };
        if !self
            .pending
            .as_ref()
            .is_some_and(|pending| current == pending.predecessor)
        {
            return self.not_committed(
                transaction,
                JournalFailure::protocol("changed-predecessor", Error::Conflict),
            );
        }
        let mut temporary = match temporary_file(&self.authority.parent) {
            Ok(t) => t,
            Err(f) => return self.not_committed(transaction, f),
        };
        let Some(pending) = self.pending.as_ref() else {
            return self.not_committed(
                transaction,
                JournalFailure::protocol("missing-original", Error::Stale),
            );
        };
        if let Err(e) = temporary.file.write_all(&pending.candidate.raw) {
            return self.not_committed(transaction, JournalFailure::io("write", e));
        }
        if let Err(e) = temporary.file.sync_all() {
            return self.not_committed(transaction, JournalFailure::io("file-sync", e));
        }
        if let Err(f) = self.verify_authority() {
            return self.not_committed(transaction, f);
        }
        let Some(pending) = self.pending.as_mut() else {
            return self.not_committed(
                transaction,
                JournalFailure::protocol("missing-original", Error::Stale),
            );
        };
        pending.temporary = Some(temporary);
        pending.phase = Phase::Unknown;
        #[cfg(test)]
        if let Some(hook) = self.test_hook
            && let Err(error) = hook(self, TestStep::BeforeRename)
        {
            return self
                .not_committed(transaction, JournalFailure::io("test-before-rename", error));
        }
        let Some(rename) = self
            .pending
            .as_ref()
            .and_then(|pending| pending.temporary.as_ref())
            .map(|temporary| fs::rename(&temporary.path, &self.path))
        else {
            return self.unknown(
                transaction,
                JournalFailure::protocol("missing-file", Error::Stale),
            );
        };
        if let Err(error) = rename {
            return self.unknown(transaction, JournalFailure::io("rename", error));
        }
        let Some(pending) = self.pending.as_mut() else {
            return self.unknown(
                transaction,
                JournalFailure::protocol("missing-original", Error::Stale),
            );
        };
        pending.renamed = true;
        #[cfg(test)]
        if let Some(hook) = self.test_hook
            && let Err(error) = hook(self, TestStep::AfterRename)
        {
            return self.unknown(transaction, JournalFailure::io("test-after-rename", error));
        }
        if let Err(f) = self.finish_candidate() {
            return self.unknown(transaction, f);
        }
        self.committed(transaction)
    }
    fn read_current(&self) -> Result<Option<(Vec<u8>, Inode)>, JournalFailure> {
        match open_data(&self.path) {
            Ok(mut file) => {
                let metadata = file
                    .metadata()
                    .map_err(|e| JournalFailure::io("readback-metadata", e))?;
                if !metadata.is_file() || Inode::of(&metadata) == self.authority.lock_id {
                    return Err(JournalFailure::protocol("readback-kind", Error::Conflict));
                }
                Ok(Some((read_bounded(&mut file)?, Inode::of(&metadata))))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(JournalFailure::io("readback-open", e)),
        }
    }
    fn finish_candidate(&mut self) -> Result<(), JournalFailure> {
        self.verify_authority()?;
        self.authority
            .directory
            .sync_all()
            .map_err(|e| JournalFailure::io("directory-sync", e))?;
        let current = self.read_current()?;
        let pending = self
            .pending
            .as_ref()
            .ok_or_else(|| JournalFailure::protocol("missing-original", Error::Stale))?;
        let temporary = pending
            .temporary
            .as_ref()
            .ok_or_else(|| JournalFailure::protocol("missing-file", Error::Stale))?;
        if !current
            .as_ref()
            .is_some_and(|(raw, inode)| raw == &pending.candidate.raw && *inode == temporary.inode)
        {
            return Err(JournalFailure::protocol(
                "candidate-readback",
                Error::Conflict,
            ));
        }
        self.verify_authority()
    }
    /// Recover only this original candidate. A renamed candidate with unexpected
    /// predecessor/other bytes remains Unknown; no new write/sign is attempted.
    pub fn recover(&mut self, transaction: &mut Transaction) -> CommitOutcome {
        if !self.matches(transaction)
            || !matches!(transaction.outcome, Some(CommitOutcome::Unknown(_)))
        {
            return CommitOutcome::NotCommitted(Error::Stale);
        }
        if let Err(f) = self.verify_authority() {
            return self.unknown(transaction, f);
        }
        let current = match self.read_current() {
            Ok(c) => c,
            Err(f) => return self.unknown(transaction, f),
        };
        let Some(pending) = self.pending.as_ref() else {
            return self.unknown(
                transaction,
                JournalFailure::protocol("missing-original", Error::Stale),
            );
        };
        if current.as_ref().is_some_and(|(raw, inode)| {
            raw == &pending.candidate.raw
                && pending
                    .temporary
                    .as_ref()
                    .is_some_and(|t| t.inode == *inode)
        }) {
            if let Some(temporary) = &pending.temporary
                && let Err(e) = temporary.file.sync_all()
            {
                return self.unknown(transaction, JournalFailure::io("recovery-file-sync", e));
            }
            if let Err(f) = self.finish_candidate() {
                return self.unknown(transaction, f);
            }
            return self.committed(transaction);
        }
        let predecessor_matches = current == pending.predecessor;
        let original_temporary_present = pending.temporary.as_ref().is_some_and(|t| {
            fs::symlink_metadata(&t.path).is_ok_and(|m| m.is_file() && Inode::of(&m) == t.inode)
        });
        if !pending.renamed && predecessor_matches && original_temporary_present {
            if let Err(e) = self.authority.directory.sync_all() {
                return self.unknown(
                    transaction,
                    JournalFailure::io("recovery-predecessor-sync", e),
                );
            }
            let current = match self.read_current() {
                Ok(current) => current,
                Err(failure) => return self.unknown(transaction, failure),
            };
            let unchanged = self.pending.as_ref().is_some_and(|pending| {
                current == pending.predecessor
                    && pending.temporary.as_ref().is_some_and(|t| {
                        fs::symlink_metadata(&t.path)
                            .is_ok_and(|m| m.is_file() && Inode::of(&m) == t.inode)
                    })
            });
            if !unchanged {
                return self.unknown(
                    transaction,
                    JournalFailure::protocol("changed-recovery-predecessor", Error::Conflict),
                );
            }
            if let Err(f) = self.verify_authority() {
                return self.unknown(transaction, f);
            }
            return self.not_committed(
                transaction,
                JournalFailure::protocol("unchanged-predecessor", Error::Storage),
            );
        }
        self.unknown(
            transaction,
            JournalFailure::protocol("unresolved-bytes", Error::Conflict),
        )
    }
    /// No syscall worker survives these synchronous calls. Quiescence is
    /// independent of whether an Unknown outcome has been resolved.
    pub fn io_quiescent(&self, transaction: &Transaction) -> bool {
        Arc::ptr_eq(&self.authority, &transaction._authority)
    }
}

mod codec;
mod fence;
use codec::{
    check_partitions, clone_rows, copy_bytes, decode_snapshot, encode_snapshot, input_record_bytes,
    validate_hello,
};
use fence::{Authority, Inode, Temporary, open_data, read_bounded, temporary_file};
#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check real filesystem bytes, original transaction fences and publication certainty"
)]
mod tests;
