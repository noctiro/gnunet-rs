//! Native single-writer DATASTORE with append WAL and immutable UID objects.
//!
//! On-disk framing is internal Rust storage, never a GNUnet wire extension.
//! Values are not required to hash to their lookup keys. Only metadata indexes
//! remain resident; one reusable IPC-sized selected-value buffer is retained.
mod codec;
mod files;
mod policy;
use files::Files;
use gnunet_crypto::hash256;
use gnunet_datastore::backend::{
    Backend, BackendError, Failure, Maintenance, MaintenancePolicy, Meta, Put, PutPolicy,
    PutReport, Record, Selection, Usage,
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::datastore::MAX_VALUE_BYTES;
use std::{
    collections::HashMap,
    fmt,
    io::{self, Seek, SeekFrom},
    path::Path,
    sync::Arc,
};

/// Finite native metadata/log/maintenance bounds, independent of service quota.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum live entries; their values remain on disk.
    pub max_records: usize,
    /// Maximum complete WAL bytes before mandatory checkpoint.
    pub max_wal_bytes: u64,
    /// Maximum operations in one atomic WAL transaction.
    pub max_transaction_ops: usize,
    /// Checkpoint before the next mutation after reaching this WAL byte count.
    pub checkpoint_bytes: u64,
    /// Maximum directory entries examined in one explicit orphan cleanup slice.
    pub garbage_entries: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_records: 65_536,
            max_wal_bytes: 64 * 1024 * 1024,
            max_transaction_ops: 4096,
            checkpoint_bytes: 8 * 1024 * 1024,
            garbage_entries: 1024,
        }
    }
}
/// Original native or pure refusal. Arc preserves the actual io::Error across
/// the returned error and a fenced instance's retained original failure.
#[derive(Clone, Debug)]
pub enum Cause {
    /// Original OS error, including raw errno and message.
    Io(Arc<io::Error>),
    /// Exact resource, format, integrity or writer authority classification.
    Protocol(ProtocolError),
}
/// Backend failure with its original stage and actual logical certainty.
#[derive(Clone, Debug)]
pub struct Error {
    /// Native stage that produced the original refusal.
    pub stage: &'static str,
    /// Original cause; no reconstructed generic I/O error replaces it.
    pub cause: Cause,
    certainty: Failure,
}
impl Error {
    fn protocol(stage: &'static str, error: ProtocolError) -> Self {
        Self {
            stage,
            cause: Cause::Protocol(error),
            certainty: Failure::BeforeCommit,
        }
    }
    fn io(stage: &'static str, error: io::Error) -> Self {
        Self {
            stage,
            cause: Cause::Io(Arc::new(error)),
            certainty: Failure::BeforeCommit,
        }
    }
    fn unknown(mut self) -> Self {
        self.certainty = Failure::Unknown;
        self
    }
    fn codec(stage: &'static str, error: codec::CodecError) -> Self {
        match error {
            codec::CodecError::Io(error) => Self::io(stage, error),
            codec::CodecError::Corrupt => Self::protocol(stage, ProtocolError::Malformed),
            codec::CodecError::InvalidInput => Self::protocol(stage, ProtocolError::InvalidInput),
            codec::CodecError::Limit => Self::protocol(stage, ProtocolError::Capacity),
            codec::CodecError::Overflow => Self::protocol(stage, ProtocolError::Overflow),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            Cause::Io(error) => write!(
                f,
                "DATASTORE {} ({:?}): {error}",
                self.stage, self.certainty
            ),
            Cause::Protocol(error) => write!(
                f,
                "DATASTORE {} ({:?}): {error}",
                self.stage, self.certainty
            ),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Cause::Io(error) => Some(error.as_ref()),
            Cause::Protocol(error) => Some(error),
        }
    }
}
impl BackendError for Error {
    fn certainty(&self) -> Failure {
        self.certainty
    }
}
/// A best-effort physical cleanup failure after a known durable logical commit.
/// This does not turn the operation's successful result into a failure/Unknown.
#[derive(Clone, Debug)]
pub struct CleanupFailure {
    /// Original filesystem cleanup stage and cause, independent of commit outcome.
    pub source: Error,
}
/// Explicit settlement after WAL recovery and durability of the selected prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recovery {
    /// Actual selected durable metadata sequence.
    pub sequence: u64,
    /// Whether the original uncertain WAL candidate was selected. None denotes
    /// a checkpoint/fence uncertainty rather than a new logical mutation.
    pub candidate_committed: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Stored {
    meta: Meta,
    len: u64,
    digest: [u8; 32],
}
#[derive(Clone, Copy, Debug)]
enum Op {
    Upsert(Stored),
    Delete(u64),
    Clear,
}
struct Index {
    sequence: u64,
    highwater: u64,
    rows: Vec<Stored>,
    keys: HashMap<[u8; 64], Vec<u64>>,
    usage: Usage,
}
impl Index {
    fn empty() -> Self {
        Self {
            sequence: 0,
            highwater: 0,
            rows: Vec::new(),
            keys: HashMap::new(),
            usage: Usage::default(),
        }
    }
    fn position(&self, uid: u64) -> Result<usize, usize> {
        self.rows.binary_search_by_key(&uid, |row| row.meta.uid)
    }
    fn row(&self, uid: u64) -> Option<Stored> {
        self.position(uid).ok().map(|index| self.rows[index])
    }
    fn from_rows(
        sequence: u64,
        highwater: u64,
        rows: Vec<Stored>,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mut index = Self::empty();
        index.sequence = sequence;
        index.highwater = highwater;
        let mut last = 0;
        for row in rows {
            if row.meta.uid <= last || row.meta.uid > highwater || row.len > MAX_VALUE_BYTES as u64
            {
                return Err(Error::protocol("snapshot-order", ProtocolError::Malformed));
            }
            last = row.meta.uid;
            index.reserve(&[Op::Upsert(row)], limits)?;
            index.apply(&[Op::Upsert(row)]);
        }
        Ok(index)
    }
    fn reserve(&mut self, ops: &[Op], limits: Limits) -> Result<(), Error> {
        let additions = ops
            .iter()
            .filter(|op| matches!(op, Op::Upsert(row) if self.position(row.meta.uid).is_err()))
            .count();
        // The transaction can insert then evict its new item. One temporary
        // metadata row is bounded separately from the final live-entry ceiling.
        if self
            .rows
            .len()
            .checked_add(additions)
            .is_none_or(|count| count > limits.max_records.saturating_add(1))
        {
            return Err(Error::protocol("index-capacity", ProtocolError::Capacity));
        }
        self.rows
            .try_reserve_exact(additions)
            .map_err(|_| Error::protocol("index-allocation", ProtocolError::Capacity))?;
        self.keys
            .try_reserve(additions)
            .map_err(|_| Error::protocol("key-index-allocation", ProtocolError::Capacity))?;
        for op in ops {
            if let Op::Upsert(row) = op
                && self.position(row.meta.uid).is_err()
            {
                let values = self.keys.entry(row.meta.key).or_default();
                values.try_reserve_exact(1).map_err(|_| {
                    Error::protocol("key-values-allocation", ProtocolError::Capacity)
                })?;
            }
        }
        Ok(())
    }
    fn apply(&mut self, ops: &[Op]) {
        if matches!(ops, [Op::Clear]) {
            self.rows.clear();
            self.keys.clear();
            self.usage = Usage::default();
            return;
        }
        let mut start = 0;
        if let Some(Op::Upsert(row)) = ops.first() {
            match self.position(row.meta.uid) {
                Ok(index) => self.rows[index] = *row,
                Err(_) => {
                    // New UIDs are strictly above the committed high-water mark.
                    self.rows.push(*row);
                    if let Some(values) = self.keys.get_mut(&row.meta.key) {
                        values.push(row.meta.uid);
                    }
                    self.usage.entries += 1;
                    self.usage.value_bytes += row.len;
                }
            }
            start = 1;
        }
        let deleted = &ops[start..];
        if !deleted.is_empty() {
            let removed_uid = |uid: u64| {
                deleted
                    .binary_search_by_key(&uid, |op| match op {
                        Op::Delete(uid) => *uid,
                        _ => 0,
                    })
                    .is_ok()
            };
            let usage = &mut self.usage;
            self.rows.retain(|row| {
                let removed = removed_uid(row.meta.uid);
                if removed {
                    usage.entries -= 1;
                    usage.value_bytes -= row.len;
                }
                !removed
            });
            // A key may own many values. Filter each UID bucket once, rather
            // than rescanning a large bucket separately for every deletion.
            for values in self.keys.values_mut() {
                values.retain(|uid| !removed_uid(*uid));
            }
        }
        if !deleted.is_empty() {
            self.keys.retain(|_, values| !values.is_empty());
        }
    }
    fn validate(&self, ops: &[Op], highwater: u64, limits: Limits) -> Result<(), Error> {
        if highwater < self.highwater {
            return Err(Error::protocol("uid-regression", ProtocolError::Malformed));
        }
        if ops.iter().any(|op| matches!(op, Op::Clear)) {
            if !matches!(ops, [Op::Clear]) {
                return Err(Error::protocol(
                    "clear-transaction",
                    ProtocolError::Malformed,
                ));
            }
            return Ok(());
        }
        let offset = usize::from(matches!(ops.first(), Some(Op::Upsert(_))));
        let mut last_delete = 0;
        for op in &ops[offset..] {
            match op {
                Op::Delete(uid) if *uid > last_delete && *uid <= highwater => last_delete = *uid,
                _ => {
                    return Err(Error::protocol(
                        "transaction-order",
                        ProtocolError::Malformed,
                    ));
                }
            }
        }
        for op in ops {
            if let Op::Upsert(row) = *op {
                if row.meta.uid == 0 || row.meta.uid > highwater || row.len > MAX_VALUE_BYTES as u64
                {
                    return Err(Error::protocol("row-shape", ProtocolError::Malformed));
                }
                if let Some(old) = self.row(row.meta.uid) {
                    if old.len != row.len
                        || old.digest != row.digest
                        || old.meta.key != row.meta.key
                        || old.meta.kind != row.meta.kind
                        || old.meta.anonymity != row.meta.anonymity
                    {
                        return Err(Error::protocol("uid-identity", ProtocolError::Malformed));
                    }
                } else if row.meta.uid <= self.highwater {
                    return Err(Error::protocol("uid-reuse", ProtocolError::Malformed));
                }
            }
        }
        if ops.len() > limits.max_transaction_ops {
            return Err(Error::protocol(
                "transaction-capacity",
                ProtocolError::Capacity,
            ));
        }
        Ok(())
    }
}

/// One actual fenced disk backend. Use on a serialized blocking service worker.
/// Append/log-sync success is required before logical results become visible.
/// Unknown refuses selects/mutations/checkpoints until explicit recovery/reopen.
pub struct Store {
    files: Files,
    limits: Limits,
    index: Index,
    heaps: policy::Heaps,
    wal_bytes: u64,
    value: Vec<u8>,
    unknown: Option<Error>,
    pending_sequence: Option<u64>,
    last_unknown: Option<Error>,
    cleanup: Option<CleanupFailure>,
    #[cfg(test)]
    test_fault: Option<TestFault>,
}
impl Store {
    /// Open/create only this versioned Rust directory, acquire its real writer
    /// lock and replay its complete WAL prefix. A torn final append is truncated
    /// and synced; a complete corrupt record is refused, not silently discarded.
    pub fn open(path: impl AsRef<Path>, limits: Limits) -> Result<Self, Error> {
        if limits.max_records == 0
            || limits.max_transaction_ops == 0
            || limits.max_wal_bytes < 224
            || limits.checkpoint_bytes == 0
            || limits.checkpoint_bytes > limits.max_wal_bytes
        {
            return Err(Error::protocol("limits", ProtocolError::InvalidInput));
        }
        let mut files = Files::open(path.as_ref())?;
        let (index, wal_bytes) = Self::load(&mut files, limits)?;
        let heaps = policy::Heaps::new(&index.rows)?;
        Ok(Self {
            files,
            limits,
            index,
            heaps,
            wal_bytes,
            value: Vec::new(),
            unknown: None,
            pending_sequence: None,
            last_unknown: None,
            cleanup: None,
            #[cfg(test)]
            test_fault: None,
        })
    }
    /// Original active uncertainty; ordinary backend results remain fenced.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.unknown.as_ref()
    }
    /// Original last uncertainty, retained even after explicit successful recovery.
    #[must_use]
    pub fn last_uncertainty(&self) -> Option<&Error> {
        self.last_unknown.as_ref()
    }
    /// Separate physical cleanup issue after a known logical commit.
    #[must_use]
    pub fn cleanup_failure(&self) -> Option<&CleanupFailure> {
        self.cleanup.as_ref()
    }
    /// Current metadata/WAL sequence; diagnostic only, never a wire identifier.
    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.index.sequence
    }
    fn fence(&mut self, error: Error, candidate: Option<u64>) -> Error {
        let error = error.unknown();
        self.pending_sequence = candidate;
        self.unknown = Some(error.clone());
        self.last_unknown = Some(error.clone());
        error
    }
    fn ready(&mut self) -> Result<(), Error> {
        if let Some(error) = &self.unknown {
            return Err(error.clone());
        }
        if let Err(error) = self.files.verify() {
            return Err(self.fence(error, None));
        }
        let actual = self
            .files
            .wal
            .metadata()
            .map_err(|e| Error::io("wal-authority-size", e))?
            .len();
        if actual != self.wal_bytes {
            return Err(self.fence(
                Error::protocol("wal-authority-size", ProtocolError::Conflict),
                None,
            ));
        }
        Ok(())
    }
    fn load(files: &mut Files, limits: Limits) -> Result<(Index, u64), Error> {
        files.verify()?;
        let mut index = if let Some(mut snapshot) = files.snapshot()? {
            let (sequence, highwater, rows) = codec::read_snapshot(&mut snapshot, limits)
                .map_err(|e| Error::codec("snapshot-read", e))?;
            Index::from_rows(sequence, highwater, rows, limits)?
        } else {
            Index::empty()
        };
        let size = files
            .wal
            .metadata()
            .map_err(|e| Error::io("wal-read-size", e))?
            .len();
        if size > limits.max_wal_bytes {
            return Err(Error::protocol(
                "wal-read-capacity",
                ProtocolError::Capacity,
            ));
        }
        files
            .wal
            .seek(SeekFrom::Start(0))
            .map_err(|e| Error::io("wal-read-seek", e))?;
        let checkpoint_sequence = index.sequence;
        let checkpoint_highwater = index.highwater;
        let mut last_wal_sequence = 0_u64;
        let mut valid = 0_u64;
        loop {
            match codec::read_tx(&mut files.wal, limits).map_err(|e| Error::codec("wal-read", e))? {
                codec::TxRead::End => break,
                codec::TxRead::Torn { bytes_read } => {
                    if valid.checked_add(bytes_read) != Some(size) {
                        return Err(Error::protocol("wal-tail-size", ProtocolError::Malformed));
                    }
                    files
                        .wal
                        .set_len(valid)
                        .map_err(|e| Error::io("wal-tail-truncate", e))?;
                    files
                        .wal
                        .sync_all()
                        .map_err(|e| Error::io("wal-tail-sync", e))?;
                    break;
                }
                codec::TxRead::Complete {
                    seq,
                    hwm,
                    ops,
                    bytes,
                } => {
                    valid = valid
                        .checked_add(bytes)
                        .ok_or_else(|| Error::protocol("wal-length", ProtocolError::Overflow))?;
                    if valid > limits.max_wal_bytes {
                        return Err(Error::protocol("wal-length", ProtocolError::Capacity));
                    }
                    if seq <= last_wal_sequence {
                        return Err(Error::protocol("wal-order", ProtocolError::Malformed));
                    }
                    last_wal_sequence = seq;
                    if seq <= checkpoint_sequence {
                        if hwm > checkpoint_highwater
                            || (seq == checkpoint_sequence && hwm != checkpoint_highwater)
                        {
                            return Err(Error::protocol(
                                "checkpoint-highwater",
                                ProtocolError::Malformed,
                            ));
                        }
                        continue;
                    }
                    if index.sequence.checked_add(1) != Some(seq) {
                        return Err(Error::protocol("wal-sequence", ProtocolError::Malformed));
                    }
                    index.validate(&ops, hwm, limits)?;
                    index.reserve(&ops, limits)?;
                    index.apply(&ops);
                    if index.rows.len() > limits.max_records {
                        return Err(Error::protocol(
                            "replay-entry-capacity",
                            ProtocolError::Capacity,
                        ));
                    }
                    index.sequence = seq;
                    index.highwater = hwm;
                }
            }
        }
        // Settle the selected prefix before exposing any ordinary record. The
        // chosen snapshot, values directory and WAL names are all durable.
        if let Some(snapshot) = files.snapshot()? {
            snapshot
                .sync_all()
                .map_err(|e| Error::io("recovery-snapshot-sync", e))?;
        }
        files
            .wal
            .sync_all()
            .map_err(|e| Error::io("recovery-wal-sync", e))?;
        files
            .values
            .sync_all()
            .map_err(|e| Error::io("recovery-values-sync", e))?;
        files
            .root
            .sync_all()
            .map_err(|e| Error::io("recovery-root-sync", e))?;
        for row in &index.rows {
            files.check_object(row.meta.uid, row.len)?;
        }
        files.adopt_snapshot()?;
        files
            .wal
            .seek(SeekFrom::Start(valid))
            .map_err(|e| Error::io("wal-append-seek", e))?;
        Ok((index, valid))
    }
    /// Re-read and durably settle only the original fenced store. A physical
    /// authority mismatch remains a refusal. Rebuild the service core/MQs after
    /// recovery; the core's global Unknown latch intentionally has no clear API.
    pub fn recover(&mut self) -> Result<Recovery, Error> {
        if self.unknown.is_none() {
            return Err(Error::protocol(
                "recovery-not-required",
                ProtocolError::NotReady,
            ));
        }
        let pending = self.pending_sequence;
        let loaded = Self::load(&mut self.files, self.limits);
        let (index, bytes) = match loaded {
            Ok(value) => value,
            Err(error) => return Err(error.unknown()),
        };
        let heaps = policy::Heaps::new(&index.rows).map_err(Error::unknown)?;
        let report = Recovery {
            sequence: index.sequence,
            candidate_committed: pending.map(|candidate| index.sequence >= candidate),
        };
        self.index = index;
        self.heaps = heaps;
        self.wal_bytes = bytes;
        self.unknown = None;
        self.pending_sequence = None;
        Ok(report)
    }
    /// Stream one metadata checkpoint, then sync/truncate the obsolete WAL.
    /// Values are never copied. Ordinary PUTs do not rewrite this snapshot.
    pub fn checkpoint(&mut self) -> Result<(), Error> {
        self.ready()?;
        self.files.reset_garbage();
        let mut temporary = self.files.temporary(false)?;
        codec::write_snapshot(
            &mut temporary.file,
            &self.index.rows,
            self.index.sequence,
            self.index.highwater,
        )
        .map_err(|e| Error::codec("snapshot-write", e))?;
        temporary
            .file
            .sync_all()
            .map_err(|e| Error::io("snapshot-sync", e))?;
        if let Err(error) = self.files.install_snapshot(&mut temporary) {
            return Err(self.fence(error, None));
        }
        if let Err(error) = self.files.verify() {
            return Err(self.fence(error, None));
        }
        if let Err(error) = self.files.wal.set_len(0) {
            return Err(self.fence(Error::io("checkpoint-wal-truncate", error), None));
        }
        if let Err(error) = self.files.wal.sync_all() {
            return Err(self.fence(Error::io("checkpoint-wal-sync", error), None));
        }
        self.wal_bytes = 0;
        self.files
            .wal
            .seek(SeekFrom::Start(0))
            .map_err(|e| Error::io("checkpoint-wal-seek", e))?;
        Ok(())
    }
    /// A bounded physical orphan cleanup slice. It removes no live value and
    /// reports errors independently of previous known committed mutations.
    pub fn collect_garbage(&mut self) -> Result<(usize, bool), Error> {
        self.ready()?;
        let rows = &self.index.rows;
        let result = self.files.collect_orphans(
            |uid| rows.binary_search_by_key(&uid, |row| row.meta.uid).is_ok(),
            self.limits.garbage_entries,
        )?;
        if !result.1 {
            self.cleanup = None;
        }
        Ok(result)
    }
    fn cleanup_ops(&mut self, ops: &[Op]) {
        if !ops.iter().any(|op| matches!(op, Op::Delete(_))) {
            return;
        }
        for op in ops {
            if let Op::Delete(uid) = op
                && let Err(error) = self.files.remove_object(*uid)
                && self.cleanup.is_none()
            {
                self.cleanup = Some(CleanupFailure { source: error });
            }
        }
        if let Err(error) = self.files.values.sync_all()
            && self.cleanup.is_none()
        {
            self.cleanup = Some(CleanupFailure {
                source: Error::io("deleted-values-sync", error),
            });
        }
    }
    fn commit(&mut self, ops: &[Op], highwater: u64) -> Result<(), Error> {
        self.ready()?;
        if ops.is_empty() {
            return Ok(());
        }
        self.index.validate(ops, highwater, self.limits)?;
        self.index.reserve(ops, self.limits)?;
        let sequence = self
            .index
            .sequence
            .checked_add(1)
            .ok_or_else(|| Error::protocol("sequence-exhausted", ProtocolError::Overflow))?;
        let bytes = 144_u64
            .checked_mul(ops.len() as u64)
            .and_then(|n| n.checked_add(80))
            .ok_or_else(|| Error::protocol("transaction-length", ProtocolError::Overflow))?;
        if bytes > self.limits.max_wal_bytes {
            return Err(Error::protocol(
                "transaction-length",
                ProtocolError::Capacity,
            ));
        }
        if self.wal_bytes >= self.limits.checkpoint_bytes
            || self
                .wal_bytes
                .checked_add(bytes)
                .is_none_or(|n| n > self.limits.max_wal_bytes)
        {
            self.checkpoint()?;
        }
        self.files
            .wal
            .seek(SeekFrom::Start(self.wal_bytes))
            .map_err(|error| Error::io("wal-append-position", error))?;
        #[cfg(test)]
        if self.test_fault == Some(TestFault::BeforeWal) {
            self.test_fault = None;
            return Err(Error::io("test-before-wal", io::Error::other("injected")));
        }
        if let Err(error) = codec::write_tx(&mut self.files.wal, sequence, highwater, ops) {
            return Err(self.fence(Error::codec("wal-append", error), Some(sequence)));
        }
        #[cfg(test)]
        if self.test_fault == Some(TestFault::AfterWal) {
            self.test_fault = None;
            return Err(self.fence(
                Error::io("test-after-wal", io::Error::other("injected")),
                Some(sequence),
            ));
        }
        if let Err(error) = self.files.wal.sync_all() {
            return Err(self.fence(Error::io("wal-commit-sync", error), Some(sequence)));
        }
        if let Err(error) = self.files.verify() {
            return Err(self.fence(error, Some(sequence)));
        }
        self.wal_bytes += bytes;
        self.index.apply(ops);
        if ops.iter().any(|op| matches!(op, Op::Delete(_) | Op::Clear)) {
            self.files.reset_garbage();
        }
        self.index.sequence = sequence;
        self.index.highwater = highwater;
        self.cleanup_ops(ops);
        Ok(())
    }
    fn read_value(&mut self, row: Stored) -> Result<(), Error> {
        let length = usize::try_from(row.len)
            .map_err(|_| Error::protocol("value-length", ProtocolError::Overflow))?;
        self.value
            .try_reserve_exact(length.saturating_sub(self.value.len()))
            .map_err(|_| Error::protocol("value-buffer", ProtocolError::Capacity))?;
        self.value.resize(length, 0);
        self.files
            .read_object(row.meta.uid, row.len, &row.digest, &mut self.value)
    }
    fn duplicate(
        &self,
        key: &[u8; 64],
        value: &[u8],
        digest: &[u8; 32],
    ) -> Result<Option<Stored>, Error> {
        if let Some(values) = self.index.keys.get(key) {
            for uid in values {
                if let Some(row) = self.index.row(*uid)
                    && row.len == value.len() as u64
                    && row.digest == *digest
                    && self.files.equals_object(*uid, value, &row.digest)?
                {
                    return Ok(Some(row));
                }
            }
        }
        Ok(None)
    }
}

impl Backend for Store {
    type Error = Error;
    fn usage(&self) -> Usage {
        self.index.usage
    }
    fn put(&mut self, value: Put<'_>, policy: PutPolicy) -> Result<PutReport, Error> {
        let result = (|| {
            self.ready()?;
            if value.value.len() > MAX_VALUE_BYTES || policy.target_bytes > policy.ceiling_bytes {
                return Err(Error::protocol("put-policy", ProtocolError::InvalidInput));
            }
            let digest = hash256(value.value);
            let old = self.duplicate(value.key, value.value, &digest)?;
            let inserted = old.is_none();
            let highwater = if inserted {
                self.index
                    .highwater
                    .checked_add(1)
                    .ok_or_else(|| Error::protocol("uid-exhausted", ProtocolError::Overflow))?
            } else {
                self.index.highwater
            };
            let row = if let Some(mut old) = old {
                old.meta.priority = old.meta.priority.saturating_add(value.priority);
                old.meta.replication = old.meta.replication.saturating_add(value.replication);
                old.meta.expiration = old.meta.expiration.max(value.expiration);
                old
            } else {
                Stored {
                    meta: Meta {
                        uid: highwater,
                        key: *value.key,
                        kind: value.kind,
                        priority: value.priority,
                        anonymity: value.anonymity,
                        replication: value.replication,
                        expiration: value.expiration,
                    },
                    len: value.value.len() as u64,
                    digest,
                }
            };
            let mut usage = self.index.usage;
            if inserted {
                usage.entries += 1;
                usage.value_bytes = usage
                    .value_bytes
                    .checked_add(row.len)
                    .ok_or_else(|| Error::protocol("usage", ProtocolError::Overflow))?;
            }
            self.heaps
                .prepare(&self.index.rows, Some(row), self.limits.max_records)?;
            let max = policy
                .max_evictions
                .min(self.limits.max_transaction_ops.saturating_sub(1));
            let (mut deleted, maintenance) = self.heaps.plan(
                &self.index.rows,
                Some(row),
                usage,
                MaintenancePolicy {
                    now: policy.now,
                    ceiling_bytes: policy.ceiling_bytes,
                    target_bytes: policy.target_bytes,
                    max_evictions: max,
                },
            )?;
            let mut ops = Vec::new();
            ops.try_reserve_exact(deleted.len() + 1)
                .map_err(|_| Error::protocol("put-operations", ProtocolError::Capacity))?;
            deleted.sort_unstable();
            ops.push(Op::Upsert(row));
            for uid in deleted {
                ops.push(Op::Delete(uid));
            }
            // Reserve every index allocation before creating/publishing an object.
            self.index.reserve(&ops, self.limits)?;
            if inserted {
                self.files.reset_garbage();
                self.files.replace_unreferenced(row.meta.uid)?;
                self.files.put_object(row.meta.uid, value.value)?;
            }
            self.commit(&ops, highwater)?;
            Ok(PutReport {
                inserted,
                maintenance,
            })
        })();
        if result.is_err() {
            self.index.keys.retain(|_, values| !values.is_empty());
        }
        result
    }
    fn select(
        &mut self,
        selection: Selection<'_>,
        random: u64,
    ) -> Result<Option<Record<'_>>, Error> {
        self.ready()?;
        let row = match selection {
            Selection::Get {
                key,
                kind,
                next_uid,
                random: false,
            } => {
                let start = self
                    .index
                    .rows
                    .partition_point(|row| row.meta.uid < next_uid);
                self.index.rows[start..].iter().copied().find(|row| {
                    key.is_none_or(|key| row.meta.key == *key)
                        && (kind == 0 || row.meta.kind == kind)
                })
            }
            Selection::Get {
                key,
                kind,
                random: true,
                ..
            } => {
                let matches = |row: &&Stored| {
                    key.is_none_or(|key| row.meta.key == *key)
                        && (kind == 0 || row.meta.kind == kind)
                };
                let count = self.index.rows.iter().filter(matches).count();
                if count == 0 {
                    None
                } else {
                    self.index
                        .rows
                        .iter()
                        .filter(matches)
                        .nth(rank(random, count))
                        .copied()
                }
            }
            Selection::ZeroAnonymity { kind, next_uid } => {
                if kind == 0 {
                    return Err(Error::protocol(
                        "zero-anonymity-type",
                        ProtocolError::InvalidInput,
                    ));
                }
                let start = self
                    .index
                    .rows
                    .partition_point(|row| row.meta.uid < next_uid);
                self.index.rows[start..]
                    .iter()
                    .copied()
                    .find(|row| row.meta.kind == kind && row.meta.anonymity == 0)
            }
            Selection::Replication => {
                let score = self.index.rows.iter().map(|row| row.meta.replication).max();
                score.and_then(|score| {
                    let count = self
                        .index
                        .rows
                        .iter()
                        .filter(|row| row.meta.replication == score)
                        .count();
                    self.index
                        .rows
                        .iter()
                        .filter(|row| row.meta.replication == score)
                        .nth(rank(random, count))
                        .copied()
                })
            }
        };
        let Some(row) = row else {
            return Ok(None);
        };
        // Read/authenticate the original body before any replication side effect.
        self.read_value(row)?;
        if matches!(selection, Selection::Replication) && row.meta.replication > 0 {
            let mut updated = row;
            updated.meta.replication -= 1;
            self.commit(&[Op::Upsert(updated)], self.index.highwater)?;
        }
        Ok(Some(Record {
            meta: row.meta,
            value: &self.value,
        }))
    }
    fn remove(&mut self, key: &[u8; 64], value: &[u8]) -> Result<bool, Error> {
        self.ready()?;
        let Some(row) = self.duplicate(key, value, &hash256(value))? else {
            return Ok(false);
        };
        self.commit(&[Op::Delete(row.meta.uid)], self.index.highwater)?;
        Ok(true)
    }
    fn maintain(&mut self, policy: MaintenancePolicy) -> Result<Maintenance, Error> {
        self.ready()?;
        self.heaps
            .prepare(&self.index.rows, None, self.limits.max_records)?;
        let mut policy = policy;
        policy.max_evictions = policy.max_evictions.min(self.limits.max_transaction_ops);
        let (mut deleted, maintenance) =
            self.heaps
                .plan(&self.index.rows, None, self.index.usage, policy)?;
        let mut ops = Vec::new();
        ops.try_reserve_exact(deleted.len())
            .map_err(|_| Error::protocol("maintenance-operations", ProtocolError::Capacity))?;
        deleted.sort_unstable();
        for uid in deleted {
            ops.push(Op::Delete(uid));
        }
        self.commit(&ops, self.index.highwater)?;
        // Reclaim crash leftovers in the same bounded maintenance cadence. A
        // cleanup refusal cannot reverse an already durable logical mutation.
        if let Err(error) = self.collect_garbage() {
            self.cleanup = Some(CleanupFailure { source: error });
        }
        Ok(maintenance)
    }
    fn drop_all(&mut self) -> Result<(), Error> {
        self.ready()?;
        self.commit(&[Op::Clear], self.index.highwater)?;
        // DROP's complete logical clear is already durable. Physical objects are
        // now orphans; cleanup failures remain separate from that known result.
        let mut removed_in_pass = 0_usize;
        loop {
            match self.collect_garbage() {
                Ok((removed, more)) => {
                    removed_in_pass = removed_in_pass.saturating_add(removed);
                    if !more {
                        // Directory mutation may affect a live readdir cursor.
                        // A fresh zero-removal pass proves quiescent cleanup.
                        if removed_in_pass == 0 {
                            break;
                        }
                        removed_in_pass = 0;
                        self.files.reset_garbage();
                    }
                }
                Err(error) => {
                    self.cleanup = Some(CleanupFailure { source: error });
                    break;
                }
            }
        }
        Ok(())
    }
}
fn rank(random: u64, count: usize) -> usize {
    ((u128::from(random) * count as u128) >> 64) as usize
}
#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestFault {
    BeforeWal,
    AfterWal,
}
#[cfg(test)]
mod tests;
