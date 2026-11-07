//! Synchronous Rust datastore boundary. The enclosing host serializes one
//! backend/service worker; these are semantic ports, not the C plugin ABI.
use gnunet_types::Error;
use gnunet_wire::official::AbsoluteTime;

/// Official GNUNET_DATASTORE_ENTRY_OVERHEAD used for quota/reservation charging.
pub const ENTRY_OVERHEAD: u64 = 256;
/// Logical usage, independent of private database pages, journal or orphan files.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    /// Number of currently retained values.
    pub entries: u64,
    /// Sum of their exact value byte lengths.
    pub value_bytes: u64,
}
impl Usage {
    /// Checked official logical charge, including per-entry overhead.
    pub fn charged(self) -> Result<u64, Error> {
        self.entries
            .checked_mul(ENTRY_OVERHEAD)
            .and_then(|overhead| overhead.checked_add(self.value_bytes))
            .ok_or(Error::Overflow)
    }
}
/// Stable owned metadata, without any borrowed pointer identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Meta {
    /// Stable unique identifier; reused identifiers must not alias removed values.
    pub uid: u64,
    /// Original key, which is not a hash of the value for all block types.
    pub key: [u8; 64],
    /// Original open GNUNET_BLOCK_Type.
    pub kind: u32,
    /// Retention priority, with saturating duplicate addition.
    pub priority: u32,
    /// Original anonymity; C plugins retain it on duplicate PUT.
    pub anonymity: u32,
    /// Remaining replication score, with saturating duplicate addition.
    pub replication: u32,
    /// Latest expiration from all merged PUTs.
    pub expiration: AbsoluteTime,
}
/// One actual value lent until the next exclusive backend call. It must fit
/// gnunet_wire::official::datastore::MAX_VALUE_BYTES before any select side effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record<'a> {
    /// Owned metadata, including the original score before replication decrement.
    pub meta: Meta,
    /// Exact retained value bytes, not a synthetic blob descriptor.
    pub value: &'a [u8],
}
/// Actual PUT input. Reservation identity and accounting stay in the service.
#[derive(Clone, Copy, Debug)]
pub struct Put<'a> {
    /// Exact key; duplicate identity is key plus exact value, ignoring type/anon.
    pub key: &'a [u8; 64],
    /// Type used only when inserting a new value.
    pub kind: u32,
    /// Added to existing priority with u32 saturation.
    pub priority: u32,
    /// Original level used only for a newly inserted value.
    pub anonymity: u32,
    /// Added to an existing replication score with u32 saturation.
    pub replication: u32,
    /// Duplicate expiration is max(old, requested).
    pub expiration: AbsoluteTime,
    /// Exact arbitrary value bytes.
    pub value: &'a [u8],
}
/// One selection. Ordinary reads include expired values until explicit maintenance.
#[derive(Clone, Copy, Debug)]
pub enum Selection<'a> {
    /// Lowest uid >= next_uid, or one random matching value without cursor use.
    Get {
        /// None matches every key.
        key: Option<&'a [u8; 64]>,
        /// Zero matches every type.
        kind: u32,
        /// Lower inclusive cursor, with no wraparound.
        next_uid: u64,
        /// Ignore next_uid and choose randomly when true.
        random: bool,
    },
    /// Lowest uid >= cursor of this nonzero type with anonymity zero.
    ZeroAnonymity {
        /// Required nonzero type.
        kind: u32,
        /// Inclusive UID cursor, without wraparound.
        next_uid: u64,
    },
    /// Random member of the maximum replication-score set. Positive scores are
    /// durably decremented once before returning; returned Meta retains old score.
    Replication,
}
/// A failure before any logical commit versus an actual uncertain commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Failure {
    /// No logical value/metadata deletion, insertion or score change committed.
    BeforeCommit,
    /// The logical mutation may have committed. The backend must fence use until
    /// explicit recovery settles that original candidate; do not retry blindly.
    Unknown,
}
/// Preserve each backend's original native error while exposing commit certainty.
pub trait BackendError {
    /// Actual mutation certainty; never infer it only from the wire status code.
    fn certainty(&self) -> Failure;
}
/// Bounded maintenance selection and its atomic logical usage ceiling.
#[derive(Clone, Copy, Debug)]
pub struct MaintenancePolicy {
    /// Current public source time for expiry (expiry <= now is expired).
    pub now: AbsoluteTime,
    /// Logical bytes available after live reservations; never exceed this.
    pub ceiling_bytes: u64,
    /// Desired cache reclamation target, no greater than ceiling_bytes.
    pub target_bytes: u64,
    /// Maximum records inspected/removed by this actual transaction.
    pub max_evictions: usize,
}
/// Actual committed reclamation. Expired removals precede lowest priority,
/// expiration, then stable UID for deterministic equal-priority ties.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Maintenance {
    /// Actual entries removed, including a newly inserted item if policy evicts it.
    pub removed_entries: u64,
    /// Actual logical bytes removed, including ENTRY_OVERHEAD per item.
    pub removed_bytes: u64,
    /// Latest official admission hint: now for expired eviction; FOREVER when
    /// removing positive priority; otherwise the evicted item's expiration.
    pub min_expiration: Option<AbsoluteTime>,
    /// The bounded slice stopped before reaching its desired target.
    pub more: bool,
}
/// Insertion/update and any required quota reclamation form one backend commit.
#[derive(Clone, Copy, Debug)]
pub struct PutPolicy {
    /// Hard logical capacity available after live reservations are charged.
    pub ceiling_bytes: u64,
    /// Desired target after restoring the quota/8 cache; bounded work may stop
    /// above target but must never commit above the hard ceiling.
    pub target_bytes: u64,
    /// Public source time, independent of local monotonic request deadlines.
    pub now: AbsoluteTime,
    /// Finite eviction work before refusing without partial mutation.
    pub max_evictions: usize,
    /// Caller-supplied random bits, available before any backend mutation.
    pub random: u64,
}
/// Actual successful PUT metadata. The service maps inserted and merged to STATUS1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PutReport {
    /// True for a new identity, false for merging an existing key/value.
    pub inserted: bool,
    /// Reclamation committed atomically with this PUT.
    pub maintenance: Maintenance,
}
/// Full semantic backend port. Every method returning BeforeCommit must preserve
/// the complete logical state; Unknown must retain/fence its original candidate.
pub trait Backend {
    /// Original caller-owned error, including native cause and commit stage.
    type Error: BackendError;
    /// Latest authoritative logical usage; no IO or guessed filesystem page count.
    fn usage(&self) -> Usage;
    /// Merge key+exact value while retaining original UID/type/anonymity, or
    /// insert a stable new UID. Saturate priority/replication, max expiration.
    /// Quota eviction is one atomic commit; insufficient bounded work refuses
    /// before commit. All retained values must fit the official IPC payload limit.
    fn put(&mut self, value: Put<'_>, policy: PutPolicy) -> Result<PutReport, Self::Error>;
    /// Select at most one actual value. For replication, reading/verifying the
    /// bytes precedes the atomic score decrement; failure returns no fake record.
    fn select(
        &mut self,
        selection: Selection<'_>,
        random: u64,
    ) -> Result<Option<Record<'_>>, Self::Error>;
    /// Remove the exact key/value, ignoring type; false means no matching identity.
    fn remove(&mut self, key: &[u8; 64], value: &[u8]) -> Result<bool, Self::Error>;
    /// Explicit bounded expiry/space maintenance. No implicit socket/task runs it.
    fn maintain(&mut self, policy: MaintenancePolicy) -> Result<Maintenance, Self::Error>;
    /// Physically/logically clear the complete dataset on service shutdown after DROP.
    fn drop_all(&mut self) -> Result<(), Self::Error>;
}
