//! Bounded immutable authority inventory and original provider transactions.
use crate::{
    Filter, MAX_LABEL_BYTES, MAX_RECORDS, RecordData, RecordFlags, RecordType, SecretKey,
    SecretKeyView, ZoneKey, append_nickname, normalize_label, normalize_records, prepare_store,
};
#[cfg(target_has_atomic = "ptr")]
use alloc::sync::Arc;
use alloc::{rc::Rc, vec::Vec};
use core::{alloc::Layout, cell::Cell, fmt, mem};
use gnunet_types::Error;
use gnunet_wire::official::namestore::{RecordSets, Records};
use zeroize::Zeroizing;
/// Actual service code, retaining extension numeric codes without success guesses.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Code(u32);
impl Code {
    /// The requested pure no-op or original provider commit completed.
    pub const NONE: Self = Self(0);
    /// Actual backend failure without a more specific cause.
    pub const UNKNOWN: Self = Self(5000);
    /// No matching delegation was found.
    pub const ZONE_NOT_FOUND: Self = Self(5002);
    /// Empty deletion found no actual records (a tombstone is not an ordinary record).
    pub const RECORD_NOT_FOUND: Self = Self(5003);
    /// Inconsistent/malformed authoritative data.
    pub const RECORD_DATA_INVALID: Self = Self(5008);
    /// Advisory begin found no existing label.
    pub const NO_RESULTS: Self = Self(5010);
    /// A complete actual response cannot fit declared limits.
    pub const RECORD_TOO_BIG: Self = Self(5012);
    /// Actual backend refused an operation.
    pub const BACKEND_FAILED: Self = Self(5013);
    /// Actual authoritative store failed.
    pub const STORE_FAILED: Self = Self(5014);
    /// Invalid NFC label.
    pub const LABEL_INVALID: Self = Self(5015);
    /// Preserve an actual extension code.
    #[must_use]
    pub const fn new(n: u32) -> Self {
        Self(n)
    }
    /// Original numeric code.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }
}
/// Explicit allocated-core resources. Historical snapshots and owned query
/// payloads share retained_bytes; no key hash or ambient cache is introduced.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum current authority labels, across all zones.
    pub rows: usize,
    /// Maximum distinct zones in a committed inventory.
    pub zones: usize,
    /// Maximum canonical label bytes, at most255.
    pub label_bytes: usize,
    /// Maximum raw decomposed label input before allocating NFC scratch.
    pub label_input_bytes: usize,
    /// Maximum advisory hint bytes, excluding NUL.
    pub hint_bytes: usize,
    /// Maximum records retained per set, leaving one possible tombstone slot.
    pub records_per_set: usize,
    /// Maximum serialized bytes in one stored set/reply, at most65535.
    pub record_bytes: usize,
    /// Maximum whole label replacements in one atomic/non-atomic frame.
    pub batch: usize,
    /// Maximum accounted current after-image bytes (including opaque owners).
    pub image_bytes: usize,
    /// Shared aggregate current/staged/history/query/change memory ceiling.
    pub retained_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            rows: 1024,
            zones: 256,
            label_bytes: 255,
            label_input_bytes: 1024,
            hint_bytes: 4096,
            records_per_set: 256,
            record_bytes: 65535,
            batch: 256,
            image_bytes: 4 * 1024 * 1024,
            retained_bytes: 16 * 1024 * 1024,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.rows == 0
            || self.zones == 0
            || self.zones > self.rows
            || self.label_bytes > MAX_LABEL_BYTES
            || self.label_input_bytes < self.label_bytes
            || self.label_input_bytes > 65530
            || self.hint_bytes > 65534
            || self.records_per_set == 0
            || self.records_per_set >= MAX_RECORDS
            || self.record_bytes > 65535
            || self.batch == 0
            || self.batch > 4095
            || self.image_bytes == 0
            || self.retained_bytes < self.image_bytes
        {
            return Err(Error::InvalidInput);
        }
        self.rows
            .checked_mul(mem::size_of::<Row>())
            .ok_or(Error::Overflow)?;
        Ok(())
    }
}
/// Shared opaque private authority owner. Clone retains a reference and never
/// copies secret bytes; matching is fixed-length constant-time comparison.
#[derive(Clone)]
pub struct Zone(Rc<SecretKey>);
impl Zone {
    /// Transfer explicit caller-owned private material into one zeroizing owner.
    #[must_use]
    pub fn new(key: SecretKey) -> Self {
        Self(Rc::new(key))
    }
    /// Explicit sensitive borrow for actual IPC/persistence; never an identifier.
    #[must_use]
    pub fn secret(&self) -> &SecretKey {
        &self.0
    }
    /// Borrow the exact structural private serialization.
    pub fn view(&self) -> Result<SecretKeyView<'_>, Error> {
        self.0.view()
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0) || self.0.constant_time_eq(&other.0)
    }
}
impl fmt::Debug for Zone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Zone([REDACTED])")
    }
}
// Payload allocations are immutable. Their last internal reference owns erasure;
// copying an image can therefore share bytes without making secret Clone/Hash
// APIs public or retaining an uncharged reference outside an image/query lease.
// Preserve OwnedRecords' host Send/Sync auto traits. On atomics-free targets
// the already single-threaded alloc core remains usable with non-atomic Rc.
#[cfg(target_has_atomic = "ptr")]
type SharedRecords = Arc<Zeroizing<Vec<u8>>>;
#[cfg(not(target_has_atomic = "ptr"))]
type SharedRecords = Rc<Zeroizing<Vec<u8>>>;
type SharedBytes = Rc<Zeroizing<Vec<u8>>>;
type SharedLabel = Rc<Vec<u8>>;

/// Erased owned record serialization. Debug reports size/count only. Immutable
/// payload sharing is private; no ordinary Clone/Hash implementation is exposed.
pub struct OwnedRecords {
    bytes: SharedRecords,
    count: u16,
}
impl OwnedRecords {
    /// Copy an explicitly supplied validated record view into erased bounded storage.
    pub fn copy(records: Records<'_>, maximum: usize) -> Result<Self, Error> {
        if records.bytes().len() > maximum {
            return Err(Error::Capacity);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(records.bytes().len())
            .map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(records.bytes());
        Ok(Self {
            bytes: SharedRecords::new(bytes),
            count: records.count(),
        })
    }
    /// Build the canonical shared GNS serialization of borrowed actual records.
    pub fn serialize(records: &[RecordData<'_>], maximum: usize) -> Result<Self, Error> {
        let count = u16::try_from(records.len()).map_err(|_| Error::Capacity)?;
        let n = gnunet_gnsrecord::serialized_len(records)?;
        if n > maximum {
            return Err(Error::Capacity);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
        bytes.resize(n, 0);
        gnunet_gnsrecord::serialize(records, &mut bytes)?;
        Ok(Self {
            bytes: SharedRecords::new(bytes),
            count,
        })
    }
    /// Checked explicit sensitive borrowed wire view.
    pub fn view(&self) -> Result<Records<'_>, Error> {
        Records::new(&self.bytes, self.count)
    }
    /// Count retained without exposing payloads.
    #[must_use]
    pub const fn count(&self) -> u16 {
        self.count
    }
    fn shared(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            count: self.count,
        }
    }
    fn storage_cost(&self) -> Result<usize, Error> {
        rc_cost::<Zeroizing<Vec<u8>>>()?
            .checked_add(self.bytes.capacity())
            .ok_or(Error::Overflow)
    }
}
impl fmt::Debug for OwnedRecords {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedRecords")
            .field("count", &self.count)
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
/// One durable authority row. Labels/hints are never used as filesystem paths.
pub struct Row {
    pub(crate) zone: Zone,
    pub(crate) label: SharedLabel,
    pub(crate) records: OwnedRecords,
    pub(crate) hint: Option<SharedBytes>,
    pub(crate) serial: u64,
}
impl Row {
    /// Construct recovery input. Core::new additionally validates canonical NFC,
    /// uniqueness, serials, record limits and deduplicates equal opaque zones.
    pub fn new(
        zone: Zone,
        label: Vec<u8>,
        records: OwnedRecords,
        hint: Option<Zeroizing<Vec<u8>>>,
        serial: u64,
    ) -> Result<Self, Error> {
        if serial == 0 || label.contains(&0) || hint.as_ref().is_some_and(|h| h.contains(&0)) {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            zone,
            label: Rc::new(label),
            records,
            hint: hint.map(Rc::new),
            serial,
        })
    }
    /// Explicit opaque original authority.
    #[must_use]
    pub const fn zone(&self) -> &Zone {
        &self.zone
    }
    /// Stored canonical case-preserving NFC label.
    #[must_use]
    pub fn label(&self) -> &[u8] {
        &self.label
    }
    /// Stored sensitive record bytes.
    #[must_use]
    pub const fn records(&self) -> &OwnedRecords {
        &self.records
    }
    /// Actual advisory hint without NUL; absent differs from nonempty hint.
    #[must_use]
    pub fn hint(&self) -> Option<&[u8]> {
        self.hint.as_ref().map(|h| h.as_slice())
    }
    /// Actual monotonically allocated database-row serial.
    #[must_use]
    pub const fn serial(&self) -> u64 {
        self.serial
    }
    fn shared(&self) -> Self {
        Self {
            zone: self.zone.clone(),
            label: self.label.clone(),
            records: self.records.shared(),
            hint: self.hint.clone(),
            serial: self.serial,
        }
    }
    fn cost(&self) -> Result<usize, Error> {
        // Deliberately charge the full logical image, even when another image
        // shares an allocation. This keeps each independently retained image
        // sufficient after every other reference/lease has been released.
        retained_cost([
            mem::size_of::<Self>(),
            rc_cost::<SecretKey>()?,
            label_cost(&self.label)?,
            self.records.storage_cost()?,
            hint_cost(self.hint.as_ref())?,
        ])
    }
}
impl fmt::Debug for Row {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Row")
            .field("serial", &self.serial)
            .field("label_bytes", &self.label.len())
            .field("records", &self.records)
            .field("hint_bytes", &self.hint.as_ref().map(|h| h.len()))
            .finish_non_exhaustive()
    }
}
pub(crate) struct Budget {
    pub(crate) live: Cell<bool>,
    used: Cell<usize>,
    maximum: usize,
}
pub(crate) struct Lease {
    budget: Rc<Budget>,
    bytes: usize,
}
impl Budget {
    fn reserve(self: &Rc<Self>, bytes: usize) -> Result<Lease, Error> {
        let n = self.used.get().checked_add(bytes).ok_or(Error::Overflow)?;
        if n > self.maximum {
            return Err(Error::Capacity);
        }
        self.used.set(n);
        Ok(Lease {
            budget: self.clone(),
            bytes,
        })
    }
}
impl Lease {
    fn shrink(&mut self, bytes: usize) -> Result<(), Error> {
        if bytes > self.bytes {
            return Err(Error::Capacity);
        }
        self.budget.used.set(
            self.budget
                .used
                .get()
                .checked_sub(self.bytes - bytes)
                .ok_or(Error::Conflict)?,
        );
        self.bytes = bytes;
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.budget
            .used
            .set(self.budget.used.get().saturating_sub(self.bytes));
    }
}
struct SnapshotData {
    rows: Vec<Row>,
    revision: u64,
    _lease: Lease,
}
/// Immutable original authority image; Clone never copies a secret or payload.
#[derive(Clone)]
pub struct Snapshot(Rc<SnapshotData>);
impl Snapshot {
    /// Explicit stored rows, only from this immutable retained image.
    #[must_use]
    pub fn rows(&self) -> &[Row] {
        &self.0.rows
    }
    /// Process revision, independent of the actual persistence generation.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.0.revision
    }
    pub(crate) fn domain(&self) -> Rc<Budget> {
        self.0._lease.budget.clone()
    }
    pub(crate) fn same_source(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0._lease.budget, &other.0._lease.budget)
    }
    pub(crate) fn row(&self, serial: u64) -> Option<&Row> {
        self.rows().iter().find(|r| r.serial == serial)
    }
}
impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("revision", &self.revision())
            .field("rows", &self.rows().len())
            .finish_non_exhaustive()
    }
}
fn retained_cost<const N: usize>(parts: [usize; N]) -> Result<usize, Error> {
    parts.into_iter().try_fold(0usize, |total, bytes| {
        total.checked_add(bytes).ok_or(Error::Overflow)
    })
}
// Rc and Arc both have a strong and weak pointer-width counter before their
// allocation value. Include the value header and alignment/tail padding; each
// owner below separately adds Vec's actual retained element capacity.
fn rc_cost<T>() -> Result<usize, Error> {
    let (layout, _) = Layout::new::<[usize; 2]>()
        .extend(Layout::new::<T>())
        .map_err(|_| Error::Overflow)?;
    Ok(layout.pad_to_align().size())
}
fn label_cost(label: &SharedLabel) -> Result<usize, Error> {
    rc_cost::<Vec<u8>>()?
        .checked_add(label.capacity())
        .ok_or(Error::Overflow)
}
fn hint_cost(hint: Option<&SharedBytes>) -> Result<usize, Error> {
    hint.map_or(Ok(0), |h| {
        rc_cost::<Zeroizing<Vec<u8>>>()?
            .checked_add(h.capacity())
            .ok_or(Error::Overflow)
    })
}
fn image_cost(rows: &[Row], capacity: usize) -> Result<usize, Error> {
    let mut cost = mem::size_of::<SnapshotData>()
        .checked_add(2 * mem::size_of::<usize>())
        .and_then(|n| {
            capacity
                .checked_mul(mem::size_of::<Row>())
                .and_then(|x| n.checked_add(x))
        })
        .ok_or(Error::Overflow)?;
    for r in rows {
        cost = cost
            .checked_add(
                r.cost()?
                    .checked_sub(mem::size_of::<Row>())
                    .ok_or(Error::Conflict)?,
            )
            .ok_or(Error::Overflow)?;
    }
    Ok(cost)
}
fn snapshot(
    rows: Vec<Row>,
    revision: u64,
    mut lease: Lease,
    maximum: usize,
) -> Result<Snapshot, Error> {
    let cost = image_cost(&rows, rows.capacity())?;
    if cost > maximum {
        return Err(Error::Capacity);
    }
    lease.shrink(cost)?;
    Ok(Snapshot(Rc::new(SnapshotData {
        rows,
        revision,
        _lease: lease,
    })))
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Capacity)?;
    v.extend_from_slice(bytes);
    Ok(v)
}
fn scratch<T: Clone>(n: usize, value: T) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    v.resize(n, value);
    Ok(v)
}
fn blank() -> RecordData<'static> {
    RecordData {
        expiration_time: 0,
        record_type: RecordType::new(0),
        flags: RecordFlags::from_bits_preserve(0),
        data: &[],
    }
}
fn label(bytes: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    if bytes.len() > limits.label_input_bytes {
        return Err(Error::TooLarge);
    }
    let n = bytes.len().checked_mul(4).ok_or(Error::Overflow)?;
    let mut input = scratch(bytes.len(), 0u32)?;
    let mut normalized = scratch(n, 0u32)?;
    let mut ordering = scratch(n, 0u32)?;
    let mut output = scratch(limits.label_bytes, 0u8)?;
    let n = normalize_label(
        bytes,
        &mut output,
        &mut input,
        &mut normalized,
        &mut ordering,
        limits.label_bytes,
    )?;
    output.truncate(n);
    Ok(output)
}
fn record_table(records: &OwnedRecords, maximum: usize) -> Result<Vec<RecordData<'_>>, Error> {
    let view = records.view()?;
    let set = view.records();
    if set.len() > maximum {
        return Err(Error::Capacity);
    }
    let mut rd = Vec::new();
    rd.try_reserve_exact(set.len())
        .map_err(|_| Error::Capacity)?;
    for r in set.iter() {
        rd.push(r?);
    }
    Ok(rd)
}
/// Owned actual query data. It has no key/record Clone/Hash/Serialize or secret
/// Debug. Its lease counts retained bytes until the caller drops the reply.
pub struct Query {
    zone: Zone,
    label: SharedLabel,
    records: OwnedRecords,
    hint: Option<SharedBytes>,
    found: bool,
    expires: u64,
    _lease: Lease,
}
impl Query {
    /// Explicit opaque authority on this original query.
    #[must_use]
    pub const fn zone(&self) -> &Zone {
        &self.zone
    }
    /// Actual canonical returned label.
    #[must_use]
    pub fn label(&self) -> &[u8] {
        &self.label
    }
    /// Checked sensitive serialized records.
    pub fn records(&self) -> Result<Records<'_>, Error> {
        self.records.view()
    }
    /// Actual row existence, even when all record payloads were filtered out.
    #[must_use]
    pub const fn found(&self) -> bool {
        self.found
    }
    /// Actual filtered record-set expiry including its live tombstone floor.
    #[must_use]
    pub const fn expires(&self) -> u64 {
        self.expires
    }
    /// Actual previous advisory hint, excluding NUL.
    #[must_use]
    pub fn hint(&self) -> Option<&[u8]> {
        self.hint.as_ref().map(|h| h.as_slice())
    }
}
impl fmt::Debug for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Query")
            .field("found", &self.found)
            .field("records", &self.records)
            .field("expires", &self.expires)
            .finish_non_exhaustive()
    }
}
/// A business reply, available from an actual provider commit or a defined
/// read/no-op. No local frame write is interpreted as this result.
#[derive(Debug)]
pub enum Reply {
    /// Numeric Store/conditional-hint result.
    Generic {
        /// Actual code.
        code: Code,
    },
    /// Advisory begin's previous record/hint view.
    Edit {
        /// Actual code, encoded16-bit by the wire owner.
        code: Code,
        /// Actual original data before the hint replacement.
        query: Query,
    },
}
impl Reply {
    /// Numeric diagnostic only; no secret material.
    #[must_use]
    pub const fn code(&self) -> Code {
        match self {
            Self::Generic { code } | Self::Edit { code, .. } => *code,
        }
    }
}
struct Domain {
    _private: u8,
}
/// Original staged provider transaction, not a wire RID or reusable generation.
#[derive(Clone)]
pub struct Transaction {
    domain: Rc<Domain>,
    serial: u64,
}
impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &other.domain) && self.serial == other.serial
    }
}
impl Eq for Transaction {}
impl fmt::Debug for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NamestoreTransaction")
            .field(&self.serial)
            .finish()
    }
}
/// Actual authority mutation family. Hint changes do not generate record events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    /// Batch replacement/deletion.
    Store,
    /// Advisory hint begin.
    EditBegin,
    /// Conditional advisory hint replacement.
    EditCancel,
}
pub(crate) struct Delta {
    zone: Zone,
    label: Vec<u8>,
    before: Option<u64>,
    after: Option<u64>,
}
struct ChangeData {
    before: Snapshot,
    after: Snapshot,
    kind: ChangeKind,
    deltas: Vec<Delta>,
    _lease: Lease,
}
/// Committed record change shared with bounded monitor owners. Clone retains
/// immutable state; it never duplicates secrets or record payloads.
#[derive(Clone)]
pub struct Change(Rc<ChangeData>);
impl Change {
    /// Original image before this actual commit.
    #[must_use]
    pub fn before(&self) -> &Snapshot {
        &self.0.before
    }
    /// Original image after this actual commit.
    #[must_use]
    pub fn after(&self) -> &Snapshot {
        &self.0.after
    }
    /// Actual mutation family.
    #[must_use]
    pub fn kind(&self) -> ChangeKind {
        self.0.kind
    }
    /// Actual complete changed-label count; a batch coalesces repeated labels.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.deltas.len()
    }
    /// No record payload changed (e.g. hint-only mutation).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.deltas.is_empty()
    }
    /// Borrow original before/after rows by changed-label position.
    pub fn changed(&self, index: usize) -> Result<Changed<'_>, Error> {
        let d = self.0.deltas.get(index).ok_or(Error::InvalidInput)?;
        Ok(Changed {
            zone: &d.zone,
            label: &d.label,
            before: d.before.and_then(|s| self.0.before.row(s)),
            after: d.after.and_then(|s| self.0.after.row(s)),
        })
    }
}
impl fmt::Debug for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Change")
            .field("revision", &self.after().revision())
            .field("kind", &self.kind())
            .field("labels", &self.len())
            .finish_non_exhaustive()
    }
}
/// Borrow one actual changed label; deletion retains its original zone/label.
pub struct Changed<'a> {
    /// Original opaque authority.
    pub zone: &'a Zone,
    /// Original canonical label.
    pub label: &'a [u8],
    /// Row before the actual commit.
    pub before: Option<&'a Row>,
    /// Row after the actual commit; None is physical deletion.
    pub after: Option<&'a Row>,
}
struct Staged {
    transaction: Transaction,
    change: Change,
    reply: Reply,
    next_record: u64,
    queued: bool,
}
pub(crate) struct ReadPolicy {
    pub filter: Filter,
    pub now: u64,
    pub nickname: bool,
}
/// Original provider plan. The caller must actually admit the after-image,
/// then call queued, and supply its real commit/known-abort/unknown outcome.
pub struct StageView<'a> {
    /// Original non-forgeable transaction.
    pub transaction: &'a Transaction,
    /// Original current image.
    pub before: &'a Snapshot,
    /// Fully prepared immutable after-image.
    pub after: &'a Snapshot,
    /// Mutation kind.
    pub kind: ChangeKind,
    /// Actual original worker admission recorded.
    pub queued: bool,
}
/// No provider effect, or one complete immutable provider plan.
#[derive(Debug)]
pub enum Decision {
    /// Actual validation/no-op/read result.
    Immediate(Reply),
    /// Fully prepared transaction, not yet provider-admitted.
    Prepared(Transaction),
}
/// Only an actual original queued provider outcome authorizes commit(). This
/// value contains its prepared reply and immutable changes, with no new copies.
#[derive(Debug)]
pub struct Committed {
    /// Actual original business reply.
    pub reply: Reply,
    /// Immutable committed changes for original monitors.
    pub change: Change,
}
/// Bounded authoritative inventory. It contains no CLIENT/clock/task/IO or
/// default/identity/namecache policy. Explicit Unknown permanently stops reads
/// and mutations until an external actual recovery constructs a new Core.
pub struct Core {
    pub(crate) limits: Limits,
    pub(crate) current: Snapshot,
    budget: Rc<Budget>,
    critical: fn(RecordType) -> bool,
    domain: Rc<Domain>,
    next_tx: u64,
    next_record: u64,
    pending: Option<Staged>,
    unknown: bool,
}
impl Core {
    /// Recover actual caller-owned persisted rows. The registry predicate must
    /// describe the caller's actual record semantics; no plugin/RNG is loaded.
    pub fn new(
        limits: Limits,
        mut rows: Vec<Row>,
        critical: fn(RecordType) -> bool,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if rows.len() > limits.rows {
            return Err(Error::Capacity);
        }
        rows.sort_unstable_by_key(|r| r.serial);
        let mut zones = 0;
        for i in 0..rows.len() {
            let row = &rows[i];
            if row.label.len() > limits.label_bytes
                || label(&row.label, limits)?.as_slice() != row.label.as_slice()
                || usize::from(row.records.count) > limits.records_per_set
                || row.records.bytes.len() > limits.record_bytes
                || row
                    .hint
                    .as_ref()
                    .is_some_and(|h| h.len() > limits.hint_bytes)
            {
                return Err(Error::InvalidInput);
            }
            // Store preparation has already removed expired values. Recovery
            // validates the complete retained local set at time zero, without
            // inventing a new recovery clock or discarding data under a rollback.
            let raw = record_table(&row.records, limits.records_per_set)?;
            let mut checked = scratch(raw.len(), blank())?;
            let mut indices = scratch(raw.len(), 0usize)?;
            normalize_records(
                &row.label,
                &raw,
                0,
                Filter::INCLUDE_MAINTENANCE,
                &mut checked,
                &mut indices,
                critical,
            )?;
            if i > 0 && rows[i - 1].serial == row.serial {
                return Err(Error::Conflict);
            }
            let same = rows[..i].iter().position(|r| r.zone.same(&row.zone));
            if let Some(j) = same {
                if rows[..i]
                    .iter()
                    .any(|r| r.zone.same(&row.zone) && r.label == row.label)
                {
                    return Err(Error::Conflict);
                }
                rows[i].zone = rows[j].zone.clone();
            } else {
                zones += 1;
            }
        }
        if zones > limits.zones {
            return Err(Error::Capacity);
        }
        let next_record = rows
            .last()
            .map_or(Ok(1), |r| r.serial.checked_add(1).ok_or(Error::Overflow))?;
        let budget = Rc::new(Budget {
            live: Cell::new(true),
            used: Cell::new(0),
            maximum: limits.retained_bytes,
        });
        let lease = budget.reserve(limits.image_bytes)?;
        let current = snapshot(rows, 0, lease, limits.image_bytes)?;
        Ok(Self {
            limits,
            current,
            budget,
            critical,
            domain: Rc::new(Domain { _private: 0 }),
            next_tx: 1,
            next_record,
            pending: None,
            unknown: false,
        })
    }
    pub(crate) fn stream_lease(&self, bytes: usize) -> Result<Lease, Error> {
        self.live()?;
        self.budget.reserve(bytes)
    }
    pub(crate) fn source(&self, snapshot: &Snapshot) -> Result<(), Error> {
        self.live()?;
        if !snapshot.same_source(&self.current) {
            return Err(Error::StaleGeneration);
        }
        Ok(())
    }
    pub(crate) fn source_domain(&self, domain: &Rc<Budget>) -> Result<(), Error> {
        self.live()?;
        if !Rc::ptr_eq(domain, &self.budget) {
            return Err(Error::StaleGeneration);
        }
        Ok(())
    }
    fn live(&self) -> Result<(), Error> {
        if self.unknown {
            Err(Error::OutcomeUnknown)
        } else {
            Ok(())
        }
    }
    /// Retain the actual committed image. New reads stop after Unknown.
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        self.live()?;
        Ok(self.current.clone())
    }
    /// Current original immutable provider plan, with no prepared success reply.
    #[must_use]
    pub fn staged(&self) -> Option<StageView<'_>> {
        self.pending.as_ref().map(|s| StageView {
            transaction: &s.transaction,
            before: s.change.before(),
            after: s.change.after(),
            kind: s.change.kind(),
            queued: s.queued,
        })
    }
    pub(crate) fn zone(&self, key: SecretKeyView<'_>) -> Result<Zone, Error> {
        let key = SecretKey::from_serialized(key.expose_serialized())?;
        if let Some(row) = self
            .current
            .rows()
            .iter()
            .find(|r| r.zone.secret().constant_time_eq(&key))
        {
            Ok(row.zone.clone())
        } else {
            Ok(Zone::new(key))
        }
    }
    fn shared_rows(&self) -> Result<Vec<Row>, Error> {
        let mut rows = Vec::new();
        rows.try_reserve_exact(self.current.rows().len())
            .map_err(|_| Error::Capacity)?;
        for r in self.current.rows() {
            rows.push(r.shared());
        }
        Ok(rows)
    }
    fn plan(
        &mut self,
        rows: Vec<Row>,
        deltas: Vec<Delta>,
        kind: ChangeKind,
        reply: Reply,
        next_record: u64,
        leases: (Lease, Lease),
    ) -> Result<Decision, Error> {
        let (image, meta) = leases;
        let revision = self
            .current
            .revision()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let next_tx = self.next_tx.checked_add(1).ok_or(Error::Overflow)?;
        let after = snapshot(rows, revision, image, self.limits.image_bytes)?;
        let change = Change(Rc::new(ChangeData {
            before: self.current.clone(),
            after,
            kind,
            deltas,
            _lease: meta,
        }));
        let transaction = Transaction {
            domain: self.domain.clone(),
            serial: self.next_tx,
        };
        self.pending = Some(Staged {
            transaction: transaction.clone(),
            change,
            reply,
            next_record,
            queued: false,
        });
        self.next_tx = next_tx;
        Ok(Decision::Prepared(transaction))
    }
    fn reservation(&self, changed: usize) -> Result<(Lease, Lease), Error> {
        let image = self.budget.reserve(self.limits.image_bytes)?;
        let metadata = changed
            .checked_mul(mem::size_of::<Delta>() + self.limits.label_bytes)
            .and_then(|n| n.checked_add(mem::size_of::<ChangeData>() + 2 * mem::size_of::<usize>()))
            .ok_or(Error::Overflow)?;
        let meta = self.budget.reserve(metadata)?;
        Ok((image, meta))
    }
    fn begin(&self) -> Result<(), Error> {
        self.live()?;
        if self.pending.is_some() {
            Err(Error::WouldBlock)
        } else {
            Ok(())
        }
    }
    /// Normalize/read one actual label with the explicit source time/filter.
    /// A found row may legitimately return zero visible payloads.
    pub fn lookup(
        &self,
        key: SecretKeyView<'_>,
        name: &[u8],
        filter: Filter,
        now: u64,
    ) -> Result<Query, Error> {
        self.live()?;
        let name = label(name, self.limits)?;
        let zone = self.zone(key)?;
        let row = self
            .current
            .rows()
            .iter()
            .find(|r| r.zone.same(&zone) && r.label.as_slice() == name.as_slice());
        self.query(
            &self.current,
            zone,
            &name,
            row,
            ReadPolicy {
                filter,
                now,
                nickname: true,
            },
        )
    }
    /// Find the first actual typed delegation record in this private authority.
    /// No signing, public-key derivation or secret-derived hash is performed.
    pub fn zone_to_name(
        &self,
        key: SecretKeyView<'_>,
        target: ZoneKey,
    ) -> Result<Option<Query>, Error> {
        self.live()?;
        let zone = self.zone(key)?;
        for row in self.current.rows() {
            if !row.zone.same(&zone) {
                continue;
            }
            for record in row.records.view()?.records().iter() {
                if ZoneKey::from_record(&record?).is_ok_and(|p| p == target) {
                    return self.raw_query(row).map(Some);
                }
            }
        }
        Ok(None)
    }
    fn query_lease(
        &self,
        label: &SharedLabel,
        records: &OwnedRecords,
        hint: Option<&SharedBytes>,
    ) -> Result<Lease, Error> {
        let cost = retained_cost([
            mem::size_of::<Query>(),
            rc_cost::<SecretKey>()?,
            label_cost(label)?,
            records.storage_cost()?,
            hint_cost(hint)?,
        ])?;
        self.budget.reserve(cost)
    }
    fn raw_query(&self, row: &Row) -> Result<Query, Error> {
        let lease = self.query_lease(&row.label, &row.records, row.hint.as_ref())?;
        Ok(Query {
            zone: row.zone.clone(),
            label: row.label.clone(),
            records: row.records.shared(),
            hint: row.hint.clone(),
            found: true,
            expires: 0,
            _lease: lease,
        })
    }
    pub(crate) fn query(
        &self,
        snapshot: &Snapshot,
        zone: Zone,
        name: &[u8],
        row: Option<&Row>,
        policy: ReadPolicy,
    ) -> Result<Query, Error> {
        let ReadPolicy {
            filter,
            now,
            nickname,
        } = policy;
        self.source(snapshot)?;
        let (found, records, hint, expires) = if let Some(row) = row {
            let rd = record_table(&row.records, self.limits.records_per_set)?;
            let mut normalized = scratch(rd.len(), blank())?;
            let mut indices = scratch(rd.len(), 0usize)?;
            let selected = normalize_records(
                name,
                &rd,
                now,
                filter,
                &mut normalized,
                &mut indices,
                self.critical,
            )?;
            let expires = selected.expires();
            let nick = if nickname && name != crate::APEX {
                snapshot
                    .rows()
                    .iter()
                    .find(|r| r.zone.same(&zone) && r.label.as_slice() == crate::APEX)
                    .map(|r| r.records.view())
                    .transpose()?
                    .map(|v| v.records())
                    .and_then(|s| {
                        s.iter().find_map(|r| match r {
                            Ok(r) if r.record_type == RecordType::NICK => Some(Ok(r)),
                            Ok(_) => None,
                            Err(e) => Some(Err(e)),
                        })
                    })
                    .transpose()?
            } else {
                None
            };
            let mut merged = scratch(selected.records().len() + 1, blank())?;
            let selected = append_nickname(name, selected.records(), nick, now, &mut merged)?;
            let serialized = OwnedRecords::serialize(selected, self.limits.record_bytes)?;
            (true, serialized, row.hint.clone(), expires)
        } else {
            (
                false,
                OwnedRecords::copy(Records::empty()?, self.limits.record_bytes)?,
                None,
                0,
            )
        };
        let label = Rc::new(copy(name)?);
        let lease = self.query_lease(&label, &records, hint.as_ref())?;
        Ok(Query {
            zone,
            label,
            records,
            hint,
            found,
            expires,
            _lease: lease,
        })
    }
    /// Prepare one complete Store frame. single_tx=true is atomic. For false,
    /// a validation failure can commit the already valid prefix and return its
    /// actual error code; notifications describe every committed final label.
    /// Capacity/overflow failures leave business state completely unchanged.
    pub fn store(
        &mut self,
        key: SecretKeyView<'_>,
        sets: RecordSets<'_>,
        single_tx: bool,
        now: u64,
    ) -> Result<Decision, Error> {
        self.begin()?;
        if usize::from(sets.count()) > self.limits.batch {
            return Err(Error::Capacity);
        }
        if sets.count() == 0 {
            return Ok(Decision::Immediate(Reply::Generic { code: Code::NONE }));
        }
        let zone = self.zone(key)?;
        let (image, meta) = self.reservation(usize::from(sets.count()))?;
        let mut rows = self.shared_rows()?;
        let mut deltas: Vec<Delta> = Vec::new();
        deltas
            .try_reserve_exact(usize::from(sets.count()))
            .map_err(|_| Error::Capacity)?;
        let mut next = self.next_record;
        let mut code = Code::NONE;
        for set in sets.iter() {
            let set = set?;
            let name = match label(set.label.bytes(), self.limits) {
                Ok(n) => n,
                Err(Error::InvalidInput | Error::TooLarge) => {
                    code = Code::LABEL_INVALID;
                    break;
                }
                Err(e) => return Err(e),
            };
            let at = rows
                .iter()
                .position(|r| r.zone.same(&zone) && r.label.as_slice() == name.as_slice());
            if set.records.count() == 0
                && at.is_none_or(|i| {
                    rows[i].records.view().is_ok_and(|v| {
                        v.records()
                            .iter()
                            .all(|r| r.is_ok_and(|r| r.record_type == RecordType::TOMBSTONE))
                    })
                })
            {
                code = Code::RECORD_NOT_FOUND;
                break;
            }
            let previous = if let Some(i) = at {
                self.query(
                    &self.current,
                    zone.clone(),
                    &name,
                    Some(&rows[i]),
                    ReadPolicy {
                        filter: Filter::OMIT_PRIVATE,
                        now,
                        nickname: false,
                    },
                )?
                .expires()
            } else {
                0
            };
            let data = set.records.records();
            if data.len() > self.limits.records_per_set {
                return Err(Error::Capacity);
            }
            let mut input = Vec::new();
            input
                .try_reserve_exact(data.len())
                .map_err(|_| Error::Capacity)?;
            for r in data.iter() {
                input.push(r?);
            }
            let mut output = scratch(input.len() + 1, blank())?;
            let mut indices = scratch(input.len(), 0usize)?;
            let prepared = match prepare_store(
                &name,
                &input,
                previous,
                now,
                &mut output,
                &mut indices,
                self.critical,
            ) {
                Ok(r) => r,
                Err(Error::InvalidInput) => {
                    code = Code::RECORD_DATA_INVALID;
                    break;
                }
                Err(e) => return Err(e),
            };
            let replacement = if prepared.records().is_empty() {
                None
            } else {
                if prepared.records().len() > self.limits.records_per_set {
                    return Err(Error::Capacity);
                }
                let serial = next;
                next = next.checked_add(1).ok_or(Error::Overflow)?;
                Some(Row {
                    zone: zone.clone(),
                    label: Rc::new(copy(&name)?),
                    records: OwnedRecords::serialize(prepared.records(), self.limits.record_bytes)?,
                    hint: None,
                    serial,
                })
            };
            let after = replacement.as_ref().map(|r| r.serial);
            let existing_delta = deltas
                .iter()
                .position(|d| d.zone.same(&zone) && d.label == name);
            if let Some(i) = existing_delta {
                deltas[i].after = after;
            } else {
                let before = self
                    .current
                    .rows()
                    .iter()
                    .find(|r| r.zone.same(&zone) && r.label.as_slice() == name.as_slice())
                    .map(|r| r.serial);
                deltas.push(Delta {
                    zone: zone.clone(),
                    label: copy(&name)?,
                    before,
                    after,
                });
            }
            match (at, replacement) {
                (Some(i), Some(row)) => rows[i] = row,
                (Some(i), None) => {
                    drop(rows.remove(i));
                }
                (None, Some(row)) => {
                    if rows.len() >= self.limits.rows {
                        return Err(Error::Capacity);
                    }
                    rows.try_reserve(1).map_err(|_| Error::Capacity)?;
                    rows.push(row);
                }
                (None, None) => {}
            }
        }
        if code != Code::NONE && (single_tx || deltas.is_empty()) {
            return Ok(Decision::Immediate(Reply::Generic { code }));
        }
        deltas.retain(|d| d.before.is_some() || d.after.is_some());
        let mut zones = 0;
        for (i, row) in rows.iter().enumerate() {
            if !rows[..i].iter().any(|r| r.zone.same(&row.zone)) {
                zones += 1;
            }
        }
        if zones > self.limits.zones {
            return Err(Error::Capacity);
        }
        rows.sort_unstable_by_key(|r| r.serial);
        self.plan(
            rows,
            deltas,
            ChangeKind::Store,
            Reply::Generic { code },
            next,
            (image, meta),
        )
    }
    /// Prepare actual advisory begin on an existing label. Missing rows return
    /// NO_RESULTS without fabricating a stored lock. Prior record data is frozen
    /// before replacement and becomes available only after actual commit.
    pub fn edit_begin(
        &mut self,
        key: SecretKeyView<'_>,
        name: &[u8],
        hint: &[u8],
        now: u64,
    ) -> Result<Decision, Error> {
        self.begin()?;
        self.check_hint(hint)?;
        let name = label(name, self.limits)?;
        let zone = self.zone(key)?;
        let index = self
            .current
            .rows()
            .iter()
            .position(|r| r.zone.same(&zone) && r.label.as_slice() == name.as_slice());
        let mut query = self.query(
            &self.current,
            zone,
            &name,
            index.map(|i| &self.current.rows()[i]),
            ReadPolicy {
                filter: Filter::NONE,
                now,
                nickname: true,
            },
        )?;
        let Some(i) = index else {
            return Ok(Decision::Immediate(Reply::Edit {
                code: Code::NO_RESULTS,
                query,
            }));
        };
        if query.hint() == Some(hint) || hint.is_empty() && query.hint.is_none() {
            query.hint = None;
            return Ok(Decision::Immediate(Reply::Edit {
                code: Code::NONE,
                query,
            }));
        }
        let (image, meta) = self.reservation(0)?;
        let mut rows = self.shared_rows()?;
        rows[i].hint = if hint.is_empty() {
            None
        } else {
            Some(Rc::new(Zeroizing::new(copy(hint)?)))
        };
        self.plan(
            rows,
            Vec::new(),
            ChangeKind::EditBegin,
            Reply::Edit {
                code: Code::NONE,
                query,
            },
            self.next_record,
            (image, meta),
        )
    }
    /// Conditionally replace the matching hint. Missing/mismatching values are
    /// actual no-ops; this is never treated as cancellation of another RPC.
    pub fn edit_cancel(
        &mut self,
        key: SecretKeyView<'_>,
        name: &[u8],
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<Decision, Error> {
        self.begin()?;
        self.check_hint(expected)?;
        self.check_hint(replacement)?;
        let name = label(name, self.limits)?;
        let zone = self.zone(key)?;
        let Some(i) = self
            .current
            .rows()
            .iter()
            .position(|r| r.zone.same(&zone) && r.label.as_slice() == name.as_slice())
        else {
            return Ok(Decision::Immediate(Reply::Generic { code: Code::NONE }));
        };
        if self.current.rows()[i].hint().unwrap_or(&[]) != expected || expected == replacement {
            return Ok(Decision::Immediate(Reply::Generic { code: Code::NONE }));
        }
        let (image, meta) = self.reservation(0)?;
        let mut rows = self.shared_rows()?;
        rows[i].hint = if replacement.is_empty() {
            None
        } else {
            Some(Rc::new(Zeroizing::new(copy(replacement)?)))
        };
        self.plan(
            rows,
            Vec::new(),
            ChangeKind::EditCancel,
            Reply::Generic { code: Code::NONE },
            self.next_record,
            (image, meta),
        )
    }
    fn check_hint(&self, h: &[u8]) -> Result<(), Error> {
        if h.len() > self.limits.hint_bytes {
            return Err(Error::TooLarge);
        }
        if h.contains(&0) {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
    fn checked(&self, t: &Transaction) -> Result<&Staged, Error> {
        self.live()?;
        self.pending
            .as_ref()
            .filter(|s| s.transaction == *t)
            .ok_or(Error::Stale)
    }
    /// Record actual original provider admission, never success or durability.
    pub fn queued(&mut self, t: &Transaction) -> Result<(), Error> {
        if self.checked(t)?.queued {
            return Err(Error::Replay);
        }
        if let Some(s) = self.pending.as_mut() {
            s.queued = true;
        }
        Ok(())
    }
    /// Consume the original provider's actual durable commit. Only preallocated
    /// state is moved; original monitor changes and reply remain immutable.
    pub fn commit(&mut self, t: &Transaction) -> Result<Committed, Error> {
        if !self.checked(t)?.queued {
            return Err(Error::NotReady);
        }
        let s = self.pending.take().ok_or(Error::Stale)?;
        self.current = s.change.after().clone();
        self.next_record = s.next_record;
        Ok(Committed {
            reply: s.reply,
            change: s.change,
        })
    }
    /// Settle a proven original prepublication failure. A timeout is insufficient
    /// proof; never pass NONE or use this as guessed rollback after exposure.
    pub fn abort(&mut self, t: &Transaction, code: Code) -> Result<Code, Error> {
        self.checked(t)?;
        if code == Code::NONE {
            return Err(Error::InvalidInput);
        }
        drop(self.pending.take());
        Ok(code)
    }
    /// Latch an actual admitted indeterminate provider outcome. Native owners
    /// must independently stop MQs and explicitly recover persisted state.
    pub fn unknown(&mut self, t: &Transaction) -> Result<(), Error> {
        if !self.checked(t)?.queued {
            return Err(Error::NotReady);
        }
        self.unknown = true;
        self.budget.live.set(false);
        drop(self.pending.take());
        Ok(())
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        self.budget.live.set(false);
    }
}
