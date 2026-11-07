//! Pure business state. The native owner supplies original-MQ FIFO ordering,
//! subscription cursors, bounded outputs, physical close, and actual persistence.
use crate::{Code, SecretKey, SecretKeyView, names};
use alloc::{rc::Rc, vec::Vec};
use core::{cell::Cell, fmt, mem};
use gnunet_types::Error;

/// Largest name fitting an official UPDATE with a serialized private key.
pub const MAX_NAME_BYTES: usize = 65535 - 12 - 36 - 1;
/// Explicit process limits. Held historical snapshots share one aggregate budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum committed/staged ego count.
    pub egos: usize,
    /// Maximum normalized name bytes, at most MAX_NAME_BYTES.
    pub name_bytes: usize,
    /// Aggregate accounted storage of all retained immutable snapshots.
    pub snapshot_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            egos: 256,
            name_bytes: 1024,
            snapshot_bytes: 4 * 1024 * 1024,
        }
    }
}
/// One stored ego. Its private bytes are zeroized by their owner on drop.
#[derive(Debug)]
pub struct Ego {
    name: Vec<u8>,
    key: SecretKey,
}
impl Ego {
    /// Construct an ego with a raw UTF-8 name. Core::new additionally requires
    /// the name already be canonical lowercase NFD, and rejects duplicates.
    pub fn new(name: Vec<u8>, key: SecretKey) -> Result<Self, Error> {
        if name.len() > MAX_NAME_BYTES || name.contains(&0) || core::str::from_utf8(&name).is_err()
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self { name, key })
    }
    /// Current UTF-8 name, excluding NUL.
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// Opaque private-key owner; exposure is explicit on that owner.
    pub const fn key(&self) -> &SecretKey {
        &self.key
    }
}
struct Budget {
    used: Cell<usize>,
    limit: usize,
}
struct SnapshotData {
    rows: Vec<Ego>,
    revision: u64,
    cost: usize,
    budget: Rc<Budget>,
}
impl Drop for SnapshotData {
    fn drop(&mut self) {
        self.budget
            .used
            .set(self.budget.used.get().saturating_sub(self.cost));
    }
}
/// Immutable inventory. Clone retains a reference; it never copies private keys.
#[derive(Clone)]
pub struct Snapshot(Rc<SnapshotData>);
impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshot")
            .field("revision", &self.revision())
            .field("egos", &self.egos().len())
            .finish()
    }
}
impl Snapshot {
    /// Borrow rows in the official enumeration order (newest creations first).
    pub fn egos(&self) -> &[Ego] {
        &self.0.rows
    }
    /// Process-local committed inventory revision, independent of disk generation.
    pub fn revision(&self) -> u64 {
        self.0.revision
    }
}
fn snapshot(rows: Vec<Ego>, revision: u64, budget: &Rc<Budget>) -> Result<Snapshot, Error> {
    let mut cost = mem::size_of::<SnapshotData>()
        .checked_add(2 * mem::size_of::<usize>())
        .and_then(|n| {
            rows.capacity()
                .checked_mul(mem::size_of::<Ego>())
                .and_then(|r| n.checked_add(r))
        })
        .ok_or(Error::Overflow)?;
    for row in &rows {
        cost = cost
            .checked_add(row.name.capacity())
            .ok_or(Error::Overflow)?;
    }
    let used = budget.used.get().checked_add(cost).ok_or(Error::Overflow)?;
    if used > budget.limit {
        return Err(Error::Capacity);
    }
    let value = Snapshot(Rc::new(SnapshotData {
        rows,
        revision,
        cost,
        budget: Rc::clone(budget),
    }));
    budget.used.set(used);
    Ok(value)
}
fn copy_name(name: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(name.len())
        .map_err(|_| Error::Capacity)?;
    out.extend_from_slice(name);
    Ok(out)
}
fn copy_ego(ego: &Ego, name: Option<&[u8]>) -> Result<Ego, Error> {
    Ok(Ego {
        name: copy_name(name.unwrap_or(ego.name()))?,
        key: ego.key.try_clone_secret(),
    })
}
/// Requested mutation. A returned Prepared transaction has no external effect
/// until the provider actually admits and durably commits its staged snapshot.
#[derive(Clone, Copy, Debug)]
pub enum Mutation<'a> {
    /// Create/import one key and normalize its supplied name.
    Create {
        /// Requested name before normalization.
        name: &'a [u8],
        /// Structurally validated supplied private key.
        key: SecretKeyView<'a>,
    },
    /// Normalize both names, then rename the old ego.
    Rename {
        /// Existing name before normalization.
        old: &'a [u8],
        /// New name before normalization.
        new: &'a [u8],
    },
    /// Normalize the name, then remove the ego.
    Delete {
        /// Existing name before normalization.
        name: &'a [u8],
    },
}
/// Immutable process-domain transaction token. It is never a wire request ID or
/// a secret-derived identifier and cannot be forged outside this module.
#[derive(Clone)]
pub struct Transaction {
    domain: Rc<()>,
    serial: u64,
}
impl fmt::Debug for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transaction")
            .field("serial", &self.serial)
            .finish_non_exhaustive()
    }
}
impl PartialEq for Transaction {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &other.domain) && self.serial == other.serial
    }
}
impl Eq for Transaction {}
/// Result of pure mutation preparation.
#[derive(Debug)]
pub enum Decision {
    /// Actual business rejection, with no staged or persisted change.
    Immediate(Code),
    /// Fully prepared immutable after-image and its original transaction token.
    Prepared(Transaction),
}
/// Inventory change kind. CREATE replies before UPDATE; RENAME/DELETE update
/// before their success reply. The native owner preserves that original-MQ order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChangeKind {
    /// New ego at index zero of the after snapshot.
    Create,
    /// Existing ego renamed in place.
    Rename,
    /// Ego removed from the after snapshot.
    Delete,
}
struct Staged {
    transaction: Transaction,
    before: Snapshot,
    after: Snapshot,
    kind: ChangeKind,
    before_index: Option<usize>,
    after_index: Option<usize>,
    queued: bool,
}
/// Borrowed staged after-image and exact affected rows. The backend receives a
/// zeroizing serialization, never this Rc inventory or another secret cache.
pub struct StageView<'a> {
    /// Original transaction token.
    pub transaction: &'a Transaction,
    /// Still committed state, available to existing subscribers.
    pub before: &'a Snapshot,
    /// Proposed complete durable state.
    pub after: &'a Snapshot,
    /// The mutation being staged.
    pub kind: ChangeKind,
    /// Affected old row, absent for create.
    pub before_index: Option<usize>,
    /// Affected new row, absent for delete.
    pub after_index: Option<usize>,
    /// Whether the provider reported actual admission to its original worker.
    pub queued: bool,
}
/// A completed durable inventory change. Cloned snapshots share their owners.
#[derive(Clone, Debug)]
pub struct Change {
    /// Inventory before the actual commit.
    pub before: Snapshot,
    /// Inventory after the actual commit.
    pub after: Snapshot,
    /// Committed mutation kind.
    pub kind: ChangeKind,
    /// Affected old row, absent for create.
    pub before_index: Option<usize>,
    /// Affected new row, absent for delete.
    pub after_index: Option<usize>,
}
/// One bounded canonical inventory and at most one globally staged mutation.
/// No socket, filesystem, clock, executor, observer queue, or private-key hash.
pub struct Core {
    limits: Limits,
    current: Snapshot,
    pending: Option<Staged>,
    domain: Rc<()>,
    next: u64,
    unknown: bool,
}
impl Core {
    /// Load a validated durable inventory. Names must already be canonical and
    /// unique; its process revision starts at zero independently of disk epochs.
    pub fn new(limits: Limits, egos: Vec<Ego>) -> Result<Self, Error> {
        if limits.name_bytes > MAX_NAME_BYTES || egos.len() > limits.egos {
            return Err(Error::InvalidInput);
        }
        for row in &egos {
            if names::normalize(row.name(), limits.name_bytes)?.as_slice() != row.name() {
                return Err(Error::InvalidInput);
            }
        }
        let mut names = Vec::new();
        names
            .try_reserve_exact(egos.len())
            .map_err(|_| Error::Capacity)?;
        names.extend(egos.iter().map(Ego::name));
        names.sort_unstable();
        if names.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error::Conflict);
        }
        drop(names);
        let budget = Rc::new(Budget {
            used: Cell::new(0),
            limit: limits.snapshot_bytes,
        });
        let current = snapshot(egos, 0, &budget)?;
        Ok(Self {
            limits,
            current,
            pending: None,
            domain: Rc::new(()),
            next: 1,
            unknown: false,
        })
    }
    /// Retain an immutable snapshot for a bounded initialization/output cursor.
    /// After OutcomeUnknown the native owner must close clients and stop serving
    /// this inventory until actual durable recovery creates a new Core instance.
    pub fn snapshot(&self) -> Snapshot {
        self.current.clone()
    }
    /// Inspect the sole prepared mutation without copying any secret or name.
    pub fn staged(&self) -> Option<StageView<'_>> {
        self.pending.as_ref().map(|s| StageView {
            transaction: &s.transaction,
            before: &s.before,
            after: &s.after,
            kind: s.kind,
            before_index: s.before_index,
            after_index: s.after_index,
            queued: s.queued,
        })
    }
    fn live(&self) -> Result<(), Error> {
        if self.unknown {
            Err(Error::OutcomeUnknown)
        } else {
            Ok(())
        }
    }
    fn checked(&self, transaction: &Transaction) -> Result<&Staged, Error> {
        self.live()?;
        self.pending
            .as_ref()
            .filter(|s| s.transaction == *transaction)
            .ok_or(Error::Stale)
    }
    /// Exact lookup follows the service's bytewise ASCII-insensitive C-locale
    /// strcasecmp. Suffix lookup is case sensitive, longest, and dot-boundary
    /// aware. Lookup requests are not normalized by the official service.
    pub fn lookup(&self, name: &[u8], suffix: bool) -> Result<Option<usize>, Error> {
        self.live()?;
        if name.len() > 65530 || name.contains(&0) {
            return Err(Error::InvalidInput);
        }
        if !suffix {
            return Ok(self
                .current
                .egos()
                .iter()
                .position(|e| e.name().eq_ignore_ascii_case(name)));
        }
        let mut found = None;
        let mut longest = None;
        for (index, ego) in self.current.egos().iter().enumerate() {
            let length = ego.name().len();
            if length <= name.len()
                && name.ends_with(ego.name())
                && (length == name.len() || name[name.len() - length - 1] == b'.')
                && longest.is_none_or(|n| length > n)
            {
                found = Some(index);
                longest = Some(length);
            }
        }
        Ok(found)
    }
    /// Normalize a mutation and prepare its complete after-image. Capacity or
    /// an existing transaction is backpressure, never a fabricated success.
    pub fn begin(&mut self, mutation: Mutation<'_>) -> Result<Decision, Error> {
        self.live()?;
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let normalize = |name: &[u8]| names::normalize(name, self.limits.name_bytes);
        let operation = (|| -> Result<_, Error> {
            match mutation {
                Mutation::Create { name, key } => {
                    Ok((ChangeKind::Create, normalize(name)?, None, Some(key)))
                }
                Mutation::Rename { old, new } => Ok((
                    ChangeKind::Rename,
                    normalize(new)?,
                    Some(normalize(old)?),
                    None,
                )),
                Mutation::Delete { name } => Ok((ChangeKind::Delete, normalize(name)?, None, None)),
            }
        })();
        let (kind, name, old, key) = match operation {
            Ok(v) => v,
            Err(Error::InvalidInput | Error::TooLarge) => {
                return Ok(Decision::Immediate(Code::INVALID));
            }
            Err(e) => return Err(e),
        };
        let existing = self
            .current
            .egos()
            .iter()
            .position(|e| e.name() == name.as_slice());
        if kind != ChangeKind::Delete && existing.is_some() {
            return Ok(Decision::Immediate(Code::NAME_CONFLICT));
        }
        let index = match kind {
            ChangeKind::Create => None,
            ChangeKind::Rename => self
                .current
                .egos()
                .iter()
                .position(|e| Some(e.name()) == old.as_deref()),
            ChangeKind::Delete => existing,
        };
        if kind != ChangeKind::Create && index.is_none() {
            return Ok(Decision::Immediate(Code::NOT_FOUND));
        }
        let size = match kind {
            ChangeKind::Create => self
                .current
                .egos()
                .len()
                .checked_add(1)
                .ok_or(Error::Overflow)?,
            ChangeKind::Rename => self.current.egos().len(),
            ChangeKind::Delete => self
                .current
                .egos()
                .len()
                .checked_sub(1)
                .ok_or(Error::Stale)?,
        };
        if size > self.limits.egos {
            return Err(Error::Capacity);
        }
        let revision = self
            .current
            .revision()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let next = self.next.checked_add(1).ok_or(Error::Overflow)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
        if let Some(key) = key {
            rows.push(Ego {
                name: copy_name(&name)?,
                key: SecretKey::from_serialized(key.expose_serialized())?,
            });
        }
        for (i, row) in self.current.egos().iter().enumerate() {
            if kind == ChangeKind::Delete && index == Some(i) {
                continue;
            }
            rows.push(copy_ego(
                row,
                if kind == ChangeKind::Rename && index == Some(i) {
                    Some(&name)
                } else {
                    None
                },
            )?);
        }
        let after = snapshot(rows, revision, &self.current.0.budget)?;
        let transaction = Transaction {
            domain: Rc::clone(&self.domain),
            serial: self.next,
        };
        self.pending = Some(Staged {
            transaction: transaction.clone(),
            before: self.current.clone(),
            after,
            kind,
            before_index: index,
            after_index: if kind == ChangeKind::Create {
                Some(0)
            } else if kind == ChangeKind::Rename {
                index
            } else {
                None
            },
            queued: false,
        });
        self.next = next;
        Ok(Decision::Prepared(transaction))
    }
    /// Record actual worker admission. Calling this is not a persistence receipt.
    pub fn queued(&mut self, transaction: &Transaction) -> Result<(), Error> {
        if self.checked(transaction)?.queued {
            return Err(Error::Replay);
        }
        if let Some(s) = self.pending.as_mut() {
            s.queued = true;
        }
        Ok(())
    }
    /// Consume the original provider's actual durable completion, then publish
    /// the prepared state. This swaps preallocated state and allocates nothing.
    pub fn commit(&mut self, transaction: &Transaction) -> Result<Change, Error> {
        if !self.checked(transaction)?.queued {
            return Err(Error::NotReady);
        }
        let s = self.pending.take().ok_or(Error::Stale)?;
        self.current = s.after.clone();
        Ok(Change {
            before: s.before,
            after: s.after,
            kind: s.kind,
            before_index: s.before_index,
            after_index: s.after_index,
        })
    }
    /// Settle an actual known pre-publication failure. The backend must prove
    /// that replacement did not happen; a transport timeout alone cannot do so.
    pub fn abort(&mut self, transaction: &Transaction, code: Code) -> Result<Code, Error> {
        self.checked(transaction)?;
        if code == Code::NONE {
            return Err(Error::InvalidInput);
        }
        self.pending.take().ok_or(Error::Stale)?;
        Ok(code)
    }
    /// Latch an indeterminate admitted storage outcome. The native owner must
    /// physically close all peers and recover durable state in a new instance;
    /// no old transaction replay or guessed rollback is permitted.
    pub fn unknown(&mut self, transaction: &Transaction) -> Result<(), Error> {
        if !self.checked(transaction)?.queued {
            return Err(Error::NotReady);
        }
        self.unknown = true;
        self.pending.take().ok_or(Error::Stale)?;
        Ok(())
    }
}
