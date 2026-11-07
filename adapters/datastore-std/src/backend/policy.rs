//! Bounded metadata-only reclamation planning over amortized heap indexes.
//!
//! A plan never changes logical rows. Every popped key which still describes
//! either an actual or the projected row is restored on every Result exit. In
//! particular an actual row shadowed by an uncommitted candidate is not lost.
//! Only keys matching neither view are permanently stale and may be discarded.
use super::{Error, Stored};
use gnunet_datastore::backend::{ENTRY_OVERHEAD, Maintenance, MaintenancePolicy, Usage};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::AbsoluteTime;
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashSet},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ExpiryKey {
    expiry: u64,
    uid: u64,
}
impl ExpiryKey {
    fn of(row: Stored) -> Self {
        Self {
            expiry: row.meta.expiration.as_micros(),
            uid: row.meta.uid,
        }
    }
    fn matches(self, row: Stored) -> bool {
        self == Self::of(row)
    }
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PriorityKey {
    priority: u32,
    expiry: u64,
    uid: u64,
}
impl PriorityKey {
    fn of(row: Stored) -> Self {
        Self {
            priority: row.meta.priority,
            expiry: row.meta.expiration.as_micros(),
            uid: row.meta.uid,
        }
    }
    fn matches(self, row: Stored) -> bool {
        self == Self::of(row)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Keys {
    expiry: ExpiryKey,
    priority: PriorityKey,
}
impl Keys {
    fn of(row: Stored) -> Self {
        Self {
            expiry: ExpiryKey::of(row),
            priority: PriorityKey::of(row),
        }
    }
}
enum Held {
    Expiry(Reverse<ExpiryKey>),
    Priority(Reverse<PriorityKey>),
}

/// The rows must remain sorted by ascending, unique, nonzero UID. New/deleted
/// rows and changed keys are published only by the enclosing committed store.
pub(super) struct Heaps {
    expiry: BinaryHeap<Reverse<ExpiryKey>>,
    priority: BinaryHeap<Reverse<PriorityKey>>,
    max_records: usize,
    prepared: Option<Keys>,
}
impl Heaps {
    /// Build linear-time initial indexes; no payload collection is retained.
    pub(super) fn new(rows: &[Stored]) -> Result<Self, Error> {
        let mut expiry = Vec::new();
        let mut priority = Vec::new();
        reserve(&mut expiry, rows.len(), "heap-initial-expiry")?;
        reserve(&mut priority, rows.len(), "heap-initial-priority")?;
        let mut previous = 0;
        for row in rows {
            if row.meta.uid <= previous {
                return Err(protocol("heap-initial-uids", ProtocolError::InvalidInput));
            }
            previous = row.meta.uid;
            expiry.push(Reverse(ExpiryKey::of(*row)));
            priority.push(Reverse(PriorityKey::of(*row)));
        }
        Ok(Self {
            expiry: BinaryHeap::from(expiry),
            priority: BinaryHeap::from(priority),
            max_records: usize::MAX,
            prepared: None,
        })
    }

    /// Prepare indexes before irreversible value/WAL I/O. Stale growth triggers
    /// a linear rebuild only after either heap exceeds approximately 2*live+1024.
    /// Consecutive preparation of the same uncommitted candidate adds no keys.
    /// Heap/vector capacities are an internal cache, not logical store mutation.
    pub(super) fn prepare(
        &mut self,
        rows: &[Stored],
        candidate: Option<Stored>,
        max_records: usize,
    ) -> Result<(), Error> {
        if candidate.is_some_and(|row| row.meta.uid == 0) {
            return Err(protocol("heap-candidate-uid", ProtocolError::InvalidInput));
        }
        let threshold = rows.len().saturating_mul(2).saturating_add(1024);
        if self.expiry.len() > threshold || self.priority.len() > threshold {
            let fresh = Self::new(rows)?;
            self.expiry = fresh.expiry;
            self.priority = fresh.priority;
            self.prepared = None;
        }
        let proposed = candidate.map(Keys::of);
        if proposed != self.prepared {
            if let Some(row) = candidate {
                let actual = actual(rows, row.meta.uid);
                let expiry = ExpiryKey::of(row);
                let priority = PriorityKey::of(row);
                let add_expiry = actual.is_none_or(|old| !expiry.matches(old));
                let add_priority = actual.is_none_or(|old| !priority.matches(old));
                if add_expiry {
                    self.expiry
                        .try_reserve(1)
                        .map_err(|_| protocol("heap-prepare-expiry", ProtocolError::Capacity))?;
                }
                if add_priority {
                    self.priority
                        .try_reserve(1)
                        .map_err(|_| protocol("heap-prepare-priority", ProtocolError::Capacity))?;
                }
                // Both fallible reservations precede either projected key.
                if add_expiry {
                    self.expiry.push(Reverse(expiry));
                }
                if add_priority {
                    self.priority.push(Reverse(priority));
                }
            }
            self.prepared = proposed;
        }
        self.max_records = max_records;
        Ok(())
    }

    /// Plan ordered deletions against the actual rows plus candidate overlay.
    /// `usage` is the projected usage AFTER applying that overlay and BEFORE
    /// deleting anything. prepare() must have seen this candidate first.
    ///
    /// The sum of popped expiry and priority keys is at most max_evictions,
    /// including duplicates, shadowed actual keys and genuinely stale keys.
    /// Each popped key causes at most one UID binary search. No table scan/sort
    /// occurs here. Failure to reach either hard ceiling returns Capacity without
    /// logical mutation; a bounded result above the soft target reports more.
    pub(super) fn plan(
        &mut self,
        rows: &[Stored],
        candidate: Option<Stored>,
        usage: Usage,
        policy: MaintenancePolicy,
    ) -> Result<(Vec<u64>, Maintenance), Error> {
        if candidate.map(Keys::of) != self.prepared {
            return Err(protocol(
                "heap-unprepared-candidate",
                ProtocolError::NotReady,
            ));
        }
        if policy.target_bytes > policy.ceiling_bytes {
            return Err(protocol("heap-policy-target", ProtocolError::InvalidInput));
        }
        let charged = usage
            .charged()
            .map_err(|cause| protocol("heap-usage", cause))?;
        let available = self
            .expiry
            .len()
            .checked_add(self.priority.len())
            .ok_or_else(|| protocol("heap-work-size", ProtocolError::Overflow))?;
        let work = policy.max_evictions.min(available);
        let entries = usize::try_from(usage.entries).unwrap_or(usize::MAX);
        let selected_capacity = work.min(entries);
        let mut selected = Vec::new();
        let mut held = Vec::new();
        let mut selected_set = HashSet::new();
        reserve(&mut selected, selected_capacity, "heap-selection")?;
        reserve(&mut held, work, "heap-restore")?;
        selected_set
            .try_reserve(selected_capacity)
            .map_err(|_| protocol("heap-selection-set", ProtocolError::Capacity))?;

        // All fallible scratch reservations precede the first pop. Restoration
        // cannot allocate: each held entry occupies a slot freed by that pop.
        let result = (|| {
            let mut budget = policy.max_evictions;
            let mut remaining = charged;
            let mut remaining_entries = usage.entries;
            let mut report = Maintenance::default();
            let now = policy.now.as_micros();
            while budget != 0 && self.expiry.peek().is_some_and(|key| key.0.expiry <= now) {
                let Some(key) = self.expiry.pop() else {
                    break;
                };
                budget -= 1;
                let (current, projected) = views(rows, candidate, key.0.uid);
                let live = current.is_some_and(|row| key.0.matches(row));
                let projected_match = projected.is_some_and(|row| key.0.matches(row));
                if live || projected_match {
                    held.push(Held::Expiry(key));
                }
                if projected_match {
                    let row = projected
                        .ok_or_else(|| protocol("heap-expiry-view", ProtocolError::Conflict))?;
                    select(
                        row,
                        &mut selected,
                        &mut selected_set,
                        &mut remaining,
                        &mut remaining_entries,
                        &mut report,
                        policy.now,
                    )?;
                }
            }
            let max_records = u64::try_from(self.max_records).unwrap_or(u64::MAX);
            while budget != 0
                && (remaining > policy.target_bytes || remaining_entries > max_records)
            {
                let Some(key) = self.priority.pop() else {
                    break;
                };
                budget -= 1;
                let (current, projected) = views(rows, candidate, key.0.uid);
                let live = current.is_some_and(|row| key.0.matches(row));
                let projected_match = projected.is_some_and(|row| key.0.matches(row));
                if live || projected_match {
                    held.push(Held::Priority(key));
                }
                if projected_match {
                    let row = projected
                        .ok_or_else(|| protocol("heap-priority-view", ProtocolError::Conflict))?;
                    select(
                        row,
                        &mut selected,
                        &mut selected_set,
                        &mut remaining,
                        &mut remaining_entries,
                        &mut report,
                        policy.now,
                    )?;
                }
            }
            if remaining > policy.ceiling_bytes || remaining_entries > max_records {
                return Err(protocol("heap-hard-ceiling", ProtocolError::Capacity));
            }
            // Check before restoration, since selected rows have not yet been
            // committed away and their valid expired keys must still be restored.
            report.more = remaining > policy.target_bytes
                || self.expiry.peek().is_some_and(|key| key.0.expiry <= now);
            Ok(report)
        })();
        for key in held {
            match key {
                Held::Expiry(key) => self.expiry.push(key),
                Held::Priority(key) => self.priority.push(key),
            }
        }
        result.map(|report| (selected, report))
    }
}

fn actual(rows: &[Stored], uid: u64) -> Option<Stored> {
    rows.binary_search_by_key(&uid, |row| row.meta.uid)
        .ok()
        .map(|index| rows[index])
}
fn views(rows: &[Stored], candidate: Option<Stored>, uid: u64) -> (Option<Stored>, Option<Stored>) {
    let current = actual(rows, uid);
    let projected = match candidate {
        Some(row) if row.meta.uid == uid => Some(row),
        _ => current,
    };
    (current, projected)
}
fn select(
    row: Stored,
    selected: &mut Vec<u64>,
    set: &mut HashSet<u64>,
    remaining: &mut u64,
    entries: &mut u64,
    report: &mut Maintenance,
    now: AbsoluteTime,
) -> Result<(), Error> {
    if set.contains(&row.meta.uid) {
        return Ok(());
    }
    let charge = row
        .len
        .checked_add(ENTRY_OVERHEAD)
        .ok_or_else(|| protocol("heap-row-charge", ProtocolError::Overflow))?;
    let next_remaining = remaining
        .checked_sub(charge)
        .ok_or_else(|| protocol("heap-usage-bytes", ProtocolError::Conflict))?;
    let next_entries = entries
        .checked_sub(1)
        .ok_or_else(|| protocol("heap-usage-entries", ProtocolError::Conflict))?;
    let removed_entries = report
        .removed_entries
        .checked_add(1)
        .ok_or_else(|| protocol("heap-removed-entries", ProtocolError::Overflow))?;
    let removed_bytes = report
        .removed_bytes
        .checked_add(charge)
        .ok_or_else(|| protocol("heap-removed-bytes", ProtocolError::Overflow))?;
    // All output collections were reserved for at most the number of popped
    // keys; this successful distinct selection consumes exactly one such slot.
    if !set.insert(row.meta.uid) {
        return Err(protocol("heap-selection-identity", ProtocolError::Conflict));
    }
    selected.push(row.meta.uid);
    *remaining = next_remaining;
    *entries = next_entries;
    report.removed_entries = removed_entries;
    report.removed_bytes = removed_bytes;
    report.min_expiration = Some(if row.meta.expiration <= now {
        now
    } else if row.meta.priority > 0 {
        AbsoluteTime::NEVER
    } else {
        row.meta.expiration
    });
    Ok(())
}
fn reserve<T>(values: &mut Vec<T>, additional: usize, stage: &'static str) -> Result<(), Error> {
    values
        .try_reserve_exact(additional)
        .map_err(|_| protocol(stage, ProtocolError::Capacity))
}
fn protocol(stage: &'static str, cause: ProtocolError) -> Error {
    Error::protocol(stage, cause)
}
