//! Fixed slot/index/work metadata; borrowed reads allocate nothing. Quota victims
//! are selected in one bounded sorted batch, not repeatedly scanning/removing
//! payloads. All fallible admission work precedes actual eviction or replacement.
use crate::{
    ANY, AbsoluteTime, Block, Cache, Evicted, EvictionReason, Key, Limits, PathElement, PutKind,
    PutOutcome, Stats, Storage,
};
use alloc::vec::Vec;
use core::{cmp::Ordering, iter::FusedIterator, mem};
use gnunet_types::Error;
struct Slot {
    live: bool,
    key: Key,
    expiration: AbsoluteTime,
    truncation_peer: [u8; 32],
    kind: u32,
    options: u32,
    distance: u32,
    serial: u64,
    data: Vec<u8>,
    path: Vec<PathElement>,
}
impl Slot {
    fn empty() -> Self {
        Self {
            live: false,
            key: [0; 64],
            expiration: AbsoluteTime::UNIX_EPOCH,
            truncation_peer: [0; 32],
            kind: 0,
            options: 0,
            distance: 0,
            serial: 0,
            data: Vec::new(),
            path: Vec::new(),
        }
    }
    fn block(&self) -> Block<'_> {
        Block {
            key: self.key,
            expiration: self.expiration,
            truncation_peer: self.truncation_peer,
            put_path: &self.path,
            data: &self.data,
            block_type: self.kind,
            route_options: self.options,
        }
    }
    fn cost(&self) -> usize {
        self.data.capacity() + self.path.capacity() * mem::size_of::<PathElement>()
    }
}
fn compare(a: &Slot, b: &Slot) -> Ordering {
    a.key
        .cmp(&b.key)
        .then_with(|| b.expiration.cmp(&a.expiration))
        .then_with(|| a.serial.cmp(&b.serial))
}
fn priority(slot: &Slot, now: AbsoluteTime) -> (u8, u32, AbsoluteTime, u64) {
    if slot.expiration < now {
        (0, 0, slot.expiration, slot.serial)
    } else {
        (1, slot.distance, slot.expiration, slot.serial)
    }
}
fn reserve<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut values = Vec::new();
    values.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(values)
}
fn copy<T: Copy>(values: &[T]) -> Result<Vec<T>, Error> {
    let mut out = reserve(values.len())?;
    out.extend_from_slice(values);
    Ok(out)
}
/// Actual bounded in-memory transient store. Fixed slots and indexes are charged
/// at construction; retained payload and typed path capacities are charged once.
/// No bloom filter/file, plugin, clock, executor, native IO or crypto operation.
pub struct Memory {
    limits: Limits,
    slots: Vec<Slot>,
    by_key: Vec<usize>,
    free: Vec<usize>,
    work: Vec<usize>,
    stats: Stats,
    next: u64,
}
impl Memory {
    /// Reserve all metadata and eviction workspace before use. The configured
    /// quota must hold those actual capacities, including every path/data owner.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        let estimate = limits
            .entries
            .checked_mul(mem::size_of::<Slot>() + 3 * mem::size_of::<usize>())
            .ok_or(Error::Overflow)?;
        limits
            .path_elements
            .checked_mul(mem::size_of::<PathElement>())
            .ok_or(Error::Overflow)?;
        if estimate > limits.bytes {
            return Err(Error::InvalidInput);
        }
        let mut slots = reserve(limits.entries)?;
        slots.resize_with(limits.entries, Slot::empty);
        let by_key: Vec<usize> = reserve(limits.entries)?;
        let mut free = reserve(limits.entries)?;
        free.extend((0..limits.entries).rev());
        let work: Vec<usize> = reserve(limits.entries)?;
        let metadata = slots
            .capacity()
            .checked_mul(mem::size_of::<Slot>())
            .and_then(|n| {
                by_key
                    .capacity()
                    .checked_add(free.capacity())
                    .and_then(|v| v.checked_add(work.capacity()))
                    .and_then(|v| v.checked_mul(mem::size_of::<usize>()))
                    .and_then(|v| n.checked_add(v))
            })
            .ok_or(Error::Overflow)?;
        if metadata > limits.bytes {
            return Err(Error::Capacity);
        }
        Ok(Self {
            limits,
            slots,
            by_key,
            free,
            work,
            stats: Stats {
                metadata_bytes: metadata,
                ..Stats::default()
            },
            next: 1,
        })
    }
    fn range(&self, key: Key) -> (usize, usize) {
        let begin = self.by_key.partition_point(|i| self.slots[*i].key < key);
        let end = self.by_key.partition_point(|i| self.slots[*i].key <= key);
        (begin, end)
    }
    fn remove(&mut self, index: usize, now: AbsoluteTime, record: bool) -> Evicted {
        let slot = &mut self.slots[index];
        let released = slot.cost();
        let reason = if slot.expiration < now {
            EvictionReason::Expired
        } else {
            EvictionReason::Quota
        };
        let removed = Evicted {
            key: slot.key,
            block_type: slot.kind,
            released_bytes: released,
            reason,
        };
        self.stats.data_bytes -= slot.data.capacity();
        self.stats.path_bytes -= slot.path.capacity() * mem::size_of::<PathElement>();
        slot.data = Vec::new();
        slot.path = Vec::new();
        slot.live = false;
        self.free.push(index);
        self.stats.entries -= 1;
        if record {
            match reason {
                EvictionReason::Expired => {
                    self.stats.expired = self.stats.expired.saturating_add(1)
                }
                EvictionReason::Quota => self.stats.evicted = self.stats.evicted.saturating_add(1),
            }
        }
        removed
    }
    fn reindex(&mut self) {
        let slots = &self.slots;
        self.by_key.retain(|i| slots[*i].live);
    }
    fn index_insert(&mut self, index: usize) {
        let slot = &self.slots[index];
        let at = self
            .by_key
            .partition_point(|other| compare(&self.slots[*other], slot) == Ordering::Less);
        self.by_key.insert(at, index);
    }
    fn matches(
        &self,
        start: usize,
        total: usize,
        circular: bool,
        kind: u32,
        limit: usize,
        now: AbsoluteTime,
    ) -> Matches<'_> {
        Matches {
            store: self,
            cursor: start,
            scanned: 0,
            total,
            circular,
            kind,
            remaining: limit,
            now,
        }
    }
}
impl Storage for Memory {
    type Matches<'a> = Matches<'a>;
    fn put(
        &mut self,
        xor_distance: u32,
        block: Block<'_>,
        now: AbsoluteTime,
    ) -> Result<PutOutcome, Error> {
        if block.expiration < now {
            return Err(Error::Timeout);
        }
        if block.data.len() > self.limits.value_bytes
            || block.put_path.len() > self.limits.path_elements
        {
            return Err(Error::TooLarge);
        }
        let minimum = block
            .data
            .len()
            .checked_add(
                block
                    .put_path
                    .len()
                    .checked_mul(mem::size_of::<PathElement>())
                    .ok_or(Error::Overflow)?,
            )
            .ok_or(Error::Overflow)?;
        if minimum > self.limits.bytes.saturating_sub(self.stats.metadata_bytes) {
            return Err(Error::TooLarge);
        }
        let (begin, end) = self.range(block.key);
        let duplicate = self.by_key[begin..end].iter().copied().find(|i| {
            let s = &self.slots[*i];
            s.kind == block.block_type && s.data.as_slice() == block.data
        });
        if duplicate.is_some_and(|i| block.expiration < self.slots[i].expiration) {
            // Expiration belongs to the same opaque context as the path and
            // truncation/options. A path for an earlier expiry cannot be paired
            // with the retained later expiry, including purpose-6 signatures.
            self.stats.duplicates = self.stats.duplicates.saturating_add(1);
            return Ok(PutOutcome {
                kind: PutKind::Duplicate,
                evicted: 0,
            });
        }
        let serial = if let Some(i) = duplicate {
            self.slots[i].serial
        } else {
            self.next
        };
        let next = if duplicate.is_none() {
            Some(self.next.checked_add(1).ok_or(Error::Overflow)?)
        } else {
            None
        };
        // Reuse existing exact payload and a sufficient path buffer on duplicate.
        let data = if duplicate.is_none() {
            Some(copy(block.data)?)
        } else {
            None
        };
        let path = if duplicate.is_none_or(|i| self.slots[i].path.capacity() < block.put_path.len())
        {
            Some(copy(block.put_path)?)
        } else {
            None
        };
        let previous = duplicate.map_or(0, |i| self.slots[i].cost());
        let data_capacity = data.as_ref().map_or_else(
            || duplicate.map_or(0, |i| self.slots[i].data.capacity()),
            Vec::capacity,
        );
        let path_capacity = path.as_ref().map_or_else(
            || duplicate.map_or(0, |i| self.slots[i].path.capacity()),
            Vec::capacity,
        );
        let cost = data_capacity
            .checked_add(
                path_capacity
                    .checked_mul(mem::size_of::<PathElement>())
                    .ok_or(Error::Overflow)?,
            )
            .ok_or(Error::Overflow)?;
        if cost > self.limits.bytes.saturating_sub(self.stats.metadata_bytes) {
            return Err(Error::TooLarge);
        }
        let mut after = self
            .stats
            .accounted_bytes()
            .checked_sub(previous)
            .and_then(|n| n.checked_add(cost))
            .ok_or(Error::Overflow)?;
        let need_slot = duplicate.is_none() && self.free.is_empty();
        let mut evicted = 0usize;
        self.work.clear();
        if after > self.limits.bytes || need_slot {
            self.work.extend(
                self.by_key
                    .iter()
                    .copied()
                    .filter(|i| Some(*i) != duplicate),
            );
            // One-victim admission needs one linear scan. Multi-victim quota
            // pressure sorts once instead of repeatedly scanning/removing data.
            let best = self
                .work
                .iter()
                .enumerate()
                .min_by_key(|(_, i)| priority(&self.slots[**i], now))
                .map(|(position, _)| position);
            if let Some(best) = best {
                let reduced = after
                    .checked_sub(self.slots[self.work[best]].cost())
                    .ok_or(Error::Stale)?;
                if reduced <= self.limits.bytes {
                    self.work.swap(0, best);
                    after = reduced;
                    evicted = 1;
                } else {
                    let slots = &self.slots;
                    self.work
                        .sort_unstable_by_key(|i| priority(&slots[*i], now));
                    for i in &self.work {
                        if after <= self.limits.bytes && (!need_slot || evicted != 0) {
                            break;
                        }
                        after = after
                            .checked_sub(self.slots[*i].cost())
                            .ok_or(Error::Stale)?;
                        evicted += 1;
                    }
                }
            }
            if after > self.limits.bytes || need_slot && evicted == 0 {
                self.work.clear();
                return Err(Error::Capacity);
            }
        }
        // Everything below is allocation-free and cannot reject admission.
        for n in 0..evicted {
            let i = self.work[n];
            self.remove(i, now, true);
        }
        if evicted != 0 {
            self.reindex();
        }
        self.work.clear();
        let index = if let Some(i) = duplicate {
            self.by_key.retain(|index| *index != i);
            i
        } else {
            self.free.pop().ok_or(Error::Stale)?
        };
        let slot = &mut self.slots[index];
        if duplicate.is_some() {
            self.stats.path_bytes -= slot.path.capacity() * mem::size_of::<PathElement>();
            if let Some(path) = path {
                slot.path = path;
            } else {
                slot.path.clear();
                slot.path.extend_from_slice(block.put_path);
            }
            self.stats.path_bytes += slot.path.capacity() * mem::size_of::<PathElement>();
            slot.expiration = block.expiration;
            self.stats.duplicates = self.stats.duplicates.saturating_add(1);
        } else {
            slot.data = data.ok_or(Error::Stale)?;
            slot.path = path.ok_or(Error::Stale)?;
            slot.key = block.key;
            slot.expiration = block.expiration;
            slot.kind = block.block_type;
            slot.distance = xor_distance;
            slot.serial = serial;
            slot.live = true;
            self.stats.data_bytes += slot.data.capacity();
            self.stats.path_bytes += slot.path.capacity() * mem::size_of::<PathElement>();
            self.stats.entries += 1;
            self.stats.insertions = self.stats.insertions.saturating_add(1);
            if let Some(next) = next {
                self.next = next;
            }
        }
        // Equal/newer expiry, path, truncation origin and route flags come
        // from one incoming context. An earlier duplicate returned above.
        slot.truncation_peer = block.truncation_peer;
        slot.options = block.route_options;
        self.index_insert(index);
        Ok(PutOutcome {
            kind: if duplicate.is_some() {
                PutKind::Duplicate
            } else {
                PutKind::Inserted
            },
            evicted,
        })
    }
    fn get(&self, key: Key, kind: u32, now: AbsoluteTime) -> Result<Matches<'_>, Error> {
        let (begin, end) = self.range(key);
        Ok(self.matches(begin, end - begin, false, kind, usize::MAX, now))
    }
    fn get_closest(
        &self,
        target: Key,
        kind: u32,
        limit: usize,
        now: AbsoluteTime,
    ) -> Result<Matches<'_>, Error> {
        let begin = self.by_key.partition_point(|i| self.slots[*i].key < target);
        Ok(self.matches(begin, self.by_key.len(), true, kind, limit, now))
    }
    fn expire_before(&mut self, now: AbsoluteTime) -> Result<usize, Error> {
        let mut removed = 0usize;
        for i in 0..self.slots.len() {
            if self.slots[i].live && self.slots[i].expiration < now {
                self.remove(i, now, true);
                removed += 1;
            }
        }
        if removed != 0 {
            self.reindex();
        }
        Ok(removed)
    }
    fn evict_one(&mut self, now: AbsoluteTime) -> Result<Option<Evicted>, Error> {
        let selected = self
            .by_key
            .iter()
            .copied()
            .min_by_key(|i| priority(&self.slots[*i], now));
        Ok(selected.map(|i| {
            let removed = self.remove(i, now, true);
            self.reindex();
            removed
        }))
    }
    fn clear(&mut self) -> Result<usize, Error> {
        let count = self.stats.entries;
        for i in 0..self.slots.len() {
            if self.slots[i].live {
                self.remove(i, AbsoluteTime::UNIX_EPOCH, false);
            }
        }
        self.by_key.clear();
        Ok(count)
    }
    fn stats(&self) -> Stats {
        self.stats
    }
}
/// Borrowed allocation-free result stream. Its one immutable owner borrow
/// prevents mutation while a callback/consumer retains any returned block.
pub struct Matches<'a> {
    store: &'a Memory,
    cursor: usize,
    scanned: usize,
    total: usize,
    circular: bool,
    kind: u32,
    remaining: usize,
    now: AbsoluteTime,
}
impl<'a> Iterator for Matches<'a> {
    type Item = Result<Block<'a>, Error>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.remaining != 0 && self.scanned < self.total {
            let position = if self.circular {
                self.cursor % self.store.by_key.len()
            } else {
                self.cursor
            };
            self.cursor += 1;
            self.scanned += 1;
            let slot = &self.store.slots[self.store.by_key[position]];
            if !slot.live {
                self.remaining = 0;
                return Some(Err(Error::Stale));
            }
            if slot.expiration < self.now || self.kind != ANY && self.kind != slot.kind {
                continue;
            }
            self.remaining -= 1;
            return Some(Ok(slot.block()));
        }
        None
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining.min(self.total - self.scanned)))
    }
}
impl FusedIterator for Matches<'_> {}
impl Cache<Memory> {
    /// Construct the actual alloc-backed local transient cache without native IO.
    pub fn memory(limits: Limits) -> Result<Self, Error> {
        Ok(Self::new(Memory::new(limits)?))
    }
}
