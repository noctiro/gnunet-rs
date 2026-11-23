//! Erasing, caller-owned custody of multiple variable-length originals.

use crate::Error;
use core::{fmt, num::NonZeroU64, num::NonZeroUsize, ops::Range, ptr};
use gnunet_types::Error as Fault;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The identity of one live byte pool. Create a separate instance for each
/// pool. Even after a pool drops, its outstanding handles keep the instance
/// borrowed so the backing can never reopen under the old identity.
#[derive(Debug, Default)]
pub struct OriginalPoolInstance {
    _storage: u8,
}

impl OriginalPoolInstance {
    /// Create an unborrowed identity without allocating or using a global counter.
    pub const fn new() -> Self {
        Self { _storage: 0 }
    }
}

/// Opaque identity for one retained original. A handle does not own the bytes
/// or prevent their removal. All access checks the originating pool and generation.
#[derive(Clone, Copy)]
pub struct OriginalId<'id> {
    owner: &'id OriginalPoolInstance,
    index: Index,
    generation: NonZeroU64,
}

/// Coordinates retained only by the owning Core's reusable metadata cells.
#[derive(Clone, Copy)]
pub(crate) struct LocalOriginal {
    owner: usize,
    index: Index,
    generation: NonZeroU64,
}

impl OriginalId<'_> {
    pub(crate) fn local(self) -> LocalOriginal {
        LocalOriginal {
            owner: ptr::from_ref(self.owner).addr(),
            index: self.index,
            generation: self.generation,
        }
    }
}

impl PartialEq for OriginalId<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.owner, other.owner)
            && self.index == other.index
            && self.generation == other.generation
    }
}

impl Eq for OriginalId<'_> {}

impl fmt::Debug for OriginalId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalId([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct Index(NonZeroUsize);

impl Index {
    fn at(index: usize) -> Self {
        // The slot itself is larger than a byte; its index is below usize::MAX.
        Self(NonZeroUsize::MIN.saturating_add(index))
    }

    const fn get(self) -> usize {
        self.0.get() - 1
    }
}

#[derive(Clone, Copy)]
struct Span {
    start: usize,
    len: usize,
    prev: Option<Index>,
    next: Option<Index>,
}

impl Span {
    const EMPTY: Self = Self {
        start: 0,
        len: 0,
        prev: None,
        next: None,
    };

    fn range(self) -> Range<usize> {
        self.start..self.start + self.len
    }
}

#[derive(Clone, Copy)]
enum State {
    Vacant,
    Live,
    Retired,
}

/// Opaque storage for one original's metadata, independent of payload width.
/// Initialize caller arrays with [`OriginalSlot::EMPTY`].
#[derive(Clone, Copy)]
pub struct OriginalSlot {
    generation: NonZeroU64,
    state: State,
    // Vacant slots reuse only `span.next` for the free list.
    span: Span,
}

impl OriginalSlot {
    /// Unused metadata for initializing caller storage.
    pub const EMPTY: Self = Self {
        generation: NonZeroU64::MIN,
        state: State::Vacant,
        span: Span::EMPTY,
    };
}

impl fmt::Debug for OriginalSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalSlot([REDACTED])")
    }
}

#[derive(Clone, Copy)]
struct LiveList {
    first: Index,
    last: Index,
}

/// Exclusive custody of multiple immutable original byte sequences, without
/// an allocator. A handle names one generation in this pool. Borrowing bytes
/// from the pool prevents mutation or relocation until that borrow ends.
/// Removal and drop erase retained bytes. An empty payload still occupies one
/// metadata slot, but no byte storage.
pub struct OriginalPool<'storage, 'id> {
    owner: &'id OriginalPoolInstance,
    slots: &'storage mut [OriginalSlot],
    bytes: &'storage mut [u8],
    free: Option<Index>,
    // Ordered by physical position, so compaction visits each live span once.
    live: Option<LiveList>,
    tail: usize,
    used: usize,
}

impl<'storage, 'id> OriginalPool<'storage, 'id> {
    /// Erase the supplied backing and start an empty pool with independent
    /// record and aggregate byte limits.
    pub fn new(
        instance: &'id mut OriginalPoolInstance,
        slots: &'storage mut [OriginalSlot],
        bytes: &'storage mut [u8],
    ) -> Self {
        bytes.zeroize();
        let mut free = None;
        for (i, slot) in slots.iter_mut().enumerate().rev() {
            *slot = OriginalSlot::EMPTY;
            slot.span.next = free;
            free = Some(Index::at(i));
        }
        Self {
            owner: instance,
            slots,
            bytes,
            free,
            live: None,
            tail: 0,
            used: 0,
        }
    }

    /// Total supplied payload bytes across all records.
    pub const fn capacity(&self) -> usize {
        self.bytes.len()
    }

    /// Actual retained original bytes, excluding free storage.
    pub const fn used_bytes(&self) -> usize {
        self.used
    }

    /// Whether the pool owns no live records, including zero-length records.
    pub const fn is_empty(&self) -> bool {
        self.live.is_none()
    }

    /// Total supplied metadata, including live and retired slots.
    pub const fn slot_capacity(&self) -> usize {
        self.slots.len()
    }

    // Core clears rows on arena return. This compares live pool owners;
    // the normal operation checks the slot generation.
    pub(crate) fn bind_local(&self, stored: LocalOriginal) -> Result<OriginalId<'id>, Error> {
        if stored.owner != ptr::from_ref(self.owner).addr() {
            return Err(Fault::StaleGeneration.into());
        }
        Ok(self.identity(stored.index, stored.generation))
    }

    /// Read the original without granting mutation or copying its contents.
    /// A separately made copy is the caller's responsibility to erase.
    ///
    /// # Errors
    /// Returns a stale-generation error for a removed or foreign handle.
    pub fn expose(&self, id: OriginalId<'_>) -> Result<&[u8], Error> {
        Ok(&self.bytes[self.span(id)?.range()])
    }

    /// Make one copy into the pool. The caller retains custody of its input.
    ///
    /// # Errors
    /// Returns capacity exhaustion if either metadata slots or aggregate bytes
    /// are insufficient.
    pub fn copy_from(&mut self, bytes: &[u8]) -> Result<OriginalId<'id>, Error> {
        self.write(bytes.len(), |out| {
            out.copy_from_slice(bytes);
            Ok(())
        })
    }

    /// Fill an erased region of exactly `len` bytes and retain it on success.
    /// Existing handles survive any in-place compaction and a failed write.
    /// Partial output is erased on error or during unwinding.
    ///
    /// # Errors
    /// Returns capacity exhaustion if metadata slots or aggregate bytes are
    /// insufficient. Otherwise, propagates the writer's error.
    pub fn write(
        &mut self,
        len: usize,
        write: impl FnOnce(&mut [u8]) -> Result<(), Error>,
    ) -> Result<OriginalId<'id>, Error> {
        let index = self.free.ok_or(Fault::Capacity)?;
        if len > self.capacity() - self.used {
            return Err(Fault::Capacity.into());
        }
        let span = self.append_span(len);
        let mut pending = PendingWrite {
            bytes: &mut self.bytes[span.range()],
            committed: false,
        };
        write(pending.bytes)?;
        pending.committed = true;
        drop(pending);
        Ok(self.commit_append(index, span))
    }

    /// Replace one original with a copy of already prepared bytes. A successful
    /// replacement invalidates the old handle even if the span stays in place.
    /// The old bytes and handle survive any error.
    ///
    /// # Errors
    /// Returns a stale-generation error for a removed or foreign handle, or
    /// capacity exhaustion if the replacement exceeds the net byte budget or
    /// the old generation must retire and no new metadata slot is free.
    pub fn replace_from_slice(
        &mut self,
        id: OriginalId<'_>,
        bytes: &[u8],
    ) -> Result<OriginalId<'id>, Error> {
        let old = self.span(id)?;
        let other_bytes = self.used - old.len;
        if bytes.len() > self.capacity() - other_bytes {
            return Err(Fault::Capacity.into());
        }
        let list = self.live.ok_or(Fault::Conflict)?;
        let index = if let Some(generation) = id.generation.checked_add(1) {
            let limit = old
                .next
                .map_or(self.capacity(), |next| self.slots[next.get()].span.start);
            if bytes.len() <= limit - old.start {
                let replacement = Span {
                    len: bytes.len(),
                    ..old
                };
                self.bytes[old.range()].zeroize();
                self.bytes[replacement.range()].copy_from_slice(bytes);
                let entry = &mut self.slots[id.index.get()];
                entry.generation = generation;
                entry.span = replacement;
                if old.next.is_none() {
                    self.tail = replacement.range().end;
                }
                self.used = other_bytes + bytes.len();
                return Ok(self.identity(id.index, generation));
            }
            id.index
        } else {
            self.free.ok_or(Fault::Capacity)?
        };

        // All checks are complete: either `erase` puts the old index at the
        // head of the free list, or it retires it and leaves that head intact.
        self.erase(id.index, old, list);
        let span = self.append_span(bytes.len());
        self.bytes[span.range()].copy_from_slice(bytes);
        Ok(self.commit_append(index, span))
    }

    fn append_span(&mut self, len: usize) -> Span {
        if len > self.capacity() - self.tail {
            self.compact();
        }
        Span {
            start: self.tail,
            len,
            prev: self.live.map(|list| list.last),
            next: None,
        }
    }

    fn commit_append(&mut self, index: Index, span: Span) -> OriginalId<'id> {
        let entry = &mut self.slots[index.get()];
        let generation = entry.generation;
        self.free = entry.span.next;
        *entry = OriginalSlot {
            generation,
            state: State::Live,
            span,
        };
        self.live = Some(if let Some(list) = self.live {
            self.slots[list.last.get()].span.next = Some(index);
            LiveList {
                last: index,
                ..list
            }
        } else {
            LiveList {
                first: index,
                last: index,
            }
        });
        self.tail += span.len;
        self.used += span.len;
        self.identity(index, generation)
    }

    fn identity(&self, index: Index, generation: NonZeroU64) -> OriginalId<'id> {
        OriginalId {
            owner: self.owner,
            index,
            generation,
        }
    }

    /// Erase one original and invalidate every handle to its generation.
    ///
    /// # Errors
    /// Returns a stale-generation error for an already removed or foreign handle.
    pub fn remove(&mut self, id: OriginalId<'_>) -> Result<(), Error> {
        let span = self.span(id)?;
        let list = self.live.ok_or(Fault::Conflict)?;
        self.erase(id.index, span, list);
        Ok(())
    }

    /// Release the exact original only if its borrower accepts it.
    pub(crate) fn consume<T>(
        &mut self,
        id: OriginalId<'_>,
        accept: impl FnOnce(&[u8]) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let span = self.span(id)?;
        let list = self.live.ok_or(Fault::Conflict)?;
        let result = accept(&self.bytes[span.range()])?;
        self.erase(id.index, span, list);
        Ok(result)
    }

    fn erase(&mut self, index: Index, span: Span, mut list: LiveList) {
        self.bytes[span.range()].zeroize();
        self.used -= span.len;
        if let Some(prev) = span.prev {
            self.slots[prev.get()].span.next = span.next;
        }
        if let Some(next) = span.next {
            self.slots[next.get()].span.prev = span.prev;
        }
        match (span.prev, span.next) {
            (None, None) => {
                self.live = None;
                self.tail = 0;
            }
            (None, Some(next)) => {
                list.first = next;
                self.live = Some(list);
            }
            (Some(prev), None) => {
                self.tail = self.slots[prev.get()].span.range().end;
                list.last = prev;
                self.live = Some(list);
            }
            (Some(_), Some(_)) => {}
        }
        let slot = &mut self.slots[index.get()];
        slot.span = Span::EMPTY;
        if let Some(next) = slot.generation.checked_add(1) {
            slot.generation = next;
            slot.state = State::Vacant;
            slot.span.next = self.free;
            self.free = Some(index);
        } else {
            slot.state = State::Retired;
        }
    }

    fn span(&self, id: OriginalId<'_>) -> Result<Span, Error> {
        if ptr::eq(self.owner, id.owner)
            && let Some(slot) = self.slots.get(id.index.get())
            && slot.generation == id.generation
            && matches!(slot.state, State::Live)
        {
            return Ok(slot.span);
        }
        Err(Fault::StaleGeneration.into())
    }

    fn compact(&mut self) {
        let mut next = self.live.map(|list| list.first);
        let mut end = 0;
        while let Some(index) = next {
            let span = self.slots[index.get()].span;
            self.slots[index.get()].span.start = end;
            if span.start != end {
                self.bytes.copy_within(span.range(), end);
            }
            end += span.len;
            next = span.next;
        }
        // Overlap can leave a second copy of moved bytes beyond the new tail.
        self.bytes[end..self.tail].zeroize();
        self.tail = end;
    }
}

impl fmt::Debug for OriginalPool<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginalPool([REDACTED])")
            .field("capacity", &self.capacity())
            .field("slot_capacity", &self.slot_capacity())
            .finish_non_exhaustive()
    }
}

impl Drop for OriginalPool<'_, '_> {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.slots.fill(OriginalSlot::EMPTY);
    }
}

impl ZeroizeOnDrop for OriginalPool<'_, '_> {}

struct PendingWrite<'a> {
    bytes: &'a mut [u8],
    committed: bool,
}

impl Drop for PendingWrite<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.bytes.zeroize();
        }
    }
}

#[cfg(test)]
mod tests;
