//! Caller-owned variable-byte storage with generational spans and explicit pins.
//! Single-object width is independent of aggregate byte capacity. No object
//! retains a Rust reference into this pool, so compaction updates only metadata.
use gnunet_types::{Error, GenerationalId};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Scope {
    epoch: u64,
    origin: usize,
}
/// Opaque local byte-object identity; never encoded in DNS or GNUnet IPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobId {
    scope: Scope,
    id: GenerationalId,
}
/// One small caller-owned metadata slot, independently of payload width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobSlot {
    current: u32,
    next: Option<u32>,
    refs: u32,
    offset: usize,
    len: usize,
    visited: bool,
}
impl BlobSlot {
    /// Initial metadata for caller Vec/static slice initialization.
    pub const EMPTY: Self = Self {
        current: 0,
        next: Some(0),
        refs: 0,
        offset: 0,
        len: 0,
        visited: false,
    };
}
/// Borrowed safe byte pool. Construction resets logical metadata only. Caller
/// supplies initialized byte storage and a nonreused logical instance epoch.
pub struct BytePool<'a> {
    scope: Scope,
    slots: &'a mut [BlobSlot],
    bytes: &'a mut [u8],
    tail: usize,
    live_bytes: usize,
}
impl PartialEq for BytePool<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope
            && self.slots == other.slots
            && self.bytes == other.bytes
            && self.tail == other.tail
            && self.live_bytes == other.live_bytes
    }
}
impl Eq for BytePool<'_> {}
impl<'a> BytePool<'a> {
    /// Initialize empty metadata without allocating or constructing a large array.
    /// Epoch must not be reused when the same backing storage begins a new owner.
    pub fn new(slots: &'a mut [BlobSlot], bytes: &'a mut [u8], epoch: u64) -> Result<Self, Error> {
        if slots.is_empty() || bytes.is_empty() || slots.len() > u32::MAX as usize {
            return Err(Error::Capacity);
        }
        if epoch == 0 {
            return Err(Error::InvalidInput);
        }
        let scope = Scope {
            epoch,
            origin: slots.as_ptr() as usize,
        };
        slots.fill(BlobSlot::EMPTY);
        bytes.fill(0);
        Ok(Self {
            scope,
            slots,
            bytes,
            tail: 0,
            live_bytes: 0,
        })
    }
    /// Aggregate supplied byte capacity, not a per-record reservation.
    pub fn capacity(&self) -> usize {
        self.bytes.len()
    }
    /// Actual live payload bytes, with shared pins counted once.
    pub const fn live_bytes(&self) -> usize {
        self.live_bytes
    }
    /// Number of referenced objects, including queued/in-flight output pins.
    pub fn live_objects(&self) -> usize {
        self.slots.iter().filter(|s| s.refs != 0).count()
    }
    /// Number of independently available metadata identities.
    pub fn slot_capacity(&self) -> usize {
        self.slots.len()
    }
    /// Whether caller slot/byte capacities match for an exact logical snapshot.
    pub fn same_geometry(&self, other: &Self) -> bool {
        self.slots.len() == other.slots.len() && self.bytes.len() == other.bytes.len()
    }
    /// Copy a logical snapshot into equal-capacity caller storage, including
    /// its original span scope. This is storage staging, not a second independent
    /// resolver owner; the outer owner enforces pair/role/epoch authority.
    pub fn copy_from(&mut self, other: &Self) -> Result<(), Error> {
        if !self.same_geometry(other) {
            return Err(Error::Capacity);
        }
        self.scope = other.scope;
        self.slots.copy_from_slice(other.slots);
        self.bytes.copy_from_slice(other.bytes);
        self.tail = other.tail;
        self.live_bytes = other.live_bytes;
        Ok(())
    }
    fn index(&self, id: BlobId) -> Result<usize, Error> {
        let i = id.id.index as usize;
        if id.scope == self.scope
            && self
                .slots
                .get(i)
                .is_some_and(|s| s.refs != 0 && s.current == id.id.generation)
        {
            Ok(i)
        } else {
            Err(Error::StaleGeneration)
        }
    }
    /// Read only this original live object; stale/replaced/foreign identities fail.
    pub fn get(&self, id: BlobId) -> Result<&[u8], Error> {
        let s = self.slots[self.index(id)?];
        self.bytes
            .get(s.offset..s.offset + s.len)
            .ok_or(Error::Malformed)
    }
    /// Write a newly allocated uniquely held object. Shared output/cache pins
    /// prohibit mutable access until only one owner remains.
    pub fn unique_mut(&mut self, id: BlobId) -> Result<&mut [u8], Error> {
        let s = self.slots[self.index(id)?];
        if s.refs != 1 {
            return Err(Error::Conflict);
        }
        self.bytes
            .get_mut(s.offset..s.offset + s.len)
            .ok_or(Error::Malformed)
    }
    /// Clone local ownership before an earlier cache/lookup lease is released.
    pub fn retain(&mut self, id: BlobId) -> Result<(), Error> {
        let i = self.index(id)?;
        let n = self.slots[i].refs.checked_add(1).ok_or(Error::Overflow)?;
        self.slots[i].refs = n;
        Ok(())
    }
    /// Release exactly one original pin. A stale token cannot release a reused slot.
    pub fn release(&mut self, id: BlobId) -> Result<(), Error> {
        let i = self.index(id)?;
        self.slots[i].refs -= 1;
        if self.slots[i].refs == 0 {
            self.live_bytes -= self.slots[i].len;
        }
        Ok(())
    }
    fn compact(&mut self) {
        for s in &mut *self.slots {
            s.visited = false;
        }
        let mut end = 0;
        loop {
            let candidate = self
                .slots
                .iter()
                .enumerate()
                .filter(|(_, s)| s.refs != 0 && !s.visited)
                .min_by_key(|(i, s)| (s.offset, *i))
                .map(|(i, s)| (i, *s));
            let Some((i, s)) = candidate else { break };
            self.bytes.copy_within(s.offset..s.offset + s.len, end);
            self.slots[i].offset = end;
            self.slots[i].visited = true;
            end += s.len;
        }
        for s in &mut *self.slots {
            s.visited = false;
        }
        self.tail = end;
    }
    /// Allocate one variable-size object. All resource checks precede compaction
    /// or metadata changes; failure leaves the complete pool unchanged.
    pub fn allocate(&mut self, len: usize) -> Result<BlobId, Error> {
        let total = self.live_bytes.checked_add(len).ok_or(Error::Overflow)?;
        if total > self.bytes.len() {
            return Err(Error::Capacity);
        }
        let i = self
            .slots
            .iter()
            .position(|s| s.refs == 0 && s.next.is_some())
            .ok_or(Error::Capacity)?;
        let generation = self.slots[i].next.ok_or(Error::Capacity)?;
        if self
            .tail
            .checked_add(len)
            .is_none_or(|end| end > self.bytes.len())
        {
            self.compact();
        }
        let offset = self.tail;
        self.tail += len;
        self.live_bytes = total;
        self.slots[i] = BlobSlot {
            current: generation,
            next: generation.checked_add(1),
            refs: 1,
            offset,
            len,
            visited: false,
        };
        self.bytes[offset..offset + len].fill(0);
        Ok(BlobId {
            scope: self.scope,
            id: GenerationalId {
                index: i as u32,
                generation,
            },
        })
    }
    /// Copy a caller slice into one new independent pool object.
    pub fn copy(&mut self, bytes: &[u8]) -> Result<BlobId, Error> {
        let id = self.allocate(bytes.len())?;
        self.unique_mut(id)?.copy_from_slice(bytes);
        Ok(id)
    }
    /// Reclaim all logical objects while retaining their nonreused generations.
    /// Used only when final service shutdown invalidates every outside token.
    pub fn clear(&mut self) {
        for s in &mut *self.slots {
            s.refs = 0;
            s.visited = false;
        }
        self.live_bytes = 0;
        self.tail = 0;
    }
}
