//! Owned metadata snapshots. Names remain in never-evicted original core rows.
use super::{ClientId, Row, Statistics};
use crate::{
    Reply, SET_PERSISTENT, Selector, Set, Statistic,
    protocol::{names_len, raw_uid},
};
use alloc::vec::Vec;
use core::mem::size_of;
use gnunet_types::Error;
use gnunet_wire::official::{MessageHeader, message_type};

/// One original GET snapshot owned by its actual client generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotId {
    client: ClientId,
    generation: u64,
}
struct Frozen {
    row: usize,
    uid: u32,
    raw_uid: u32,
    value: u64,
    order: (u64, u64),
}
pub(super) struct Active {
    generation: u64,
    rows: Vec<Frozen>,
    cursor: usize,
}
impl Active {
    pub(super) fn retained_bytes(&self) -> usize {
        self.rows.capacity() * size_of::<Frozen>()
    }
}
impl<const R: usize, const N: usize, const C: usize, const W: usize, const E: usize>
    Statistics<R, N, C, W, E>
{
    /// Capture the original matching set and values once, before releasing its
    /// immutable view. Row names never change or disappear during this core's
    /// lifetime; the original client generation owns this metadata allocation.
    /// No response or END has been sent or admitted by this call.
    pub fn snapshot(
        &mut self,
        client: ClientId,
        selector: Selector<'_>,
    ) -> Result<SnapshotId, Error> {
        let slot = self.client_index(client)?;
        if self.clients[slot].snapshot.is_some() {
            return Err(Error::Conflict);
        }
        MessageHeader::new(message_type::STATISTICS_GET, names_len(selector)?)?;
        let generation = self.clients[slot]
            .next_snapshot
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let matches = |row: &Row<N>| {
            let names = row.selector();
            (selector.subsystem.is_empty() || selector.subsystem == names.subsystem)
                && (selector.name.is_empty() || selector.name == names.name)
        };
        let count = self.rows.iter().flatten().filter(|r| matches(r)).count();
        let bytes = count
            .checked_mul(size_of::<Frozen>())
            .ok_or(Error::Overflow)?;
        if self
            .retained_bytes()?
            .checked_add(bytes)
            .ok_or(Error::Overflow)?
            > self.limits.max_retained_bytes
        {
            return Err(Error::Capacity);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(count).map_err(|_| Error::Capacity)?;
        let bytes = rows
            .capacity()
            .checked_mul(size_of::<Frozen>())
            .ok_or(Error::Overflow)?;
        if self
            .retained_bytes()?
            .checked_add(bytes)
            .ok_or(Error::Overflow)?
            > self.limits.max_retained_bytes
        {
            return Err(Error::Capacity);
        }
        for (index, row) in self
            .rows
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.as_ref().map(|r| (i, r)))
        {
            if matches(row) {
                rows.push(Frozen {
                    row: index,
                    uid: row.uid,
                    raw_uid: raw_uid(row.uid, row.persistent),
                    value: row.value,
                    order: row.order(),
                });
            }
        }
        rows.sort_unstable_by_key(|row| core::cmp::Reverse(row.order));
        self.snapshots_retained += bytes;
        self.clients[slot].next_snapshot = generation;
        self.clients[slot].snapshot = Some(Active {
            generation,
            rows,
            cursor: 0,
        });
        Ok(SnapshotId { client, generation })
    }
    fn active_snapshot(&self, id: SnapshotId) -> Result<&Active, Error> {
        let slot = self.client_index(id.client)?;
        self.clients[slot]
            .snapshot
            .as_ref()
            .filter(|s| s.generation == id.generation)
            .ok_or(Error::StaleGeneration)
    }
    /// Encode only the next original snapshot response, without consuming it.
    /// The caller must reserve/admit this exact frame before consuming the row.
    pub fn snapshot_reply(&self, id: SnapshotId, output: &mut [u8]) -> Result<usize, Error> {
        let snapshot = self.active_snapshot(id)?;
        let reply = if let Some(frozen) = snapshot.rows.get(snapshot.cursor) {
            let row = self
                .rows
                .get(frozen.row)
                .and_then(Option::as_ref)
                .filter(|r| r.uid == frozen.uid)
                .ok_or(Error::StaleGeneration)?;
            Reply::Value(Statistic {
                raw_uid: frozen.raw_uid,
                value: frozen.value,
                selector: row.selector(),
            })
        } else {
            Reply::End
        };
        reply.encode(output)
    }
    /// Commit one actual host-queue admission. True means the original END was
    /// admitted and snapshot metadata is now released, not that bytes were sent.
    pub fn consume_snapshot_reply(&mut self, id: SnapshotId) -> Result<bool, Error> {
        let slot = self.client_index(id.client)?;
        let snapshot = self.clients[slot]
            .snapshot
            .as_mut()
            .filter(|s| s.generation == id.generation)
            .ok_or(Error::StaleGeneration)?;
        if snapshot.cursor < snapshot.rows.len() {
            snapshot.cursor += 1;
            return Ok(false);
        }
        if let Some(snapshot) = self.clients[slot].snapshot.take() {
            self.snapshots_retained -= snapshot.retained_bytes();
        }
        Ok(true)
    }
    /// Prepare one immutable persistent ordering index in O(R log R) time and
    /// actual O(persistent rows) metadata. It borrows names/values from this
    /// unchanged core for both preflight and writing, without encoded buffering.
    pub fn persistent_snapshot(&self) -> Result<PersistentSnapshot<'_, N>, Error> {
        let count = self
            .rows
            .iter()
            .flatten()
            .filter(|row| row.persistent)
            .count();
        let bytes = count
            .checked_mul(size_of::<usize>())
            .ok_or(Error::Overflow)?;
        if self
            .retained_bytes()?
            .checked_add(bytes)
            .ok_or(Error::Overflow)?
            > self.limits.max_retained_bytes
        {
            return Err(Error::Capacity);
        }
        let mut order = Vec::new();
        order
            .try_reserve_exact(count)
            .map_err(|_| Error::Capacity)?;
        let bytes = order
            .capacity()
            .checked_mul(size_of::<usize>())
            .ok_or(Error::Overflow)?;
        if self
            .retained_bytes()?
            .checked_add(bytes)
            .ok_or(Error::Overflow)?
            > self.limits.max_retained_bytes
        {
            return Err(Error::Capacity);
        }
        for (index, row) in self.rows.iter().enumerate() {
            if row.as_ref().is_some_and(|r| r.persistent) {
                order.push(index);
            }
        }
        order.sort_unstable_by_key(|&index| {
            core::cmp::Reverse(self.rows[index].as_ref().map(Row::order))
        });
        self.persistent_retained.set(
            self.persistent_retained
                .get()
                .checked_add(bytes)
                .ok_or(Error::Overflow)?,
        );
        Ok(PersistentSnapshot {
            rows: &self.rows,
            order,
            retained: &self.persistent_retained,
            bytes,
        })
    }
}
/// An immutable borrowed database view with one fallibly allocated ordering index.
/// The core borrow prevents mutation until both preflight and write passes end.
pub struct PersistentSnapshot<'a, const N: usize> {
    rows: &'a [Option<Row<N>>],
    order: Vec<usize>,
    retained: &'a core::cell::Cell<usize>,
    bytes: usize,
}
impl<'a, const N: usize> PersistentSnapshot<'a, N> {
    /// Repeat the same immutable absolute-persistent SET stream without allocating.
    pub fn iter(&self) -> impl Iterator<Item = Set<'a>> + '_ {
        let rows = self.rows;
        self.order.iter().filter_map(move |&index| {
            rows[index].as_ref().map(|row| Set {
                selector: row.selector(),
                flags: SET_PERSISTENT,
                value: row.value,
            })
        })
    }
}

impl<const N: usize> Drop for PersistentSnapshot<'_, N> {
    fn drop(&mut self) {
        if let Some(remaining) = self.retained.get().checked_sub(self.bytes) {
            self.retained.set(remaining);
        }
    }
}
