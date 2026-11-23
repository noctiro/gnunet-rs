//! Bounded ciphertext storage with independently sized caller-owned slots.

use crate::{Block, BlockInfo, InsertOutcome, lookup_response};
use gnunet_gnscrypto::BLOCK_HEADER_LEN;
use gnunet_types::{AbsoluteTime, Error};
use gnunet_wire::official::namecache::{self as wire, Request, Response};

#[cfg(test)]
mod tests;

struct Entry {
    info: BlockInfo,
    len: usize,
}

/// Exclusive storage for one complete original block.
pub struct Slot<'storage> {
    body: &'storage mut [u8],
    entry: Option<Entry>,
}

impl<'storage> Slot<'storage> {
    /// Lend one empty slot with its actual ciphertext byte capacity.
    ///
    /// # Errors
    /// Refuses a body smaller than a block header or larger than official IPC
    /// can carry. The caller can independently size each slot.
    pub fn new(body: &'storage mut [u8]) -> Result<Self, Error> {
        if !(BLOCK_HEADER_LEN..=wire::MAX_WIRE_BLOCK_BYTES).contains(&body.len()) {
            return Err(Error::InvalidInput);
        }
        Ok(Self { body, entry: None })
    }

    fn block(&self) -> Option<&[u8]> {
        self.entry.as_ref().map(|entry| &self.body[..entry.len])
    }

    fn replace(&mut self, info: BlockInfo, bytes: &[u8]) {
        let previous = self.entry.as_ref().map_or(0, |entry| entry.len);
        self.body[..bytes.len()].copy_from_slice(bytes);
        if previous > bytes.len() {
            self.body[bytes.len()..previous].fill(0);
        }
        self.entry = Some(Entry {
            info,
            len: bytes.len(),
        });
    }

    fn clear(&mut self) -> bool {
        if let Some(entry) = self.entry.take() {
            self.body[..entry.len].fill(0);
            true
        } else {
            false
        }
    }
}

/// One fixed volatile cache of the greatest-expiration block for each query.
/// Payloads reside in the caller's original slots. No unexpired query is
/// evicted to admit a different one.
pub struct Cache<'storage, const N: usize> {
    slots: [Slot<'storage>; N],
}

impl<'storage, const N: usize> Cache<'storage, N> {
    /// Take exclusive ownership of the independently sized body slots.
    #[must_use]
    pub const fn new(slots: [Slot<'storage>; N]) -> Self {
        Self { slots }
    }

    /// Erase the used bytes and release all retained entries for reuse.
    pub fn clear(&mut self) {
        for slot in &mut self.slots {
            slot.clear();
        }
    }

    /// Visit exact retained ciphertext blocks without copying or decrypting.
    /// Use [Self::expire_before] before taking a live-only snapshot.
    pub fn blocks(&self) -> impl Iterator<Item = &[u8]> {
        self.slots.iter().filter_map(Slot::block)
    }

    /// Lookup the highest retained expiration using the caller's qualified UTC.
    /// Equality remains eligible under the reference expiration predicate.
    ///
    /// # Errors
    /// Refuses an unbounded clock or invalid retained framing.
    pub fn lookup(&self, query: &[u8; 64], now: AbsoluteTime) -> Result<Option<Block<'_>>, Error> {
        clock(now)?;
        let Some(slot) = self.slots.iter().find(|slot| {
            slot.entry
                .as_ref()
                .is_some_and(|entry| &entry.info.query == query && entry.info.expiration >= now)
        }) else {
            return Ok(None);
        };
        slot.block().map(Block::decode).transpose()
    }

    /// Retain the complete block using the inner expiration and carried query.
    /// Like the reference backend, this checks structure and stores opaque
    /// ciphertext. The lookup consumer verifies the carried-key signature.
    ///
    /// # Errors
    /// Refuses invalid framing, insufficient original slot capacity, an
    /// unbounded clock or a stale block with no live replacement.
    pub fn insert(&mut self, bytes: &[u8], now: AbsoluteTime) -> Result<InsertOutcome, Error> {
        clock(now)?;
        if !self.slots.iter().any(|slot| slot.body.len() >= bytes.len()) {
            return Err(Error::TooLarge);
        }
        let info = BlockInfo::decode(bytes)?;
        self.purge(now);
        let previous = self.locate(&info.query);
        if let Some(index) = previous {
            let slot = &self.slots[index];
            let entry = slot.entry.as_ref().ok_or(Error::Conflict)?;
            if let Some(outcome) = entry.info.retained(&slot.body[..entry.len], info, bytes) {
                return Ok(outcome);
            }
        }
        if info.expiration < now || info.expiration == AbsoluteTime::UNIX_EPOCH {
            return Err(Error::Deadline);
        }
        let target = self
            .slots
            .iter()
            .enumerate()
            .filter(|(index, slot)| {
                (Some(*index) == previous || slot.entry.is_none()) && slot.body.len() >= bytes.len()
            })
            .min_by_key(|(index, slot)| (slot.body.len(), Some(*index) != previous))
            .map(|(index, _)| index)
            .ok_or(Error::Capacity)?;
        self.slots[target].replace(info, bytes);
        if let Some(index) = previous.filter(|&index| index != target) {
            self.slots[index].clear();
        }
        Ok(if previous.is_some() {
            InsertOutcome::Replaced
        } else {
            InsertOutcome::Inserted
        })
    }

    /// Delete the currently retained original query, returning its disposition.
    ///
    /// # Errors
    /// Refuses an unbounded clock.
    pub fn delete(&mut self, query: &[u8; 64], now: AbsoluteTime) -> Result<bool, Error> {
        self.expire_before(now)?;
        Ok(self
            .locate(query)
            .is_some_and(|index| self.slots[index].clear()))
    }

    /// Remove only the original records strictly older than the supplied UTC.
    ///
    /// # Errors
    /// Refuses an unbounded clock.
    pub fn expire_before(&mut self, now: AbsoluteTime) -> Result<usize, Error> {
        clock(now)?;
        Ok(self.purge(now))
    }

    /// Apply one original official operation and echo its connection-local RID.
    /// The returned block borrow must be consumed before another operation.
    ///
    /// # Errors
    /// Refuses malformed ciphertext framing or an unbounded clock. Resource
    /// failures and a stale insertion return the corresponding signed result.
    pub fn handle(
        &mut self,
        request: Request<'_>,
        now: AbsoluteTime,
    ) -> Result<Response<'_>, Error> {
        match request {
            Request::Lookup { rid, query } => lookup_response(rid, self.lookup(query, now)?),
            Request::Cache { rid, block, .. } => {
                let result = match self.insert(block, now) {
                    Ok(_) => wire::OK,
                    Err(Error::Capacity | Error::TooLarge) => wire::SYSERR,
                    Err(Error::Deadline) => wire::NO,
                    Err(error) => return Err(error),
                };
                Ok(Response::Cache { rid, result })
            }
            Request::Delete { rid, query } => Ok(Response::Delete {
                rid,
                result: if self.delete(query, now)? {
                    wire::OK
                } else {
                    wire::NO
                },
            }),
        }
    }

    fn locate(&self, query: &[u8; 64]) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.entry
                .as_ref()
                .is_some_and(|entry| &entry.info.query == query)
        })
    }

    fn purge(&mut self, now: AbsoluteTime) -> usize {
        let mut removed = 0;
        for slot in &mut self.slots {
            if slot
                .entry
                .as_ref()
                .is_some_and(|entry| entry.info.expiration < now)
            {
                removed += usize::from(slot.clear());
            }
        }
        removed
    }
}

fn clock(now: AbsoluteTime) -> Result<(), Error> {
    if now.is_never() {
        Err(Error::TimeUncertain)
    } else {
        Ok(())
    }
}
