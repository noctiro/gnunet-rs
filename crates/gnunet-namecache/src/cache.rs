//! Actual bounded volatile storage for opaque official encrypted blocks.
use crate::Block;
use alloc::vec::Vec;
use core::mem;
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    namecache::{self as wire, Request, Response},
};

/// Explicit finite allocation policy. Limits are internal resource bounds,
/// not a different block encoding or a private NAMECACHE protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum distinct query keys retained at once.
    pub entries: usize,
    /// Maximum accounted metadata capacity plus ciphertext-buffer capacities.
    pub bytes: usize,
    /// Maximum whole encrypted block bytes, at most MAX_WIRE_BLOCK_BYTES.
    pub block_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: 1024,
            bytes: 8 * 1024 * 1024,
            block_bytes: wire::MAX_VALUE_SIZE,
        }
    }
}
/// Actual memory-cache result, separate from a wire/backend receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InsertOutcome {
    /// A previously absent query now has a stored block.
    Inserted,
    /// Same or later expiration replaced the old block with the actual new bytes.
    Replaced,
    /// Equal expiration and identical bytes were already present.
    AlreadyPresent,
    /// An existing later-expiring version remains authoritative for lookup.
    RetainedNewer,
}
/// Current resource use. Values include reserved metadata, not allocator headers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stats {
    /// Stored distinct queries.
    pub entries: usize,
    /// Retained ciphertext allocation capacities.
    pub block_bytes: usize,
    /// Metadata vector allocation capacity in bytes.
    pub metadata_bytes: usize,
}
impl Stats {
    /// Total accounted cache allocations, excluding the Cache value itself.
    pub fn accounted_bytes(self) -> usize {
        self.metadata_bytes.saturating_add(self.block_bytes)
    }
}
struct Entry {
    query: [u8; 64],
    expiration: AbsoluteTime,
    bytes: Vec<u8>,
}
/// Sorted, bounded query map. Payloads are never moved/copied during metadata
/// insertion, and lookup needs no allocation. This is real in-memory storage,
/// not a promise that any filesystem backend committed or can recover it.
pub struct Cache {
    limits: Limits,
    rows: Vec<Entry>,
    metadata: usize,
    block_bytes: usize,
}
impl Cache {
    /// Reserve bounded metadata once. No native backend, private key, resolver,
    /// clock or executor is created. There is no implicit unexpired eviction.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        if limits.block_bytes > wire::MAX_WIRE_BLOCK_BYTES {
            return Err(Error::InvalidInput);
        }
        let minimum = limits
            .entries
            .checked_mul(mem::size_of::<Entry>())
            .ok_or(Error::Overflow)?;
        if minimum > limits.bytes {
            return Err(Error::InvalidInput);
        }
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.entries)
            .map_err(|_| Error::Capacity)?;
        let metadata = rows
            .capacity()
            .checked_mul(mem::size_of::<Entry>())
            .ok_or(Error::Overflow)?;
        if metadata > limits.bytes {
            return Err(Error::Capacity);
        }
        Ok(Self {
            limits,
            rows,
            metadata,
            block_bytes: 0,
        })
    }
    /// Read current resource accounting without inspecting block contents.
    pub fn stats(&self) -> Stats {
        Stats {
            entries: self.rows.len(),
            block_bytes: self.block_bytes,
            metadata_bytes: self.metadata,
        }
    }
    fn locate(&self, query: &[u8; 64]) -> Result<usize, usize> {
        self.rows.binary_search_by_key(query, |r| r.query)
    }
    /// Lookup the greatest-expiration retained block, without signature checking
    /// or decryption. As in the reference SQL backend, expiration removal is an
    /// explicit maintenance operation; this raw lookup does not invent a miss
    /// from an unconsulted clock. Consumers still enforce their own expiry.
    pub fn lookup(&self, query: &[u8; 64]) -> Result<Option<Block<'_>>, Error> {
        match self.locate(query) {
            Ok(i) => Ok(Some(Block::decode(&self.rows[i].bytes)?)),
            Err(_) => Ok(None),
        }
    }
    /// Structurally validate and actually cache a complete encrypted block.
    /// The official service/backend also treats the ciphertext as opaque and
    /// derives its query/expiration from the block, not the outer IPC field.
    /// The caller/client is responsible for public signature validation.
    /// Any allocation/size failure leaves the cache unchanged.
    pub fn insert(&mut self, bytes: &[u8]) -> Result<InsertOutcome, Error> {
        if bytes.len() > self.limits.block_bytes {
            return Err(Error::TooLarge);
        }
        let block = Block::decode(bytes)?;
        let query = block.query()?;
        let expiration = AbsoluteTime::from_micros(block.expiration()?);
        let location = self.locate(&query);
        let previous = match location {
            Ok(i) => {
                let old = &self.rows[i];
                if old.expiration > expiration {
                    return Ok(InsertOutcome::RetainedNewer);
                }
                if old.expiration == expiration && old.bytes.as_slice() == bytes {
                    return Ok(InsertOutcome::AlreadyPresent);
                }
                if old.bytes.capacity() >= bytes.len() {
                    // The complete replacement is already validated and its
                    // existing capacity is charged. Reuse it without a second
                    // ciphertext allocation or temporary doubling of storage.
                    let old = &mut self.rows[i];
                    old.bytes.clear();
                    old.bytes.extend_from_slice(bytes);
                    old.expiration = expiration;
                    return Ok(InsertOutcome::Replaced);
                }
                old.bytes.capacity()
            }
            Err(_) => {
                if self.rows.len() == self.limits.entries {
                    return Err(Error::Capacity);
                }
                0
            }
        };
        let retained = self.block_bytes.checked_sub(previous).ok_or(Error::Stale)?;
        let requested = self
            .metadata
            .checked_add(retained)
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or(Error::Overflow)?;
        if requested > self.limits.bytes {
            return Err(Error::Capacity);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| Error::Capacity)?;
        let used = retained
            .checked_add(owned.capacity())
            .ok_or(Error::Overflow)?;
        if self.metadata.checked_add(used).ok_or(Error::Overflow)? > self.limits.bytes {
            return Err(Error::Capacity);
        }
        owned.extend_from_slice(bytes);
        let entry = Entry {
            query,
            expiration,
            bytes: owned,
        };
        let result = match location {
            Ok(i) => {
                self.rows[i] = entry;
                InsertOutcome::Replaced
            }
            Err(i) => {
                self.rows.insert(i, entry);
                InsertOutcome::Inserted
            }
        };
        self.block_bytes = used;
        Ok(result)
    }
    /// Actually remove the query, returning false only when it was absent.
    /// Keeping only the greatest version makes this equivalent to deleting all
    /// SQL rows under that query; lower versions cannot become unexpired later.
    pub fn delete(&mut self, query: &[u8; 64]) -> bool {
        let Ok(i) = self.locate(query) else {
            return false;
        };
        let removed = self.rows.remove(i);
        self.block_bytes -= removed.bytes.capacity();
        true
    }
    /// Actually discard blocks strictly older than caller-supplied trusted UTC.
    /// Equality stays valid, matching the official SQL expiration predicate.
    /// The caller chooses scheduling (SQLite hourly, PostgreSQL on cache calls).
    pub fn expire_before(&mut self, now: AbsoluteTime) -> usize {
        let previous = self.rows.len();
        let mut removed = 0usize;
        self.rows.retain(|row| {
            if row.expiration < now {
                removed += row.bytes.capacity();
                false
            } else {
                true
            }
        });
        self.block_bytes -= removed;
        previous - self.rows.len()
    }
    /// Apply an official request to this actual memory backend. Only after
    /// insert/delete has completed is its result generated. There is no durable
    /// disk receipt, publication claim, synthetic cancel, or extra completion.
    /// A resource refusal is an actual SYSERR; malformed block input is an error
    /// for the native owner to reject/close, never a fabricated cache success.
    pub fn handle<'a>(&'a mut self, request: Request<'_>) -> Result<Response<'a>, Error> {
        match request {
            Request::Lookup { rid, query } => match self.lookup(query)? {
                Some(block) => Ok(Response::Lookup {
                    rid,
                    expiration: AbsoluteTime::from_micros(block.expiration()?),
                    block: block.as_bytes(),
                }),
                None => Ok(Response::Lookup {
                    rid,
                    expiration: AbsoluteTime::UNIX_EPOCH,
                    block: &[],
                }),
            },
            Request::Cache { rid, block, .. } => {
                let result = match self.insert(block) {
                    Ok(_) => wire::OK,
                    Err(Error::Capacity | Error::TooLarge) => wire::SYSERR,
                    Err(e) => return Err(e),
                };
                Ok(Response::Cache { rid, result })
            }
            Request::Delete { rid, query } => Ok(Response::Delete {
                rid,
                result: if self.delete(query) {
                    wire::OK
                } else {
                    wire::NO
                },
            }),
        }
    }
}
