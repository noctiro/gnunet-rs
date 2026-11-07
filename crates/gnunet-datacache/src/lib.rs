//! Independent local GNUnet DATACACHE API. This transient library defines no
//! IPC, service, network owner, key operation, C plugin ABI or SQL schema.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod memory;
use core::{fmt, ops::ControlFlow};
use gnunet_types::Error;
pub use gnunet_wire::official::AbsoluteTime;
#[cfg(feature = "alloc")]
pub use memory::{Matches, Memory};
/// Opaque official 512-bit block key. Ordering is canonical byte lexicographic,
/// as the SQL key blobs; no host-endian C structure comparison is reproduced.
pub type Key = [u8; 64];
/// Official wildcard block type; other numeric values are preserved unchanged.
pub const ANY: u32 = 0;
/// One official path element, copied as public opaque metadata without asserting
/// signature validity or executing any routing/network behavior.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PathElement {
    /// Public EdDSA hop signature bytes.
    pub signature: [u8; 64],
    /// Previous public peer identity.
    pub predecessor: [u8; 32],
}
impl fmt::Debug for PathElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PathElement(public opaque metadata)")
    }
}
/// One borrowed cached block. Data and path retain their exact original bytes;
/// no block parser, signature verifier, decryption or authority claim is implied.
#[derive(Clone, Copy)]
pub struct Block<'a> {
    /// Original opaque block key.
    pub key: Key,
    /// Absolute UTC microseconds, including the official never sentinel.
    pub expiration: AbsoluteTime,
    /// Original public peer where a path was truncated.
    pub truncation_peer: [u8; 32],
    /// Exact original typed path elements.
    pub put_path: &'a [PathElement],
    /// Exact opaque payload bytes.
    pub data: &'a [u8],
    /// Original numeric official block type.
    pub block_type: u32,
    /// Original numeric route options, preserving unknown bits.
    pub route_options: u32,
}
impl fmt::Debug for Block<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Block")
            .field("type", &self.block_type)
            .field("expiration", &self.expiration)
            .field("data_bytes", &self.data.len())
            .field("path_elements", &self.put_path.len())
            .finish_non_exhaustive()
    }
}
/// Explicit finite metadata and value/path allocation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum simultaneously live values, including multiple values per key.
    pub entries: usize,
    /// Maximum accounted fixed metadata plus payload/path allocation capacities.
    pub bytes: usize,
    /// Maximum payload bytes in one value; this is not a wire-format bound.
    pub value_bytes: usize,
    /// Maximum path elements in one value; this is not a C ABI or wire bound.
    pub path_elements: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: 1024,
            bytes: 8 * 1024 * 1024,
            value_bytes: 64 * 1024,
            path_elements: 256,
        }
    }
}
/// Actual put result: duplicate means same key/type/data, while expiration/path
/// metadata may have been updated. A reported result follows actual storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutKind {
    /// New distinct value stored.
    Inserted,
    /// Same value retained at the later expiry, with its complete path context.
    /// Equal-expiry duplicates may replace that context with the incoming one.
    Duplicate,
}
/// Actual insertion/duplicate settlement and required quota eviction count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PutOutcome {
    /// Actual storage disposition.
    pub kind: PutKind,
    /// Other actual values evicted to admit this operation.
    pub evicted: usize,
}
impl PutOutcome {
    /// Equivalent official success1 or duplicate0. Errors remain Result errors;
    /// they are not mapped into an empty query or successful put here.
    pub const fn official_status(self) -> i32 {
        match self.kind {
            PutKind::Inserted => 1,
            PutKind::Duplicate => 0,
        }
    }
}
/// Why a value actually left the transient storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvictionReason {
    /// Expiration strictly predates caller-supplied trusted UTC.
    Expired,
    /// Space/count quota admission or explicit backend eviction.
    Quota,
}
/// Metadata of an actual removal; no payload copy or secret-derived ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evicted {
    /// Actual removed key.
    pub key: Key,
    /// Actual removed block type.
    pub block_type: u32,
    /// Actual released payload/path allocation capacity in bytes.
    pub released_bytes: usize,
    /// Actual reason under the supplied time/quota policy.
    pub reason: EvictionReason,
}
/// Accounted storage and actual operation counters, excluding allocator headers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    /// Actual live values.
    pub entries: usize,
    /// Preallocated fixed metadata/index/work capacities in bytes.
    pub metadata_bytes: usize,
    /// Retained payload capacity in bytes.
    pub data_bytes: usize,
    /// Retained typed path capacity in bytes.
    pub path_bytes: usize,
    /// Actual new insertions.
    pub insertions: u64,
    /// Actual duplicate updates.
    pub duplicates: u64,
    /// Actual quota removals.
    pub evicted: u64,
    /// Actual expired removals.
    pub expired: u64,
}
impl Stats {
    /// Total accounted storage; saturates only for externally fabricated Stats.
    pub fn accounted_bytes(self) -> usize {
        self.metadata_bytes
            .saturating_add(self.data_bytes)
            .saturating_add(self.path_bytes)
    }
}
/// Replaceable native Rust storage contract, without a dynamic C ABI. Backends
/// own their actual data/bounds and must not return success before the operation
/// settles. A failed put preserves prior values; backend failures stay errors.
/// Queries exclude expiry<now, retain type0 as ANY, and return borrowed values.
pub trait Storage {
    /// Borrowed, allocation-free query stream; backend read failures remain errors.
    type Matches<'a>: Iterator<Item = Result<Block<'a>, Error>>
    where
        Self: 'a;
    /// Actually insert/update with the supplied eviction priority and trusted UTC.
    fn put(
        &mut self,
        xor_distance: u32,
        block: Block<'_>,
        now: AbsoluteTime,
    ) -> Result<PutOutcome, Error>;
    /// Exact key/type results, newest expiration first.
    fn get(&self, key: Key, block_type: u32, now: AbsoluteTime)
    -> Result<Self::Matches<'_>, Error>;
    /// At most limit results in canonical clockwise key order, starting at keys
    /// greater than or equal to target, wrapping once. Equal keys are freshest
    /// first. This is a bounded public-library ring query, not XOR routing.
    fn get_closest(
        &self,
        target: Key,
        block_type: u32,
        limit: usize,
        now: AbsoluteTime,
    ) -> Result<Self::Matches<'_>, Error>;
    /// Actually discard all expired values; equality with now remains valid.
    fn expire_before(&mut self, now: AbsoluteTime) -> Result<usize, Error>;
    /// Actually remove one expired-first then distance/expiry-priority value.
    fn evict_one(&mut self, now: AbsoluteTime) -> Result<Option<Evicted>, Error>;
    /// Drop all actual transient content while retaining bounded working storage.
    fn clear(&mut self) -> Result<usize, Error>;
    /// Read actual resource counters.
    fn stats(&self) -> Stats;
}
/// Public local API over a caller-selected actual storage implementation. The
/// facade neither loads a plugin nor starts a service, thread, clock or resolver.
pub struct Cache<S: Storage> {
    storage: S,
}
impl<S: Storage> Cache<S> {
    /// Consume an already constructed actual bounded storage owner.
    pub const fn new(storage: S) -> Self {
        Self { storage }
    }
    /// Actually insert/update, preserving storage errors.
    pub fn put(
        &mut self,
        distance: u32,
        block: Block<'_>,
        now: AbsoluteTime,
    ) -> Result<PutOutcome, Error> {
        self.storage.put(distance, block, now)
    }
    /// Borrow exact unexpired values in newest-expiry order.
    pub fn get(&self, key: Key, kind: u32, now: AbsoluteTime) -> Result<S::Matches<'_>, Error> {
        self.storage.get(key, kind, now)
    }
    /// Borrow at most limit clockwise results without an invented wire request.
    pub fn get_closest(
        &self,
        key: Key,
        kind: u32,
        limit: usize,
        now: AbsoluteTime,
    ) -> Result<S::Matches<'_>, Error> {
        self.storage.get_closest(key, kind, limit, now)
    }
    /// Count actual exact matches without collecting/copying any payload.
    pub fn count(&self, key: Key, kind: u32, now: AbsoluteTime) -> Result<usize, Error> {
        count(self.get(key, kind, now)?)
    }
    /// Visit exact results, counting the item on which the callback aborts, as
    /// the public iterator API does. Callback break is not a backend read failure.
    pub fn visit(
        &self,
        key: Key,
        kind: u32,
        now: AbsoluteTime,
        mut visitor: impl FnMut(Block<'_>) -> ControlFlow<()>,
    ) -> Result<usize, Error> {
        let mut n = 0usize;
        for block in self.get(key, kind, now)? {
            let block = block?;
            n = n.checked_add(1).ok_or(Error::Overflow)?;
            if visitor(block).is_break() {
                break;
            }
        }
        Ok(n)
    }
    /// Actual expired removals.
    pub fn expire_before(&mut self, now: AbsoluteTime) -> Result<usize, Error> {
        self.storage.expire_before(now)
    }
    /// Actual single eviction.
    pub fn evict_one(&mut self, now: AbsoluteTime) -> Result<Option<Evicted>, Error> {
        self.storage.evict_one(now)
    }
    /// Clear actual contents while retaining the storage owner.
    pub fn clear(&mut self) -> Result<usize, Error> {
        self.storage.clear()
    }
    /// Actual cache counters.
    pub fn stats(&self) -> Stats {
        self.storage.stats()
    }
    /// Recover the same actual storage owner without a private migration layer.
    pub fn into_storage(self) -> S {
        self.storage
    }
}
/// Count a fallible borrowed stream, preserving a real backend failure.
pub fn count<'a>(matches: impl Iterator<Item = Result<Block<'a>, Error>>) -> Result<usize, Error> {
    let mut n = 0usize;
    for block in matches {
        block?;
        n = n.checked_add(1).ok_or(Error::Overflow)?;
    }
    Ok(n)
}
