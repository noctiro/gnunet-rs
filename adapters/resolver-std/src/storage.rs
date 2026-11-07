//! Explicit fallible backing storage; the caller borrows two independent stores.
use gnunet_dnsstub_host::RequestId;
use gnunet_resolver_service_core::{
    cache::{BucketMeta, CacheBuffers, RecordEntry, RecordMeta},
    owner::{self, Buffers},
    pool::BlobSlot,
};
use gnunet_types::Error;
/// Metadata capacities and one aggregate byte pool, independently of record width.
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    /// Client metadata slots.
    pub clients: usize,
    /// Independent active lookup slots.
    pub lookups: usize,
    /// Maximum individual hosts-file aliases.
    pub hosts: usize,
    /// Dynamic cache buckets; use at least 1025 for the upstream eviction threshold.
    pub buckets: usize,
    /// Total dynamic cached record slots.
    pub records: usize,
    /// Ordinary pinned output/query effect slots.
    pub effects: usize,
    /// Initialized aggregate bytes for variable-length names and record payloads.
    pub byte_pool: usize,
}
impl Default for Geometry {
    fn default() -> Self {
        Self {
            clients: 64,
            lookups: 128,
            hosts: 1024,
            buckets: 1025,
            records: 4096,
            effects: 512,
            byte_pool: 8 * 1024 * 1024,
        }
    }
}
fn vec_with<T>(n: usize, f: impl FnMut() -> T) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    v.resize_with(n, f);
    Ok(v)
}
/// Owns only initialized vectors. Never stores a borrow into itself.
pub struct Store {
    clients: Vec<owner::ClientSlot>,
    lookups: Vec<owner::LookupSlot>,
    hosts: Vec<Option<RecordMeta>>,
    buckets: Vec<Option<BucketMeta>>,
    records: Vec<Option<RecordEntry>>,
    effects: Vec<owner::EffectSlot>,
    cleanups: Vec<Option<RequestId>>,
    blobs: Vec<BlobSlot>,
    bytes: Vec<u8>,
}
impl Store {
    /// Allocate all metadata and initialized bytes fallibly without borrowing self.
    pub fn new(g: Geometry) -> Result<Self, Error> {
        let objects = g
            .records
            .checked_mul(3)
            .and_then(|n| n.checked_add(g.hosts.checked_mul(3)?))
            .and_then(|n| n.checked_add(g.buckets))
            .and_then(|n| n.checked_add(g.lookups.checked_mul(2)?))
            .and_then(|n| n.checked_add(g.effects))
            .and_then(|n| n.checked_add(64))
            .ok_or(Error::Overflow)?;
        Ok(Self {
            clients: vec_with(g.clients, || owner::ClientSlot::EMPTY)?,
            lookups: vec_with(g.lookups, || owner::LookupSlot::EMPTY)?,
            hosts: vec_with(g.hosts, || None)?,
            buckets: vec_with(g.buckets, || None)?,
            records: vec_with(g.records, || None)?,
            effects: vec_with(g.effects, || owner::EffectSlot::EMPTY)?,
            cleanups: vec_with(g.lookups, || None)?,
            blobs: vec_with(objects, || BlobSlot::EMPTY)?,
            bytes: vec_with(g.byte_pool, || 0)?,
        })
    }
    /// Borrow the complete live or staging geometry; the Store must outlive it.
    pub fn buffers(&mut self) -> Buffers<'_> {
        Buffers {
            clients: &mut self.clients,
            lookups: &mut self.lookups,
            cache: CacheBuffers {
                hosts: &mut self.hosts,
                buckets: &mut self.buckets,
                records: &mut self.records,
            },
            effects: &mut self.effects,
            cleanups: &mut self.cleanups,
            blobs: &mut self.blobs,
            bytes: &mut self.bytes,
        }
    }
}
