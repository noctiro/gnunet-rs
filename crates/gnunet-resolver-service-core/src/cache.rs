//! Bounded cache using caller metadata and variable-byte objects. The Resolver
//! wraps fallible cache operations in typed transaction scratch. Direct component
//! mutation can be dirty on error; standalone callers must stage it themselves.
use crate::{
    files::HostsFile,
    pool::{BlobId, BytePool},
    storage::{Limits, TextScratch},
};
use gnunet_dns::{AbsoluteTime, Idna, RData, Record};
use gnunet_types::Error;
/// Exact source bucket threshold (temporary1025th bucket remains allowed).
pub const MAX_CACHE: usize = 1024;
/// Small record metadata for caller Vec/static-slice initialization. Payload
/// ownership is library-controlled through the private span fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordMeta {
    pub(crate) owner: BlobId,
    pub(crate) kind: u16,
    pub(crate) class: u16,
    pub(crate) expires: u64,
    pub(crate) data: BlobId,
    pub(crate) target: Option<BlobId>,
}
impl RecordMeta {
    /// Borrow this original record from its pool, without retaining a reference
    /// beyond the callback or fabricating a normalized payload.
    pub fn view<'p>(self, pool: &'p BytePool<'_>) -> Result<RecordView<'p>, Error> {
        Ok(RecordView {
            owner: pool.get(self.owner)?,
            kind: self.kind,
            class: self.class,
            expiration: self.expires,
            data: pool.get(self.data)?,
            target: self.target.map(|id| pool.get(id)).transpose()?,
        })
    }
}
/// Small dynamic bucket metadata; construct vacant slots with Option::None.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BucketMeta {
    pub(crate) key: BlobId,
    pub(crate) lru: u64,
}
/// Small cached-record list metadata, without an inline RDATA/name array.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordEntry {
    pub(crate) record: RecordMeta,
    pub(crate) bucket: usize,
    pub(crate) order: u64,
}
/// Borrowed lookup name from a request or a retained stored CNAME/lookup lease.
#[derive(Clone, Copy)]
pub enum NameRef<'a> {
    /// Caller input borrowed for this operation only.
    External(&'a [u8]),
    /// Original retained pool span.
    Stored(BlobId),
}
/// Lookup result. Follow transfers one retained target lease to its caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hit {
    /// No matching supported row.
    Miss,
    /// Matching rows were emitted; owner appends one END.
    Rows,
    /// Owned original native target lease, before owner-name filtering.
    Follow(BlobId),
}
/// Borrowed record view valid only until the next mutable operation.
#[derive(Clone, Copy, Debug)]
pub struct RecordView<'a> {
    /// Original native owner name.
    pub owner: &'a [u8],
    /// Lossless type number.
    pub kind: u16,
    /// Original class, never rewritten to IN.
    pub class: u16,
    /// Exact absolute UTC expiration.
    pub expiration: u64,
    /// Raw/complete uncompressed RDATA encoding.
    pub data: &'a [u8],
    /// Native hostname target when represented by this DNS type.
    pub target: Option<&'a [u8]>,
}
/// Caller-owned logical cache buffers, independently allocated from payload bytes.
pub struct CacheBuffers<'a> {
    /// Independent hosts aliases, newest at index0.
    pub hosts: &'a mut [Option<RecordMeta>],
    /// Dynamic queried-name buckets.
    pub buckets: &'a mut [Option<BucketMeta>],
    /// Shared dynamic record metadata.
    pub records: &'a mut [Option<RecordEntry>],
}
/// Borrowed pure cache, including its one logical variable-byte pool.
pub struct Cache<'a> {
    pub(crate) pool: BytePool<'a>,
    hosts: &'a mut [Option<RecordMeta>],
    buckets: &'a mut [Option<BucketMeta>],
    records: &'a mut [Option<RecordEntry>],
    order: u64,
    limits: Limits,
}
impl PartialEq for Cache<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.pool == o.pool
            && self.hosts == o.hosts
            && self.buckets == o.buckets
            && self.records == o.records
            && self.order == o.order
            && self.limits == o.limits
    }
}
impl Eq for Cache<'_> {}
impl<'a> Cache<'a> {
    /// Initialize borrowed metadata. All mutation errors may leave this staging
    /// cache dirty; the outer service transaction preserves its original owner.
    pub fn new(
        buffers: CacheBuffers<'a>,
        pool: BytePool<'a>,
        limits: Limits,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        buffers.hosts.fill(None);
        buffers.buckets.fill(None);
        buffers.records.fill(None);
        Ok(Self {
            pool,
            hosts: buffers.hosts,
            buckets: buffers.buckets,
            records: buffers.records,
            order: 0,
            limits,
        })
    }
    pub(crate) fn same_geometry(&self, o: &Self) -> bool {
        self.hosts.len() == o.hosts.len()
            && self.buckets.len() == o.buckets.len()
            && self.records.len() == o.records.len()
            && self.pool.same_geometry(&o.pool)
            && self.limits == o.limits
    }
    pub(crate) fn copy_from(&mut self, o: &Self) -> Result<(), Error> {
        if !self.same_geometry(o) {
            return Err(Error::Capacity);
        }
        self.pool.copy_from(&o.pool)?;
        self.hosts.copy_from_slice(o.hosts);
        self.buckets.copy_from_slice(o.buckets);
        self.records.copy_from_slice(o.records);
        self.order = o.order;
        Ok(())
    }
    /// Number of dynamic queried-name buckets.
    pub fn bucket_count(&self) -> usize {
        self.buckets.iter().flatten().count()
    }
    /// Number of retained dynamic records, including unsupported/duplicate data.
    pub fn record_count(&self) -> usize {
        self.records.iter().flatten().count()
    }
    /// Independent native hosts alias count.
    pub fn host_count(&self) -> usize {
        self.hosts.iter().flatten().count()
    }
    /// Actual variable payload bytes, counted once despite multiple retained pins.
    pub fn live_bytes(&self) -> usize {
        self.pool.live_bytes()
    }
    /// Aggregate caller byte capacity.
    pub fn byte_capacity(&self) -> usize {
        self.pool.capacity()
    }
    /// Original small-slot capacity for logical variable-byte objects.
    pub fn blob_capacity(&self) -> usize {
        self.pool.slot_capacity()
    }
    pub(crate) fn name<'n>(&'n self, n: NameRef<'n>) -> Result<&'n [u8], Error> {
        match n {
            NameRef::External(b) => Ok(&b[..b.iter().position(|b| *b == 0).unwrap_or(b.len())]),
            NameRef::Stored(id) => self.pool.get(id),
        }
    }
    pub(crate) fn text(&mut self, bytes: &[u8]) -> Result<BlobId, Error> {
        let b = &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())];
        if b.len() > self.limits.max_name_bytes {
            return Err(Error::Capacity);
        }
        self.pool.copy(b)
    }
    pub(crate) fn release_record(&mut self, r: RecordMeta) -> Result<(), Error> {
        self.pool.release(r.owner)?;
        self.pool.release(r.data)?;
        if let Some(id) = r.target {
            self.pool.release(id)?;
        }
        Ok(())
    }
    fn next_order(&mut self) -> Result<u64, Error> {
        let n = self
            .order
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Overflow)?;
        self.order = n;
        Ok(n)
    }
    /// Copy a native/raw record without reserving maximum width per metadata slot.
    /// Caller uses this only within staging when fallible multi-object allocation
    /// is part of a larger atomic operation.
    pub fn raw_record(
        &mut self,
        owner: &[u8],
        kind: u16,
        class: u16,
        expires: u64,
        bytes: &[u8],
        target: Option<&[u8]>,
    ) -> Result<RecordMeta, Error> {
        if bytes.len() > self.limits.max_record_bytes {
            return Err(Error::Capacity);
        }
        let owner = self.text(owner)?;
        let data = self.pool.copy(bytes)?;
        let target = target.map(|s| self.text(s)).transpose()?;
        Ok(RecordMeta {
            owner,
            kind,
            class,
            expires,
            data,
            target,
        })
    }
    pub(crate) fn project(
        &mut self,
        record: Record<'_>,
        idna: &impl Idna,
        text: &mut TextScratch<'_>,
    ) -> Result<RecordMeta, Error> {
        let n = record
            .name
            .write_native_text(idna, text.work, text.native)?;
        let owner = self.text(&text.native[..n])?;
        let len = record.data.encoded_len()?;
        if len > self.limits.max_record_bytes {
            return Err(Error::Capacity);
        }
        let data = self.pool.allocate(len)?;
        record.data.encode(self.pool.unique_mut(data)?)?;
        let target = if let RData::Hostname(name) = record.data {
            let n = name.write_native_text(idna, text.work, text.native)?;
            Some(self.text(&text.native[..n])?)
        } else {
            None
        };
        Ok(RecordMeta {
            owner,
            kind: record.kind.0,
            class: record.class,
            expires: record.expiration.as_micros(),
            data,
            target,
        })
    }
    /// Borrow an original record payload; it cannot outlive mutable pool access.
    pub fn view(&self, r: RecordMeta) -> Result<RecordView<'_>, Error> {
        Ok(RecordView {
            owner: self.pool.get(r.owner)?,
            kind: r.kind,
            class: r.class,
            expiration: r.expires,
            data: self.pool.get(r.data)?,
            target: r.target.map(|id| self.pool.get(id)).transpose()?,
        })
    }
    pub(crate) fn add_host(&mut self, r: RecordMeta) -> Result<(), Error> {
        if self.hosts.is_empty() || self.hosts.last().is_some_and(Option::is_some) {
            return Err(Error::Capacity);
        }
        for i in (1..self.hosts.len()).rev() {
            self.hosts[i] = self.hosts[i - 1];
        }
        self.hosts[0] = Some(r);
        Ok(())
    }
    /// Source-exact hosts parsing into forever IN raw A/AAAA entries.
    pub fn load_hosts(&mut self, bytes: &[u8]) -> Result<(), Error> {
        for h in HostsFile::new(bytes) {
            let (kind, bytes, len) = match h.address {
                core::net::IpAddr::V4(ip) => {
                    let mut b = [0; 16];
                    b[..4].copy_from_slice(&ip.octets());
                    (1, b, 4)
                }
                core::net::IpAddr::V6(ip) => (28, ip.octets(), 16),
            };
            let r = self.raw_record(h.alias, kind, 1, u64::MAX, &bytes[..len], None)?;
            self.add_host(r)?;
        }
        Ok(())
    }
    fn remove_bucket(&mut self, i: usize) -> Result<(), Error> {
        if let Some(bucket) = self.buckets[i].take() {
            self.pool.release(bucket.key)?;
        }
        for index in 0..self.records.len() {
            if self.records[index].is_some_and(|r| r.bucket == i) {
                let r = self.records[index].take().ok_or(Error::Malformed)?;
                self.release_record(r.record)?;
            }
        }
        Ok(())
    }
    /// Source pre-packet eviction is strictly >1024, not >= and not record count.
    pub fn begin_batch(&mut self) -> Result<(), Error> {
        while self.bucket_count() > MAX_CACHE {
            let tail = self
                .buckets
                .iter()
                .enumerate()
                .filter_map(|(i, b)| b.map(|b| (b.lru, i)))
                .min();
            let Some((_, i)) = tail else { break };
            self.remove_bucket(i)?;
        }
        Ok(())
    }
    pub(crate) fn insert(&mut self, key: BlobId, record: RecordMeta) -> Result<(), Error> {
        let r = self
            .records
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let mut existing = None;
        for (i, b) in self.buckets.iter().enumerate() {
            if let Some(b) = b
                && self
                    .pool
                    .get(b.key)?
                    .eq_ignore_ascii_case(self.pool.get(key)?)
            {
                existing = Some(i);
                break;
            }
        }
        let i = existing
            .or_else(|| self.buckets.iter().position(Option::is_none))
            .ok_or(Error::Capacity)?;
        let order = self.next_order()?;
        if existing.is_none() {
            self.pool.retain(key)?;
            self.buckets[i] = Some(BucketMeta { key, lru: order });
        }
        self.records[r] = Some(RecordEntry {
            record,
            bucket: i,
            order,
        });
        Ok(())
    }
    /// Test/embedding native-record insertion. The service result path projects
    /// actual parsed records instead; this does not invent official config keys.
    #[expect(
        clippy::too_many_arguments,
        reason = "Lossless source record fields and independent native cache key are explicit."
    )]
    pub fn insert_raw(
        &mut self,
        key: &[u8],
        owner: &[u8],
        kind: u16,
        class: u16,
        expires: u64,
        bytes: &[u8],
        target: Option<&[u8]>,
    ) -> Result<(), Error> {
        let key = self.text(key)?;
        let r = self.raw_record(owner, kind, class, expires, bytes, target)?;
        self.insert(key, r)?;
        self.pool.release(key)
    }
    fn matches(&self, r: RecordMeta, name: NameRef<'_>, desired: u16) -> Result<bool, Error> {
        Ok(self.pool.get(r.owner)? == self.name(name)?
            && match r.kind {
                1 | 28 => desired == r.kind || desired == 255,
                5 | 12 => desired == r.kind,
                _ => false,
            })
    }
    fn follow(&mut self, r: RecordMeta) -> Result<Hit, Error> {
        let target = r.target.ok_or(Error::Malformed)?;
        self.pool.retain(target)?;
        Ok(Hit::Follow(target))
    }
    /// Search the source hosts/bucket/record order. Callback receives small
    /// metadata and mutable pool, so it can retain an output pin before later
    /// cache expiry/LRU release. Follow also transfers one explicit target pin.
    pub fn lookup(
        &mut self,
        name: NameRef<'_>,
        desired: u16,
        now: AbsoluteTime,
        mut emit: impl FnMut(RecordMeta, &mut BytePool<'_>) -> Result<(), Error>,
    ) -> Result<Hit, Error> {
        for h in self.hosts.iter().flatten().copied() {
            if self.pool.get(h.owner)? == self.name(name)? {
                if h.kind == 5 && desired != 5 {
                    return self.follow(h);
                }
                if self.matches(h, name, desired)? {
                    emit(h, &mut self.pool)?;
                    return Ok(Hit::Rows);
                }
                return Ok(Hit::Miss);
            }
        }
        let mut previous = u64::MAX;
        let mut chosen = None;
        loop {
            let next = self
                .buckets
                .iter()
                .enumerate()
                .filter_map(|(i, b)| b.filter(|b| b.lru < previous).map(|b| (b.lru, i)))
                .max();
            let Some((order, i)) = next else { break };
            previous = order;
            for r in 0..self.records.len() {
                if self.records[r]
                    .is_some_and(|r| r.bucket == i && now.as_micros() > r.record.expires)
                {
                    let entry = self.records[r].take().ok_or(Error::Malformed)?;
                    self.release_record(entry.record)?;
                }
            }
            if !self.records.iter().flatten().any(|r| r.bucket == i) {
                self.remove_bucket(i)?;
                continue;
            }
            if let Some(bucket) = self.buckets[i]
                && self.pool.get(bucket.key)? == self.name(name)?
            {
                chosen = Some(i);
                break;
            }
        }
        let Some(i) = chosen else {
            return Ok(Hit::Miss);
        };
        let lru = self.next_order()?;
        self.buckets[i].as_mut().ok_or(Error::Malformed)?.lru = lru;
        let mut found = false;
        let mut previous = u64::MAX;
        loop {
            let next = self
                .records
                .iter()
                .flatten()
                .filter(|r| r.bucket == i && r.order < previous)
                .max_by_key(|r| r.order)
                .copied();
            let Some(entry) = next else { break };
            previous = entry.order;
            let r = entry.record;
            if r.kind == 5 && desired != 5 && !found {
                return self.follow(r);
            }
            if self.matches(r, name, desired)? {
                emit(r, &mut self.pool)?;
                found = true;
            }
        }
        Ok(if found { Hit::Rows } else { Hit::Miss })
    }
    /// Borrow the retained target returned by Hit::Follow.
    pub fn follow_text(&self, id: BlobId) -> Result<&[u8], Error> {
        self.pool.get(id)
    }
    /// Release exactly the target pin transferred by Hit::Follow, after copying
    /// or handing it to the next lookup owner.
    pub fn release_follow(&mut self, id: BlobId) -> Result<(), Error> {
        self.pool.release(id)
    }
    /// Reclaim owned cache pins only; separately queued outputs retain theirs.
    pub fn clear(&mut self) -> Result<(), Error> {
        for i in 0..self.hosts.len() {
            if let Some(r) = self.hosts[i].take() {
                self.release_record(r)?;
            }
        }
        for i in 0..self.buckets.len() {
            self.remove_bucket(i)?;
        }
        self.order = 0;
        Ok(())
    }
}
