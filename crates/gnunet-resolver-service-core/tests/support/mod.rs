//! Host-only safe backing and owned observation adapters for semantic fixtures.
#![expect(
    dead_code,
    reason = "Shared helpers are used by separate cache/lifecycle/pooled integration suites with different subsets."
)]
use gnunet_client::resolver::{Request, WireId};
use gnunet_dns::{AbsoluteTime, Idna, Packet};
use gnunet_dnsstub::{Admission, RequestId as StubId};
use gnunet_resolver_service_core::{
    cache::{BucketMeta, CacheBuffers, RecordEntry, RecordMeta},
    lookup::Name,
    owner as real,
    pool::BlobSlot,
    storage::{Limits, TextScratch},
};
use gnunet_types::{Error, MonoInstant};
pub use real::{ClientId, Disposition, LookupId};
pub const DNS_TIMEOUT: u64 = real::DNS_TIMEOUT;
fn vector<T>(n: usize, mut value: impl FnMut() -> T) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    v.resize_with(n, &mut value);
    Ok(v)
}
pub struct Store {
    clients: Vec<real::ClientSlot>,
    lookups: Vec<real::LookupSlot>,
    hosts: Vec<Option<RecordMeta>>,
    buckets: Vec<Option<BucketMeta>>,
    records: Vec<Option<RecordEntry>>,
    effects: Vec<real::EffectSlot>,
    cleanups: Vec<Option<StubId>>,
    blobs: Vec<BlobSlot>,
    bytes: Vec<u8>,
}
impl Store {
    pub fn new(g: [usize; 6], byte_count: usize) -> Result<Self, Error> {
        let [c, l, h, k, m, e] = g;
        let objects = m
            .checked_mul(3)
            .and_then(|n| n.checked_add(h * 3 + k + l * 2 + e + 64))
            .ok_or(Error::Overflow)?;
        Ok(Self {
            clients: vector(c, || real::ClientSlot::EMPTY)?,
            lookups: vector(l, || real::LookupSlot::EMPTY)?,
            hosts: vector(h, || None)?,
            buckets: vector(k, || None)?,
            records: vector(m, || None)?,
            effects: vector(e, || real::EffectSlot::EMPTY)?,
            cleanups: vector(l, || None)?,
            blobs: vector(objects, || BlobSlot::EMPTY)?,
            bytes: vector(byte_count, || 0)?,
        })
    }
    pub fn buffers(&mut self) -> real::Buffers<'_> {
        real::Buffers {
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
    pub fn allocated_bytes(&self) -> usize {
        self.clients.capacity() * core::mem::size_of::<real::ClientSlot>()
            + self.lookups.capacity() * core::mem::size_of::<real::LookupSlot>()
            + self.hosts.capacity() * core::mem::size_of::<Option<RecordMeta>>()
            + self.buckets.capacity() * core::mem::size_of::<Option<BucketMeta>>()
            + self.records.capacity() * core::mem::size_of::<Option<RecordEntry>>()
            + self.effects.capacity() * core::mem::size_of::<real::EffectSlot>()
            + self.cleanups.capacity() * core::mem::size_of::<Option<StubId>>()
            + self.blobs.capacity() * core::mem::size_of::<BlobSlot>()
            + self.bytes.capacity()
    }
}
pub struct Memory<const N: usize, const B: usize> {
    pub owner: Store,
    pub stage: Store,
    pub baseline: Store,
    pub limits: Limits,
}
impl<const N: usize, const B: usize> Memory<N, B> {
    pub fn new(g: [usize; 6], hops: usize, bytes: usize) -> Result<Self, Error> {
        Ok(Self {
            owner: Store::new(g, bytes)?,
            stage: Store::new(g, bytes)?,
            baseline: Store::new(g, bytes)?,
            limits: Limits {
                max_name_bytes: N,
                max_record_bytes: B,
                cname_hops: hops,
            },
        })
    }
    pub fn raw_views(
        &mut self,
        epoch: u64,
    ) -> Result<(real::Resolver<'_>, real::Scratch<'_>, real::Scratch<'_>), Error> {
        let c = real::Resolver::new(self.owner.buffers(), self.limits, epoch)?;
        let s = c.make_scratch(self.stage.buffers())?;
        let before = c.make_scratch(self.baseline.buffers())?;
        Ok((c, s, before))
    }
    pub fn views(&mut self, epoch: u64) -> Result<(Core<'_, N, B>, Stage<'_>, Stage<'_>), Error> {
        let (c, s, b) = self.raw_views(epoch)?;
        Ok((Core { inner: c }, Stage { inner: s }, Stage { inner: b }))
    }
}
pub struct Stage<'a> {
    pub inner: real::Scratch<'a>,
}
impl PartialEq for Stage<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.inner == o.inner
    }
}
impl Eq for Stage<'_> {}
pub struct Core<'a, const N: usize, const B: usize> {
    pub inner: real::Resolver<'a>,
}
impl<const N: usize, const B: usize> PartialEq<Stage<'_>> for Core<'_, N, B> {
    fn eq(&self, o: &Stage<'_>) -> bool {
        self.inner == o.inner
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Payload<const N: usize, const B: usize> {
    End,
    Raw { bytes: [u8; B], len: usize },
    Hostname(Name<N>),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output<const N: usize, const B: usize> {
    pub client: ClientId,
    pub wire_id: WireId,
    pub payload: Payload<N, B>,
}
impl<const N: usize, const B: usize> Output<N, B> {
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let payload = match &self.payload {
            Payload::End => real::Payload::End,
            Payload::Raw { bytes, len } => {
                real::Payload::Raw(bytes.get(..*len).ok_or(Error::Malformed)?)
            }
            Payload::Hostname(n) => real::Payload::Hostname(n.bytes()),
        };
        real::Output {
            client: self.client,
            wire_id: self.wire_id,
            payload,
        }
        .encode(out)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartQuery<const N: usize> {
    pub lookup: LookupId,
    pub client: ClientId,
    pub hostname: Name<N>,
    pub kind: u16,
    pub deadline: MonoInstant,
    bytes: [u8; 271],
    len: usize,
}
impl<const N: usize> StartQuery<N> {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "Test-only Copy observation DTO keeps the real fixed DNS query visible without heap indirection."
)]
pub enum Effect<const N: usize, const B: usize> {
    Output(Output<N, B>),
    StartQuery(StartQuery<N>),
    CancelQuery(StubId),
    DropClient { client: ClientId, reason: Error },
    Stop,
    ObservationError(Error),
}
fn copied<const N: usize, const B: usize>(v: real::Effect<'_>) -> Result<Effect<N, B>, Error> {
    Ok(match v {
        real::Effect::Output(o) => Effect::Output(Output {
            client: o.client,
            wire_id: o.wire_id,
            payload: match o.payload {
                real::Payload::End => Payload::End,
                real::Payload::Hostname(n) => Payload::Hostname(Name::from_c_prefix(n)?),
                real::Payload::Raw(b) => {
                    if b.len() > B {
                        return Err(Error::Capacity);
                    }
                    let mut bytes = [0; B];
                    bytes[..b.len()].copy_from_slice(b);
                    Payload::Raw {
                        bytes,
                        len: b.len(),
                    }
                }
            },
        }),
        real::Effect::StartQuery(q) => {
            let mut bytes = [0; 271];
            bytes[..q.bytes.len()].copy_from_slice(q.bytes);
            Effect::StartQuery(StartQuery {
                lookup: q.lookup,
                client: q.client,
                hostname: Name::from_c_prefix(q.hostname)?,
                kind: q.kind,
                deadline: q.deadline,
                bytes,
                len: q.bytes.len(),
            })
        }
        real::Effect::CancelQuery(t) => Effect::CancelQuery(t),
        real::Effect::DropClient { client, reason } => Effect::DropClient { client, reason },
        real::Effect::Stop => Effect::Stop,
    })
}
impl<'a, const N: usize, const B: usize> Core<'a, N, B> {
    pub fn connect(&mut self) -> Result<ClientId, Error> {
        self.inner.connect()
    }
    pub fn copy_logical_state_to(&self, s: &mut Stage<'a>) -> Result<(), Error> {
        self.inner.copy_logical_state_to(&mut s.inner)
    }
    pub fn cache(&self) -> &gnunet_resolver_service_core::cache::Cache<'a> {
        self.inner.cache()
    }
    pub fn owns_client(&self, id: ClientId) -> bool {
        self.inner.owns_client(id)
    }
    pub fn owns_lookup(&self, id: LookupId) -> bool {
        self.inner.owns_lookup(id)
    }
    pub fn lookup_count(&self) -> usize {
        self.inner.lookup_count()
    }
    pub fn lookup_stub(&self, id: LookupId) -> Result<Option<StubId>, Error> {
        self.inner.lookup_stub(id)
    }
    pub fn lookup_deadline(&self, id: LookupId) -> Result<MonoInstant, Error> {
        self.inner.lookup_deadline(id)
    }
    pub fn next_wakeup(&self) -> Option<MonoInstant> {
        self.inner.next_wakeup()
    }
    pub fn pending_cleanups(&self) -> usize {
        self.inner.pending_cleanups()
    }
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
    pub fn effect_count(&self) -> usize {
        let leased_query = self
            .inner
            .current_effect()
            .and_then(|t| self.inner.effect(t).ok())
            .is_some_and(|e| matches!(e, real::Effect::StartQuery(_)));
        self.inner.effect_count() - usize::from(leased_query)
    }
    pub fn take_effect(&mut self) -> Option<Effect<N, B>> {
        let observed = (|| {
            let Some(t) = self.inner.take_effect()? else {
                return Ok(None);
            };
            let value = copied(self.inner.effect(t)?)?;
            if !matches!(value, Effect::StartQuery(_)) {
                self.inner.release_effect(t)?;
            }
            Ok(Some(value))
        })();
        match observed {
            Ok(v) => v,
            Err(e) => Some(Effect::ObservationError(e)),
        }
    }
    pub fn load_machine_files(
        &mut self,
        s: &mut Stage<'a>,
        h: &[u8],
        r: &[u8],
    ) -> Result<(), Error> {
        self.inner.load_machine_files(&mut s.inner, h, r)
    }
    pub fn set_search(&mut self, s: &mut Stage<'a>, v: Option<&[u8]>) -> Result<(), Error> {
        self.inner.set_search(&mut s.inner, v)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Baseline semantic fixture adapter names independent explicit clock, entropy and IDNA ports; production bundles Evaluation."
    )]
    pub fn request(
        &mut self,
        s: &mut Stage<'a>,
        c: ClientId,
        r: Request<'_>,
        mono: MonoInstant,
        utc: AbsoluteTime,
        mut random: impl FnMut(u32) -> Result<u32, Error>,
        idna: &impl Idna,
    ) -> Result<Option<LookupId>, Error> {
        let mut native = vector(N.max(1), || 0)?;
        let mut work = vector(N.max(1), || 0)?;
        let mut wire = [0; 255];
        let mut p = real::Evaluation {
            mono,
            utc,
            idna,
            random: &mut random,
            text: TextScratch {
                native: &mut native,
                work: &mut work,
                wire_name: &mut wire,
            },
        };
        self.inner.request(&mut s.inner, c, r, &mut p)
    }
    pub fn query_admitted(
        &mut self,
        s: &mut Stage<'a>,
        id: LookupId,
        a: Admission,
    ) -> Result<(), Error> {
        self.inner.query_admitted(&mut s.inner, id, a)?;
        if let Some(t) = self.inner.current_effect()
            && matches!(self.inner.effect(t)?,real::Effect::StartQuery(q)if q.lookup==id)
        {
            self.inner.release_effect(t)?;
        }
        Ok(())
    }
    pub fn query_unavailable(&mut self, s: &mut Stage<'a>, id: LookupId) -> Result<(), Error> {
        self.inner.query_unavailable(&mut s.inner, id)?;
        if let Some(t) = self.inner.current_effect()
            && matches!(self.inner.effect(t)?,real::Effect::StartQuery(q)if q.lookup==id)
        {
            self.inner.release_effect(t)?;
        }
        Ok(())
    }
    pub fn malformed_dns(&self, id: LookupId, stub: StubId) -> Result<Disposition, Error> {
        self.inner.malformed_dns(id, stub)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Baseline fixture adapter preserves explicit response, clock and capability arguments; production bundles Evaluation."
    )]
    pub fn dns_result(
        &mut self,
        s: &mut Stage<'a>,
        id: LookupId,
        stub: StubId,
        packet: Packet<'_, '_>,
        mono: MonoInstant,
        utc: AbsoluteTime,
        mut random: impl FnMut(u32) -> Result<u32, Error>,
        idna: &impl Idna,
    ) -> Result<Disposition, Error> {
        let mut native = vector(N.max(1), || 0)?;
        let mut work = vector(N.max(1), || 0)?;
        let mut wire = [0; 255];
        let mut p = real::Evaluation {
            mono,
            utc,
            idna,
            random: &mut random,
            text: TextScratch {
                native: &mut native,
                work: &mut work,
                wire_name: &mut wire,
            },
        };
        self.inner
            .dns_result(&mut s.inner, id, stub, packet, &mut p)
    }
    pub fn tick(&mut self, s: &mut Stage<'a>, now: MonoInstant) -> Result<usize, Error> {
        self.inner.tick(&mut s.inner, now)
    }
    pub fn disconnect(&mut self, s: &mut Stage<'a>, id: ClientId) -> Result<(), Error> {
        self.inner.disconnect(&mut s.inner, id)
    }
    pub fn begin_soft_shutdown(&mut self, s: &mut Stage<'a>) -> Result<(), Error> {
        self.inner.begin_soft_shutdown(&mut s.inner)
    }
    pub fn shutdown(&mut self, s: &mut Stage<'a>) -> Result<(), Error> {
        self.inner.shutdown(&mut s.inner)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredRecord<const N: usize, const B: usize> {
    owner: Name<N>,
    kind: u16,
    class: u16,
    expires: u64,
    bytes: [u8; B],
    len: usize,
    target: Option<Name<N>>,
}
impl<const N: usize, const B: usize> StoredRecord<N, B> {
    pub fn raw(
        owner: &[u8],
        kind: u16,
        class: u16,
        expires: u64,
        data: &[u8],
    ) -> Result<Self, Error> {
        if data.len() > B {
            return Err(Error::Capacity);
        }
        let mut bytes = [0; B];
        bytes[..data.len()].copy_from_slice(data);
        Ok(Self {
            owner: Name::from_c_prefix(owner)?,
            kind,
            class,
            expires,
            bytes,
            len: data.len(),
            target: None,
        })
    }
    pub fn hostname(
        owner: &[u8],
        kind: u16,
        class: u16,
        expires: u64,
        target: &[u8],
    ) -> Result<Self, Error> {
        let mut v = Self::raw(owner, kind, class, expires, &[])?;
        v.target = Some(Name::from_c_prefix(target)?);
        Ok(v)
    }
    pub fn raw_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
    pub fn class(&self) -> u16 {
        self.class
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Hit<const N: usize> {
    Miss,
    Rows,
    Follow(Name<N>),
}
pub struct CacheMemory<
    const H: usize,
    const K: usize,
    const M: usize,
    const N: usize,
    const B: usize,
> {
    store: Store,
}
impl<const H: usize, const K: usize, const M: usize, const N: usize, const B: usize>
    CacheMemory<H, K, M, N, B>
{
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            store: Store::new([1, 1, H, K, M, 1], 65536)?,
        })
    }
    pub fn view(&mut self) -> Result<CacheView<'_, N, B>, Error> {
        let pool = gnunet_resolver_service_core::pool::BytePool::new(
            &mut self.store.blobs,
            &mut self.store.bytes,
            1,
        )?;
        let inner = gnunet_resolver_service_core::cache::Cache::new(
            CacheBuffers {
                hosts: &mut self.store.hosts,
                buckets: &mut self.store.buckets,
                records: &mut self.store.records,
            },
            pool,
            Limits {
                max_name_bytes: N,
                max_record_bytes: B,
                cname_hops: 8,
            },
        )?;
        Ok(CacheView { inner })
    }
}
pub struct CacheView<'a, const N: usize, const B: usize> {
    inner: gnunet_resolver_service_core::cache::Cache<'a>,
}
impl<const N: usize, const B: usize> CacheView<'_, N, B> {
    pub fn begin_batch(&mut self) -> Result<(), Error> {
        self.inner.begin_batch()
    }
    pub fn insert(&mut self, key: &[u8], r: StoredRecord<N, B>) -> Result<(), Error> {
        self.inner.insert_raw(
            key,
            r.owner.bytes(),
            r.kind,
            r.class,
            r.expires,
            r.raw_bytes(),
            r.target.as_ref().map(Name::bytes),
        )
    }
    pub fn load_hosts(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.inner.load_hosts(bytes)
    }
    pub fn bucket_count(&self) -> usize {
        self.inner.bucket_count()
    }
    pub fn record_count(&self) -> usize {
        self.inner.record_count()
    }
    pub fn host_count(&self) -> usize {
        self.inner.host_count()
    }
    pub fn clear(&mut self) -> Result<(), Error> {
        self.inner.clear()
    }
    pub fn lookup(
        &mut self,
        name: &[u8],
        desired: u16,
        utc: AbsoluteTime,
        mut emit: impl FnMut(&StoredRecord<N, B>) -> Result<(), Error>,
    ) -> Result<Hit<N>, Error> {
        let hit = self.inner.lookup(
            gnunet_resolver_service_core::cache::NameRef::External(name),
            desired,
            utc,
            |meta, pool| {
                let r = meta.view(pool)?;
                let mut copied = StoredRecord::raw(r.owner, r.kind, r.class, r.expiration, r.data)?;
                copied.target = r.target.map(Name::from_c_prefix).transpose()?;
                emit(&copied)
            },
        )?;
        Ok(match hit {
            gnunet_resolver_service_core::cache::Hit::Miss => Hit::Miss,
            gnunet_resolver_service_core::cache::Hit::Rows => Hit::Rows,
            gnunet_resolver_service_core::cache::Hit::Follow(id) => {
                let name = Name::from_c_prefix(self.inner.follow_text(id)?)?;
                self.inner.release_follow(id)?;
                Hit::Follow(name)
            }
        })
    }
}
