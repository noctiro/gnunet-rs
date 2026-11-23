//! Borrowed-buffer Resolver owner. Metadata/payload storage belongs to the caller;
//! no maximum-width record arrays or allocator are hidden in this core.
//! All fallible business transitions use a distinct typed Scratch. Errors leave
//! the owner unchanged; scratch may be dirty. Effects retain local byte leases
//! until release after host copying/admission; release is never a remote ACK.
use crate::{
    cache::{Cache, CacheBuffers, Hit, NameRef},
    pool::{BlobId, BlobSlot, BytePool},
    storage::{Limits, TextScratch},
};
use core::net::IpAddr;
use gnunet_client::resolver::{Family, Query as ResolverQuery, Request, WireId};
use gnunet_dns::{
    AbsoluteTime, Arena, Idna, Limits as DnsLimits, Name as DnsName, Packet, Query, Type,
};
use gnunet_dnsstub::{Admission, RequestId as StubId};
use gnunet_types::{Error, GenerationalId, MonoInstant};
use gnunet_wire::official::{MessageHeader, message_type};
mod system;
pub use system::{SystemAnswer, SystemQuery, SystemQuestion};

/// Official service lookup duration, microseconds.
pub const DNS_TIMEOUT: u64 = 30_000_000;
/// Maximum complete uncompressed DNS query bytes, independently of RDATA width.
pub const QUERY_BYTES: usize = 271;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PairId {
    epoch: u64,
    origin: usize,
}
/// Original local service client identity; never a wire protocol field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientId {
    scope: PairId,
    id: GenerationalId,
}
/// Original lookup identity, independent from duplicate opaque client IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupId {
    scope: PairId,
    id: GenerationalId,
}
impl ClientId {
    /// Original internal slot/generation.
    pub const fn resource_id(self) -> GenerationalId {
        self.id
    }
}
impl LookupId {
    /// Original internal slot/generation.
    pub const fn resource_id(self) -> GenerationalId {
        self.id
    }
}
/// Scoped original effect ownership ticket, not a send/remote completion token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectTicket {
    scope: PairId,
    serial: u64,
}
/// One original DNS exchange admitted by an external native transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeDnsId {
    lookup: LookupId,
    ticket: EffectTicket,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Slot {
    current: u32,
    next: Option<u32>,
    active: bool,
}
impl Slot {
    const EMPTY: Self = Self {
        current: 0,
        next: Some(0),
        active: false,
    };
    fn allocate(&mut self) -> Result<u32, Error> {
        let n = self.next.ok_or(Error::Capacity)?;
        self.current = n;
        self.next = n.checked_add(1);
        self.active = true;
        Ok(n)
    }
}
/// Small caller-owned client slot. Closing has reserved capacity independent of
/// ordinary output backpressure, and prevents reuse before physical close release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientSlot {
    id: Slot,
    closing: Option<Error>,
}
impl ClientSlot {
    /// Vacant metadata for Vec::resize_with or a static slice.
    pub const EMPTY: Self = Self {
        id: Slot::EMPTY,
        closing: None,
    };
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpPhase {
    Queued,
    AwaitAdmission,
    Active(Option<DnsOwner>),
    UpstreamChanged,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnsOwner {
    Stub(StubId),
    Native(NativeDnsId),
}

impl DnsOwner {
    const fn cancellation(self) -> QueryCancellation {
        match self {
            Self::Stub(id) => QueryCancellation::Stub(id),
            Self::Native(id) => QueryCancellation::NativeDns(id),
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SystemPhase {
    Queued,
    AwaitAdmission,
    Active,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookupName {
    Original(BlobId),
    Cname { original: BlobId, target: BlobId },
}
impl LookupName {
    const fn current(self) -> BlobId {
        match self {
            Self::Original(name) | Self::Cname { target: name, .. } => name,
        }
    }
    const fn original(self) -> BlobId {
        match self {
            Self::Original(name) | Self::Cname { original: name, .. } => name,
        }
    }
    fn forget_target(&mut self, pool: &mut BytePool<'_>) -> Result<(), Error> {
        if let Self::Cname { original, target } = *self {
            pool.release(target)?;
            *self = Self::Original(original);
        }
        Ok(())
    }
    fn release(mut self, pool: &mut BytePool<'_>) -> Result<(), Error> {
        self.forget_target(pool)?;
        pool.release(self.original())
    }
}
#[derive(Clone, Copy)]
enum LookupStart<'a> {
    Client(&'a [u8]),
    Cname { original: BlobId, target: BlobId },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UdpLookup {
    name: LookupName,
    desired: u16,
    second: bool,
    dns_id: [u8; 2],
    phase: UdpPhase,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredSystemQuestion {
    Forward { family: Family, hostname: BlobId },
    Reverse(IpAddr),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookupSource {
    Udp(UdpLookup),
    System {
        question: StoredSystemQuestion,
        phase: SystemPhase,
    },
}
impl LookupSource {
    fn release(self, pool: &mut BytePool<'_>) -> Result<(), Error> {
        match self {
            Self::Udp(udp) => udp.name.release(pool),
            Self::System {
                question: StoredSystemQuestion::Forward { hostname, .. },
                ..
            } => pool.release(hostname),
            Self::System {
                question: StoredSystemQuestion::Reverse(_),
                ..
            } => Ok(()),
        }
    }

    fn await_admission(&mut self) -> Result<(), Error> {
        match self {
            Self::Udp(udp) if udp.phase == UdpPhase::Queued => {
                udp.phase = UdpPhase::AwaitAdmission;
            }
            Self::System { phase, .. } if *phase == SystemPhase::Queued => {
                *phase = SystemPhase::AwaitAdmission;
            }
            _ => return Err(Error::Conflict),
        }
        Ok(())
    }

    fn admission_pending(self) -> bool {
        matches!(
            self,
            Self::Udp(UdpLookup {
                phase: UdpPhase::AwaitAdmission,
                ..
            }) | Self::System {
                phase: SystemPhase::AwaitAdmission,
                ..
            }
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Active {
    client: ClientId,
    wire: WireId,
    source: LookupSource,
    deadline: MonoInstant,
    order: u64,
}
/// Small caller-owned lookup metadata, without an inline native-name buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupSlot {
    id: Slot,
    value: Option<Active>,
}
impl LookupSlot {
    /// Vacant metadata for safe caller initialization.
    pub const EMPTY: Self = Self {
        id: Slot::EMPTY,
        value: None,
    };
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StoredPayload {
    End,
    Raw(BlobId),
    Hostname(BlobId),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "Only the fixed271-byte DNS question is inline; variable RDATA/native text are spans, not maximum-width arrays."
)]
enum StoredEffect {
    Output {
        client: ClientId,
        wire: WireId,
        payload: StoredPayload,
    },
    Query {
        lookup: LookupId,
        client: ClientId,
        name: BlobId,
        kind: u16,
        deadline: MonoInstant,
        bytes: [u8; QUERY_BYTES],
        len: usize,
    },
    SystemQuery {
        lookup: LookupId,
        client: ClientId,
    },
    Cancel(QueryCancellation),
    Close {
        client: ClientId,
        reason: Error,
    },
    Stop,
}
impl StoredEffect {
    fn query_lookup(self) -> Option<LookupId> {
        match self {
            Self::Query { lookup, .. } | Self::SystemQuery { lookup, .. } => Some(lookup),
            _ => None,
        }
    }
}
/// Small fixed-question/effect metadata slot. No per-record RDATA reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectSlot {
    value: Option<StoredEffect>,
}
impl EffectSlot {
    /// Vacant metadata for caller vector/static initialization.
    pub const EMPTY: Self = Self { value: None };
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InFlight {
    serial: u64,
    effect: StoredEffect,
}
/// Borrowed real response payload, without an independently forgeable raw length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Payload<'a> {
    /// Final daemon response has no payload.
    End,
    /// Exact raw A/AAAA data; no fabricated address width validation.
    Raw(&'a [u8]),
    /// Native PTR hostname before one appended NUL.
    Hostname(&'a [u8]),
}
/// Response5 view tied to original client generation and unchanged opaque ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output<'a> {
    /// Original physical client identity.
    pub client: ClientId,
    /// Four native opaque echo bytes.
    pub wire_id: WireId,
    /// Borrowed pinned result bytes.
    pub payload: Payload<'a>,
}
impl Output<'_> {
    /// Preflight frame length before any mutation; oversized/short-output errors
    /// leave destination unchanged. No application status/cancel field is added.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let n = match self.payload {
            Payload::End => 0,
            Payload::Raw(b) => b.len(),
            Payload::Hostname(b) => b.len().checked_add(1).ok_or(Error::Overflow)?,
        };
        let size = 8usize.checked_add(n).ok_or(Error::Overflow)?;
        let h = MessageHeader::from_total_size(message_type::RESOLVER_RESPONSE, size)?;
        if out.len() < size {
            return Err(Error::Capacity);
        }
        h.encode(out)?;
        out[4..8].copy_from_slice(&self.wire_id.0);
        match self.payload {
            Payload::End => {}
            Payload::Raw(b) => out[8..size].copy_from_slice(b),
            Payload::Hostname(b) => {
                out[8..size - 1].copy_from_slice(b);
                out[size - 1] = 0;
            }
        }
        Ok(size)
    }
}
/// Borrowed official DNS query view. Stub resolve copies these bytes before host
/// reports admission and releases the local effect ticket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StartQuery<'a> {
    /// Original lookup generation.
    pub lookup: LookupId,
    /// Original client generation.
    pub client: ClientId,
    /// Native effective query name, pinned independently of cache.
    pub hostname: &'a [u8],
    /// A/AAAA/PTR question type.
    pub kind: u16,
    /// Original30s deadline shared by Any phases.
    pub deadline: MonoInstant,
    /// Complete official DNS packet, with no private fields.
    pub bytes: &'a [u8],
}
/// Exact original backend association to retire through reserved cleanup storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryCancellation {
    /// DNSSTUB request generation.
    Stub(StubId),
    /// Actual connected native DNS exchange generation.
    NativeDns(NativeDnsId),
    /// Native lookup generation.
    System(LookupId),
}
/// One effect view borrowed for immediate local execution/copy only. Do not hold
/// this borrow across await: copy into a real bounded TX queue before release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Effect<'a> {
    /// Genuine result or END.
    Output(Output<'a>),
    /// Packed query requiring real stub admission.
    StartQuery(StartQuery<'a>),
    /// Query requiring real native system admission.
    StartSystemQuery(SystemQuery<'a>),
    /// Exact original stub generation to cancel.
    CancelQuery(StubId),
    /// Cancel the original native DNS exchange, without affecting replacement.
    CancelNativeDns(NativeDnsId),
    /// Cancel the exact native lookup.
    CancelSystemQuery(LookupId),
    /// Close this original client, not a replacement generation.
    DropClient {
        /// Original client.
        client: ClientId,
        /// Actual source/resource failure.
        reason: Error,
    },
    /// Stop real stub/client owners; no remote flush claim.
    Stop,
}
/// Explicit caller clocks, entropy, native backend and temporary text storage.
/// No field is an OS resolver or production fallback backend.
pub struct Evaluation<'a, I: Idna, R: FnMut(u32) -> Result<u32, Error>> {
    /// Current monotonic service time.
    pub mono: MonoInstant,
    /// Current absolute TTL time.
    pub utc: AbsoluteTime,
    /// Complete explicitly selected native IDNA capability.
    pub idna: &'a I,
    /// Unbiased integer source below the supplied bound.
    pub random: &'a mut R,
    /// Independent caller temporary conversion buffers.
    pub text: TextScratch<'a>,
}
/// How an actual parsed datagram affected its original lookup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Parser failure or mismatching transaction ID.
    Ignored,
    /// First nonempty Any result cached; original deadline remains.
    AwaitingAaaa,
    /// Original lookup retired; output or CNAME continuation is queued.
    Completed,
}
/// All caller storage, independently allocated with safe vector reserve/resize or
/// static slices. No self-referential backing+core structure is necessary.
pub struct Buffers<'a> {
    /// At least one physical client metadata slot.
    pub clients: &'a mut [ClientSlot],
    /// At least one active lookup metadata slot.
    pub lookups: &'a mut [LookupSlot],
    /// Hosts/bucket/record metadata.
    pub cache: CacheBuffers<'a>,
    /// At least one ordinary effect metadata slot.
    pub effects: &'a mut [EffectSlot],
    /// Reserved cancel slots, at least lookup count.
    pub cleanups: &'a mut [Option<QueryCancellation>],
    /// Variable-byte object metadata, independent from max RDATA width.
    pub blobs: &'a mut [BlobSlot],
    /// Aggregate initialized byte storage, not per-record capacity.
    pub bytes: &'a mut [u8],
}
#[derive(PartialEq, Eq)]
struct State<'a> {
    clients: &'a mut [ClientSlot],
    lookups: &'a mut [LookupSlot],
    cache: Cache<'a>,
    effects: &'a mut [EffectSlot],
    used: usize,
    cleanups: &'a mut [Option<QueryCancellation>],
    cleanup_used: usize,
    current: Option<InFlight>,
    ticket_serial: u64,
    search: Option<BlobId>,
    search_ignored: bool,
    order: u64,
    soft: bool,
    closed: bool,
}
/// Small logical owner borrowing all metadata/byte buffers. The caller keeps
/// backing vectors/static arrays alive outside the host driver/reactor.
pub struct Resolver<'a> {
    scope: PairId,
    limits: Limits,
    state: State<'a>,
}
/// Typed staging/snapshot storage. It has no connect/request/effect/IO ports and
/// therefore cannot accidentally be another live service owner during commit.
///
/// The type has no client admission authority:
///
/// ```compile_fail,E0599
/// use gnunet_resolver_service_core::owner::Scratch;
/// fn cannot_connect(scratch: &mut Scratch<'_>) {
///     scratch.connect();
/// }
/// ```
///
/// Matching backing is supplied from a separate caller allocation:
///
/// ```
/// use gnunet_resolver_service_core::owner::{Buffers, Resolver, Scratch};
/// use gnunet_types::Error;
/// fn staging<'a>(owner: &Resolver<'a>, backing: Buffers<'a>) -> Result<Scratch<'a>, Error> {
///     owner.make_scratch(backing)
/// }
/// ```
pub struct Scratch<'a> {
    scope: PairId,
    limits: Limits,
    state: State<'a>,
}
impl PartialEq<Scratch<'_>> for Resolver<'_> {
    fn eq(&self, o: &Scratch<'_>) -> bool {
        self.scope == o.scope && self.limits == o.limits && self.state == o.state
    }
}
impl PartialEq for Scratch<'_> {
    fn eq(&self, o: &Self) -> bool {
        self.scope == o.scope && self.limits == o.limits && self.state == o.state
    }
}
impl Eq for Scratch<'_> {}
impl<'a> State<'a> {
    fn new(b: Buffers<'a>, limits: Limits, epoch: u64) -> Result<Self, Error> {
        if b.clients.is_empty()
            || b.lookups.is_empty()
            || b.effects.is_empty()
            || b.cleanups.len() < b.lookups.len()
            || b.clients.len() > u32::MAX as usize
            || b.lookups.len() > u32::MAX as usize
        {
            return Err(Error::Capacity);
        }
        b.clients.fill(ClientSlot::EMPTY);
        b.lookups.fill(LookupSlot::EMPTY);
        b.effects.fill(EffectSlot::EMPTY);
        b.cleanups.fill(None);
        let pool = BytePool::new(b.blobs, b.bytes, epoch)?;
        let cache = Cache::new(b.cache, pool, limits)?;
        Ok(Self {
            clients: b.clients,
            lookups: b.lookups,
            cache,
            effects: b.effects,
            used: 0,
            cleanups: b.cleanups,
            cleanup_used: 0,
            current: None,
            ticket_serial: 0,
            search: None,
            search_ignored: false,
            order: 0,
            soft: false,
            closed: false,
        })
    }
    fn same_geometry(&self, o: &Self) -> bool {
        self.clients.len() == o.clients.len()
            && self.lookups.len() == o.lookups.len()
            && self.effects.len() == o.effects.len()
            && self.cleanups.len() == o.cleanups.len()
            && self.cache.same_geometry(&o.cache)
    }

    fn reset_epoch(&mut self, epoch: u64) {
        self.clients.fill(ClientSlot::EMPTY);
        self.lookups.fill(LookupSlot::EMPTY);
        self.cache.reset_epoch(epoch);
        self.effects.fill(EffectSlot::EMPTY);
        self.used = 0;
        self.cleanups.fill(None);
        self.cleanup_used = 0;
        self.current = None;
        self.ticket_serial = 0;
        self.search = None;
        self.search_ignored = false;
        self.order = 0;
        self.soft = false;
        self.closed = false;
    }
    fn copy_from(&mut self, o: &Self) -> Result<(), Error> {
        if !self.same_geometry(o) {
            return Err(Error::Capacity);
        }
        self.cache.copy_from(&o.cache)?;
        self.clients.copy_from_slice(o.clients);
        self.lookups.copy_from_slice(o.lookups);
        self.effects.copy_from_slice(o.effects);
        self.cleanups.copy_from_slice(o.cleanups);
        self.used = o.used;
        self.cleanup_used = o.cleanup_used;
        self.current = o.current;
        self.ticket_serial = o.ticket_serial;
        self.search = o.search;
        self.search_ignored = o.search_ignored;
        self.order = o.order;
        self.soft = o.soft;
        self.closed = o.closed;
        Ok(())
    }
    fn open(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn client(&self, scope: PairId, id: ClientId) -> Result<usize, Error> {
        let i = id.id.index as usize;
        if !self.closed
            && scope == id.scope
            && self
                .clients
                .get(i)
                .is_some_and(|s| s.id.active && s.id.current == id.id.generation)
        {
            Ok(i)
        } else {
            Err(Error::StaleGeneration)
        }
    }
    fn known_client(&self, scope: PairId, id: ClientId) -> Result<usize, Error> {
        let i = id.id.index as usize;
        if !self.closed
            && scope == id.scope
            && self.clients.get(i).is_some_and(|s| {
                (s.id.active || s.closing.is_some()) && s.id.current == id.id.generation
            })
        {
            Ok(i)
        } else {
            Err(Error::StaleGeneration)
        }
    }
    fn lookup(&self, scope: PairId, id: LookupId) -> Result<usize, Error> {
        let i = id.id.index as usize;
        if !self.closed
            && scope == id.scope
            && self.lookups.get(i).is_some_and(|s| {
                s.id.active && s.id.current == id.id.generation && s.value.is_some()
            })
        {
            Ok(i)
        } else {
            Err(Error::StaleGeneration)
        }
    }
    fn active(&self, scope: PairId, id: LookupId) -> Result<Active, Error> {
        self.lookups[self.lookup(scope, id)?]
            .value
            .ok_or(Error::StaleGeneration)
    }
    fn push(&mut self, e: StoredEffect) -> Result<(), Error> {
        let i = self
            .effects
            .iter()
            .position(|s| s.value.is_none())
            .ok_or(Error::Capacity)?;
        self.effects[i].value = Some(e);
        self.used += 1;
        Ok(())
    }
    fn cancel(&mut self, id: QueryCancellation) -> Result<(), Error> {
        if self.cleanups.iter().flatten().any(|t| *t == id)
            || self
                .current
                .is_some_and(|c| matches!(c.effect,StoredEffect::Cancel(t)if t==id))
        {
            return Err(Error::Conflict);
        }
        let i = self
            .cleanups
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        self.cleanups[i] = Some(id);
        self.cleanup_used += 1;
        Ok(())
    }
    fn release_stored(&mut self, e: StoredEffect) -> Result<(), Error> {
        match e {
            StoredEffect::Output {
                payload: StoredPayload::Raw(id) | StoredPayload::Hostname(id),
                ..
            }
            | StoredEffect::Query { name: id, .. } => self.cache.pool.release(id),
            _ => Ok(()),
        }
    }
    fn remove_effect(&mut self, index: usize) -> Option<StoredEffect> {
        let value = self.effects.get_mut(index)?.value.take()?;
        for i in index + 1..self.used {
            self.effects[i - 1].value = self.effects[i].value.take();
        }
        self.used -= 1;
        Some(value)
    }
    fn is_client(e: StoredEffect, id: ClientId) -> bool {
        matches!(
            e,
            StoredEffect::Output { client, .. }
                | StoredEffect::Query { client, .. }
                | StoredEffect::SystemQuery { client, .. }
                | StoredEffect::Close { client, .. } if client == id
        )
    }
    fn purge(&mut self, predicate: impl Fn(StoredEffect) -> bool) -> Result<(), Error> {
        let mut write = 0;
        for i in 0..self.effects.len() {
            if let Some(e) = self.effects[i].value.take() {
                if predicate(e) {
                    self.release_stored(e)?;
                } else {
                    self.effects[write].value = Some(e);
                    write += 1;
                }
            }
        }
        self.used = write;
        if self.current.is_some_and(|c| predicate(c.effect)) {
            let c = self.current.take().ok_or(Error::Malformed)?;
            self.release_stored(c.effect)?;
        }
        Ok(())
    }
    fn remove_lookup(&mut self, scope: PairId, id: LookupId) -> Result<Active, Error> {
        let i = self.lookup(scope, id)?;
        let active = self.lookups[i].value.take().ok_or(Error::StaleGeneration)?;
        self.lookups[i].id.active = false;
        self.purge(|effect| effect.query_lookup() == Some(id))?;
        Ok(active)
    }
    fn retire(&mut self, scope: PairId, id: LookupId) -> Result<Active, Error> {
        let active = self.remove_lookup(scope, id)?;
        match active.source {
            LookupSource::Udp(UdpLookup {
                phase: UdpPhase::Active(Some(owner)),
                ..
            }) => self.cancel(owner.cancellation())?,
            LookupSource::System {
                phase: SystemPhase::Active,
                ..
            } => self.cancel(QueryCancellation::System(id))?,
            _ => {}
        }
        Ok(active)
    }
    fn output(
        &mut self,
        client: ClientId,
        wire: WireId,
        payload: StoredPayload,
    ) -> Result<(), Error> {
        self.push(StoredEffect::Output {
            client,
            wire,
            payload,
        })
    }
    fn cached(
        &mut self,
        client: ClientId,
        wire: WireId,
        name: NameRef<'_>,
        desired: u16,
        utc: AbsoluteTime,
    ) -> Result<Hit, Error> {
        let slots = &mut self.effects;
        let used = &mut self.used;
        let hit = self.cache.lookup(name, desired, utc, |r, pool| {
            let payload = if r.kind == 5 || r.kind == 12 {
                StoredPayload::Hostname(r.target.ok_or(Error::Malformed)?)
            } else {
                StoredPayload::Raw(r.data)
            };
            let (id, extra) = match payload {
                StoredPayload::Raw(id) => (id, 0usize),
                StoredPayload::Hostname(id) => (id, 1),
                StoredPayload::End => return Err(Error::Malformed),
            };
            let size = pool
                .get(id)?
                .len()
                .checked_add(extra + 8)
                .ok_or(Error::Overflow)?;
            MessageHeader::from_total_size(message_type::RESOLVER_RESPONSE, size)?;
            pool.retain(id)?;
            let i = slots
                .iter()
                .position(|s| s.value.is_none())
                .ok_or(Error::Capacity)?;
            slots[i].value = Some(StoredEffect::Output {
                client,
                wire,
                payload,
            });
            *used += 1;
            Ok(())
        })?;
        if hit == Hit::Rows {
            self.output(client, wire, StoredPayload::End)?;
        }
        Ok(hit)
    }
    fn draw(random: &mut impl FnMut(u32) -> Result<u32, Error>) -> Result<[u8; 2], Error> {
        let n = random(65535)?;
        if n >= 65535 {
            return Err(Error::InvalidInput);
        }
        Ok((n as u16).to_be_bytes())
    }
    fn pack(
        &self,
        name: BlobId,
        kind: u16,
        id: [u8; 2],
        idna: &impl Idna,
        text: &mut TextScratch<'_>,
    ) -> Result<([u8; QUERY_BYTES], usize), Error> {
        let input = self.cache.pool.get(name)?;
        let mut arena = Arena::new(text.wire_name);
        let name = DnsName::from_native_text(input, idna, text.work, &mut arena, DnsLimits::DNS)?;
        let q = [Query {
            name,
            kind: Type(kind),
            class: 1,
        }];
        let packet = Packet::new(id, 0x0100, &q, &[], &[], &[]);
        let mut bytes = [0; QUERY_BYTES];
        let len = packet.encode(AbsoluteTime::from_micros(0), &mut bytes)?;
        Ok((bytes, len))
    }
    fn content(e: Error) -> bool {
        matches!(e, Error::Malformed | Error::InvalidInput | Error::TooLarge)
    }
    fn allocate_lookup(
        &mut self,
        scope: PairId,
        client: ClientId,
        wire: WireId,
        source: LookupSource,
        deadline: MonoInstant,
    ) -> Result<LookupId, Error> {
        let i = self
            .lookups
            .iter()
            .position(|l| !l.id.active && l.id.next.is_some())
            .ok_or(Error::Capacity)?;
        let order = self
            .order
            .checked_add(1)
            .filter(|o| *o != u64::MAX)
            .ok_or(Error::Overflow)?;
        let generation = self.lookups[i].id.allocate()?;
        self.lookups[i].value = Some(Active {
            client,
            wire,
            source,
            deadline,
            order,
        });
        self.order = order;
        Ok(LookupId {
            scope,
            id: GenerationalId {
                index: i as u32,
                generation,
            },
        })
    }
    fn start<I: Idna, R: FnMut(u32) -> Result<u32, Error>>(
        &mut self,
        scope: PairId,
        client: ClientId,
        wire: WireId,
        name: LookupName,
        desired: u16,
        p: &mut Evaluation<'_, I, R>,
    ) -> Result<Option<LookupId>, Error> {
        let id = Self::draw(p.random)?;
        let kind = if desired == 255 { 1 } else { desired };
        let current = name.current();
        let (bytes, len) = match self.pack(current, kind, id, p.idna, &mut p.text) {
            Ok(v) => v,
            Err(e) if Self::content(e) => {
                self.output(client, wire, StoredPayload::End)?;
                name.release(&mut self.cache.pool)?;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        let deadline = MonoInstant(p.mono.0.checked_add(DNS_TIMEOUT).ok_or(Error::Overflow)?);
        let source = LookupSource::Udp(UdpLookup {
            name,
            desired,
            second: false,
            dns_id: id,
            phase: UdpPhase::Queued,
        });
        let lookup = self.allocate_lookup(scope, client, wire, source, deadline)?;
        self.cache.pool.retain(current)?;
        self.push(StoredEffect::Query {
            lookup,
            client,
            name: current,
            kind,
            deadline,
            bytes,
            len,
        })?;
        Ok(Some(lookup))
    }
    fn expanded(&self, name: NameRef<'_>, out: &mut [u8]) -> Result<usize, Error> {
        let name = self.cache.name(name)?;
        let search = self.search.map(|id| self.cache.pool.get(id)).transpose()?;
        if let Some(search) = search
            && !name.contains(&b'.')
            && name
                .len()
                .checked_add(search.len())
                .is_some_and(|n| n <= 253)
        {
            let n = name.len() + search.len() + 1;
            if n > out.len() {
                return Err(Error::Capacity);
            }
            out[..name.len()].copy_from_slice(name);
            out[name.len()] = b'.';
            out[name.len() + 1..n].copy_from_slice(search);
            Ok(n)
        } else {
            if name.len() >= 255 {
                return Err(Error::TooLarge);
            }
            if name.len() > out.len() {
                return Err(Error::Capacity);
            }
            out[..name.len()].copy_from_slice(name);
            Ok(name.len())
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Original client/ID, lookup name, query type and evaluation ports remain independently visible."
    )]
    fn process<I: Idna, R: FnMut(u32) -> Result<u32, Error>>(
        &mut self,
        scope: PairId,
        client: ClientId,
        wire: WireId,
        start: LookupStart<'_>,
        desired: u16,
        p: &mut Evaluation<'_, I, R>,
        limits: Limits,
    ) -> Result<Option<LookupId>, Error> {
        let (mut name, mut owned) = match start {
            LookupStart::Client(name) => (NameRef::External(name), None),
            LookupStart::Cname { target, .. } => (NameRef::Stored(target), Some(target)),
        };
        for _ in 0..=limits.cname_hops {
            match self.cached(client, wire, name, desired, p.utc)? {
                Hit::Rows => {
                    if let Some(id) = owned {
                        self.cache.pool.release(id)?;
                    }
                    return Ok(None);
                }
                Hit::Follow(id) => {
                    if let Some(old) = owned {
                        self.cache.pool.release(old)?;
                    }
                    owned = Some(id);
                    name = NameRef::Stored(id);
                    continue;
                }
                Hit::Miss => {}
            }
            let n = match self.expanded(name, p.text.native) {
                Ok(n) => n,
                Err(Error::TooLarge) => {
                    if let Some(id) = owned {
                        self.cache.pool.release(id)?;
                    }
                    self.disconnect(scope, client, Some(Error::TooLarge))?;
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            match self.cached(
                client,
                wire,
                NameRef::External(&p.text.native[..n]),
                desired,
                p.utc,
            )? {
                Hit::Rows => {
                    if let Some(id) = owned {
                        self.cache.pool.release(id)?;
                    }
                    return Ok(None);
                }
                Hit::Follow(id) => {
                    if let Some(old) = owned {
                        self.cache.pool.release(old)?;
                    }
                    owned = Some(id);
                    name = NameRef::Stored(id);
                    continue;
                }
                Hit::Miss => {}
            }
            let effective = self.cache.text(&p.text.native[..n])?;
            let name = match start {
                LookupStart::Client(original) if owned.is_some() => {
                    let n = self.expanded(NameRef::External(original), p.text.native)?;
                    LookupName::Cname {
                        original: self.cache.text(&p.text.native[..n])?,
                        target: effective,
                    }
                }
                LookupStart::Client(_) => LookupName::Original(effective),
                LookupStart::Cname { original, .. } => {
                    self.cache.pool.retain(original)?;
                    LookupName::Cname {
                        original,
                        target: effective,
                    }
                }
            };
            if let Some(id) = owned {
                self.cache.pool.release(id)?;
            }
            return self.start(scope, client, wire, name, desired, p);
        }
        Err(Error::Capacity)
    }
    fn complete_cache<I: Idna, R: FnMut(u32) -> Result<u32, Error>>(
        &mut self,
        scope: PairId,
        active: Active,
        udp: UdpLookup,
        p: &mut Evaluation<'_, I, R>,
        limits: Limits,
    ) -> Result<(), Error> {
        match self.cached(
            active.client,
            active.wire,
            NameRef::Stored(udp.name.current()),
            udp.desired,
            p.utc,
        )? {
            Hit::Rows => {}
            Hit::Miss => self.output(active.client, active.wire, StoredPayload::End)?,
            Hit::Follow(target) => {
                self.process(
                    scope,
                    active.client,
                    active.wire,
                    LookupStart::Cname {
                        original: udp.name.original(),
                        target,
                    },
                    udp.desired,
                    p,
                    limits,
                )?;
            }
        }
        udp.name.release(&mut self.cache.pool)
    }
    fn detach(&mut self, stub: StubId) -> usize {
        let mut count = 0;
        for l in &mut *self.lookups {
            if let Some(Active {
                source: LookupSource::Udp(udp),
                ..
            }) = l.value.as_mut()
                && udp.phase == UdpPhase::Active(Some(DnsOwner::Stub(stub)))
            {
                udp.phase = UdpPhase::Active(None);
                count += 1;
            }
        }
        count
    }
    fn authority(
        &self,
        scope: PairId,
        id: LookupId,
        owner: DnsOwner,
    ) -> Result<(Active, UdpLookup), Error> {
        let active = self.active(scope, id)?;
        self.client(scope, active.client)?;
        match active.source {
            LookupSource::Udp(udp) if udp.phase == UdpPhase::Active(Some(owner)) => {
                Ok((active, udp))
            }
            _ => Err(Error::StaleGeneration),
        }
    }
    fn disconnect(
        &mut self,
        scope: PairId,
        client: ClientId,
        reason: Option<Error>,
    ) -> Result<(), Error> {
        let i = self.known_client(scope, client)?;
        self.purge(|e| Self::is_client(e, client))?;
        loop {
            let next = self
                .lookups
                .iter()
                .enumerate()
                .filter_map(|(i, l)| l.value.filter(|v| v.client == client).map(|v| (v.order, i)))
                .max();
            let Some((_, n)) = next else { break };
            let id = LookupId {
                scope,
                id: GenerationalId {
                    index: n as u32,
                    generation: self.lookups[n].id.current,
                },
            };
            let v = self.retire(scope, id)?;
            v.source.release(&mut self.cache.pool)?;
        }
        self.clients[i].id.active = false;
        self.clients[i].closing = reason;
        if self.soft
            && !self
                .clients
                .iter()
                .any(|c| c.id.active || c.closing.is_some())
        {
            self.shutdown()?;
        }
        Ok(())
    }
    fn shutdown(&mut self) -> Result<(), Error> {
        self.effects.fill(EffectSlot::EMPTY);
        self.used = 0;
        self.cleanups.fill(None);
        self.cleanup_used = 0;
        self.current = None;
        for c in &mut *self.clients {
            c.id.active = false;
            c.closing = None;
        }
        for l in &mut *self.lookups {
            l.id.active = false;
            l.value = None;
        }
        self.cache.clear()?;
        self.cache.pool.clear();
        self.search = None;
        self.search_ignored = false;
        self.closed = true;
        self.push(StoredEffect::Stop)
    }
}
impl<'a> Resolver<'a> {
    /// Borrow fully initialized caller storage. Epoch must be nonzero and never
    /// reused for a reset of the same backing; no OS entropy is consumed here.
    pub fn new(buffers: Buffers<'a>, limits: Limits, epoch: u64) -> Result<Self, Error> {
        let limits = limits.validate()?;
        if epoch == 0 {
            return Err(Error::InvalidInput);
        }
        let scope = PairId {
            epoch,
            origin: buffers.clients.as_ptr() as usize,
        };
        let state = State::new(buffers, limits, epoch)?;
        Ok(Self {
            scope,
            limits,
            state,
        })
    }
    /// Create distinct typed staging or snapshot buffers with exactly equal
    /// geometry. No self-reference or giant Core temporary is constructed.
    pub fn make_scratch(&self, buffers: Buffers<'a>) -> Result<Scratch<'a>, Error> {
        let state = State::new(buffers, self.limits, self.scope.epoch)?;
        if !self.state.same_geometry(&state) {
            return Err(Error::Capacity);
        }
        Ok(Scratch {
            scope: self.scope,
            limits: self.limits,
            state,
        })
    }
    fn stage<T>(
        &mut self,
        scratch: &mut Scratch<'a>,
        f: impl FnOnce(&mut State<'a>, PairId, Limits) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if scratch.scope != self.scope
            || scratch.limits != self.limits
            || !self.state.same_geometry(&scratch.state)
        {
            return Err(Error::InvalidInput);
        }
        scratch.state.copy_from(&self.state)?;
        let value = f(&mut scratch.state, self.scope, self.limits)?;
        core::mem::swap(&mut self.state, &mut scratch.state);
        Ok(value)
    }
    /// Deep logical snapshot into matching typed scratch, for explicit checkpoints.
    pub fn copy_logical_state_to(&self, scratch: &mut Scratch<'a>) -> Result<(), Error> {
        if scratch.scope != self.scope || scratch.limits != self.limits {
            return Err(Error::InvalidInput);
        }
        scratch.state.copy_from(&self.state)
    }
    /// Small inline control structure only; payload/metadata slice RAM is separate.
    pub const fn control_bytes() -> usize {
        core::mem::size_of::<Self>()
    }
    /// Aggregate actual variable byte capacity, not multiplied by record count.
    pub fn byte_capacity(&self) -> usize {
        self.state.cache.byte_capacity()
    }
    /// Borrow cache metrics without exposing mutable pool authority.
    pub fn cache(&self) -> &Cache<'a> {
        &self.state.cache
    }
    /// Exact current client generation authority.
    pub fn owns_client(&self, id: ClientId) -> bool {
        self.state.client(self.scope, id).is_ok()
    }
    /// Exact current lookup generation authority.
    pub fn owns_lookup(&self, id: LookupId) -> bool {
        self.state.lookup(self.scope, id).is_ok()
    }
    /// Active lookup count; queued output has separate ownership.
    pub fn lookup_count(&self) -> usize {
        self.state.lookups.iter().filter(|l| l.id.active).count()
    }
    /// Current original deadline, not the caller drive wait budget.
    pub fn lookup_deadline(&self, id: LookupId) -> Result<MonoInstant, Error> {
        Ok(self.state.active(self.scope, id)?.deadline)
    }
    /// Exact associated current real stub generation.
    pub fn lookup_stub(&self, id: LookupId) -> Result<Option<StubId>, Error> {
        Ok(match self.state.active(self.scope, id)?.source {
            LookupSource::Udp(UdpLookup {
                phase: UdpPhase::Active(Some(DnsOwner::Stub(stub))),
                ..
            }) => Some(stub),
            _ => None,
        })
    }
    /// Earliest service timer, including still-due callbacks after bounded tick.
    pub fn next_wakeup(&self) -> Option<MonoInstant> {
        if self.state.closed {
            return None;
        }
        self.state
            .lookups
            .iter()
            .filter_map(|l| l.value.map(|v| v.deadline))
            .min()
    }
    /// Dedicated cleanup tokens not yet moved into the current effect lease.
    pub const fn pending_cleanups(&self) -> usize {
        self.state.cleanup_used
    }
    /// Total pending logical obligations; closing and in-flight close count once.
    pub fn effect_count(&self) -> usize {
        self.state.used
            + self.state.cleanup_used
            + self
                .state
                .clients
                .iter()
                .filter(|c| c.closing.is_some())
                .count()
            + usize::from(
                self.state
                    .current
                    .is_some_and(|c| !matches!(c.effect, StoredEffect::Close { .. })),
            )
    }
    /// Whether final shutdown revoked every original authority.
    pub const fn is_closed(&self) -> bool {
        self.state.closed
    }
    /// Admit one actual connection generation. Pending physical close prevents
    /// slot reuse, independently from output/effect queue capacity.
    pub fn connect(&mut self) -> Result<ClientId, Error> {
        self.state.open()?;
        if self.state.soft {
            return Err(Error::Closed);
        }
        let i = self
            .state
            .clients
            .iter()
            .position(|c| !c.id.active && c.closing.is_none() && c.id.next.is_some())
            .ok_or(Error::Capacity)?;
        let generation = self.state.clients[i].id.allocate()?;
        Ok(ClientId {
            scope: self.scope,
            id: GenerationalId {
                index: i as u32,
                generation,
            },
        })
    }
    /// Parse owned machine-file bytes; only search/hosts are logical state. The
    /// host separately passes ResolverFile nameservers to the actual stub owner.
    pub fn load_machine_files(
        &mut self,
        s: &mut Scratch<'a>,
        hosts: &[u8],
        resolv: &[u8],
    ) -> Result<(), Error> {
        self.stage(s, |v, _, _| {
            v.open()?;
            v.cache.load_hosts(hosts)?;
            for f in crate::files::ResolverFile::new(resolv) {
                if let crate::files::ResolverField::Search(text) = f
                    && v.search.is_none()
                    && !v.search_ignored
                {
                    if text.len() > 253 {
                        v.search_ignored = true
                    } else {
                        v.search = Some(v.cache.text(text)?);
                    }
                }
            }
            Ok(())
        })
    }
    /// Explicit embedding/test search capability, not an invented official key.
    pub fn set_search(&mut self, s: &mut Scratch<'a>, search: Option<&[u8]>) -> Result<(), Error> {
        self.stage(s, |v, _, _| {
            v.open()?;
            if let Some(old) = v.search.take() {
                v.cache.pool.release(old)?;
            }
            let search = search.map(|b| &b[..b.iter().position(|x| *x == 0).unwrap_or(b.len())]);
            v.search_ignored = search.is_some_and(|b| b.len() > 253);
            if !v.search_ignored {
                v.search = search.map(|b| v.cache.text(b)).transpose()?;
            }
            Ok(())
        })
    }
    /// Admit one decoded request. Distinct internal lookup IDs preserve duplicate
    /// WireIds. No DNS/NSS/socket operation occurs in this pure transition.
    pub fn request<I: Idna, R: FnMut(u32) -> Result<u32, Error>>(
        &mut self,
        s: &mut Scratch<'a>,
        client: ClientId,
        request: Request<'_>,
        p: &mut Evaluation<'_, I, R>,
    ) -> Result<Option<LookupId>, Error> {
        self.stage(s, |v, scope, limits| {
            v.client(scope, client)?;
            match request.query() {
                ResolverQuery::Forward { family, hostname } => v.process(
                    scope,
                    client,
                    request.id(),
                    LookupStart::Client(hostname),
                    match family {
                        Family::Any => 255,
                        Family::V4 => 1,
                        Family::V6 => 28,
                    },
                    p,
                    limits,
                ),
                ResolverQuery::Reverse(address) => {
                    let mut bytes = [0; 80];
                    let n = crate::lookup::reverse_name(address, &mut bytes)?;
                    v.process(
                        scope,
                        client,
                        request.id(),
                        LookupStart::Client(&bytes[..n]),
                        12,
                        p,
                        limits,
                    )
                }
            }
        })
    }
    /// Report actual copied stub admission after Start was leased. Rejected
    /// admission leaves original state unchanged; caller still owns its actual
    /// returned token and must cancel it if it cannot be adopted.
    pub fn query_admitted(
        &mut self,
        s: &mut Scratch<'a>,
        id: LookupId,
        a: Admission,
    ) -> Result<(), Error> {
        self.stage(s, |v, scope, _| {
            let i = v.lookup(scope, id)?;
            let active = v.active(scope, id)?;
            if !matches!(
                active.source,
                LookupSource::Udp(UdpLookup {
                    phase: UdpPhase::AwaitAdmission,
                    ..
                })
            ) || a.evicted == Some(a.request)
            {
                return Err(Error::InvalidInput);
            }
            if let Some(old) = a.evicted {
                v.detach(old);
            }
            if v.lookups.iter().filter_map(|l| l.value).any(|l| {
                matches!(
                    l.source,
                    LookupSource::Udp(UdpLookup {
                        phase: UdpPhase::Active(Some(DnsOwner::Stub(stub))),
                        ..
                    }) if stub == a.request
                )
            }) {
                return Err(Error::Conflict);
            }
            let active = v.lookups[i].value.as_mut().ok_or(Error::StaleGeneration)?;
            let LookupSource::Udp(udp) = &mut active.source else {
                return Err(Error::InvalidInput);
            };
            udp.phase = UdpPhase::Active(Some(DnsOwner::Stub(a.request)));
            Ok(())
        })
    }
    /// Bind a real native transport to the original currently leased DNS start.
    /// The returned generation distinguishes every attempt phase of one lookup.
    pub fn query_admitted_native(
        &mut self,
        s: &mut Scratch<'a>,
        ticket: EffectTicket,
    ) -> Result<NativeDnsId, Error> {
        let Effect::StartQuery(original) = self.effect(ticket)? else {
            return Err(Error::InvalidInput);
        };
        let id = NativeDnsId {
            lookup: original.lookup,
            ticket,
        };
        self.stage(s, |v, scope, _| {
            let i = v.lookup(scope, id.lookup)?;
            let active = v.lookups[i].value.as_mut().ok_or(Error::StaleGeneration)?;
            let LookupSource::Udp(udp) = &mut active.source else {
                return Err(Error::InvalidInput);
            };
            if udp.phase != UdpPhase::AwaitAdmission {
                return Err(Error::InvalidInput);
            }
            udp.phase = UdpPhase::Active(Some(DnsOwner::Native(id)));
            Ok(id)
        })
    }
    /// Actual failed/unavailable stub admission keeps the original30s deadline.
    pub fn query_unavailable(&mut self, s: &mut Scratch<'a>, id: LookupId) -> Result<(), Error> {
        self.stage(s, |v, scope, _| {
            let i = v.lookup(scope, id)?;
            let active = v.lookups[i].value.as_mut().ok_or(Error::StaleGeneration)?;
            let LookupSource::Udp(udp) = &mut active.source else {
                return Err(Error::InvalidInput);
            };
            if udp.phase != UdpPhase::AwaitAdmission {
                return Err(Error::InvalidInput);
            }
            udp.phase = UdpPhase::Active(None);
            Ok(())
        })
    }
    /// Original NULL/0 eviction detaches only that old generation, without END.
    pub fn stub_evicted(&mut self, id: StubId) -> usize {
        self.state.detach(id)
    }
    /// Revoke the previous network's DNS queries and dynamic cache. The caller
    /// must retire their actual DNSSTUB owner associations at the same boundary.
    /// Original IPC clients, lookup deadlines, hosts and queued results remain.
    pub fn replace_upstreams(
        &mut self,
        scratch: &mut Scratch<'a>,
        has_servers: bool,
    ) -> Result<(), Error> {
        self.stage(scratch, |state, _, _| {
            if state.closed {
                return Err(Error::Closed);
            }
            state.cache.clear_dynamic()?;
            state.purge(|effect| matches!(effect, StoredEffect::Query { .. }))?;
            for active in state
                .lookups
                .iter_mut()
                .filter_map(|slot| slot.value.as_mut())
            {
                if let LookupSource::Udp(udp) = &mut active.source {
                    udp.name.forget_target(&mut state.cache.pool)?;
                    udp.second = false;
                    udp.phase = if has_servers {
                        UdpPhase::UpstreamChanged
                    } else {
                        UdpPhase::Active(None)
                    };
                }
            }
            Ok(())
        })
    }
    /// Prepare one previous lookup for the current upstream set with a fresh
    /// DNS transaction draw and its original absolute deadline. Capacity stays
    /// with the existing effect queue.
    pub fn resume_upstream_lookup(
        &mut self,
        now: MonoInstant,
        idna: &impl Idna,
        random: &mut impl FnMut(u32) -> Result<u32, Error>,
        text: &mut TextScratch<'_>,
    ) -> Result<bool, Error> {
        let state = &mut self.state;
        if state.closed || state.used == state.effects.len() {
            return Ok(false);
        }
        let candidate = state
            .lookups
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let active = slot.value?;
                match active.source {
                    LookupSource::Udp(udp)
                        if udp.phase == UdpPhase::UpstreamChanged && now < active.deadline =>
                    {
                        Some((index, active, udp))
                    }
                    _ => None,
                }
            })
            .min_by_key(|(_, active, _)| active.order);
        let Some((index, mut active, mut udp)) = candidate else {
            return Ok(false);
        };
        let lookup = LookupId {
            scope: self.scope,
            id: GenerationalId {
                index: index as u32,
                generation: state.lookups[index].id.current,
            },
        };
        let kind = if udp.desired == 255 { 1 } else { udp.desired };
        // Exclude the old wire ID even when the new network uses the same
        // server addresses. Each old UDP socket is retired independently.
        let draw = random(65534)?;
        if draw >= 65534 {
            return Err(Error::InvalidInput);
        }
        let previous = u32::from(u16::from_be_bytes(udp.dns_id));
        let dns_id = ((draw + u32::from(draw >= previous)) as u16).to_be_bytes();
        let name = udp.name.original();
        let (bytes, len) = state.pack(name, kind, dns_id, idna, text)?;
        let slot = &mut state.effects[state.used];
        if slot.value.is_some() {
            return Err(Error::Conflict);
        }
        state.cache.pool.retain(name)?;
        slot.value = Some(StoredEffect::Query {
            lookup,
            client: active.client,
            name,
            kind,
            deadline: active.deadline,
            bytes,
            len,
        });
        state.used += 1;
        udp.dns_id = dns_id;
        udp.phase = UdpPhase::Queued;
        active.source = LookupSource::Udp(udp);
        state.lookups[index].value = Some(active);
        Ok(true)
    }
    /// Parser failure is ignored only for the exact original live association.
    pub fn malformed_dns(&self, id: LookupId, stub: StubId) -> Result<Disposition, Error> {
        self.state.authority(self.scope, id, DnsOwner::Stub(stub))?;
        Ok(Disposition::Ignored)
    }
    /// Cache all actual sections, preserve Any/CNAME clocks and reject capability
    /// or aggregate storage errors atomically without a fabricated result.
    pub fn dns_result<I: Idna, R: FnMut(u32) -> Result<u32, Error>>(
        &mut self,
        s: &mut Scratch<'a>,
        id: LookupId,
        stub: StubId,
        packet: Packet<'_, '_>,
        p: &mut Evaluation<'_, I, R>,
    ) -> Result<Disposition, Error> {
        self.network_result(s, id, DnsOwner::Stub(stub), packet, p)
    }

    /// Apply a parsed, matched response from the exact admitted native DNS phase.
    pub fn native_dns_result<I: Idna, R: FnMut(u32) -> Result<u32, Error>>(
        &mut self,
        s: &mut Scratch<'a>,
        original: NativeDnsId,
        packet: Packet<'_, '_>,
        p: &mut Evaluation<'_, I, R>,
    ) -> Result<Disposition, Error> {
        self.network_result(s, original.lookup, DnsOwner::Native(original), packet, p)
    }

    fn network_result<I: Idna, R: FnMut(u32) -> Result<u32, Error>>(
        &mut self,
        s: &mut Scratch<'a>,
        id: LookupId,
        owner: DnsOwner,
        packet: Packet<'_, '_>,
        p: &mut Evaluation<'_, I, R>,
    ) -> Result<Disposition, Error> {
        self.stage(s, |v, scope, limits| {
            let (active, udp) = v.authority(scope, id, owner)?;
            if packet.id != udp.dns_id {
                return Ok(Disposition::Ignored);
            }
            let name = udp.name.current();
            let incoming = packet.answers.len() + packet.authority.len() + packet.additional.len();
            if incoming != 0 {
                match owner {
                    DnsOwner::Native(_) => v.cache.begin_native_batch(name, incoming)?,
                    DnsOwner::Stub(_) => v.cache.begin_batch()?,
                }
                for r in packet
                    .answers
                    .iter()
                    .chain(packet.authority)
                    .chain(packet.additional)
                {
                    let record = v.cache.project(*r, p.idna, &mut p.text)?;
                    v.cache.insert(name, record)?;
                }
            }
            // No A records does not establish the absence of IPv6 records.
            // AF_UNSPEC still owes its original AAAA phase before final END.
            if udp.desired == 255 && !udp.second {
                let dns_id = State::draw(p.random)?;
                match v.pack(name, 28, dns_id, p.idna, &mut p.text) {
                    Ok((bytes, len)) => {
                        v.cancel(owner.cancellation())?;
                        let i = v.lookup(scope, id)?;
                        let a = v.lookups[i].value.as_mut().ok_or(Error::StaleGeneration)?;
                        a.source = LookupSource::Udp(UdpLookup {
                            second: true,
                            dns_id,
                            phase: UdpPhase::Queued,
                            ..udp
                        });
                        v.cache.pool.retain(name)?;
                        v.push(StoredEffect::Query {
                            lookup: id,
                            client: active.client,
                            name,
                            kind: 28,
                            deadline: active.deadline,
                            bytes,
                            len,
                        })?;
                        return Ok(Disposition::AwaitingAaaa);
                    }
                    Err(e) if State::content(e) => {}
                    Err(e) => return Err(e),
                }
            }
            let active = v.retire(scope, id)?;
            v.complete_cache(scope, active, udp, p, limits)?;
            Ok(Disposition::Completed)
        })
    }
    /// Execute one earliest due callback. Dedicated cancels permit progress after
    /// ordinary queue draining, even with many equal deadlines and E=1.
    pub fn tick(&mut self, s: &mut Scratch<'a>, now: MonoInstant) -> Result<usize, Error> {
        self.stage(s, |v, scope, _| {
            v.open()?;
            let next = v
                .lookups
                .iter()
                .enumerate()
                .filter_map(|(i, l)| {
                    l.value
                        .filter(|a| a.deadline <= now)
                        .map(|a| (a.deadline, a.order, i))
                })
                .min();
            let Some((_, _, i)) = next else { return Ok(0) };
            let id = LookupId {
                scope,
                id: GenerationalId {
                    index: i as u32,
                    generation: v.lookups[i].id.current,
                },
            };
            let active = v.retire(scope, id)?;
            v.output(active.client, active.wire, StoredPayload::End)?;
            active.source.release(&mut v.cache.pool)?;
            Ok(1)
        })
    }
    /// Actual EOF revokes authority immediately and queues all original cancels
    /// in dedicated lookup-sized capacity; ordinary output cannot block cleanup.
    pub fn disconnect(&mut self, s: &mut Scratch<'a>, id: ClientId) -> Result<(), Error> {
        self.stage(s, |v, scope, _| v.disconnect(scope, id, None))
    }
    /// Optional generic Soft; Resolver process default remains immediate NONE.
    pub fn begin_soft_shutdown(&mut self, s: &mut Scratch<'a>) -> Result<(), Error> {
        self.stage(s, |v, _, _| {
            v.open()?;
            v.soft = true;
            if !v.clients.iter().any(|c| c.id.active || c.closing.is_some()) {
                v.shutdown()?;
            }
            Ok(())
        })
    }
    /// Immediate final shutdown produces a host Stop obligation, not flush success.
    pub fn shutdown(&mut self, s: &mut Scratch<'a>) -> Result<(), Error> {
        self.stage(s, |v, _, _| {
            if !v.closed {
                v.shutdown()?;
            }
            Ok(())
        })
    }

    /// Reopen the original backing with no clients, lookups, hosts or cache.
    ///
    /// The host must have retired every original native port and released the
    /// shutdown `Stop` effect. Old client, lookup, payload and effect IDs cannot
    /// regain authority even when the new service uses the same slots.
    ///
    /// # Errors
    ///
    /// Rejects a foreign scratch pair, an unsettled shutdown or exhausted epochs.
    pub fn restart(&mut self, s: &mut Scratch<'a>) -> Result<(), Error> {
        if s.scope != self.scope || s.limits != self.limits || !self.state.same_geometry(&s.state) {
            return Err(Error::InvalidInput);
        }
        if !self.state.closed
            || self.state.current.is_some()
            || self.state.used != 0
            || self.state.cleanup_used != 0
        {
            return Err(Error::NotReady);
        }
        let epoch = self.scope.epoch.checked_add(1).ok_or(Error::Overflow)?;
        self.state.reset_epoch(epoch);
        s.state.reset_epoch(epoch);
        self.scope.epoch = epoch;
        s.scope = self.scope;
        Ok(())
    }
    /// Recover the exact current effect after a canceled host drive future.
    pub fn current_effect(&self) -> Option<EffectTicket> {
        self.state.current.map(|c| EffectTicket {
            scope: self.scope,
            serial: c.serial,
        })
    }
    /// Lease reserved cleanup/close first, then the oldest ordinary effect. No
    /// payload is copied or dropped; repeated call returns the same current ticket.
    pub fn take_effect(&mut self) -> Result<Option<EffectTicket>, Error> {
        self.take_effect_with_output(|_| true)
    }

    /// Lease the oldest effect whose original destination can accept it.
    /// Cleanup and close retain priority. A blocked output stays queued in
    /// order for its client, while other clients and DNS starts can progress.
    /// An already leased ticket retains its original authority.
    pub fn take_effect_with_output(
        &mut self,
        mut can_write: impl FnMut(ClientId) -> bool,
    ) -> Result<Option<EffectTicket>, Error> {
        if let Some(t) = self.current_effect() {
            return Ok(Some(t));
        }
        let closing = self.state.clients.iter().position(|c| c.closing.is_some());
        let ordinary = (self.state.cleanup_used == 0 && closing.is_none())
            .then(|| {
                self.state.effects[..self.state.used]
                    .iter()
                    .position(|slot| match slot.value.as_ref() {
                        Some(StoredEffect::Output { client, .. }) => can_write(*client),
                        Some(_) => true,
                        None => false,
                    })
            })
            .flatten();
        if self.state.cleanup_used == 0 && closing.is_none() && ordinary.is_none() {
            return Ok(None);
        }
        let serial = self
            .state
            .ticket_serial
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let effect = if let Some(id) = self.state.cleanups.first_mut().and_then(Option::take) {
            for i in 1..self.state.cleanups.len() {
                self.state.cleanups[i - 1] = self.state.cleanups[i].take();
            }
            self.state.cleanup_used -= 1;
            StoredEffect::Cancel(id)
        } else if let Some(i) = closing {
            StoredEffect::Close {
                client: ClientId {
                    scope: self.scope,
                    id: GenerationalId {
                        index: i as u32,
                        generation: self.state.clients[i].id.current,
                    },
                },
                reason: self.state.clients[i].closing.ok_or(Error::Malformed)?,
            }
        } else {
            self.state
                .remove_effect(ordinary.ok_or(Error::Malformed)?)
                .ok_or(Error::Malformed)?
        };
        if let Some(lookup) = effect.query_lookup() {
            let i = self.state.lookup(self.scope, lookup)?;
            self.state.lookups[i]
                .value
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .source
                .await_admission()?;
        }
        self.state.ticket_serial = serial;
        self.state.current = Some(InFlight { serial, effect });
        Ok(Some(EffectTicket {
            scope: self.scope,
            serial,
        }))
    }
    /// Borrow pinned effect bytes only for synchronous execution/copy. End this
    /// borrow before any await or subsequent mutable core operation.
    ///
    /// A view cannot outlive release of its byte lease:
    ///
    /// ```compile_fail,E0502
    /// use gnunet_resolver_service_core::owner::{Effect, EffectTicket, Resolver};
    /// use gnunet_types::Error;
    /// fn escape(owner: &mut Resolver<'_>, ticket: EffectTicket) -> Result<(), Error> {
    ///     let view = owner.effect(ticket)?;
    ///     owner.release_effect(ticket)?;
    ///     if let Effect::StartQuery(query) = view { assert!(!query.bytes.is_empty()); }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// Copy into caller-owned bounded frame storage before releasing output:
    ///
    /// ```
    /// use gnunet_resolver_service_core::owner::{Effect, EffectTicket, Resolver};
    /// use gnunet_types::Error;
    /// fn copy_output(owner: &mut Resolver<'_>, ticket: EffectTicket,
    ///                persistent_tx: &mut [u8]) -> Result<usize, Error> {
    ///     let length = match owner.effect(ticket)? {
    ///         Effect::Output(output) => output.encode(persistent_tx)?,
    ///         _ => return Err(Error::InvalidInput),
    ///     };
    ///     owner.release_effect(ticket)?;
    ///     Ok(length)
    /// }
    /// ```
    pub fn effect(&self, ticket: EffectTicket) -> Result<Effect<'_>, Error> {
        if ticket.scope != self.scope {
            return Err(Error::StaleGeneration);
        }
        let c = self
            .state
            .current
            .filter(|c| c.serial == ticket.serial)
            .ok_or(Error::StaleGeneration)?;
        Ok(match c.effect {
            StoredEffect::Output {
                client,
                wire,
                payload,
            } => Effect::Output(Output {
                client,
                wire_id: wire,
                payload: match payload {
                    StoredPayload::End => Payload::End,
                    StoredPayload::Raw(id) => Payload::Raw(self.state.cache.pool.get(id)?),
                    StoredPayload::Hostname(id) => {
                        Payload::Hostname(self.state.cache.pool.get(id)?)
                    }
                },
            }),
            StoredEffect::Query {
                lookup,
                client,
                name,
                kind,
                deadline,
                ..
            } => {
                let Some(InFlight {
                    effect: StoredEffect::Query { bytes, len, .. },
                    ..
                }) = self.state.current.as_ref()
                else {
                    return Err(Error::Malformed);
                };
                Effect::StartQuery(StartQuery {
                    lookup,
                    client,
                    hostname: self.state.cache.pool.get(name)?,
                    kind,
                    deadline,
                    bytes: &bytes[..*len],
                })
            }
            StoredEffect::SystemQuery { lookup, .. } => {
                let active = self.state.active(self.scope, lookup)?;
                let LookupSource::System { question, .. } = active.source else {
                    return Err(Error::Malformed);
                };
                Effect::StartSystemQuery(SystemQuery {
                    lookup,
                    deadline: active.deadline,
                    question: match question {
                        StoredSystemQuestion::Forward { family, hostname } => {
                            let hostname = self.state.cache.pool.get(hostname)?;
                            SystemQuestion::Forward {
                                family,
                                hostname: core::str::from_utf8(hostname)
                                    .map_err(|_| Error::Malformed)?,
                            }
                        }
                        StoredSystemQuestion::Reverse(address) => SystemQuestion::Reverse(address),
                    },
                })
            }
            StoredEffect::Cancel(QueryCancellation::Stub(id)) => Effect::CancelQuery(id),
            StoredEffect::Cancel(QueryCancellation::NativeDns(id)) => Effect::CancelNativeDns(id),
            StoredEffect::Cancel(QueryCancellation::System(id)) => Effect::CancelSystemQuery(id),
            StoredEffect::Close { client, reason } => Effect::DropClient { client, reason },
            StoredEffect::Stop => Effect::Stop,
        })
    }
    /// Release LOCAL effect ownership after the host copied/admitted it. This is
    /// never OS send success, remote processing or DNS completion. Query lease
    /// cannot be released before actual admission/unavailability was reported.
    pub fn release_effect(&mut self, ticket: EffectTicket) -> Result<(), Error> {
        if ticket.scope != self.scope {
            return Err(Error::StaleGeneration);
        }
        let c = self
            .state
            .current
            .filter(|c| c.serial == ticket.serial)
            .ok_or(Error::StaleGeneration)?;
        if let Some(lookup) = c.effect.query_lookup()
            && self
                .state
                .active(self.scope, lookup)?
                .source
                .admission_pending()
        {
            return Err(Error::NotReady);
        }
        self.state.release_stored(c.effect)?;
        if let StoredEffect::Close { client, .. } = c.effect {
            let i = self.state.known_client(self.scope, client)?;
            self.state.clients[i].closing = None;
        }
        self.state.current = None;
        if self.state.soft
            && !self
                .state
                .clients
                .iter()
                .any(|c| c.id.active || c.closing.is_some())
            && !self.state.closed
        {
            self.state.shutdown()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::cache::{BucketMeta, RecordEntry, RecordMeta};
    use std::{format, vec::Vec};
    fn vector<T>(n: usize, mut value: impl FnMut() -> T) -> Result<Vec<T>, Error> {
        let mut v = Vec::new();
        v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
        v.resize_with(n, &mut value);
        Ok(v)
    }
    struct Backing {
        clients: Vec<ClientSlot>,
        lookups: Vec<LookupSlot>,
        hosts: Vec<Option<RecordMeta>>,
        buckets: Vec<Option<BucketMeta>>,
        records: Vec<Option<RecordEntry>>,
        effects: Vec<EffectSlot>,
        cleanups: Vec<Option<QueryCancellation>>,
        blobs: Vec<BlobSlot>,
        bytes: Vec<u8>,
    }
    impl Backing {
        fn new() -> Result<Self, Error> {
            Ok(Self {
                clients: vector(1, || ClientSlot::EMPTY)?,
                lookups: vector(2, || LookupSlot::EMPTY)?,
                hosts: Vec::new(),
                buckets: vector(1026, || None)?,
                records: vector(1026, || None)?,
                effects: vector(8, || EffectSlot::EMPTY)?,
                cleanups: vector(2, || None)?,
                blobs: vector(5000, || BlobSlot::EMPTY)?,
                bytes: vector(17000, || 0)?,
            })
        }
        fn buffers(&mut self) -> Buffers<'_> {
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
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert the native lookup scope, exact response frames and retirement."
    )]
    fn system_lookup_uses_original_name_and_ordinary_resolver_frames() -> Result<(), Error> {
        let mut owner = Backing::new()?;
        let mut staging = Backing::new()?;
        let mut core = Resolver::new(
            owner.buffers(),
            Limits {
                max_name_bytes: 1024,
                max_record_bytes: 65535,
                cname_hops: 8,
            },
            1,
        )?;
        let mut stage = core.make_scratch(staging.buffers())?;
        let client = core.connect()?;
        core.set_search(&mut stage, Some(b"different.suffix"))?;
        let wire_id = WireId([10, 20, 30, 40]);
        let lookup = core
            .request_system(
                &mut stage,
                client,
                Request::forward(wire_id, Family::Any, b"source")?,
                MonoInstant(37),
            )?
            .ok_or(Error::NotReady)?;
        let ticket = core.take_effect()?.ok_or(Error::NotReady)?;
        assert_eq!(
            core.effect(ticket)?,
            Effect::StartSystemQuery(SystemQuery {
                lookup,
                deadline: MonoInstant(37 + DNS_TIMEOUT),
                question: SystemQuestion::Forward {
                    family: Family::Any,
                    hostname: "source",
                },
            }),
        );
        assert_eq!(core.release_effect(ticket), Err(Error::NotReady));
        core.system_admitted(&mut stage, lookup)?;
        core.release_effect(ticket)?;

        let v4 = core::net::Ipv4Addr::new(192, 0, 2, 1);
        let v6 = core::net::Ipv6Addr::LOCALHOST;
        core.system_result(
            &mut stage,
            lookup,
            [SystemAnswer::V4(v4), SystemAnswer::V6(v6)],
        )?;
        assert_eq!(core.pending_cleanups(), 0);
        assert_eq!(core.cache().bucket_count(), 0);
        for expected in [
            Payload::Raw(&v4.octets()),
            Payload::Raw(&v6.octets()),
            Payload::End,
        ] {
            let ticket = core.take_effect()?.ok_or(Error::NotReady)?;
            assert_eq!(
                core.effect(ticket)?,
                Effect::Output(Output {
                    client,
                    wire_id,
                    payload: expected,
                }),
            );
            core.release_effect(ticket)?;
        }
        assert_eq!(core.take_effect()?, None);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert exact cancellation and stale result rejection across lookup reuse."
    )]
    fn native_expiry_and_unavailable_start_retire_only_their_original_lookup() -> Result<(), Error>
    {
        let mut owner = Backing::new()?;
        let mut staging = Backing::new()?;
        let mut core = Resolver::new(
            owner.buffers(),
            Limits {
                max_name_bytes: 1024,
                max_record_bytes: 65535,
                cname_hops: 8,
            },
            1,
        )?;
        let mut stage = core.make_scratch(staging.buffers())?;
        let client = core.connect()?;
        let addr = IpAddr::V6(core::net::Ipv6Addr::LOCALHOST);
        let request = Request::reverse(WireId([1, 3, 5, 7]), addr);
        let lookup = core
            .request_system(&mut stage, client, request, MonoInstant(0))?
            .ok_or(Error::NotReady)?;
        let ticket = core.take_effect()?.ok_or(Error::NotReady)?;
        assert!(matches!(
            core.effect(ticket)?,
            Effect::StartSystemQuery(q) if q.question == SystemQuestion::Reverse(addr)
        ));
        core.system_admitted(&mut stage, lookup)?;
        core.release_effect(ticket)?;
        assert_eq!(core.tick(&mut stage, MonoInstant(DNS_TIMEOUT))?, 1);

        let ticket = core.take_effect()?.ok_or(Error::NotReady)?;
        assert_eq!(core.effect(ticket)?, Effect::CancelSystemQuery(lookup));
        core.release_effect(ticket)?;
        let ticket = core.take_effect()?.ok_or(Error::NotReady)?;
        assert!(matches!(
            core.effect(ticket)?,
            Effect::Output(out) if out.payload == Payload::End && out.wire_id == request.id()
        ));
        core.release_effect(ticket)?;

        let next = core
            .request_system(&mut stage, client, request, MonoInstant(DNS_TIMEOUT))?
            .ok_or(Error::NotReady)?;
        assert_eq!(lookup.resource_id().index, next.resource_id().index);
        assert_ne!(lookup, next);
        assert_eq!(
            core.system_result(&mut stage, lookup, [SystemAnswer::Name(b"old.example")]),
            Err(Error::StaleGeneration),
        );
        let ticket = core.take_effect()?.ok_or(Error::NotReady)?;
        core.system_unavailable(&mut stage, next)?;
        assert_eq!(core.release_effect(ticket), Err(Error::StaleGeneration));
        assert_eq!(core.pending_cleanups(), 0);
        let ticket = core.take_effect()?.ok_or(Error::NotReady)?;
        assert!(matches!(
            core.effect(ticket)?,
            Effect::Output(out) if out.payload == Payload::End && out.wire_id == request.id()
        ));
        core.release_effect(ticket)?;
        assert_eq!(core.take_effect()?, None);
        Ok(())
    }

    struct UnavailableText;
    impl Idna for UnavailableText {
        fn to_ascii(&self, _: &[u8], _: &mut [u8]) -> Result<usize, Error> {
            Err(Error::Unavailable)
        }
        fn to_unicode_label(&self, _: &[u8], _: &mut [u8]) -> Result<usize, Error> {
            Err(Error::Unavailable)
        }
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "A real queued output pin must survive source-exact LRU release plus in-place byte compaction."
    )]
    fn queued_output_pin_survives_1025_bucket_lru_eviction_and_pool_compaction() -> Result<(), Error>
    {
        let mut owner = Backing::new()?;
        let mut staging = Backing::new()?;
        let mut c = Resolver::new(
            owner.buffers(),
            Limits {
                max_name_bytes: 1024,
                max_record_bytes: 65535,
                cname_hops: 8,
            },
            1,
        )?;
        let mut s = c.make_scratch(staging.buffers())?;
        let client = c.connect()?;
        // Reachable prior-cache fixture: exact production cache insertion, no claim of
        // actual OS/DNS packets or a1025-way native resolver process in this unit test.
        c.stage(&mut s, |v, _, _| {
            v.cache
                .insert_raw(b"q", b"q", 1, 1, u64::MAX, &[7, 8, 9, 10], None)
        })?;
        let mut native = [0; 1024];
        let mut work = [0; 1024];
        let mut wire = [0; 255];
        let mut rng = |_| Err(Error::Entropy);
        let mut p = Evaluation {
            mono: MonoInstant(0),
            utc: AbsoluteTime::from_micros(0),
            idna: &UnavailableText,
            random: &mut rng,
            text: TextScratch {
                native: &mut native,
                work: &mut work,
                wire_name: &mut wire,
            },
        };
        assert_eq!(
            c.request(
                &mut s,
                client,
                Request::forward(WireId([1; 4]), Family::V4, b"q")?,
                &mut p
            )?,
            None
        );
        assert_eq!(c.effect_count(), 2);
        c.stage(&mut s, |v, _, _| {
            for n in 0..1024 {
                let name = format!("k{n}");
                v.cache.begin_batch()?;
                v.cache.insert_raw(
                    name.as_bytes(),
                    name.as_bytes(),
                    1,
                    1,
                    u64::MAX,
                    &[1; 4],
                    None,
                )?;
            }
            Ok(())
        })?;
        assert_eq!(c.cache().bucket_count(), 1025);
        c.stage(&mut s, |v, _, _| {
            v.cache.begin_batch()?;
            v.cache
                .insert_raw(b"last", b"last", 1, 1, u64::MAX, &[2; 4], None)?;
            let free = v.cache.pool.capacity() - v.cache.pool.live_bytes();
            let pressure = v.cache.pool.allocate(free)?;
            v.cache.pool.release(pressure)?;
            Ok(())
        })?;
        assert_eq!(c.cache().bucket_count(), 1025);
        let ticket = c.take_effect()?.ok_or(Error::NotReady)?;
        assert!(
            matches!(c.effect(ticket)?,Effect::Output(o)if o.payload==Payload::Raw(&[7,8,9,10]))
        );
        let mut out = [0; 32];
        let n = match c.effect(ticket)? {
            Effect::Output(o) => o.encode(&mut out)?,
            _ => return Err(Error::Malformed),
        };
        assert_eq!(&out[..n], b"\0\x0c\0\x05\x01\x01\x01\x01\x07\x08\x09\x0a");
        c.release_effect(ticket)?;
        Ok(())
    }
}
