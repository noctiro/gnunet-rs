//! Bounded GAP content-hash query/return-path ownership; allocation-free by default.
//! Larger official filters use caller-owned route storage or bounded optional `alloc`.
//!
//! This composable layer handles official CORE FS137/138 D/I/UBLOCK/ANY routing.
//! Hosts supply actual CORE neighbor generations, logical source microseconds,
//! cryptographic entropy, original source operations and actual MQ write facts.
//! It opens no socket, datastore, CADET, DHT, timer, task or private wire protocol.
//! Unaddressed requests use hop-by-hop CORE queries. Forward-only requests
//! name their original ingress, and forwarded requests retain provider hints.
//! Higher numeric output needs the explicit privacy owner's real cover permission;
//! this alone is no global anonymity proof.
//! Unsolicited migration remains separate. UBLOCK result groups use
//! the official BLOCK Bloom logic; each original request keeps independent state.
mod group;
/// Bounded history of actual DATASTORE service times.
pub mod load;
/// Real cover-budget claims and bounded randomized release over original IO.
pub mod privacy;
/// Historical scheduling policy for local outbound query plans.
pub mod scheduling;
pub mod storage;
mod timing;
use core::num::NonZeroU16;
use gnunet_crypto::hash512;
use gnunet_types::Error;
/// Inline per-request official BLOCK Bloom bits, independent of result buffers.
/// The full query table is bounded by caller-provided RouteSlots.
pub const GROUP_FILTER_BYTES: usize = group::BYTES;
/// Largest official serialized group's bit array; its nonce is four extra wire bytes.
pub const MAX_GROUP_FILTER_BYTES: usize = gnunet_wire::official::fs_gap::MAX_BLOOM_BYTES;
use gnunet_wire::official::{
    datastore::Data,
    fs::BlockType,
    fs_gap::{GET_PREFIX, Get, KNOWN_OPTIONS, Put, RETURN_TO, TRANSMIT_TO},
    message_type as mt,
};

/// Exclusive local token identity storage; never sent as a wire identifier.
#[derive(Debug, Default)]
pub struct Instance {
    _private: u8,
}
impl Instance {
    /// Construct one token domain.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: 0 }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ref {
    slot: usize,
    serial: u64,
}
macro_rules! token {
    ($name:ident) => {
        #[doc = "Original local owner token. Only its originating router can authorize it."]
        #[derive(Clone, Copy, Debug)]
        pub struct $name<'id> {
            owner: &'id Instance,
            reference: Ref,
        }
        impl PartialEq for $name<'_> {
            fn eq(&self, other: &Self) -> bool {
                core::ptr::eq(self.owner, other.owner) && self.reference == other.reference
            }
        }
        impl Eq for $name<'_> {}
        impl $name<'_> {
            #[doc = "Monotonic diagnostic only, never a wire request ID."]
            #[must_use]
            pub const fn value(self) -> u64 {
                self.reference.serial
            }
        }
    };
}
token!(Neighbor);
token!(Route);
token!(Path);
token!(Transmit);
/// Real connected CORE neighbor slot. Identity is public peer identity bytes.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeighborSlot {
    serial: u64,
    peer: Option<[u8; 32]>,
    withdrawing: bool,
    transmission: timing::TransmissionTiming,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Target {
    Peer(Ref),
    Local(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplyRouting {
    HopByHop,
    DirectToIngress(Ref),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Forwarding {
    replies: ReplyRouting,
    preferred_provider: Option<[u8; 32]>,
}

impl Forwarding {
    const HOP_BY_HOP: Self = Self {
        replies: ReplyRouting::HopByHop,
        preferred_provider: None,
    };

    fn bitmap(self) -> u32 {
        (u32::from(matches!(self.replies, ReplyRouting::DirectToIngress(_))) * RETURN_TO)
            | (u32::from(self.preferred_provider.is_some()) * TRANSMIT_TO)
    }

    fn encoded_len(self) -> usize {
        GET_PREFIX + self.bitmap().count_ones() as usize * 32
    }
}

#[derive(Clone, Copy)]
struct Consumer {
    target: Target,
    forbidden: u64,
    anonymity: u32,
    foreign: bool,
}

impl Consumer {
    const fn local(tag: u64, anonymity: u32) -> Self {
        Self {
            target: Target::Local(tag),
            forbidden: 0,
            anonymity,
            foreign: false,
        }
    }
}
#[derive(Clone, Copy, Debug)]
struct Return {
    serial: u64,
    route: Ref,
    target: Target,
    done: bool,
    delivered: u64,
    anonymity: u32,
    reply_credit: u32,
}

#[derive(Clone, Copy)]
struct Priority {
    forwarding: u32,
    paid: u32,
}

impl Priority {
    const fn unmetered(forwarding: u32) -> Self {
        Self {
            forwarding,
            paid: 0,
        }
    }
}
/// Caller-provided bounded reverse/local return-path slot.
#[derive(Clone, Copy, Debug, Default)]
pub struct PathSlot {
    record: Option<Return>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Source {
    Queued,
    Running,
    Done,
}
#[derive(Clone, Copy, Debug)]
enum StoredSource {
    Unspecified,
    Local(u32),
    Peer { from: Ref, is_local: bool },
}

enum ResultFrame<'bytes> {
    Encoded(&'bytes [u8]),
    Datastore(Put<'bytes>),
}

impl ResultFrame<'_> {
    fn wire_size(&self) -> Result<usize, Error> {
        match self {
            Self::Encoded(frame) => Ok(frame.len()),
            Self::Datastore(put) => put.encoded_len(),
        }
    }

    fn write(self, output: &mut [u8]) -> Result<(), Error> {
        match self {
            Self::Encoded(frame) => output.copy_from_slice(frame),
            Self::Datastore(put) => {
                put.encode(output)?;
            }
        }
        Ok(())
    }
}
/// Actual provenance/anonymity kept outside the original PUT138 bytes.
#[derive(Clone, Copy, Debug)]
pub enum ResultSource<'id> {
    /// No explicit source policy was supplied; external delivery must wait.
    Unspecified,
    /// Actual original DATASTORE anonymity field, including a type6 resolution.
    Local {
        /// Original source anonymity, never inferred from a peer frame.
        anonymity: u32,
    },
    /// Original connected CORE source; peer anonymity is unknown on the wire.
    Peer {
        /// Actual original neighbor generation.
        neighbor: Neighbor<'id>,
        /// Actual CORE local-loopback announcement.
        is_local: bool,
    },
}
/// One real retained result's immutable local ownership/provenance metadata.
#[derive(Clone, Copy, Debug)]
pub struct ResultInfo<'id> {
    /// Original per-route result serial, not a wire request ID.
    pub serial: u64,
    /// Original source facts, independent of application bytes.
    pub source: ResultSource<'id>,
    /// Actual returned concrete type.
    pub block_type: BlockType,
    /// Exact complete original application frame bytes.
    pub bytes: usize,
}
#[derive(Clone, Copy, Debug)]
struct Query {
    serial: u64,
    kind: BlockType,
    key: [u8; 64],
    priority: u32,
    wire_deadline: i128,
    started_us: u64,
    retain_until: u64,
    source: Source,
    retiring: bool,
    forbidden: u64,
    attempted: u64,
    forwards: u16,
    positive: usize,
    result_serial: u64,
    terminal: bool,
    request_group: [u8; 64],
    forwarding: Forwarding,
    foreign: bool,
    result_source: StoredSource,
    unsolicited: bool,
}
/// One caller-provided route and immutable positive frame buffer. It is a real
/// retained result for active reverse paths, not an invented datastore cache hit.
pub struct RouteSlot<'bytes> {
    record: Option<Query>,
    bytes: &'bytes mut [u8],
    group: group::Group<'bytes>,
}
impl<'bytes> RouteSlot<'bytes> {
    /// Borrow one finite original-result buffer.
    #[must_use]
    pub fn new(bytes: &'bytes mut [u8]) -> Self {
        Self::with_group_filter(bytes, &mut [])
    }

    /// Reserve a separate wide Bloom filter buffer alongside this route's result.
    /// Each admitted group uses its original width. The caller can provision a
    /// subset of route slots for filters up to [`MAX_GROUP_FILTER_BYTES`].
    #[must_use]
    pub fn with_group_filter(bytes: &'bytes mut [u8], filter: &'bytes mut [u8]) -> Self {
        Self {
            record: None,
            bytes,
            group: group::Group::empty(filter),
        }
    }
}
/// Explicit local resource/forwarding policy, independent of block expiration.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Finite route/dedup residence in the caller's logical source clock domain.
    pub residence_us: u64,
    /// At most this many distinct actual neighbors per logical query.
    pub fanout: u16,
    /// Bound offered priorities before C-compatible positive-TTL bounding.
    pub max_priority: u32,
    /// Aggregate actual additional filter Vec capacities, including retiring routes.
    /// Zero admits only groups that fit inline or in the caller's fixed storage.
    pub filter_heap_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            residence_us: 60_000_000,
            fanout: 4,
            max_priority: 65535,
            filter_heap_bytes: 1024 * 1024,
        }
    }
}
/// Real retained router state; this is no native operation or completion authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Original live or retiring route records.
    pub routes: usize,
    /// Actual additional filter heap capacities currently owned by those routes.
    pub filter_heap_bytes: usize,
}
/// Actual uniform cryptographic entropy supplied by the host. Failure admits
/// no query. Implementations must return a value strictly below `upper`.
pub trait Entropy {
    /// Actual bounded random draw, not an implicit OS call.
    fn uniform(&mut self, upper: u32) -> Result<u32, Error>;
}
/// Local selection and source port request. An on-demand descriptor must be
/// resolved by the actual shared local owner before passing an actual PUT here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection {
    kind: BlockType,
    /// Original content hash.
    pub query: [u8; 64],
}
impl Selection {
    /// Admit one official D/I/UBLOCK/ANY query type and its original hash.
    pub const fn new(kind: BlockType, query: [u8; 64]) -> Result<Self, Error> {
        if !matches!(
            kind,
            BlockType::ANY | BlockType::DBLOCK | BlockType::IBLOCK | BlockType::UBLOCK
        ) {
            return Err(Error::Unsupported);
        }
        Ok(Self { kind, query })
    }

    /// Original official registry value.
    #[must_use]
    pub const fn kind(self) -> BlockType {
        self.kind
    }

    const fn tracks_results(self) -> bool {
        matches!(self.kind, BlockType::ANY | BlockType::UBLOCK)
    }
}
/// Original one-shot source job; retain its Route token through cancellation.
#[derive(Clone, Copy, Debug)]
pub struct Lookup<'id> {
    /// Exact original query generation.
    pub route: Route<'id>,
    /// Actual selection, no datastore UID/metadata guess.
    pub selection: Selection,
    /// Creation time of that original request in source microseconds.
    pub started_us: u64,
}
/// Query admission has no network or datastore success meaning.
#[derive(Clone, Copy, Debug)]
pub struct Admission<'id> {
    /// Original logical query generation.
    pub route: Route<'id>,
    /// Exact bounded reverse/local return path.
    pub path: Path<'id>,
    /// True only for an existing matching type/key route.
    pub joined: bool,
}

/// Original sender's spendable balance and the current DATASTORE load.
#[derive(Clone, Copy, Debug)]
pub struct GetBudget {
    available: u32,
    load: load::Load,
}

impl GetBudget {
    /// Bind the sender's available respect to one load observation.
    #[must_use]
    pub const fn new(available: u32, load: load::Load) -> Self {
        Self { available, load }
    }

    fn offered(self, requested: u32) -> u32 {
        if self.load.free() {
            0
        } else {
            requested.min(i32::MAX as u32).min(self.available)
        }
    }
}

#[derive(Clone, Copy)]
enum Ingress {
    Loopback,
    Unmetered,
    Accounted(GetBudget),
}

/// Admitted peer request and the exact debit owed by its original sender.
#[derive(Clone, Copy, Debug)]
pub struct ChargedGet<'id> {
    /// Original GAP route and return path.
    pub admission: Admission<'id>,
    /// Respect the transport sender pays once for this accepted frame.
    pub debit: u32,
}

/// Admission of a verified peer result with its one-shot respect credit.
#[derive(Clone, Copy, Debug)]
pub struct PeerResult {
    /// Actual result observation.
    pub state: ResultState,
    /// Respect earned by the original sender of a retained nonterminal result.
    pub credit: u32,
}
/// Actual positive source/peer observation; none implies absence or an END.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultState {
    /// Actual validated result retained atomically.
    Retained,
    /// This request's group already contains the actual whole-result hash.
    Duplicate,
    /// Original operation settled after its local query retired.
    Retired,
    /// Actual source operation completed without a transferable block.
    NoBlock,
    /// Original source operation failed. Its concrete cause remains with the
    /// external owner, including any fatal/Unknown classification; not absence.
    SourceFailed,
    /// No active matching query; this layer performs no migration/cache.
    Unmatched,
}
/// Original immutable outgoing operation type, never a remote processing ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendKind {
    /// Official GET137 to one original neighbor generation.
    Query,
    /// Official PUT138 to one original reverse path.
    Reply,
}
/// Explicit actual consumer of one original retained positive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Destination<'id> {
    /// Current or retired original CORE neighbor generation.
    Neighbor(Neighbor<'id>),
    /// Original caller-supplied local consumer tag, never sent on wire.
    Local(u64),
}
#[derive(Clone, Copy, Debug)]
enum SendTarget {
    Query(Option<NonZeroU16>),
    Reply(Ref),
}

#[derive(Clone, Copy, Debug)]
struct Sending {
    serial: u64,
    neighbor: Ref,
    route: Ref,
    target: SendTarget,
    priority: u32,
    length: usize,
    admitted: bool,
    exposed: bool,
}

/// Authority to plan the next query attempt on the same route and neighbor.
/// Only a complete local CORE write can create it.
#[derive(Debug)]
pub struct RetrySeed<'id> {
    route: Route<'id>,
    neighbor: Neighbor<'id>,
    attempts: NonZeroU16,
}

/// One locally planned retry. Dispatch consumes it and must use its exact
/// original route and neighbor generation.
#[derive(Debug)]
pub struct Retry<'id> {
    seed: RetrySeed<'id>,
    plan: scheduling::Plan,
}

impl<'id> Retry<'id> {
    /// The route that owned the completed original query write.
    #[must_use]
    pub const fn route(&self) -> Route<'id> {
        self.seed.route
    }

    /// The neighbor generation that received the original local handoff.
    #[must_use]
    pub const fn neighbor(&self) -> Neighbor<'id> {
        self.seed.neighbor
    }

    /// Earliest eligible dispatch in the original runtime clock.
    #[must_use]
    pub const fn ready_at(&self) -> u64 {
        self.plan.ready_at()
    }

    /// The local FS queue rank among eligible attempts.
    #[must_use]
    pub const fn weight(&self) -> scheduling::QueueWeight {
        self.plan.weight()
    }
}
/// Original actual send-retirement facts; the concrete host failure remains
/// with its source port. Exposed/failed work is never auto-replayed here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendRetired<'id> {
    /// Original immutable operation.
    pub transmit: Transmit<'id>,
    /// Original actual neighbor.
    pub neighbor: Neighbor<'id>,
    /// Original route, never a replacement owner.
    pub route: Route<'id>,
    /// Actual original kind.
    pub kind: SendKind,
    /// Original reverse result path, absent only for a GET.
    pub path: Option<Path<'id>>,
    /// Exact complete original application bytes, independent of capacity.
    pub bytes: usize,
    /// Whether an actual CORE MQ admitted the original bytes.
    pub admitted: bool,
    /// Whether any actual positive write was observed.
    pub exposed: bool,
    /// Whether this exact local frame actually fully wrote.
    pub written: bool,
}
/// Actual disconnected original neighbor, including any pending original output.
#[derive(Clone, Copy, Debug)]
pub struct Loss<'id> {
    /// Original physical neighbor generation.
    pub neighbor: Neighbor<'id>,
    /// Original retained outgoing operation if any.
    pub pending: Option<SendRetired<'id>>,
}

/// Validate a real transferable FS block and derive its official query key.
/// DBLOCK/IBLOCK use ciphertext SHA512; UBLOCK authenticates its signed envelope.
pub fn validate_put(put: Put<'_>) -> Result<[u8; 64], Error> {
    validated_key(put, &hash512(put.block))
}
fn validated_key(put: Put<'_>, digest: &[u8; 64]) -> Result<[u8; 64], Error> {
    match put.block_type.value() {
        1 | 2 => Ok(*digest),
        9 => {
            let public = put.block.get(72..104).ok_or(Error::Malformed)?;
            let key = hash512(public);
            crate::ublock::verify_envelope(put.block, &key)?;
            Ok(key)
        }
        _ => Err(Error::Unsupported),
    }
}
/// Borrowed authenticated original PUT shared by routing/cache owners. Its
/// private fields prevent a caller from asserting verification without checking.
#[derive(Clone, Copy)]
pub struct CheckedPut<'a> {
    frame: &'a [u8],
    put: Put<'a>,
    key: [u8; 64],
    digest: [u8; 64],
}
impl<'a> CheckedPut<'a> {
    /// Check complete official framing and block authenticity once.
    pub fn decode(frame: &'a [u8]) -> Result<Self, Error> {
        let put = Put::decode(frame)?;
        let digest = hash512(put.block);
        let key = validated_key(put, &digest)?;
        Ok(Self {
            frame,
            put,
            key,
            digest,
        })
    }
    /// Exact original received application frame.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.frame
    }
    /// Already authenticated original fields; no policy metadata is inferred.
    #[must_use]
    pub const fn put(self) -> Put<'a> {
        self.put
    }
    /// Official validated content query key.
    #[must_use]
    pub const fn key(self) -> [u8; 64] {
        self.key
    }
}

/// Actual local interest used for optional cache admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheInterest {
    /// At least one real active local/reverse query matched this block.
    pub requested: bool,
    /// Highest actual bounded offered query priority; absent interest is zero.
    pub priority: u32,
}

/// One bounded router and one immutable outgoing native frame at a time.
pub struct Router<'id, 'slots, 'bytes> {
    owner: &'id Instance,
    neighbors: &'slots mut [NeighborSlot],
    routes: &'slots mut [RouteSlot<'bytes>],
    paths: &'slots mut [PathSlot],
    output: &'bytes mut [u8],
    pending: Option<Sending>,
    serial: u64,
    limits: Limits,
    filter_heap_bytes: usize,
    route_lifetime: timing::RouteLifetime,
    scheduling: scheduling::History,
    stopping: bool,
}
impl<'id, 'slots, 'bytes> Router<'id, 'slots, 'bytes> {
    /// Borrow all finite state. Up to64 neighbor slots allow fixed per-query
    /// loop suppression without per-query heap allocations or identity guessing.
    pub fn new(
        instance: &'id mut Instance,
        neighbors: &'slots mut [NeighborSlot],
        routes: &'slots mut [RouteSlot<'bytes>],
        paths: &'slots mut [PathSlot],
        output: &'bytes mut [u8],
        limits: Limits,
    ) -> Result<Self, Error> {
        if neighbors.is_empty()
            || neighbors.len() > 64
            || routes.is_empty()
            || paths.is_empty()
            || output.len() < GET_PREFIX
            || limits.residence_us == 0
            || limits.fanout == 0
            || limits.max_priority == u32::MAX
        {
            return Err(Error::InvalidInput);
        }
        if neighbors.iter().any(|n| n.peer.is_some())
            || routes.iter().any(|r| r.record.is_some())
            || paths.iter().any(|p| p.record.is_some())
        {
            return Err(Error::Conflict);
        }
        Ok(Self {
            owner: instance,
            neighbors,
            routes,
            paths,
            output,
            pending: None,
            serial: 0,
            limits,
            filter_heap_bytes: 0,
            route_lifetime: timing::RouteLifetime::new(),
            scheduling: scheduling::History::new(),
            stopping: false,
        })
    }
    /// Observe actual current route/filter storage without creating work.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            routes: self.routes.iter().filter(|r| r.record.is_some()).count(),
            filter_heap_bytes: self.filter_heap_bytes,
        }
    }
    fn next_serial(&self) -> Result<u64, Error> {
        self.serial.checked_add(1).ok_or(Error::Overflow)
    }
    fn neighbor(&self, n: Neighbor<'id>) -> Result<Ref, Error> {
        if !core::ptr::eq(self.owner, n.owner) {
            return Err(Error::StaleGeneration);
        }
        self.neighbors
            .get(n.reference.slot)
            .filter(|s| s.serial == n.reference.serial && s.peer.is_some())
            .map(|_| n.reference)
            .ok_or(Error::StaleGeneration)
    }
    fn route(&self, r: Route<'id>) -> Result<Ref, Error> {
        if !core::ptr::eq(self.owner, r.owner) {
            return Err(Error::StaleGeneration);
        }
        self.routes
            .get(r.reference.slot)
            .and_then(|s| s.record)
            .filter(|q| q.serial == r.reference.serial)
            .map(|_| r.reference)
            .ok_or(Error::StaleGeneration)
    }
    fn path(&self, p: Path<'id>) -> Result<Ref, Error> {
        if !core::ptr::eq(self.owner, p.owner) {
            return Err(Error::StaleGeneration);
        }
        self.paths
            .get(p.reference.slot)
            .and_then(|s| s.record)
            .filter(|r| r.serial == p.reference.serial)
            .map(|_| p.reference)
            .ok_or(Error::StaleGeneration)
    }
    fn r(&self, r: Ref) -> Route<'id> {
        Route {
            owner: self.owner,
            reference: r,
        }
    }
    fn p(&self, r: Ref) -> Path<'id> {
        Path {
            owner: self.owner,
            reference: r,
        }
    }
    fn n(&self, r: Ref) -> Neighbor<'id> {
        Neighbor {
            owner: self.owner,
            reference: r,
        }
    }
    fn t(&self, serial: u64) -> Transmit<'id> {
        Transmit {
            owner: self.owner,
            reference: Ref { slot: 0, serial },
        }
    }
    fn query(&self, r: Ref) -> Result<Query, Error> {
        self.routes
            .get(r.slot)
            .and_then(|s| s.record)
            .filter(|q| q.serial == r.serial)
            .ok_or(Error::StaleGeneration)
    }
    /// Fixed borrowed route capacity for a containing owner's bounded metadata.
    #[must_use]
    pub fn route_capacity(&self) -> usize {
        self.routes.len()
    }
    /// Maximum simultaneous retry authorities for all owned routes. Each one
    /// follows a distinct first attempt within that route's fanout.
    pub fn retry_capacity(&self) -> Result<usize, Error> {
        self.route_capacity()
            .checked_mul(self.neighbors.len().min(usize::from(self.limits.fanout)))
            .ok_or(Error::Overflow)
    }
    /// Whether this original source selection is locally retiring. This is no
    /// storage terminal, network absence or permission to replace its generation.
    pub fn retiring(&self, route: Route<'id>) -> Result<bool, Error> {
        Ok(self.query(self.route(route)?)?.retiring)
    }
    /// Original query generation attached to one still-owned reverse path.
    pub fn path_route(&self, path: Path<'id>) -> Result<Route<'id>, Error> {
        let p = self.path(path)?;
        Ok(self.r(self.paths[p.slot]
            .record
            .ok_or(Error::StaleGeneration)?
            .route))
    }
    /// Enumerate real current neighbor tokens for an explicit routing policy.
    pub fn neighbors(&self) -> impl Iterator<Item = Neighbor<'id>> + '_ {
        self.neighbors.iter().enumerate().filter_map(|(slot, n)| {
            n.peer.map(|_| {
                self.n(Ref {
                    slot,
                    serial: n.serial,
                })
            })
        })
    }
    /// Enumerate unresolved routes whose actual source terminal permits CORE
    /// forwarding. The caller chooses neighbors and bounded scheduling fairness.
    pub fn forwarding(&self) -> impl Iterator<Item = Route<'id>> + '_ {
        self.routes.iter().enumerate().filter_map(|(slot, r)| {
            r.record
                .filter(|q| {
                    !q.retiring
                        && q.source == Source::Done
                        && q.positive == 0
                        && !q.terminal
                        && self.relay_origin_live(q.forwarding)
                        && q.forwards < self.limits.fanout
                })
                .map(|q| {
                    self.r(Ref {
                        slot,
                        serial: q.serial,
                    })
                })
        })
    }
    /// Enumerate all still-owned generations, including retired dedup tombstones
    /// and original jobs that must settle before bounded garbage collection.
    pub fn routes(&self) -> impl Iterator<Item = Route<'id>> + '_ {
        self.routes.iter().enumerate().filter_map(|(slot, r)| {
            r.record.map(|q| {
                self.r(Ref {
                    slot,
                    serial: q.serial,
                })
            })
        })
    }
    /// Enumerate positive return paths still awaiting actual consumer ownership.
    pub fn ready_returns(&self) -> impl Iterator<Item = Path<'id>> + '_ {
        self.paths.iter().enumerate().filter_map(|(slot, p)| {
            p.record
                .filter(|p| {
                    !p.done
                        && self.query(p.route).is_ok_and(|q| {
                            !q.retiring && q.positive != 0 && p.delivered != q.result_serial
                        })
                })
                .map(|p| {
                    self.p(Ref {
                        slot,
                        serial: p.serial,
                    })
                })
        })
    }
    /// Original fixed query selection; it carries no local source success.
    pub fn selection(&self, route: Route<'id>) -> Result<Selection, Error> {
        let q = self.query(self.route(route)?)?;
        Ok(Selection {
            kind: q.kind,
            query: q.key,
        })
    }
    /// Original path destination; a stale neighbor never grants replacement
    /// authority. Prepare still verifies actual current connectivity.
    pub fn destination(&self, path: Path<'id>) -> Result<Destination<'id>, Error> {
        let p = self.path(path)?;
        let p = self.paths[p.slot].record.ok_or(Error::StaleGeneration)?;
        Ok(match p.target {
            Target::Peer(n) => Destination::Neighbor(self.n(n)),
            Target::Local(tag) => Destination::Local(tag),
        })
    }
    /// Recover the same immutable pending operation after a canceled wait.
    #[must_use]
    pub fn pending_send(&self) -> Option<Transmit<'id>> {
        self.pending.map(|p| self.t(p.serial))
    }
    /// Attach only an actual authenticated current CORE neighbor, after the
    /// external owner has established it. This method creates no connection.
    pub fn attach(&mut self, peer: [u8; 32]) -> Result<Neighbor<'id>, Error> {
        if self.stopping {
            return Err(Error::Closed);
        }
        if self.neighbors.iter().any(|n| n.peer == Some(peer)) {
            return Err(Error::Conflict);
        }
        let slot = self
            .neighbors
            .iter()
            .position(|n| n.peer.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.next_serial()?;
        self.serial = serial;
        self.neighbors[slot] = NeighborSlot {
            serial,
            peer: Some(peer),
            withdrawing: false,
            transmission: timing::TransmissionTiming::new(),
        };
        Ok(self.n(Ref { slot, serial }))
    }
    /// Original current public peer identity for a real neighbor token.
    pub fn peer(&self, neighbor: Neighbor<'id>) -> Result<[u8; 32], Error> {
        let r = self.neighbor(neighbor)?;
        self.neighbors[r.slot].peer.ok_or(Error::StaleGeneration)
    }

    /// Observe one complete local CORE handoff on its original neighbor.
    /// Queue and completion timestamps use the same clock as GET admission.
    /// A clock rollback leaves the estimate unchanged.
    pub fn record_handoff(
        &mut self,
        neighbor: Neighbor<'id>,
        queued_us: u64,
        now_us: u64,
    ) -> Result<(), Error> {
        let n = self.neighbor(neighbor)?;
        if let Some(elapsed) = now_us.checked_sub(queued_us) {
            self.neighbors[n.slot].transmission.record(elapsed);
        }
        Ok(())
    }
    fn vacant_route(&self, filter_bytes: usize, result_bytes: usize) -> Result<usize, Error> {
        let may_allocate = cfg!(feature = "alloc")
            && filter_bytes
                <= self
                    .limits
                    .filter_heap_bytes
                    .saturating_sub(self.filter_heap_bytes);
        self.routes
            .iter()
            .enumerate()
            .filter(|(_, route)| route.record.is_none() && route.bytes.len() >= result_bytes)
            .filter_map(|(slot, route)| {
                let fixed = route.group.fixed_capacity();
                let needs_heap = fixed < filter_bytes;
                (!needs_heap || may_allocate).then_some((slot, needs_heap, fixed))
            })
            .min_by_key(|&(_, needs_heap, fixed)| (needs_heap, fixed))
            .map(|(slot, _, _)| slot)
            .ok_or(Error::Capacity)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "Original selection/return authority, TTL and independent reply group are explicit admission inputs"
    )]
    fn admit(
        &mut self,
        selection: Selection,
        consumer: Consumer,
        priority: Priority,
        ttl: i32,
        now: u64,
        group: Option<group::Initial<'_, '_>>,
        request_group: [u8; 64],
        forwarding: Forwarding,
        commit: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Admission<'id>, Error> {
        let Consumer {
            target,
            forbidden,
            anonymity,
            foreign,
        } = consumer;
        if self.stopping {
            return Err(Error::Closed);
        }
        let multiple = selection.tracks_results();
        if multiple && group.is_none() {
            return Err(Error::NotReady);
        }
        let old = self.routes.iter().enumerate().find_map(|(slot, r)| {
            r.record
                .filter(|q| {
                    let same_target = || {
                        self.paths.iter().any(|p| {
                            p.record.is_some_and(|p| {
                                p.route
                                    == Ref {
                                        slot,
                                        serial: q.serial,
                                    }
                                    && p.target == target
                            })
                        })
                    };
                    !q.unsolicited
                        && q.kind == selection.kind
                        && q.key == selection.query
                        && q.forwarding == forwarding
                        // A fresh local consumer can repeat a completed block.
                        // Keep the old owner and peer-loop tombstone unchanged.
                        && (!q.retiring || !matches!(target, Target::Local(_)) || same_target())
                        && (!multiple || q.request_group == request_group && same_target())
                })
                .map(|q| Ref {
                    slot,
                    serial: q.serial,
                })
        });
        if let Some(old) = old
            && self.query(old)?.retiring
        {
            return Err(Error::Closed);
        }
        if let Some(route) = old
            && let Some((slot, path)) = self.paths.iter().enumerate().find_map(|(slot, p)| {
                p.record
                    .filter(|p| p.route == route && p.target == target)
                    .map(|p| (slot, p))
            })
        {
            commit()?;
            if let Some(q) = self.routes[route.slot].record.as_mut() {
                q.forbidden |= forbidden;
                q.foreign &= foreign;
                if priority.paid != 0 {
                    q.priority = q
                        .priority
                        .saturating_add(priority.forwarding)
                        .min(self.limits.max_priority);
                    let deadline = i128::from(now) + i128::from(ttl) * 1_000_000;
                    if deadline > q.wire_deadline {
                        q.wire_deadline = deadline;
                        if let Some(path) = self.paths[slot].record.as_mut() {
                            path.reply_credit = path
                                .reply_credit
                                .saturating_add(priority.paid)
                                .min(q.priority);
                        }
                    }
                }
            }
            if let Some(ret) = self.paths[slot].record.as_mut() {
                ret.anonymity = ret.anonymity.max(anonymity);
            }
            return Ok(Admission {
                route: self.r(route),
                path: self.p(Ref {
                    slot,
                    serial: path.serial,
                }),
                joined: true,
            });
        }
        let path_slot = self
            .paths
            .iter()
            .position(|p| p.record.is_none())
            .ok_or(Error::Capacity)?;
        let route_slot = if let Some(old) = old {
            old.slot
        } else {
            self.vacant_route(group.as_ref().map_or(0, group::Initial::len), 0)?
        };
        let route_serial = if let Some(old) = old {
            old.serial
        } else {
            self.next_serial()?
        };
        let path_serial = route_serial
            .max(self.serial)
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let retain_until = now
            .checked_add(self.limits.residence_us)
            .ok_or(Error::Overflow)?;
        let reference = Ref {
            slot: route_slot,
            serial: route_serial,
        };
        let staged_group = if old.is_none()
            && let Some(group) = group
        {
            let available = self
                .limits
                .filter_heap_bytes
                .checked_sub(self.filter_heap_bytes)
                .ok_or(Error::Overflow)?;
            let slot = &mut self.routes[route_slot];
            if let Err(error) = slot.group.initialize(group, available) {
                slot.group.reset();
                return Err(error);
            }
            true
        } else {
            false
        };
        if let Err(error) = commit() {
            if staged_group {
                self.routes[route_slot].group.reset();
            }
            return Err(error);
        }
        if old.is_none() {
            let slot = &mut self.routes[route_slot];
            if staged_group {
                self.filter_heap_bytes += slot.group.heap_bytes();
            }
            slot.record = Some(Query {
                serial: route_serial,
                kind: selection.kind,
                key: selection.query,
                priority: priority.forwarding.min(self.limits.max_priority),
                wire_deadline: i128::from(now) + i128::from(ttl) * 1_000_000,
                started_us: now,
                retain_until,
                source: Source::Queued,
                retiring: false,
                forbidden,
                attempted: 0,
                forwards: 0,
                positive: 0,
                result_serial: 0,
                terminal: false,
                request_group,
                forwarding,
                foreign,
                result_source: StoredSource::Unspecified,
                unsolicited: false,
            });
        } else if let Some(q) = self.routes[route_slot].record.as_mut() {
            q.forbidden |= forbidden;
            q.foreign &= foreign;
        }
        self.paths[path_slot].record = Some(Return {
            serial: path_serial,
            route: reference,
            target,
            done: false,
            delivered: 0,
            anonymity,
            reply_credit: priority.paid,
        });
        self.serial = path_serial;
        Ok(Admission {
            route: self.r(reference),
            path: self.p(Ref {
                slot: path_slot,
                serial: path_serial,
            }),
            joined: old.is_some(),
        })
    }
    /// Actual matching query interest; dedicated unsolicited paths never create
    /// fake requested/cache priority or make incoming content appear solicited.
    pub fn cache_interest(&self, frame: &[u8]) -> Result<CacheInterest, Error> {
        self.cache_interest_checked(CheckedPut::decode(frame)?)
    }
    /// Read matching local interest without repeating block signature checks.
    pub fn cache_interest_checked(&self, checked: CheckedPut<'_>) -> Result<CacheInterest, Error> {
        let put = checked.put;
        let key = checked.key;
        let mut interest = CacheInterest {
            requested: false,
            priority: 0,
        };
        for slot in &*self.routes {
            if let Some(q) = slot.record
                && !q.unsolicited
                && !q.retiring
                && q.key == key
                && (q.kind == put.block_type || q.kind == BlockType::ANY)
            {
                interest.requested = true;
                interest.priority = interest.priority.max(q.priority);
            }
        }
        Ok(interest)
    }
    /// Queue an actual selected block for unsolicited migration to one existing
    /// neighbor. This is a dedicated local transmission owner, never a received
    /// GET, local-client request or network RID. It cannot merge with solicited
    /// paths. Actual source anonymity is retained and gated by the same content
    /// cover policy before external IO; no GET/source lookup is manufactured.
    pub fn queue_push(
        &mut self,
        neighbor: Neighbor<'id>,
        frame: &[u8],
        anonymity: u32,
        now: u64,
    ) -> Result<Admission<'id>, Error> {
        if self.stopping {
            return Err(Error::Closed);
        }
        let target = self.neighbor(neighbor)?;
        let put = Put::decode(frame)?;
        let key = validate_put(put)?;
        // Leave one route and path for genuine queries/relay cover progress.
        if self.routes.iter().filter(|r| r.record.is_none()).count() < 2
            || self.paths.iter().filter(|p| p.record.is_none()).count() < 2
        {
            return Err(Error::Capacity);
        }
        let route_slot = self.vacant_route(0, frame.len())?;
        let path_slot = self
            .paths
            .iter()
            .position(|p| p.record.is_none())
            .ok_or(Error::Capacity)?;
        let route_serial = self.next_serial()?;
        let path_serial = route_serial.checked_add(1).ok_or(Error::Overflow)?;
        let retain_until = now
            .checked_add(self.limits.residence_us)
            .ok_or(Error::Overflow)?;
        let route = Ref {
            slot: route_slot,
            serial: route_serial,
        };
        self.routes[route_slot].bytes[..frame.len()].copy_from_slice(frame);
        self.routes[route_slot].record = Some(Query {
            serial: route_serial,
            kind: put.block_type,
            key,
            priority: 0,
            wire_deadline: i128::from(now),
            started_us: now,
            retain_until,
            source: Source::Done,
            retiring: false,
            forbidden: 0,
            attempted: 0,
            forwards: 0,
            positive: frame.len(),
            result_serial: 1,
            terminal: true,
            request_group: [0; 64],
            forwarding: Forwarding::HOP_BY_HOP,
            foreign: false,
            result_source: StoredSource::Local(anonymity),
            unsolicited: true,
        });
        self.paths[path_slot].record = Some(Return {
            serial: path_serial,
            route,
            target: Target::Peer(target),
            done: false,
            delivered: 0,
            anonymity,
            reply_credit: 0,
        });
        self.serial = path_serial;
        Ok(Admission {
            route: self.r(route),
            path: self.p(Ref {
                slot: path_slot,
                serial: path_serial,
            }),
            joined: false,
        })
    }
    /// Whether this exact original path is an unsolicited migration owner.
    pub fn unsolicited(&self, path: Path<'id>) -> Result<bool, Error> {
        let p = self.path(path)?;
        let ret = self.paths[p.slot].record.ok_or(Error::StaleGeneration)?;
        Ok(self.query(ret.route)?.unsolicited)
    }
    /// Original consumer retirement without fabricating a native IO receipt.
    pub fn path_done(&self, path: Path<'id>) -> Result<bool, Error> {
        let p = self.path(path)?;
        Ok(self.paths[p.slot]
            .record
            .ok_or(Error::StaleGeneration)?
            .done)
    }
    /// Exact path still owned by the one original native output, if any.
    #[must_use]
    pub fn pending_path(&self) -> Option<Path<'id>> {
        match self.pending?.target {
            SendTarget::Reply(path) => Some(self.p(path)),
            SendTarget::Query(_) => None,
        }
    }

    /// Start a local basic-anonymous content request. Level1 deliberately uses
    /// hop-by-hop CORE and emits no target/origin extension. Quantitative levels
    /// above 1 are refused until a real cover/mixing owner is composed.
    ///
    /// This no-entropy convenience admits D/I; UBLOCK/ANY use start_with_seen.
    pub fn start(
        &mut self,
        selection: Selection,
        local_tag: u64,
        anonymity: u32,
        priority: u32,
        ttl_seconds: i32,
        now: u64,
    ) -> Result<Admission<'id>, Error> {
        if anonymity != 1 || selection.tracks_results() {
            return Err(Error::Unsupported);
        }
        self.admit(
            selection,
            Consumer::local(local_tag, anonymity),
            Priority::unmetered(priority),
            ttl_seconds,
            now,
            None,
            [0; 64],
            Forwarding::HOP_BY_HOP,
            || Ok(()),
        )
    }
    /// Start one original request with its actual whole-UBLOCK seen set. Entropy
    /// creates its official local Bloom group for ANY and UBLOCK. Every query
    /// retains its original anonymity level, including level zero.
    /// Output above1 requires the matching live privacy permission,
    /// without adding an anonymity field or private RID to peer messages.
    #[expect(
        clippy::too_many_arguments,
        reason = "Original local query policy and caller seen/entropy ports remain independent"
    )]
    pub fn start_with_seen(
        &mut self,
        selection: Selection,
        local_tag: u64,
        anonymity: u32,
        priority: u32,
        ttl_seconds: i32,
        now: u64,
        seen: &[[u8; 64]],
        entropy: &mut impl Entropy,
    ) -> Result<Admission<'id>, Error> {
        let group = selection
            .tracks_results()
            .then_some(group::Initial::Local { seen, entropy });
        self.admit(
            selection,
            Consumer::local(local_tag, anonymity),
            Priority::unmetered(priority),
            ttl_seconds,
            now,
            group,
            [0; 64],
            Forwarding::HOP_BY_HOP,
            || Ok(()),
        )
    }

    /// Start forwarding after the caller has settled its direct local source
    /// phase. A newly created route schedules no duplicate DATASTORE sweep.
    /// A joined original retains its own queued or running source.
    #[expect(
        clippy::too_many_arguments,
        reason = "Uses the same original policy and entropy inputs as start_with_seen"
    )]
    pub fn start_forwarding_with_seen(
        &mut self,
        selection: Selection,
        local_tag: u64,
        anonymity: u32,
        priority: u32,
        ttl_seconds: i32,
        now: u64,
        seen: &[[u8; 64]],
        entropy: &mut impl Entropy,
    ) -> Result<Admission<'id>, Error> {
        let original = self.start_with_seen(
            selection,
            local_tag,
            anonymity,
            priority,
            ttl_seconds,
            now,
            seen,
            entropy,
        )?;
        if !original.joined {
            let route = self.route(original.route)?;
            self.routes[route.slot]
                .record
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .source = Source::Done;
        }
        Ok(original)
    }

    /// Accept-copy one complete actual neighbor GET. Missing RETURN_TO is the
    /// actual ingress; an explicit return-to must already be a connected neighbor.
    /// Unknown extensions are a refusal, never reinterpreted as a local origin.
    pub fn receive_get(
        &mut self,
        from: Neighbor<'id>,
        frame: &[u8],
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Admission<'id>, Error> {
        self.receive_get_from(from, frame, now, entropy, true)
    }
    /// Accept one original GET with its actual CORE local-loopback provenance.
    /// A nonlocal source can earn cover only through a later actual relay write.
    pub fn receive_get_from(
        &mut self,
        from: Neighbor<'id>,
        frame: &[u8],
        now: u64,
        entropy: &mut impl Entropy,
        is_local: bool,
    ) -> Result<Admission<'id>, Error> {
        let ingress = if is_local {
            Ingress::Loopback
        } else {
            Ingress::Unmetered
        };
        self.receive_get_with_policy(from, frame, now, entropy, ingress, |_| Ok(()))?
            .map(|get| get.admission)
            .ok_or(Error::Conflict)
    }

    /// Admit a nonlocal GET against its original sender's respect. A valid
    /// request declined under load returns `None` and admits no source work.
    pub fn receive_get_accounted(
        &mut self,
        from: Neighbor<'id>,
        frame: &[u8],
        now: u64,
        entropy: &mut impl Entropy,
        budget: GetBudget,
    ) -> Result<Option<ChargedGet<'id>>, Error> {
        self.receive_get_accounted_with(from, frame, now, entropy, budget, |_| Ok(()))
    }

    /// Confirm a positive debit after route admission preflight and before
    /// publishing any changes to a new or existing route. A refused debit
    /// leaves no source lookup or return path on the original peer's behalf.
    pub fn receive_get_accounted_with(
        &mut self,
        from: Neighbor<'id>,
        frame: &[u8],
        now: u64,
        entropy: &mut impl Entropy,
        budget: GetBudget,
        commit_debit: impl FnOnce(u32) -> Result<(), Error>,
    ) -> Result<Option<ChargedGet<'id>>, Error> {
        self.receive_get_with_policy(
            from,
            frame,
            now,
            entropy,
            Ingress::Accounted(budget),
            commit_debit,
        )
    }

    fn receive_get_with_policy(
        &mut self,
        from: Neighbor<'id>,
        frame: &[u8],
        now: u64,
        entropy: &mut impl Entropy,
        policy: Ingress,
        commit_debit: impl FnOnce(u32) -> Result<(), Error>,
    ) -> Result<Option<ChargedGet<'id>>, Error> {
        let ingress = self.neighbor(from)?;
        if self.neighbors[ingress.slot].withdrawing {
            return Err(Error::Closed);
        }
        let get = Get::decode(frame)?;
        let selection = Selection::new(get.block_type, *get.query)?;
        if get.bitmap & !KNOWN_OPTIONS != 0 {
            return Err(Error::Unsupported);
        }
        let target = if let Some(peer) = get.identity(RETURN_TO)? {
            self.neighbors
                .iter()
                .enumerate()
                .find_map(|(slot, n)| {
                    (!n.withdrawing && n.peer.as_ref() == Some(peer)).then_some(Ref {
                        slot,
                        serial: n.serial,
                    })
                })
                .ok_or(Error::NotFound)?
        } else {
            ingress
        };
        let preferred_provider = get.identity(TRANSMIT_TO)?.copied();
        let requested = get.priority.min(self.limits.max_priority);
        let (debit, priority, replies) = match policy {
            Ingress::Accounted(budget) => {
                let offered = budget.offered(requested);
                if !budget.load.free() && !budget.load.admits(offered) {
                    self.scheduling.observe_offer(offered);
                    return Ok(None);
                }
                if self.neighbors[target.slot]
                    .transmission
                    .relay_only(offered, &self.route_lifetime)
                {
                    (
                        offered,
                        Priority::unmetered(0),
                        ReplyRouting::DirectToIngress(ingress),
                    )
                } else {
                    (
                        offered,
                        Priority {
                            forwarding: offered,
                            paid: offered,
                        },
                        ReplyRouting::HopByHop,
                    )
                }
            }
            _ => (0, Priority::unmetered(requested), ReplyRouting::HopByHop),
        };
        // Exact active C bound/decrement; actual send/create TTL unit is seconds.
        let ttl = if get.ttl_seconds > 0 {
            i64::from(get.ttl_seconds)
                .min(i64::from(priority.forwarding) * 5)
                .min(1 << 30)
        } else {
            i64::from(get.ttl_seconds)
        };
        let random = entropy.uniform(5000)?;
        if random >= 5000 {
            return Err(Error::InvalidInput);
        }
        let ttl = i32::try_from(ttl - 10_000 - i64::from(random)).map_err(|_| Error::Overflow)?;
        let raw =
            (get.block_type == BlockType::UBLOCK && !get.bloom.is_empty()).then_some(get.bloom);
        let group = if !selection.tracks_results() {
            None
        } else if let Some(raw) = raw {
            Some(group::Initial::incoming(raw)?)
        } else {
            Some(group::Initial::Local { seen: &[], entropy })
        };
        let admission = self.admit(
            selection,
            Consumer {
                target: Target::Peer(target),
                forbidden: (1_u64 << ingress.slot) | (1_u64 << target.slot),
                anonymity: 1,
                foreign: !matches!(policy, Ingress::Loopback),
            },
            priority,
            ttl,
            now,
            group,
            hash512(get.bloom),
            Forwarding {
                replies,
                preferred_provider,
            },
            || {
                if debit == 0 {
                    Ok(())
                } else {
                    commit_debit(debit)
                }
            },
        )?;
        self.scheduling.observe_offer(debit);
        Ok(Some(ChargedGet { admission, debit }))
    }
    /// Dispatch one actual original local source job. No result/cache hit is
    /// fabricated; cancellation retains Running until source_finished settles it.
    pub fn next_lookup(&mut self) -> Option<Lookup<'id>> {
        let (slot, q) = self.routes.iter().enumerate().find_map(|(s, r)| {
            r.record
                .filter(|q| q.source == Source::Queued && !q.retiring)
                .map(|q| (s, q))
        })?;
        self.routes[slot].record.as_mut()?.source = Source::Running;
        Some(Lookup {
            route: self.r(Ref {
                slot,
                serial: q.serial,
            }),
            selection: Selection {
                kind: q.kind,
                query: q.key,
            },
            started_us: q.started_us,
        })
    }
    fn result_key(put: Put<'_>, digest: &[u8; 64]) -> Result<[u8; 64], Error> {
        validated_key(put, digest)
    }
    fn preflight(
        &mut self,
        route: Ref,
        put: Put<'_>,
        key: &[u8; 64],
        digest: &[u8; 64],
        size: usize,
    ) -> Result<ResultState, Error> {
        let q = self.query(route)?;
        if q.retiring {
            return Ok(ResultState::Retired);
        }
        if q.key != *key || q.kind != BlockType::ANY && q.kind != put.block_type {
            return Err(Error::Authentication);
        }
        if q.positive != 0 {
            let retained = Put::decode(&self.routes[route.slot].bytes[..q.positive])?;
            return if retained.block_type == put.block_type && hash512(retained.block) == *digest {
                Ok(ResultState::Duplicate)
            } else {
                Err(Error::WouldBlock)
            };
        }
        if put.block_type == BlockType::UBLOCK && self.routes[route.slot].group.duplicate(digest)? {
            return Ok(ResultState::Duplicate);
        }
        if q.result_serial == u64::MAX {
            return Err(Error::Overflow);
        }
        if self.routes[route.slot].bytes.len() < size {
            return Err(Error::Capacity);
        }
        Ok(ResultState::Retained)
    }
    fn commit_result(
        &mut self,
        route: Ref,
        frame: ResultFrame<'_>,
        kind: BlockType,
        digest: &[u8; 64],
        source: StoredSource,
        observed_us: Option<u64>,
    ) -> Result<u32, Error> {
        let size = frame.wire_size()?;
        let lifetime = if kind == BlockType::UBLOCK {
            None
        } else {
            let started_us = self.query(route)?.started_us;
            observed_us.and_then(|now| now.checked_sub(started_us))
        };
        if kind == BlockType::UBLOCK {
            self.routes[route.slot].group.mark(digest)?;
        }
        frame.write(&mut self.routes[route.slot].bytes[..size])?;
        let q = self.routes[route.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        q.positive = size;
        q.result_serial += 1;
        q.terminal = kind != BlockType::UBLOCK;
        q.result_source = source;
        if q.source == Source::Queued {
            q.source = Source::Done;
        }
        let mut credit = 0_u32;
        if kind == BlockType::UBLOCK {
            for path in &mut *self.paths {
                if let Some(path) = &mut path.record
                    && path.route == route
                    && !path.done
                {
                    credit = credit.saturating_add(core::mem::take(&mut path.reply_credit));
                }
            }
            if credit != 0 {
                q.priority = 0;
            }
        }
        if let Some(elapsed) = lifetime {
            self.route_lifetime.record(elapsed);
        }
        Ok(credit)
    }
    fn install(
        &mut self,
        route: Ref,
        frame: &[u8],
        source: StoredSource,
        observed_us: Option<u64>,
    ) -> Result<ResultState, Error> {
        if self.query(route)?.retiring {
            return Ok(ResultState::Retired);
        }
        let put = Put::decode(frame)?;
        let digest = hash512(put.block);
        let key = Self::result_key(put, &digest)?;
        let state = self.preflight(route, put, &key, &digest, frame.len())?;
        if state == ResultState::Retained {
            let _consumed = self.commit_result(
                route,
                ResultFrame::Encoded(frame),
                put.block_type,
                &digest,
                source,
                observed_us,
            )?;
        }
        Ok(state)
    }
    /// Whether an actual result is still owned for any original consumer. A
    /// streaming source must pause unadmitted UID continuation while this holds.
    pub fn positive_pending(&self, route: Route<'id>) -> Result<bool, Error> {
        Ok(self.query(self.route(route)?)?.positive != 0)
    }

    /// Whether this live original request has yet to accept its first result.
    pub fn awaiting_first_result(&self, route: Route<'id>) -> Result<bool, Error> {
        let query = self.query(self.route(route)?)?;
        Ok(!query.retiring && query.result_serial == 0)
    }

    /// Decide whether the original local DATASTORE scan may request another
    /// row. An active local client keeps its unlimited-priority source policy.
    pub fn continue_source(&self, route: Route<'id>, load: load::Load) -> Result<bool, Error> {
        let reference = self.route(route)?;
        let query = self.query(reference)?;
        if self.paths.iter().any(|path| {
            path.record.is_some_and(|path| {
                path.route == reference && !path.done && matches!(path.target, Target::Local(_))
            })
        }) {
            return Ok(true);
        }
        Ok(load.free() && query.result_serial <= 5 + 2 * u64::from(query.priority))
    }
    /// Accept one nonterminal original source item. Its real source operation
    /// remains Running until its later original storage terminal/failure retires.
    pub fn source_result(&mut self, route: Route<'id>, frame: &[u8]) -> Result<ResultState, Error> {
        let r = self.route(route)?;
        if self.query(r)?.source != Source::Running {
            return Err(Error::Conflict);
        }
        self.install(r, frame, StoredSource::Unspecified, None)
    }
    /// Accept an actual nonterminal source result together with its original
    /// DATASTORE anonymity. This metadata is absent from the encoded peer PUT.
    pub fn source_result_local(
        &mut self,
        route: Route<'id>,
        frame: &[u8],
        anonymity: u32,
    ) -> Result<ResultState, Error> {
        let r = self.route(route)?;
        if self.query(r)?.source != Source::Running {
            return Err(Error::Conflict);
        }
        self.install(r, frame, StoredSource::Local(anonymity), None)
    }
    /// Validate one real DATASTORE row and encode its official PUT directly
    /// into the original route's result slot. The original source remains
    /// running for keyword results. A retained D/I block settles that source.
    /// Callers check the stored expiry against their qualified absolute clock
    /// before admitting the row. No intermediate full-size frame is required.
    pub fn source_datastore(
        &mut self,
        route: Route<'id>,
        record: Data<'_>,
        observed_us: u64,
    ) -> Result<ResultState, Error> {
        let r = self.route(route)?;
        let original = self.query(r)?;
        if original.source != Source::Running {
            return Err(Error::Conflict);
        }
        if original.retiring {
            return Ok(ResultState::Retired);
        }
        let put = Put {
            block_type: BlockType::new(record.kind),
            expiration: record.expiration,
            block: record.value,
        };
        let size = put.encoded_len()?;
        let digest = hash512(put.block);
        let key = Self::result_key(put, &digest)?;
        if key != *record.key {
            return Err(Error::Authentication);
        }
        let result = self.preflight(r, put, &key, &digest, size)?;
        if result == ResultState::Retained {
            let _credit = self.commit_result(
                r,
                ResultFrame::Datastore(put),
                put.block_type,
                &digest,
                StoredSource::Local(record.anonymity),
                Some(observed_us),
            )?;
            if put.block_type != BlockType::UBLOCK {
                self.routes[r.slot]
                    .record
                    .as_mut()
                    .ok_or(Error::StaleGeneration)?
                    .source = Source::Done;
            }
        }
        Ok(result)
    }
    /// Settle only the actual original source operation. None means its real
    /// no-block terminal; failures stay with the explicit source caller. A type6
    /// descriptor is never accepted in place of a real type1 resolved block.
    pub fn source_finished(
        &mut self,
        route: Route<'id>,
        actual: Option<&[u8]>,
    ) -> Result<ResultState, Error> {
        let r = self.route(route)?;
        let q = self.query(r)?;
        if q.source != Source::Running {
            return Err(Error::Conflict);
        }
        let result = if let Some(frame) = actual {
            self.install(r, frame, StoredSource::Unspecified, None)?
        } else if q.retiring {
            ResultState::Retired
        } else {
            ResultState::NoBlock
        };
        self.routes[r.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .source = Source::Done;
        Ok(result)
    }
    /// Settle one actual local source terminal with its original DATASTORE
    /// anonymity. None remains an actual source terminal, not a peer negative.
    pub fn source_finished_local(
        &mut self,
        route: Route<'id>,
        actual: Option<&[u8]>,
        anonymity: u32,
        observed_us: u64,
    ) -> Result<ResultState, Error> {
        let r = self.route(route)?;
        let q = self.query(r)?;
        if q.source != Source::Running {
            return Err(Error::Conflict);
        }
        let state = if let Some(frame) = actual {
            self.install(r, frame, StoredSource::Local(anonymity), Some(observed_us))?
        } else if q.retiring {
            ResultState::Retired
        } else {
            ResultState::NoBlock
        };
        self.routes[r.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .source = Source::Done;
        Ok(state)
    }
    /// Settle an actual failed original source operation without translating its
    /// cause into NoBlock. The explicit host still owns/reports that exact cause
    /// and applies its fatal/Unknown shutdown policy. This emits no wire result.
    pub fn source_failed(&mut self, route: Route<'id>) -> Result<ResultState, Error> {
        let r = self.route(route)?;
        let q = self.query(r)?;
        if q.source != Source::Running {
            return Err(Error::Conflict);
        }
        self.routes[r.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .source = Source::Done;
        Ok(if q.retiring {
            ResultState::Retired
        } else {
            ResultState::SourceFailed
        })
    }
    /// Consume one actual connected-neighbor PUT after validating its real key.
    /// Unmatched positives cause no cache write or fabricated pending request.
    pub fn receive_put(&mut self, from: Neighbor<'id>, frame: &[u8]) -> Result<ResultState, Error> {
        self.receive_put_from(from, frame, true)
    }
    /// Accept one original PUT with actual CORE local-loopback provenance.
    /// No numeric source anonymity is inferred from this peer frame.
    pub fn receive_put_from(
        &mut self,
        from: Neighbor<'id>,
        frame: &[u8],
        is_local: bool,
    ) -> Result<ResultState, Error> {
        self.receive_put_checked(from, CheckedPut::decode(frame)?, is_local)
    }
    /// Consume an authenticated original PUT without rechecking its signature.
    pub fn receive_put_checked(
        &mut self,
        from: Neighbor<'id>,
        checked: CheckedPut<'_>,
        is_local: bool,
    ) -> Result<ResultState, Error> {
        Ok(self
            .retain_peer_result(from, checked, is_local, None)?
            .state)
    }

    /// Retain a verified original result once and settle each matched path's
    /// remaining credit. Duplicate, terminal and unmatched PUTs earn none.
    pub fn receive_put_accounted(
        &mut self,
        from: Neighbor<'id>,
        checked: CheckedPut<'_>,
        is_local: bool,
        observed_us: u64,
    ) -> Result<PeerResult, Error> {
        self.retain_peer_result(from, checked, is_local, Some(observed_us))
    }

    fn retain_peer_result(
        &mut self,
        from: Neighbor<'id>,
        checked: CheckedPut<'_>,
        is_local: bool,
        observed_us: Option<u64>,
    ) -> Result<PeerResult, Error> {
        let origin = self.neighbor(from)?;
        if self.neighbors[origin.slot].withdrawing {
            return Err(Error::Closed);
        }
        let source = StoredSource::Peer {
            from: origin,
            is_local,
        };
        let frame = checked.frame;
        let put = checked.put;
        let digest = checked.digest;
        let key = checked.key;
        let mut state = ResultState::Unmatched;
        let mut credit = 0_u32;
        // Preflight all matching requests before any original group/result
        // changes. A busy consumer retains the caller's exact original frame.
        for slot in 0..self.routes.len() {
            if let Some(q) = self.routes[slot].record
                && !q.unsolicited
                && q.key == key
                && (q.kind == put.block_type || q.kind == BlockType::ANY)
            {
                let found = self.preflight(
                    Ref {
                        slot,
                        serial: q.serial,
                    },
                    put,
                    &key,
                    &digest,
                    frame.len(),
                )?;
                if found == ResultState::Retained || state == ResultState::Unmatched {
                    state = found;
                }
            }
        }
        for slot in 0..self.routes.len() {
            if let Some(q) = self.routes[slot].record
                && !q.unsolicited
                && q.key == key
                && (q.kind == put.block_type || q.kind == BlockType::ANY)
            {
                let route = Ref {
                    slot,
                    serial: q.serial,
                };
                if self.preflight(route, put, &key, &digest, frame.len())? == ResultState::Retained
                {
                    let settled = self.commit_result(
                        route,
                        ResultFrame::Encoded(frame),
                        put.block_type,
                        &digest,
                        source,
                        observed_us,
                    )?;
                    if !is_local {
                        credit = credit.saturating_add(settled);
                    }
                }
            }
        }
        Ok(PeerResult { state, credit })
    }
    fn begin_send(
        &mut self,
        neighbor: Ref,
        route: Ref,
        target: SendTarget,
        priority: u32,
        length: usize,
    ) -> Result<Transmit<'id>, Error> {
        let serial = self.next_serial()?;
        self.serial = serial;
        self.pending = Some(Sending {
            serial,
            neighbor,
            route,
            target,
            priority,
            length,
            admitted: false,
            exposed: false,
        });
        Ok(self.t(serial))
    }
    /// Actual immutable policy requirement for one prospective query. Any
    /// local consumer preserves its highest active numeric level. A route ever
    /// originating locally is never relabeled as foreign cover after cancel.
    pub fn query_requirement(
        &self,
        route: Route<'id>,
        neighbor: Neighbor<'id>,
    ) -> Result<privacy::Requirement<'id>, Error> {
        self.query_requirement_for(route, neighbor, None)
    }

    fn forwarding_query(&self, r: Ref) -> Result<Query, Error> {
        let q = self.query(r)?;
        if self.stopping || q.retiring || q.terminal || !self.relay_origin_live(q.forwarding) {
            return Err(Error::Closed);
        }
        Ok(q)
    }

    fn relay_origin_live(&self, forwarding: Forwarding) -> bool {
        match forwarding.replies {
            ReplyRouting::HopByHop => true,
            ReplyRouting::DirectToIngress(origin) => self
                .neighbors
                .get(origin.slot)
                .is_some_and(|n| n.serial == origin.serial && n.peer.is_some() && !n.withdrawing),
        }
    }

    fn check_attempt(&self, q: &Query, n: Ref, previous: Option<NonZeroU16>) -> Result<(), Error> {
        if self.neighbors[n.slot].withdrawing {
            return Err(Error::Closed);
        }
        let bit = 1_u64 << n.slot;
        let attempted = q.attempted & bit != 0;
        if q.forbidden & bit != 0
            || attempted != previous.is_some()
            || previous.is_none() && q.forwards >= self.limits.fanout
        {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    fn query_requirement_for(
        &self,
        route: Route<'id>,
        neighbor: Neighbor<'id>,
        previous: Option<NonZeroU16>,
    ) -> Result<privacy::Requirement<'id>, Error> {
        let r = self.route(route)?;
        let n = self.neighbor(neighbor)?;
        let q = self.forwarding_query(r)?;
        if q.source != Source::Done || q.positive != 0 {
            return Err(Error::NotReady);
        }
        self.check_attempt(&q, n, previous)?;
        let level = self
            .paths
            .iter()
            .filter_map(|p| {
                p.record
                    .filter(|p| p.route == r && !p.done && matches!(p.target, Target::Local(_)))
                    .map(|p| p.anonymity)
            })
            .max()
            .unwrap_or(1);
        Ok(privacy::Requirement::query(
            route,
            neighbor,
            previous,
            privacy::Class::new(mt::FS_GET, q.kind, q.forwarding.encoded_len())?,
            level,
            q.foreign,
        ))
    }

    fn retry_residence(&self, seed: &RetrySeed<'id>) -> Result<u64, Error> {
        let route = self.route(seed.route)?;
        let neighbor = self.neighbor(seed.neighbor)?;
        let q = self.forwarding_query(route)?;
        self.check_attempt(&q, neighbor, Some(seed.attempts))?;
        Ok(q.retain_until)
    }

    /// Convert the original completed handoff into one immutable retry plan.
    /// Stale, forbidden or completed routes and exhausted residence retire it.
    pub fn schedule_retry(
        &mut self,
        seed: RetrySeed<'id>,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Option<Retry<'id>>, Error> {
        let Ok(retain_until) = self.retry_residence(&seed) else {
            return Ok(None);
        };
        if retain_until.saturating_sub(now) <= scheduling::RETRY_FLOOR_US {
            return Ok(None);
        }
        let plan = self.scheduling.plan(now, seed.attempts.get(), entropy)?;
        Ok((plan.ready_at() < retain_until).then_some(Retry { seed, plan }))
    }

    /// Whether the original planned retry may still become eligible during its
    /// residence. A held nonterminal positive pauses dispatch.
    #[must_use]
    pub fn retry_current(&self, retry: &Retry<'id>, now: u64) -> bool {
        self.retry_residence(&retry.seed)
            .is_ok_and(|end| now < end && retry.ready_at() < end)
    }

    /// Current privacy requirements for this retry's original route and peer.
    /// Dispatch also verifies the plan's clock target.
    pub fn retry_requirement(
        &self,
        retry: &Retry<'id>,
    ) -> Result<privacy::Requirement<'id>, Error> {
        self.query_requirement_for(retry.route(), retry.neighbor(), Some(retry.seed.attempts))
    }
    /// Original positive/provenance for one still-owned return path. This
    /// distinguishes actual local DATA anonymity from unknown peer metadata.
    pub fn result_info(&self, path: Path<'id>) -> Result<ResultInfo<'id>, Error> {
        let p = self.path(path)?;
        let ret = self.paths[p.slot].record.ok_or(Error::StaleGeneration)?;
        let q = self.query(ret.route)?;
        if q.positive == 0 {
            return Err(Error::NotReady);
        }
        let put = Put::decode(&self.routes[ret.route.slot].bytes[..q.positive])?;
        let source = match q.result_source {
            StoredSource::Unspecified => ResultSource::Unspecified,
            StoredSource::Local(anonymity) => ResultSource::Local { anonymity },
            StoredSource::Peer { from, is_local } => ResultSource::Peer {
                neighbor: self.n(from),
                is_local,
            },
        };
        Ok(ResultInfo {
            serial: q.result_serial,
            source,
            block_type: put.block_type,
            bytes: q.positive,
        })
    }
    /// Actual reply requirement. Local publisher metadata above1 requires real
    /// content cover; peer replies explicitly retain unknown source anonymity.
    pub fn reply_requirement(&self, path: Path<'id>) -> Result<privacy::Requirement<'id>, Error> {
        let p = self.path(path)?;
        let ret = self.paths[p.slot].record.ok_or(Error::StaleGeneration)?;
        let q = self.query(ret.route)?;
        if ret.done || q.retiring {
            return Err(Error::Closed);
        }
        if q.positive == 0 || ret.delivered == q.result_serial {
            return Err(Error::NotReady);
        }
        let Target::Peer(target) = ret.target else {
            return Err(Error::InvalidInput);
        };
        let neighbor = self.n(target);
        self.neighbor(neighbor)?;
        let info = self.result_info(path)?;
        let (level, relay, known, delayed) = match q.result_source {
            StoredSource::Unspecified => (None, false, false, false),
            StoredSource::Local(anonymity) => (Some(anonymity), false, true, anonymity != 0),
            StoredSource::Peer { from, is_local } => {
                (None, !is_local && from != target, true, true)
            }
        };
        Ok(privacy::Requirement::reply(
            self.r(ret.route),
            path,
            info.serial,
            neighbor,
            privacy::Class::new(mt::FS_PUT, info.block_type, info.bytes)?,
            level,
            relay,
            known,
            delayed,
        ))
    }
    /// Original absolute local residence target. A separate unadmitted policy
    /// hold may retire explicitly at this bound; it is never a wire absence.
    pub fn residence_deadline(&self, route: Route<'id>) -> Result<u64, Error> {
        Ok(self.query(self.route(route)?)?.retain_until)
    }
    /// Borrow the actual still-unconsumed positive for a policy/consumer owner.
    /// This grants no send permission and does not commit its original path.
    pub fn retained_result(&self, path: Path<'id>) -> Result<Option<&[u8]>, Error> {
        let p = self.path(path)?;
        let ret = self.paths[p.slot].record.ok_or(Error::StaleGeneration)?;
        let q = self.query(ret.route)?;
        if ret.done || q.retiring || q.positive == 0 || ret.delivered == q.result_serial {
            return Ok(None);
        }
        Ok(Some(&self.routes[ret.route.slot].bytes[..q.positive]))
    }
    /// Check a queued metadata intent against this exact current generation and
    /// result. Retired paths/updated source facts cannot mint a stale admission.
    #[must_use]
    pub fn requirement_current(&self, requirement: privacy::Requirement<'id>) -> bool {
        let current = if let Some(path) = requirement.path() {
            self.reply_requirement(path)
        } else {
            self.query_requirement_for(
                requirement.route(),
                requirement.neighbor(),
                requirement.previous_attempts(),
            )
        };
        current.is_ok_and(|r| r == requirement)
    }
    /// Basic no-cover query preparation. Higher numeric requests require the
    /// corresponding live policy permission; they are never sent as level1.
    pub fn prepare_query(
        &mut self,
        route: Route<'id>,
        neighbor: Neighbor<'id>,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Transmit<'id>, Error> {
        if self.query_requirement(route, neighbor)?.needed() != 0 {
            return Err(Error::NotReady);
        }
        self.prepare_query_inner(route, neighbor, now, entropy, None)
    }
    /// Prepare only this exact query authorized by the explicit cover owner.
    pub fn prepare_query_with_permit(
        &mut self,
        route: Route<'id>,
        neighbor: Neighbor<'id>,
        now: u64,
        entropy: &mut impl Entropy,
        permit: privacy::Permit<'id>,
    ) -> Result<Transmit<'id>, Error> {
        permit.authorizes(self.query_requirement(route, neighbor)?)?;
        self.prepare_query_inner(route, neighbor, now, entropy, None)
    }

    /// Prepare this original elapsed retry once under its own live permission.
    /// The route's current wire TTL, remaining respect and coverage are used.
    pub fn prepare_retry_with_permit(
        &mut self,
        retry: Retry<'id>,
        now: u64,
        entropy: &mut impl Entropy,
        permit: privacy::Permit<'id>,
    ) -> Result<Transmit<'id>, Error> {
        if now < retry.ready_at() {
            return Err(Error::NotReady);
        }
        permit.authorizes(self.retry_requirement(&retry)?)?;
        self.prepare_query_inner(
            retry.route(),
            retry.neighbor(),
            now,
            entropy,
            Some(retry.seed.attempts),
        )
    }
    /// Prepare an anonymous hop-by-hop query to one explicit real neighbor.
    /// Caller chooses routing/queue heuristics; this enforces loop/fanout bounds,
    /// local-source completion, real elapsed TTL seconds and priority spending.
    fn prepare_query_inner(
        &mut self,
        route: Route<'id>,
        neighbor: Neighbor<'id>,
        now: u64,
        entropy: &mut impl Entropy,
        previous: Option<NonZeroU16>,
    ) -> Result<Transmit<'id>, Error> {
        let r = self.route(route)?;
        let n = self.neighbor(neighbor)?;
        if self.stopping {
            return Err(Error::Closed);
        }
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let q = self.forwarding_query(r)?;
        if now >= q.retain_until {
            return Err(Error::Closed);
        }
        if q.source != Source::Done || q.positive != 0 {
            return Err(Error::NotReady);
        }
        self.check_attempt(&q, n, previous)?;
        let ttl = i32::try_from((q.wire_deadline - i128::from(now)) / 1_000_000)
            .map_err(|_| Error::Overflow)?;
        let mut identities = [[0_u8; 32]; 2];
        let mut used = 0;
        let priority = if let ReplyRouting::DirectToIngress(origin) = q.forwarding.replies {
            identities[used] = self.peer(self.n(origin))?;
            used += 1;
            0
        } else {
            entropy.uniform(q.priority + 1)?
        };
        if let Some(provider) = q.forwarding.preferred_provider {
            identities[used] = provider;
            used += 1;
        }
        if priority > q.priority {
            return Err(Error::InvalidInput);
        }
        let length = Get {
            block_type: q.kind,
            priority,
            ttl_seconds: ttl,
            reserved: 0,
            bitmap: q.forwarding.bitmap(),
            query: &q.key,
            identities: identities[..used].as_flattened(),
            bloom: &[],
        }
        .encode(self.output)?;
        let tx = self.begin_send(n, r, SendTarget::Query(previous), priority, length)?;
        if previous.is_none() {
            self.scheduling.observe_initial();
        }
        Ok(tx)
    }
    /// Basic reply preparation with actual supplied source policy. A local
    /// source above1 needs a live content-cover permission; unknown peer policy
    /// remains separate from omitted metadata.
    pub fn prepare_reply(&mut self, path: Path<'id>) -> Result<Transmit<'id>, Error> {
        let requirement = self.reply_requirement(path)?;
        if !requirement.source_policy_supplied() || requirement.needed() != 0 {
            return Err(Error::NotReady);
        }
        self.prepare_reply_inner(path)
    }
    /// Prepare only the exact retained result/path under its live permission.
    pub fn prepare_reply_with_permit(
        &mut self,
        path: Path<'id>,
        permit: privacy::Permit<'id>,
    ) -> Result<Transmit<'id>, Error> {
        permit.authorizes(self.reply_requirement(path)?)?;
        self.prepare_reply_inner(path)
    }
    /// Prepare exact original positive bytes for one still-owned reverse path.
    fn prepare_reply_inner(&mut self, path: Path<'id>) -> Result<Transmit<'id>, Error> {
        if self.stopping {
            return Err(Error::Closed);
        }
        let p = self.path(path)?;
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let ret = self.paths[p.slot].record.ok_or(Error::StaleGeneration)?;
        let q = self.query(ret.route)?;
        if ret.done || q.retiring || ret.delivered == q.result_serial && q.positive != 0 {
            return Err(Error::Closed);
        }
        let Target::Peer(neighbor) = ret.target else {
            return Err(Error::InvalidInput);
        };
        self.neighbor(self.n(neighbor))?;
        if q.positive == 0 {
            return Err(Error::NotReady);
        }
        let out = self.output.get_mut(..q.positive).ok_or(Error::Capacity)?;
        out.copy_from_slice(&self.routes[ret.route.slot].bytes[..q.positive]);
        self.begin_send(neighbor, ret.route, SendTarget::Reply(p), 0, q.positive)
    }
    fn sending(&self, tx: Transmit<'id>) -> Result<Sending, Error> {
        if !core::ptr::eq(self.owner, tx.owner) {
            return Err(Error::StaleGeneration);
        }
        self.pending
            .filter(|p| p.serial == tx.reference.serial)
            .ok_or(Error::StaleGeneration)
    }
    /// Exact immutable native bytes and original neighbor; retained until actual
    /// full write or explicit physical failure settlement. Caller must not ACK a
    /// retained input before its chosen accept-copy/ownership policy allows it.
    pub fn send_bytes(&self, tx: Transmit<'id>) -> Result<(Neighbor<'id>, &[u8]), Error> {
        let p = self.sending(tx)?;
        Ok((self.n(p.neighbor), &self.output[..p.length]))
    }
    /// Whether any named relay origin still authorizes this prepared send.
    /// A withdrawn origin leaves already exposed bytes on their original MQ.
    pub fn relay_origin_current(&self, tx: Transmit<'id>) -> Result<bool, Error> {
        let p = self.sending(tx)?;
        Ok(!matches!(p.target, SendTarget::Query(_))
            || self.relay_origin_live(self.query(p.route)?.forwarding))
    }
    /// Record actual MQ admission, not remote transmission or processing.
    pub fn admitted(&mut self, tx: Transmit<'id>) -> Result<(), Error> {
        self.sending(tx)?;
        self.pending
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .admitted = true;
        Ok(())
    }
    /// Record only a positive actual original write on its exact MQ generation.
    pub fn exposed(&mut self, tx: Transmit<'id>) -> Result<(), Error> {
        let p = self.sending(tx)?;
        if !p.admitted {
            return Err(Error::NotReady);
        }
        self.pending.as_mut().ok_or(Error::StaleGeneration)?.exposed = true;
        Ok(())
    }
    fn settle_send(&mut self, p: Sending, success: bool) -> Result<SendRetired<'id>, Error> {
        let (kind, path) = match p.target {
            SendTarget::Reply(path) => {
                let q = self.query(p.route)?;
                if let Some(ret) = self.paths[path.slot]
                    .record
                    .as_mut()
                    .filter(|r| r.serial == path.serial)
                {
                    ret.delivered = q.result_serial;
                    ret.done = q.terminal;
                }
                self.release_positive(p.route)?;
                (SendKind::Reply, Some(self.p(path)))
            }
            SendTarget::Query(previous) => {
                if let Some(q) = self.routes[p.route.slot]
                    .record
                    .as_mut()
                    .filter(|q| q.serial == p.route.serial)
                {
                    if previous.is_none() {
                        q.attempted |= 1_u64 << p.neighbor.slot;
                        q.forwards = q.forwards.saturating_add(1);
                    }
                    q.priority = q.priority.saturating_sub(p.priority);
                }
                (SendKind::Query, None)
            }
        };
        let fact = SendRetired {
            transmit: self.t(p.serial),
            neighbor: self.n(p.neighbor),
            route: self.r(p.route),
            kind,
            path,
            bytes: p.length,
            admitted: p.admitted,
            exposed: p.exposed,
            written: success,
        };
        self.pending = None;
        Ok(fact)
    }
    /// Commit an actual full original write. This releases local output storage;
    /// it is not a reply, peer processing acknowledgement or successful lookup.
    pub fn written(&mut self, tx: Transmit<'id>) -> Result<SendRetired<'id>, Error> {
        self.written_for_forwarding(tx).map(|(fact, _)| fact)
    }

    /// Commit an actual full original write and retain its single authority to
    /// plan a follow-up query on the same route and CORE generation.
    pub fn written_for_forwarding(
        &mut self,
        tx: Transmit<'id>,
    ) -> Result<(SendRetired<'id>, Option<RetrySeed<'id>>), Error> {
        let p = self.sending(tx)?;
        if !p.admitted || !p.exposed {
            return Err(Error::NotReady);
        }
        let fact = self.settle_send(p, true)?;
        let seed = match p.target {
            SendTarget::Query(previous) => previous
                .map_or(Some(1), |n| n.get().checked_add(1))
                .and_then(NonZeroU16::new)
                .map(|attempts| RetrySeed {
                    route: fact.route,
                    neighbor: fact.neighbor,
                    attempts,
                }),
            SendTarget::Reply(_) => None,
        };
        Ok((fact, seed))
    }
    /// Settle only after the original external MQ operation physically stopped.
    /// Its concrete failure/Unknown remains owned by the caller. No automatic
    /// same-query replay is scheduled, including on a replacement generation.
    pub fn send_failed(&mut self, tx: Transmit<'id>) -> Result<SendRetired<'id>, Error> {
        let p = self.sending(tx)?;
        self.settle_send(p, false)
    }
    /// Borrow an actual validated positive for a local caller. Copy/admit it to
    /// the original consumer before commit_local; dropping this borrow does not.
    pub fn local_result(&self, path: Path<'id>) -> Result<Option<(u64, &[u8])>, Error> {
        let p = self.path(path)?;
        let ret = self.paths[p.slot].record.ok_or(Error::StaleGeneration)?;
        let q = self.query(ret.route)?;
        let Target::Local(tag) = ret.target else {
            return Err(Error::InvalidInput);
        };
        if ret.done || q.retiring || q.positive == 0 || ret.delivered == q.result_serial {
            return Ok(None);
        }
        Ok(Some((
            tag,
            &self.routes[ret.route.slot].bytes[..q.positive],
        )))
    }
    /// Commit only actual local consumer ownership, independently of network IO.
    pub fn commit_local(&mut self, path: Path<'id>) -> Result<(), Error> {
        if self.local_result(path)?.is_none() {
            return Err(Error::NotReady);
        }
        let p = self.path(path)?;
        let route = self.paths[p.slot]
            .record
            .ok_or(Error::StaleGeneration)?
            .route;
        let q = self.query(route)?;
        let ret = self.paths[p.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        ret.delivered = q.result_serial;
        ret.done = q.terminal;
        self.release_positive(route)
    }
    fn release_positive(&mut self, route: Ref) -> Result<(), Error> {
        let q = self.query(route)?;
        if q.positive != 0
            && self.paths.iter().all(|p| {
                p.record
                    .is_none_or(|p| p.route != route || p.done || p.delivered == q.result_serial)
            })
        {
            self.routes[route.slot].bytes[..q.positive].fill(0);
            self.routes[route.slot]
                .record
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .positive = 0;
            self.retire_if_unused(route);
        }
        Ok(())
    }
    fn retire_if_unused(&mut self, r: Ref) {
        if self
            .paths
            .iter()
            .all(|p| p.record.is_none_or(|p| p.route != r || p.done))
            && let Some(q) = self.routes[r.slot]
                .record
                .as_mut()
                .filter(|q| q.serial == r.serial)
        {
            q.retiring = true;
            if q.source == Source::Queued {
                q.source = Source::Done;
            }
        }
    }
    /// Cancel just this original local/reverse consumer, with no cancel wire or
    /// END. A running source/native operation retains its old generation.
    pub fn cancel(&mut self, path: Path<'id>) -> Result<(), Error> {
        let p = self.path(path)?;
        let ret = self.paths[p.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        ret.done = true;
        let r = ret.route;
        self.release_positive(r)?;
        self.retire_if_unused(r);
        Ok(())
    }
    /// Withdraw only this original neighbor's reverse consumers after an actual
    /// disconnect notice. Frozen/native output remains original and pending;
    /// this is deliberately separate from physical disconnect/send settlement.
    pub fn retire_neighbor_paths(&mut self, neighbor: Neighbor<'id>) -> Result<(), Error> {
        let n = self.neighbor(neighbor)?;
        self.neighbors[n.slot].withdrawing = true;
        for p in &mut *self.paths {
            if let Some(p) = p.record.as_mut()
                && p.target == Target::Peer(n)
            {
                p.done = true;
            }
        }
        for slot in 0..self.routes.len() {
            if let Some(q) = self.routes[slot].record {
                self.retire_if_unused(Ref {
                    slot,
                    serial: q.serial,
                });
            }
        }
        Ok(())
    }
    /// Actual CORE physical neighbor loss. Call only after that original MQ and
    /// any original write stopped; preserve returned exposure with its cause.
    pub fn disconnect(&mut self, neighbor: Neighbor<'id>) -> Result<Loss<'id>, Error> {
        let n = self.neighbor(neighbor)?;
        let pending = if let Some(p) = self.pending.filter(|p| p.neighbor == n) {
            Some(self.settle_send(p, false)?)
        } else {
            None
        };
        self.neighbors[n.slot].peer = None;
        for slot in 0..self.paths.len() {
            if let Some(p) = self.paths[slot].record.as_mut()
                && p.target == Target::Peer(n)
            {
                p.done = true;
            }
        }
        for slot in 0..self.routes.len() {
            if let Some(q) = self.routes[slot].record {
                self.retire_if_unused(Ref {
                    slot,
                    serial: q.serial,
                });
            }
        }
        Ok(Loss { neighbor, pending })
    }
    /// Next absolute logical residence/collection target requiring a host wake.
    /// Held real positives and original unsettled retired jobs have their own
    /// consumer/operation wake; they never create a perpetually due timer.
    pub fn next_deadline(&self, now: u64) -> Option<u64> {
        self.routes
            .iter()
            .enumerate()
            .filter_map(|(slot, r)| {
                let q = r.record?;
                let reference = Ref {
                    slot,
                    serial: q.serial,
                };
                if q.retiring {
                    (q.source == Source::Done
                        && !self.pending.is_some_and(|p| p.route == reference)
                        && q.retain_until > now)
                        .then_some(q.retain_until)
                } else if q.positive != 0
                    && self
                        .paths
                        .iter()
                        .any(|p| p.record.is_some_and(|p| p.route == reference && !p.done))
                {
                    None
                } else {
                    Some(q.retain_until)
                }
            })
            .min()
    }
    /// Retire one elapsed local residence. A real positive held for an actual
    /// consumer remains owned until delivery/cancel. Negative wire TTL stays a
    /// valid signed metric; this independent bound limits local query memory.
    pub fn expire(&mut self, now: u64) -> Result<Option<Route<'id>>, Error> {
        let item = self.routes.iter().enumerate().find_map(|(slot, r)| {
            r.record
                .filter(|q| {
                    !q.retiring
                        && now >= q.retain_until
                        && (q.positive == 0
                            || !self.paths.iter().any(|p| {
                                p.record.is_some_and(|p| {
                                    p.route
                                        == Ref {
                                            slot,
                                            serial: q.serial,
                                        }
                                        && !p.done
                                })
                            }))
                })
                .map(|q| Ref {
                    slot,
                    serial: q.serial,
                })
        });
        let Some(r) = item else {
            return Ok(None);
        };
        if let Some(q) = self.routes[r.slot].record.as_mut() {
            q.retiring = true;
            if q.source == Source::Queued {
                q.source = Source::Done;
            }
        }
        for p in &mut *self.paths {
            if let Some(p) = p.record.as_mut()
                && p.route == r
            {
                p.done = true;
            }
        }
        Ok(Some(self.r(r)))
    }
    /// Stop new ingress/forwarding and retire all local consumers. Original
    /// dispatched source jobs and admitted/exposed native sends still settle
    /// through their actual ports; this emits no END, negative or wire cancel.
    pub fn request_shutdown(&mut self) {
        self.stopping = true;
        for r in &mut *self.routes {
            if let Some(q) = r.record.as_mut() {
                q.retiring = true;
                if q.source == Source::Queued {
                    q.source = Source::Done;
                }
            }
        }
        for p in &mut *self.paths {
            if let Some(p) = p.record.as_mut() {
                p.done = true;
            }
        }
    }
    /// Only local original source/output ownership has settled. This does not
    /// claim CORE transport disconnection, remote processing or network quiescence.
    #[must_use]
    pub fn quiesced(&self) -> bool {
        self.stopping
            && self.pending.is_none()
            && self
                .routes
                .iter()
                .all(|r| r.record.is_none_or(|q| q.source != Source::Running))
    }

    /// Release retired routes after all original operations and GAP neighbors
    /// retire, without reopening admission.
    pub fn finish_shutdown(&mut self) -> Result<(), Error> {
        if !self.stopping {
            return Err(Error::Conflict);
        }
        if !self.quiesced() || self.neighbors.iter().any(|slot| slot.peer.is_some()) {
            return Err(Error::WouldBlock);
        }
        for slot in 0..self.routes.len() {
            if let Some(query) = self.routes[slot].record {
                self.clear_route(
                    Ref {
                        slot,
                        serial: query.serial,
                    },
                    query.positive,
                )?;
            }
        }
        Ok(())
    }

    /// Reopen the workspace. Old tokens cannot authorize new work.
    pub fn restart(&mut self) -> Result<(), Error> {
        self.finish_shutdown()?;
        self.route_lifetime = timing::RouteLifetime::new();
        self.scheduling = scheduling::History::new();
        self.stopping = false;
        Ok(())
    }

    /// Release only an expired dedup tombstone whose actual original source and
    /// native output have settled. Time/cancel never turns an operation into END.
    pub fn collect(&mut self, route: Route<'id>, now: u64) -> Result<(), Error> {
        let r = self.route(route)?;
        let q = self.query(r)?;
        if !q.retiring
            || (!self.stopping && now < q.retain_until)
            || q.source != Source::Done
            || self.pending.is_some_and(|p| p.route == r)
        {
            return Err(Error::WouldBlock);
        }
        self.clear_route(r, q.positive)
    }

    fn clear_route(&mut self, r: Ref, positive: usize) -> Result<(), Error> {
        let heap = self
            .filter_heap_bytes
            .checked_sub(self.routes[r.slot].group.heap_bytes())
            .ok_or(Error::Overflow)?;
        self.routes[r.slot].bytes[..positive].fill(0);
        self.routes[r.slot].record = None;
        self.routes[r.slot].group.reset();
        self.filter_heap_bytes = heap;
        for p in &mut *self.paths {
            if p.record.is_some_and(|p| p.route == r) {
                p.record = None;
            }
        }
        Ok(())
    }
}
