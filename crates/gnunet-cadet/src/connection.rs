//! Bounded CORE-neighbor routing and connection ownership for CADET peer frames.
//!
//! CID is a route label, never endpoint authentication. A current actual CORE
//! neighbor generation must authorize every input direction before CID lookup
//! can grant endpoint/forwarding authority. Tunnel KX/AEAD remains a separate port.
use core::{fmt, ptr};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, Entropy};
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::cadet_peer::{
    CONNECTION_CREATE_PREFIX, CONNECTION_INITIATOR_PURPOSE, ConnectionInitiatorPurpose, PathPeers,
    PeerMessage,
};

/// Distinct exclusively borrowed identity for one original routing book.
#[derive(Default)]
pub struct Instance {
    marker: u8,
}
impl Instance {
    /// Construct local identity without a global counter.
    #[must_use]
    pub const fn new() -> Self {
        Self { marker: 0 }
    }
}
#[derive(Clone, Copy)]
struct Brand<'a>(&'a Instance);
impl PartialEq for Brand<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.0, other.0)
    }
}
impl Eq for Brand<'_> {}
impl fmt::Debug for Brand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _marker = self.0.marker;
        f.write_str("ConnectionBook")
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NeighborRef {
    slot: usize,
    serial: u64,
    peer: [u8; 32],
}
/// Current actual CORE peer announcement, including its original generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Neighbor<'a> {
    brand: Brand<'a>,
    reference: NeighborRef,
}
impl Neighbor<'_> {
    /// Actual announced CORE peer identity, not a CID lookup.
    #[must_use]
    pub const fn identity(self) -> [u8; 32] {
        self.reference.peer
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RouteRef {
    slot: usize,
    serial: u64,
    connection: [u8; 32],
}
/// Original local route allocation. Equal raw CIDs cannot replace this authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route<'a> {
    brand: Brand<'a>,
    reference: RouteRef,
}
impl Route<'_> {
    /// Actual opaque connection label; not an authenticated peer.
    #[must_use]
    pub const fn connection(self) -> [u8; 32] {
        self.reference.connection
    }
}
/// Original retained immutable frame generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Frame<'a> {
    brand: Brand<'a>,
    slot: usize,
    serial: u64,
}
/// Original CORE send attempt, retaining its target and optional route epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Attempt<'a> {
    frame: Frame<'a>,
    serial: u64,
    neighbor: Neighbor<'a>,
    route: Option<Route<'a>>,
}
impl<'a> Attempt<'a> {
    /// Original immutable frame, not merely its route CID.
    #[must_use]
    pub const fn frame(self) -> Frame<'a> {
        self.frame
    }
    /// Exact original CORE peer generation that owns this physical attempt.
    #[must_use]
    pub const fn neighbor(self) -> Neighbor<'a> {
        self.neighbor
    }
    /// Original route allocation, absent for an unknown-route BROKEN reply.
    #[must_use]
    pub const fn route(self) -> Option<Route<'a>> {
        self.route
    }
}
/// One async PILS signature request scoped to original route and monotime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignRequest<'a> {
    route: Route<'a>,
    monotime: u64,
}
impl<'id> SignRequest<'id> {
    /// Original route capability; neither CID nor a numeric slot is authority.
    #[must_use]
    pub const fn route(self) -> Route<'id> {
        self.route
    }
    /// Original exact signed monotime, without sampling or extending its value.
    #[must_use]
    pub const fn monotime(self) -> u64 {
        self.monotime
    }
    /// Encode exactly purpose38 and the original monotime.
    pub fn purpose(self, output: &mut [u8]) -> Result<usize, Error> {
        ConnectionInitiatorPurpose {
            monotime: self.monotime,
        }
        .encode(output)
    }
}
/// Initial outgoing CREATE authentication selected by the actual tunnel owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authentication {
    /// Ordinary CREATE when no tunnel-reset request is needed.
    Unsigned,
    /// Async PILS must sign the exact original initiator monotime.
    Monotime(u64),
}
/// Original local connection-book authority, never an on-wire credential.
/// A containing controller can bind reset proofs to this exact source domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResetAuthority<'a> {
    brand: Brand<'a>,
    local: [u8; 32],
}
impl ResetAuthority<'_> {
    /// Actual local identity originally bound to this book.
    #[must_use]
    pub const fn local(self) -> [u8; 32] {
        self.local
    }
}
/// Non-forgeable evidence of an actually verified original origin signature and
/// strict replay high-water advancement at this destination's connection book.
/// Copies remain the same observation; controllers must suppress repeated use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResetProof<'a> {
    authority: ResetAuthority<'a>,
    origin: [u8; 32],
    monotime: u64,
}
impl<'a> ResetProof<'a> {
    /// Original exact local connection-book source domain.
    #[must_use]
    pub const fn authority(self) -> ResetAuthority<'a> {
        self.authority
    }
    /// Actual signed original origin identity, not an adjacent-hop identity.
    #[must_use]
    pub const fn origin(self) -> [u8; 32] {
        self.origin
    }
    /// Strictly newer verified monotime in the origin's domain.
    #[must_use]
    pub const fn monotime(self) -> u64 {
        self.monotime
    }
}
/// Actual initiator observation; this authorizes only a fresh reset request,
/// never path ownership, endpoint identity or successful tunnel crypto.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reset<'a> {
    /// No recognized native presence flag requested a signed reset.
    Absent,
    /// Actual verified signature and strictly newer origin observation.
    Fresh(ResetProof<'a>),
    /// Verified but old/equal monotime cannot trigger another reset.
    Replayed,
}
/// Native C integer representation used for the two opaque CREATE fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeOrder {
    /// Pinned current native little-endian C representation.
    Little,
    /// Big-endian C representation, without inventing a new wire field.
    Big,
}
impl NativeOrder {
    fn number(self, number: u32) -> [u8; 4] {
        match self {
            Self::Little => number.to_le_bytes(),
            Self::Big => number.to_be_bytes(),
        }
    }
}
/// Explicit local routing limits and monotonic timer policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum encoded outer message, at most 65535 bytes.
    pub frame_bytes: usize,
    /// Initial CREATE retry in canonical microseconds.
    pub retry_micros: u64,
    /// Maximum capped retry interval.
    pub maximum_retry_micros: u64,
    /// Endpoint keepalive-request interval; relays expire after three periods.
    pub keepalive_micros: u64,
    /// Native fields for locally generated CREATE messages.
    pub native_order: NativeOrder,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: 65535,
            retry_micros: 250_000,
            maximum_retry_micros: 900_000_000,
            keepalive_micros: 30_000_000,
            native_order: NativeOrder::Little,
        }
    }
}
#[derive(Clone, Copy)]
struct NeighborRecord {
    serial: u64,
    peer: [u8; 32],
    live: bool,
    ready: bool,
}
/// Fixed caller slot for one actual CORE neighbor generation.
#[derive(Clone, Copy, Default)]
pub struct NeighborSlot {
    record: Option<NeighborRecord>,
}
impl NeighborSlot {
    /// Empty metadata without allocation.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
#[derive(Clone, Copy)]
struct Observation {
    origin: [u8; 32],
    monotime: u64,
}
/// Non-evicting bounded original-origin replay high-water observation.
#[derive(Clone, Copy, Default)]
pub struct OriginSlot {
    record: Option<Observation>,
}
impl OriginSlot {
    /// Empty replay observation; persistence is supplied explicitly.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
    /// Restore the actual persisted original origin's high-water value.
    #[must_use]
    pub const fn restored(origin: [u8; 32], monotime: u64) -> Self {
        Self {
            record: Some(Observation { origin, monotime }),
        }
    }
}
/// Local role in a validated complete origin-to-destination path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Path position0.
    Origin,
    /// Last path position, reached from the original preceding neighbor.
    Destination,
    /// Strict intermediate position with two original adjacent peers.
    Relay,
}
/// Actual route establishment/retirement phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Original async PILS request has not returned its signature.
    Signing,
    /// CREATE queued/emitted, waiting for actual reverse confirmation.
    Opening,
    /// Destination accepted CREATE; its original CREATE_ACK is pending.
    AckPending,
    /// Actual route ACK or authorized reverse payload established it.
    Ready,
    /// Original route retired; outcomes/notifications still drain.
    Retired,
}
#[derive(Clone, Copy)]
struct Material {
    options: [u8; 4],
    has_monotime: [u8; 4],
    monotime: u64,
    signature: [u8; 64],
}
#[derive(Clone, Copy)]
struct RouteRecord<const P: usize> {
    serial: u64,
    connection: [u8; 32],
    path: [[u8; 32]; P],
    length: usize,
    position: usize,
    role: Role,
    phase: Phase,
    prev: Option<NeighborRef>,
    next: Option<NeighborRef>,
    material: Material,
    last_use: MonoInstant,
    retry_at: MonoInstant,
    retry_delay: u64,
    create_exposed: bool,
    notify_prev: bool,
    notify_next: bool,
    notice_destroy: bool,
    edge: ([u8; 32], [u8; 32]),
    latency: Option<u64>,
    samples: u8,
}
/// Caller-owned route metadata and a fixed maximum whole-path capacity.
#[derive(Clone, Copy)]
pub struct RouteSlot<const P: usize = 16> {
    record: Option<RouteRecord<P>>,
}
impl<const P: usize> RouteSlot<P> {
    /// Empty bounded route metadata.
    #[must_use]
    pub const fn new() -> Self {
        Self { record: None }
    }
}
impl<const P: usize> Default for RouteSlot<P> {
    fn default() -> Self {
        Self::new()
    }
}
/// Priority class for the enclosing real CORE port, not an added wire field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Actual connection control, including CREATE and failure notices.
    Control,
    /// Actual KX/KX_AUTH, requiring control-priority CORE handling.
    KeyExchange,
    /// Original encrypted tunnel packet.
    Encrypted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FrameType {
    Create,
    Ack,
    Notice,
    Payload(Kind),
}
/// Terminal original-frame physical outcome, without remote delivery assertions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// Whole original frame actually written by its actual CORE owner.
    Written,
    /// Original frame physically retired before any exposure.
    Unsent,
    /// Original frame retired after exposure without a full-write fact.
    Unknown,
}
#[derive(Clone, Copy)]
enum FrameState {
    Queued,
    Active {
        serial: u64,
        exposed: bool,
    },
    Complete {
        attempt: Option<u64>,
        exposed: bool,
        outcome: Outcome,
    },
}
#[derive(Clone, Copy)]
struct FrameRecord {
    serial: u64,
    target: NeighborRef,
    route: Option<RouteRef>,
    length: usize,
    kind: FrameType,
    state: FrameState,
}
/// Exact encoded frames retained in fixed caller buffers through original outcomes.
pub struct FrameSlot<'bytes> {
    bytes: &'bytes mut [u8],
    record: Option<FrameRecord>,
}
impl<'bytes> FrameSlot<'bytes> {
    /// Wrap empty fixed original-frame storage.
    #[must_use]
    pub fn new(bytes: &'bytes mut [u8]) -> Self {
        Self {
            bytes,
            record: None,
        }
    }
}
/// Borrowed actual eligible frame, before final native copy/queue allocation.
pub struct Queued<'id, 'bytes> {
    /// Original immutable retained frame.
    pub frame: Frame<'id>,
    /// Original route epoch, if known.
    pub route: Option<Route<'id>>,
    /// Exact current CORE neighbor generation.
    pub neighbor: Neighbor<'id>,
    /// Actual outer frame, with unchanged relay bytes.
    pub bytes: &'bytes [u8],
    /// Correct CORE scheduling class.
    pub kind: Kind,
}
/// One original frame's retained terminal facts. release_frame explicitly frees it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Completion<'id> {
    /// Original retained frame.
    pub frame: Frame<'id>,
    /// Original target, even after that neighbor was retired.
    pub neighbor: Neighbor<'id>,
    /// Original route epoch, even if retired.
    pub route: Option<Route<'id>>,
    /// Original physical attempt, absent if never started.
    pub attempt: Option<Attempt<'id>>,
    /// Actual physical outcome, never a peer receipt.
    pub outcome: Outcome,
    /// Whether actual original output was ever exposed.
    pub exposed: bool,
}
/// Actual local route observations. expected_peer remains unverified by tunnel crypto.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteInfo {
    /// Actual local role.
    pub role: Role,
    /// Actual establishment/retirement phase.
    pub phase: Phase,
    /// Expected opposite endpoint from the validated whole path.
    pub expected_peer: Option<[u8; 32]>,
    /// Number of identities including both endpoints.
    pub path_length: usize,
    /// Actual local path position.
    pub position: usize,
    /// Actual most recent authorized route activity.
    pub last_use: MonoInstant,
}
/// Receipt minted only after the actual original CORE Neighbor and route
/// direction passed Book::receive checks. It does not authenticate the far
/// endpoint; the original tunnel context must still verify KX/AEAD.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint<'id, 'message> {
    authority: ResetAuthority<'id>,
    route: Route<'id>,
    source: Neighbor<'id>,
    expected_peer: [u8; 32],
    message: PeerMessage<'message>,
    implicit_ready: bool,
}
impl<'id, 'message> Endpoint<'id, 'message> {
    /// Original exact connection-book source domain.
    #[must_use]
    pub const fn authority(self) -> ResetAuthority<'id> {
        self.authority
    }
    /// Original route generation which authorized the actual incoming direction.
    #[must_use]
    pub const fn route(self) -> Route<'id> {
        self.route
    }
    /// Original actual adjacent CORE peer generation, never a raw identity lookup.
    #[must_use]
    pub const fn source(self) -> Neighbor<'id> {
        self.source
    }
    /// Expected opposite identity from the validated path, not KX authentication.
    #[must_use]
    pub const fn expected_peer(self) -> [u8; 32] {
        self.expected_peer
    }
    /// Actual original structurally decoded packet; only tunnel crypto authenticates it.
    #[must_use]
    pub const fn message(self) -> PeerMessage<'message> {
        self.message
    }
    /// Whether this actual authorized reverse payload confirmed an opening route.
    #[must_use]
    pub const fn implicit_ready(self) -> bool {
        self.implicit_ready
    }
}
/// Actual incoming route disposition. Endpoint packets remain unauthenticated
/// until their separate original tunnel session verifies KX/AEAD.
#[expect(
    clippy::large_enum_variant,
    reason = "Return the bounded original endpoint receipt and borrowed peer message without heap allocation after accepting original authorized neighbor input"
)]
pub enum Event<'id, 'message> {
    /// New endpoint or relay state; actual forward/ACK is retained.
    Created {
        /// Original route allocation.
        route: Route<'id>,
        /// Verified origin reset observation, not automatic key replacement.
        reset: Reset<'id>,
    },
    /// Duplicate CREATE on the same exact original path/source.
    Duplicate {
        /// Original route allocation.
        route: Route<'id>,
        /// Verified fresh/replayed reset observation.
        reset: Reset<'id>,
    },
    /// Original complete raw frame retained for the opposite adjacent peer.
    Forwarded {
        /// Original route allocation.
        route: Route<'id>,
        /// Actual queued immutable frame.
        frame: Frame<'id>,
    },
    /// Actual endpoint reverse ACK established this original route.
    Ready(Route<'id>),
    /// Actual endpoint packet with an unforgeable original source/direction receipt.
    Endpoint(Endpoint<'id, 'message>),
    /// Actual authorized remote teardown/failure.
    Retired(Route<'id>),
    /// Real BROKEN reply is retained for the original sender.
    Rejected {
        /// Actual queued control frame.
        reply: Frame<'id>,
    },
    /// Unknown late DESTROY/BROKEN or terminal route input.
    Ignored,
}
/// One local origin request and any original async signing work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Opened<'id> {
    /// Original new route.
    pub route: Route<'id>,
    /// Exact original monotime-purpose request, if requested.
    pub sign: Option<SignRequest<'id>>,
}
/// Native CORE boundary. Implementations retain original external peer/send IDs,
/// final immutable frames and partial cursors; no default success is supplied.
pub trait CorePort<'id> {
    /// Actual original native/resource refusal.
    type Error;
    /// Preflight original current peer permission and immutable frame capacity.
    fn reserve(&mut self, neighbor: Neighbor<'id>, bytes: usize) -> Result<(), Self::Error>;
    /// Queue the exact original retained bytes after Book::start. Only later
    /// positive/full original CORE output may call exposed/settle on this attempt.
    fn submit(
        &mut self,
        attempt: Attempt<'id>,
        bytes: &[u8],
        kind: Kind,
    ) -> Result<(), Self::Error>;
}
/// Explicit fresh discovery/DHT boundary; this book starts no lookup itself.
/// Results must retain this original operation token in the containing owner,
/// then supply a bounded whole PathPeers candidate to open. Discovery evidence
/// never manufactures a current CORE Neighbor or authenticated tunnel identity.
pub trait DiscoveryPort {
    /// Opaque original lookup generation, not just its requested peer bytes.
    type Query: Copy + Eq;
    /// Actual original lookup/resource refusal.
    type Error;
    /// Start one real caller-budgeted query with its original canonical deadline.
    fn start(&mut self, peer: [u8; 32], deadline: MonoInstant) -> Result<Self::Query, Self::Error>;
    /// Cancel only this original query's callbacks; copied/native IO remains with
    /// the actual underlying owner until its own completion or retirement.
    fn cancel(&mut self, query: Self::Query) -> Result<(), Self::Error>;
}
/// Obtain a fresh real 256-bit CID from the caller's explicit entropy port.
pub fn fresh_connection(entropy: &mut impl Entropy) -> Result<[u8; 32], Error> {
    let mut connection = [0; 32];
    entropy.fill(&mut connection)?;
    Ok(connection)
}

/// One bounded routing/path book, borrowing all metadata and immutable-frame buffers.
/// No allocator, resolver, DHT client, native CORE connection or hidden task is used.
pub struct Book<'id, 'slots, 'bytes, const P: usize = 16> {
    brand: Brand<'id>,
    local: [u8; 32],
    neighbors: &'slots mut [NeighborSlot],
    routes: &'slots mut [RouteSlot<P>],
    origins: &'slots mut [OriginSlot],
    frames: &'slots mut [FrameSlot<'bytes>],
    limits: Limits,
    next_neighbor: u64,
    next_route: u64,
    next_frame: u64,
    next_attempt: u64,
    last_now: MonoInstant,
    statistics: crate::statistics::OwnedStore,
    // Diagnostic causality only: a native consumed input may settle this once.
    frame_capacity_refused: bool,
    refused_input: Option<(NeighborRef, [u8; 32], FrameType)>,
}
impl<'id, 'slots, 'bytes, const P: usize> Book<'id, 'slots, 'bytes, P> {
    /// Bind an actual local identity and empty caller metadata. Persisted OriginSlot
    /// observations may be preloaded; a local identity alone grants no CORE peer.
    #[expect(
        clippy::too_many_arguments,
        reason = "All actual identity, bounded storage and time resources are supplied explicitly"
    )]
    pub fn new(
        instance: &'id mut Instance,
        local: [u8; 32],
        neighbors: &'slots mut [NeighborSlot],
        routes: &'slots mut [RouteSlot<P>],
        origins: &'slots mut [OriginSlot],
        frames: &'slots mut [FrameSlot<'bytes>],
        now: MonoInstant,
        limits: Limits,
    ) -> Result<Self, Error> {
        if P < 2
            || neighbors.is_empty()
            || routes.is_empty()
            || frames.is_empty()
            || frames
                .iter()
                .all(|slot| slot.bytes.len() < CONNECTION_CREATE_PREFIX + 64)
            || !((CONNECTION_CREATE_PREFIX + 64)..=65535).contains(&limits.frame_bytes)
            || limits.retry_micros == 0
            || limits.maximum_retry_micros < limits.retry_micros
            || limits.keepalive_micros == 0
        {
            return Err(Error::InvalidInput);
        }
        if neighbors.iter().any(|slot| slot.record.is_some())
            || routes.iter().any(|slot| slot.record.is_some())
            || frames.iter().any(|slot| slot.record.is_some())
        {
            return Err(Error::Conflict);
        }
        for (index, slot) in origins.iter().enumerate() {
            if let Some(record) = slot.record
                && origins[..index]
                    .iter()
                    .any(|slot| slot.record.is_some_and(|old| old.origin == record.origin))
            {
                return Err(Error::Conflict);
            }
        }
        Ok(Self {
            brand: Brand(instance),
            local,
            neighbors,
            routes,
            origins,
            frames,
            limits,
            next_neighbor: 0,
            next_route: 0,
            next_frame: 0,
            next_attempt: 0,
            last_now: now,
            statistics: crate::statistics::OwnedStore::new(),
            frame_capacity_refused: false,
            refused_input: None,
        })
    }
    fn time(&mut self, now: MonoInstant) -> Result<(), Error> {
        if now < self.last_now {
            return Err(Error::TimeUncertain);
        }
        self.last_now = now;
        Ok(())
    }
    fn neighbor(&self, reference: NeighborRef) -> Neighbor<'id> {
        Neighbor {
            brand: self.brand,
            reference,
        }
    }
    fn route(&self, reference: RouteRef) -> Route<'id> {
        Route {
            brand: self.brand,
            reference,
        }
    }
    fn route_ref(slot: usize, record: RouteRecord<P>) -> RouteRef {
        RouteRef {
            slot,
            serial: record.serial,
            connection: record.connection,
        }
    }
    fn neighbor_record(&self, neighbor: Neighbor<'id>) -> Result<&NeighborRecord, Error> {
        if neighbor.brand != self.brand {
            return Err(Error::StaleGeneration);
        }
        self.neighbor_ref(neighbor.reference)
    }
    fn neighbor_ref(&self, reference: NeighborRef) -> Result<&NeighborRecord, Error> {
        self.neighbors
            .get(reference.slot)
            .and_then(|slot| slot.record.as_ref())
            .filter(|record| {
                record.live && record.serial == reference.serial && record.peer == reference.peer
            })
            .ok_or(Error::StaleGeneration)
    }
    fn route_record(&self, route: Route<'id>) -> Result<&RouteRecord<P>, Error> {
        if route.brand != self.brand {
            return Err(Error::StaleGeneration);
        }
        self.routes
            .get(route.reference.slot)
            .and_then(|slot| slot.record.as_ref())
            .filter(|record| {
                record.serial == route.reference.serial
                    && record.connection == route.reference.connection
            })
            .ok_or(Error::StaleGeneration)
    }
    fn frame_record(&self, frame: Frame<'id>) -> Result<&FrameRecord, Error> {
        if frame.brand != self.brand {
            return Err(Error::StaleGeneration);
        }
        self.frames
            .get(frame.slot)
            .and_then(|slot| slot.record.as_ref())
            .filter(|record| record.serial == frame.serial)
            .ok_or(Error::StaleGeneration)
    }
    fn find_neighbor(&self, peer: [u8; 32]) -> Option<NeighborRef> {
        self.neighbors
            .iter()
            .enumerate()
            .find_map(|(slot, neighbor)| {
                neighbor
                    .record
                    .filter(|record| record.live && record.peer == peer)
                    .map(|record| NeighborRef {
                        slot,
                        serial: record.serial,
                        peer,
                    })
            })
    }
    fn find_route(&self, connection: [u8; 32]) -> Option<Route<'id>> {
        self.routes.iter().enumerate().find_map(|(slot, route)| {
            route
                .record
                .filter(|record| record.connection == connection)
                .map(|record| self.route(Self::route_ref(slot, record)))
        })
    }
    /// Commit only an actual CORE peer-connected announcement. It starts busy;
    /// neighbor_ready is separately fed by actual current CORE send availability.
    pub fn neighbor_up(&mut self, peer: [u8; 32]) -> Result<Neighbor<'id>, Error> {
        if peer == self.local || self.find_neighbor(peer).is_some() {
            return Err(Error::Conflict);
        }
        let slot = self
            .neighbors
            .iter()
            .position(|slot| slot.record.is_none_or(|record| !record.live))
            .ok_or(Error::Capacity)?;
        let serial = self.next_neighbor.checked_add(1).ok_or(Error::Overflow)?;
        let reference = NeighborRef { slot, serial, peer };
        self.neighbors[slot].record = Some(NeighborRecord {
            serial,
            peer,
            live: true,
            ready: false,
        });
        self.next_neighbor = serial;
        Ok(self.neighbor(reference))
    }
    /// Current local request-admission observation for this exact live neighbor.
    /// This validates the original Book brand and neighbor generation; it grants
    /// neither a wire send permit nor peer acknowledgement.
    pub fn neighbor_is_ready(&self, neighbor: Neighbor<'id>) -> Result<bool, Error> {
        Ok(self.neighbor_record(neighbor)?.ready)
    }
    /// Actual original local CORE request-admission availability. The native
    /// owner observes its exact current Peer generation and bounded capacity;
    /// this is neither per-operation wire SendReady nor remote acknowledgement.
    /// start() consumes the observation; actual admission can still refuse.
    pub fn neighbor_ready(&mut self, neighbor: Neighbor<'id>, ready: bool) -> Result<(), Error> {
        self.neighbor_record(neighbor)?;
        self.neighbors[neighbor.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .ready = ready;
        Ok(())
    }
    /// Original local authority to which a tunnel controller binds reset proofs.
    #[must_use]
    pub const fn reset_authority(&self) -> ResetAuthority<'id> {
        ResetAuthority {
            brand: self.brand,
            local: self.local,
        }
    }
    /// Current original CORE token for an actually live announced peer.
    /// Use this for outgoing lookup. Incoming frames must carry the original
    /// token retained with their actual CORE peer/epoch, never be relabeled by
    /// looking up a raw peer identity after a disconnect/reconnect.
    #[must_use]
    pub fn current_neighbor(&self, peer: [u8; 32]) -> Option<Neighbor<'id>> {
        self.find_neighbor(peer)
            .map(|reference| self.neighbor(reference))
    }
    /// Original currently retained live neighbor identities for a synchronous
    /// management capture. No lookup, new permission or physical fact is minted.
    pub fn known_neighbors(&self) -> impl Iterator<Item = [u8; 32]> + '_ {
        self.neighbors
            .iter()
            .filter_map(|s| s.record)
            .filter(|r| r.live)
            .map(|r| r.peer)
    }
    /// Actual retained route allocations for a synchronous read-only capture.
    /// Inspect phase separately; retired routes still own their original drain.
    pub fn retained_routes(&self) -> impl Iterator<Item = Route<'id>> + '_ {
        self.routes
            .iter()
            .enumerate()
            .filter_map(|(slot, s)| s.record.map(|r| self.route(Self::route_ref(slot, r))))
    }
    /// Exact original whole path backing a retained route. Snapshot code may
    /// copy it before this immutable borrow ends; it cannot mutate route state.
    pub fn route_peers(&self, route: Route<'id>) -> Result<&[[u8; 32]], Error> {
        let record = self.route_record(route)?;
        Ok(&record.path[..record.length])
    }
    /// Actual route metadata; this never treats its expected peer as authenticated.
    pub fn route_info(&self, route: Route<'id>) -> Result<RouteInfo, Error> {
        let record = self.route_record(route)?;
        Ok(RouteInfo {
            role: record.role,
            phase: record.phase,
            expected_peer: match record.role {
                Role::Origin => Some(record.path[record.length - 1]),
                Role::Destination => Some(record.path[0]),
                Role::Relay => None,
            },
            path_length: record.length,
            position: record.position,
            last_use: record.last_use,
        })
    }
    /// Actual persisted/recent high-water value for one original origin.
    #[must_use]
    pub fn observed_monotime(&self, origin: [u8; 32]) -> Option<u64> {
        self.origins.iter().find_map(|slot| {
            slot.record
                .filter(|record| record.origin == origin)
                .map(|record| record.monotime)
        })
    }
    fn path(&self, path: PathPeers<'_>) -> Result<([[u8; 32]; P], usize, usize), Error> {
        let length = path.len();
        if length < 2 {
            return Err(Error::Malformed);
        }
        if length > P {
            return Err(Error::TooLarge);
        }
        let mut peers = [[0; 32]; P];
        let mut position = None;
        for (index, peer) in path.iter().enumerate() {
            if peers[..index].contains(&peer) {
                return Err(Error::Malformed);
            }
            peers[index] = peer;
            if peer == self.local {
                position = Some(index);
            }
        }
        Ok((peers, length, position.ok_or(Error::Authentication)?))
    }
    fn enqueue(
        &mut self,
        target: NeighborRef,
        route: Option<RouteRef>,
        kind: FrameType,
        message: PeerMessage<'_>,
    ) -> Result<Frame<'id>, Error> {
        self.neighbor_ref(target)?;
        let length = message.encoded_len()?;
        if length > self.frame_capacity() {
            return Err(Error::TooLarge);
        }
        let Some(slot) = self
            .frames
            .iter()
            .position(|slot| slot.record.is_none() && slot.bytes.len() >= length)
        else {
            self.frame_capacity_refused = true;
            return Err(Error::Capacity);
        };
        let serial = self.next_frame.checked_add(1).ok_or(Error::Overflow)?;
        message.encode(self.frames[slot].bytes)?;
        self.frames[slot].record = Some(FrameRecord {
            serial,
            target,
            route,
            length,
            kind,
            state: FrameState::Queued,
        });
        self.next_frame = serial;
        Ok(Frame {
            brand: self.brand,
            slot,
            serial,
        })
    }
    /// Borrow the exact original retained wire frame in Queued, Active or
    /// Complete state. Released/stale generations refuse; no mutable view exists.
    pub fn frame_bytes(&self, frame: Frame<'id>) -> Result<&[u8], Error> {
        let record = self.frame_record(frame)?;
        Ok(&self.frames[frame.slot].bytes[..record.length])
    }
    /// Actual endpoint routes for this peer still own retained control/frame
    /// state. Includes retired routes until explicit original release.
    #[must_use]
    pub fn peer_has_work(&self, peer: [u8; 32]) -> bool {
        self.routes.iter().filter_map(|s| s.record).any(|r| {
            (r.role == Role::Origin && r.path[r.length - 1] == peer)
                || (r.role == Role::Destination && r.path[0] == peer)
        })
    }
    /// Retire every actual endpoint route for this peer, preserving active
    /// original frames and genuine bounded teardown notifications.
    pub fn close_peer(&mut self, peer: [u8; 32]) -> Result<usize, Error> {
        let mut closed = 0;
        for slot in 0..self.routes.len() {
            if let Some(r) = self.routes[slot].record
                && r.phase != Phase::Retired
                && ((r.role == Role::Origin && r.path[r.length - 1] == peer)
                    || (r.role == Role::Destination && r.path[0] == peer))
            {
                self.close_route(self.route(Self::route_ref(slot, r)))?;
                closed += 1;
            }
        }
        Ok(closed)
    }
    /// Actual original route allocation for this retained frame.
    pub fn frame_route(&self, frame: Frame<'id>) -> Result<Option<Route<'id>>, Error> {
        Ok(self
            .frame_record(frame)?
            .route
            .map(|route| self.route(route)))
    }
    /// Original terminal fact read from this actual Book, not caller labels.
    pub fn frame_completion(&self, frame: Frame<'id>) -> Result<Completion<'id>, Error> {
        self.completion_for(frame)
    }
    /// Preflight one local encrypted/control frame before irreversible sealing.
    /// The caller must queue synchronously before mutating any other Book state.
    pub fn payload_capacity(&self, route: Route<'id>, bytes: usize) -> Result<bool, Error> {
        let record = self.route_record(route)?;
        if record.phase != Phase::Ready || record.role == Role::Relay {
            return Err(Error::NotReady);
        }
        if bytes > self.limits.frame_bytes {
            return Err(Error::TooLarge);
        }
        if self.frames.iter().any(|s| {
            s.record.is_some_and(|f| {
                f.route == Some(route.reference)
                    && matches!(f.state, FrameState::Queued | FrameState::Active { .. })
            })
        }) {
            return Ok(false);
        }
        Ok(self
            .frames
            .iter()
            .any(|s| s.record.is_none() && s.bytes.len() >= bytes))
    }
    /// Whether original retained route/frame work still needs explicit drain.
    #[must_use]
    pub fn has_work(&self) -> bool {
        self.frames.iter().any(|s| s.record.is_some())
            || self.routes.iter().any(|s| s.record.is_some())
    }
    /// Effective largest original output frame supported by fixed caller storage.
    #[must_use]
    pub fn frame_capacity(&self) -> usize {
        self.frames
            .iter()
            .map(|slot| slot.bytes.len())
            .max()
            .unwrap_or(0)
            .min(self.limits.frame_bytes)
    }
    fn create_message<'path>(record: &'path RouteRecord<P>) -> PeerMessage<'path> {
        PeerMessage::ConnectionCreate {
            options_bytes: record.material.options,
            has_monotime_bytes: record.material.has_monotime,
            monotime: record.material.monotime,
            monotime_signature: record.material.signature,
            connection: record.connection,
            path: PathPeers::new(&record.path[..record.length]),
        }
    }
    /// Begin a real whole-path request from the actual local origin. CID must be
    /// fresh caller entropy; no discovered path alone creates a CORE neighbor.
    pub fn open(
        &mut self,
        path: PathPeers<'_>,
        connection: [u8; 32],
        authentication: Authentication,
        now: MonoInstant,
    ) -> Result<Opened<'id>, Error> {
        self.time(now)?;
        if self.find_route(connection).is_some() {
            return Err(Error::Conflict);
        }
        let (peers, length, position) = self.path(path)?;
        if position != 0 {
            return Err(Error::Authentication);
        }
        let next = self.find_neighbor(peers[1]).ok_or(Error::NotReady)?;
        let slot = self
            .routes
            .iter()
            .position(|slot| slot.record.is_none())
            .ok_or(Error::Capacity)?;
        let serial = self.next_route.checked_add(1).ok_or(Error::Overflow)?;
        let reference = RouteRef {
            slot,
            serial,
            connection,
        };
        let material = Material {
            options: self.limits.native_order.number(2),
            has_monotime: [0; 4],
            monotime: match authentication {
                Authentication::Unsigned => 0,
                Authentication::Monotime(monotime) => monotime,
            },
            signature: [0; 64],
        };
        let record = RouteRecord {
            serial,
            connection,
            path: peers,
            length,
            position,
            role: Role::Origin,
            phase: if matches!(authentication, Authentication::Unsigned) {
                Phase::Opening
            } else {
                Phase::Signing
            },
            prev: None,
            next: Some(next),
            material,
            last_use: now,
            retry_at: now,
            retry_delay: self.limits.retry_micros,
            create_exposed: false,
            notify_prev: false,
            notify_next: false,
            notice_destroy: false,
            edge: ([0; 32], [0; 32]),
            latency: None,
            samples: 0,
        };
        if matches!(authentication, Authentication::Unsigned) {
            self.enqueue(
                next,
                Some(reference),
                FrameType::Create,
                Self::create_message(&record),
            )?;
        }
        self.routes[slot].record = Some(record);
        self.next_route = serial;
        let route = self.route(reference);
        Ok(Opened {
            route,
            sign: match authentication {
                Authentication::Unsigned => None,
                Authentication::Monotime(monotime) => Some(SignRequest { route, monotime }),
            },
        })
    }
    /// Check a live original asynchronous signing request without mutating it.
    /// A native signer uses this plus its original book domain before admission;
    /// old/closed/reused routes cannot authorize another backend operation.
    pub fn signing_local(&self, request: SignRequest<'id>) -> Result<[u8; 32], Error> {
        let record = self.route_record(request.route)?;
        if record.phase != Phase::Signing || record.material.monotime != request.monotime {
            return Err(Error::StaleGeneration);
        }
        Ok(self.local)
    }
    /// Accept only the original async PILS completion, actual local identity and
    /// exact purpose38 signature. Capacity refusal retains the original request.
    pub fn signed(
        &mut self,
        request: SignRequest<'id>,
        identity: [u8; 32],
        signature: [u8; 64],
        now: MonoInstant,
    ) -> Result<Frame<'id>, Error> {
        self.time(now)?;
        let mut record = *self.route_record(request.route)?;
        if record.phase != Phase::Signing || record.material.monotime != request.monotime {
            return Err(Error::StaleGeneration);
        }
        if identity != self.local {
            return Err(Error::Authentication);
        }
        let mut purpose = [0; 16];
        request.purpose(&mut purpose)?;
        EddsaPublicKey::from_bytes(identity).verify(
            CONNECTION_INITIATOR_PURPOSE,
            &purpose,
            &EddsaSignature::from_bytes(signature),
        )?;
        record.material.signature = signature;
        record.material.has_monotime = self.limits.native_order.number(1);
        record.phase = Phase::Opening;
        let next = record.next.ok_or(Error::NotReady)?;
        let frame = self.enqueue(
            next,
            Some(request.route.reference),
            FrameType::Create,
            Self::create_message(&record),
        )?;
        self.routes[request.route.reference.slot].record = Some(record);
        Ok(frame)
    }
    fn reset(
        &self,
        origin: [u8; 32],
        material: Material,
    ) -> Result<(Reset<'id>, Option<usize>), Error> {
        if !matches!(material.has_monotime, [1, 0, 0, 0] | [0, 0, 0, 1]) {
            return Ok((Reset::Absent, None));
        }
        let mut purpose = [0; 16];
        ConnectionInitiatorPurpose {
            monotime: material.monotime,
        }
        .encode(&mut purpose)?;
        EddsaPublicKey::from_bytes(origin).verify(
            CONNECTION_INITIATOR_PURPOSE,
            &purpose,
            &EddsaSignature::from_bytes(material.signature),
        )?;
        if material.monotime == 0 {
            return Ok((Reset::Replayed, None));
        }
        let existing = self
            .origins
            .iter()
            .position(|slot| slot.record.is_some_and(|record| record.origin == origin));
        if existing.is_some_and(|slot| {
            self.origins[slot]
                .record
                .is_some_and(|record| record.monotime >= material.monotime)
        }) {
            return Ok((Reset::Replayed, None));
        }
        let slot = existing
            .or_else(|| self.origins.iter().position(|slot| slot.record.is_none()))
            .ok_or(Error::Capacity)?;
        Ok((
            Reset::Fresh(ResetProof {
                authority: self.reset_authority(),
                origin,
                monotime: material.monotime,
            }),
            Some(slot),
        ))
    }
    fn observe_reset(&mut self, reset: Reset<'id>, slot: Option<usize>) {
        if let (Reset::Fresh(proof), Some(slot)) = (reset, slot) {
            self.origins[slot].record = Some(Observation {
                origin: proof.origin,
                monotime: proof.monotime,
            });
        }
    }
    fn broken(
        &mut self,
        target: NeighborRef,
        connection: [u8; 32],
        failure: [u8; 32],
    ) -> Result<Frame<'id>, Error> {
        self.enqueue(
            target,
            None,
            FrameType::Notice,
            PeerMessage::ConnectionBroken {
                reserved: 0,
                connection,
                peer1: self.local,
                peer2: failure,
            },
        )
    }
    /// Feed an actual structurally decoded outer frame from exactly this current
    /// CORE neighbor. Endpoint events still need their original tunnel crypto.
    pub fn receive<'message>(
        &mut self,
        source: Neighbor<'id>,
        message: PeerMessage<'message>,
        now: MonoInstant,
    ) -> Result<Event<'id, 'message>, Error> {
        self.frame_capacity_refused = false;
        self.refused_input = None;
        let result = self.receive_inner(source, message, now);
        if self.frame_capacity_refused && matches!(&result, Err(Error::Capacity)) {
            self.refused_input = Some((
                source.reference,
                connection_id(message),
                frame_type(message),
            ));
        }
        self.frame_capacity_refused = false;
        result
    }
    fn receive_inner<'message>(
        &mut self,
        source: Neighbor<'id>,
        message: PeerMessage<'message>,
        now: MonoInstant,
    ) -> Result<Event<'id, 'message>, Error> {
        self.neighbor_record(source)?;
        self.time(now)?;
        if let PeerMessage::ConnectionCreate {
            options_bytes,
            has_monotime_bytes,
            monotime,
            monotime_signature,
            connection,
            path,
        } = message
        {
            return self.create(
                source,
                message,
                path,
                connection,
                Material {
                    options: options_bytes,
                    has_monotime: has_monotime_bytes,
                    monotime,
                    signature: monotime_signature,
                },
                now,
            );
        }
        let connection = connection_id(message);
        let Some(route) = self.find_route(connection) else {
            return match message {
                PeerMessage::ConnectionDestroy { .. } | PeerMessage::ConnectionBroken { .. } => {
                    Ok(Event::Ignored)
                }
                _ => Ok(Event::Rejected {
                    reply: self.broken(source.reference, connection, [0; 32])?,
                }),
            };
        };
        let record = *self.route_record(route)?;
        let from_prev = record.prev == Some(source.reference);
        let from_next = record.next == Some(source.reference);
        if !from_prev && !from_next {
            return Err(Error::Authentication);
        }
        if record.phase == Phase::Retired {
            return Ok(Event::Ignored);
        }
        if matches!(message, PeerMessage::ConnectionCreateAck { .. })
            && ((record.role == Role::Relay && !from_next) || record.role == Role::Destination)
        {
            return Err(Error::Authentication);
        }
        if record.role == Role::Origin
            && (!record.create_exposed || record.phase == Phase::Signing)
            && matches!(
                message,
                PeerMessage::ConnectionCreateAck { .. }
                    | PeerMessage::KeyExchange { .. }
                    | PeerMessage::KeyExchangeAuth { .. }
                    | PeerMessage::Encrypted { .. }
            )
        {
            return Ok(Event::Ignored);
        }
        if let PeerMessage::ConnectionBroken { peer1, peer2, .. } = message
            && !valid_broken(
                &record.path[..record.length],
                record.position,
                from_prev,
                peer1,
                peer2,
            )
        {
            return Err(Error::Authentication);
        }
        if record.role == Role::Relay {
            let target =
                if from_prev { record.next } else { record.prev }.ok_or(Error::NotReady)?;
            let kind = frame_type(message);
            let frame = self.enqueue(target, Some(route.reference), kind, message)?;
            self.routes[route.reference.slot]
                .record
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .last_use = now;
            if matches!(
                message,
                PeerMessage::ConnectionBroken { .. } | PeerMessage::ConnectionDestroy { .. }
            ) {
                self.retire_route(route.reference, false, false, false, ([0; 32], [0; 32]));
            } else if matches!(
                message,
                PeerMessage::ConnectionCreateAck { .. }
                    | PeerMessage::KeyExchange { .. }
                    | PeerMessage::KeyExchangeAuth { .. }
                    | PeerMessage::Encrypted { .. }
            ) {
                self.confirm_route(route.reference, now);
            }
            return Ok(Event::Forwarded { route, frame });
        }
        match message {
            PeerMessage::ConnectionCreateAck { .. } => {
                if record.phase == Phase::Ready {
                    return Ok(Event::Ignored);
                }
                self.confirm_route(route.reference, now);
                Ok(Event::Ready(route))
            }
            PeerMessage::ConnectionBroken { .. } | PeerMessage::ConnectionDestroy { .. } => {
                self.retire_route(route.reference, false, false, false, ([0; 32], [0; 32]));
                Ok(Event::Retired(route))
            }
            PeerMessage::KeyExchange { .. }
            | PeerMessage::KeyExchangeAuth { .. }
            | PeerMessage::Encrypted { .. } => {
                let implicit_ready = record.phase != Phase::Ready;
                self.confirm_route(route.reference, now);
                let expected_peer = if record.role == Role::Origin {
                    record.path[record.length - 1]
                } else {
                    record.path[0]
                };
                Ok(Event::Endpoint(Endpoint {
                    authority: self.reset_authority(),
                    route,
                    source,
                    expected_peer,
                    message,
                    implicit_ready,
                }))
            }
            PeerMessage::ConnectionCreate { .. } => Err(Error::Malformed),
        }
    }
    fn create<'message>(
        &mut self,
        source: Neighbor<'id>,
        message: PeerMessage<'message>,
        path: PathPeers<'message>,
        connection: [u8; 32],
        material: Material,
        now: MonoInstant,
    ) -> Result<Event<'id, 'message>, Error> {
        let (peers, length, position) = self.path(path)?;
        if position == 0 || peers[position - 1] != source.reference.peer {
            return Err(Error::Authentication);
        }
        let destination = position == length - 1;
        let (reset, observation) = if destination {
            match self.reset(peers[0], material) {
                Ok(observation) => observation,
                Err(Error::Capacity) => {
                    return Ok(Event::Rejected {
                        reply: self.broken(source.reference, connection, [0; 32])?,
                    });
                }
                Err(error) => return Err(error),
            }
        } else {
            (Reset::Absent, None)
        };
        if let Some(route) = self.find_route(connection) {
            let record = *self.route_record(route)?;
            if record.phase == Phase::Retired {
                return Ok(Event::Ignored);
            }
            if record.length != length
                || record.path[..length] != peers[..length]
                || record.prev != Some(source.reference)
            {
                return Err(Error::Conflict);
            }
            if destination {
                self.enqueue(
                    source.reference,
                    Some(route.reference),
                    FrameType::Ack,
                    PeerMessage::ConnectionCreateAck {
                        reserved: 0,
                        connection,
                    },
                )?;
            } else {
                self.enqueue(
                    record.next.ok_or(Error::NotReady)?,
                    Some(route.reference),
                    FrameType::Create,
                    message,
                )?;
            }
            self.observe_reset(reset, observation);
            self.routes[route.reference.slot]
                .record
                .as_mut()
                .ok_or(Error::StaleGeneration)?
                .last_use = now;
            return Ok(Event::Duplicate { route, reset });
        }
        let next = if destination {
            None
        } else {
            match self.find_neighbor(peers[position + 1]) {
                Some(next) => Some(next),
                None => {
                    return Ok(Event::Rejected {
                        reply: self.broken(source.reference, connection, peers[position + 1])?,
                    });
                }
            }
        };
        let Some(slot) = self.routes.iter().position(|slot| slot.record.is_none()) else {
            return Ok(Event::Rejected {
                reply: self.broken(source.reference, connection, source.reference.peer)?,
            });
        };
        let serial = self.next_route.checked_add(1).ok_or(Error::Overflow)?;
        let reference = RouteRef {
            slot,
            serial,
            connection,
        };
        let role = if destination {
            Role::Destination
        } else {
            Role::Relay
        };
        let record = RouteRecord {
            serial,
            connection,
            path: peers,
            length,
            position,
            role,
            phase: if destination {
                Phase::AckPending
            } else {
                Phase::Opening
            },
            prev: Some(source.reference),
            next,
            material,
            last_use: now,
            retry_at: now,
            retry_delay: self.limits.retry_micros,
            create_exposed: false,
            notify_prev: false,
            notify_next: false,
            notice_destroy: false,
            edge: ([0; 32], [0; 32]),
            latency: None,
            samples: 0,
        };
        if destination {
            self.enqueue(
                source.reference,
                Some(reference),
                FrameType::Ack,
                PeerMessage::ConnectionCreateAck {
                    reserved: 0,
                    connection,
                },
            )?;
        } else {
            self.enqueue(
                next.ok_or(Error::NotReady)?,
                Some(reference),
                FrameType::Create,
                message,
            )?;
        }
        self.routes[slot].record = Some(record);
        self.next_route = serial;
        self.observe_reset(reset, observation);
        Ok(Event::Created {
            route: self.route(reference),
            reset,
        })
    }
    /// Queue an actual locally generated KX/KX_AUTH/encrypted packet only on an
    /// established endpoint route and its real current adjacent CORE neighbor.
    pub fn queue_payload(
        &mut self,
        route: Route<'id>,
        message: PeerMessage<'_>,
        now: MonoInstant,
    ) -> Result<Frame<'id>, Error> {
        self.time(now)?;
        let record = *self.route_record(route)?;
        if record.phase != Phase::Ready || record.role == Role::Relay {
            return Err(Error::NotReady);
        }
        if connection_id(message) != record.connection {
            return Err(Error::Authentication);
        }
        let kind = match message {
            PeerMessage::KeyExchange { .. } | PeerMessage::KeyExchangeAuth { .. } => {
                Kind::KeyExchange
            }
            PeerMessage::Encrypted { .. } => Kind::Encrypted,
            _ => return Err(Error::InvalidInput),
        };
        if self.frames.iter().any(|slot| {
            slot.record.is_some_and(|frame| {
                frame.route == Some(route.reference)
                    && matches!(frame.state, FrameState::Queued | FrameState::Active { .. })
            })
        }) {
            return Err(Error::WouldBlock);
        }
        self.enqueue(
            record.next.or(record.prev).ok_or(Error::NotReady)?,
            Some(route.reference),
            FrameType::Payload(kind),
            message,
        )
    }
    fn active_neighbor(&self, target: NeighborRef) -> bool {
        self.frames.iter().any(|slot| {
            slot.record.is_some_and(|frame| {
                frame.target == target && matches!(frame.state, FrameState::Active { .. })
            })
        })
    }
    /// Preview one immutable eligible frame before fallible final native copying.
    /// Both actual neighbor generation and actual CORE availability are required.
    #[must_use]
    pub fn next_frame(&self) -> Option<Queued<'id, '_>> {
        self.frames
            .iter()
            .enumerate()
            .filter_map(|(slot, buffer)| {
                let frame = buffer.record?;
                if !matches!(frame.state, FrameState::Queued)
                    || !self
                        .neighbor_ref(frame.target)
                        .is_ok_and(|neighbor| neighbor.ready)
                    || self.active_neighbor(frame.target)
                {
                    return None;
                }
                Some((slot, frame))
            })
            .min_by_key(|(_, frame)| {
                (
                    matches!(frame.kind, FrameType::Payload(Kind::Encrypted)),
                    frame.serial,
                )
            })
            .map(|(slot, frame)| Queued {
                frame: Frame {
                    brand: self.brand,
                    slot,
                    serial: frame.serial,
                },
                route: frame.route.map(|route| self.route(route)),
                neighbor: self.neighbor(frame.target),
                bytes: &self.frames[slot].bytes[..frame.length],
                kind: match frame.kind {
                    FrameType::Payload(kind) => kind,
                    _ => Kind::Control,
                },
            })
    }
    /// Commit only after final immutable copy/reservation succeeded on the actual
    /// original CORE port. This consumes availability, not physical exposure.
    pub fn start(&mut self, frame: Frame<'id>) -> Result<Attempt<'id>, Error> {
        let record = *self.frame_record(frame)?;
        if !matches!(record.state, FrameState::Queued)
            || !self.neighbor_ref(record.target)?.ready
            || self.active_neighbor(record.target)
        {
            return Err(Error::WouldBlock);
        }
        let serial = self.next_attempt.checked_add(1).ok_or(Error::Overflow)?;
        self.frames[frame.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .state = FrameState::Active {
            serial,
            exposed: false,
        };
        self.neighbors[record.target.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .ready = false;
        self.next_attempt = serial;
        Ok(Attempt {
            frame,
            serial,
            neighbor: self.neighbor(record.target),
            route: record.route.map(|route| self.route(route)),
        })
    }
    fn attempt_record(&self, attempt: Attempt<'id>) -> Result<&FrameRecord, Error> {
        let record = self.frame_record(attempt.frame)?;
        if record.target != attempt.neighbor.reference
            || attempt.neighbor.brand != self.brand
            || record.route.map(|route| self.route(route)) != attempt.route
            || !matches!(record.state, FrameState::Active { serial, .. } if serial == attempt.serial)
        {
            return Err(Error::StaleGeneration);
        }
        Ok(record)
    }
    /// Record only an actual positive original CORE_SEND payload-frame write.
    /// INIT/CORE_SEND_REQUEST bytes, wire SendReady and queue admission do not
    /// establish this exposure; native per-send receipts retain the original ID.
    pub fn exposed(&mut self, attempt: Attempt<'id>) -> Result<(), Error> {
        let original = *self.attempt_record(attempt)?;
        if original.kind == FrameType::Create
            && let Some(route) = original.route
            && let Some(record) = self
                .routes
                .get_mut(route.slot)
                .and_then(|slot| slot.record.as_mut())
                .filter(|record| {
                    record.serial == route.serial && record.connection == route.connection
                })
        {
            record.create_exposed = true;
        }
        let record = self.frames[attempt.frame.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if let FrameState::Active { exposed, .. } = &mut record.state {
            *exposed = true;
        }
        Ok(())
    }
    /// Settle an original full-write or actual physically retired send failure.
    /// This grants no remote receipt and does not replenish CORE availability.
    pub fn settle(
        &mut self,
        attempt: Attempt<'id>,
        fully_written: bool,
        now: MonoInstant,
    ) -> Result<Completion<'id>, Error> {
        let frame = *self.attempt_record(attempt)?;
        let FrameState::Active { exposed, .. } = frame.state else {
            return Err(Error::StaleGeneration);
        };
        if fully_written && !exposed {
            return Err(Error::NotReady);
        }
        self.time(now)?;
        let outcome = if fully_written {
            Outcome::Written
        } else if exposed {
            Outcome::Unknown
        } else {
            Outcome::Unsent
        };
        self.frames[attempt.frame.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .state = FrameState::Complete {
            attempt: Some(attempt.serial),
            exposed,
            outcome,
        };
        if let Some(route) = frame.route
            && let Some(record) = self
                .routes
                .get_mut(route.slot)
                .and_then(|slot| slot.record.as_mut())
                .filter(|record| {
                    record.serial == route.serial
                        && record.connection == route.connection
                        && record.phase != Phase::Retired
                })
        {
            if fully_written {
                record.last_use = now;
                if frame.kind == FrameType::Ack && record.role == Role::Destination {
                    record.phase = Phase::Ready;
                }
            }
            if frame.kind == FrameType::Create {
                record.retry_at = MonoInstant(now.0.saturating_add(record.retry_delay));
                record.retry_delay = record
                    .retry_delay
                    .saturating_mul(2)
                    .min(self.limits.maximum_retry_micros);
            }
        }
        self.completion_for(attempt.frame)
    }
    fn completion_for(&self, frame: Frame<'id>) -> Result<Completion<'id>, Error> {
        let record = *self.frame_record(frame)?;
        let FrameState::Complete {
            attempt,
            exposed,
            outcome,
        } = record.state
        else {
            return Err(Error::NotReady);
        };
        let neighbor = self.neighbor(record.target);
        let route = record.route.map(|route| self.route(route));
        Ok(Completion {
            frame,
            neighbor,
            route,
            attempt: attempt.map(|serial| Attempt {
                frame,
                serial,
                neighbor,
                route,
            }),
            outcome,
            exposed,
        })
    }
    /// One exact retained terminal frame; original bytes remain until release_frame.
    #[must_use]
    pub fn completion(&self) -> Option<Completion<'id>> {
        self.frames.iter().enumerate().find_map(|(slot, buffer)| {
            buffer
                .record
                .filter(|record| matches!(record.state, FrameState::Complete { .. }))
                .and_then(|record| {
                    self.completion_for(Frame {
                        brand: self.brand,
                        slot,
                        serial: record.serial,
                    })
                    .ok()
                })
        })
    }
    /// Cancel only an original frame that has never started on a CORE owner.
    /// This suppresses that immutable frame, not its route's retry policy; close
    /// the route explicitly when canceling logical connection establishment.
    pub fn cancel_frame(&mut self, frame: Frame<'id>) -> Result<(), Error> {
        let record = *self.frame_record(frame)?;
        if !matches!(record.state, FrameState::Queued) {
            return Err(Error::WouldBlock);
        }
        self.frames[frame.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .state = FrameState::Complete {
            attempt: None,
            exposed: false,
            outcome: Outcome::Unsent,
        };
        Ok(())
    }
    /// Explicitly release the exact observed terminal frame and wipe its bytes.
    pub fn release_frame(&mut self, frame: Frame<'id>) -> Result<(), Error> {
        let record = *self.frame_record(frame)?;
        if !matches!(record.state, FrameState::Complete { .. }) {
            return Err(Error::WouldBlock);
        }
        self.frames[frame.slot].bytes[..record.length].fill(0);
        self.frames[frame.slot].record = None;
        Ok(())
    }
    fn confirm_route(&mut self, route: RouteRef, now: MonoInstant) {
        if let Some(record) = self
            .routes
            .get_mut(route.slot)
            .and_then(|slot| slot.record.as_mut())
            .filter(|record| record.serial == route.serial && record.connection == route.connection)
        {
            record.phase = Phase::Ready;
            record.last_use = now;
        }
        for slot in self.frames.iter_mut() {
            if let Some(frame) = slot.record.as_mut()
                && frame.route == Some(route)
                && frame.kind == FrameType::Create
                && matches!(frame.state, FrameState::Queued)
            {
                frame.state = FrameState::Complete {
                    attempt: None,
                    exposed: false,
                    outcome: Outcome::Unsent,
                };
            }
        }
    }
    fn retire_route(
        &mut self,
        route: RouteRef,
        prev: bool,
        next: bool,
        destroy: bool,
        edge: ([u8; 32], [u8; 32]),
    ) {
        if let Some(record) = self
            .routes
            .get_mut(route.slot)
            .and_then(|slot| slot.record.as_mut())
            .filter(|record| record.serial == route.serial && record.connection == route.connection)
        {
            record.phase = Phase::Retired;
            record.notify_prev |= prev && record.prev.is_some();
            record.notify_next |= next && record.next.is_some();
            record.notice_destroy = destroy;
            record.edge = edge;
        }
        for slot in self.frames.iter_mut() {
            if let Some(frame) = slot.record.as_mut()
                && frame.route == Some(route)
                && matches!(frame.state, FrameState::Queued)
                && frame.kind != FrameType::Notice
            {
                if self
                    .routes
                    .get(route.slot)
                    .and_then(|s| s.record)
                    .is_some_and(|r| r.serial == route.serial && r.role == Role::Relay)
                {
                    self.statistics
                        .add(crate::statistics::Metric::RouteDestroyed, 1);
                }
                frame.state = FrameState::Complete {
                    attempt: None,
                    exposed: false,
                    outcome: Outcome::Unsent,
                };
            }
        }
    }
    /// Actual original CORE neighbor loss. Call only after its original native
    /// sends/cursors stopped. Active attempts on other peers still settle there.
    pub fn neighbor_lost(
        &mut self,
        neighbor: Neighbor<'id>,
        now: MonoInstant,
    ) -> Result<usize, Error> {
        self.neighbor_record(neighbor)?;
        self.time(now)?;
        self.neighbors[neighbor.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .live = false;
        let mut retired = 0;
        for slot in 0..self.routes.len() {
            if let Some(record) = self.routes[slot].record
                && record.phase != Phase::Retired
                && (record.prev == Some(neighbor.reference)
                    || record.next == Some(neighbor.reference))
            {
                let route = Self::route_ref(slot, record);
                self.retire_route(
                    route,
                    record.next == Some(neighbor.reference),
                    record.prev == Some(neighbor.reference),
                    false,
                    (self.local, neighbor.reference.peer),
                );
                retired += 1;
            }
        }
        for slot in self.frames.iter_mut() {
            if let Some(record) = slot.record.as_mut()
                && record.target == neighbor.reference
            {
                record.state = match record.state {
                    FrameState::Queued => FrameState::Complete {
                        attempt: None,
                        exposed: false,
                        outcome: Outcome::Unsent,
                    },
                    FrameState::Active { serial, exposed } => FrameState::Complete {
                        attempt: Some(serial),
                        exposed,
                        outcome: if exposed {
                            Outcome::Unknown
                        } else {
                            Outcome::Unsent
                        },
                    },
                    complete @ FrameState::Complete { .. } => complete,
                };
            }
        }
        Ok(retired)
    }
    /// Queue authenticated local route teardown intent, preserving original active
    /// physical attempts and retaining notifications until bounded storage frees.
    pub fn close_route(&mut self, route: Route<'id>) -> Result<(), Error> {
        let record = *self.route_record(route)?;
        if record.phase == Phase::Retired {
            return Err(Error::Closed);
        }
        self.retire_route(route.reference, true, true, true, ([0; 32], [0; 32]));
        Ok(())
    }
    /// Explicitly free only a retired route after its original frames/notifications
    /// drained, so stale local callbacks cannot mutate a reused route slot.
    pub fn release_route(&mut self, route: Route<'id>) -> Result<(), Error> {
        let record = *self.route_record(route)?;
        if record.phase != Phase::Retired
            || record.notify_prev
            || record.notify_next
            || self.frames.iter().any(|slot| {
                slot.record
                    .is_some_and(|frame| frame.route == Some(route.reference))
            })
        {
            return Err(Error::WouldBlock);
        }
        self.routes[route.reference.slot].record = None;
        Ok(())
    }
    /// Advance bounded CREATE retry, failure notifications and relay liveness.
    /// Capacity refusal retains all original intents; no fake callback is emitted.
    pub fn tick(&mut self, now: MonoInstant) -> Result<usize, Error> {
        self.time(now)?;
        let mut expired = 0;
        for slot in 0..self.routes.len() {
            let Some(mut record) = self.routes[slot].record else {
                continue;
            };
            let route = Self::route_ref(slot, record);
            if record.role == Role::Relay
                && record.phase != Phase::Retired
                && now.0.saturating_sub(record.last_use.0)
                    >= self.limits.keepalive_micros.saturating_mul(3)
            {
                self.retire_route(route, true, true, false, ([0; 32], [0; 32]));
                record = self.routes[slot].record.ok_or(Error::StaleGeneration)?;
                expired += 1;
            }
            if record.phase == Phase::Retired {
                for previous in [true, false] {
                    let notify = if previous {
                        record.notify_prev
                    } else {
                        record.notify_next
                    };
                    if !notify {
                        continue;
                    }
                    let target = if previous { record.prev } else { record.next };
                    if let Some(target) = target
                        && self.neighbor_ref(target).is_ok()
                    {
                        let message = if record.notice_destroy {
                            PeerMessage::ConnectionDestroy {
                                reserved: 0,
                                connection: record.connection,
                            }
                        } else {
                            PeerMessage::ConnectionBroken {
                                reserved: 0,
                                connection: record.connection,
                                peer1: record.edge.0,
                                peer2: record.edge.1,
                            }
                        };
                        self.enqueue(target, Some(route), FrameType::Notice, message)?;
                    }
                    if previous {
                        self.routes[slot]
                            .record
                            .as_mut()
                            .ok_or(Error::StaleGeneration)?
                            .notify_prev = false;
                    } else {
                        self.routes[slot]
                            .record
                            .as_mut()
                            .ok_or(Error::StaleGeneration)?
                            .notify_next = false;
                    }
                }
            } else if record.role == Role::Origin
                && record.phase == Phase::Opening
                && now >= record.retry_at
                && !self.frames.iter().any(|slot| {
                    slot.record.is_some_and(|frame| {
                        frame.route == Some(route)
                            && frame.kind == FrameType::Create
                            && matches!(frame.state, FrameState::Queued | FrameState::Active { .. })
                    })
                })
            {
                self.enqueue(
                    record.next.ok_or(Error::NotReady)?,
                    Some(route),
                    FrameType::Create,
                    Self::create_message(&record),
                )?;
            }
        }
        Ok(expired)
    }
    /// One actual established endpoint needing a genuine encrypted channel
    /// KEEPALIVE from its separate tunnel session. No plaintext keepalive is sent.
    #[must_use]
    pub fn keepalive_due(&self, now: MonoInstant) -> Option<Route<'id>> {
        self.routes.iter().enumerate().find_map(|(slot, route)| {
            let record = route.record?;
            if record.role == Role::Relay
                || record.phase != Phase::Ready
                || now.0.saturating_sub(record.last_use.0) < self.limits.keepalive_micros
            {
                return None;
            }
            let reference = Self::route_ref(slot, record);
            let target = record.next.or(record.prev)?;
            if !self
                .neighbor_ref(target)
                .is_ok_and(|neighbor| neighbor.ready)
                || self.active_neighbor(target)
                || self.frames.iter().any(|slot| {
                    slot.record.is_some_and(|frame| {
                        frame.route == Some(reference)
                            && matches!(frame.state, FrameState::Queued | FrameState::Active { .. })
                    })
                })
            {
                return None;
            }
            Some(self.route(reference))
        })
    }
    /// One actual retired route whose original notifications/outcomes still need
    /// draining. Repeated observation is harmless; release_route removes it.
    #[must_use]
    pub fn retired_route(&self) -> Option<Route<'id>> {
        self.routes.iter().enumerate().find_map(|(slot, route)| {
            route
                .record
                .filter(|record| record.phase == Phase::Retired)
                .map(|record| self.route(Self::route_ref(slot, record)))
        })
    }
    /// Select a real established endpoint path only when its original adjacent
    /// CORE peer is live, has observed local request-admission capacity, and owns
    /// no pending retained route frame. This grants no wire SendReady or ACK.
    #[must_use]
    pub fn select(&self, expected_peer: [u8; 32]) -> Option<Route<'id>> {
        self.routes
            .iter()
            .enumerate()
            .filter_map(|(slot, route)| {
                let record = route.record?;
                if record.phase != Phase::Ready || record.role == Role::Relay {
                    return None;
                }
                let remote = if record.role == Role::Origin {
                    record.path[record.length - 1]
                } else {
                    record.path[0]
                };
                let target = record.next.or(record.prev)?;
                let reference = Self::route_ref(slot, record);
                if remote != expected_peer
                    || !self
                        .neighbor_ref(target)
                        .is_ok_and(|neighbor| neighbor.ready)
                    || self.active_neighbor(target)
                    || self.frames.iter().any(|slot| {
                        slot.record.is_some_and(|frame| {
                            frame.route == Some(reference)
                                && matches!(
                                    frame.state,
                                    FrameState::Queued | FrameState::Active { .. }
                                )
                        })
                    })
                {
                    return None;
                }
                Some((reference, record))
            })
            .min_by_key(|(_, record)| {
                (
                    record.latency.unwrap_or(1_000_000),
                    record.last_use,
                    record.serial,
                )
            })
            .map(|(route, _)| self.route(route))
    }
    /// Actual relay-only current queues/routes and original cumulative observations.
    #[must_use]
    pub fn statistics(&self) -> crate::statistics::Snapshot {
        let mut snapshot = self.statistics.snapshot();
        snapshot.set(
            crate::statistics::Metric::Routes,
            self.routes
                .iter()
                .filter(|r| {
                    r.record
                        .is_some_and(|r| r.role == Role::Relay && r.phase != Phase::Retired)
                })
                .count(),
        );
        snapshot.set(
            crate::statistics::Metric::BufferUse,
            self.frames
                .iter()
                .filter(|f| {
                    f.record.is_some_and(|f| {
                        matches!(f.state, FrameState::Queued)
                            && f.route
                                .and_then(|r| {
                                    self.routes
                                        .get(r.slot)
                                        .and_then(|s| s.record)
                                        .filter(|v| v.serial == r.serial)
                                })
                                .is_some_and(|r| r.role == Role::Relay)
                    })
                })
                .count(),
        );
        snapshot
    }
    /// Record only the same original native input actually discarded after
    /// enqueue refused a full retained frame pool. The private refusal label is
    /// consumed once; coincidentally full pools, other Capacity errors and local
    /// output retries never become dropped-input observations. No ACK is implied.
    pub fn discarded_full_buffer(&mut self, source: Neighbor<'id>, message: PeerMessage<'_>) {
        // Refusal metadata is diagnostic, but foreign domains still cannot
        // consume this original source's observation.
        if self.neighbor_record(source).is_err() {
            return;
        }
        if self.refused_input.take()
            == Some((
                source.reference,
                connection_id(message),
                frame_type(message),
            ))
        {
            self.statistics
                .add(crate::statistics::Metric::FullBuffer, 1);
        }
    }
    /// Actual unambiguous end-to-end latency observation supplied by the channel
    /// ACK owner, scoped to this original route epoch rather than a raw reused CID.
    pub fn latency_observed(&mut self, route: Route<'id>, micros: u64) -> Result<(), Error> {
        self.route_record(route)?;
        let record = self.routes[route.reference.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        if record.phase != Phase::Ready {
            return Err(Error::NotReady);
        }
        let weight = u128::from(record.samples.min(7));
        record.latency = Some(match record.latency {
            Some(old) => ((u128::from(old) * weight + u128::from(micros)) / (weight + 1)) as u64,
            None => micros,
        });
        record.samples = record.samples.saturating_add(1).min(7);
        self.statistics.add(crate::statistics::Metric::Latencies, 1);
        Ok(())
    }
}
fn connection_id(message: PeerMessage<'_>) -> [u8; 32] {
    match message {
        PeerMessage::ConnectionCreate { connection, .. }
        | PeerMessage::ConnectionCreateAck { connection, .. }
        | PeerMessage::ConnectionBroken { connection, .. }
        | PeerMessage::ConnectionDestroy { connection, .. }
        | PeerMessage::KeyExchange { connection, .. }
        | PeerMessage::KeyExchangeAuth { connection, .. }
        | PeerMessage::Encrypted { connection, .. } => connection,
    }
}
fn frame_type(message: PeerMessage<'_>) -> FrameType {
    match message {
        PeerMessage::ConnectionCreate { .. } => FrameType::Create,
        PeerMessage::ConnectionCreateAck { .. } => FrameType::Ack,
        PeerMessage::ConnectionBroken { .. } | PeerMessage::ConnectionDestroy { .. } => {
            FrameType::Notice
        }
        PeerMessage::KeyExchange { .. } | PeerMessage::KeyExchangeAuth { .. } => {
            FrameType::Payload(Kind::KeyExchange)
        }
        PeerMessage::Encrypted { .. } => FrameType::Payload(Kind::Encrypted),
    }
}
fn valid_broken(
    path: &[[u8; 32]],
    position: usize,
    from_prev: bool,
    peer1: [u8; 32],
    peer2: [u8; 32],
) -> bool {
    if peer2 == [0; 32] {
        return peer1 == [0; 32]
            || path.iter().enumerate().any(|(index, peer)| {
                *peer == peer1
                    && if from_prev {
                        index < position
                    } else {
                        index > position
                    }
            });
    }
    path.windows(2).enumerate().any(|(index, peers)| {
        ((peers[0] == peer1 && peers[1] == peer2) || (peers[0] == peer2 && peers[1] == peer1))
            && if from_prev {
                index < position
            } else {
                index >= position
            }
    })
}

#[cfg(test)]
#[path = "connection_tests.rs"]
mod tests;
