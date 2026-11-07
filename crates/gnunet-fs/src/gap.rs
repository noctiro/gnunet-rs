//! Bounded GAP content-hash query/return-path ownership; allocation-free by default.
//! Optional `alloc` supports actual larger official filters under an aggregate cap.
//!
//! This composable layer handles official CORE FS137/138 D/I/UBLOCK/ANY routing.
//! Hosts supply actual CORE neighbor generations, logical source microseconds,
//! cryptographic entropy, original source operations and actual MQ write facts.
//! It opens no socket, datastore, CADET, DHT, timer, task or private wire protocol.
//! Unknown-source level0 D/I and anonymous level1 use hop-by-hop CORE queries:
//! no origin/target identity extensions are emitted. Original level0 stays0.
//! Higher numeric output needs the explicit privacy owner's real cover permission;
//! this alone is no global anonymity proof.
//! Unsolicited migration remains separate. UBLOCK result groups use
//! the official BLOCK Bloom logic; each original request keeps independent state.
mod group;
/// Real cover-budget claims and bounded randomized release over original IO.
pub mod privacy;
pub mod storage;
use gnunet_crypto::hash512;
use gnunet_types::Error;
/// Inline per-request official BLOCK Bloom bits, independent of result buffers.
/// The full query table is bounded by caller-provided RouteSlots.
pub const GROUP_FILTER_BYTES: usize = group::BYTES;
/// Largest official serialized group's bit array; its nonce is four extra wire bytes.
pub const MAX_GROUP_FILTER_BYTES: usize = gnunet_wire::official::fs_gap::MAX_BLOOM_BYTES;
use gnunet_wire::official::{
    fs::BlockType,
    fs_gap::{GET_PREFIX, Get, KNOWN_OPTIONS, Put, RETURN_TO},
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
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Target {
    Peer(Ref),
    Local(u64),
}
#[derive(Clone, Copy, Debug)]
struct Return {
    serial: u64,
    route: Ref,
    target: Target,
    done: bool,
    delivered: u64,
    anonymity: u32,
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
    relay: bool,
    result_source: StoredSource,
    unsolicited: bool,
}
/// One caller-provided route and immutable positive frame buffer. It is a real
/// retained result for active reverse paths, not an invented datastore cache hit.
pub struct RouteSlot<'bytes> {
    record: Option<Query>,
    bytes: &'bytes mut [u8],
    group: group::Group,
}
impl<'bytes> RouteSlot<'bytes> {
    /// Borrow one finite original-result buffer.
    #[must_use]
    pub fn new(bytes: &'bytes mut [u8]) -> Self {
        Self {
            record: None,
            bytes,
            group: group::Group::empty(),
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
    /// Zero admits only inline groups; no-alloc builds never allocate large groups.
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
    /// Actual D/I/UBLOCK/ANY registry value.
    pub kind: BlockType,
    /// Original content hash.
    pub query: [u8; 64],
}
/// Original one-shot source job; retain its Route token through cancellation.
#[derive(Clone, Copy, Debug)]
pub struct Lookup<'id> {
    /// Exact original query generation.
    pub route: Route<'id>,
    /// Actual selection, no datastore UID/metadata guess.
    pub selection: Selection,
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
struct Sending {
    serial: u64,
    neighbor: Ref,
    route: Ref,
    path: Option<Ref>,
    priority: u32,
    length: usize,
    admitted: bool,
    exposed: bool,
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
        };
        Ok(self.n(Ref { slot, serial }))
    }
    /// Original current public peer identity for a real neighbor token.
    pub fn peer(&self, neighbor: Neighbor<'id>) -> Result<[u8; 32], Error> {
        let r = self.neighbor(neighbor)?;
        self.neighbors[r.slot].peer.ok_or(Error::StaleGeneration)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Original selection/return authority, TTL and independent reply group are explicit admission inputs"
    )]
    fn admit(
        &mut self,
        selection: Selection,
        target: Target,
        forbidden: u64,
        priority: u32,
        ttl: i32,
        now: u64,
        group: Option<impl FnOnce(usize) -> Result<group::Group, Error>>,
        request_group: [u8; 64],
        anonymity: u32,
        relay: bool,
    ) -> Result<Admission<'id>, Error> {
        if self.stopping {
            return Err(Error::Closed);
        }
        if !matches!(selection.kind.value(), 0 | 1 | 2 | 9) {
            return Err(Error::Unsupported);
        }
        let multiple = matches!(selection.kind.value(), 0 | 9);
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
            if let Some(q) = self.routes[route.slot].record.as_mut() {
                q.forbidden |= forbidden;
                q.relay &= relay;
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
            self.routes
                .iter()
                .position(|r| r.record.is_none())
                .ok_or(Error::Capacity)?
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
        // Existing route/path merges above never build or copy filter state.
        // All metadata arithmetic precedes the only optional new allocation.
        let prepared_group = if old.is_none() {
            let available = self
                .limits
                .filter_heap_bytes
                .checked_sub(self.filter_heap_bytes)
                .ok_or(Error::Overflow)?;
            let group = group
                .map(|build| build(available))
                .transpose()?
                .unwrap_or_else(group::Group::empty);
            let heap = self
                .filter_heap_bytes
                .checked_add(group.heap_bytes())
                .ok_or(Error::Overflow)?;
            if heap > self.limits.filter_heap_bytes {
                return Err(Error::Capacity);
            }
            Some((group, heap))
        } else {
            None
        };
        if let Some((group, heap)) = prepared_group {
            self.routes[route_slot].record = Some(Query {
                serial: route_serial,
                kind: selection.kind,
                key: selection.query,
                priority: priority.min(self.limits.max_priority),
                wire_deadline: i128::from(now) + i128::from(ttl) * 1_000_000,
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
                relay,
                result_source: StoredSource::Unspecified,
                unsolicited: false,
            });
            self.routes[route_slot].group = group;
            self.filter_heap_bytes = heap;
        } else if let Some(q) = self.routes[route_slot].record.as_mut() {
            q.forbidden |= forbidden;
            q.relay &= relay;
        }
        self.paths[path_slot].record = Some(Return {
            serial: path_serial,
            route: reference,
            target,
            done: false,
            delivered: 0,
            anonymity,
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
        let route_slot = self
            .routes
            .iter()
            .position(|r| r.record.is_none())
            .ok_or(Error::Capacity)?;
        let path_slot = self
            .paths
            .iter()
            .position(|p| p.record.is_none())
            .ok_or(Error::Capacity)?;
        if self.routes[route_slot].bytes.len() < frame.len() {
            return Err(Error::Capacity);
        }
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
        self.routes[route_slot].group = group::Group::empty();
        self.routes[route_slot].record = Some(Query {
            serial: route_serial,
            kind: put.block_type,
            key,
            priority: 0,
            wire_deadline: i128::from(now),
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
            relay: false,
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
        self.pending.and_then(|p| p.path.map(|path| self.p(path)))
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
        if anonymity != 1 || !matches!(selection.kind.value(), 1 | 2) {
            return Err(Error::Unsupported);
        }
        self.admit(
            selection,
            Target::Local(local_tag),
            0,
            priority,
            ttl_seconds,
            now,
            None::<fn(usize) -> Result<group::Group, Error>>,
            [0; 64],
            anonymity,
            false,
        )
    }
    /// Start one original request with its actual whole-UBLOCK seen set. Entropy
    /// creates its official local Bloom group; D/I use no group. Level0
    /// D/I/UBLOCK discovery keeps its original numeric0. Level0 ANY is refused.
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
        if anonymity == 0 && !matches!(selection.kind.value(), 1 | 2 | 9) {
            return Err(Error::Unsupported);
        }
        let group = matches!(selection.kind.value(), 0 | 9)
            .then_some(|available| group::Group::new(None, seen, entropy, available));
        self.admit(
            selection,
            Target::Local(local_tag),
            0,
            priority,
            ttl_seconds,
            now,
            group,
            [0; 64],
            anonymity,
            false,
        )
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
        let ingress = self.neighbor(from)?;
        let get = Get::decode(frame)?;
        if get.bitmap & !KNOWN_OPTIONS != 0 {
            return Err(Error::Unsupported);
        }
        let target = if let Some(peer) = get.identity(RETURN_TO)? {
            self.neighbors
                .iter()
                .enumerate()
                .find_map(|(slot, n)| {
                    (n.peer.as_ref() == Some(peer)).then_some(Ref {
                        slot,
                        serial: n.serial,
                    })
                })
                .ok_or(Error::NotFound)?
        } else {
            ingress
        };
        let priority = get.priority.min(self.limits.max_priority);
        // Exact active C bound/decrement; actual send/create TTL unit is seconds.
        let ttl = if get.ttl_seconds > 0 {
            i64::from(get.ttl_seconds)
                .min(i64::from(priority) * 5)
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
        let group = matches!(get.block_type.value(), 0 | 9)
            .then_some(|available| group::Group::new(raw, &[], entropy, available));
        self.admit(
            Selection {
                kind: get.block_type,
                query: *get.query,
            },
            Target::Peer(target),
            (1_u64 << ingress.slot) | (1_u64 << target.slot),
            priority,
            ttl,
            now,
            group,
            hash512(get.bloom),
            1,
            !is_local,
        )
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
        frame: &[u8],
        kind: BlockType,
        digest: &[u8; 64],
        source: StoredSource,
    ) -> Result<(), Error> {
        if kind == BlockType::UBLOCK {
            self.routes[route.slot].group.mark(digest)?;
        }
        self.routes[route.slot].bytes[..frame.len()].copy_from_slice(frame);
        let q = self.routes[route.slot]
            .record
            .as_mut()
            .ok_or(Error::StaleGeneration)?;
        q.positive = frame.len();
        q.result_serial += 1;
        q.terminal = kind != BlockType::UBLOCK;
        q.result_source = source;
        if q.source == Source::Queued {
            q.source = Source::Done;
        }
        Ok(())
    }
    fn install(
        &mut self,
        route: Ref,
        frame: &[u8],
        source: StoredSource,
    ) -> Result<ResultState, Error> {
        if self.query(route)?.retiring {
            return Ok(ResultState::Retired);
        }
        let put = Put::decode(frame)?;
        let digest = hash512(put.block);
        let key = Self::result_key(put, &digest)?;
        let state = self.preflight(route, put, &key, &digest, frame.len())?;
        if state == ResultState::Retained {
            self.commit_result(route, frame, put.block_type, &digest, source)?;
        }
        Ok(state)
    }
    /// Whether an actual result is still owned for any original consumer. A
    /// streaming source must pause unadmitted UID continuation while this holds.
    pub fn positive_pending(&self, route: Route<'id>) -> Result<bool, Error> {
        Ok(self.query(self.route(route)?)?.positive != 0)
    }
    /// Accept one nonterminal original source item. Its real source operation
    /// remains Running until its later original storage terminal/failure retires.
    pub fn source_result(&mut self, route: Route<'id>, frame: &[u8]) -> Result<ResultState, Error> {
        let r = self.route(route)?;
        if self.query(r)?.source != Source::Running {
            return Err(Error::Conflict);
        }
        self.install(r, frame, StoredSource::Unspecified)
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
        self.install(r, frame, StoredSource::Local(anonymity))
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
            self.install(r, frame, StoredSource::Unspecified)?
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
    ) -> Result<ResultState, Error> {
        let r = self.route(route)?;
        let q = self.query(r)?;
        if q.source != Source::Running {
            return Err(Error::Conflict);
        }
        let state = if let Some(frame) = actual {
            self.install(r, frame, StoredSource::Local(anonymity))?
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
        let origin = self.neighbor(from)?;
        let source = StoredSource::Peer {
            from: origin,
            is_local,
        };
        self.neighbor(from)?;
        let frame = checked.frame;
        let put = checked.put;
        let digest = checked.digest;
        let key = checked.key;
        let mut state = ResultState::Unmatched;
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
                    self.commit_result(route, frame, put.block_type, &digest, source)?;
                }
            }
        }
        Ok(state)
    }
    fn begin_send(
        &mut self,
        neighbor: Ref,
        route: Ref,
        path: Option<Ref>,
        priority: u32,
        length: usize,
    ) -> Result<Transmit<'id>, Error> {
        let serial = self.next_serial()?;
        self.serial = serial;
        self.pending = Some(Sending {
            serial,
            neighbor,
            route,
            path,
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
        let r = self.route(route)?;
        self.neighbor(neighbor)?;
        let q = self.query(r)?;
        if q.retiring {
            return Err(Error::Closed);
        }
        if q.source != Source::Done || q.positive != 0 {
            return Err(Error::NotReady);
        }
        let n = self.neighbor(neighbor)?;
        if q.forwards >= self.limits.fanout || ((q.forbidden | q.attempted) & (1u64 << n.slot)) != 0
        {
            return Err(Error::PermissionDenied);
        }
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
            privacy::Class::new(mt::FS_GET, q.kind, GET_PREFIX)?,
            level,
            q.relay,
        ))
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
            self.query_requirement(requirement.route(), requirement.neighbor())
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
        self.prepare_query_inner(route, neighbor, now, entropy)
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
        self.prepare_query_inner(route, neighbor, now, entropy)
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
    ) -> Result<Transmit<'id>, Error> {
        let r = self.route(route)?;
        let n = self.neighbor(neighbor)?;
        if self.stopping {
            return Err(Error::Closed);
        }
        if self.pending.is_some() {
            return Err(Error::WouldBlock);
        }
        let q = self.query(r)?;
        if q.retiring || now >= q.retain_until {
            return Err(Error::Closed);
        }
        if q.source != Source::Done || q.positive != 0 {
            return Err(Error::NotReady);
        }
        if q.forwards >= self.limits.fanout
            || ((q.forbidden | q.attempted) & (1_u64 << n.slot)) != 0
        {
            return Err(Error::PermissionDenied);
        }
        let ttl = i32::try_from((q.wire_deadline - i128::from(now)) / 1_000_000)
            .map_err(|_| Error::Overflow)?;
        let priority = entropy.uniform(q.priority + 1)?;
        if priority > q.priority {
            return Err(Error::InvalidInput);
        }
        let length = Get {
            block_type: q.kind,
            priority,
            ttl_seconds: ttl,
            reserved: 0,
            bitmap: 0,
            query: &q.key,
            identities: &[],
            bloom: &[],
        }
        .encode(self.output)?;
        self.begin_send(n, r, None, priority, length)
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
        self.begin_send(neighbor, ret.route, Some(p), 0, q.positive)
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
        if let Some(path) = p.path {
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
        } else if let Some(q) = self.routes[p.route.slot]
            .record
            .as_mut()
            .filter(|q| q.serial == p.route.serial)
        {
            q.attempted |= 1_u64 << p.neighbor.slot;
            q.forwards = q.forwards.saturating_add(1);
            q.priority = q.priority.saturating_sub(p.priority);
        }
        let fact = SendRetired {
            transmit: self.t(p.serial),
            neighbor: self.n(p.neighbor),
            route: self.r(p.route),
            kind: if p.path.is_some() {
                SendKind::Reply
            } else {
                SendKind::Query
            },
            path: p.path.map(|path| self.p(path)),
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
        let p = self.sending(tx)?;
        if !p.admitted || !p.exposed {
            return Err(Error::NotReady);
        }
        self.settle_send(p, true)
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
        let heap = self
            .filter_heap_bytes
            .checked_sub(self.routes[r.slot].group.heap_bytes())
            .ok_or(Error::Overflow)?;
        self.routes[r.slot].bytes[..q.positive].fill(0);
        self.routes[r.slot].record = None;
        self.routes[r.slot].group = group::Group::empty();
        self.filter_heap_bytes = heap;
        for p in &mut *self.paths {
            if p.record.is_some_and(|p| p.route == r) {
                p.record = None;
            }
        }
        Ok(())
    }
}
