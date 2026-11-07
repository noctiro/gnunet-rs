//! Allocation-free official FS query service ownership over explicit local and
//! peer effects. No socket, task, storage or private wire identifier is created.
//!
//! A native host must retain an original datastore operation until it settles,
//! and admit an encoded result to its original socket queue before commit_reply.
//! Disconnect invalidates every query/lease for that physical client. There is
//! no local search END, negative reply or per-query wire cancellation message.
use gnunet_crypto::hash512;
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, MAX_MESSAGE_SIZE,
    datastore::Data,
    fs::{BlockType, ClientPut, Response, SEARCH_CONTINUED, SEARCH_LOOPBACK_ONLY, Search},
};
use subtle::ConstantTimeEq;

/// Exclusive identity storage borrowed while this service and its tokens exist.
#[derive(Debug, Default)]
pub struct Instance {
    _private: u8,
}
impl Instance {
    /// Construct fresh local identity storage, never encoded as an FS field.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: 0 }
    }
}
/// One caller-provided physical client slot.
#[derive(Clone, Copy, Debug, Default)]
pub struct ClientSlot {
    serial: u64,
    active: bool,
}
/// Original physical client authority; its diagnostic number is not a wire RID.
#[derive(Clone, Copy, Debug)]
pub struct ClientId<'id> {
    owner: &'id Instance,
    slot: usize,
    serial: u64,
}
impl PartialEq for ClientId<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.owner, other.owner)
            && self.slot == other.slot
            && self.serial == other.serial
    }
}
impl Eq for ClientId<'_> {}
impl ClientId<'_> {
    /// Monotonic local diagnostic only; it cannot construct or authorize an ID.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}
/// One original query, scoped to this instance and physical client lifetime.
#[derive(Clone, Copy, Debug)]
pub struct QueryId<'id> {
    owner: &'id Instance,
    slot: usize,
    serial: u64,
}
impl PartialEq for QueryId<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.owner, other.owner)
            && self.slot == other.slot
            && self.serial == other.serial
    }
}
impl Eq for QueryId<'_> {}
impl QueryId<'_> {
    /// Monotonic local diagnostic, never transmitted as a request identifier.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.serial
    }
}
/// Public query fields retained independently of the original input frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Descriptor<'id> {
    /// Actual original physical client.
    pub client: ClientId<'id>,
    /// Requested concrete FS type, or official ANY.
    pub block_type: BlockType,
    /// Caller-requested anonymity level for real peer routing.
    pub anonymity: u32,
    /// Requested peer for D/I, otherwise all zeros.
    pub target: [u8; 32],
    /// Exact official lookup key.
    pub query: [u8; 64],
    /// Do not start peer effects after the local sweep.
    pub local_only: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Local {
    Assembling,
    Ready(u64),
    Pending { attempt: u64, next_uid: u64 },
    Exhausted,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Network {
    None,
    Ready,
    Active(u64),
    Dormant,
}
#[derive(Clone, Copy, Debug)]
struct State {
    serial: u64,
    client_slot: usize,
    client_serial: u64,
    block_type: BlockType,
    anonymity: u32,
    target: [u8; 32],
    query: [u8; 64],
    local_only: bool,
    local: Local,
    network: Network,
    complete: bool,
    revision: u64,
}
/// Query state and its exact whole-block digest set use caller-provided storage.
/// Seen hashes are kept sorted; unused caller entries carry no authority.
pub struct QuerySlot<'seen> {
    seen: &'seen mut [[u8; 64]],
    seen_len: usize,
    state: Option<State>,
}
impl<'seen> QuerySlot<'seen> {
    /// Empty query slot using this exact hash buffer. No allocation occurs.
    #[must_use]
    pub fn new(seen: &'seen mut [[u8; 64]]) -> Self {
        Self {
            seen,
            seen_len: 0,
            state: None,
        }
    }
}
/// Explicit block/expiry policy, separate from socket and datastore resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum body allowed in a complete official ClientPutMessage.
    pub max_block_bytes: usize,
    /// Optional source-UTC UBLOCK expiration filtering before seen-set admission.
    /// False preserves the pinned service's local result behavior; D/I are not filtered.
    pub expire_ublocks: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_block_bytes: MAX_MESSAGE_SIZE - 32,
            expire_ublocks: false,
        }
    }
}
/// Successful admission or extension of one assembling official search.
#[derive(Clone, Copy, Debug)]
pub struct Admission<'id> {
    /// Retained original query authority.
    pub query: QueryId<'id>,
    /// Additional CONTINUED fragments must arrive before lookup starts.
    pub assembling: bool,
    /// True when extending the matching still-assembling search.
    pub merged: bool,
}
/// One leased original local datastore GET. It cannot authorize another attempt.
#[derive(Clone, Copy, Debug)]
pub struct Lookup<'id> {
    query: QueryId<'id>,
    client: ClientId<'id>,
    attempt: u64,
    key: [u8; 64],
    kind: BlockType,
    next_uid: u64,
}
impl<'id> Lookup<'id> {
    /// Query authority retained until original local operation settlement.
    #[must_use]
    pub const fn query_id(self) -> QueryId<'id> {
        self.query
    }
    /// Original physical client, which may already have disconnected.
    #[must_use]
    pub const fn client(self) -> ClientId<'id> {
        self.client
    }
    /// Exact datastore key.
    #[must_use]
    pub const fn key(&self) -> &[u8; 64] {
        &self.key
    }
    /// Datastore selector. DBLOCK maps to ANY so type6 on-demand records are visible.
    #[must_use]
    pub const fn block_type(self) -> BlockType {
        self.kind
    }
    /// Inclusive UID cursor; this deterministic sweep does not wrap.
    #[must_use]
    pub const fn next_uid(self) -> u64 {
        self.next_uid
    }
}
/// Original active peer-route authority. One route may produce many UBLOCKs.
#[derive(Clone, Copy, Debug)]
pub struct Route<'id> {
    query: QueryId<'id>,
    descriptor: Descriptor<'id>,
    attempt: u64,
}
impl<'id> Route<'id> {
    /// Original query owner, invalidated by physical disconnect.
    #[must_use]
    pub const fn query_id(self) -> QueryId<'id> {
        self.query
    }
    /// Original physical client.
    #[must_use]
    pub const fn client(self) -> ClientId<'id> {
        self.descriptor.client
    }
    /// Actual routing inputs; copy the exact seen set separately through Service::seen.
    #[must_use]
    pub const fn descriptor(self) -> Descriptor<'id> {
        self.descriptor
    }
    /// Official search inputs with no borrowed seen buffer. No private routing field.
    #[must_use]
    pub const fn search(self) -> Search<'static> {
        Search {
            options: 0,
            block_type: self.descriptor.block_type,
            anonymity: self.descriptor.anonymity,
            target: self.descriptor.target,
            query: self.descriptor.query,
            seen: &[],
        }
    }
}
/// Why a real candidate was not emitted. No variant encodes an FS negative reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SkipReason {
    /// Its whole signed UBLOCK digest was already present.
    Duplicate,
    /// Explicit UBLOCK source-UTC expiration policy rejected the candidate.
    Expired,
    /// Original candidate key, type, shape, signature or resource refusal.
    Invalid(Error),
}
/// Original local result advancement, prepared without changing the query cursor.
#[derive(Clone, Copy, Debug)]
pub struct Advance<'id> {
    lookup: Lookup<'id>,
    revision: u64,
    next_uid: Option<u64>,
    reason: SkipReason,
}
impl<'id> Advance<'id> {
    /// Original query authority.
    #[must_use]
    pub const fn query_id(self) -> QueryId<'id> {
        self.lookup.query
    }
    /// Original diagnostic; native hosts can retain it before committing advancement.
    #[must_use]
    pub const fn reason(self) -> SkipReason {
        self.reason
    }
}
#[derive(Clone, Copy, Debug)]
enum Origin {
    Local {
        attempt: u64,
        cursor: u64,
        advance: Option<u64>,
    },
    Peer {
        attempt: u64,
    },
}
/// Exact encoded reply prefix with deferred seen/cursor changes. Retain its output
/// bytes on the original socket before committing this opaque preparation.
#[derive(Clone, Copy, Debug)]
pub struct PreparedReply<'id> {
    query: QueryId<'id>,
    client: ClientId<'id>,
    revision: u64,
    origin: Origin,
    digest: Option<[u8; 64]>,
    terminal: bool,
    bytes: usize,
}
impl<'id> PreparedReply<'id> {
    /// Number of already encoded official response bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }
    /// Original query authority.
    #[must_use]
    pub const fn query_id(self) -> QueryId<'id> {
        self.query
    }
    /// Original physical client for output admission.
    #[must_use]
    pub const fn client(self) -> ClientId<'id> {
        self.client
    }
    /// True only for a terminal actual D/I result, never for a keyword hit.
    #[must_use]
    pub const fn completed(self) -> bool {
        self.terminal
    }
}
/// An actual type6 datastore descriptor requiring native indexed-file access.
/// The original Lookup remains pending while the host resolves and encodes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OnDemand {
    /// Whole plaintext file identifier.
    pub file_id: [u8; 64],
    /// Big-endian decoded byte offset within that original indexed file.
    pub offset: u64,
}
/// Pure preparation result for one original actual local datastore DATA.
#[derive(Clone, Copy, Debug)]
pub enum LocalResult<'id> {
    /// Output bytes exist, but query state has not yet advanced.
    Reply(PreparedReply<'id>),
    /// No output bytes; commit this original candidate's UID advancement explicitly.
    Skip(Advance<'id>),
    /// Resolve actual source bytes, then prepare Local again as a real DBLOCK
    /// using the original UID/key/expiry, or explicitly skip_local on failure.
    OnDemand(OnDemand),
}
/// Pure preparation of a candidate from the original real peer route.
#[derive(Clone, Copy, Debug)]
pub enum PeerResult<'id> {
    /// Output exists; commit only after admission to the original native queue.
    Reply(PreparedReply<'id>),
    /// An irrelevant, duplicate or invalid result; no query mutation or wire reply.
    Ignored(SkipReason),
}
/// Shared query owner with explicit connection/query/seen capacity and no allocator.
pub struct Service<'id, 'slots, 'seen> {
    owner: &'id Instance,
    clients: &'slots mut [ClientSlot],
    queries: &'slots mut [QuerySlot<'seen>],
    limits: Limits,
    client_serial: u64,
    query_serial: u64,
    attempt_serial: u64,
    local_cursor: usize,
    route_cursor: usize,
}
impl<'id, 'slots, 'seen> Service<'id, 'slots, 'seen> {
    /// Number of caller query slots, for native work/scratch preflight.
    #[must_use]
    pub fn query_capacity(&self) -> usize {
        self.queries.len()
    }
    /// Validate policy before resetting caller slots for this new instance. The
    /// exclusive Instance borrow prevents old tokens from authorizing a new owner.
    pub fn new(
        owner: &'id mut Instance,
        clients: &'slots mut [ClientSlot],
        queries: &'slots mut [QuerySlot<'seen>],
        limits: Limits,
    ) -> Result<Self, Error> {
        if limits.max_block_bytes == 0 || limits.max_block_bytes > MAX_MESSAGE_SIZE - 32 {
            return Err(Error::InvalidInput);
        }
        for client in clients.iter_mut() {
            *client = ClientSlot::default();
        }
        for query in queries.iter_mut() {
            query.state = None;
            query.seen_len = 0;
        }
        Ok(Self {
            owner,
            clients,
            queries,
            limits,
            client_serial: 0,
            query_serial: 0,
            attempt_serial: 0,
            local_cursor: 0,
            route_cursor: 0,
        })
    }
    fn client(&self, client: ClientId<'id>) -> Result<(), Error> {
        if !core::ptr::eq(self.owner, client.owner) {
            return Err(Error::Stale);
        }
        match self.clients.get(client.slot) {
            Some(slot) if slot.active && slot.serial == client.serial => Ok(()),
            _ => Err(Error::Stale),
        }
    }
    fn state(&self, query: QueryId<'id>) -> Result<State, Error> {
        if !core::ptr::eq(self.owner, query.owner) {
            return Err(Error::Stale);
        }
        self.queries
            .get(query.slot)
            .and_then(|slot| slot.state)
            .filter(|state| state.serial == query.serial)
            .ok_or(Error::Stale)
    }
    fn id(&self, slot: usize, state: State) -> QueryId<'id> {
        QueryId {
            owner: self.owner,
            slot,
            serial: state.serial,
        }
    }
    fn client_id(&self, state: State) -> ClientId<'id> {
        ClientId {
            owner: self.owner,
            slot: state.client_slot,
            serial: state.client_serial,
        }
    }
    fn description(&self, state: State) -> Descriptor<'id> {
        Descriptor {
            client: self.client_id(state),
            block_type: state.block_type,
            anonymity: state.anonymity,
            target: state.target,
            query: state.query,
            local_only: state.local_only,
        }
    }
    fn lookup_state(&self, lookup: Lookup<'id>) -> Result<State, Error> {
        let state = self.state(lookup.query)?;
        self.client(lookup.client)?;
        if state.complete
            || state.local
                != (Local::Pending {
                    attempt: lookup.attempt,
                    next_uid: lookup.next_uid,
                })
        {
            return Err(Error::Stale);
        }
        Ok(state)
    }
    fn route_state(&self, route: Route<'id>) -> Result<State, Error> {
        let state = self.state(route.query)?;
        self.client(route.descriptor.client)?;
        if state.complete || state.network != Network::Active(route.attempt) {
            return Err(Error::Stale);
        }
        Ok(state)
    }
    /// Admit one actual physical client. Exhaustion leaves all caller state unchanged.
    pub fn connect(&mut self) -> Result<ClientId<'id>, Error> {
        let slot = self
            .clients
            .iter()
            .position(|slot| !slot.active)
            .ok_or(Error::Capacity)?;
        let serial = self.client_serial.checked_add(1).ok_or(Error::Overflow)?;
        self.client_serial = serial;
        self.clients[slot] = ClientSlot {
            serial,
            active: true,
        };
        Ok(ClientId {
            owner: self.owner,
            slot,
            serial,
        })
    }
    /// Invalidate all queries/leases for a physically closed client. The host
    /// still drains its original datastore operation before reusing that MQ.
    pub fn disconnect(&mut self, client: ClientId<'id>) -> Result<(), Error> {
        self.client(client)?;
        self.clients[client.slot].active = false;
        for slot in self.queries.iter_mut() {
            if slot.state.is_some_and(|state| {
                state.client_serial == client.serial && state.client_slot == client.slot
            }) {
                slot.state = None;
                slot.seen_len = 0;
            }
        }
        Ok(())
    }
    /// Retain or extend a real Search. CONTINUED fragments assemble only the same
    /// still-unstarted query/type and must preserve its other routing fields.
    /// This follows the public comment, fixing the pinned C unequal-query bug.
    pub fn admit(
        &mut self,
        client: ClientId<'id>,
        search: Search<'_>,
    ) -> Result<Admission<'id>, Error> {
        self.client(client)?;
        search.validate()?;
        if !matches!(search.block_type.value(), 0 | 1 | 2 | 9) {
            return Err(Error::Unsupported);
        }
        let local_only = search.options & SEARCH_LOOPBACK_ONLY != 0;
        let assembling = search.options & SEARCH_CONTINUED != 0;
        let existing = self.queries.iter().position(|slot| {
            slot.state.is_some_and(|state| {
                state.client_serial == client.serial
                    && state.client_slot == client.slot
                    && state.local == Local::Assembling
                    && state.block_type == search.block_type
                    && state.query == search.query
            })
        });
        if let Some(index) = existing {
            let mut state = self.queries[index].state.ok_or(Error::Stale)?;
            if state.anonymity != search.anonymity
                || state.target != search.target
                || state.local_only != local_only
            {
                return Err(Error::Conflict);
            }
            reserve_seen(&self.queries[index], search.seen)?;
            append_seen(&mut self.queries[index], search.seen)?;
            if !assembling {
                state.local = Local::Ready(0);
                self.queries[index].state = Some(state);
            }
            return Ok(Admission {
                query: self.id(index, state),
                assembling,
                merged: true,
            });
        }
        let index = self
            .queries
            .iter()
            .position(|slot| slot.state.is_none())
            .ok_or(Error::Capacity)?;
        reserve_seen(&self.queries[index], search.seen)?;
        let serial = self.query_serial.checked_add(1).ok_or(Error::Overflow)?;
        append_seen(&mut self.queries[index], search.seen)?;
        let state = State {
            serial,
            client_slot: client.slot,
            client_serial: client.serial,
            block_type: search.block_type,
            anonymity: search.anonymity,
            target: search.target,
            query: search.query,
            local_only,
            local: if assembling {
                Local::Assembling
            } else {
                Local::Ready(0)
            },
            network: Network::None,
            complete: false,
            revision: 0,
        };
        self.query_serial = serial;
        self.queries[index].state = Some(state);
        Ok(Admission {
            query: self.id(index, state),
            assembling,
            merged: false,
        })
    }
    /// Copy routing fields for one still-retained original query.
    pub fn descriptor(&self, query: QueryId<'id>) -> Result<Descriptor<'id>, Error> {
        self.state(query).map(|state| self.description(state))
    }
    /// Borrow the full sorted exact whole-UBLOCK seen set. No Bloom false-positive
    /// profile or hidden allocation is used by this implementation.
    pub fn seen(&self, query: QueryId<'id>) -> Result<&[[u8; 64]], Error> {
        self.state(query)?;
        let slot = &self.queries[query.slot];
        Ok(&slot.seen[..slot.seen_len])
    }
    /// Iterate retained query authorities without allocating an ID list.
    pub fn query_ids(&self) -> impl Iterator<Item = QueryId<'id>> + '_ {
        self.queries
            .iter()
            .enumerate()
            .filter_map(|(slot, query)| query.state.map(|state| self.id(slot, state)))
    }
    /// Lease one next real local GET fairly. Allocate/admit native command storage
    /// before calling; the resulting original lease must settle exactly once.
    pub fn next_local(&mut self) -> Result<Option<Lookup<'id>>, Error> {
        for offset in 0..self.queries.len() {
            let index = (self.local_cursor + offset) % self.queries.len();
            let Some(mut state) = self.queries[index].state else {
                continue;
            };
            let Local::Ready(next_uid) = state.local else {
                continue;
            };
            if state.complete {
                continue;
            }
            let attempt = self.attempt_serial.checked_add(1).ok_or(Error::Overflow)?;
            let query = self.id(index, state);
            let client = self.client_id(state);
            state.local = Local::Pending { attempt, next_uid };
            self.queries[index].state = Some(state);
            self.attempt_serial = attempt;
            self.local_cursor = (index + 1) % self.queries.len();
            return Ok(Some(Lookup {
                query,
                client,
                attempt,
                key: state.query,
                kind: if state.block_type == BlockType::DBLOCK {
                    BlockType::ANY
                } else {
                    state.block_type
                },
                next_uid,
            }));
        }
        Ok(None)
    }
    /// Restore an original failed local GET's cursor after the host settled/drained
    /// that operation. This does not replay PUTs or synthesize DATA_END.
    pub fn local_failed(&mut self, lookup: Lookup<'id>) -> Result<(), Error> {
        let mut state = self.lookup_state(lookup)?;
        state.local = Local::Ready(lookup.next_uid);
        self.queries[lookup.query.slot].state = Some(state);
        Ok(())
    }
    fn finish_local(state: &mut State) {
        state.local = Local::Exhausted;
        if state.local_only {
            state.complete = true;
        } else if state.network == Network::None {
            state.network = Network::Ready;
        }
    }
    /// Commit an actual local DATA_END without emitting any FS END/negative frame.
    pub fn local_end(&mut self, lookup: Lookup<'id>) -> Result<(), Error> {
        let mut state = self.lookup_state(lookup)?;
        Self::finish_local(&mut state);
        self.queries[lookup.query.slot].state = Some(state);
        Ok(())
    }
    /// Stop this local phase after an actual dependency error while preserving
    /// peer-routing opportunity. The native diagnostic remains the host's cause.
    pub fn local_unavailable(&mut self, lookup: Lookup<'id>) -> Result<(), Error> {
        self.local_end(lookup)
    }
    /// Prepare explicit advancement for a native on-demand failure, retaining the
    /// actual candidate UID. No cursor or seen state changes until skip().
    pub fn skip_local(
        &self,
        lookup: Lookup<'id>,
        uid: u64,
        reason: SkipReason,
    ) -> Result<Advance<'id>, Error> {
        let state = self.lookup_state(lookup)?;
        if uid < lookup.next_uid {
            return Err(Error::Malformed);
        }
        Ok(Advance {
            lookup,
            revision: state.revision,
            next_uid: uid.checked_add(1),
            reason,
        })
    }
    /// Check/encode an actual local DATA without mutating query state. A type6
    /// descriptor remains pending while native indexed-file work completes.
    pub fn prepare_local(
        &self,
        lookup: Lookup<'id>,
        record: Data<'_>,
        output: &mut [u8],
        now: AbsoluteTime,
    ) -> Result<LocalResult<'id>, Error> {
        let state = self.lookup_state(lookup)?;
        if record.uid < lookup.next_uid {
            return Err(Error::Malformed);
        }
        let invalid = |reason| {
            LocalResult::Skip(Advance {
                lookup,
                revision: state.revision,
                next_uid: record.uid.checked_add(1),
                reason,
            })
        };
        if !bool::from(record.key.ct_eq(&state.query)) {
            return Ok(invalid(SkipReason::Invalid(Error::Authentication)));
        }
        if record.kind == 6 {
            if !matches!(state.block_type.value(), 0 | 1) || record.value.len() != 72 {
                return Ok(invalid(SkipReason::Invalid(Error::Malformed)));
            }
            let file_id = record.value[..64]
                .try_into()
                .map_err(|_| Error::Malformed)?;
            let offset = u64::from_be_bytes(
                record.value[64..72]
                    .try_into()
                    .map_err(|_| Error::Malformed)?,
            );
            return Ok(LocalResult::OnDemand(OnDemand { file_id, offset }));
        }
        let result = ClientPut {
            block_type: BlockType::new(record.kind),
            expiration: record.expiration,
            last_transmission: AbsoluteTime::NEVER,
            num_transmissions: 0,
            respect_offered: 0,
            block: record.value,
        };
        match self.prepare(
            state,
            lookup.query,
            Origin::Local {
                attempt: lookup.attempt,
                cursor: lookup.next_uid,
                advance: record.uid.checked_add(1),
            },
            result,
            output,
            now,
        )? {
            Preparation::Reply(reply) => Ok(LocalResult::Reply(reply)),
            Preparation::Skip(reason) => Ok(invalid(reason)),
        }
    }
    fn prepare(
        &self,
        state: State,
        query: QueryId<'id>,
        origin: Origin,
        result: ClientPut<'_>,
        output: &mut [u8],
        now: AbsoluteTime,
    ) -> Result<Preparation<'id>, Error> {
        state.revision.checked_add(1).ok_or(Error::Overflow)?;
        let kind = result.block_type;
        if !matches!(kind.value(), 1 | 2 | 9)
            || (state.block_type != BlockType::ANY && state.block_type != kind)
        {
            return Ok(Preparation::Skip(SkipReason::Invalid(
                Error::Authentication,
            )));
        }
        if result.block.len() > self.limits.max_block_bytes {
            return Ok(Preparation::Skip(SkipReason::Invalid(Error::TooLarge)));
        }
        let digest = hash512(result.block);
        if kind == BlockType::UBLOCK {
            if let Err(error) = crate::ublock::verify_envelope(result.block, &state.query) {
                return Ok(Preparation::Skip(SkipReason::Invalid(error)));
            }
            if self.limits.expire_ublocks && result.expiration <= now {
                return Ok(Preparation::Skip(SkipReason::Expired));
            }
            let slot = &self.queries[query.slot];
            if slot.seen[..slot.seen_len].binary_search(&digest).is_ok() {
                return Ok(Preparation::Skip(SkipReason::Duplicate));
            }
            if slot.seen_len == slot.seen.len() {
                return Err(Error::Capacity);
            }
        } else if !bool::from(digest.ct_eq(&state.query)) {
            return Ok(Preparation::Skip(SkipReason::Invalid(
                Error::Authentication,
            )));
        }
        let bytes = Response::Put(result).encode(output)?;
        Ok(Preparation::Reply(PreparedReply {
            query,
            client: self.client_id(state),
            revision: state.revision,
            origin,
            digest: (kind == BlockType::UBLOCK).then_some(digest),
            terminal: kind != BlockType::UBLOCK,
            bytes,
        }))
    }
    /// Commit a prepared response only after the native host retained its bytes on
    /// the original physical output queue. Returns whether that actual D/I hit is
    /// terminal. Failed/canceled queue admission must leave this preparation uncommitted.
    pub fn commit_reply(&mut self, reply: PreparedReply<'id>) -> Result<bool, Error> {
        let mut state = self.state(reply.query)?;
        self.client(reply.client)?;
        if state.complete || self.client_id(state) != reply.client {
            return Err(Error::Stale);
        }
        let original = match reply.origin {
            Origin::Local {
                attempt, cursor, ..
            } => {
                state.local
                    == Local::Pending {
                        attempt,
                        next_uid: cursor,
                    }
            }
            Origin::Peer { attempt } => state.network == Network::Active(attempt),
        };
        if !original {
            return Err(Error::Stale);
        }
        if state.revision != reply.revision {
            return Err(Error::Stale);
        }
        let revision = state.revision.checked_add(1).ok_or(Error::Overflow)?;
        if let Some(digest) = reply.digest {
            insert_seen(&mut self.queries[reply.query.slot], digest)?;
        }
        state.revision = revision;
        if reply.terminal {
            state.complete = true;
            state.local = Local::Exhausted;
            state.network = Network::Dormant;
        } else if let Origin::Local { advance, .. } = reply.origin {
            match advance {
                Some(uid) => state.local = Local::Ready(uid),
                None => Self::finish_local(&mut state),
            }
        }
        self.queries[reply.query.slot].state = Some(state);
        Ok(state.complete)
    }
    /// Commit one prepared local skip after retaining its original diagnostic.
    pub fn skip(&mut self, advance: Advance<'id>) -> Result<(), Error> {
        let mut state = self.lookup_state(advance.lookup)?;
        if state.revision != advance.revision {
            return Err(Error::Stale);
        }
        state.revision = state.revision.checked_add(1).ok_or(Error::Overflow)?;
        match advance.next_uid {
            Some(uid) => state.local = Local::Ready(uid),
            None => Self::finish_local(&mut state),
        }
        self.queries[advance.lookup.query.slot].state = Some(state);
        Ok(())
    }
    /// Lease one route only after the real local phase concluded. A port with no
    /// connected peers should park it with route_idle rather than manufacture a
    /// successful route or spin. Future topology availability can retry_route.
    pub fn next_route(&mut self) -> Result<Option<Route<'id>>, Error> {
        for offset in 0..self.queries.len() {
            let index = (self.route_cursor + offset) % self.queries.len();
            let Some(mut state) = self.queries[index].state else {
                continue;
            };
            if state.complete || state.local_only || state.network != Network::Ready {
                continue;
            }
            let attempt = self.attempt_serial.checked_add(1).ok_or(Error::Overflow)?;
            let query = self.id(index, state);
            let descriptor = self.description(state);
            state.network = Network::Active(attempt);
            self.queries[index].state = Some(state);
            self.attempt_serial = attempt;
            self.route_cursor = (index + 1) % self.queries.len();
            return Ok(Some(Route {
                query,
                descriptor,
                attempt,
            }));
        }
        Ok(None)
    }
    /// Park an original real route after no peer/dependency availability or after
    /// its actual termination. No synthetic peer result or wire frame is emitted.
    pub fn route_idle(&mut self, route: Route<'id>) -> Result<(), Error> {
        let mut state = self.route_state(route)?;
        state.network = Network::Dormant;
        self.queries[route.query.slot].state = Some(state);
        Ok(())
    }
    /// Re-arm peer routing after an explicit topology/port retry decision. The
    /// previous route token becomes stale; an active port must be canceled first.
    pub fn retry_route(&mut self, query: QueryId<'id>) -> Result<(), Error> {
        let mut state = self.state(query)?;
        if state.complete || state.local_only || state.local == Local::Assembling {
            return Err(Error::InvalidInput);
        }
        if state.network == Network::None && state.local != Local::Exhausted {
            return Err(Error::WouldBlock);
        }
        state.network = Network::Ready;
        self.queries[query.slot].state = Some(state);
        Ok(())
    }
    /// Read the still-active original route and its current whole-result seen
    /// set without changing its attempt, client, revision or routing state.
    /// Disconnected clients, completed queries and stale attempts are rejected.
    pub fn route_snapshot(
        &self,
        route: Route<'id>,
    ) -> Result<(Search<'static>, &[[u8; 64]]), Error> {
        self.route_state(route)?;
        Ok((route.search(), self.seen(route.query)?))
    }
    /// Validate/encode a candidate from the original active peer route. The
    /// explicit local composition supplies transmission counters and timestamps;
    /// this method forwards them without inferring their source or authority.
    pub fn prepare_peer(
        &self,
        route: Route<'id>,
        result: ClientPut<'_>,
        output: &mut [u8],
        now: AbsoluteTime,
    ) -> Result<PeerResult<'id>, Error> {
        let state = self.route_state(route)?;
        match self.prepare(
            state,
            route.query,
            Origin::Peer {
                attempt: route.attempt,
            },
            result,
            output,
            now,
        )? {
            Preparation::Reply(reply) => Ok(PeerResult::Reply(reply)),
            Preparation::Skip(reason) => Ok(PeerResult::Ignored(reason)),
        }
    }
    /// Start another explicit local sweep for an ongoing query without losing its
    /// whole-block seen set or original peer route. No hidden timer is created.
    pub fn rescan(&mut self, query: QueryId<'id>) -> Result<(), Error> {
        let mut state = self.state(query)?;
        if state.complete || !matches!(state.block_type.value(), 0 | 9) {
            return Err(Error::InvalidInput);
        }
        if state.local != Local::Exhausted {
            return Err(Error::WouldBlock);
        }
        state.local = Local::Ready(0);
        self.queries[query.slot].state = Some(state);
        Ok(())
    }
    /// Whether a real terminal D/I result or local-only exhaustion completed this query.
    pub fn completed(&self, query: QueryId<'id>) -> Result<bool, Error> {
        self.state(query).map(|state| state.complete)
    }
    /// Release completed query storage after retaining any terminal output bytes.
    /// Active query cancellation is only via actual physical client disconnect.
    pub fn release(&mut self, query: QueryId<'id>) -> Result<(), Error> {
        if !self.state(query)?.complete {
            return Err(Error::WouldBlock);
        }
        let slot = &mut self.queries[query.slot];
        slot.state = None;
        slot.seen_len = 0;
        Ok(())
    }
}
enum Preparation<'id> {
    Reply(PreparedReply<'id>),
    Skip(SkipReason),
}
fn reserve_seen(slot: &QuerySlot<'_>, input: &[u8]) -> Result<(), Error> {
    let mut additions = 0_usize;
    for (index, hash) in input.as_chunks::<64>().0.iter().enumerate() {
        if slot.seen[..slot.seen_len].binary_search(hash).is_err()
            && !input[..index * 64]
                .as_chunks::<64>()
                .0
                .iter()
                .any(|previous| previous == hash)
        {
            additions = additions.checked_add(1).ok_or(Error::Overflow)?;
        }
    }
    if slot
        .seen_len
        .checked_add(additions)
        .is_none_or(|count| count > slot.seen.len())
    {
        return Err(Error::Capacity);
    }
    Ok(())
}
fn append_seen(slot: &mut QuerySlot<'_>, input: &[u8]) -> Result<(), Error> {
    for hash in input.as_chunks::<64>().0 {
        insert_seen(slot, *hash)?;
    }
    Ok(())
}
fn insert_seen(slot: &mut QuerySlot<'_>, digest: [u8; 64]) -> Result<(), Error> {
    match slot.seen[..slot.seen_len].binary_search(&digest) {
        Ok(_) => Ok(()),
        Err(index) => {
            if slot.seen_len == slot.seen.len() {
                return Err(Error::Capacity);
            }
            slot.seen.copy_within(index..slot.seen_len, index + 1);
            slot.seen[index] = digest;
            slot.seen_len += 1;
            Ok(())
        }
    }
}
