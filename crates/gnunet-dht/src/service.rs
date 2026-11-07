//! Real volatile DHT local IPC state. Native IO and network routes are separate.
/// Bounded R5N GET/PUT/RESULT owner over original peer capabilities.
pub mod network;
use alloc::vec::Vec;
use core::{fmt, ptr};
use gnunet_block::{
    BlockType, ReplyEvaluation, ReturnValue,
    plugins::{Context, Work},
};
use gnunet_crypto::hash512;
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    dht::{
        Path,
        ipc::{self, Request, RequestId},
    },
};

/// Caller-owned nonzero-sized lifetime brand; one live owner borrows it exclusively.
///
/// ```compile_fail
/// use gnunet_dht::service::{Instance,Limits,LocalOwner};
/// let mut instance=Instance::new();
/// let first=LocalOwner::new(&mut instance,Limits::default()).unwrap();
/// let second=LocalOwner::new(&mut instance,Limits::default()).unwrap();
/// drop(first);
/// drop(second);
/// ```
pub struct Instance {
    _nonzero_size: u8,
}
impl Instance {
    /// Create storage before constructing an owner; no hidden allocator/global ID.
    #[must_use]
    pub const fn new() -> Self {
        Self { _nonzero_size: 0 }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Clone, Copy)]
struct Brand<'id>(&'id Instance);
impl PartialEq for Brand<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.0, other.0)
    }
}
impl Eq for Brand<'_> {}
impl fmt::Debug for Brand<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OriginalInstance")
    }
}
/// Original physical local MQ identity. Numeric diagnostics cannot construct one.
///
/// ```compile_fail
/// use gnunet_dht::service::ClientId;
/// let fabricated=ClientId { serial:1 };
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientId<'id> {
    brand: Brand<'id>,
    serial: u64,
}
impl ClientId<'_> {
    /// Diagnostic counter, without authority to reconstruct a client.
    #[must_use]
    pub const fn diagnostic(self) -> u64 {
        self.serial
    }
}
/// Original local GET, distinct from its opaque wire ID and all network keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryId<'id> {
    brand: Brand<'id>,
    serial: u64,
}
/// Explicit bounded local resources. Wire framing limits remain independent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Concurrent physical clients.
    pub clients: usize,
    /// Active original GETs.
    pub queries: usize,
    /// Original monitor registrations.
    pub monitors: usize,
    /// Stored volatile blocks, including different values under one key.
    pub cache_records: usize,
    /// Total retained volatile payload bytes.
    pub cache_bytes: usize,
    /// Per-block payload bound, also the actual allocation-capacity ceiling
    /// for the one separate validated own-HELLO payload.
    pub block_bytes: usize,
    /// Known payload hashes per original GET.
    pub seen_hashes: usize,
    /// Queued complete local frames.
    pub output_frames: usize,
    /// Queued complete local frame bytes.
    pub output_bytes: usize,
    /// Nearest distinct keys considered for approximate cache lookup; must be nonzero.
    pub approximate_keys: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 64,
            queries: 64,
            monitors: 64,
            cache_records: 64,
            cache_bytes: 1024 * 1024,
            block_bytes: 65535,
            seen_hashes: 128,
            output_frames: 128,
            output_bytes: 1024 * 1024,
            approximate_keys: 4,
        }
    }
}
/// Data classification, separate from a fallible validation resource/port error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Validity {
    /// Concrete block and key association validated.
    Valid,
    /// Concrete data is invalid or no longer valid at the operation time.
    Invalid,
    /// No installed concrete operation can validate the block.
    Unsupported,
}
/// Independent fact about the actual selected BLOCK registry, not validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TypeCapability {
    /// A selected concrete handler exists; every operation failure remains a failure.
    Installed,
    /// No selected handler owns the concrete type. Opaque transport and original
    /// query correlation do not assert payload validity or trusted cache admission.
    Absent,
}
/// Trusted configured Rust BLOCK operations. No default accept-all implementation.
/// Resource failures retain their cause and never become an invalid-block success.
pub trait Blocks {
    /// Inspect the actual registry independently of query/block execution. An
    /// unavailable provider must return its error, never default to `Absent`.
    /// ANY is a query wildcard and must not be passed as a concrete type here.
    fn type_capability(&self, kind: u32) -> Result<TypeCapability, Error>;
    /// Validate original query semantics; ANY handling remains explicit.
    fn query(&mut self, kind: u32, key: &[u8; 64], xquery: &[u8]) -> Result<(), Error>;
    /// Validate complete block and any derived key association at this time.
    fn validate(
        &mut self,
        kind: u32,
        key: &[u8; 64],
        payload: &[u8],
        now: u64,
    ) -> Result<Validity, Error>;
    /// Evaluate an already validated candidate against the original query.
    /// For ANY, an installed candidate's explicit query rejection is only
    /// Irrelevant to that candidate; operation/provider errors remain errors.
    fn reply(
        &mut self,
        requested: u32,
        key: &[u8; 64],
        xquery: &[u8],
        kind: u32,
        payload: &[u8],
        now: u64,
    ) -> Result<ReplyEvaluation, Error>;
}
/// Adapter to the existing real BLOCK plugins with caller-owned work memory.
pub struct BuiltinBlocks<'a, 'w> {
    /// Immutable configured registry, not a filesystem plugin loader.
    pub context: Context<'a>,
    /// Exact HELLO/PoW scratch and compilation profile.
    pub work: Work<'w>,
}
impl BuiltinBlocks<'_, '_> {
    // ANY itself has no concrete query validation. Check applicability only
    // for this installed concrete candidate, before invoking its reply codec.
    // NO is precise query rejection; never catch generic reply/crypto errors.
    fn candidate_query_applies(
        &self,
        requested: u32,
        key: &[u8; 64],
        xquery: &[u8],
        kind: u32,
    ) -> Result<bool, Error> {
        if requested != 0 {
            return Ok(true);
        }
        match self.context.check_query(BlockType(kind), key, xquery) {
            ReturnValue::Yes => Ok(true),
            ReturnValue::No => Ok(false),
            ReturnValue::SysErr => Err(Error::Unsupported),
        }
    }
}
impl Blocks for BuiltinBlocks<'_, '_> {
    fn type_capability(&self, kind: u32) -> Result<TypeCapability, Error> {
        if kind == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(if self.context.has_type(BlockType(kind)) {
            TypeCapability::Installed
        } else {
            TypeCapability::Absent
        })
    }
    fn query(&mut self, kind: u32, key: &[u8; 64], xquery: &[u8]) -> Result<(), Error> {
        if kind == 0 {
            return if xquery.is_empty() {
                Ok(())
            } else {
                Err(Error::Unsupported)
            };
        }
        match self.context.check_query(BlockType(kind), key, xquery) {
            ReturnValue::Yes => Ok(()),
            ReturnValue::No => Err(Error::InvalidInput),
            ReturnValue::SysErr => Err(Error::Unsupported),
        }
    }
    fn validate(
        &mut self,
        kind: u32,
        key: &[u8; 64],
        payload: &[u8],
        now: u64,
    ) -> Result<Validity, Error> {
        let mut clock = || now;
        match self
            .context
            .check_block(BlockType(kind), payload, &mut self.work, &mut clock)?
        {
            ReturnValue::Yes => {}
            ReturnValue::No => return Ok(Validity::Invalid),
            ReturnValue::SysErr => return Ok(Validity::Unsupported),
        }
        let derived = self
            .context
            .get_key(BlockType(kind), payload, &mut self.work, &mut clock)?;
        Ok(match (derived.status, derived.key) {
            (ReturnValue::No, _) => Validity::Valid,
            (ReturnValue::Yes, Some(actual)) if actual == *key => Validity::Valid,
            (ReturnValue::Yes, Some(_)) => Validity::Invalid,
            _ => Validity::Unsupported,
        })
    }
    fn reply(
        &mut self,
        requested: u32,
        key: &[u8; 64],
        xquery: &[u8],
        kind: u32,
        payload: &[u8],
        now: u64,
    ) -> Result<ReplyEvaluation, Error> {
        if !self.candidate_query_applies(requested, key, xquery, kind)? {
            return Ok(ReplyEvaluation::Irrelevant);
        }
        let mut clock = || now;
        let result = self.context.check_reply(
            BlockType(kind),
            None,
            key,
            Some(xquery),
            payload,
            &mut self.work,
            &mut clock,
        )?;
        Ok(if requested == 0 && result == ReplyEvaluation::Last {
            ReplyEvaluation::More
        } else {
            result
        })
    }
}
struct Query<'id> {
    token: QueryId<'id>,
    client: ClientId<'id>,
    key: [u8; 64],
    id: RequestId,
    kind: u32,
    options: u32,
    replication: u32,
    xquery: Vec<u8>,
    seen: Vec<[u8; 64]>,
}
// Borrowed reply metadata, without a validated/cache-entry capability. Unknown
// results can use the original IPC correlation without manufacturing an Entry.
struct Reply<'a> {
    key: &'a [u8; 64],
    kind: u32,
    options: u32,
    expiration: u64,
    payload: &'a [u8],
    put: Path<'a>,
    get: Path<'a>,
    truncated: Option<&'a [u8; 32]>,
}
struct Entry {
    key: [u8; 64],
    kind: u32,
    options: u32,
    expiration: u64,
    payload: Vec<u8>,
    hash: [u8; 64],
    put_path: Vec<u8>,
    truncated_peer: Option<[u8; 32]>,
}
#[derive(Clone, Copy, Eq, PartialEq)]
struct Monitor<'id> {
    client: ClientId<'id>,
    kind: u32,
    get: u16,
    result: u16,
    put: u16,
    key: Option<[u8; 64]>,
}
/// An original complete frame, moved to its original physical MQ only.
/// Taking it is not a write/delivery acknowledgement. The host must preserve
/// its immutable allocation/partial cursor or retire that original MQ.
pub struct Output<'id> {
    client: ClientId<'id>,
    query: Option<QueryId<'id>>,
    correlation: Option<([u8; 64], RequestId)>,
    bytes: Vec<u8>,
}
impl fmt::Debug for Output<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
            .field("client", &self.client)
            .field("query", &self.query)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}
impl<'id> Output<'id> {
    /// Original physical destination; never map its diagnostic number to a new MQ.
    #[must_use]
    pub const fn client(&self) -> ClientId<'id> {
        self.client
    }
    /// Original local operation when this is a result, not a monitor notification.
    #[must_use]
    pub const fn query(&self) -> Option<QueryId<'id>> {
        self.query
    }
    /// Complete original official bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Transfer the same allocation to the original native framing owner.
    #[must_use]
    pub fn into_parts(self) -> (ClientId<'id>, Option<QueryId<'id>>, Vec<u8>) {
        (self.client, self.query, self.bytes)
    }
}
/// Local transition only. None of these values asserts network replication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome<'id> {
    /// Block really entered or updated the volatile cache.
    Cached,
    /// A concrete type has no installed local BLOCK handler. This original
    /// PUT may be forwarded by the containing network owner, but acquired no
    /// validated cache entry, local query result or replication acknowledgement.
    OpaquePut,
    /// Original block was already expired, so no data was stored.
    Expired,
    /// Original GET admitted; BLOCK Last may already have completed it.
    /// Network routing remains a separate capability.
    Get(QueryId<'id>),
    /// The same original request was already active, without duplicate admission.
    Duplicate(QueryId<'id>),
    /// Matching original local operations were stopped (possibly zero).
    Stopped(usize),
    /// Original known-result filter was updated.
    Known,
    /// An original monitor registration was installed.
    MonitorStarted,
    /// One matching monitor registration was removed, if any.
    MonitorStopped(bool),
    /// Actual current absence of a self HELLO was queued as header-only159.
    HelloAbsent,
}
/// Bounded memory state; counts are diagnostics rather than capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// Active physical MQs.
    pub clients: usize,
    /// Active original GETs, including those awaiting network work.
    pub queries: usize,
    /// Monitor registrations.
    pub monitors: usize,
    /// Actual volatile blocks.
    pub cache_records: usize,
    /// Actual volatile payload bytes.
    pub cache_bytes: usize,
    /// Actual dedicated own-HELLO payload Vec capacity, separate from cache.
    pub own_hello_bytes: usize,
    /// Queued complete local frames.
    pub output_frames: usize,
    /// Their complete frame-byte charge.
    pub output_bytes: usize,
    /// Closed owners refuse all new operations.
    pub closed: bool,
}
/// Bounded local IPC/cache owner. It does not pretend to be a complete R5N host.
/// No external store completion or network packet can be injected through an
/// unchecked successful callback; those original ports are separate next work.
pub struct LocalOwner<'id> {
    brand: Brand<'id>,
    limits: Limits,
    serial: u64,
    clients: Vec<ClientId<'id>>,
    queries: Vec<Query<'id>>,
    monitors: Vec<Monitor<'id>>,
    cache: Vec<Entry>,
    cache_bytes: usize,
    // Only NetworkOwner can install an actual validated local-peer HELLO.
    // It cannot consume ordinary cache records or their payload quota.
    own_hello: Option<Entry>,
    output: Vec<Output<'id>>,
    output_bytes: usize,
    closed: bool,
}
impl<'id> LocalOwner<'id> {
    /// Reserve bounded metadata before publishing any client/operation token.
    pub fn new(instance: &'id mut Instance, limits: Limits) -> Result<Self, Error> {
        if limits.approximate_keys == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            brand: Brand(instance),
            limits,
            serial: 0,
            clients: reserved(limits.clients)?,
            queries: reserved(limits.queries)?,
            monitors: reserved(limits.monitors)?,
            cache: reserved(limits.cache_records)?,
            cache_bytes: 0,
            own_hello: None,
            output: reserved(limits.output_frames)?,
            output_bytes: 0,
            closed: false,
        })
    }
    /// Register one new physical MQ. Reconnect is always a fresh token.
    pub fn connect(&mut self) -> Result<ClientId<'id>, Error> {
        self.open()?;
        if self.clients.len() == self.limits.clients {
            return Err(Error::Capacity);
        }
        let next = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let id = ClientId {
            brand: self.brand,
            serial: next,
        };
        self.clients.push(id);
        self.serial = next;
        Ok(id)
    }
    /// Retire only this MQ's queries, monitors and not-yet-transferred frames.
    /// Published cache blocks survive their original publisher's disconnect.
    pub fn disconnect(&mut self, client: ClientId<'id>) -> Result<(), Error> {
        self.client(client)?;
        self.clients.retain(|c| *c != client);
        self.queries.retain(|q| q.client != client);
        self.monitors.retain(|m| m.client != client);
        self.output.retain(|f| f.client != client);
        self.recount_output();
        Ok(())
    }
    /// Interpret one complete original frame only after checking its physical MQ.
    pub fn ingest(
        &mut self,
        client: ClientId<'id>,
        input: &[u8],
        now: u64,
        blocks: &mut impl Blocks,
    ) -> Result<Outcome<'id>, Error> {
        self.client(client)?;
        match Request::decode(input)? {
            Request::Put(p) => self.put(client, p, now, blocks),
            Request::Get(g) => self.get(client, g, now, blocks),
            Request::Stop(s) => {
                let before = self.queries.len();
                self.queries
                    .retain(|q| !(q.client == client && q.key == *s.key && q.id == s.id));
                self.output
                    .retain(|f| !(f.client == client && f.correlation == Some((*s.key, s.id))));
                self.recount_output();
                Ok(Outcome::Stopped(before - self.queries.len()))
            }
            Request::Known(k) => {
                let q = self
                    .queries
                    .iter_mut()
                    .find(|q| q.client == client && q.key == *k.key && q.id == k.id)
                    .ok_or(Error::NotFound)?;
                let extra = k
                    .hashes
                    .iter()
                    .enumerate()
                    .filter(|(i, h)| {
                        !q.seen.contains(h)
                            && !k.hashes.iter().take(*i).any(|previous| previous == *h)
                    })
                    .count();
                if q.seen.len().checked_add(extra).ok_or(Error::Overflow)? > self.limits.seen_hashes
                {
                    return Err(Error::Capacity);
                }
                q.seen.try_reserve(extra).map_err(|_| Error::Capacity)?;
                for h in k.hashes.iter() {
                    if !q.seen.contains(h) {
                        q.seen.push(*h);
                    }
                }
                Ok(Outcome::Known)
            }
            Request::MonitorStart(m) => {
                if self.monitors.len() == self.limits.monitors {
                    return Err(Error::Capacity);
                }
                self.monitors.push(Monitor {
                    client,
                    kind: m.block_type,
                    get: m.get,
                    result: m.get_response,
                    put: m.put,
                    key: m.key.copied(),
                });
                Ok(Outcome::MonitorStarted)
            }
            Request::MonitorStop(m) => {
                let wanted = Monitor {
                    client,
                    kind: m.block_type,
                    get: m.get,
                    result: m.get_response,
                    put: m.put,
                    key: m.key.copied(),
                };
                let found = self.monitors.iter().position(|r| *r == wanted);
                if let Some(i) = found {
                    self.monitors.remove(i);
                }
                Ok(Outcome::MonitorStopped(found.is_some()))
            }
            Request::HelloGet => {
                let mut stage = Vec::new();
                let mut frame = self.frame(&mut stage, 4)?;
                ipc::encode_hello(None, false, &mut frame)?;
                self.stage(
                    &mut stage,
                    Output {
                        client,
                        query: None,
                        correlation: None,
                        bytes: frame,
                    },
                )?;
                self.commit(stage);
                Ok(Outcome::HelloAbsent)
            }
            Request::HelloUrl(_) => Err(Error::Unsupported),
        }
    }
    /// Remove expired volatile entries. Equality remains valid as in reference time.
    /// Logical time may move backwards; removed expired entries are not resurrected.
    pub fn tick(&mut self, now: u64) -> Result<(), Error> {
        self.open()?;
        self.cache.retain(|e| e.expiration >= now);
        self.cache_bytes = self.cache.iter().map(|e| e.payload.len()).sum();
        if self.own_hello.as_ref().is_some_and(|e| e.expiration < now) {
            self.own_hello = None;
        }
        Ok(())
    }
    /// Transfer one complete frame without claiming a native write or client receipt.
    pub fn take_output(&mut self) -> Option<Output<'id>> {
        if self.output.is_empty() {
            None
        } else {
            let f = self.output.remove(0);
            self.output_bytes -= f.bytes.len();
            Some(f)
        }
    }
    /// Read bounded diagnostic counts.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            clients: self.clients.len(),
            queries: self.queries.len(),
            monitors: self.monitors.len(),
            cache_records: self.cache.len(),
            cache_bytes: self.cache_bytes,
            own_hello_bytes: self.own_hello.as_ref().map_or(0, |e| e.payload.capacity()),
            output_frames: self.output.len(),
            output_bytes: self.output_bytes,
            closed: self.closed,
        }
    }
    /// Release only owned memory. This is not native socket/backend quiescence.
    pub fn close(&mut self) {
        self.closed = true;
        self.clients.clear();
        self.queries.clear();
        self.monitors.clear();
        self.cache.clear();
        self.own_hello = None;
        self.output.clear();
        self.cache_bytes = 0;
        self.output_bytes = 0;
    }
    fn open(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn client(&self, c: ClientId<'id>) -> Result<(), Error> {
        self.open()?;
        if c.brand != self.brand {
            return Err(Error::InvalidInput);
        }
        if !self.clients.contains(&c) {
            return Err(Error::Stale);
        }
        Ok(())
    }
    fn recount_output(&mut self) {
        self.output_bytes = self.output.iter().map(|f| f.bytes.len()).sum();
    }
    fn frame(&self, stage: &mut Vec<Output<'id>>, n: usize) -> Result<Vec<u8>, Error> {
        self.output_budget(stage, n)?;
        stage.try_reserve(1).map_err(|_| Error::Capacity)?;
        bytes(n)
    }
    fn output_budget(&self, stage: &[Output<'id>], n: usize) -> Result<(), Error> {
        let count = self
            .output
            .len()
            .checked_add(stage.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?;
        let used = stage
            .iter()
            .try_fold(self.output_bytes, |sum, f| {
                sum.checked_add(f.bytes.len()).ok_or(Error::Overflow)
            })?
            .checked_add(n)
            .ok_or(Error::Overflow)?;
        if count > self.limits.output_frames || used > self.limits.output_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    fn stage(&self, stage: &mut Vec<Output<'id>>, f: Output<'id>) -> Result<(), Error> {
        self.output_budget(stage, f.bytes.len())?;
        stage.try_reserve(1).map_err(|_| Error::Capacity)?;
        stage.push(f);
        Ok(())
    }
    fn commit(&mut self, stage: Vec<Output<'id>>) {
        for f in stage {
            self.output_bytes += f.bytes.len();
            self.output.push(f);
        }
    }
    fn put(
        &mut self,
        _client: ClientId<'id>,
        p: ipc::Put<'_>,
        now: u64,
        blocks: &mut impl Blocks,
    ) -> Result<Outcome<'id>, Error> {
        // ANY denotes a query wildcard, never a concrete PUT block.
        if p.block_type == 0 {
            return Err(Error::InvalidInput);
        }
        // Local PUT has no predecessor/path field. Its metadata cannot create
        // an asserted truncated boundary or a synthetic all-zero identity.
        if p.options & 8 != 0 {
            return Err(Error::Unsupported);
        }
        if p.expiration.as_micros() < now {
            return Ok(Outcome::Expired);
        }
        if p.payload.len() > self.limits.block_bytes {
            return Err(Error::Capacity);
        }
        if blocks.type_capability(p.block_type)? == TypeCapability::Absent {
            // Absence is routing permission, not a validation result. Preserve
            // the actual local PUT monitor observation without constructing a
            // trusted Entry, feeding a local query, or touching cache state.
            let mut stage = Vec::new();
            self.monitor_put_message(
                ipc::MonitorPut {
                    options: p.options,
                    block_type: p.block_type,
                    hop_count: 0,
                    replication: p.replication,
                    expiration: p.expiration,
                    key: p.key,
                    truncated_peer: None,
                    put_path: Path::empty(),
                    payload: p.payload,
                },
                &mut stage,
            )?;
            self.commit(stage);
            return Ok(Outcome::OpaquePut);
        }
        match blocks.validate(p.block_type, p.key, p.payload, now)? {
            Validity::Valid => {}
            Validity::Invalid => return Err(Error::Authentication),
            Validity::Unsupported => return Err(Error::Unsupported),
        }
        let existing = self
            .cache
            .iter()
            .position(|e| e.key == *p.key && e.kind == p.block_type && e.payload == p.payload);
        if existing.is_none()
            && (self.cache.len() == self.limits.cache_records
                || self
                    .cache_bytes
                    .checked_add(p.payload.len())
                    .ok_or(Error::Overflow)?
                    > self.limits.cache_bytes)
        {
            return Err(Error::Capacity);
        }
        let entry = Entry {
            key: *p.key,
            kind: p.block_type,
            options: p.options,
            expiration: p.expiration.as_micros(),
            payload: copy(p.payload)?,
            hash: hash512(p.payload),
            put_path: Vec::new(),
            truncated_peer: None,
        };
        let mut stage = Vec::new();
        let mut updates = Vec::new();
        for (i, q) in self.queries.iter().enumerate() {
            if let Some(last) = self.deliver(q, &entry, now, blocks, &mut stage)? {
                updates.try_reserve(1).map_err(|_| Error::Capacity)?;
                updates.push((i, last));
            }
        }
        self.monitor_put(&entry, p.replication, &mut stage)?;

        for (i, last) in &updates {
            let q = &mut self.queries[*i];
            if !last {
                if q.seen.len() == self.limits.seen_hashes {
                    return Err(Error::Capacity);
                }
                q.seen.try_reserve(1).map_err(|_| Error::Capacity)?;
            }
        }
        if let Some(i) = existing {
            if entry.expiration > self.cache[i].expiration {
                // A local replacement has no inherited signed path. Keeping
                // an older network path would bind the wrong expiration.
                self.cache[i] = entry;
            }
        } else {
            self.cache_bytes += entry.payload.len();
            self.cache.push(entry);
        }
        for (i, last) in updates.into_iter().rev() {
            if last {
                self.queries.remove(i);
            } else {
                self.queries[i].seen.push(hash512(p.payload));
            }
        }
        self.commit(stage);
        Ok(Outcome::Cached)
    }
    fn get(
        &mut self,
        client: ClientId<'id>,
        g: ipc::Get<'_>,
        now: u64,
        blocks: &mut impl Blocks,
    ) -> Result<Outcome<'id>, Error> {
        if let Some(q) = self
            .queries
            .iter()
            .find(|q| q.client == client && q.key == *g.key && q.id == g.id)
        {
            return if q.kind == g.block_type
                && q.options == g.options
                && q.replication == g.replication
                && q.xquery == g.extended_query
            {
                Ok(Outcome::Duplicate(q.token))
            } else {
                Err(Error::Conflict)
            };
        }
        if self.queries.len() == self.limits.queries {
            return Err(Error::Capacity);
        }
        // ANY has no concrete query codec. An absent type retains its exact
        // opaque XQUERY; installed query errors are never an absence bypass.
        let installed =
            g.block_type != 0 && blocks.type_capability(g.block_type)? == TypeCapability::Installed;
        if installed {
            blocks.query(g.block_type, g.key, g.extended_query)?;
        }
        let next = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let token = QueryId {
            brand: self.brand,
            serial: next,
        };
        let mut q = Query {
            token,
            client,
            key: *g.key,
            id: g.id,
            kind: g.block_type,
            options: g.options,
            replication: g.replication,
            xquery: copy(g.extended_query)?,
            seen: Vec::new(),
        };
        let mut stage = Vec::new();
        let mut complete = false;
        let selected = if installed || g.block_type == 0 {
            self.cache_selection(&q, now)?
        } else {
            Vec::new()
        };
        // Retain local GET access to the actual self announcement without
        // placing another copy in the ordinary volatile cache. The existing
        // deliver gate keeps exact/approximate IPC query-key semantics.
        let own_hello =
            (installed || q.kind == 0) && matches!(q.kind, 0 | 13) && self.own_hello.is_some();
        for candidate in 0..selected.len() + usize::from(own_hello) {
            let e = if own_hello && candidate == 0 {
                self.own_hello.as_ref().ok_or(Error::Stale)?
            } else {
                &self.cache[selected[candidate - usize::from(own_hello)]]
            };
            match blocks.validate(e.kind, &e.key, &e.payload, now)? {
                Validity::Valid => {}
                Validity::Invalid | Validity::Unsupported => continue,
            }
            if let Some(last) = self.deliver(&q, e, now, blocks, &mut stage)? {
                if last {
                    complete = true;
                    break;
                }
                if q.seen.len() == self.limits.seen_hashes {
                    return Err(Error::Capacity);
                }
                q.seen.try_reserve(1).map_err(|_| Error::Capacity)?;
                q.seen.push(e.hash);
            }
        }
        self.monitor_get(&q, &mut stage)?;
        self.serial = next;
        if !complete {
            self.queries.push(q);
        }
        self.commit(stage);
        Ok(Outcome::Get(token))
    }
    fn cache_selection(&self, q: &Query<'id>, now: u64) -> Result<Vec<usize>, Error> {
        self.cache_selection_for(&q.key, q.kind, q.options, now)
    }
    fn cache_selection_for(
        &self,
        target: &[u8; 64],
        kind: u32,
        options: u32,
        now: u64,
    ) -> Result<Vec<usize>, Error> {
        let mut order = Vec::new();
        for (i, e) in self.cache.iter().enumerate() {
            if e.expiration >= now
                && (kind == 0 || kind == e.kind)
                && (options & 4 != 0 || e.key == *target)
            {
                order.try_reserve(1).map_err(|_| Error::Capacity)?;
                order.push(i);
            }
        }
        order.sort_unstable_by(|a, b| {
            distance(&self.cache[*a].key, target).cmp(&distance(&self.cache[*b].key, target))
        });
        let mut keys = Vec::new();
        let mut keep = Vec::new();
        for i in order {
            let key = self.cache[i].key;
            if !keys.contains(&key) {
                if keys.len() == self.limits.approximate_keys {
                    break;
                }
                keys.try_reserve(1).map_err(|_| Error::Capacity)?;
                keys.push(key);
            }
            keep.try_reserve(1).map_err(|_| Error::Capacity)?;
            keep.push(i);
        }
        Ok(keep)
    }
    fn deliver(
        &self,
        q: &Query<'id>,
        e: &Entry,
        now: u64,
        blocks: &mut impl Blocks,
        stage: &mut Vec<Output<'id>>,
    ) -> Result<Option<bool>, Error> {
        self.deliver_paths(q, e, Path::empty(), now, blocks, stage)
    }
    fn deliver_paths(
        &self,
        q: &Query<'id>,
        e: &Entry,
        get_path: Path<'_>,
        now: u64,
        blocks: &mut impl Blocks,
        stage: &mut Vec<Output<'id>>,
    ) -> Result<Option<bool>, Error> {
        if e.expiration < now
            || (q.kind != 0 && q.kind != e.kind)
            || (q.options & 4 == 0 && q.key != e.key)
            || q.seen.contains(&e.hash)
        {
            return Ok(None);
        }
        let last = match blocks.reply(q.kind, &e.key, &q.xquery, e.kind, &e.payload, now)? {
            ReplyEvaluation::More => false,
            // One concrete type cannot complete an ANY subscription.
            ReplyEvaluation::Last => q.kind != 0,
            ReplyEvaluation::Duplicate | ReplyEvaluation::Irrelevant => return Ok(None),
            ReplyEvaluation::Unsupported => return Err(Error::Unsupported),
        };
        self.stage_reply(
            q,
            &Reply {
                key: &e.key,
                kind: e.kind,
                options: e.options,
                expiration: e.expiration,
                payload: &e.payload,
                put: Path::new(&e.put_path)?,
                get: get_path,
                truncated: e.truncated_peer.as_ref(),
            },
            stage,
        )?;
        Ok(Some(last))
    }
    fn stage_reply(
        &self,
        q: &Query<'id>,
        reply: &Reply<'_>,
        stage: &mut Vec<Output<'id>>,
    ) -> Result<(), Error> {
        // The original opaque UID (including all-zero bytes) is correlation,
        // never a completion sentinel or an assertion of BLOCK validation.
        let tracked = q.options & 2 != 0;
        let m = ipc::ResultMessage {
            block_type: reply.kind,
            options: if tracked {
                reply.options
            } else {
                reply.options & !8
            },
            put_path: if tracked { reply.put } else { Path::empty() },
            get_path: if tracked { reply.get } else { Path::empty() },
            id: q.id,
            expiration: AbsoluteTime::from_micros(reply.expiration),
            key: &q.key,
            truncated_peer: if tracked { reply.truncated } else { None },
            payload: reply.payload,
        };
        let mut frame = self.frame(stage, m.encoded_len()?)?;
        m.encode(&mut frame)?;
        self.stage(
            stage,
            Output {
                client: q.client,
                query: Some(q.token),
                correlation: Some((q.key, q.id)),
                bytes: frame,
            },
        )
    }
    fn matches(&self, m: &Monitor<'id>, event: u8, kind: u32, key: &[u8; 64]) -> bool {
        (m.kind == 0 || m.kind == kind)
            && m.key.is_none_or(|k| k == *key)
            && match event {
                0 => m.get != 0,
                1 => m.result != 0,
                _ => m.put != 0,
            }
    }
    fn monitor_targets(
        &self,
        event: u8,
        kind: u32,
        key: &[u8; 64],
    ) -> impl Iterator<Item = ClientId<'id>> + '_ {
        let key = *key;
        self.monitors.iter().enumerate().filter_map(move |(i, m)| {
            if self.matches(m, event, kind, &key)
                && !self.monitors[..i]
                    .iter()
                    .any(|old| old.client == m.client && self.matches(old, event, kind, &key))
            {
                Some(m.client)
            } else {
                None
            }
        })
    }
    fn monitor_get(&self, q: &Query<'id>, stage: &mut Vec<Output<'id>>) -> Result<(), Error> {
        for client in self.monitor_targets(0, q.kind, &q.key) {
            let m = ipc::MonitorGet {
                options: q.options,
                block_type: q.kind,
                hop_count: 0,
                replication: q.replication,
                key: &q.key,
            };
            let mut frame = self.frame(stage, 88)?;
            m.encode(&mut frame)?;
            self.stage(
                stage,
                Output {
                    client,
                    query: None,
                    correlation: None,
                    bytes: frame,
                },
            )?;
        }
        Ok(())
    }
    fn monitor_put(
        &self,
        e: &Entry,
        replication: u32,
        stage: &mut Vec<Output<'id>>,
    ) -> Result<(), Error> {
        self.monitor_put_message(
            ipc::MonitorPut {
                options: e.options,
                block_type: e.kind,
                hop_count: 0,
                replication,
                expiration: AbsoluteTime::from_micros(e.expiration),
                key: &e.key,
                truncated_peer: None,
                put_path: Path::empty(),
                payload: &e.payload,
            },
            stage,
        )
    }
    fn monitor_put_message(
        &self,
        m: ipc::MonitorPut<'_>,
        stage: &mut Vec<Output<'id>>,
    ) -> Result<(), Error> {
        for client in self.monitor_targets(2, m.block_type, m.key) {
            let mut frame = self.frame(stage, m.encoded_len()?)?;
            m.encode(&mut frame)?;
            self.stage(
                stage,
                Output {
                    client,
                    query: None,
                    correlation: None,
                    bytes: frame,
                },
            )?;
        }
        Ok(())
    }
}
fn reserved<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    Ok(v)
}
fn bytes(n: usize) -> Result<Vec<u8>, Error> {
    let mut v = reserved(n)?;
    v.resize(n, 0);
    Ok(v)
}
fn copy(value: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = reserved(value.len())?;
    v.extend_from_slice(value);
    Ok(v)
}
fn distance(a: &[u8; 64], b: &[u8; 64]) -> [u8; 64] {
    let mut v = [0; 64];
    for (i, x) in v.iter_mut().enumerate() {
        *x = a[i] ^ b[i];
    }
    v
}
