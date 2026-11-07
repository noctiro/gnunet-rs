//! Bounded original-source R5N business owner. The native underlay must admit
//! authenticated peer sources and retain complete frames before `admitted`.
//! This module creates no listener, session, key, worker, scheduler or ACK.
use super::{ClientId, Entry, LocalOwner, Output, Validity};
use crate::routing::{self, Candidate, PeerBloom};
use alloc::{borrow::Cow, collections::VecDeque, vec::Vec};
use gnunet_block::ReplyEvaluation;
use gnunet_crypto::{EddsaPublicKey, EddsaSignature, Entropy, hash512};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime, Frame,
    dht::{self, GetMessage, Path, PutMessage, ResultMessage, RouteOptions, ipc},
    message_type as mt,
};
mod types;
pub use types::*;
use types::{PeerRow, PutBlocked, Retry, Route, UnroutedPut};
mod filter;
pub use super::TypeCapability;
pub use filter::{Filter, NetworkBlocks};
mod frames;
use frames::{Block, MonitorFanout, Pending};

// Carry both selected path segments and the exact boundary as one unit.
// Only the segment extended by the actual sender is allocated; the other
// segment keeps borrowing the immutable original message bytes.
struct IncomingPath<'a> {
    options: RouteOptions,
    truncated: Option<[u8; 32]>,
    put: Cow<'a, [u8]>,
    get: Cow<'a, [u8]>,
}
impl IncomingPath<'_> {
    fn put(&self) -> Result<Path<'_>, Error> {
        Path::new(self.put.as_ref())
    }
    fn get(&self) -> Result<Path<'_>, Error> {
        Path::new(self.get.as_ref())
    }
}
fn own_path(path: Cow<'_, [u8]>) -> Result<Vec<u8>, Error> {
    match path {
        Cow::Owned(path) => Ok(path),
        Cow::Borrowed(path) => copy(path),
    }
}

/// Same original local owner plus bounded peers, retries and reverse routes.
/// Native queue/physical debts remain with the original native owner after a
/// complete handoff. An empty queue here does not certify native quiescence.
pub struct NetworkOwner<'id> {
    local: LocalOwner<'id>,
    identity: [u8; 32],
    limits: Limits,
    policy: Policy,
    serial: u64,
    peers: Vec<PeerRow<'id>>,
    // Original admission order; repeated requests merge without renewing age.
    routes: VecDeque<Route<'id>>,
    // Increasing original Job serials. Ordered insertion and stable removals
    // maintain this index independently of transmission preference classes.
    pending: Vec<Pending<'id>>,
    pending_bytes: usize,
    monitor_fanouts: Vec<MonitorFanout<'id>>,
    monitor_frames: usize,
    monitor_bytes: usize,
    monitor_first: bool,
    retries: Vec<Retry<'id>>,
    // Original serial order: new intents append after checked allocation;
    // removals preserve order and retry restores the same original index.
    unrouted: Vec<UnroutedPut<'id>>,
    put_bytes: usize,
    put_stats: PutStats,
    put_failure: Option<PutFailure<'id>>,
    put_cursor: usize,
    put_first: bool,
    route_revision: u64,
    closed: bool,
}
impl<'id> NetworkOwner<'id> {
    /// Adopt exactly one existing local/cache owner; no new Instance is forged.
    pub fn new(
        local: LocalOwner<'id>,
        identity: [u8; 32],
        limits: Limits,
        policy: Policy,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if local.closed {
            return Err(Error::Closed);
        }
        let mut routes = VecDeque::new();
        routes
            .try_reserve_exact(limits.routes)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            peers: super::reserved(limits.peers)?,
            routes,
            pending: super::reserved(limits.output_frames)?,
            monitor_fanouts: super::reserved(limits.monitor_fanouts.min(64))?,
            monitor_frames: 0,
            monitor_bytes: 0,
            monitor_first: true,
            retries: super::reserved(local.limits.queries)?,
            unrouted: super::reserved(limits.unrouted_puts.min(64))?,
            put_bytes: 0,
            put_stats: PutStats::default(),
            put_failure: None,
            put_cursor: 0,
            put_first: true,
            route_revision: 0,
            local,
            identity,
            limits,
            policy,
            serial: 0,
            pending_bytes: 0,
            closed: false,
        })
    }
    /// Adopt an actual new local PILS routing identity without replacing any
    /// local client, cache payload, query, reverse route or original PUT intent.
    /// Same-identity observations are no-ops. Old unadmitted frames retire;
    /// issued signatures keep their original tombstones until real completion.
    /// The containing host independently owns every already admitted native send
    /// and must bind each new tracked operation to a matching actual carrier.
    pub fn update_identity(&mut self, identity: [u8; 32]) -> Result<bool, Error> {
        self.open()?;
        if identity == self.identity {
            return Ok(false);
        }
        // The host must first retire any actual peer already claiming the new
        // local identity. Refuse before changing jobs, paths or retry state.
        if self.peers.iter().any(|peer| peer.identity == identity) {
            return Err(Error::Conflict);
        }
        let revision = self.route_revision.checked_add(1).ok_or(Error::Overflow)?;
        for pending in &mut self.pending {
            pending.retiring = true;
        }
        self.prune_unissued();
        // The last retained PUT signature named the old local identity as its
        // successor. A new signer cannot extend that link. Drop the old chain
        // using its real final signer as the explicit truncation boundary.
        for entry in &mut self.local.cache {
            if let Some(last) = entry.put_path.last_chunk::<{ dht::PATH_ELEMENT_LEN }>() {
                let mut predecessor = [0; 32];
                predecessor.copy_from_slice(&last[64..]);
                entry.truncated_peer = Some(predecessor);
                entry.options |= u32::from(RouteOptions::TRUNCATED.bits());
                entry.put_path = Vec::new();
            }
        }
        self.local.own_hello = None;
        self.identity = identity;
        self.route_revision = revision;
        self.wake_puts();
        Ok(true)
    }
    /// Admit one actual authenticated source. A replacement must first retire
    /// its old source token; a matching public identity does not revive it.
    pub fn connect_peer(&mut self, identity: [u8; 32]) -> Result<Peer<'id>, Error> {
        self.open()?;
        if identity == self.identity || self.peers.iter().any(|p| p.identity == identity) {
            return Err(Error::Conflict);
        }
        if self.peers.len() == self.limits.peers {
            return Err(Error::Capacity);
        }
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let revision = self.route_revision.checked_add(1).ok_or(Error::Overflow)?;
        let token = Peer {
            brand: self.local.brand,
            serial,
        };
        self.peers.push(PeerRow { token, identity });
        self.serial = serial;
        self.route_revision = revision;
        self.wake_puts();
        Ok(token)
    }
    /// Permanently retire this exact source. Issued signatures keep tombstones
    /// until their actual original native operation terminates.
    pub fn disconnect_peer(&mut self, peer: Peer<'id>) -> Result<(), Error> {
        self.peer(peer)?;
        let revision = self.route_revision.checked_add(1).ok_or(Error::Overflow)?;
        self.peers.retain(|p| p.token != peer);
        self.routes.retain(|r| r.peer != peer);
        for output in &mut self.pending {
            if output.peer == peer {
                output.retiring = true;
            }
        }
        self.prune_unissued();
        self.route_revision = revision;
        self.wake_puts();
        Ok(())
    }
    /// Original local IPC source admission.
    pub fn connect_client(&mut self) -> Result<ClientId<'id>, Error> {
        self.open()?;
        self.local.connect()
    }
    /// Stop only this original client's queries and unadmitted retry frames.
    pub fn disconnect_client(&mut self, client: ClientId<'id>) -> Result<(), Error> {
        self.local.disconnect(client)?;
        self.prune_monitor_targets();
        self.prune_queries();
        Ok(())
    }
    /// Transfer a real original-client local frame; not a native write receipt.
    pub fn take_output(&mut self) -> Option<Output<'id>> {
        // Fairly transfer a real retained frame. A full native client queue
        // leaves that same Output with the caller, never a new destination.
        if self.monitor_first
            && let Some(frame) = self.take_monitor_output()
        {
            self.monitor_first = false;
            return Some(frame);
        }
        if let Some(frame) = self.local.take_output() {
            self.monitor_first = true;
            return Some(frame);
        }
        let frame = self.take_monitor_output();
        if frame.is_some() {
            self.monitor_first = false;
        }
        frame
    }
    fn take_monitor_output(&mut self) -> Option<Output<'id>> {
        let index = self.monitor_fanouts.iter().position(|f| f.ready)?;
        let group = &mut self.monitor_fanouts[index];
        let frame = group.frames.remove(0);
        self.monitor_frames -= 1;
        self.monitor_bytes -= frame.bytes.capacity();
        if group.frames.is_empty() {
            self.monitor_fanouts.remove(index);
        }
        Some(frame)
    }
    fn prune_monitor_targets(&mut self) {
        // Disconnect/cancel never transfers a held observation to a replacement
        // MQ. Original full ClientIds are compared against current selectors.
        let local = &self.local;
        for fanout in &mut self.monitor_fanouts {
            let (event, kind, key) = (fanout.event, fanout.kind, fanout.key);
            fanout.frames.retain(|frame| {
                local.monitors.iter().any(|monitor| {
                    monitor.client == frame.client && local.matches(monitor, event, kind, &key)
                })
            });
        }
        self.monitor_fanouts.retain(|f| !f.frames.is_empty());
        self.monitor_frames = self.monitor_fanouts.iter().map(|f| f.frames.len()).sum();
        self.monitor_bytes = self
            .monitor_fanouts
            .iter()
            .flat_map(|f| &f.frames)
            .map(|frame| frame.bytes.capacity())
            .sum();
    }
    fn monitor_budget(&self, stage: &[Output<'id>], bytes: usize) -> Result<(), Error> {
        if self.monitor_fanouts.len() == self.limits.monitor_fanouts {
            return Err(Error::Capacity);
        }
        let count = self
            .monitor_frames
            .checked_add(stage.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?;
        let used = stage
            .iter()
            .try_fold(self.monitor_bytes, |n, frame| {
                n.checked_add(frame.bytes.capacity()).ok_or(Error::Overflow)
            })?
            .checked_add(bytes)
            .ok_or(Error::Overflow)?;
        if count > self.limits.monitor_frames || used > self.limits.monitor_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    fn monitor_frame(&self, stage: &mut Vec<Output<'id>>, bytes: usize) -> Result<Vec<u8>, Error> {
        self.monitor_budget(stage, bytes)?;
        stage.try_reserve(1).map_err(|_| Error::Capacity)?;
        let frame = super::bytes(bytes)?;
        self.monitor_budget(stage, frame.capacity())?;
        Ok(frame)
    }
    fn prepare_monitor(
        &mut self,
        jobs: &mut [Pending<'id>],
        frames: Vec<Output<'id>>,
        event: u8,
        kind: u32,
        key: [u8; 64],
        options: u32,
    ) -> Result<Option<MonitorFanout<'id>>, Error> {
        if frames.is_empty() {
            return Ok(None);
        }
        self.monitor_fanouts
            .try_reserve(1)
            .map_err(|_| Error::Capacity)?;
        let original = jobs.first().map(|job| job.job);
        let mut fanout = MonitorFanout {
            original,
            remaining: jobs.len(),
            ready: false,
            event,
            kind,
            key,
            options,
            frames,
        };
        for job in jobs {
            job.monitor = original;
        }
        if original.is_none() {
            fanout.conclude(true);
        }
        Ok(Some(fanout))
    }
    fn commit_monitor(&mut self, fanout: Option<MonitorFanout<'id>>) {
        if let Some(fanout) = fanout {
            self.monitor_frames += fanout.frames.len();
            self.monitor_bytes += fanout
                .frames
                .iter()
                .map(|f| f.bytes.capacity())
                .sum::<usize>();
            self.monitor_fanouts.push(fanout);
        }
    }
    fn monitor_terminal(
        fanouts: &mut [MonitorFanout<'id>],
        original: Option<Job<'id>>,
        admitted: bool,
    ) {
        if let Some(original) = original
            && let Some(fanout) = fanouts.iter_mut().find(|f| f.original == Some(original))
        {
            fanout.terminal(admitted);
        }
    }
    /// Ordinary local/cache diagnostic snapshot.
    #[must_use]
    pub fn local_snapshot(&self) -> super::Snapshot {
        self.local.snapshot()
    }
    /// Network-state snapshot; no remote processing is inferred.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            peers: self.peers.len(),
            routes: self.routes.len(),
            jobs: self.pending.len(),
            bytes: self.pending_bytes,
            cache_path_bytes: self
                .local
                .cache
                .iter()
                .fold(0usize, |n, e| n.saturating_add(e.put_path.capacity())),
            monitor_fanouts: self.monitor_fanouts.len(),
            monitor_frames: self.monitor_frames,
            monitor_bytes: self.monitor_bytes,
            unrouted_puts: self.unrouted.len(),
            unrouted_put_bytes: self.put_bytes,
            issued: self.pending.iter().filter(|p| p.issued).count(),
            closed: self.closed,
        }
    }
    /// Inspect genuine original jobs without allocating. A containing native
    /// owner records each new job's hard target using the native anchor captured
    /// before the business step that created it; later peeks never renew it.
    pub fn jobs(&self) -> impl Iterator<Item = JobInfo<'id>> + '_ {
        self.pending.iter().map(Self::pending_info)
    }
    /// Whether this exact original job remains owned, including issued signing
    /// tombstones. Foreign instances and retired jobs return false. This is a
    /// bounded O(log n) lookup without allocation, not a native admission fact.
    #[must_use]
    pub fn owns_job(&self, job: Job<'id>) -> bool {
        self.job_index(job).is_ok()
    }
    /// Inspect one exact currently owned job without allocating or renewing its
    /// targets. Issued/retiring jobs remain observable until actual retirement;
    /// a foreign-instance or retired token returns None.
    #[must_use]
    pub fn job_info(&self, job: Job<'id>) -> Option<JobInfo<'id>> {
        self.job_index(job)
            .ok()
            .map(|index| Self::pending_info(&self.pending[index]))
    }
    fn pending_info(p: &Pending<'id>) -> JobInfo<'id> {
        JobInfo {
            job: p.job,
            peer: p.peer,
            until: p.until,
            issued: p.issued,
            retiring: p.retiring,
            put: p.put,
        }
    }
    /// Actual configured/NSE estimate replacement, without recreating sources.
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
        // A genuine new routing estimate may change an unsubmitted fanout's
        // capacity requirement; it never changes its original retention bound.
        self.wake_puts();
    }
    /// Inspect accepted PUTs without native admission. Diagnostic inspection
    /// cannot reconstruct intent, client, signing or native-send capabilities.
    pub fn unrouted_puts(&self) -> impl Iterator<Item = PutInfo<'id>> + '_ {
        self.unrouted.iter().map(UnroutedPut::info)
    }
    /// Test membership of the complete original intent, including its brand.
    /// The internal serial index never reconstructs authority from diagnostics.
    #[must_use]
    pub fn owns_unrouted_put(&self, put: PutId<'id>) -> bool {
        self.put_index(put).is_some()
    }
    fn put_index(&self, put: PutId<'id>) -> Option<usize> {
        if put.brand != self.local.brand {
            return None;
        }
        let index = self
            .unrouted
            .binary_search_by_key(&put.serial, |row| row.id.serial)
            .ok()?;
        (self.unrouted[index].id == put).then_some(index)
    }
    /// Actual cumulative/local queued PUT facts; no remote replication claim.
    pub fn put_stats(&self) -> PutStats {
        PutStats {
            retained: self.unrouted.len(),
            payload_bytes: self.put_bytes,
            ..self.put_stats
        }
    }
    /// Native-hard retirement of this exact still-unsubmitted intent. All its
    /// unadmitted frames retire; already issued signatures retain original
    /// tombstones until the actual provider returns. No native/remote success
    /// or wire cancellation is manufactured by this clock-free method.
    pub fn expire_unrouted_put(&mut self, put: PutId<'id>) -> Result<PutInfo<'id>, Error> {
        self.open()?;
        if put.brand != self.local.brand {
            return Err(Error::InvalidInput);
        }
        let i = self.put_index(put).ok_or(Error::Stale)?;
        let info = self.unrouted[i].info();
        self.remove_put(i, true);
        Ok(info)
    }
    /// Consume the bounded original semantic BLOCK rejection observation.
    /// Repeated polling cannot recreate it or authorize retry of that intent.
    pub fn take_unrouted_failure(&mut self) -> Option<PutFailure<'id>> {
        self.put_failure.take()
    }
    fn wake_puts(&mut self) {
        for put in &mut self.unrouted {
            put.at = 0;
            put.blocked = None;
        }
    }
    fn put_pressure(&self) -> PutBlocked {
        PutBlocked {
            frames: self.pending.len(),
            bytes: self.pending_bytes,
            revision: self.route_revision,
        }
    }
    fn put_ready(&self, put: &UnroutedPut<'id>) -> bool {
        self.put_failure.is_none()
            && put.blocked != Some(self.put_pressure())
            && !self.pending.iter().any(|p| p.put == Some(put.id))
    }
    fn remove_put(&mut self, index: usize, expired: bool) {
        let original = self.unrouted.remove(index);
        self.put_bytes -= original.payload.capacity();
        if expired {
            self.put_stats.expired = self.put_stats.expired.saturating_add(1);
        }
        for pending in &mut self.pending {
            if pending.put == Some(original.id) {
                pending.retiring = true;
            }
        }
        self.prune_unissued();
    }
    fn prepare_put(
        &mut self,
        client: ClientId<'id>,
        put: ipc::Put<'_>,
        now: u64,
    ) -> Result<UnroutedPut<'id>, Error> {
        if self.unrouted.len() == self.limits.unrouted_puts
            || self
                .put_bytes
                .checked_add(put.payload.len())
                .is_none_or(|n| n > self.limits.unrouted_put_bytes)
        {
            return Err(Error::Capacity);
        }
        let until = finite_add(now, self.limits.unrouted_put_lifetime_micros)?
            .min(put.expiration.as_micros());
        let at = finite_add(now, self.limits.unrouted_put_retry_micros)?.min(until);
        self.unrouted.try_reserve(1).map_err(|_| Error::Capacity)?;
        let payload = copy(put.payload)?;
        if self
            .put_bytes
            .checked_add(payload.capacity())
            .is_none_or(|n| n > self.limits.unrouted_put_bytes)
        {
            return Err(Error::Capacity);
        }
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        self.serial = serial;
        Ok(UnroutedPut {
            id: PutId {
                brand: self.local.brand,
                serial,
            },
            client,
            accepted: now,
            until,
            expiration: put.expiration.as_micros(),
            at,
            blocked: None,
            key: *put.key,
            kind: put.block_type,
            options: RouteOptions::from_bits(put.options as u16),
            replication: put.replication,
            payload,
        })
    }
    fn retry_put(
        &mut self,
        now: u64,
        blocks: &mut impl NetworkBlocks,
        entropy: &mut impl Entropy,
    ) -> Result<bool, Error> {
        if self.unrouted.is_empty() {
            return Ok(false);
        }
        let index = (0..self.unrouted.len())
            .map(|offset| (self.put_cursor + offset) % self.unrouted.len())
            .find(|&i| self.unrouted[i].at <= now && self.put_ready(&self.unrouted[i]));
        let Some(index) = index else {
            return Ok(false);
        };
        // Temporarily own the one original payload while staging. The removed
        // metadata slot remains allocated, so restoration is infallible on all
        // faults and no second full payload copy is made for retry.
        let mut original = self.unrouted.remove(index);
        // Time-sensitive HELLO/GNS/etc blocks are checked again using the same
        // installed registry before a genuinely new, still-unsubmitted attempt.
        let validation = match blocks.type_capability(original.kind) {
            Ok(TypeCapability::Absent) => Ok(None),
            Ok(TypeCapability::Installed) => blocks
                .validate(original.kind, &original.key, &original.payload, now)
                .map(Some),
            Err(error) => Err(error),
        };
        match validation {
            Ok(None | Some(Validity::Valid)) => {}
            Ok(Some(validity @ (Validity::Invalid | Validity::Unsupported))) => {
                let reason = if validity == Validity::Unsupported {
                    Error::Unsupported
                } else {
                    Error::Authentication
                };
                self.put_bytes -= original.payload.capacity();
                self.put_stats.rejected = self.put_stats.rejected.saturating_add(1);
                self.put_failure = Some(PutFailure {
                    info: original.info(),
                    reason,
                });
                return Ok(true);
            }
            Err(error) => {
                self.unrouted.insert(index, original);
                return Err(error);
            }
        }
        let prepared = (|| -> Result<(Vec<Pending<'id>>, Option<PutBlocked>, u64), Error> {
            let next = finite_add(now, self.limits.unrouted_put_retry_micros)?.min(original.until);
            match self.plan_put(
                original.kind,
                original.options,
                origin_replication(original.replication),
                0,
                original.expiration,
                &original.key,
                &original.payload,
                None,
                Path::empty(),
                PeerBloom::empty(),
                now,
                entropy,
            )? {
                PutPlan::Blocked => Ok((Vec::new(), Some(self.put_pressure()), next)),
                PutPlan::Ready(mut outputs) => {
                    for output in &mut outputs {
                        output.put = Some(original.id);
                        output.until = output.until.min(original.until);
                    }
                    self.reserve_outputs(&outputs)?;
                    Ok((outputs, None, next))
                }
            }
        })();
        match prepared {
            Ok((outputs, blocked, next)) => {
                original.at = next;
                original.blocked = blocked;
                self.unrouted.insert(index, original);
                self.put_cursor = (index + 1) % self.unrouted.len();
                self.commit_outputs(outputs);
                Ok(blocked.is_none())
            }
            Err(error) => {
                self.unrouted.insert(index, original);
                Err(error)
            }
        }
    }
    /// Process one original local IPC frame and stage real GET/PUT work. Every
    /// fallible outbound reservation precedes the local business transition.
    pub fn ingest_client(
        &mut self,
        client: ClientId<'id>,
        input: &[u8],
        now: u64,
        blocks: &mut impl NetworkBlocks,
        entropy: &mut impl Entropy,
    ) -> Result<super::Outcome<'id>, Error> {
        self.open()?;
        self.local.client(client)?;
        let request = ipc::Request::decode(input)?;
        if let ipc::Request::Put(put) = request
            && put.block_type == 0
        {
            return Err(Error::InvalidInput);
        }
        if let ipc::Request::Get(get) = request
            && self
                .local
                .queries
                .iter()
                .any(|q| q.client == client && q.key == *get.key && q.id == get.id)
        {
            return self.local.ingest(client, input, now, blocks);
        }
        let next_retry = if matches!(request, ipc::Request::Get(_)) {
            finite_add(now, self.limits.retry_micros)?
        } else {
            0
        };
        let mut outputs = Vec::new();
        let mut put_intent = None;
        let mut put_blocked = false;
        match request {
            ipc::Request::Get(get) => {
                let mut group = self.group(get.block_type, None, blocks, entropy)?;
                // An exact retry of a logical GET preserves observed filters.
                if let Some(q) = self
                    .local
                    .queries
                    .iter()
                    .find(|q| q.client == client && q.key == *get.key && q.id == get.id)
                {
                    for h in &q.seen {
                        group.mark(h)?;
                    }
                }
                outputs = self.forward_get(
                    get.block_type,
                    RouteOptions::from_bits(get.options as u16),
                    origin_replication(get.replication),
                    0,
                    get.key,
                    get.extended_query,
                    &group,
                    PeerBloom::empty(),
                    now,
                    entropy,
                    Charge::default(),
                )?;
            }
            ipc::Request::Put(put) if put.expiration.as_micros() > now => {
                // All payload/metadata capacity is reserved before local.ingest
                // can accept this frame or expose related local query/monitor output.
                // The official PUT protocol itself has no service ACK.
                put_intent = Some(self.prepare_put(client, put, now)?);
                match self.plan_put(
                    put.block_type,
                    RouteOptions::from_bits(put.options as u16),
                    origin_replication(put.replication),
                    0,
                    put.expiration.as_micros(),
                    put.key,
                    put.payload,
                    None,
                    Path::empty(),
                    PeerBloom::empty(),
                    now,
                    entropy,
                )? {
                    PutPlan::Ready(stage) => outputs = stage,
                    PutPlan::Blocked => put_blocked = true,
                }
            }
            _ => {}
        }
        self.reserve_outputs(&outputs)?;
        let outcome = self.local.ingest(client, input, now, blocks)?;
        if let super::Outcome::Get(query) | super::Outcome::Duplicate(query) = outcome {
            if self.local.queries.iter().any(|q| q.token == query) {
                for output in &mut outputs {
                    output.query = Some(query);
                }
                if !self.retries.iter().any(|r| r.query == query) {
                    self.retries.push(Retry {
                        client,
                        query,
                        at: next_retry,
                    });
                }
            } else {
                outputs.clear();
            }
        }
        if let Some(mut put) = put_intent {
            if matches!(outcome, super::Outcome::Cached | super::Outcome::OpaquePut) {
                for output in &mut outputs {
                    output.put = Some(put.id);
                    output.until = output.until.min(put.until);
                }
                if put_blocked {
                    put.blocked = Some(self.put_pressure());
                }
                self.put_bytes += put.payload.capacity();
                self.put_stats.accepted = self.put_stats.accepted.saturating_add(1);
                self.unrouted.push(put);
            } else {
                // A rejected/expired local PUT cannot acquire forwarding work.
                outputs.clear();
            }
        }
        self.commit_outputs(outputs);
        if matches!(request, ipc::Request::MonitorStop(_)) {
            self.prune_monitor_targets();
        }
        self.prune_queries();
        Ok(outcome)
    }
    /// Consume one complete official peer frame on the original admitted source.
    /// BLOCK validation and tracked path verification precede route/cache effects.
    pub fn ingest_peer(
        &mut self,
        peer: Peer<'id>,
        input: &[u8],
        now: u64,
        blocks: &mut impl NetworkBlocks,
        entropy: &mut impl Entropy,
    ) -> Result<Outcome, Error> {
        self.open()?;
        self.peer(peer)?;
        match Frame::decode(input)?.header().message_type() {
            mt::DHT_P2P_GET => self.get(peer, GetMessage::decode(input)?, now, blocks, entropy),
            mt::DHT_P2P_PUT => self.put(peer, PutMessage::decode(input)?, now, blocks, entropy),
            mt::DHT_P2P_RESULT => self.result(peer, ResultMessage::decode(input)?, now, blocks),
            _ => Err(Error::Unsupported),
        }
    }
    /// Native-free time progression. Retry is an actual new read attempt on the
    /// same original local query; expired/canceled pending work is never renewed.
    pub fn tick(
        &mut self,
        now: u64,
        blocks: &mut impl NetworkBlocks,
        entropy: &mut impl Entropy,
    ) -> Result<(), Error> {
        self.local.tick(now)?;
        self.routes.retain(|r| r.until > now);
        for pending in &mut self.pending {
            if pending.until <= now {
                pending.retiring = true;
            }
        }
        self.prune_unissued();
        self.prune_queries();
        if self.closed {
            return Ok(());
        }
        for i in (0..self.unrouted.len()).rev() {
            if self.unrouted[i].until <= now {
                self.remove_put(i, true);
            }
        }
        for offset in 0..2 {
            let put = (offset == 0) == self.put_first;
            let progressed = if put {
                self.retry_put(now, blocks, entropy)?
            } else {
                self.retry_get(now, blocks, entropy)?
            };
            if progressed {
                self.put_first = !put;
                break;
            }
        }
        Ok(())
    }
    fn retry_get(
        &mut self,
        now: u64,
        blocks: &mut impl NetworkBlocks,
        entropy: &mut impl Entropy,
    ) -> Result<bool, Error> {
        // A slow original peer/signing job may hold one query's retry. Other
        // due queries can still use their own original peers and output slots.
        // This also matches next_wakeup's exclusion of those retained jobs.
        let Some(index) = self
            .retries
            .iter()
            .position(|r| r.at <= now && !self.pending.iter().any(|p| p.query == Some(r.query)))
        else {
            return Ok(false);
        };
        let query = self.retries[index].query;
        let Some(q) = self.local.queries.iter().find(|q| q.token == query) else {
            return Err(Error::Stale);
        };
        let key = q.key;
        let kind = q.kind;
        let options = q.options;
        let replication = origin_replication(q.replication);
        let xquery = copy(&q.xquery)?;
        let seen = copy_hashes(&q.seen)?;
        let mut group = self.group(kind, None, blocks, entropy)?;
        for h in &seen {
            group.mark(h)?;
        }
        let mut outputs = self.forward_get(
            kind,
            RouteOptions::from_bits(options as u16),
            replication,
            0,
            &key,
            &xquery,
            &group,
            PeerBloom::empty(),
            now,
            entropy,
            Charge::default(),
        )?;
        self.reserve_outputs(&outputs)?;
        let next = finite_add(now, self.limits.retry_micros)?;
        for output in &mut outputs {
            output.query = Some(query);
        }
        self.commit_outputs(outputs);
        self.retries[index].at = next;
        Ok(true)
    }
    /// Earliest original finite logical target. The native owner must also use
    /// its original native alarms; this value never grants a fresh operation.
    #[must_use]
    pub fn next_wakeup(&self) -> Option<u64> {
        self.pending
            .iter()
            .filter(|p| !p.retiring)
            .map(|p| p.until)
            .chain(self.routes.iter().map(|r| r.until))
            .chain(
                self.retries
                    .iter()
                    .filter(|r| !self.pending.iter().any(|p| p.query == Some(r.query)))
                    .map(|r| r.at),
            )
            .chain(self.unrouted.iter().map(|put| put.until))
            .chain(
                self.unrouted
                    .iter()
                    .filter(|put| self.put_ready(put))
                    .map(|put| put.at),
            )
            .min()
    }
    /// Borrow bounded original work in transmission preference order. Issued
    /// retirement debts remain first; otherwise RESULT jobs precede GET/PUT,
    /// retaining original order within each class. The host checks its actual
    /// resource availability and can skip a busy candidate. No queue/payload is
    /// copied, no effect starts, and already issued work is not preempted.
    pub fn work(&self) -> impl Iterator<Item = Work<'_, 'id>> {
        let retire = self
            .pending
            .iter()
            .filter(|p| p.retiring && p.issued)
            .map(|p| Work::Retire {
                job: p.job,
                peer: p.peer,
            });
        let results = self
            .pending
            .iter()
            .filter(|p| !p.retiring && !p.issued && p.kind == JobKind::Result)
            .map(Self::active_work);
        let requests = self
            .pending
            .iter()
            .filter(|p| !p.retiring && !p.issued && p.kind != JobKind::Result)
            .map(Self::active_work);
        retire.chain(results).chain(requests)
    }
    /// Peek the first original preference without consuming it. Hosts with
    /// independent native resources should consider work() and skip busy items.
    #[must_use]
    pub fn next_work(&self) -> Option<Work<'_, 'id>> {
        self.work().next()
    }
    fn active_work<'work>(p: &'work Pending<'id>) -> Work<'work, 'id> {
        match &p.signing {
            Some(s) => Work::Sign {
                job: p.job,
                peer: p.peer,
                frame_bytes: p.frame.len(),
                material: &s.material,
                until: p.until,
            },
            None => Work::Send {
                job: p.job,
                peer: p.peer,
                kind: p.kind,
                frame: &p.frame,
                until: p.until,
            },
        }
    }
    /// Mark actual original PILS admission only after it retained this material.
    pub fn sign_started(&mut self, job: Job<'id>) -> Result<(), Error> {
        let p = self.job_mut(job)?;
        if p.retiring || p.issued || p.signing.is_none() {
            return Err(Error::Conflict);
        }
        p.issued = true;
        Ok(())
    }
    /// Accept only the actual callback for an issued original job, verifying the
    /// exact original local key/purpose/material before exposing its same frame.
    pub fn signed(&mut self, job: Job<'id>, signature: [u8; 64]) -> Result<Signed, Error> {
        let index = self.job_index(job)?;
        let pending = &self.pending[index];
        if !pending.issued {
            return Err(Error::Conflict);
        }
        if pending.retiring {
            self.remove_job(index);
            return Ok(Signed::Retired);
        }
        let signing = pending.signing.as_ref().ok_or(Error::Conflict)?;
        EddsaPublicKey::from_bytes(self.identity).verify(
            crate::path::PURPOSE,
            &signing.material,
            &EddsaSignature::from_bytes(signature),
        )?;
        let offset = signing.offset;
        let output = self.pending.get_mut(index).ok_or(Error::Stale)?;
        output
            .frame
            .get_mut(offset..offset + 64)
            .ok_or(Error::InvalidInput)?
            .copy_from_slice(&signature);
        output.signing = None;
        output.issued = false;
        Ok(Signed::Ready)
    }
    /// Original signature failed/was canceled and its native owner is terminal.
    /// The host separately retains the actual provider error; no frame is sent.
    pub fn signing_failed(&mut self, job: Job<'id>) -> Result<(), Error> {
        let i = self.job_index(job)?;
        if !self.pending[i].issued {
            return Err(Error::Conflict);
        }
        self.remove_job(i);
        Ok(())
    }
    /// Transfer the same complete frame after real native FIFO admission. This
    /// never claims written bytes, remote storage or remote callback success.
    pub fn admitted(&mut self, job: Job<'id>, peer: Peer<'id>) -> Result<(), Error> {
        let i = self.job_index(job)?;
        let p = &self.pending[i];
        if p.peer != peer || p.issued || p.retiring || p.signing.is_some() {
            return Err(Error::Conflict);
        }
        let put = p.put;
        let monitor = p.monitor;
        Self::monitor_terminal(&mut self.monitor_fanouts, monitor, true);
        self.remove_job(i);
        if let Some(put) = put {
            // Caller has already transferred the original frame to its native
            // FIFO. Never recreate this intent after loss or Unknown.
            if let Some(index) = self.put_index(put) {
                let original = self.unrouted.remove(index);
                self.put_bytes -= original.payload.capacity();
                self.put_stats.submitted = self.put_stats.submitted.saturating_add(1);
            }
            for sibling in &mut self.pending {
                if sibling.put == Some(put) {
                    sibling.put = None;
                }
            }
        }
        Ok(())
    }
    /// Clock-free cancellation of this original job by the native owner. A
    /// hard deadline is not a provider completion: issued work keeps its original
    /// tombstone until `retired` or its genuine signature callback arrives.
    pub fn cancel_job(&mut self, job: Job<'id>) -> Result<(), Error> {
        let i = self.job_index(job)?;
        self.pending[i].retiring = true;
        if !self.pending[i].issued {
            self.remove_job(i);
        }
        Ok(())
    }
    /// Originate one genuine autonomous FIND PEER round for this node's own
    /// identity hash. The caller supplies the same original finite round target;
    /// retries while capacity is refused must not renew it. No local client,
    /// request id, reverse route or remote completion is manufactured.
    pub fn find_peers(
        &mut self,
        now: u64,
        until: u64,
        blocks: &mut impl NetworkBlocks,
        entropy: &mut impl Entropy,
    ) -> Result<usize, Error> {
        self.open()?;
        if until <= now || until == u64::MAX {
            return Err(Error::Deadline);
        }
        let key = routing::peer_key(&self.identity);
        blocks.query(13, &key, &[])?;
        let mut filter = self.group(13, None, blocks, entropy)?;
        for peer in &self.peers {
            filter.mark(&routing::peer_key(&peer.identity))?;
        }
        let mut outputs = self.forward_get(
            13,
            RouteOptions::FIND_APPROXIMATE | RouteOptions::RECORD_ROUTE,
            4,
            0,
            &key,
            &[],
            &filter,
            PeerBloom::empty(),
            now,
            entropy,
            Charge::default(),
        )?;
        // The round was minted before this attempt. Logical clock rollback or
        // another capacity attempt cannot give these new jobs a fresh target.
        for output in &mut outputs {
            output.until = until;
        }
        self.reserve_outputs(&outputs)?;
        let prepared = outputs.len();
        self.commit_outputs(outputs);
        Ok(prepared)
    }
    /// Cache/deliver a genuinely observed public HELLO using the installed
    /// verifier, derived key and original volatile cache policy. Even a genuine
    /// signed copy of our own HELLO from a remote observer cannot replace the
    /// actual local PILS announcement.
    pub fn observe_hello(
        &mut self,
        payload: &[u8],
        now: u64,
        blocks: &mut impl NetworkBlocks,
    ) -> Result<(), Error> {
        let entry = self.hello_entry(payload, now, blocks)?;
        self.accept_entry(entry, Path::empty(), None, true, None, now, blocks)
    }
    /// Observe the actual current local PILS announcement, in that original
    /// source's observation order. Native callers must not route remote HELLOs
    /// through this entry. Validation and derived local-peer identity remain
    /// mandatory; expiration is a bound, never a publication-version counter.
    /// Exactly one payload is retained independently of ordinary cache quota.
    pub fn observe_local_hello(
        &mut self,
        payload: &[u8],
        now: u64,
        blocks: &mut impl NetworkBlocks,
    ) -> Result<(), Error> {
        let entry = self.hello_entry(payload, now, blocks)?;
        if entry.key != routing::peer_key(&self.identity) {
            return Err(Error::Authentication);
        }
        // Prepare the dedicated allocation before any local output or old
        // announcement changes. The other bounded copy is transient input to
        // the existing atomic local query/monitor transition.
        let retained = entry_copy(&entry)?;
        if retained.payload.capacity() > self.local.limits.block_bytes {
            return Err(Error::Capacity);
        }
        self.accept_entry(entry, Path::empty(), None, false, None, now, blocks)?;
        self.local.own_hello = Some(retained);
        Ok(())
    }
    fn hello_entry(
        &self,
        payload: &[u8],
        now: u64,
        blocks: &mut impl NetworkBlocks,
    ) -> Result<Entry, Error> {
        self.open()?;
        if payload.len() > self.local.limits.block_bytes {
            return Err(Error::TooLarge);
        }
        let expiration =
            AbsoluteTime::decode(payload.get(96..104).ok_or(Error::Truncated)?)?.as_micros();
        if expiration < now {
            return Err(Error::Deadline);
        }
        let kind = 13;
        let key = blocks
            .derive_key(kind, payload, now)?
            .ok_or(Error::Authentication)?;
        if blocks.validate(kind, &key, payload, now)? != Validity::Valid {
            return Err(Error::Authentication);
        }
        Ok(Entry {
            key,
            kind,
            options: 0,
            expiration,
            payload: copy(payload)?,
            hash: hash512(payload),
            put_path: Vec::new(),
            truncated_peer: None,
        })
    }
    /// Clock-free actual original issued-provider retirement, not a timeout ACK.
    pub fn retired(&mut self, job: Job<'id>) -> Result<(), Error> {
        let i = self.job_index(job)?;
        if !self.pending[i].issued || !self.pending[i].retiring {
            return Err(Error::Conflict);
        }
        self.remove_job(i);
        Ok(())
    }
    /// Stop local/peer business while preserving real issued signing debts.
    /// The caller must additionally close/drain its original native frame queues.
    pub fn close(&mut self) {
        self.closed = true;
        self.local.close();
        // No monitoring MQ remains: abandon notifications without claiming
        // their delivery or prematurely retiring issued signing tombstones.
        self.monitor_fanouts.clear();
        self.monitor_frames = 0;
        self.monitor_bytes = 0;
        self.routes.clear();
        self.retries.clear();
        self.put_stats.closed = self
            .put_stats
            .closed
            .saturating_add(self.unrouted.len() as u64);
        self.unrouted.clear();
        self.put_bytes = 0;
        self.peers.clear();
        for p in &mut self.pending {
            p.retiring = true;
        }
        self.prune_unissued();
    }

    fn open(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn peer(&self, peer: Peer<'id>) -> Result<&PeerRow<'id>, Error> {
        if peer.brand != self.local.brand {
            return Err(Error::InvalidInput);
        }
        self.peers
            .iter()
            .find(|p| p.token == peer)
            .ok_or(Error::Stale)
    }
    fn job_index(&self, job: Job<'id>) -> Result<usize, Error> {
        if job.brand != self.local.brand {
            return Err(Error::InvalidInput);
        }
        let index = self
            .pending
            .binary_search_by_key(&job.serial, |p| p.job.serial)
            .map_err(|_| Error::Stale)?;
        // A serial only locates a row; it never substitutes for its complete
        // original capability, even after churn leaves gaps in this index.
        if self.pending[index].job != job {
            return Err(Error::InvalidInput);
        }
        Ok(index)
    }
    fn job_mut(&mut self, job: Job<'id>) -> Result<&mut Pending<'id>, Error> {
        let i = self.job_index(job)?;
        self.pending.get_mut(i).ok_or(Error::Stale)
    }
    fn new_job(&mut self) -> Result<Job<'id>, Error> {
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        self.serial = serial;
        Ok(Job {
            brand: self.local.brand,
            serial,
        })
    }
    fn remove_job(&mut self, index: usize) {
        let p = self.pending.remove(index);
        self.pending_bytes -= p.frame.len();
        Self::monitor_terminal(&mut self.monitor_fanouts, p.monitor, false);
    }
    fn prune_unissued(&mut self) {
        let fanouts = &mut self.monitor_fanouts;
        self.pending.retain(|p| {
            if p.retiring && !p.issued {
                Self::monitor_terminal(fanouts, p.monitor, false);
                false
            } else {
                true
            }
        });
        self.pending_bytes = self.pending.iter().map(|p| p.frame.len()).sum();
    }
    fn prune_queries(&mut self) {
        self.retries.retain(|r| {
            self.local
                .queries
                .iter()
                .any(|q| q.token == r.query && q.client == r.client)
        });
        for p in &mut self.pending {
            if p.query
                .is_some_and(|id| !self.local.queries.iter().any(|q| q.token == id))
            {
                p.retiring = true;
            }
        }
        self.prune_unissued();
    }
    fn reserve_outputs(&mut self, stage: &[Pending<'id>]) -> Result<(), Error> {
        let n = self
            .pending
            .len()
            .checked_add(stage.len())
            .ok_or(Error::Overflow)?;
        let used = stage.iter().try_fold(self.pending_bytes, |n, p| {
            n.checked_add(p.frame.len()).ok_or(Error::Overflow)
        })?;
        if n > self.limits.output_frames || used > self.limits.output_bytes {
            return Err(Error::Capacity);
        }
        self.pending
            .try_reserve(stage.len())
            .map_err(|_| Error::Capacity)
    }
    fn check_frame(
        &self,
        prefix: Charge,
        stage: &[Pending<'id>],
        bytes: usize,
    ) -> Result<(), Error> {
        let staged = Charge::of(stage)?;
        let count = self
            .pending
            .len()
            .checked_add(prefix.frames)
            .and_then(|n| n.checked_add(staged.frames))
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?;
        let used = self
            .pending_bytes
            .checked_add(prefix.bytes)
            .and_then(|n| n.checked_add(staged.bytes))
            .and_then(|n| n.checked_add(bytes))
            .ok_or(Error::Overflow)?;
        if count > self.limits.output_frames || used > self.limits.output_bytes {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    fn commit_outputs(&mut self, stage: Vec<Pending<'id>>) {
        for p in stage {
            self.pending_bytes += p.frame.len();
            let index = self
                .pending
                .partition_point(|old| old.job.serial < p.job.serial);
            self.pending.insert(index, p);
        }
    }
    fn candidates(&self) -> Result<Vec<Candidate<Peer<'id>>>, Error> {
        let mut out = super::reserved(self.peers.len())?;
        for p in &self.peers {
            out.push(Candidate {
                origin: p.token,
                identity: p.identity,
            });
        }
        Ok(out)
    }
    fn group(
        &self,
        kind: u32,
        raw: Option<&[u8]>,
        blocks: &mut impl NetworkBlocks,
        entropy: &mut impl Entropy,
    ) -> Result<Filter, Error> {
        let raw = raw.filter(|s| !s.is_empty());
        let size = raw.map_or(self.limits.initial_filter_bytes, |s| s.len());
        if size > self.limits.filter_bytes {
            return Err(Error::Capacity);
        }
        if kind == 0 || blocks.type_capability(kind)? == TypeCapability::Absent {
            // RF_SIZE and XQUERY belong to the unknown type's codec. Retain
            // the received bytes without guessing a nonce/group layout.
            return Filter::opaque(
                kind,
                raw.unwrap_or(&[]),
                self.limits.group_profile,
                self.limits.opaque_seen_hashes,
            );
        }
        let mut filter =
            blocks.filter(kind, raw, size, nonce(entropy)?, self.limits.group_profile)?;
        filter.set_seen_limit(self.limits.opaque_seen_hashes);
        Ok(filter)
    }
}
enum PutPlan<'id> {
    Ready(Vec<Pending<'id>>),
    Blocked,
}
impl<'id> NetworkOwner<'id> {
    #[expect(
        clippy::too_many_arguments,
        reason = "Original query metadata, route filter, visited peers and independent entropy are explicit caller-owned inputs"
    )]
    fn forward_get(
        &mut self,
        kind: u32,
        options: RouteOptions,
        replication: u16,
        hop: u16,
        key: &[u8; 64],
        xquery: &[u8],
        filter: &Filter,
        visited: PeerBloom,
        now: u64,
        entropy: &mut impl Entropy,
        prefix: Charge,
    ) -> Result<Vec<Pending<'id>>, Error> {
        if xquery.len() > self.limits.extended_query_bytes {
            return Err(Error::Capacity);
        }
        let candidates = self.candidates()?;
        let plan = routing::plan(
            &self.identity,
            key,
            &candidates,
            visited,
            self.policy.estimate,
            hop,
            replication,
            self.limits.bucket_size,
            entropy,
        )?;
        let raw = filter.encode()?;
        let mut out = super::reserved(routing::MAX_REPLICATION)?;
        for peer in plan.selected() {
            let next = hop.checked_add(1).ok_or(Error::Overflow)?;
            let message = GetMessage {
                block_type: kind,
                options,
                hop_count: next,
                desired_replication_level: replication,
                peer_bloom: plan.bloom().as_bytes(),
                key,
                result_filter: &raw,
                extended_query: xquery,
            };
            let job = self.new_job()?;
            self.check_frame(prefix, &out, message.encoded_len()?)?;
            out.push(Pending::get(
                job,
                peer,
                message,
                finite_add(now, self.limits.operation_lifetime_micros)?,
            )?);
        }
        Ok(out)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Original complete block, signed path and routing inputs stay independently bound without copying a private message shape"
    )]
    fn forward_put(
        &mut self,
        kind: u32,
        options: RouteOptions,
        replication: u16,
        hop: u16,
        expiration: u64,
        key: &[u8; 64],
        payload: &[u8],
        truncated: Option<&[u8; 32]>,
        path: Path<'_>,
        visited: PeerBloom,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Vec<Pending<'id>>, Error> {
        match self.plan_put(
            kind,
            options,
            replication,
            hop,
            expiration,
            key,
            payload,
            truncated,
            path,
            visited,
            now,
            entropy,
        )? {
            PutPlan::Ready(outputs) => Ok(outputs),
            PutPlan::Blocked => Err(Error::Capacity),
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Same complete original PUT/path inputs; known output backpressure is separate from allocation/provider failure"
    )]
    fn plan_put(
        &mut self,
        kind: u32,
        options: RouteOptions,
        replication: u16,
        hop: u16,
        expiration: u64,
        key: &[u8; 64],
        payload: &[u8],
        truncated: Option<&[u8; 32]>,
        path: Path<'_>,
        visited: PeerBloom,
        now: u64,
        entropy: &mut impl Entropy,
    ) -> Result<PutPlan<'id>, Error> {
        let candidates = self.candidates()?;
        let plan = routing::plan(
            &self.identity,
            key,
            &candidates,
            visited,
            self.policy.estimate,
            hop,
            replication,
            self.limits.bucket_size,
            entropy,
        )?;
        let mut out = super::reserved(routing::MAX_REPLICATION)?;
        for peer in plan.selected() {
            let identity = self.peer(peer)?.identity;
            let job = self.new_job()?;
            let message = PutMessage {
                block_type: kind,
                options,
                hop_count: hop.checked_add(1).ok_or(Error::Overflow)?,
                desired_replication_level: replication,
                expiration: AbsoluteTime::from_micros(expiration),
                peer_bloom: plan.bloom().as_bytes(),
                key,
                truncated_peer: truncated,
                put_path: path,
                sender_signature: None,
                payload,
            };
            // One temporary complete frame is permitted, never an unbounded
            // multicast stage. The original transition is still atomic.
            let output = Pending::put(
                job,
                peer,
                &identity,
                message,
                self.limits.put_frame_limit,
                finite_add(now, self.limits.operation_lifetime_micros)?.min(expiration),
            )?;
            match self.check_frame(Charge::default(), &out, output.frame.len()) {
                Ok(()) => {}
                Err(Error::Capacity) => return Ok(PutPlan::Blocked),
                Err(error) => return Err(error),
            }
            out.push(output);
        }
        Ok(PutPlan::Ready(out))
    }
    fn reply_to(
        &mut self,
        peer: Peer<'id>,
        requested: &[u8; 64],
        requested_options: RouteOptions,
        block: &Block<'_>,
        now: u64,
        until: u64,
    ) -> Result<Pending<'id>, Error> {
        let identity = self.peer(peer)?.identity;
        let job = self.new_job()?;
        let mut message = block.result(requested);
        if requested_options.contains(RouteOptions::RECORD_ROUTE) {
            message.options = message.options | RouteOptions::RECORD_ROUTE;
        } else {
            message.options = RouteOptions::from_bits(
                message.options.bits()
                    & !(RouteOptions::RECORD_ROUTE.bits() | RouteOptions::TRUNCATED.bits()),
            );
            message.truncated_peer = None;
            message.put_path = Path::empty();
            message.get_path = Path::empty();
        }
        Pending::result(
            job,
            peer,
            &identity,
            message,
            finite_add(now, self.limits.operation_lifetime_micros)?
                .min(until)
                .min(block.expiration),
        )
    }
    fn get(
        &mut self,
        peer: Peer<'id>,
        get: GetMessage<'_>,
        now: u64,
        blocks: &mut impl NetworkBlocks,
        entropy: &mut impl Entropy,
    ) -> Result<Outcome, Error> {
        if get.extended_query.len() > self.limits.extended_query_bytes {
            return Err(Error::Capacity);
        }
        let installed = get.block_type != 0
            && blocks.type_capability(get.block_type)? == TypeCapability::Installed;
        if installed {
            blocks.query(get.block_type, get.key, get.extended_query)?;
        }
        let existing = self.routes.iter().position(|r| {
            r.peer == peer
                && r.key == *get.key
                && r.kind == get.block_type
                && r.xquery == get.extended_query
        });
        let until = if let Some(index) = existing {
            self.routes[index].until
        } else {
            finite_add(now, self.limits.route_lifetime_micros)?
        };
        let mut filter = self.group(get.block_type, Some(get.result_filter), blocks, entropy)?;
        if let Some(index) = existing {
            filter.merge(&self.routes[index].filter)?;
        }
        let mut visited = PeerBloom::from_bytes(*get.peer_bloom);
        visited.insert_key(&routing::peer_key(&self.peer(peer)?.identity));
        let candidates = self.candidates()?;
        let local = get.options.contains(RouteOptions::DEMULTIPLEX_EVERYWHERE)
            || routing::am_closest(
                &self.identity,
                get.key,
                &candidates,
                Some(&visited),
                self.limits.bucket_size,
            );
        let mut outputs = Vec::new();
        let mut last = false;
        if local && (installed || get.block_type == 0) {
            let selected = self.local.cache_selection_for(
                get.key,
                get.block_type,
                u32::from(get.options.bits()),
                now,
            )?;
            // The reference HELLO path offers our current announcement first,
            // independently of the datacache's nearest-key subset. The same
            // original BLOCK group suppresses already-known identities.
            let own_hello = matches!(get.block_type, 0 | 13)
                && self
                    .local
                    .own_hello
                    .as_ref()
                    .is_some_and(|e| e.expiration >= now);
            for candidate in 0..selected.len() + usize::from(own_hello) {
                let e = if own_hello && candidate == 0 {
                    self.local.own_hello.as_ref().ok_or(Error::Stale)?
                } else {
                    &self.local.cache[selected[candidate - usize::from(own_hello)]]
                };
                if blocks.validate(e.kind, &e.key, &e.payload, now)? != Validity::Valid {
                    continue;
                }
                let quote = Block {
                    reserved: 0,
                    kind: e.kind,
                    options: RouteOptions::from_bits(e.options as u16),
                    expiration: e.expiration,
                    payload: &e.payload,
                    truncated: e.truncated_peer.as_ref(),
                    put: Path::new(&e.put_path)?,
                    get: Path::empty(),
                };
                let evaluation = evaluate_reply(
                    blocks,
                    get.block_type,
                    &e.key,
                    get.extended_query,
                    &quote,
                    &e.hash,
                    now,
                    true,
                    &mut filter,
                )?;
                if !matches!(evaluation, ReplyEvaluation::More | ReplyEvaluation::Last) {
                    continue;
                }
                // Own only this selected bounded candidate while making the
                // outbound job; never alias the cache across a mutable owner step.
                self.check_frame(
                    Charge::default(),
                    &outputs,
                    reply_length(get.key, get.options, &quote)?,
                )?;
                let value = entry_copy(e)?;
                let block = Block {
                    reserved: 0,
                    kind: value.kind,
                    options: RouteOptions::from_bits(value.options as u16),
                    expiration: value.expiration,
                    payload: &value.payload,
                    truncated: value.truncated_peer.as_ref(),
                    put: Path::new(&value.put_path)?,
                    get: Path::empty(),
                };
                outputs.try_reserve(1).map_err(|_| Error::Capacity)?;
                outputs.push(self.reply_to(peer, get.key, get.options, &block, now, until)?);
                if evaluation == ReplyEvaluation::Last {
                    last = true;
                    break;
                }
            }
        }
        let forwarding_start = outputs.len();
        if !last {
            let forwarded = self.forward_get(
                get.block_type,
                get.options,
                get.desired_replication_level,
                get.hop_count,
                get.key,
                get.extended_query,
                &filter,
                visited,
                now,
                entropy,
                Charge::of(&outputs)?,
            )?;
            outputs
                .try_reserve(forwarded.len())
                .map_err(|_| Error::Capacity)?;
            outputs.extend(forwarded);
        }
        self.reserve_outputs(&outputs)?;
        let xquery = if existing.is_none() && !last {
            copy(get.extended_query)?
        } else {
            Vec::new()
        };
        let mut monitor_frames = Vec::new();
        self.monitor_get(get, &mut monitor_frames)?;
        // Cache RESULT replies are not forwarding this received GET.
        let monitor = self.prepare_monitor(
            &mut outputs[forwarding_start..],
            monitor_frames,
            0,
            get.block_type,
            *get.key,
            u32::from(get.options.bits()),
        )?;
        // All allocation, query evaluation and output staging succeeded. A
        // terminal reply removes only reverse-route metadata, never the old
        // signing/native-send debt or the newly staged terminal RESULT.
        if let Some(index) = existing {
            if last {
                self.routes.remove(index);
            } else {
                self.routes[index].filter = filter;
            }
        } else if !last {
            if self.routes.len() == self.limits.routes {
                self.routes.pop_front();
            }
            self.routes.push_back(Route {
                peer,
                key: *get.key,
                kind: get.block_type,
                options: get.options,
                xquery,
                filter,
                until,
            });
        }
        self.commit_monitor(monitor);
        self.commit_outputs(outputs);
        Ok(if get.block_type == 0 || installed {
            Outcome::Get
        } else {
            Outcome::OpaqueGet
        })
    }
    fn put(
        &mut self,
        peer: Peer<'id>,
        put: PutMessage<'_>,
        now: u64,
        blocks: &mut impl NetworkBlocks,
        entropy: &mut impl Entropy,
    ) -> Result<Outcome, Error> {
        // ANY is a query wildcard, never an opaque concrete PUT type.
        if put.block_type == 0 {
            return Err(Error::InvalidInput);
        }
        let expiration = put.expiration.as_micros();
        if expiration < now {
            return Ok(Outcome::Expired);
        }
        if put.payload.len() > self.local.limits.block_bytes {
            return Err(Error::Capacity);
        }
        let installed = match blocks.type_capability(put.block_type)? {
            TypeCapability::Installed => {
                // Unsupported operations, malformed blocks and resource faults
                // from a real handler cannot become an absent-type bypass.
                match blocks.validate(put.block_type, put.key, put.payload, now)? {
                    Validity::Valid => {}
                    Validity::Invalid => return Err(Error::Authentication),
                    Validity::Unsupported => return Err(Error::Unsupported),
                }
                true
            }
            TypeCapability::Absent => false,
        };
        let sender = self.peer(peer)?.identity;
        let path = self.incoming_path(
            put.payload,
            expiration,
            put.options,
            put.truncated_peer,
            put.put_path,
            Path::empty(),
            put.sender_signature,
            &sender,
            now,
            false,
        )?;
        let mut visited = PeerBloom::from_bytes(*put.peer_bloom);
        visited.insert_key(&routing::peer_key(&sender));
        let cache = if installed {
            let candidates = self.candidates()?;
            path.options.contains(RouteOptions::DEMULTIPLEX_EVERYWHERE)
                || routing::am_closest(
                    &self.identity,
                    put.key,
                    &candidates,
                    Some(&visited),
                    self.limits.bucket_size,
                )
        } else {
            false
        };
        let mut outputs = self.forward_put(
            put.block_type,
            path.options,
            put.desired_replication_level,
            put.hop_count,
            expiration,
            put.key,
            put.payload,
            path.truncated.as_ref(),
            path.put()?,
            visited,
            now,
            entropy,
        )?;
        self.reserve_outputs(&outputs)?;
        let mut monitor_frames = Vec::new();
        // A monitor records the actual received payload and selected recorded
        // path; it is not a validated payload result. Opaque transit still needs
        // no owned Entry or payload copy.
        self.monitor_put(
            ipc::MonitorPut {
                options: u32::from(path.options.bits()),
                block_type: put.block_type,
                hop_count: u32::from(put.hop_count),
                replication: u32::from(put.desired_replication_level),
                expiration: put.expiration,
                key: put.key,
                truncated_peer: path.truncated.as_ref(),
                put_path: path.put()?,
                payload: put.payload,
            },
            &mut monitor_frames,
        )?;
        let monitor = self.prepare_monitor(
            &mut outputs,
            monitor_frames,
            2,
            put.block_type,
            *put.key,
            u32::from(path.options.bits()),
        )?;
        if !installed {
            // The unchanged payload may reach a peer with this type installed.
            // Do not claim it is valid or run cache/local-query delivery paths.
            self.commit_monitor(monitor);
            self.commit_outputs(outputs);
            return Ok(Outcome::OpaquePut);
        }
        let entry = Entry {
            key: *put.key,
            kind: put.block_type,
            options: u32::from(path.options.bits()),
            expiration,
            payload: copy(put.payload)?,
            hash: hash512(put.payload),
            put_path: own_path(path.put)?,
            truncated_peer: path.truncated,
        };
        self.accept_entry(
            entry,
            Path::empty(),
            None,
            cache,
            Some((
                u32::from(put.hop_count),
                u32::from(put.desired_replication_level),
            )),
            now,
            blocks,
        )?;
        self.commit_monitor(monitor);
        self.commit_outputs(outputs);
        Ok(Outcome::Put)
    }
    fn result(
        &mut self,
        peer: Peer<'id>,
        result: ResultMessage<'_>,
        now: u64,
        blocks: &mut impl NetworkBlocks,
    ) -> Result<Outcome, Error> {
        // ANY is legal only as a requested wildcard, never as a concrete RESULT.
        if result.block_type == 0 {
            return Err(Error::InvalidInput);
        }
        let expiration = result.expiration.as_micros();
        if expiration < now {
            return Ok(Outcome::Expired);
        }
        if result.payload.len() > self.local.limits.block_bytes {
            return Err(Error::Capacity);
        }
        let installed = blocks.type_capability(result.block_type)? == TypeCapability::Installed;
        let key = if installed {
            let key = blocks
                .derive_key(result.block_type, result.payload, now)?
                .unwrap_or(*result.key);
            match blocks.validate(result.block_type, &key, result.payload, now)? {
                Validity::Valid => {}
                Validity::Invalid => return Err(Error::Authentication),
                Validity::Unsupported => return Err(Error::Unsupported),
            }
            key
        } else {
            // Only the original routed query key is known. This is not a
            // plugin-derived key or an authenticated cache-entry association.
            *result.key
        };
        let sender = self.peer(peer)?.identity;
        let path = self.incoming_path(
            result.payload,
            expiration,
            result.options,
            result.truncated_peer,
            result.put_path,
            result.get_path,
            result.sender_signature,
            &sender,
            now,
            true,
        )?;
        let block = Block {
            reserved: result.reserved,
            kind: result.block_type,
            options: path.options,
            expiration,
            payload: result.payload,
            truncated: path.truncated.as_ref(),
            put: path.put()?,
            get: path.get()?,
        };
        // Snapshot original pending ownership before any terminal filter
        // verdict removes a route or local query. No output does not imply no
        // pending request: a real request can filter this candidate out.
        let pending = self
            .routes
            .iter()
            .any(|route| route.until > now && route.key == *result.key)
            || self.local.queries.iter().any(|q| q.key == *result.key);
        if !pending {
            // An independent monitor still observes the complete received
            // result. It is not cache admission or a query result, and an
            // absent handler does not acquire a validated Entry capability.
            let mut stage = Vec::new();
            self.monitor_reply(
                &super::Reply {
                    key: &key,
                    kind: block.kind,
                    options: u32::from(block.options.bits()),
                    expiration,
                    payload: block.payload,
                    put: block.put,
                    get: block.get,
                    truncated: block.truncated,
                },
                &mut stage,
            )?;
            self.local.commit(stage);
            return Ok(if installed {
                Outcome::UnmatchedResult
            } else {
                Outcome::OpaqueUnmatchedResult
            });
        }
        let hash = hash512(result.payload);
        let mut outputs = Vec::new();
        let mut updates = Vec::new();
        for index in 0..self.routes.len() {
            let route = &self.routes[index];
            if route.until <= now
                || route.peer == peer
                || route.key != *result.key
                || (route.kind != 0 && route.kind != result.block_type)
                || route.filter.has_seen(&hash)
                || (!route.options.contains(RouteOptions::FIND_APPROXIMATE) && route.key != key)
            {
                continue;
            }
            let original_peer = route.peer;
            let requested = route.key;
            let options = route.options;
            let until = route.until;
            let mut filter = route.filter.duplicate()?;
            let evaluation = evaluate_reply(
                blocks,
                route.kind,
                &key,
                &route.xquery,
                &block,
                &hash,
                now,
                installed,
                &mut filter,
            )?;
            if !matches!(evaluation, ReplyEvaluation::More | ReplyEvaluation::Last) {
                continue;
            }
            self.check_frame(
                Charge::default(),
                &outputs,
                reply_length(&requested, options, &block)?,
            )?;
            outputs.try_reserve(1).map_err(|_| Error::Capacity)?;
            updates.try_reserve(1).map_err(|_| Error::Capacity)?;
            outputs.push(self.reply_to(original_peer, &requested, options, &block, now, until)?);
            updates.push((
                index,
                (evaluation != ReplyEvaluation::Last).then_some(filter),
            ));
        }
        self.reserve_outputs(&outputs)?;
        if !installed {
            // Only borrowed metadata is needed. In particular, do not copy an
            // unknown payload into Entry merely to reuse trusted cache logic.
            self.accept_opaque(
                &super::Reply {
                    key: result.key,
                    kind: block.kind,
                    options: u32::from(block.options.bits()),
                    expiration,
                    payload: block.payload,
                    put: block.put,
                    get: block.get,
                    truncated: block.truncated,
                },
                &hash,
            )?;
            self.commit_route_updates(updates);
            self.commit_outputs(outputs);
            return Ok(Outcome::OpaqueResult);
        }
        let entry = Entry {
            key,
            kind: result.block_type,
            options: u32::from(path.options.bits()),
            expiration,
            payload: copy(result.payload)?,
            hash,
            put_path: own_path(path.put)?,
            truncated_peer: path.truncated,
        };
        self.accept_entry(
            entry,
            Path::new(path.get.as_ref())?,
            Some(result.key),
            self.limits.cache_results,
            None,
            now,
            blocks,
        )?;
        self.commit_route_updates(updates);
        self.commit_outputs(outputs);
        Ok(Outcome::Result)
    }
    // Updates contain increasing original route indices. Commit in one stable
    // pass after every fallible result/output/cache preparation has succeeded;
    // deletion therefore cannot shift a later update onto a different route.
    // None is an actual FILTER_LAST decision; no native work is retired here.
    fn commit_route_updates(&mut self, updates: Vec<(usize, Option<Filter>)>) {
        let mut updates = updates.into_iter();
        let mut next = updates.next();
        let mut index = 0;
        self.routes.retain_mut(|route| {
            let update = if next
                .as_ref()
                .is_some_and(|(original, _)| *original == index)
            {
                next.take()
            } else {
                None
            };
            index += 1;
            match update {
                Some((_, filter)) => {
                    next = updates.next();
                    if let Some(filter) = filter {
                        route.filter = filter;
                        true
                    } else {
                        false
                    }
                }
                None => true,
            }
        });
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Exact sender/recipient, payload, original time and independently borrowed PUT/GET metadata are required for purpose6 verification"
    )]
    fn incoming_path<'a>(
        &self,
        payload: &[u8],
        expiration: u64,
        options: RouteOptions,
        truncated: Option<&[u8; 32]>,
        put: Path<'a>,
        get: Path<'a>,
        signature: Option<&[u8; 64]>,
        sender: &[u8; 32],
        now: u64,
        is_result: bool,
    ) -> Result<IncomingPath<'a>, Error> {
        if !options.contains(RouteOptions::RECORD_ROUTE) {
            if truncated.is_some() || !put.is_empty() || !get.is_empty() || signature.is_some() {
                return Err(Error::Authentication);
            }
            return Ok(IncomingPath {
                options,
                truncated: None,
                put: Cow::Borrowed(&[]),
                get: Cow::Borrowed(&[]),
            });
        }
        let signature = signature.ok_or(Error::Authentication)?;
        if put
            .len()
            .checked_add(get.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?
            > self.limits.path_entries
        {
            return Err(Error::Capacity);
        }
        let selected = crate::path::receive_incoming(
            payload,
            expiration,
            now,
            truncated,
            put,
            get,
            sender,
            &self.identity,
            signature,
        )?;
        let options = if selected.removed == 0 {
            options
        } else {
            options | RouteOptions::TRUNCATED
        };
        let mut appended = copy(if is_result {
            selected.get.as_bytes()
        } else {
            selected.put.as_bytes()
        })?;
        appended
            .try_reserve(dht::PATH_ELEMENT_LEN)
            .map_err(|_| Error::Capacity)?;
        // These are still the exact signature and authenticated identity of the
        // actual underlay sender, including after an older recorded failure.
        appended.extend_from_slice(signature);
        appended.extend_from_slice(sender);
        let (put, get) = if is_result {
            (Cow::Borrowed(selected.put.as_bytes()), Cow::Owned(appended))
        } else {
            (Cow::Owned(appended), Cow::Borrowed(selected.get.as_bytes()))
        };
        Ok(IncomingPath {
            options,
            truncated: selected.truncated,
            put,
            get,
        })
    }
    fn accept_opaque(&mut self, reply: &super::Reply<'_>, hash: &[u8; 64]) -> Result<(), Error> {
        let mut stage = Vec::new();
        let mut updates = Vec::new();
        for (index, q) in self.local.queries.iter().enumerate() {
            if q.key != *reply.key || (q.kind != 0 && q.kind != reply.kind) || q.seen.contains(hash)
            {
                continue;
            }
            if q.seen.len() >= self.local.limits.seen_hashes {
                return Err(Error::Capacity);
            }
            self.local.stage_reply(q, reply, &mut stage)?;
            updates.try_reserve(1).map_err(|_| Error::Capacity)?;
            updates.push(index);
        }
        self.monitor_reply(reply, &mut stage)?;
        for index in &updates {
            self.local.queries[*index]
                .seen
                .try_reserve_exact(1)
                .map_err(|_| Error::Capacity)?;
        }
        // No fallible operation remains. Exact seen denotes retained complete
        // original local output, never a Last verdict or remote delivery ACK.
        for index in updates {
            self.local.queries[index].seen.push(*hash);
        }
        self.local.commit(stage);
        Ok(())
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "The original block, response path, query key, cache policy and monitor fact remain explicit independent inputs"
    )]
    fn accept_entry(
        &mut self,
        mut entry: Entry,
        get_path: Path<'_>,
        query_hash: Option<&[u8; 64]>,
        cache: bool,
        put: Option<(u32, u32)>,
        now: u64,
        blocks: &mut impl NetworkBlocks,
    ) -> Result<(), Error> {
        let existing =
            self.local.cache.iter().position(|e| {
                e.key == entry.key && e.kind == entry.kind && e.payload == entry.payload
            });
        if cache
            && existing.is_none()
            && (self.local.cache.len() == self.local.limits.cache_records
                || self
                    .local
                    .cache_bytes
                    .checked_add(entry.payload.len())
                    .ok_or(Error::Overflow)?
                    > self.local.limits.cache_bytes)
        {
            return Err(Error::Capacity);
        }
        // All fallible local frames, filters and metadata are prepared before
        // any cache/seen/output mutation. The original query id remains intact.
        let mut local_stage = Vec::new();
        let mut updates = Vec::new();
        for (index, q) in self.local.queries.iter().enumerate() {
            if query_hash.is_some_and(|key| q.key != *key) {
                continue;
            }
            if let Some(last) =
                self.local
                    .deliver_paths(q, &entry, get_path, now, blocks, &mut local_stage)?
            {
                updates.try_reserve(1).map_err(|_| Error::Capacity)?;
                updates.push((index, last));
            }
        }
        // P2P PUT notifications belong to their separately reserved original
        // fanout. RESULT observations keep their existing local output path.
        if put.is_none() {
            self.monitor_block(&entry, get_path, None, &mut local_stage)?;
        }
        for (index, last) in &updates {
            if !last {
                let q = &mut self.local.queries[*index];
                if q.seen.len() == self.local.limits.seen_hashes {
                    return Err(Error::Capacity);
                }
                q.seen.try_reserve(1).map_err(|_| Error::Capacity)?;
            }
        }
        let replace_cache = cache
            && existing.is_none_or(|index| entry.expiration > self.local.cache[index].expiration);
        if replace_cache {
            entry
                .put_path
                .try_reserve_exact(get_path.as_bytes().len())
                .map_err(|_| Error::Capacity)?;
            let old = existing.map_or(0, |index| self.local.cache[index].put_path.capacity());
            let current = self.local.cache.iter().try_fold(0usize, |n, e| {
                n.checked_add(e.put_path.capacity()).ok_or(Error::Overflow)
            })?;
            let used = current
                .checked_sub(old)
                .and_then(|n| n.checked_add(entry.put_path.capacity()))
                .ok_or(Error::Overflow)?;
            if used > self.limits.cache_path_bytes {
                return Err(Error::Capacity);
            }
        }
        let hash = entry.hash;
        if replace_cache {
            entry.put_path.extend_from_slice(get_path.as_bytes());
            if let Some(index) = existing {
                if entry.expiration > self.local.cache[index].expiration {
                    self.local.cache[index] = entry;
                }
            } else {
                self.local.cache_bytes += entry.payload.len();
                self.local.cache.push(entry);
            }
        }
        for (index, last) in updates.into_iter().rev() {
            if last {
                self.local.queries.remove(index);
            } else {
                self.local.queries[index].seen.push(hash);
            }
        }
        self.local.commit(local_stage);
        self.prune_queries();
        Ok(())
    }
    fn monitor_get(&self, get: GetMessage<'_>, stage: &mut Vec<Output<'id>>) -> Result<(), Error> {
        for client in self.local.monitor_targets(0, get.block_type, get.key) {
            let m = ipc::MonitorGet {
                options: u32::from(get.options.bits()),
                block_type: get.block_type,
                hop_count: u32::from(get.hop_count),
                replication: u32::from(get.desired_replication_level),
                key: get.key,
            };
            let mut frame = self.monitor_frame(stage, 88)?;
            m.encode(&mut frame)?;
            stage.push(Output {
                client,
                query: None,
                correlation: None,
                bytes: frame,
            });
        }
        Ok(())
    }
    fn monitor_put(
        &self,
        put: ipc::MonitorPut<'_>,
        stage: &mut Vec<Output<'id>>,
    ) -> Result<(), Error> {
        for client in self.local.monitor_targets(2, put.block_type, put.key) {
            let mut frame = self.monitor_frame(stage, put.encoded_len()?)?;
            put.encode(&mut frame)?;
            stage.push(Output {
                client,
                query: None,
                correlation: None,
                bytes: frame,
            });
        }
        Ok(())
    }
    fn monitor_block(
        &self,
        entry: &Entry,
        get_path: Path<'_>,
        put: Option<(u32, u32)>,
        stage: &mut Vec<Output<'id>>,
    ) -> Result<(), Error> {
        if let Some((hop_count, replication)) = put {
            return self.monitor_put(
                ipc::MonitorPut {
                    options: entry.options,
                    block_type: entry.kind,
                    hop_count,
                    replication,
                    expiration: AbsoluteTime::from_micros(entry.expiration),
                    key: &entry.key,
                    truncated_peer: entry.truncated_peer.as_ref(),
                    put_path: Path::new(&entry.put_path)?,
                    payload: &entry.payload,
                },
                stage,
            );
        }
        self.monitor_reply(
            &super::Reply {
                key: &entry.key,
                kind: entry.kind,
                options: entry.options,
                expiration: entry.expiration,
                payload: &entry.payload,
                put: Path::new(&entry.put_path)?,
                get: get_path,
                truncated: entry.truncated_peer.as_ref(),
            },
            stage,
        )
    }
    fn monitor_reply(
        &self,
        reply: &super::Reply<'_>,
        stage: &mut Vec<Output<'id>>,
    ) -> Result<(), Error> {
        for client in self.local.monitor_targets(1, reply.kind, reply.key) {
            let m = ipc::MonitorResult {
                block_type: reply.kind,
                options: reply.options,
                put_path: reply.put,
                get_path: reply.get,
                expiration: AbsoluteTime::from_micros(reply.expiration),
                key: reply.key,
                truncated_peer: reply.truncated,
                payload: reply.payload,
            };
            let mut frame = self.local.frame(stage, m.encoded_len()?)?;
            m.encode(&mut frame)?;
            self.local.stage(
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
#[expect(
    clippy::too_many_arguments,
    reason = "Original query fields, concrete candidate, current time, registry fact and original filter are independent BLOCK inputs"
)]
fn evaluate_reply(
    blocks: &mut impl NetworkBlocks,
    requested: u32,
    key: &[u8; 64],
    xquery: &[u8],
    block: &Block<'_>,
    hash: &[u8; 64],
    now: u64,
    installed: bool,
    filter: &mut Filter,
) -> Result<ReplyEvaluation, Error> {
    if filter.has_seen(hash) {
        return Ok(ReplyEvaluation::Duplicate);
    }
    let evaluation = if installed {
        blocks.filtered_reply(
            requested,
            key,
            xquery,
            block.kind,
            block.payload,
            now,
            filter,
        )?
    } else {
        // Unknown XQUERY/filter semantics cannot establish irrelevant or Last.
        ReplyEvaluation::More
    };
    if evaluation == ReplyEvaluation::Unsupported {
        return Err(Error::Unsupported);
    }
    let evaluation = if requested == 0 && evaluation == ReplyEvaluation::Last {
        ReplyEvaluation::More
    } else {
        evaluation
    };
    if (filter.is_opaque() || !installed)
        && matches!(evaluation, ReplyEvaluation::More | ReplyEvaluation::Last)
    {
        filter.mark_exact(hash)?;
    }
    Ok(evaluation)
}
#[derive(Clone, Copy, Default)]
struct Charge {
    frames: usize,
    bytes: usize,
}
impl Charge {
    fn of(stage: &[Pending<'_>]) -> Result<Self, Error> {
        Ok(Self {
            frames: stage.len(),
            bytes: stage.iter().try_fold(0usize, |n, p| {
                n.checked_add(p.frame.len()).ok_or(Error::Overflow)
            })?,
        })
    }
}
fn reply_length(
    requested: &[u8; 64],
    options: RouteOptions,
    block: &Block<'_>,
) -> Result<usize, Error> {
    let zero = [0; 64];
    let mut message = block.result(requested);
    if options.contains(RouteOptions::RECORD_ROUTE) {
        message.options = message.options | RouteOptions::RECORD_ROUTE;
        message.sender_signature = Some(&zero);
    } else {
        message.options = RouteOptions::from_bits(
            message.options.bits()
                & !(RouteOptions::RECORD_ROUTE.bits() | RouteOptions::TRUNCATED.bits()),
        );
        message.put_path = Path::empty();
        message.get_path = Path::empty();
        message.truncated_peer = None;
        message.sender_signature = None;
    }
    message.encoded_len()
}
fn entry_copy(e: &Entry) -> Result<Entry, Error> {
    Ok(Entry {
        key: e.key,
        kind: e.kind,
        options: e.options,
        expiration: e.expiration,
        payload: copy(&e.payload)?,
        hash: e.hash,
        put_path: copy(&e.put_path)?,
        truncated_peer: e.truncated_peer,
    })
}
// Existing local-origin profile: retain the caller's original u32 intent and
// monitor data, but choose a bounded u16 value for a newly originated P2P GET
// or PUT. Received P2P fields never pass this boundary; their full u16 datum is
// forwarded unchanged, with fanout independently limited by routing::plan.
fn origin_replication(replication: u32) -> u16 {
    replication.min(routing::MAX_REPLICATION as u32) as u16
}
fn finite_add(now: u64, delta: u64) -> Result<u64, Error> {
    now.checked_add(delta)
        .filter(|n| *n != u64::MAX)
        .ok_or(Error::Overflow)
}
fn nonce(entropy: &mut impl Entropy) -> Result<u32, Error> {
    for _ in 0..8 {
        let mut b = [0; 4];
        entropy.fill(&mut b).map_err(|_| Error::Entropy)?;
        let n = u32::from_be_bytes(b);
        if n != u32::MAX {
            return Ok(n);
        }
    }
    Err(Error::Entropy)
}
fn copy_hashes(hashes: &[[u8; 64]]) -> Result<Vec<[u8; 64]>, Error> {
    let mut out = super::reserved(hashes.len())?;
    out.extend_from_slice(hashes);
    Ok(out)
}
fn bytes(n: usize) -> Result<Vec<u8>, Error> {
    super::bytes(n)
}
fn copy(input: &[u8]) -> Result<Vec<u8>, Error> {
    super::copy(input)
}
