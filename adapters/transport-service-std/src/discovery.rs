//! Actual external PEERSTORE discovery. This is a cache of dial candidates, never
//! communicator authentication or an authenticated remote endpoint. One general
//! iterator MQ and an explicit fixed pool of per-peer monitor MQs are driven by
//! the caller. No socket, task, Resolver or thread is hidden in `visit`.
use crate::time::{Bounds, Clock};
use gnunet_crypto::EddsaPublicKey;
use gnunet_hello::{AbsoluteTime, Hello, SignatureCoverage, SignatureProfile};
/// Original endpoint/native failure. No cache result fabricates service success.
pub use gnunet_peerstore_client_host::Error;
use gnunet_peerstore_client_host::{
    Client, Command, EndpointSource, Epoch, Filter, Instance, Kind, Limits as NativeLimits,
    Observation, Operation, Outcome, Progress, RecordPhase,
};
use gnunet_transport::PeerId;
use gnunet_transport_host::discovery::{AddressSource, Visit, VisitControl};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::MessageHeader;
use std::{
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Public ordinary HELLO record namespace (not the signed-own-address record).
pub const HELLO_SUBSYSTEM: &[u8] = b"peerstore";
/// `GNUNET_PEERSTORE_HELLO_KEY` from the pinned public header.
pub const HELLO_KEY: &[u8] = b"peerstore-peer-hello-uri";
/// Public successful-validation URL cache namespace.
pub const URL_SUBSYSTEM: &[u8] = b"transport";
/// `GNUNET_PEERSTORE_TRANSPORT_URLADDRESS_KEY`; values have one final NUL.
pub const URL_KEY: &[u8] = b"transport-communicator-url";
/// Explicit local budgets, separate from official record expiration.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneously desired peers, exactly the monitor Instance count.
    pub peers: usize,
    /// Fixed shared candidate metadata slots.
    pub cache_records: usize,
    /// Sum of actual allocated candidate byte capacities, excluding fixed metadata.
    pub cache_bytes: usize,
    /// Maximum native communicator address bytes, excluding final NUL.
    pub address_bytes: usize,
    /// Complete binary HELLO and canonical parser scratch byte cap.
    pub hello_bytes: usize,
    /// Canonical address count cap for the existing bounded HELLO parser.
    pub hello_addresses: usize,
    /// Maximum HELLO addresses ingested from one retained record per poll.
    pub record_quantum: NonZeroUsize,
    /// Maximum actual native progress events per poll, with round-robin sources.
    pub io_quantum: NonZeroUsize,
    /// Original read-only iterator lifetime; a failed round is not a cache miss.
    pub query_lifetime: Duration,
    /// Interval between fresh successful URL scans; each has its own original RID.
    pub query_refresh: Duration,
    /// Original monitor lifetime; renewal is a fresh operation and actual SYNC.
    pub monitor_lifetime: Duration,
    /// Retire a peer intent not visited by the application within this native interval.
    /// New visits renew demand only, never an existing query/frame/source deadline.
    pub idle: Duration,
    /// Fixed source admission-to-first-complete-record/SYNC/END native bound.
    pub initialization: Duration,
    /// First partial read/write byte to that whole frame, never refreshed by bytes.
    pub partial_frame: Duration,
    /// Fresh read-only retry delay after a terminal round; no expired RID replay.
    pub retry: Duration,
    /// Finite grace for original cancelled iterator suffix/STOP retirement.
    pub retirement: Duration,
    /// Explicit upstream HELLO signature build profile; no fallback guessing.
    pub signature_profile: SignatureProfile,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            peers: 16,
            cache_records: 256,
            cache_bytes: 256 * 1024,
            address_bytes: 4096,
            hello_bytes: 65535,
            hello_addresses: 256,
            record_quantum: NonZeroUsize::new(16).unwrap_or(NonZeroUsize::MIN),
            io_quantum: NonZeroUsize::new(8).unwrap_or(NonZeroUsize::MIN),
            query_lifetime: Duration::from_secs(30),
            query_refresh: Duration::from_secs(60),
            monitor_lifetime: Duration::from_secs(300),
            idle: Duration::from_secs(600),
            initialization: Duration::from_secs(10),
            partial_frame: Duration::from_secs(5),
            retry: Duration::from_secs(1),
            retirement: Duration::from_secs(5),
            signature_profile: SignatureProfile::Gnunet029,
        }
    }
}
impl Limits {
    fn validate(self, native: NativeLimits, monitors: usize) -> Result<(), ProtocolError> {
        if self.peers == 0
            || self.peers != monitors
            || native.operations < self.peers
            || self.cache_records == 0
            || self.cache_bytes < self.address_bytes
            || self.address_bytes == 0
            || self.hello_bytes < gnunet_hello::MESSAGE_FIXED_LEN
            || self.hello_bytes > native.frame_bytes
            || self.hello_addresses == 0
            || self.query_lifetime.is_zero()
            || self.query_refresh.is_zero()
            || self.monitor_lifetime.is_zero()
            || self.idle.is_zero()
            || self.initialization.is_zero()
            || self.partial_frame.is_zero()
            || self.retry.is_zero()
            || self.retirement.is_zero()
        {
            return Err(ProtocolError::InvalidInput);
        }
        // Fixed metadata and worst-case retained original record bounds must be
        // representable, as well as the caller-supplied native per-MQ budgets.
        self.peers
            .checked_add(1)
            .and_then(|n| n.checked_mul(native.frame_bytes))
            .ok_or(ProtocolError::Overflow)?;
        self.cache_records
            .checked_mul(core::mem::size_of::<Option<Candidate<'_>>>())
            .ok_or(ProtocolError::Overflow)?;
        for d in [
            self.query_lifetime,
            self.query_refresh,
            self.monitor_lifetime,
            self.idle,
            self.initialization,
            self.partial_frame,
            self.retry,
            self.retirement,
        ] {
            let us = u64::try_from(d.as_micros()).map_err(|_| ProtocolError::Overflow)?;
            if us == 0 || us == u64::MAX {
                return Err(ProtocolError::InvalidInput);
            }
            Instant::now()
                .checked_add(d)
                .ok_or(ProtocolError::Overflow)?;
        }
        Ok(())
    }
}
/// Which real original MQ supplied an observation. A peer is a requested cache
/// selector, not a claim that this source authenticated that remote peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    /// Shared general iterator MQ.
    Queries,
    /// Dedicated HELLO monitor MQ for this desired peer.
    Monitor(PeerId),
    /// Never-admitted fixed monitor owner, relevant only to independent cleanup.
    VacantMonitor(usize),
}
/// Provenance of a retained public candidate; never a dial authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Provenance<'id> {
    /// Actual transport URL cache response, with no signature claim.
    Url {
        /// Original iterator.
        operation: Operation<'id>,
        /// Actual source epoch.
        epoch: Epoch<'id>,
    },
    /// Actual ordinary HELLO record, signature checked under the configured
    /// build profile. Normal v0.29.1 covers metadata, not its address list.
    Hello {
        /// Original monitor intent.
        operation: Operation<'id>,
        /// Actual source epoch.
        epoch: Epoch<'id>,
        /// Precisely the fields covered by the signature.
        coverage: SignatureCoverage,
        /// Actual initial/live phase on that original MQ.
        phase: RecordPhase,
    },
}
/// Borrowed candidate metadata, independent of application/transport success.
#[derive(Clone, Copy, Debug)]
pub struct CandidateView<'a, 'id> {
    /// Claimed expected peer.
    pub peer: PeerId,
    /// Native `prefix-body` address, without a wire NUL.
    pub address: &'a [u8],
    /// UTC validity from the actual record/HELLO intersection.
    pub expires: u64,
    /// Original input provenance.
    pub provenance: Provenance<'id>,
}
/// Original facts and explicit local capacity/refusal. Record payloads are not
/// logged or cloned by this layer. Callbacks run after native drive borrows end.
pub enum Event<'id> {
    /// Actual SDK observation, including original errors/exposure/credit writes.
    Native {
        /// Original source role.
        source: Source,
        /// Exact original SDK event (records use `Record` below).
        progress: Progress<'id>,
    },
    /// Actual retained RECORD, before cache ingestion; not a new network source.
    Record {
        /// Original source.
        source: Source,
        /// Original operation.
        operation: Operation<'id>,
        /// Actual source epoch.
        epoch: Epoch<'id>,
        /// Actual original iterator/initial/live phase.
        phase: RecordPhase,
        /// Complete original retained wire bytes.
        bytes: usize,
    },
    /// Cache capacity retains the exact record and withholds real NEXT credit.
    Blocked {
        /// Original source.
        source: Source,
        /// Original record operation.
        operation: Operation<'id>,
    },
    /// Invalid/expired/permanently over-policy input was consumed, without
    /// certifying a complete cache pass if a local policy limit was exceeded.
    Rejected {
        /// Original source.
        source: Source,
        /// Original operation.
        operation: Operation<'id>,
        /// Exact classified local refusal.
        reason: ProtocolError,
    },
    /// Actual native hard bound caused original physical source retirement first.
    NativeDeadline {
        /// Source stopped, not a synthetic empty result.
        source: Source,
    },
    /// Original per-peer intents and sources have actually retired locally.
    Retired {
        /// Requested peer.
        peer: PeerId,
    },
    /// Every explicit source is physically closed; no remote revoke ACK exists.
    Closed,
    /// An independent cleanup failure; all other sources are still attempted.
    Cleanup {
        /// Original source.
        source: Source,
        /// Original SDK failure.
        error: Error,
    },
}
/// One bounded caller-driven scheduling observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Step {
    /// Some real source/cache/lifecycle progress occurred.
    Progress,
    /// Caller wait elapsed, without terminating original operations.
    WaitDeadline,
    /// Permanently closed after physical cleanup.
    Closed,
}
#[derive(Clone, Copy)]
struct HelloHint<'id> {
    expires: u64,
    provenance: Provenance<'id>,
}
struct Candidate<'id> {
    hello: Option<HelloHint<'id>>,
    peer: PeerId,
    address: Vec<u8>,
    expires: u64,
    provenance: Provenance<'id>,
    serial: usize,
}
#[derive(Clone, Copy)]
struct Round<'id> {
    operation: Operation<'id>,
    bounds: Bounds,
    initial: Option<Instant>,
    terminal: bool,
    retiring: bool,
    cancel_sent: bool,
    retire_hard: Option<Instant>,
}
#[derive(Default)]
struct Guard {
    init: Option<Instant>,
    read_partial: Option<Instant>,
    write_partial: Option<Instant>,
    allocation_retry: Option<Instant>,
}
impl Guard {
    fn next(&self) -> Option<Instant> {
        minimum(
            minimum(minimum(self.init, self.read_partial), self.write_partial),
            self.allocation_retry.filter(|at| *at > Instant::now()),
        )
    }
    fn expired(&self, now: Instant) -> bool {
        minimum(minimum(self.init, self.read_partial), self.write_partial).is_some_and(|n| n <= now)
    }
    fn complete(&mut self) {
        self.init = None;
        self.read_partial = None;
    }
    fn progress(
        &mut self,
        p: &Progress<'_>,
        partial: Duration,
        retry: Duration,
    ) -> Result<(), ProtocolError> {
        self.allocation_retry = None;
        match p {
            Progress::Activity {
                read_bytes,
                written_bytes,
                ..
            } => {
                if *read_bytes != 0 && self.read_partial.is_none() {
                    self.read_partial = Some(
                        Instant::now()
                            .checked_add(partial)
                            .ok_or(ProtocolError::Overflow)?,
                    );
                }
                if *written_bytes != 0 && self.write_partial.is_none() {
                    self.write_partial = Some(
                        Instant::now()
                            .checked_add(partial)
                            .ok_or(ProtocolError::Overflow)?,
                    );
                }
            }
            Progress::Written { .. } => self.write_partial = None,
            Progress::Completed {
                outcome: Outcome::Local { .. },
                ..
            } => {}
            Progress::Record(_) | Progress::Sync { .. } | Progress::Completed { .. } => {
                self.complete()
            }
            Progress::Ignored(_) => self.read_partial = None,
            Progress::Capacity(_) => {
                self.read_partial = None;
                self.allocation_retry = Some(
                    Instant::now()
                        .checked_add(retry)
                        .ok_or(ProtocolError::Overflow)?,
                );
            }
            Progress::Lost { .. } => *self = Self::default(),
            _ => {}
        }
        Ok(())
    }
}
struct Held<'id> {
    observation: Observation<'id>,
    cursor: usize,
    verified: Option<(u64, SignatureCoverage)>,
    blocked_reported: bool,
}
struct Peer<'id> {
    client: Client<'id>,
    peer: Option<PeerId>,
    desired: bool,
    last_visit: Option<Instant>,
    monitor: Option<Round<'id>>,
    query: Option<Round<'id>>,
    synced: Option<Epoch<'id>>,
    query_complete: bool,
    query_incomplete: bool,
    monitor_incomplete: bool,
    held: Option<Held<'id>>,
    next_monitor: Option<(Operation<'id>, Epoch<'id>)>,
    next_query: Option<(Operation<'id>, Epoch<'id>)>,
    guard: Guard,
    retry_query: Option<Instant>,
    retry_monitor: Option<Instant>,
}
impl Peer<'_> {
    fn synced_now(&self) -> bool {
        self.synced.is_some()
            && self.synced == self.client.epoch()
            && self
                .monitor
                .is_some_and(|r| !r.retiring && self.client.live(r.operation))
    }
}
/// Actual fixed source/cache owner. All Instances outlive this owner; a slot can
/// change desired peer only after its old operations/observations retire. No
/// self-reference, leaked allocation, global ID or per-peer task is required.
pub struct Provider<'id> {
    query: Client<'id>,
    peers: Vec<Peer<'id>>,
    clock: Clock,
    limits: Limits,
    cache: Vec<Option<Candidate<'id>>>,
    cache_bytes: usize,
    last_candidate: usize,
    scratch: Vec<u8>,
    native_scratch: Vec<u8>,
    query_held: Option<(usize, Held<'id>)>,
    query_guard: Guard,
    cursor: usize,
    scan_remaining: usize,
    alarm: Option<Pin<Box<Sleep>>>,
    alarm_at: Option<Instant>,
    closed: bool,
    waker: Option<Waker>,
}
impl<'id> Provider<'id> {
    /// Reserve metadata and native CLIENT pools only; no IO occurs. `source`
    /// must use the exact same RuntimeClock Arc as the supplied stable Clock.
    /// Dedicated monitors each use one native operation slot. The general MQ
    /// uses caller native limits, with at least `limits.peers` operation slots.
    pub fn new(
        query_instance: &'id mut Instance,
        monitor_instances: &'id mut [Instance],
        source: EndpointSource,
        clock: Clock,
        native: NativeLimits,
        mut limits: Limits,
    ) -> Result<Self, Error> {
        limits.retirement = limits
            .retirement
            .min(Duration::from_micros(native.retirement_grace_micros));
        limits.validate(native, monitor_instances.len())?;
        if !Arc::ptr_eq(&source.clock(), &clock.source()) {
            return Err(ProtocolError::InvalidInput.into());
        }
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.peers)
            .map_err(|_| ProtocolError::Capacity)?;
        for instance in monitor_instances {
            let monitor = NativeLimits {
                operations: 1,
                ..native
            };
            peers.push(Peer {
                client: Client::new_monitor(instance, source.duplicate()?, monitor)?,
                peer: None,
                desired: false,
                last_visit: None,
                monitor: None,
                query: None,
                synced: None,
                query_complete: false,
                query_incomplete: false,
                monitor_incomplete: false,
                held: None,
                next_monitor: None,
                next_query: None,
                guard: Guard::default(),
                retry_query: None,
                retry_monitor: None,
            });
        }
        let query = Client::new(query_instance, source, native)?;
        let mut cache = Vec::new();
        cache
            .try_reserve_exact(limits.cache_records)
            .map_err(|_| ProtocolError::Capacity)?;
        cache.resize_with(limits.cache_records, || None);
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(limits.hello_bytes)
            .map_err(|_| ProtocolError::Capacity)?;
        scratch.resize(limits.hello_bytes, 0);
        let mut native_scratch = Vec::new();
        native_scratch
            .try_reserve_exact(limits.address_bytes)
            .map_err(|_| ProtocolError::Capacity)?;
        Ok(Self {
            query,
            peers,
            clock,
            limits,
            cache,
            cache_bytes: 0,
            last_candidate: 0,
            scratch,
            native_scratch,
            query_held: None,
            query_guard: Guard::default(),
            cursor: 0,
            scan_remaining: 0,
            alarm: None,
            alarm_at: None,
            closed: false,
            waker: None,
        })
    }
    fn desire(&mut self, peer: PeerId) -> Result<usize, ProtocolError> {
        if self.closed {
            return Err(ProtocolError::Closed);
        }
        let row = if let Some(i) = self.peers.iter().position(|p| p.peer == Some(peer)) {
            if !self.peers[i].desired {
                return Err(ProtocolError::WouldBlock);
            }
            i
        } else {
            let i = self
                .peers
                .iter()
                .position(|p| p.peer.is_none())
                .ok_or(ProtocolError::Capacity)?;
            self.peers[i].peer = Some(peer);
            self.peers[i].desired = true;
            self.peers[i].query_complete = false;
            self.peers[i].query_incomplete = false;
            self.peers[i].monitor_incomplete = false;
            self.peers[i].synced = None;
            if let Some(waker) = &self.waker {
                waker.wake_by_ref();
            }
            i
        };
        self.peers[row].last_visit = Some(Instant::now());
        Ok(row)
    }
    /// Enumerate only original real HELLO hints, never URL-only cache entries.
    /// The HELLO profile's exact coverage remains explicit; no address acquires
    /// authenticated reachability merely because its metadata signature passed.
    pub fn visit_hello(
        &mut self,
        peer: PeerId,
        utc: u64,
        start: usize,
        quantum: NonZeroUsize,
        visitor: &mut dyn FnMut(CandidateView<'_, 'id>) -> Result<VisitControl, ProtocolError>,
    ) -> Result<Visit, ProtocolError> {
        let row = self.desire(peer)?;
        let mut cursor = start;
        for _ in 0..quantum.get() {
            let next = self
                .cache
                .iter()
                .flatten()
                .filter(|e| {
                    e.peer == peer
                        && e.serial > cursor
                        && e.hello.is_some_and(|hint| hint.expires > utc)
                })
                .min_by_key(|e| e.serial);
            let Some(entry) = next else { break };
            let hint = entry.hello.ok_or(ProtocolError::Stale)?;
            if visitor(CandidateView {
                peer,
                address: &entry.address,
                expires: hint.expires,
                provenance: hint.provenance,
            })? == VisitControl::Pause
            {
                return Ok(Visit {
                    cursor,
                    finished: false,
                });
            }
            cursor = entry.serial;
        }
        let remaining = self.cache.iter().flatten().any(|e| {
            e.peer == peer && e.serial > cursor && e.hello.is_some_and(|hint| hint.expires > utc)
        });
        let p = &self.peers[row];
        Ok(Visit {
            cursor,
            finished: !remaining && p.synced_now() && !p.monitor_incomplete && p.held.is_none(),
        })
    }
    /// Fixed number of explicit monitor source owners.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.peers.len()
    }
    /// Peers with original currently desired read-only intents. Callers may
    /// explicitly `retire` these as soon as their last transport demand ends.
    pub fn desired_peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.peers
            .iter()
            .filter(|p| p.desired)
            .filter_map(|p| p.peer)
    }
    /// Whether the actual current monitor SYNC and successful URL END have both
    /// been observed. False also covers retained capacity/policy gaps.
    #[must_use]
    pub fn complete(&self, peer: PeerId) -> bool {
        self.peers
            .iter()
            .find(|p| p.peer == Some(peer))
            .is_some_and(|p| {
                p.desired
                    && p.query_complete
                    && p.synced_now()
                    && !p.query_incomplete
                    && !p.monitor_incomplete
                    && p.held.is_none()
                    && self
                        .query_held
                        .as_ref()
                        .is_none_or(|(i, _)| self.peers[*i].peer != Some(peer))
            })
    }
    /// Read already retained provenance without granting source or dial authority.
    #[must_use]
    pub fn candidate(&self, peer: PeerId, address: &[u8]) -> Option<CandidateView<'_, 'id>> {
        self.cache
            .iter()
            .flatten()
            .find(|e| e.peer == peer && e.address == address)
            .map(|e| CandidateView {
                peer: e.peer,
                address: &e.address,
                expires: e.expires,
                provenance: e.provenance,
            })
    }
    /// Request actual cancellation of this peer's original operations on the next
    /// poll. The slot stays occupied until their real terminal events are drained.
    /// This method does no IO and does not claim cancellation/physical retirement.
    pub fn retire(&mut self, peer: PeerId) -> Result<(), ProtocolError> {
        let p = self
            .peers
            .iter_mut()
            .find(|p| p.peer == Some(peer))
            .ok_or(ProtocolError::NotFound)?;
        p.desired = false;
        p.synced = None;
        p.query_complete = false;
        if let Some(r) = &mut p.monitor {
            r.retiring = true;
        }
        if let Some(r) = &mut p.query {
            r.retiring = true;
        }
        self.alarm = None;
        self.alarm_at = None;
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
        Ok(())
    }
    /// Retire all old Engine demands without changing the actual candidate
    /// source or inventing END/SYNC. Native cancellation/terminal debt drains
    /// under the original operation/source bounds on subsequent polls.
    pub fn retire_all(&mut self) {
        for p in &mut self.peers {
            p.desired = false;
            p.synced = None;
            p.query_complete = false;
            if let Some(r) = &mut p.monitor {
                r.retiring = true;
            }
            if let Some(r) = &mut p.query {
                r.retiring = true;
            }
        }
        self.alarm = None;
        self.alarm_at = None;
        if let Some(waker) = &self.waker {
            waker.wake_by_ref();
        }
    }
    /// Permanently stop all actual MQ owners first, without consulting a logical
    /// clock. Each cleanup result and retained original completion is reported;
    /// independent sources are closed even if one cleanup fails.
    pub fn close_all(&mut self, observe: &mut impl FnMut(Event<'id>)) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
        close_client(&mut self.query, Source::Queries, observe);
        for (slot, p) in self.peers.iter_mut().enumerate() {
            let source = p.peer.map_or(Source::VacantMonitor(slot), Source::Monitor);
            close_client(&mut p.client, source, observe);
            p.held = None;
            p.monitor = None;
            p.query = None;
            p.next_monitor = None;
            p.next_query = None;
            p.synced = None;
        }
        self.query_held = None;
        self.alarm = None;
        self.alarm_at = None;
        observe(Event::Closed);
    }
    /// Poll actual sources fairly, bounded by `io_quantum`, preserving native
    /// partial cursors when this call/future is cancelled. Hard native guards
    /// are checked and registered before any CLIENT clock wait can be pending.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Step, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Step::Closed));
        }
        self.waker = Some(cx.waker().clone());
        let result = self.poll_inner(cx, wait, observe);
        if matches!(&result, Poll::Ready(Err(_))) {
            self.close_all(observe);
        }
        result
    }
    /// Optional cancellation-safe future wrapper; the owner retains all state.
    pub async fn drive(
        &mut self,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<Step, Error> {
        std::future::poll_fn(|cx| self.poll(cx, wait, observe)).await
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Step, Error>> {
        let native_now = Instant::now();
        let mut progressed = self.native_guards(native_now, observe)?;
        // Arm native timers BEFORE any source clock/CLIENT future can wait.
        self.arm(cx, minimum(self.next_deadline(), wait));
        let utc = self.clock.sample()?.absolute().as_micros();
        progressed |= self.expire_cache(utc);
        for i in 0..self.peers.len() {
            progressed |= self.lifecycle(i, utc, observe)?;
        }
        if let Some((i, held)) = self.query_held.take() {
            progressed |= self.consume(i, false, held, utc, observe)?;
        }
        // At most one HELLO ingestion quantum per source, no extra frame copies.
        for i in 0..self.peers.len() {
            if let Some(held) = self.peers[i].held.take() {
                progressed |= self.consume(i, true, held, utc, observe)?;
            }
        }
        let count = self.peers.len() + 1;
        if self.scan_remaining == 0 {
            self.scan_remaining = count;
        }
        let scans = self.limits.io_quantum.get().min(self.scan_remaining);
        self.scan_remaining -= scans;
        for _ in 0..scans {
            let index = self.cursor % count;
            self.cursor = (self.cursor + 1) % count;
            let source = if index == 0 {
                Source::Queries
            } else {
                let Some(peer) = self.peers[index - 1].peer else {
                    continue;
                };
                Source::Monitor(peer)
            };
            let result = if index == 0 {
                if let Some(progress) = self.query.next_event() {
                    Poll::Ready(Ok(progress))
                } else {
                    if self.query_held.is_some()
                        || self.query.pending() == 0
                        || self
                            .query_guard
                            .allocation_retry
                            .is_some_and(|at| at > Instant::now())
                    {
                        continue;
                    }
                    poll_client(&mut self.query, cx)
                }
            } else {
                if let Some(progress) = self.peers[index - 1].client.next_event() {
                    Poll::Ready(Ok(progress))
                } else {
                    if self.peers[index - 1].held.is_some()
                        || self.peers[index - 1].client.pending() == 0
                        || self.peers[index - 1]
                            .guard
                            .allocation_retry
                            .is_some_and(|at| at > Instant::now())
                    {
                        continue;
                    }
                    poll_client(&mut self.peers[index - 1].client, cx)
                }
            };
            match result {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(progress)) => {
                    self.process(source, progress, observe)?;
                    progressed = true;
                }
            }
        }
        // New result/whole NEXT may have changed guards or made cache work due.
        self.arm(cx, minimum(self.next_deadline(), wait));
        if progressed {
            cx.waker().wake_by_ref();
            return Poll::Ready(Ok(Step::Progress));
        }
        if wait.is_some_and(|at| at <= Instant::now()) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        // Finish registering every source over bounded polls. Otherwise a wake
        // from a source outside this quantum could be lost behind an idle slice.
        if self.scan_remaining != 0 {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    fn native_guards(
        &mut self,
        now: Instant,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let mut changed = false;
        let query_expired = self.query_guard.expired(now)
            || self.peers.iter().any(|p| {
                p.query.is_some_and(|r| {
                    (!r.retiring && (r.bounds.hard <= now || r.initial.is_some_and(|at| at <= now)))
                        || r.retire_hard.is_some_and(|at| at <= now)
                })
            });
        if query_expired && self.query.pending() != 0 {
            // reconnect detaches its physical owner before sampling retry clock;
            // all old iterators are terminal, never replayed under a fresh RID.
            let progress = self.query.reconnect()?;
            self.query_guard = Guard::default();
            observe(Event::NativeDeadline {
                source: Source::Queries,
            });
            self.process(Source::Queries, progress, observe)?;
            changed = true;
            for p in &mut self.peers {
                if let Some(r) = &mut p.query {
                    r.retiring = true;
                    r.retire_hard = None;
                }
            }
        }
        for i in 0..self.peers.len() {
            let expired = self.peers[i].guard.expired(now)
                || self.peers[i].monitor.is_some_and(|r| {
                    (!r.retiring && (r.bounds.hard <= now || r.initial.is_some_and(|at| at <= now)))
                        || r.retire_hard.is_some_and(|h| h <= now)
                });
            if expired && self.peers[i].client.pending() != 0 {
                let peer = self.peers[i].peer.ok_or(ProtocolError::Stale)?;
                let progress = self.peers[i].client.reconnect()?;
                self.peers[i].guard = Guard::default();
                if let Some(r) = &mut self.peers[i].monitor {
                    r.retiring = true;
                    r.retire_hard = None;
                }
                observe(Event::NativeDeadline {
                    source: Source::Monitor(peer),
                });
                self.process(Source::Monitor(peer), progress, observe)?;
                changed = true;
            }
        }
        Ok(changed)
    }
    fn next_deadline(&self) -> Option<Instant> {
        let mut result = self.query_guard.next();
        for p in &self.peers {
            result = minimum(result, p.guard.next());
            if p.desired {
                result = minimum(
                    result,
                    p.last_visit.and_then(|at| at.checked_add(self.limits.idle)),
                );
            }
            for r in [p.query, p.monitor].into_iter().flatten() {
                if !r.retiring {
                    result = minimum(result, Some(r.bounds.hard));
                    result = minimum(result, r.initial);
                }
                result = minimum(result, r.retire_hard);
            }
            result = minimum(result, p.retry_query.filter(|at| *at > Instant::now()));
            result = minimum(result, p.retry_monitor.filter(|at| *at > Instant::now()));
        }
        result
    }
    fn arm(&mut self, cx: &mut Context<'_>, target: Option<Instant>) {
        if self.alarm_at != target {
            self.alarm_at = target;
            self.alarm = target.map(|at| Box::pin(tokio::time::sleep_until(at)));
        }
        if let Some(alarm) = &mut self.alarm {
            let _readiness = alarm.as_mut().poll(cx);
        }
    }
    fn lifecycle(
        &mut self,
        i: usize,
        utc: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let mut changed = false;
        let Some(peer) = self.peers[i].peer else {
            return Ok(false);
        };
        if self.peers[i].desired
            && self.peers[i].last_visit.is_some_and(|at| {
                at.checked_add(self.limits.idle)
                    .is_none_or(|until| until <= Instant::now())
            })
        {
            self.peers[i].desired = false;
            self.peers[i].synced = None;
            self.peers[i].query_complete = false;
            changed = true;
        }
        // Original terminal observations are drained by the same bounded
        // round-robin source poll as native IO, before any slot can be reused.
        for monitor in [false, true] {
            let round = if monitor {
                self.peers[i].monitor
            } else {
                self.peers[i].query
            };
            if let Some(mut r) = round {
                let client = if monitor {
                    &self.peers[i].client
                } else {
                    &self.query
                };
                if r.terminal && !present(client, r.operation) {
                    if monitor {
                        self.peers[i].monitor = None;
                    } else {
                        self.peers[i].query = None;
                    }
                    changed = true;
                    continue;
                }
                if !self.peers[i].desired {
                    r.retiring = true;
                }
                if r.retiring && !r.cancel_sent {
                    let client = if monitor {
                        &mut self.peers[i].client
                    } else {
                        &mut self.query
                    };
                    if client.live(r.operation) {
                        match client.cancel(r.operation) {
                            Ok(_) => {
                                r.cancel_sent = true;
                                r.retire_hard = Some(
                                    Instant::now()
                                        .checked_add(self.limits.retirement)
                                        .ok_or(ProtocolError::Overflow)?
                                        .min(
                                            r.bounds
                                                .hard
                                                .checked_add(self.limits.retirement)
                                                .ok_or(ProtocolError::Overflow)?,
                                        ),
                                );
                                changed = true;
                            }
                            Err(Error::Protocol(
                                ProtocolError::NotReady
                                | ProtocolError::WouldBlock
                                | ProtocolError::Capacity,
                            )) => {}
                            Err(error) => return Err(error),
                        }
                    }
                }
                if monitor {
                    self.peers[i].monitor = Some(r);
                } else {
                    self.peers[i].query = Some(r);
                }
            }
        }
        if !self.peers[i].desired {
            self.peers[i].held = None;
            self.peers[i].next_monitor = None;
            self.peers[i].next_query = None;
            if self.query_held.as_ref().is_some_and(|(row, _)| *row == i) {
                self.query_held = None;
            }
            if self.peers[i].monitor.is_none()
                && self.peers[i].query.is_none()
                && self.peers[i].client.is_idle()
            {
                self.remove_peer_cache(peer);
                self.peers[i].peer = None;
                self.peers[i].last_visit = None;
                self.peers[i].guard = Guard::default();
                self.peers[i].retry_query = None;
                self.peers[i].retry_monitor = None;
                observe(Event::Retired { peer });
                return Ok(true);
            }
            return Ok(changed);
        }
        let now = Instant::now();
        if self.peers[i].monitor.is_none()
            && self.peers[i].client.is_idle()
            && self.peers[i].retry_monitor.is_none_or(|at| at <= now)
        {
            let bounds = Bounds::after(utc, self.limits.monitor_lifetime)?;
            let filter = Filter {
                peer: Some(peer.0),
                subsystem: Some(HELLO_SUBSYSTEM),
                key: Some(HELLO_KEY),
            };
            match self.peers[i].client.monitor(filter, true, bounds.expires) {
                Ok(operation) => {
                    self.peers[i].monitor = Some(Round {
                        operation,
                        bounds,
                        initial: Some(
                            now.checked_add(self.limits.initialization)
                                .ok_or(ProtocolError::Overflow)?
                                .min(bounds.hard),
                        ),
                        terminal: false,
                        retiring: false,
                        cancel_sent: false,
                        retire_hard: None,
                    });
                    self.peers[i].synced = None;
                    self.peers[i].monitor_incomplete = false;
                    self.peers[i].retry_monitor = None;
                    self.peers[i].guard.init = Some(
                        now.checked_add(self.limits.initialization)
                            .ok_or(ProtocolError::Overflow)?
                            .min(bounds.hard),
                    );
                    changed = true;
                }
                Err(Error::Protocol(ProtocolError::WouldBlock | ProtocolError::Capacity)) => {}
                Err(error) => return Err(error),
            }
        }
        if self.peers[i].query.is_none()
            && (!self.peers[i].query_complete
                || self.peers[i].retry_query.is_some_and(|at| at <= now))
            && self.peers[i].retry_query.is_none_or(|at| at <= now)
        {
            let bounds = Bounds::after(utc, self.limits.query_lifetime)?;
            let filter = Filter {
                peer: Some(peer.0),
                subsystem: Some(URL_SUBSYSTEM),
                key: Some(URL_KEY),
            };
            match self.query.iterate(filter, bounds.expires) {
                Ok(operation) => {
                    self.peers[i].query = Some(Round {
                        operation,
                        bounds,
                        initial: Some(
                            now.checked_add(self.limits.initialization)
                                .ok_or(ProtocolError::Overflow)?
                                .min(bounds.hard),
                        ),
                        terminal: false,
                        retiring: false,
                        cancel_sent: false,
                        retire_hard: None,
                    });
                    self.peers[i].retry_query = None;
                    self.peers[i].query_complete = false;
                    self.peers[i].query_incomplete = false;
                    let init = now
                        .checked_add(self.limits.initialization)
                        .ok_or(ProtocolError::Overflow)?
                        .min(bounds.hard);
                    self.query_guard.init = minimum(self.query_guard.init, Some(init));
                    changed = true;
                }
                Err(Error::Protocol(ProtocolError::WouldBlock | ProtocolError::Capacity)) => {}
                Err(error) => return Err(error),
            }
        }
        for monitor in [false, true] {
            let pending = if monitor {
                self.peers[i].next_monitor
            } else {
                self.peers[i].next_query
            };
            if let Some((operation, epoch)) = pending {
                let client = if monitor {
                    &mut self.peers[i].client
                } else {
                    &mut self.query
                };
                if client.epoch() != Some(epoch) || !client.live(operation) {
                    if monitor {
                        self.peers[i].next_monitor = None;
                    } else {
                        self.peers[i].next_query = None;
                    }
                } else {
                    match client.next(operation, 1) {
                        Ok(()) => {
                            if monitor {
                                self.peers[i].next_monitor = None;
                            } else {
                                self.peers[i].next_query = None;
                            }
                            changed = true;
                        }
                        Err(Error::Protocol(
                            ProtocolError::NotReady
                            | ProtocolError::WouldBlock
                            | ProtocolError::Capacity,
                        )) => {}
                        Err(error) => return Err(error),
                    }
                }
            }
        }
        Ok(changed)
    }
    fn process(
        &mut self,
        source: Source,
        progress: Progress<'id>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let index = match source {
            Source::Queries => None,
            Source::VacantMonitor(_) => return Err(ProtocolError::Stale.into()),
            Source::Monitor(peer) => Some(
                self.peers
                    .iter()
                    .position(|p| p.peer == Some(peer))
                    .ok_or(ProtocolError::Stale)?,
            ),
        };
        let guard = if let Some(i) = index {
            &mut self.peers[i].guard
        } else {
            &mut self.query_guard
        };
        guard.progress(&progress, self.limits.partial_frame, self.limits.retry)?;
        if let Progress::Record(observation) = progress {
            let operation = observation.operation();
            let epoch = observation.epoch();
            let bytes = observation.bytes().len();
            let phase = observation.phase();
            let row = if let Some(i) = index {
                self.peers[i]
                    .monitor
                    .filter(|r| r.operation == operation)
                    .map(|_| i)
            } else {
                self.peers
                    .iter()
                    .position(|p| p.query.is_some_and(|r| r.operation == operation))
            };
            if let Some(i) = row {
                if let Some(round) = if index.is_some() {
                    &mut self.peers[i].monitor
                } else {
                    &mut self.peers[i].query
                } {
                    round.initial = None;
                }
                if self.peers[i].desired {
                    observe(Event::Record {
                        source,
                        operation,
                        epoch,
                        phase,
                        bytes,
                    });
                    let held = Held {
                        observation,
                        cursor: 0,
                        verified: None,
                        blocked_reported: false,
                    };
                    if index.is_some() {
                        if self.peers[i].held.is_some() {
                            return Err(ProtocolError::Capacity.into());
                        }
                        self.peers[i].held = Some(held);
                    } else {
                        if self.query_held.is_some() {
                            return Err(ProtocolError::Capacity.into());
                        }
                        self.query_held = Some((i, held));
                    }
                }
            }
            return Ok(());
        }
        match &progress {
            Progress::Sync { epoch, operation } => {
                let i = index.ok_or(ProtocolError::Malformed)?;
                if self.peers[i].desired
                    && self.peers[i]
                        .monitor
                        .is_some_and(|r| r.operation == *operation && !r.retiring)
                    && self.peers[i].client.epoch() == Some(*epoch)
                {
                    self.peers[i].synced = Some(*epoch);
                    if let Some(round) = &mut self.peers[i].monitor {
                        round.initial = None;
                    }
                }
            }
            Progress::Completed {
                operation,
                kind,
                outcome,
                ..
            } => {
                if *kind == Kind::Iteration {
                    if let Some(i) = self
                        .peers
                        .iter()
                        .position(|p| p.query.is_some_and(|r| r.operation == *operation))
                    {
                        if let Some(r) = &mut self.peers[i].query {
                            terminal(r, self.limits.retirement)?;
                        }
                        self.peers[i].next_query = None;
                        self.peers[i].query_complete = matches!(outcome, Outcome::IterationEnd(1));
                        self.peers[i].retry_query = Some(
                            Instant::now()
                                .checked_add(if self.peers[i].query_complete {
                                    self.limits.query_refresh
                                } else {
                                    self.limits.retry
                                })
                                .ok_or(ProtocolError::Overflow)?,
                        );
                    }
                } else if *kind == Kind::Monitor
                    && let Some(i) = index.filter(|i| {
                        self.peers[*i]
                            .monitor
                            .is_some_and(|r| r.operation == *operation)
                    })
                {
                    if let Some(r) = &mut self.peers[i].monitor {
                        terminal(r, self.limits.retirement)?;
                    }
                    self.peers[i].synced = None;
                    self.peers[i].next_monitor = None;
                    self.peers[i].retry_monitor = Some(
                        Instant::now()
                            .checked_add(self.limits.retry)
                            .ok_or(ProtocolError::Overflow)?,
                    );
                }
            }
            Progress::Lost { .. } => {
                if let Some(i) = index {
                    self.peers[i].synced = None;
                    self.peers[i].next_monitor = None;
                    if self.peers[i].monitor.is_some_and(|r| !r.retiring) {
                        self.peers[i].guard.init = Some(
                            Instant::now()
                                .checked_add(self.limits.initialization)
                                .ok_or(ProtocolError::Overflow)?,
                        );
                    }
                } else {
                    for p in &mut self.peers {
                        if p.query.is_some() {
                            p.query_complete = false;
                            p.next_query = None;
                        }
                    }
                }
            }
            // Actual NEXT credit remains inside the SDK until this exact whole
            // Written observation. No local guessed credit is maintained here.
            Progress::Written {
                command: Command::Next { .. },
                ..
            } => {}
            _ => {}
        }
        observe(Event::Native { source, progress });
        Ok(())
    }
    fn consume(
        &mut self,
        i: usize,
        monitor: bool,
        mut held: Held<'id>,
        utc: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        let peer = self.peers[i].peer.ok_or(ProtocolError::Stale)?;
        let source = if monitor {
            Source::Monitor(peer)
        } else {
            Source::Queries
        };
        let operation = held.observation.operation();
        let epoch = held.observation.epoch();
        let prior_cursor = held.cursor;
        if !self.peers[i].desired {
            return Ok(true);
        }
        let record = held.observation.record()?.record;
        let result: Result<bool, ProtocolError> = (|| {
            if record.peer != peer.0 {
                return Err(ProtocolError::Authentication);
            }
            if record.expiry <= utc {
                return Err(ProtocolError::Timeout);
            }
            if !monitor {
                if record.subsystem != Some(URL_SUBSYSTEM) || record.key != Some(URL_KEY) {
                    return Err(ProtocolError::Malformed);
                }
                let bytes = record
                    .value
                    .strip_suffix(&[0])
                    .ok_or(ProtocolError::Malformed)?;
                validate_native(bytes, self.limits.address_bytes)?;
                insert(
                    &mut self.cache,
                    &mut self.cache_bytes,
                    &mut self.last_candidate,
                    self.limits.cache_bytes,
                    Admission {
                        peer,
                        address: bytes,
                        expires: record.expiry,
                        provenance: Provenance::Url { operation, epoch },
                    },
                )?;
                return Ok(true);
            }
            if record.subsystem != Some(HELLO_SUBSYSTEM) || record.key != Some(HELLO_KEY) {
                return Err(ProtocolError::Malformed);
            }
            if record.value.len() > self.limits.hello_bytes {
                return Err(ProtocolError::TooLarge);
            }
            let hello_limits = gnunet_hello::Limits {
                maximum_input_bytes: self.limits.hello_bytes,
                maximum_address_bytes: self.limits.hello_bytes,
                maximum_addresses: self.limits.hello_addresses,
            };
            // The official record helper accepts an opaque record containing a
            // complete HELLO prefix and extra tail. Only the header-sized
            // original message participates in its parser/signature contract.
            let header = MessageHeader::decode(record.value)?;
            let message = record
                .value
                .get(..header.size())
                .ok_or(ProtocolError::Truncated)?;
            let hello = Hello::parse_message(
                message,
                Some(EddsaPublicKey::from_bytes(peer.0)),
                &mut self.scratch,
                hello_limits,
            )
            .map_err(|e| {
                if e == ProtocolError::Capacity {
                    ProtocolError::TooLarge
                } else {
                    e
                }
            })?;
            if hello.peer().as_bytes() != &peer.0 {
                return Err(ProtocolError::Authentication);
            }
            let (expiry, coverage) = match held.verified {
                Some(v) => v,
                None => {
                    let verified = hello.verify_at(
                        self.limits.signature_profile,
                        AbsoluteTime::from_micros(utc),
                    )?;
                    let v = (
                        record.expiry.min(hello.expiration().as_micros()),
                        verified.coverage(),
                    );
                    held.verified = Some(v);
                    v
                }
            };
            if expiry <= utc {
                return Err(ProtocolError::Timeout);
            }
            let total = hello.address_count();
            for address in hello
                .addresses()
                .skip(held.cursor)
                .take(self.limits.record_quantum.get())
            {
                let native_len = address
                    .scheme()
                    .len()
                    .checked_add(1)
                    .and_then(|n| n.checked_add(address.body().len()))
                    .ok_or(ProtocolError::TooLarge)?;
                if native_len > self.limits.address_bytes {
                    self.peers[i].monitor_incomplete = true;
                    held.cursor += 1;
                    continue;
                }
                self.native_scratch.clear();
                self.native_scratch.extend_from_slice(address.scheme());
                self.native_scratch.push(b'-');
                self.native_scratch.extend_from_slice(address.body());
                match validate_native(&self.native_scratch, self.limits.address_bytes) {
                    Ok(()) => {}
                    Err(_) => {
                        held.cursor += 1;
                        continue;
                    }
                }
                insert(
                    &mut self.cache,
                    &mut self.cache_bytes,
                    &mut self.last_candidate,
                    self.limits.cache_bytes,
                    Admission {
                        peer,
                        address: &self.native_scratch,
                        expires: expiry,
                        provenance: Provenance::Hello {
                            operation,
                            epoch,
                            coverage,
                            phase: held.observation.phase(),
                        },
                    },
                )?;
                held.cursor += 1;
            }
            Ok(held.cursor == total)
        })();
        match result {
            Ok(true) => {
                if monitor {
                    self.peers[i].next_monitor = Some((operation, epoch));
                } else {
                    self.peers[i].next_query = Some((operation, epoch));
                }
                Ok(true)
            }
            Ok(false) => {
                held.blocked_reported = false;
                if monitor {
                    self.peers[i].held = Some(held);
                } else {
                    self.query_held = Some((i, held));
                }
                Ok(true)
            }
            Err(ProtocolError::Capacity) => {
                // No false credit and no false END: preserve the exact input.
                let changed = held.cursor != prior_cursor;
                if !held.blocked_reported {
                    observe(Event::Blocked { source, operation });
                    held.blocked_reported = true;
                }
                if monitor {
                    self.peers[i].held = Some(held);
                } else {
                    self.query_held = Some((i, held));
                }
                Ok(changed)
            }
            Err(reason) => {
                if matches!(reason, ProtocolError::TooLarge | ProtocolError::Overflow) {
                    if monitor {
                        self.peers[i].monitor_incomplete = true;
                    } else {
                        self.peers[i].query_incomplete = true;
                    }
                }
                observe(Event::Rejected {
                    source,
                    operation,
                    reason,
                });
                if monitor {
                    self.peers[i].next_monitor = Some((operation, epoch));
                } else {
                    self.peers[i].next_query = Some((operation, epoch));
                }
                Ok(true)
            }
        }
    }
    fn expire_cache(&mut self, utc: u64) -> bool {
        let mut changed = false;
        for row in &mut self.cache {
            if row.as_ref().is_some_and(|entry| entry.expires <= utc)
                && let Some(entry) = row.take()
            {
                self.cache_bytes -= entry.address.capacity();
                changed = true;
            }
        }
        changed
    }
    fn remove_peer_cache(&mut self, peer: PeerId) {
        for row in &mut self.cache {
            if row.as_ref().is_some_and(|e| e.peer == peer)
                && let Some(entry) = row.take()
            {
                self.cache_bytes -= entry.address.capacity();
            }
        }
    }
}
impl AddressSource for Provider<'_> {
    fn visit(
        &mut self,
        peer: PeerId,
        utc: u64,
        start: usize,
        quantum: NonZeroUsize,
        visitor: &mut dyn FnMut(&[u8]) -> Result<VisitControl, ProtocolError>,
    ) -> Result<Visit, ProtocolError> {
        if self.closed {
            return Err(ProtocolError::Closed);
        }
        let row = self.desire(peer)?;
        let mut cursor = start;
        for _ in 0..quantum.get() {
            let next = self
                .cache
                .iter()
                .flatten()
                .filter(|e| e.peer == peer && e.expires > utc && e.serial > cursor)
                .min_by_key(|e| e.serial);
            let Some(entry) = next else {
                break;
            };
            if visitor(&entry.address)? == VisitControl::Pause {
                return Ok(Visit {
                    cursor,
                    finished: false,
                });
            }
            cursor = entry.serial;
        }
        let remaining = self
            .cache
            .iter()
            .flatten()
            .any(|e| e.peer == peer && e.expires > utc && e.serial > cursor);
        let p = &self.peers[row];
        let finished = !remaining
            && p.query_complete
            && p.synced_now()
            && !p.query_incomplete
            && !p.monitor_incomplete
            && p.held.is_none()
            && self.query_held.as_ref().is_none_or(|(i, _)| *i != row);
        Ok(Visit { cursor, finished })
    }
}
impl Drop for Provider<'_> {
    fn drop(&mut self) {
        self.close_all(&mut |_| {});
    }
}
fn present(client: &Client<'_>, operation: Operation<'_>) -> bool {
    client.credit(operation).is_ok()
}
fn terminal(round: &mut Round<'_>, grace: Duration) -> Result<(), ProtocolError> {
    round.terminal = true;
    round.retiring = true;
    round.cancel_sent = true;
    round.initial = None;
    round.retire_hard = Some(
        Instant::now()
            .checked_add(grace)
            .ok_or(ProtocolError::Overflow)?
            .min(
                round
                    .bounds
                    .hard
                    .checked_add(grace)
                    .ok_or(ProtocolError::Overflow)?,
            ),
    );
    Ok(())
}
fn poll_client<'id>(
    client: &mut Client<'id>,
    cx: &mut Context<'_>,
) -> Poll<Result<Progress<'id>, Error>> {
    // Dropping a pending drive retains its native read/write cursor in Client.
    let future = client.drive(None);
    let mut future = std::pin::pin!(future);
    future.as_mut().poll(cx)
}
fn minimum(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}
fn validate_native(bytes: &[u8], max: usize) -> Result<(), ProtocolError> {
    if bytes.len() > max {
        return Err(ProtocolError::TooLarge);
    }
    if bytes.is_empty()
        || bytes.contains(&0)
        || gnunet_hello::address_to_prefix(bytes).is_none_or(|p| p.is_empty())
    {
        return Err(ProtocolError::Malformed);
    }
    Ok(())
}
struct Admission<'a, 'id> {
    peer: PeerId,
    address: &'a [u8],
    expires: u64,
    provenance: Provenance<'id>,
}
fn insert<'id>(
    cache: &mut [Option<Candidate<'id>>],
    charged: &mut usize,
    last: &mut usize,
    max: usize,
    admission: Admission<'_, 'id>,
) -> Result<(), ProtocolError> {
    let Admission {
        peer,
        address,
        expires,
        provenance,
    } = admission;
    if let Some(entry) = cache
        .iter_mut()
        .flatten()
        .find(|e| e.peer == peer && e.address == address)
    {
        if matches!(provenance, Provenance::Hello { .. })
            && entry.hello.is_none_or(|hello| expires > hello.expires)
        {
            entry.hello = Some(HelloHint {
                expires,
                provenance,
            });
        }
        if expires > entry.expires {
            entry.expires = expires;
            entry.provenance = provenance;
        }
        return Ok(());
    }
    let slot = cache
        .iter()
        .position(Option::is_none)
        .ok_or(ProtocolError::Capacity)?;
    if address.len() > max.saturating_sub(*charged) {
        return Err(ProtocolError::Capacity);
    }
    let serial = last.checked_add(1).ok_or(ProtocolError::Overflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(address.len())
        .map_err(|_| ProtocolError::Capacity)?;
    let sum = charged
        .checked_add(bytes.capacity())
        .ok_or(ProtocolError::Capacity)?;
    if sum > max {
        return Err(ProtocolError::Capacity);
    }
    bytes.extend_from_slice(address);
    cache[slot] = Some(Candidate {
        hello: matches!(provenance, Provenance::Hello { .. }).then_some(HelloHint {
            expires,
            provenance,
        }),
        peer,
        address: bytes,
        expires,
        provenance,
        serial,
    });
    *last = serial;
    *charged = sum;
    Ok(())
}
fn close_client<'id>(
    client: &mut Client<'id>,
    source: Source,
    observe: &mut impl FnMut(Event<'id>),
) {
    match client.close() {
        Ok(Some(progress)) => observe(Event::Native { source, progress }),
        Ok(None) => {}
        Err(error) => observe(Event::Cleanup { source, error }),
    }
    while let Some(progress) = client.next_event() {
        observe(Event::Native { source, progress });
    }
}
