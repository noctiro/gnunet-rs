//! Official GNS500/501 frontend over the actual retained business Manager.
use crate::{Bounds, Manager, Provider};
use gnunet_client::gns::{self, Lookup as WireLookup, WireId};
use gnunet_gns::{Failure, Policy, QueryId, Record};
use gnunet_service_runtime::{
    accepted::{AcceptState, SocketEvent},
    clock::{ClockSubscription, Deadline, RuntimeClock},
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions, ShutdownMode},
};
use gnunet_types::{AbsoluteTime, Duration, Error as Fault};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

/// Stable peer identity storage, independent of protocol request ID bytes.
pub struct Instance {
    marker: u8,
    dns: gnunet_dns_client_host::Instance,
}
impl Instance {
    /// Construct explicit bounded owner state; no IO is started.
    pub const fn new() -> Self {
        Self {
            marker: 1,
            dns: gnunet_dns_client_host::Instance::new(),
        }
    }
}
impl Default for Instance {
    fn default() -> Self {
        Self::new()
    }
}
/// One actual admitted client MQ. Diagnostic counters cannot recreate it.
#[derive(Clone, Copy, Debug)]
pub struct PeerId<'a> {
    owner: &'a u8,
    serial: u64,
}
impl PartialEq for PeerId<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.owner, other.owner) && self.serial == other.serial
    }
}
impl Eq for PeerId<'_> {}
impl PeerId<'_> {
    /// Project only the original serial; this grants no owner authority.
    pub const fn diagnostic(self) -> u64 {
        self.serial
    }
}
/// Native frontend resources; all are independent of record/wire identities.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneously owned client MQs.
    pub peers: usize,
    /// Calls including original response frames still draining.
    pub calls: usize,
    /// Maximum retained calls for one original client.
    pub per_peer: usize,
    /// Credits for immutable original response frames.
    pub output: Budget,
    /// Maximum bytes of one actual read or write step.
    pub io_chunk_bytes: usize,
    /// Original complete-call source/native span, never renewed by dependencies.
    pub query_timeout: Duration,
    /// First input byte through actual admission; fixed for the same frame.
    pub input_timeout: std::time::Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            peers: 32,
            calls: 64,
            per_peer: 8,
            output: Budget {
                frames: 8,
                bytes: 8 * 65535,
            },
            io_chunk_bytes: 65535,
            query_timeout: Duration(180_000_000),
            input_timeout: std::time::Duration::from_secs(15),
        }
    }
}
/// Frontend failures retain original OS/allocation causes.
#[derive(Debug)]
pub enum Error {
    /// Original protocol or resource refusal.
    Protocol(Fault),
    /// Original canonical-clock failure.
    Clock(Fault),
    /// Original operating-system IO cause.
    Io(io::Error),
    /// Original fallible allocation failure.
    Allocation(std::collections::TryReserveError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "GNS IPC: {e}"),
            Self::Clock(e) => write!(f, "GNS clock: {e}"),
            Self::Io(e) => write!(f, "GNS IPC IO: {e}"),
            Self::Allocation(e) => write!(f, "GNS IPC allocation: {e}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) | Self::Clock(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Allocation(e) => Some(e),
        }
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
/// Actual bounded frontend observations; no event claims remote consumption.
pub enum Event<'p, 'q, P: Provider> {
    /// An actual client MQ was admitted.
    Accepted {
        /// Exact original client identity.
        peer: PeerId<'p>,
        /// Actual bounded native socket diagnostics.
        diagnostics: gnunet_native::network::Diagnostics,
    },
    /// This unadmitted native connection was physically closed.
    Refused {
        /// Original accepted address.
        address: PeerAddress,
        /// Actual local rejection category.
        reason: Fault,
        /// Actual bounded native socket diagnostics.
        diagnostics: gnunet_native::network::Diagnostics,
    },
    /// An unadmitted Unix peer was physically closed after credential lookup failed.
    AdmissionFailed {
        /// Original accepted address.
        address: PeerAddress,
        /// Earlier actual bounded native diagnostics.
        diagnostics: gnunet_native::network::Diagnostics,
        /// Original kernel or group-lookup cause, without a fabricated errno.
        cause: io::Error,
    },
    /// An actual accept or socket-initialization observation.
    Accept(SocketEvent),
    /// Actual original-client input bytes.
    Read {
        /// Exact original client identity.
        peer: PeerId<'p>,
        /// Actual bytes transferred by this original operation.
        bytes: usize,
    },
    /// An original lookup was admitted, not completed.
    Lookup {
        /// Exact original client identity.
        peer: PeerId<'p>,
        /// Original logical query identity.
        query: QueryId<'q>,
        /// Original client-supplied correlation bytes.
        wire: WireId,
    },
    /// The original input was rejected; an empty result frame was queued.
    Rejected {
        /// Exact original client identity.
        peer: PeerId<'p>,
        /// Original client-supplied correlation bytes.
        wire: WireId,
        /// Actual local rejection category.
        reason: Fault,
    },
    /// An actual result frame was queued, not yet written.
    Reply {
        /// Exact original client identity.
        peer: PeerId<'p>,
        /// Original client-supplied correlation bytes.
        wire: WireId,
        /// Records actually admitted in this response frame.
        records: usize,
        /// Actual semantic failure retained independently of the wire empty set.
        failure: Option<Failure>,
    },
    /// One actual local write of the original result frame.
    Written {
        /// Exact original client identity.
        peer: PeerId<'p>,
        /// Original client-supplied correlation bytes.
        wire: WireId,
        /// Actual bytes transferred by this original operation.
        bytes: usize,
        /// True only after the complete original frame was written locally.
        complete: bool,
    },
    /// The original client MQ was physically retired.
    Closed {
        /// Exact original client identity.
        peer: PeerId<'p>,
        /// Original owned cause; absence does not imply a remote acknowledgement.
        cause: Option<Error>,
        /// Independent errors canceling only this client's original queries.
        cancel_errors: Vec<Fault>,
        /// Actual original frames discarded when closing this MQ.
        pending_frames: usize,
        /// Actual unwritten original response suffix bytes at physical close.
        pending_suffix_bytes: usize,
        /// Actual positive prefix bytes previously written from the incomplete head frame.
        partial_prefix_bytes: usize,
    },
    /// An original dependency/business observation.
    Manager(crate::manager::ProviderEvent<'q, P>),
    /// Actual DNS interception callback/source/business observation.
    Interception(crate::interceptor::Event<'p>),
    /// Canonical work is suspended; native guards remain live.
    ClockFailed(Fault),
    /// A tolerant unsupported frame was released without a lookup.
    Ignored(PeerId<'p>),
    /// Local frontend/operation scope only; shared broker Driver still retires
    /// independently in the foreground's unconditional finally path.
    Stopped,
}
#[derive(Clone, Copy)]
struct Reply<'p> {
    peer: PeerId<'p>,
    wire: WireId,
    serial: u64,
    hard: Instant,
}
struct Peer<'p> {
    id: PeerId<'p>,
    io: Framed<Reply<'p>>,
    input_hard: Option<Instant>,
    partial: Option<(Reply<'p>, usize)>,
    cancel_errors: Vec<Fault>,
    output: Vec<Reply<'p>>,
}
struct Call<'p, 'q> {
    peer: PeerId<'p>,
    query: Option<QueryId<'q>>,
    serial: u64,
    wire: WireId,
    bounds: Bounds,
    outcome: Option<Result<Vec<Record>, Failure>>,
    queued: bool,
}
/// Caller-driven frontend. Borrowing Manager keeps constructor failure from
/// destroying an already live provider and lets the foreground finally retire it.
pub struct Server<'p, 'q, P: Provider> {
    owner: &'p u8,
    manager: &'p mut Manager<'q, P>,
    dns_owner: &'p gnunet_dns_client_host::Instance,
    interception: Option<crate::interceptor::Interceptor<'p, 'q>>,
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    refused_clock: bool,
    options: ServiceOptions,
    unix: UnixAccess,
    limits: Limits,
    peers: Vec<Peer<'p>>,
    calls: Vec<Call<'p, 'q>>,
    peer_serial: u64,
    call_serial: u64,
    peer_cursor: usize,
    call_cursor: usize,
    listener_cursor: usize,
    phase: usize,
    accept: AcceptState,
    stopping: Option<ShutdownMode>,
    manager_stopping: bool,
    stopped: bool,
    alarm: Option<Pin<Box<Sleep>>>,
    alarm_at: Option<Instant>,
    logical: Option<Pin<Box<Deadline>>>,
    logical_at: Option<AbsoluteTime>,
}
impl<'p, 'q, P: Provider> Server<'p, 'q, P> {
    /// Construct explicit bounded owner state; no IO is started.
    pub fn new(
        instance: &'p mut Instance,
        manager: &'p mut Manager<'q, P>,
        clock: Arc<dyn RuntimeClock>,
        options: ServiceOptions,
        unix: UnixAccess,
        limits: Limits,
    ) -> Result<Self, Error> {
        if instance.marker != 1
            || manager.queries() != 0
            || limits.peers == 0
            || limits.calls == 0
            || limits.per_peer == 0
            || limits.per_peer > limits.calls
            || limits.output.frames == 0
            || limits.output.bytes < 12
            || limits.io_chunk_bytes == 0
            || limits.query_timeout.0 == 0
            || limits.query_timeout.0 == u64::MAX
            || limits.input_timeout.is_zero()
            || Instant::now().checked_add(limits.input_timeout).is_none()
            || Instant::now()
                .checked_add(std::time::Duration::from_micros(limits.query_timeout.0))
                .is_none()
        {
            return Err(Fault::InvalidInput.into());
        }
        let mut peers = Vec::new();
        peers
            .try_reserve_exact(limits.peers)
            .map_err(Error::Allocation)?;
        let mut calls = Vec::new();
        calls
            .try_reserve_exact(limits.calls)
            .map_err(Error::Allocation)?;
        let subscription = clock.subscribe().map_err(Error::Clock)?;
        let sample = clock.sample().map_err(Error::Clock)?;
        Ok(Self {
            owner: &instance.marker,
            manager,
            dns_owner: &instance.dns,
            interception: None,
            clock,
            subscription: Some(subscription),
            revision: sample.revision,
            refused_clock: false,
            options,
            unix,
            limits,
            peers,
            calls,
            peer_serial: 0,
            call_serial: 0,
            peer_cursor: 0,
            call_cursor: 0,
            listener_cursor: 0,
            phase: 0,
            accept: AcceptState::default(),
            stopping: None,
            manager_stopping: false,
            stopped: false,
            alarm: None,
            alarm_at: None,
            logical: None,
            logical_at: None,
        })
    }
    /// Number of actual retained client MQs.
    pub fn peers(&self) -> usize {
        self.peers.len()
    }
    /// Number of original retained calls including output debt.
    pub fn calls(&self) -> usize {
        self.calls.len()
    }
    /// Borrow the same original business owner.
    pub fn manager(&self) -> &Manager<'q, P> {
        self.manager
    }
    /// Attach the configured DNS PRE_RESOLUTION source before ordinary clients
    /// start. DNS callbacks use this same Manager and exact clock, without RPC
    /// through the GNS service socket or another dependency owner.
    pub fn enable_interception(
        &mut self,
        source: gnunet_client_host::EndpointSource,
        configuration: gnunet_config::Configuration,
        limits: crate::interceptor::Limits,
    ) -> Result<(), crate::interceptor::Error> {
        if self.interception.is_some()
            || self.stopping.is_some()
            || !self.peers.is_empty()
            || self.manager.queries() != 0
        {
            return Err(crate::interceptor::Error::Protocol(Fault::Conflict));
        }
        self.interception = Some(crate::interceptor::Interceptor::new(
            self.dns_owner,
            source,
            &self.clock,
            configuration,
            limits,
        )?);
        Ok(())
    }
    /// Foreground-only explicit native source recovery; cannot recreate receipts.
    pub fn provider_mut(&mut self) -> &mut P {
        self.manager.provider_mut()
    }
    /// Whether new canonical processing is currently suspended.
    pub fn clock_suspended(&self) -> bool {
        self.refused_clock
    }
    /// Restore only the same clock port; original calls, frames and bounds survive.
    pub fn recover_clock(&mut self) -> Result<(), Error> {
        self.subscription = None;
        self.subscription = Some(self.clock.subscribe().map_err(Error::Clock)?);
        let sample = self.clock.sample().map_err(Error::Clock)?;
        self.revision = sample.revision;
        self.refused_clock = false;
        self.logical = None;
        self.logical_at = None;
        Ok(())
    }
    /// Fence new IPC admissions. Soft retains only already admitted calls and
    /// their actual reply writes; the foreground supplies its one fixed grace.
    pub fn request_stop(&mut self, mode: ShutdownMode) {
        self.stopping.get_or_insert(mode);
        if let Some(interceptor) = &mut self.interception {
            interceptor.begin_close(self.manager, mode == ShutdownMode::Immediate);
        }
    }
    /// Escalation uses no clock and creates no new grace or source owner.
    pub fn force_stop(&mut self) {
        self.stopping = Some(ShutdownMode::Immediate);
        if let Some(interceptor) = &mut self.interception {
            interceptor.begin_close(self.manager, true);
        }
    }
    fn close_peer(&mut self, index: usize, cause: Option<Error>) -> Event<'p, 'q, P> {
        let mut peer = self.peers.swap_remove(index);
        let pending_frames = peer.io.queued_frames();
        let pending_suffix_bytes = peer.io.remaining_bytes();
        let partial_prefix_bytes = peer.partial.map_or(0, |(_, bytes)| bytes);
        peer.io.retire(); // actual old MQ before discarding any response suffix
        self.accept.client_closed();
        let mut i = 0;
        while i < self.calls.len() {
            if self.calls[i].peer != peer.id {
                i += 1;
                continue;
            }
            if let Some(query) = self.calls[i].query {
                if let Err(error) = self.manager.cancel(query) {
                    peer.cancel_errors.push(error);
                }
                i += 1; // keep original query/native cleanup debt until taken
            } else {
                self.calls.swap_remove(i);
            }
        }
        Event::Closed {
            peer: peer.id,
            cause,
            cancel_errors: peer.cancel_errors,
            pending_frames,
            pending_suffix_bytes,
            partial_prefix_bytes,
        }
    }
    fn native_expiry(&mut self, cx: &mut Context<'_>) -> Result<Option<Event<'p, 'q, P>>, Error> {
        if let Some(event) = self.manager.poll_native_guard(cx)? {
            return Ok(Some(Event::Manager(event)));
        }
        if let Some(interceptor) = &mut self.interception
            && let Some(event) = interceptor.poll_native_guard(cx, self.manager)
        {
            return Ok(Some(Event::Interception(event)));
        }
        let now = Instant::now();
        if let Some(i) = self
            .peers
            .iter()
            .position(|peer| peer.input_hard.is_some_and(|hard| now >= hard))
        {
            return Ok(Some(self.close_peer(i, Some(Fault::Timeout.into()))));
        }
        if let Some(i) = self
            .peers
            .iter()
            .position(|peer| peer.output.iter().any(|reply| now >= reply.hard))
        {
            return Ok(Some(self.close_peer(i, Some(Fault::Timeout.into()))));
        }
        let target = self
            .peers
            .iter()
            .filter_map(|peer| peer.input_hard)
            .chain(
                self.peers
                    .iter()
                    .flat_map(|peer| peer.output.iter().map(|reply| reply.hard)),
            )
            .min();
        if self.alarm_at != target {
            self.alarm_at = target;
            self.alarm = target.map(|at| Box::pin(tokio::time::sleep_until(at)));
        }
        if let Some(alarm) = &mut self.alarm
            && alarm.as_mut().poll(cx).is_ready()
        {
            cx.waker().wake_by_ref();
        }
        Ok(None)
    }
    /// Native-first guards, usable before a foreground canonical time read.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Result<Option<Event<'p, 'q, P>>, Error> {
        self.native_expiry(cx)
    }
    fn sample(&mut self, cx: &mut Context<'_>) -> Result<Option<AbsoluteTime>, Fault> {
        let Some(subscription) = &mut self.subscription else {
            return Err(Fault::NotReady);
        };
        if let Poll::Ready(result) = subscription.poll_changed(cx, self.revision) {
            self.revision = result?.revision;
        }
        let sample = self.clock.sample()?;
        if let Poll::Ready(result) = subscription.poll_changed(cx, sample.revision) {
            result?;
            cx.waker().wake_by_ref();
            return Ok(None);
        }
        self.revision = sample.revision;
        Ok(Some(sample.now))
    }
    fn accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
    ) -> Result<Option<Event<'p, 'q, P>>, Error> {
        if self.stopping.is_some() || !self.accept.ready() || listeners.is_empty() {
            return Ok(None);
        }
        for _ in 0..listeners.len() {
            let i = self.listener_cursor % listeners.len();
            self.listener_cursor = (i + 1) % listeners.len();
            let accepted = match listeners[i].poll_canonical_connection(cx) {
                Poll::Pending => continue,
                Poll::Ready(Err(error)) => {
                    return Ok(Some(Event::Accept(self.accept.failed(error))));
                }
                Poll::Ready(Ok(accepted)) => accepted,
            };
            let (connection, address, diagnostics) = accepted.into_parts();
            if self.peers.len() == self.limits.peers {
                drop(connection);
                return Ok(Some(Event::Refused {
                    address,
                    diagnostics,
                    reason: Fault::Capacity,
                }));
            }
            let allowed = match address {
                PeerAddress::Unix => match self.unix.allows(&connection) {
                    Ok(allowed) => allowed,
                    Err(cause) => {
                        drop(connection);
                        return Ok(Some(Event::AdmissionFailed {
                            address,
                            diagnostics,
                            cause,
                        }));
                    }
                },
                PeerAddress::Tcp(address) => self.options.access.allows(address.ip()),
            };
            if !allowed || self.peers.len() == self.limits.peers {
                drop(connection);
                return Ok(Some(Event::Refused {
                    address,
                    diagnostics,
                    reason: if allowed {
                        Fault::Capacity
                    } else {
                        Fault::PermissionDenied
                    },
                }));
            }
            let serial = self.peer_serial.checked_add(1).ok_or(Fault::Overflow)?;
            let mut cancel_errors = Vec::new();
            cancel_errors
                .try_reserve_exact(self.limits.per_peer)
                .map_err(Error::Allocation)?;
            let mut output = Vec::new();
            output
                .try_reserve_exact(self.limits.output.frames)
                .map_err(Error::Allocation)?;
            let io = Framed::new(
                connection,
                FrameLimits {
                    frame_bytes: 65535,
                    ordinary: self.limits.output,
                    reserved: Budget::default(),
                    accounting: Accounting::Retained,
                    io_slice_bytes: self.limits.io_chunk_bytes,
                },
            )?;
            let peer = PeerId {
                owner: self.owner,
                serial,
            };
            self.peer_serial = serial;
            self.peers.push(Peer {
                id: peer,
                io,
                input_hard: None,
                partial: None,
                cancel_errors,
                output,
            });
            return Ok(Some(Event::Accepted { peer, diagnostics }));
        }
        Ok(None)
    }
    fn reject(
        &mut self,
        i: usize,
        wire: WireId,
        reason: Fault,
    ) -> Result<Option<Event<'p, 'q, P>>, Error> {
        if !self.peers[i].io.capacity(12, Class::Ordinary) {
            return Ok(None);
        }
        self.peers[i].io.reserve(12, Class::Ordinary)?;
        let serial = self.call_serial.checked_add(1).ok_or(Fault::Overflow)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(12).map_err(Error::Allocation)?;
        bytes.resize(12, 0);
        gns::encode_result(wire, &[], &mut bytes)?;
        let peer = self.peers[i].id;
        let hard = self.peers[i].input_hard.ok_or(Fault::NotReady)?;
        let origin = Reply {
            peer,
            wire,
            serial,
            hard,
        };
        self.peers[i]
            .io
            .enqueue_owned(OwnedFrame::new(bytes), origin, Class::Ordinary)
            .map_err(|rejected| Error::Protocol(rejected.reason))?;
        self.peers[i].output.push(origin);
        self.call_serial = serial;
        self.peers[i].io.release_frame();
        self.peers[i].input_hard = None;
        Ok(Some(Event::Rejected { peer, wire, reason }))
    }
    fn dispatch(
        &mut self,
        i: usize,
        now: AbsoluteTime,
        native: Instant,
    ) -> Result<Option<Event<'p, 'q, P>>, Error> {
        if self.stopping.is_some() {
            return Ok(None);
        }
        let peer = self.peers[i].id;
        let frame = self.peers[i].io.frame().ok_or(Fault::NotReady)?;
        if frame.get(2..4) != Some(500u16.to_be_bytes().as_slice()) {
            if self.options.tolerant {
                self.peers[i].io.release_frame();
                self.peers[i].input_hard = None;
                return Ok(Some(Event::Ignored(peer)));
            }
            return Ok(Some(self.close_peer(i, Some(Fault::Unsupported.into()))));
        }
        let Some(id) = frame.get(4..8) else {
            return Ok(Some(self.close_peer(i, Some(Fault::Truncated.into()))));
        };
        let wire = WireId(id.try_into().map_err(|_| Fault::Truncated)?);
        let lookup = match WireLookup::decode(frame) {
            Ok(value) => value,
            Err(reason) => return self.reject(i, wire, reason),
        };
        let name = match std::str::from_utf8(lookup.name()) {
            Ok(value) => value,
            Err(_) => return self.reject(i, wire, Fault::Malformed),
        };
        let parameters = lookup.parameters();
        let policy = match Policy::from_local_options(parameters.options.bits()) {
            Ok(value) => value,
            Err(reason) => return self.reject(i, wire, reason),
        };
        if self.calls.len() == self.limits.calls
            || self.calls.iter().filter(|call| call.peer == peer).count() == self.limits.per_peer
        {
            return Ok(None); // keep the same complete frame under real backpressure
        }
        if self.peers[i]
            .input_hard
            .is_some_and(|hard| Instant::now() >= hard)
        {
            return Ok(Some(self.close_peer(i, Some(Fault::Timeout.into()))));
        }
        let serial = self.call_serial.checked_add(1).ok_or(Fault::Overflow)?;
        let until = AbsoluteTime::from_micros(
            now.as_micros()
                .checked_add(self.limits.query_timeout.0)
                .ok_or(Fault::Overflow)?,
        );
        let hard = native
            .checked_add(std::time::Duration::from_micros(
                self.limits.query_timeout.0,
            ))
            .ok_or(Fault::Overflow)?;
        let bounds = Bounds::new(until, hard)?;
        let query = match self.manager.lookup(
            gnunet_gns::Lookup {
                zone: parameters.zone,
                name,
                record_type: parameters.record_type,
                policy,
                recursion_limit: parameters.recursion_depth,
            },
            bounds,
            now,
        ) {
            Ok(query) => query,
            Err(Fault::WouldBlock) => return Ok(None),
            Err(reason) => return self.reject(i, wire, reason),
        };
        self.call_serial = serial;
        self.calls.push(Call {
            peer,
            query: Some(query),
            serial,
            wire,
            bounds,
            outcome: None,
            queued: false,
        });
        if self.peers[i]
            .input_hard
            .is_some_and(|hard| Instant::now() >= hard)
        {
            return Ok(Some(self.close_peer(i, Some(Fault::Timeout.into()))));
        }
        self.peers[i].io.release_frame();
        self.peers[i].input_hard = None;
        Ok(Some(Event::Lookup { peer, query, wire }))
    }
    fn poll_peers(
        &mut self,
        cx: &mut Context<'_>,
        now: Option<(AbsoluteTime, Instant)>,
    ) -> Result<Option<Event<'p, 'q, P>>, Error> {
        for _ in 0..self.peers.len() {
            let i = self.peer_cursor % self.peers.len();
            self.peer_cursor = (i + 1) % self.peers.len();
            if self.stopping == Some(ShutdownMode::Immediate)
                || self.stopping == Some(ShutdownMode::Soft)
                    && !self.calls.iter().any(|call| call.peer == self.peers[i].id)
                    && self.peers[i].io.queued_frames() == 0
            {
                return Ok(Some(self.close_peer(i, None)));
            }
            let peer = self.peers[i].id;
            match self.peers[i].io.poll_write(cx) {
                Poll::Ready(Err(error)) => {
                    return Ok(Some(self.close_peer(i, Some(Error::Io(error)))));
                }
                Poll::Ready(Ok(progress)) => {
                    if progress.origin.peer != peer {
                        return Err(Fault::Stale.into());
                    }
                    if progress.complete {
                        self.peers[i].partial = None;
                        self.peers[i]
                            .output
                            .retain(|reply| reply.serial != progress.origin.serial);
                        self.calls.retain(|call| {
                            call.peer != peer || call.serial != progress.origin.serial
                        });
                    } else {
                        let old = self.peers[i]
                            .partial
                            .filter(|(reply, _)| reply.serial == progress.origin.serial)
                            .map_or(0, |(_, bytes)| bytes);
                        self.peers[i].partial = Some((
                            progress.origin,
                            old.checked_add(progress.bytes).ok_or(Fault::Overflow)?,
                        ));
                    }
                    return Ok(Some(Event::Written {
                        peer,
                        wire: progress.origin.wire,
                        bytes: progress.bytes,
                        complete: progress.complete,
                    }));
                }
                Poll::Pending => {}
            }
            if self.stopping.is_some() {
                continue;
            }
            let Some((now, native)) = now else {
                continue;
            };
            if self.peers[i].io.frame().is_some() {
                if let Some(event) = self.dispatch(i, now, native)? {
                    return Ok(Some(event));
                }
                continue;
            }
            let started = Instant::now();
            match self.peers[i].io.poll_read(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => {
                    return Ok(Some(self.close_peer(i, Some(Error::Io(error)))));
                }
                Poll::Ready(Ok(ReadStep::Eof)) => return Ok(Some(self.close_peer(i, None))),
                Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                    if self.peers[i].input_hard.is_none() {
                        self.peers[i].input_hard = Some(
                            started
                                .checked_add(self.limits.input_timeout)
                                .ok_or(Fault::Overflow)?,
                        );
                    }
                    return Ok(Some(Event::Read { peer, bytes }));
                }
            }
        }
        Ok(None)
    }
    fn replies(&mut self) -> Result<Option<Event<'p, 'q, P>>, Error> {
        for _ in 0..self.calls.len() {
            let i = self.call_cursor % self.calls.len();
            self.call_cursor = (i + 1) % self.calls.len();
            if self.calls[i].queued {
                continue;
            }
            if self.calls[i].outcome.is_none() {
                let Some(query) = self.calls[i].query else {
                    return Err(Fault::NotReady.into());
                };
                let Some(outcome) = self.manager.take_result(query)? else {
                    continue;
                };
                self.calls[i].query = None;
                self.calls[i].outcome = Some(outcome);
            }
            let peer = self.calls[i].peer;
            let Some(p) = self.peers.iter().position(|candidate| candidate.id == peer) else {
                self.calls.swap_remove(i);
                continue;
            };
            if self.stopping == Some(ShutdownMode::Immediate) {
                continue;
            }
            let outcome = self.calls[i].outcome.as_ref().ok_or(Fault::NotReady)?;
            let mut failure = outcome.as_ref().err().copied();
            let mut views = Vec::new();
            if let Ok(records) = outcome {
                views
                    .try_reserve_exact(records.len())
                    .map_err(Error::Allocation)?;
                views.extend(records.iter().map(Record::as_data));
            }
            let body = match gnunet_gnsrecord::serialized_len(&views)
                .and_then(|body| body.checked_add(12).ok_or(Fault::Overflow))
            {
                Ok(bytes) if bytes <= 65535 => bytes,
                Ok(_) | Err(_) => {
                    failure = Some(Failure::Fault(Fault::TooLarge));
                    views.clear();
                    12
                }
            };
            if !self.peers[p].io.capacity(body, Class::Ordinary) {
                continue;
            }
            self.peers[p].io.reserve(body, Class::Ordinary)?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(body).map_err(Error::Allocation)?;
            bytes.resize(body, 0);
            let wire = self.calls[i].wire;
            gns::encode_result(wire, &views, &mut bytes)?;
            let origin = Reply {
                peer,
                wire,
                serial: self.calls[i].serial,
                hard: self.calls[i].bounds.hard(),
            };
            self.peers[p]
                .io
                .enqueue_owned(OwnedFrame::new(bytes), origin, Class::Ordinary)
                .map_err(|rejected| Error::Protocol(rejected.reason))?;
            self.peers[p].output.push(origin);
            let records = views.len();
            drop(views);
            self.calls[i].queued = true;
            self.calls[i].outcome = None;
            return Ok(Some(Event::Reply {
                peer,
                wire,
                records,
                failure,
            }));
        }
        Ok(None)
    }
    fn begin_manager_stop(&mut self) -> Result<(), Error> {
        if !self.manager_stopping {
            self.manager_stopping = true;
            self.manager.begin_close()?;
        }
        Ok(())
    }
    /// One real frontend/dependency observation. Caller must gate Stop/Reporter
    /// before each poll and retain every returned owned error/report.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
    ) -> Poll<Result<Event<'p, 'q, P>, Error>> {
        if let Some(event) = self.native_expiry(cx)? {
            return Poll::Ready(Ok(event));
        }
        if self.stopped {
            return Poll::Pending;
        }
        if self.stopping == Some(ShutdownMode::Immediate) {
            if !self.peers.is_empty() {
                return Poll::Ready(Ok(self.close_peer(0, None)));
            }
            self.begin_manager_stop()?;
        } else if self.stopping == Some(ShutdownMode::Soft)
            && self.peers.is_empty()
            && self
                .interception
                .as_ref()
                .is_none_or(crate::interceptor::Interceptor::is_stopped)
        {
            // The original DNS callback/drop/output drain still needs its same
            // clock while Manager retires canceled interception lookups. Stop
            // the shared provider only after that source is actually closed.
            self.begin_manager_stop()?;
        }
        let native = Instant::now(); // before the canonical sample/setup span
        let now = if self.manager_stopping || self.refused_clock {
            None
        } else {
            match self.sample(cx) {
                Ok(Some(now)) => Some((now, native)),
                Ok(None) => return Poll::Pending,
                Err(error) => {
                    self.refused_clock = true;
                    self.logical = None;
                    self.logical_at = None;
                    return Poll::Ready(Ok(Event::ClockFailed(error)));
                }
            }
        };
        let classes = if self.interception.is_some() { 5 } else { 4 };
        for _ in 0..classes {
            let phase = self.phase;
            self.phase = (phase + 1) % classes;
            let event = match phase {
                0 if now.is_some() => self.accept(cx, listeners)?,
                1 => self.poll_peers(cx, now)?,
                2 => {
                    let result = match now {
                        Some((now, _)) => self.manager.poll(cx, now),
                        None => self.manager.poll_close(cx),
                    };
                    match result {
                        Poll::Pending => None,
                        Poll::Ready(Ok(event)) => Some(Event::Manager(event)),
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error.into())),
                    }
                }
                3 if now.is_some() || self.manager_stopping => self.replies()?,
                4 => match self.interception.as_mut() {
                    Some(interceptor) => {
                        match interceptor.poll(cx, self.manager, now.map(|(n, _)| n)) {
                            Poll::Ready(event) => Some(Event::Interception(event)),
                            Poll::Pending => None,
                        }
                    }
                    None => None,
                },
                _ => None,
            };
            if let Some(event) = event {
                return Poll::Ready(Ok(event));
            }
        }
        if self.manager_stopping
            && self.peers.is_empty()
            && self.manager.is_quiescent()
            && self
                .interception
                .as_ref()
                .is_none_or(crate::interceptor::Interceptor::is_stopped)
        {
            // Consume canceled/completed logical rows after all real native tasks
            // retired. No output is manufactured for already closed clients.
            let mut i = 0;
            while i < self.calls.len() {
                if let Some(query) = self.calls[i].query
                    && self.manager.take_result(query)?.is_none()
                {
                    i += 1;
                    continue;
                }
                self.calls.swap_remove(i);
            }
            if self.calls.is_empty() {
                self.stopped = true;
                self.subscription = None;
                self.logical = None;
                return Poll::Ready(Ok(Event::Stopped));
            }
        }
        if now.is_some() {
            let target = self.manager.next_wakeup();
            if target != self.logical_at {
                self.logical_at = target;
                self.logical = match target {
                    Some(at) => Some(Box::pin(
                        Deadline::at(self.clock.clone(), at).map_err(Error::Clock)?,
                    )),
                    None => None,
                };
            }
            if let Some(logical) = &mut self.logical
                && let Poll::Ready(result) = logical.as_mut().poll(cx)
            {
                result.map_err(Error::Clock)?;
                self.logical = None;
                self.logical_at = None;
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
}
