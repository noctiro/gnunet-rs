//! Actual caller-driven TOPOLOGY composition. No hidden Resolver, task or store.
#![forbid(unsafe_code)]
use gnunet_client_host::EndpointSource;
use gnunet_core_client_host as core;
use gnunet_peerstore_client_host as ps;
use gnunet_pils_host::client as pils;
use gnunet_service_runtime::clock::{ClockSubscription, Deadline, RuntimeClock};
use gnunet_topology::{Control, Engine, Gossip, Node, VerifiedFrame};
use gnunet_types::Error as Fault;
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
mod application;
mod peerstore;
pub use peerstore::{Outcome as HelloAddOutcome, Status as HelloAddStatus};
/// Original source/protocol/clock failure. Native owners close before returning.
#[derive(Debug)]
pub enum Error {
    /// Original business/codec fault.
    Fault(Fault),
    /// Original CLIENT/Resolver error.
    Native(gnunet_client_host::ConnectError),
    /// Original clock failure.
    Clock(Fault),
    /// Actual OS error.
    Io(io::Error),
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Fault(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Native(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TOPOLOGY: {self:?}")
    }
}
impl std::error::Error for Error {}
/// Actual local diagnostic observations, never inferred connections/storage.
#[derive(Debug)]
pub enum Event<'id> {
    /// Actual local PILS public identity.
    Identity(gnunet_pils::client::Identity<'id>),
    /// Actual source lost.
    Lost(&'static str),
    /// Actual original I/O error.
    Io(&'static str, io::Error),
    /// Explicit finite capacity refusal.
    Capacity(&'static str),
    /// Existing HELLO accepted after real signature verification, with exact coverage.
    Hello([u8; 32], gnunet_hello::SignatureCoverage),
    /// Actual CORE send admission.
    GossipQueued(core::SendId<'id>, Gossip),
    /// Actual original terminal payload/result.
    GossipFinished(
        core::SendId<'id>,
        core::PayloadState<'id>,
        core::SendOutcome,
    ),
    /// Actual original TRANSPORT source retired; prefix bytes retain unknown exposure.
    ApplicationRetired {
        /// Original local source epoch.
        epoch: u64,
        /// Original pending control, when one was admitted.
        job: Option<Control>,
        /// Actual prefix bytes accepted by the original source.
        bytes: usize,
    },
    /// Actual original unwritten-payload cancellation; no remote ACK.
    GossipCanceled(core::SendId<'id>, core::SendOutcome),
    /// Actual transport source attach (local diagnostic epoch only).
    ApplicationAttached(u64),
    /// Actual whole local control writes, not connection success.
    ApplicationWritten(u64, Control, usize),
    /// Actual peerstore original final outcome.
    HelloAdd(HelloAddOutcome<'id>),
    /// Actual native source refusal.
    Port(&'static str, gnunet_client_host::ConnectError),
    /// Independent actual cleanup/source failure, retained alongside the primary.
    Cleanup(&'static str, Error),
    /// Actual initial monitor synchronization.
    Sync(ps::Epoch<'id>),
}
/// Actual local policy/source observations for the official nonpersistent counters.
/// Queued requests and gossips count local admissions, never remote delivery.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Statistics {
    /// Currently observed CORE peer connections.
    pub peers_connected: u64,
    /// Newly admitted nonzero TRANSPORT connection suggestions.
    pub connect_requests: u64,
    /// Original full HELLO messages received from CORE before local validation.
    pub hellos_received: u64,
    /// Original HELLO sends admitted to CORE.
    pub hellos_gossipped: u64,
}
/// Externally owned stable allocation domains, no self-reference/leaked instance.
pub struct Instances<'id> {
    /// CORE domain.
    pub core: &'id mut core::Instance,
    /// PILS domain.
    pub pils: &'id mut gnunet_pils::client::Instance,
    /// General PEERSTORE domain.
    pub peerstore: &'id mut ps::Instance,
    /// Dedicated monitor domain.
    pub monitor: &'id mut ps::Instance,
}
/// Explicit native endpoints; all selectors are snapshot together before admission.
pub struct Sources {
    /// CORE.
    pub core: EndpointSource,
    /// PILS.
    pub pils: EndpointSource,
    /// PEERSTORE.
    pub peerstore: EndpointSource,
    /// TRANSPORT application.
    pub transport: EndpointSource,
}
/// Host memory, exact profile and native/lifetime bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Pure business resources.
    pub core: gnunet_topology::Limits,
    /// Canonical public address parser bounds.
    pub hello: gnunet_hello::Limits,
    /// Exact local PILS derivation; never inferred from remote HELLO coverage.
    pub pils_profile: gnunet_pils::Profile,
    /// Explicit remote HELLO signature coverage.
    pub profile: gnunet_hello::SignatureProfile,
    /// Native CORE class ABI.
    pub core_order: core::ClassOrder,
    /// Maximum pending incoming HELLO jobs.
    pub incoming: usize,
    /// Native syscall byte slice.
    pub io_slice: usize,
    /// Original individual send/store deadline.
    pub operation: Duration,
    /// Original partial cancellation grace.
    pub grace: Duration,
    /// Finite source rotation interval (fresh source epochs).
    pub source_lifetime: Duration,
    /// Original finite daemon intent; never renewed by reconnect.
    pub lifetime: Duration,
    /// Maximum scheduler bookkeeping interval.
    pub tick: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            core: gnunet_topology::Limits {
                peers: 63,
                frame_bytes: 64000,
                ..Default::default()
            },
            hello: gnunet_hello::Limits {
                maximum_input_bytes: 64000,
                maximum_address_bytes: 63888,
                maximum_addresses: 256,
            },
            pils_profile: gnunet_pils::Profile::Reference029,
            profile: gnunet_hello::SignatureProfile::Gnunet029,
            core_order: if cfg!(target_endian = "little") {
                core::ClassOrder::Little
            } else {
                core::ClassOrder::Big
            },
            incoming: 8,
            io_slice: 65535,
            operation: Duration::from_secs(30),
            grace: Duration::from_secs(5),
            source_lifetime: Duration::from_secs(3600),
            lifetime: Duration::from_secs(365 * 86400),
            tick: Duration::from_millis(100),
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Fault> {
        self.core.validate()?;
        if self.core.peers > 63
            || self.core.frame_bytes > 64000
            || self.hello.maximum_input_bytes < self.core.frame_bytes
            || self.hello.maximum_address_bytes > 65535
            || self.hello.maximum_addresses > 4096
            || self.incoming == 0
            || self.incoming > 1024
            || self.io_slice == 0
            || self.io_slice > 65535
        {
            return Err(Fault::Capacity);
        }
        for d in [
            self.operation,
            self.grace,
            self.source_lifetime,
            self.lifetime,
            self.tick,
        ] {
            if d.is_zero()
                || d.as_micros() >= u128::from(u64::MAX)
                || Instant::now().checked_add(d).is_none()
            {
                return Err(Fault::Deadline);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
struct Bound {
    until: u64,
    hard: Instant,
}
fn bound(now: u64, d: Duration) -> Result<Bound, Error> {
    Ok(Bound {
        until: now
            .checked_add(u64::try_from(d.as_micros()).map_err(|_| Fault::Overflow)?)
            .filter(|n| *n < u64::MAX)
            .ok_or(Fault::Overflow)?,
        hard: Instant::now().checked_add(d).ok_or(Fault::Overflow)?,
    })
}
fn alloc(n: usize) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    b.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    b.resize(n, 0);
    Ok(b)
}
struct Sending<'id> {
    id: core::SendId<'id>,
    epoch: core::ConnectionEpoch<'id>,
    peer: core::Peer<'id>,
    job: Gossip,
    bound: Bound,
    drain: Option<Instant>,
    retired: bool,
}
struct Link<'id> {
    peer: core::Peer<'id>,
    node: Node,
}
struct Incoming<'id> {
    bytes: Vec<u8>,
    epoch: core::ConnectionEpoch<'id>,
    sender: [u8; 32],
    bound: Bound,
}
/// Real caller-driven composition; exactly zero background tasks/threads.
pub struct Runtime<'id> {
    statistics: Statistics,
    engine: Engine,
    core: core::Client<'id, 64, 64>,
    pils: pils::Client<'id, 1>,
    peerstore: peerstore::Port<'id>,
    app: application::Application,
    limits: Limits,
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    timer: Pin<Box<Sleep>>,
    tick: Instant,
    intent: Bound,
    source_at: Instant,
    links: Vec<Link<'id>>,
    sends: Vec<Sending<'id>>,
    incoming: VecDeque<Incoming<'id>>,
    scratch: Vec<u8>,
    turn: u8,
    ready: Option<Instant>,
    core_local: Option<[u8; 32]>,
    closed: bool,
    yield_due: bool,
    cleanup: Option<Error>,
}
/// One finite actual driver observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One real protocol/local policy step.
    Activity,
    /// Caller observation wait ended; original owners persist.
    WaitDeadline,
    /// Explicit original daemon lifetime/shutdown ended.
    Stopped,
}
impl<'id> Runtime<'id> {
    /// Construct real native owners from one grouped selector snapshot and one
    /// canonical clock. Opens no socket, hidden Resolver, thread, store or task.
    pub fn new(instances: Instances<'id>, sources: Sources, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let [cs, pi, pss, ts] = EndpointSource::snapshot_all([
            &sources.core,
            &sources.pils,
            &sources.peerstore,
            &sources.transport,
        ])?;
        let clock = cs.clock();
        for source in [&pi, &pss, &ts] {
            if !Arc::ptr_eq(&clock, &source.clock()) {
                return Err(Fault::Conflict.into());
            }
        }
        let subscription = clock.subscribe().map_err(Error::Clock)?;
        let sample = clock.sample().map_err(Error::Clock)?;
        let now = sample.now.as_micros();
        let intent = bound(now, limits.lifetime)?;
        let engine = Engine::new(limits.core, now)?;
        let core = core::Client::new(
            instances.core,
            cs,
            limits.core_order,
            0,
            &[16],
            core::Limits {
                sends: limits.core.peers,
                source_bytes: limits
                    .core
                    .peers
                    .checked_mul(limits.core.frame_bytes)
                    .ok_or(Fault::Overflow)?,
                frame_bytes: 65535,
                output: gnunet_service_runtime::framing::Budget {
                    frames: limits.core.peers * 2 + 1,
                    bytes: (limits.core.peers * 2 + 1) * 65535,
                },
                io_slice_bytes: limits.io_slice,
            },
        )?;
        let pils = pils::Client::new(
            instances.pils,
            pi,
            limits.pils_profile,
            pils::Limits {
                pending_operations: 1,
                frame_bytes: 65535,
                io_slice_bytes: limits.io_slice,
            },
            limits.hello,
        )?;
        let peerstore = peerstore::Port::new(instances.peerstore, instances.monitor, pss, limits)?;
        let app = application::Application::new(ts, limits.io_slice)?;
        let mut links = Vec::new();
        links
            .try_reserve_exact(limits.core.peers)
            .map_err(|_| Fault::Capacity)?;
        let mut sends = Vec::new();
        sends
            .try_reserve_exact(limits.core.peers)
            .map_err(|_| Fault::Capacity)?;
        let mut incoming = VecDeque::new();
        incoming
            .try_reserve_exact(limits.incoming)
            .map_err(|_| Fault::Capacity)?;
        let tick = Instant::now()
            .checked_add(limits.tick)
            .ok_or(Fault::Overflow)?;
        let source_at = Instant::now()
            .checked_add(limits.source_lifetime)
            .ok_or(Fault::Overflow)?;
        Ok(Self {
            statistics: Statistics::default(),
            engine,
            core,
            pils,
            peerstore,
            app,
            limits,
            clock,
            subscription,
            revision: sample.revision,
            alarm: None,
            alarm_at: None,
            timer: Box::pin(tokio::time::sleep_until(tick)),
            tick,
            intent,
            source_at,
            links,
            sends,
            incoming,
            scratch: alloc(limits.hello.maximum_address_bytes)?,
            turn: 0,
            ready: None,
            core_local: None,
            closed: false,
            yield_due: false,
            cleanup: None,
        })
    }
    /// Snapshot actual local observations; no statistic implies an ACK or storage.
    pub fn statistics(&self) -> Statistics {
        Statistics {
            peers_connected: u64::try_from(self.engine.connections()).unwrap_or(u64::MAX),
            ..self.statistics
        }
    }
    /// Retained independent cleanup failure, separate from the primary poll error.
    pub fn take_cleanup_error(&mut self) -> Option<Error> {
        self.cleanup.take()
    }
    /// Actual source readiness snapshot; it is not permanent connection authority.
    pub fn readiness(&self) -> Readiness {
        Readiness {
            core: self.ready.is_some(),
            pils: self.pils.identity().is_some(),
            monitor: self.peerstore.synced().is_some(),
            transport: self.app.attached(),
        }
    }
    /// Immutable business policy state, independent of native delivery authority.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
    fn core_lost(&mut self, now: Option<u64>, observe: &mut impl FnMut(Event<'id>)) {
        self.links.clear();
        self.ready = None;
        self.core_local = None;
        self.engine.connections_lost(now.unwrap_or(0));
        observe(Event::Lost("CORE"));
    }
    fn rotate(
        &mut self,
        now: Option<u64>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        // Every original source is physically retired before any preceding failure
        // can abort this cleanup. No immutable partial frame migrates to another MQ.
        let a = self.core.reconnect();
        let b = self.pils.reconnect();
        let c = self.peerstore.rotate(observe);
        let d = self.app.rotate(observe);
        self.engine.controls_retired();
        self.engine.local_lost(now.unwrap_or(0));
        self.core_lost(now, observe);
        self.source_at = Instant::now()
            .checked_add(self.limits.source_lifetime)
            .ok_or(Fault::Overflow)?;
        let mut first = None;
        for (label, result) in [
            ("CORE rotation", a.map(|_| ()).map_err(Error::Native)),
            ("PILS rotation", b.map(|_| ()).map_err(Error::Native)),
            ("PEERSTORE rotation", c),
            ("TRANSPORT rotation", d.map(|_| ())),
        ] {
            if let Err(error) = result {
                if first.is_none() {
                    first = Some(error)
                } else {
                    observe(Event::Cleanup(label, error));
                }
            }
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
    fn guard(
        &mut self,
        now: Option<u64>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<bool, Error> {
        if self.closed {
            return Ok(true);
        }
        let at = Instant::now();
        if at >= self.intent.hard || now.is_some_and(|n| n >= self.intent.until) {
            self.close(observe)?;
            return Ok(true);
        }
        self.peerstore.expire(now, observe)?;
        if self.app.expired(now) {
            let _old = self.app.rotate(observe)?;
            self.engine.controls_retired();
            observe(Event::Lost("TRANSPORT original control deadline"));
        }
        let mut reset = false;
        let mut i = 0;
        while i < self.sends.len() {
            if self.sends[i].retired {
                i += 1;
                continue;
            }
            if self.sends[i].drain.is_some_and(|d| at >= d) {
                reset = true;
                i += 1;
                continue;
            }
            if self.sends[i].drain.is_none()
                && (at >= self.sends[i].bound.hard
                    || now.is_some_and(|n| n >= self.sends[i].bound.until))
            {
                let id = self.sends[i].id;
                match self.core.cancel(id) {
                    Ok(Some(completion)) => {
                        let old = self.sends.remove(i);
                        self.engine.gossip_retired(&old.job)?;
                        observe(Event::GossipCanceled(id, completion.outcome));
                        continue;
                    }
                    Ok(None) => {
                        self.sends[i].drain = Some(
                            self.sends[i]
                                .bound
                                .hard
                                .min(at)
                                .checked_add(self.limits.grace)
                                .ok_or(Fault::Overflow)?,
                        );
                    }
                    Err(e) => {
                        observe(Event::Port("CORE cancellation", e));
                        reset = true;
                    }
                }
            }
            i += 1;
        }
        if reset {
            match self.core.reconnect() {
                Ok(_) => {}
                Err(gnunet_client_host::ConnectError::Protocol(Fault::Conflict)) => {}
                Err(e) => {
                    let _closed = self.core.close();
                    return Err(e.into());
                }
            }
            self.core_lost(now, observe);
            for send in &mut self.sends {
                send.retired = true;
            }
        }
        if at >= self.source_at {
            self.rotate(now, observe)?;
        }
        Ok(false)
    }
    fn native_target(&self) -> Instant {
        self.sends
            .iter()
            .filter(|s| !s.retired)
            .map(|s| s.drain.unwrap_or(s.bound.hard))
            .chain(self.peerstore.next_native())
            .chain(self.app.next_native())
            .chain(std::iter::once(self.source_at))
            .chain(std::iter::once(self.intent.hard))
            .fold(self.tick, Instant::min)
    }
    fn prepare(&mut self, now: u64, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        self.engine.expire(now);
        if self.ready.is_some_and(|at| Instant::now() >= at)
            && self.peerstore.begin_monitor(self.intent.until)?
        {
            return Ok(true);
        }
        if self.peerstore.idle()
            && let Some(input) = self.incoming.pop_front()
        {
            if now < input.bound.until && Instant::now() < input.bound.hard {
                let frame = match VerifiedFrame::verify(
                    &input.bytes,
                    &mut self.scratch,
                    self.limits.hello,
                    self.limits.profile,
                    now,
                ) {
                    Ok(frame) => frame,
                    Err(_) => return Ok(true),
                };
                let peer = *frame.verified().hello().peer().as_bytes();
                let expiry = frame.verified().hello().expiration().as_micros();
                if expiry <= now {
                    return Ok(true);
                }
                match self.peerstore.start(input, peer, expiry) {
                    Ok(()) => return Ok(true),
                    Err(rejected) => match *rejected {
                        (
                            Error::Native(gnunet_client_host::ConnectError::Protocol(
                                Fault::WouldBlock | Fault::Capacity | Fault::NotReady,
                            )),
                            input,
                        ) => self.incoming.push_front(input),
                        (e, _) => return Err(e),
                    },
                }
            } else {
                return Ok(true);
            }
        }
        if self.app.ready()
            && let Some(control) = self.engine.control(now)?
        {
            let peer = self.engine.peer(control.node())?;
            self.app
                .enqueue(control.clone(), peer, bound(now, self.limits.operation)?)?;
            if control.before() == 0 && control.after() > 0 {
                self.statistics.connect_requests =
                    self.statistics.connect_requests.saturating_add(1);
            }
            self.engine.control_queued(&control)?;
            return Ok(true);
        }
        if self.sends.len() < self.limits.core.peers
            && let Some(advert) = self.engine.advertisement(now)?
        {
            let job = advert.job;
            let target = self
                .links
                .iter()
                .find(|link| link.node == *job.target())
                .map(|link| link.peer)
                .ok_or(Fault::Stale)?;
            if self
                .core
                .request_available(target, advert.bytes.len(), advert.bytes.len())?
            {
                let message = core::Message::copy_from(advert.bytes)?;
                let target_bound = bound(now, self.limits.operation)?;
                let id = self
                    .core
                    .send(target, 1, target_bound.until, message)
                    .map_err(|e| Error::Native(e.reason.into()))?;
                self.statistics.hellos_gossipped =
                    self.statistics.hellos_gossipped.saturating_add(1);
                self.engine.gossip_queued(&job)?;
                self.sends.push(Sending {
                    id,
                    epoch: self.core.epoch().ok_or(Fault::Stale)?,
                    peer: target,
                    job: job.clone(),
                    bound: target_bound,
                    drain: None,
                    retired: false,
                });
                observe(Event::GossipQueued(id, job));
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn core_step(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Error>> {
        let step = match self.core.poll(cx, None) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        };
        match step {
            core::Progress::Inbound {
                event: core::Inbound::Ready { local, .. },
                ..
            } => {
                self.core_local = Some(local.identity().0);
                if self
                    .engine
                    .local()
                    .is_some_and(|own| own != local.identity().0)
                {
                    let _lost = self.core.reconnect()?;
                    self.core_lost(Some(now), observe);
                    return Poll::Ready(Ok(()));
                }
                self.ready = Some(
                    Instant::now()
                        .checked_add(Duration::from_secs(1))
                        .ok_or(Fault::Overflow)?,
                );
            }
            core::Progress::Inbound {
                event: core::Inbound::Connected(peer),
                ..
            } => {
                if Some(peer.identity().0) != self.core_local {
                    if self.links.len() == self.limits.core.peers {
                        observe(Event::Capacity("CORE peer rows"))
                    } else {
                        let node = self.engine.connected(peer.identity().0, now)?;
                        if let Some(link) = self.links.iter_mut().find(|l| l.node == node) {
                            link.peer = peer
                        } else {
                            self.links.push(Link { peer, node });
                        }
                    }
                }
            }
            core::Progress::Inbound {
                event: core::Inbound::Disconnected(peer),
                ..
            }
            | core::Progress::PeerLost { peer, .. } => {
                if let Some(i) = self.links.iter().position(|l| l.peer == peer) {
                    let old = self.links.remove(i);
                    self.engine.disconnected(&old.node, now)?;
                }
            }
            core::Progress::Inbound {
                epoch,
                event:
                    core::Inbound::Traffic {
                        peer,
                        direction: core::Direction::Inbound,
                        traffic: core::OwnedTraffic::Full(message),
                        ..
                    },
            } => {
                self.statistics.hellos_received = self.statistics.hellos_received.saturating_add(1);
                if self.incoming.len() == self.limits.incoming {
                    observe(Event::Capacity("incoming HELLO add"));
                } else {
                    let bytes = message.as_ref();
                    match VerifiedFrame::verify(
                        bytes,
                        &mut self.scratch,
                        self.limits.hello,
                        self.limits.profile,
                        now,
                    ) {
                        Ok(frame) => {
                            let coverage = frame.verified().coverage();
                            let subject = *frame.verified().hello().peer().as_bytes();
                            let mut owned = Vec::new();
                            owned
                                .try_reserve_exact(bytes.len())
                                .map_err(|_| Fault::Capacity)?;
                            owned.extend_from_slice(bytes);
                            self.incoming.push_back(Incoming {
                                bytes: owned,
                                epoch,
                                sender: peer.0,
                                bound: bound(now, self.limits.operation)?,
                            });
                            observe(Event::Hello(subject, coverage));
                        }
                        Err(_) => observe(Event::Lost("rejected unverified/expired CORE HELLO")),
                    }
                }
            }
            core::Progress::Finished {
                epoch,
                peer,
                send,
                payload,
                completion,
            } => {
                observe(Event::GossipFinished(send, payload, completion.outcome));
                if let Some(i) = self
                    .sends
                    .iter()
                    .position(|s| s.id == send && s.epoch == epoch && s.peer == peer)
                {
                    let original = self.sends.remove(i);
                    self.engine
                        .gossip_finished(&original.job, payload.complete(), now)?;
                } else {
                    return Poll::Ready(Err(Fault::Stale.into()));
                }
            }
            core::Progress::Lost { .. } => self.core_lost(Some(now), observe),
            core::Progress::ConnectRetry { error, .. } => observe(Event::Io("CORE retry", error)),
            core::Progress::Unavailable(e) => return Poll::Ready(Err(e.into())),
            core::Progress::Closed => return Poll::Ready(Err(Fault::Closed.into())),
            _ => {}
        }
        Poll::Ready(Ok(()))
    }
    fn pils_step(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Error>> {
        let step = {
            let f = self.pils.drive(None);
            let mut f = std::pin::pin!(f);
            f.as_mut().poll(cx)
        };
        let progress = match step {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(r) => r?,
        };
        match progress {
            pils::Progress::Inbound(gnunet_pils::client::Inbound::Identity {
                identity,
                identity_changed,
                ..
            }) => {
                if (identity_changed && self.engine.local().is_some())
                    || self
                        .core_local
                        .is_some_and(|own| own != *identity.peer().as_bytes())
                {
                    match self.core.reconnect() {
                        Ok(_) => {}
                        Err(gnunet_client_host::ConnectError::Protocol(Fault::Conflict)) => {}
                        Err(e) => return Poll::Ready(Err(e.into())),
                    }
                    self.core_lost(Some(now), observe);
                }
                self.engine.set_local(*identity.peer().as_bytes(), now);
                observe(Event::Identity(identity));
            }
            pils::Progress::Lost { .. } => {
                self.engine.local_lost(now);
                observe(Event::Lost("PILS"));
            }
            pils::Progress::ConnectRetry { error, .. } => observe(Event::Io("PILS retry", error)),
            pils::Progress::Unavailable(e) => return Poll::Ready(Err(e.into())),
            pils::Progress::Closed => return Poll::Ready(Err(Fault::Closed.into())),
            _ => {}
        }
        Poll::Ready(Ok(()))
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.guard(None, observe)? {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        let at = wait.map_or(self.native_target(), |w| w.min(self.native_target()));
        self.timer.as_mut().reset(at);
        if self.timer.as_mut().poll(cx).is_ready() {
            self.tick = Instant::now()
                .checked_add(self.limits.tick)
                .ok_or(Fault::Overflow)?;
            if self.guard(None, observe)? {
                return Poll::Ready(Ok(Progress::Stopped));
            }
        }
        let changed = self.subscription.poll_changed(cx, self.revision);
        if let Poll::Ready(Err(e)) = changed {
            return Poll::Ready(Err(Error::Clock(e)));
        }
        let sample = self.clock.sample().map_err(Error::Clock)?;
        self.revision = sample.revision;
        let now = sample.now.as_micros();
        if self.guard(Some(now), observe)? {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if wait.is_some_and(|w| Instant::now() >= w) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if let Poll::Ready(changed) = self.subscription.poll_changed(cx, self.revision) {
            changed.map_err(Error::Clock)?;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let target = self
            .engine
            .next_deadline(now)
            .min(self.intent.until)
            .min(self.peerstore.next_logical().unwrap_or(u64::MAX))
            .min(self.app.next_logical().unwrap_or(u64::MAX));
        if self.alarm_at != Some(target) {
            self.alarm = Some(Box::pin(
                Deadline::at(
                    self.clock.clone(),
                    gnunet_types::AbsoluteTime::from_micros(target),
                )
                .map_err(Error::Clock)?,
            ));
            self.alarm_at = Some(target)
        }
        if let Some(alarm) = &mut self.alarm {
            match alarm.as_mut().poll(cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
                Poll::Ready(Ok(())) => {
                    self.alarm = None;
                    self.alarm_at = None;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Pending => {}
            }
        }
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        for off in 0..5 {
            let direction = (self.turn + off) % 5;
            let result = match direction {
                0 => self.core_step(cx, now, observe),
                1 => self.pils_step(cx, now, observe),
                2 => self.peerstore.poll(cx, &mut self.engine, now, observe),
                3 => match self.app.poll(cx, observe) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Ready(Ok(step)) => {
                        match step {
                            application::Step::Written(job) => self.engine.control_written(&job)?,
                            application::Step::Lost(_old) => {
                                self.engine.controls_retired();
                                observe(Event::Lost("TRANSPORT application"));
                            }
                            application::Step::Activity => {}
                        }
                        Poll::Ready(Ok(()))
                    }
                },
                _ => {
                    if self.prepare(now, observe)? {
                        Poll::Ready(Ok(()))
                    } else {
                        Poll::Pending
                    }
                }
            };
            if let Poll::Ready(result) = result {
                self.turn = (direction + 1) % 5;
                result?;
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        Poll::Pending
    }
    /// Poll actual original owners fairly. Clock errors close every physical source
    /// before returning, without a second clock sample or waiting for native progress.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let result = self.poll_inner(cx, wait, observe);
        if matches!(result, Poll::Ready(Err(_)))
            && let Err(error) = self.close(observe)
            && self.cleanup.is_none()
        {
            self.cleanup = Some(error);
        }
        if matches!(result, Poll::Ready(Ok(Progress::Activity))) {
            self.yield_due = true;
        }
        result
    }
    /// Canceling this future retains original immutable RX/TX/effect/deadline cursors.
    pub async fn drive(
        &mut self,
        wait: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, wait, &mut observe)).await
    }
    /// Physical cleanup of all four services (five MQs) precedes error propagation.
    /// CORE/PEERSTORE debts are consumed only from their actual original owners.
    pub fn close(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let a = self.core.close();
        let _pils = self.pils.close();
        let b = self.peerstore.close_observed(observe);
        let old = self.app.close();
        observe(Event::ApplicationRetired {
            epoch: old.epoch,
            job: old.job,
            bytes: old.bytes,
        });
        self.incoming.clear();
        self.links.clear();
        self.alarm = None;
        self.engine.controls_retired();
        let mut first = a.err().map(Error::Native);
        if let Err(e) = b {
            if first.is_none() {
                first = Some(e)
            } else {
                observe(Event::Cleanup("PEERSTORE close", e));
            }
        }
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for _ in 0..self.limits.core.peers.saturating_mul(4).saturating_add(4) {
            match self.core.poll(&mut cx, None) {
                Poll::Ready(Ok(core::Progress::Finished {
                    send,
                    payload,
                    completion,
                    ..
                })) => observe(Event::GossipFinished(send, payload, completion.outcome)),
                Poll::Ready(Ok(core::Progress::Closed)) => break,
                Poll::Ready(Err(e)) => {
                    if first.is_none() {
                        first = Some(e.into())
                    }
                    break;
                }
                Poll::Pending => {
                    if first.is_none() {
                        first = Some(Fault::OutcomeUnknown.into())
                    }
                    break;
                }
                _ => {}
            }
        }
        self.sends.clear();
        match first {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
impl Drop for Runtime<'_> {
    fn drop(&mut self) {
        let _closed = self.close(&mut |_| {});
    }
}

/// Actual original source observations needed by foreground startup.
#[derive(Clone, Copy, Debug)]
pub struct Readiness {
    /// Actual CORE initialization.
    pub core: bool,
    /// Actual verified PILS identity.
    pub pils: bool,
    /// Actual initial PEERSTORE SYNC on current monitor MQ.
    pub monitor: bool,
    /// Actual current TRANSPORT application MQ attachment.
    pub transport: bool,
}
impl Readiness {
    /// All four source observations are currently available.
    pub const fn complete(self) -> bool {
        self.core && self.pils && self.monitor && self.transport
    }
}
