//! Caller-driven native NSE host over the original CORE and PILS clients.
//! Protocol, history, proof and lease authority remain in the pure NSE owner.
#![forbid(unsafe_code)]
/// Actual raw8 proof persistence, OS fencing and explicit unknown recovery.
pub mod proof;
/// Foreground official configuration and shared process resources.
pub mod startup;
/// Injected source-independent statistics driver/factory ports.
pub mod statistics;
use gnunet_client_host::EndpointSource;
use gnunet_core_client_host::{self as core, Client as CoreClient};
use gnunet_crypto::pow;
/// Original NSE domain statistics snapshot and exact ordinary metric names.
pub use gnunet_nse::metrics::{METRIC_NAMES, Metrics};
use gnunet_nse::owner::{
    self as pure, Alarm, Notification, PersistRequest, Retirement, Service, SignRequest,
    Transmission,
};
use gnunet_pils::{
    HelloLimits, Profile,
    client::{self as pc, KeyTarget},
};
use gnunet_pils_host::client::{self as pils, Client as PilsClient};
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection, SocketEvent},
    clock::{ClockSubscription, Deadline, RuntimeClock},
    connection::Connection,
    credentials::UnixAccess,
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::{Listener, PeerAddress, ServiceOptions},
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::{
    self,
    core::{ClassOrder, Direction},
    nse::{self, flood},
};
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
const NSE_TYPES: [u16; 1] = [official::message_type::NSE_P2P_FLOOD.value()];
/// Explicit finite resource and CPU slices; protocol defaults remain15/1h/5ms.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Explicit official PILS/HELLO source profile; verification never falls back.
    pub pils_profile: Profile,
    /// At most P actual announced peers, including CORE's local loopback.
    pub peers: usize,
    /// At most S accepted subscriber streams, including those awaiting START.
    pub subscribers: usize,
    /// One through four Argon2 candidates per work lease; normal host default1.
    pub work_budget: u16,
    /// Minimum absolute-source delay between progress checkpoints; final proofs
    /// and shutdown flush immediately. This is native durability policy, not PoW delay.
    pub checkpoint_micros: u64,
    /// Maximum bytes per actual native socket syscall, nonzero.
    pub io_slice_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            pils_profile: Profile::Reference029,
            peers: 64,
            subscribers: 32,
            work_budget: 1,
            checkpoint_micros: 1_000_000,
            io_slice_bytes: 65535,
        }
    }
}
/// Shared caller-selected process sources; no Resolver or background owner is created.
pub struct Ports {
    /// Actual CORE source on this canonical clock.
    pub core: EndpointSource,
    /// Actual PILS source on this same clock.
    pub pils: EndpointSource,
    /// Explicit canonical absolute UTC process source.
    pub clock: Arc<dyn RuntimeClock>,
}
/// Original pure identity storage remains external to movable host owners.
pub struct Instances<'a> {
    /// NSE effect brand.
    pub nse: &'a mut pure::Instance,
    /// CORE physical/peer/send brands.
    pub core: &'a mut core::Instance,
    /// PILS operation/announcement brands.
    pub pils: &'a mut pc::Instance,
}
/// Actual host cause, never relabeled as remote delivery or durable success.
#[derive(Debug)]
pub enum Error {
    /// Original protocol or bounded resource refusal.
    Protocol(ProtocolError),
    /// Original CORE/PILS CLIENT error.
    Client(gnunet_client_host::ConnectError),
    /// Canonical clock refusal.
    Clock(ProtocolError),
    /// Actual native socket cause.
    Io(io::Error),
    /// Actual fenced raw8 persistence cause.
    Backend(proof::Error),
    /// Two actual independent original close failures, neither replaced by the other.
    Cleanup {
        /// Original CORE/client close failure.
        original: Box<Error>,
        /// Independent original proof flush or service settlement failure.
        cleanup: Box<Error>,
    },
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "NSE protocol: {e}"),
            Self::Client(e) => e.fmt(f),
            Self::Clock(e) => write!(f, "NSE clock: {e}"),
            Self::Io(e) => e.fmt(f),
            Self::Backend(e) => e.fmt(f),
            Self::Cleanup { original, cleanup } => {
                write!(f, "{original}; independent NSE cleanup: {cleanup}")
            }
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) | Self::Clock(e) => Some(e),
            Self::Client(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Backend(e) => Some(e),
            Self::Cleanup { original, .. } => Some(original.as_ref()),
        }
    }
}
impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Client(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<proof::Error> for Error {
    fn from(e: proof::Error) -> Self {
        Self::Backend(e)
    }
}
/// Actual completed local effects, not application delivery or exact network size.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Successful validated identity activations.
    pub activations: u64,
    /// Actual canonically accepted subscriber streams admitted by access policy.
    pub accepted: u64,
    /// Actual ACL/kernel-credential rejections before framing or a pure subscriber.
    pub rejected: u64,
    /// Actual credential/resource failures on unadmitted streams, already closed.
    pub admission_failures: u64,
    /// Actual full original estimate writes.
    pub estimates: u64,
    /// Real caller-budgeted proof candidates attempted.
    pub work_calls: u64,
    /// Valid original proof discoveries.
    pub proofs: u64,
    /// Fully durable raw8 original commits.
    pub durable: u64,
    /// Actual completed original round alarms.
    pub rounds: u64,
    /// Actual verified PILS signatures applied to original leases.
    pub signatures: u64,
    /// Actual full original CORE payload submissions.
    pub submissions: u64,
    /// Actual self-loopback updates.
    pub self_updates: u64,
    /// Actual admitted remote claims.
    pub remote_claims: u64,
    /// Invalid peer claims rejected without fabricated history.
    pub rejected_claims: u64,
    /// Original CORE physical MQ losses.
    pub core_losses: u64,
    /// Original PILS physical MQ losses.
    pub pils_losses: u64,
}
/// One actual bounded host action.
#[derive(Debug)]
pub enum Progress {
    /// CORE/PILS and NSE have the same actually verified identity.
    Activated([u8; 32]),
    /// Positive native input/output or original CLIENT attempt event.
    Activity,
    /// Actual physical subscriber accepted after access/credential checks.
    Accepted,
    /// This original stream was closed by access policy before framing/core use.
    AdmissionRejected {
        /// Actual original peer address; no protocol token was allocated.
        peer: PeerAddress,
    },
    /// Original unadmitted stream was closed after a credential/resource failure.
    /// The caller retains the concrete cause without stopping unrelated clients.
    AdmissionFailed {
        /// Actual original peer address.
        peer: PeerAddress,
        /// Concrete original refusal; never a fabricated peer/protocol result.
        error: Error,
    },
    /// One original subscriber was physically retired.
    SubscriberClosed,
    /// One exact original estimate fully written.
    EstimateWritten,
    /// One original pure timer advanced.
    Alarm(pure::AlarmProgress),
    /// One actual bounded Argon2 slice completed.
    Work(pure::WorkProgress),
    /// One raw8 original commit is actually durable.
    Durable,
    /// Original service context is being retired before reactivation.
    Retired,
    /// Original backend fault remains quiescent until explicit recovery.
    BackendQuiescent,
    /// This wait's native deadline expired.
    WaitDeadline,
    /// All physical owners are permanently stopped.
    Closed,
}
#[derive(Clone, Copy)]
struct Peer<'a> {
    core: core::Peer<'a>,
    epoch: core::ConnectionEpoch<'a>,
    nse: pure::PeerId<'a>,
}
struct Sign<'a> {
    request: SignRequest<'a>,
    operation: pc::OperationId<'a>,
}
struct Send<'a> {
    request: Transmission<'a>,
    operation: core::SendId<'a>,
    epoch: core::ConnectionEpoch<'a>,
}
struct Subscriber<'a> {
    framed: Framed<Notification<'a>>,
    id: Option<pure::SubscriberId<'a>>,
    refresh: bool,
}
struct NoRandom;
impl pure::Random for NoRandom {
    fn below(&mut self, _: u32) -> Result<u32, ProtocolError> {
        Err(ProtocolError::Entropy)
    }
}
/// Bounded movable NSE composition. Each original socket/client/effect retains
/// its own pure brand; no hand-written CORE/PILS protocol appears in this layer.
pub struct Host<'a, const P: usize = 64, const S: usize = 32> {
    core: CoreClient<'a, P, P>,
    pils: PilsClient<'a, P>,
    service: Service<'a, P, S>,
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    clock_error: Option<ProtocolError>,
    store: proof::Store,
    backend_fault: bool,
    persist: Option<PersistRequest<'a>>,
    persist_at: u64,
    memory: Vec<pow::Block>,
    limits: Limits,
    options: ServiceOptions,
    unix: UnixAccess,
    peers: Vec<Peer<'a>>,
    signs: Vec<Sign<'a>>,
    sends: Vec<Send<'a>>,
    subscribers: Vec<Option<Subscriber<'a>>>,
    pils_identity: Option<pc::Identity<'a>>,
    core_local: Option<(core::ConnectionEpoch<'a>, core::Peer<'a>)>,
    barrier: Option<Retirement<'a>>,
    waiting_sign: Option<SignRequest<'a>>,
    waiting_send: Option<Transmission<'a>>,
    alarm: Option<Alarm<'a>>,
    sleep: Option<Pin<Box<Deadline>>>,
    wait: Option<Pin<Box<Sleep>>>,
    notification_bytes: Option<Vec<u8>>,
    cursor: usize,
    yield_due: bool,
    subscriber_cursor: usize,
    listener_cursor: usize,
    accept: AcceptState,
    closed: bool,
    report: Report,
}
fn reserve<T>(capacity: usize) -> Result<Vec<T>, ProtocolError> {
    let mut v = Vec::new();
    v.try_reserve_exact(capacity)
        .map_err(|_| ProtocolError::Capacity)?;
    Ok(v)
}
fn bytes(len: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut v = reserve(len)?;
    v.resize(len, 0);
    Ok(v)
}
impl<'a, const P: usize, const S: usize> Host<'a, P, S> {
    /// Reserve native owners and heap scratch exactly once. Sources must explicitly
    /// share the supplied clock; no lookup, background task or application I/O occurs.
    pub fn new(
        instances: Instances<'a>,
        ports: Ports,
        config: pure::Config,
        limits: Limits,
        options: ServiceOptions,
        store: proof::Store,
    ) -> Result<Self, Error> {
        Self::new_with_access(
            instances,
            ports,
            config,
            limits,
            options,
            UnixAccess::default(),
            store,
        )
    }
    /// Construct the same original bounded owners with explicit shared runtime
    /// Unix kernel-credential policy. Checks precede per-MQ framing and pure START
    /// admission; UID precedence is implemented by UnixAccess itself.
    pub fn new_with_access(
        instances: Instances<'a>,
        ports: Ports,
        config: pure::Config,
        limits: Limits,
        options: ServiceOptions,
        unix: UnixAccess,
        store: proof::Store,
    ) -> Result<Self, Error> {
        if P == 0
            || limits.peers == 0
            || limits.peers > P
            || limits.subscribers > S
            || limits.work_budget == 0
            || limits.work_budget > 4
            || limits.io_slice_bytes == 0
        {
            return Err(ProtocolError::Capacity.into());
        }
        if !Arc::ptr_eq(&ports.core.clock(), &ports.clock)
            || !Arc::ptr_eq(&ports.pils.clock(), &ports.clock)
        {
            return Err(ProtocolError::Conflict.into());
        }
        let subscription = ports.clock.subscribe().map_err(Error::Clock)?;
        let mut memory = reserve(pow::MEMORY_BLOCKS)?;
        for _ in 0..pow::MEMORY_BLOCKS {
            memory.push(pow::Block::default());
        }
        let mut service = Service::new(instances.nse, config)?;
        let barrier = Some(service.begin_identity_change()?);
        let core = CoreClient::new(
            instances.core,
            ports.core,
            if cfg!(target_endian = "little") {
                ClassOrder::Little
            } else {
                ClassOrder::Big
            },
            0,
            &NSE_TYPES,
            core::Limits {
                sends: P,
                source_bytes: P
                    .checked_mul(flood::MESSAGE_LEN)
                    .ok_or(ProtocolError::Capacity)?,
                output: Budget {
                    frames: P
                        .checked_mul(2)
                        .and_then(|p| p.checked_add(1))
                        .ok_or(ProtocolError::Capacity)?,
                    bytes: 65535_usize.max(P.checked_mul(256).ok_or(ProtocolError::Capacity)?),
                },
                io_slice_bytes: limits.io_slice_bytes,
                ..core::Limits::default()
            },
        )?;
        let pils = PilsClient::new(
            instances.pils,
            ports.pils,
            limits.pils_profile,
            pils::Limits {
                pending_operations: P,
                io_slice_bytes: limits.io_slice_bytes,
                ..pils::Limits::default()
            },
            HelloLimits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 128,
            },
        )?;
        let mut subscribers = reserve(limits.subscribers)?;
        subscribers.resize_with(limits.subscribers, || None);
        Ok(Self {
            core,
            pils,
            service,
            clock: ports.clock,
            subscription: Some(subscription),
            revision: 0,
            clock_error: None,
            store,
            backend_fault: false,
            persist: None,
            persist_at: 0,
            memory,
            limits,
            options,
            unix,
            peers: reserve(limits.peers)?,
            signs: reserve(P)?,
            sends: reserve(P)?,
            subscribers,
            pils_identity: None,
            core_local: None,
            barrier,
            waiting_sign: None,
            waiting_send: None,
            alarm: None,
            sleep: None,
            wait: None,
            notification_bytes: Some(bytes(nse::ESTIMATE_LEN)?),
            cursor: 0,
            yield_due: true,
            subscriber_cursor: 0,
            listener_cursor: 0,
            accept: AcceptState::default(),
            closed: false,
            report: Report::default(),
        })
    }
    /// Actual verified identity only while the pure service context is active.
    #[must_use]
    pub fn identity(&self) -> Option<[u8; 32]> {
        self.service.identity()
    }
    /// Actual live NSE peer count, including CORE's self-loopback entry.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.service.peer_count()
    }
    /// Current original native operation counts and selected absolute alarm.
    #[must_use]
    pub fn pending_effects(&self) -> (usize, usize, bool, bool, Option<u64>) {
        (
            self.signs.len(),
            self.sends.len(),
            self.waiting_sign.is_some(),
            self.waiting_send.is_some(),
            self.alarm.map(|a| a.deadline()),
        )
    }
    /// Completed local effect counters.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Read actual unique-Service metric coordinates without native activity,
    /// hashing, clock sampling or a new statistics publisher.
    #[must_use]
    pub fn metrics(&self) -> Metrics {
        self.service.metrics()
    }

    fn now(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Error>> {
        if let Some(error) = self.clock_error {
            return Poll::Ready(Err(Error::Clock(error)));
        }
        let result = self.poll_now(cx);
        if let Poll::Ready(Err(Error::Clock(error))) = &result {
            self.clock_error = Some(*error);
        }
        result
    }
    fn poll_now(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Error>> {
        let sub = self.subscription.as_mut().ok_or(ProtocolError::Closed)?;
        match sub.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample().map_err(Error::Clock)?;
        match sub.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(Error::Clock(e))),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => {
                self.revision = sample.revision;
                Poll::Ready(Ok(sample.now.as_micros()))
            }
        }
    }
    /// Explicitly re-reserve a refused canonical-clock listener. Original alarms,
    /// frames, signing leases and identity barriers remain retained.
    pub fn recover_clock(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if self.clock_error.is_none() {
            return Err(ProtocolError::NotReady.into());
        }
        self.subscription = None;
        self.subscription = Some(self.clock.subscribe().map_err(Error::Clock)?);
        self.clock_error = None;
        self.sleep = None;
        Ok(())
    }
    fn close_subscriber(&mut self, index: usize) {
        if let Some(mut sub) = self.subscribers[index].take() {
            sub.framed.retire();
            if let Some(id) = sub.id {
                let _retired = self.service.unsubscribe(id);
            }
            self.accept.client_closed();
        }
    }
    fn cancel_signs(&mut self, peer: Option<pure::PeerId<'a>>) -> Result<(), Error> {
        let mut i = 0;
        while i < self.signs.len() {
            if peer.is_none_or(|p| self.signs[i].request.peer() == p) {
                let sign = self.signs.remove(i);
                self.pils.cancel(sign.operation)?;
                let _cancelled = self.service.cancel_sign(&sign.request);
            } else {
                i += 1;
            }
        }
        if self
            .waiting_sign
            .is_some_and(|r| peer.is_none_or(|p| r.peer() == p))
        {
            self.waiting_sign = None;
        }
        Ok(())
    }
    fn retire_identity(&mut self) -> Result<(), Error> {
        if self.barrier.is_none() {
            self.barrier = Some(self.service.begin_identity_change()?);
        }
        if self.core.epoch().is_some() {
            match self.core.reconnect() {
                Ok(_) | Err(core::Error::Protocol(ProtocolError::Conflict)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.cancel_signs(None)?;
        for i in 0..self.subscribers.len() {
            self.close_subscriber(i);
        }
        self.service.core_lost();
        self.peers.clear();
        self.core_local = None;
        self.waiting_send = None;
        self.waiting_sign = None;
        self.alarm = None;
        self.sleep = None;
        Ok(())
    }
    fn activate(&mut self, now: u64) -> Result<Option<Progress>, Error> {
        if self.backend_fault || !self.store.quiescent()? {
            return Ok(None);
        }
        let (Some(identity), Some((_, local)), Some(barrier)) =
            (self.pils_identity, self.core_local, self.barrier.as_ref())
        else {
            return Ok(None);
        };
        let key = *identity.peer().as_bytes();
        if key != local.identity().0 {
            return Ok(None);
        }
        let saved = self.store.loaded()?.unwrap_or([0; 8]);
        self.service
            .finish_identity_change(barrier, key, saved, now, &mut self.memory)?;
        self.barrier = None;
        self.report.activations = self.report.activations.saturating_add(1);
        Ok(Some(Progress::Activated(key)))
    }
    fn connect_peer(
        &mut self,
        epoch: core::ConnectionEpoch<'a>,
        peer: core::Peer<'a>,
    ) -> Result<(), Error> {
        if self.peers.len() >= self.limits.peers {
            return Err(ProtocolError::Capacity.into());
        }
        if self
            .peers
            .iter()
            .any(|p| p.core == peer && p.epoch == epoch)
        {
            return Err(ProtocolError::Conflict.into());
        }
        let nse = self.service.connect_peer(peer.identity().0)?;
        self.peers.push(Peer {
            core: peer,
            epoch,
            nse,
        });
        Ok(())
    }
    fn handle_core(&mut self, progress: core::Progress<'a>) -> Result<Progress, Error> {
        match progress {
            core::Progress::Inbound { epoch, event } => match event {
                core::Inbound::Ready { local, .. } => {
                    if self
                        .pils_identity
                        .is_some_and(|p| *p.peer().as_bytes() != local.identity().0)
                    {
                        self.retire_identity()?;
                        return Ok(Progress::Retired);
                    }
                    self.core_local = Some((epoch, local));
                    self.connect_peer(epoch, local)?;
                }
                core::Inbound::Connected(peer) => self.connect_peer(epoch, peer)?,
                core::Inbound::Disconnected(peer) => {
                    if let Some(i) = self
                        .peers
                        .iter()
                        .position(|p| p.core == peer && p.epoch == epoch)
                    {
                        let p = self.peers.remove(i);
                        self.cancel_signs(Some(p.nse))?;
                        self.service.disconnect_peer(p.nse)?;
                    }
                }
                core::Inbound::Traffic {
                    connection: Some(peer),
                    direction: Direction::Inbound,
                    traffic: core::OwnedTraffic::Full(bytes),
                    ..
                } => {
                    if let Some(p) = self
                        .peers
                        .iter()
                        .find(|p| p.core == peer && p.epoch == epoch)
                    {
                        match self
                            .service
                            .receive(p.nse, bytes.as_ref(), &mut self.memory)
                        {
                            Ok(pure::Received::SelfUpdate) => {
                                self.report.self_updates =
                                    self.report.self_updates.saturating_add(1)
                            }
                            Ok(pure::Received::Better | pure::Received::Carryover) => {
                                self.report.remote_claims =
                                    self.report.remote_claims.saturating_add(1)
                            }
                            Ok(_) => {}
                            Err(
                                ProtocolError::Authentication
                                | ProtocolError::Malformed
                                | ProtocolError::Truncated
                                | ProtocolError::InvalidInput
                                | ProtocolError::Unsupported,
                            ) => {
                                self.report.rejected_claims =
                                    self.report.rejected_claims.saturating_add(1)
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                _ => {}
            },
            core::Progress::Finished {
                epoch,
                send,
                completion,
                ..
            } => {
                if let Some(i) = self
                    .sends
                    .iter()
                    .position(|s| s.operation == send && s.epoch == epoch)
                {
                    let s = self.sends.remove(i);
                    if completion.outcome == core::SendOutcome::Written {
                        match self.service.transmitted(&s.request) {
                            Ok(()) => {
                                self.report.submissions = self.report.submissions.saturating_add(1)
                            }
                            Err(ProtocolError::Stale) => {}
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
            }
            core::Progress::Lost { .. } => {
                self.report.core_losses = self.report.core_losses.saturating_add(1);
                self.cancel_signs(None)?;
                self.service.core_lost();
                self.peers.clear();
                self.core_local = None;
                self.waiting_send = None;
                self.alarm = None;
                self.sleep = None;
            }
            core::Progress::Capacity(_) => {
                let _retired = self.core.reconnect()?;
                self.cancel_signs(None)?;
                self.service.core_lost();
                self.peers.clear();
                self.core_local = None;
                self.waiting_send = None;
            }
            core::Progress::Closed => return Err(ProtocolError::Closed.into()),
            _ => {}
        }
        Ok(Progress::Activity)
    }
    fn handle_pils(&mut self, progress: pils::Progress<'a, P>) -> Result<Progress, Error> {
        match progress {
            pils::Progress::Inbound(pc::Inbound::Identity { identity, .. }) => {
                let changed = self
                    .pils_identity
                    .is_some_and(|old| old.peer() != identity.peer());
                self.pils_identity = Some(identity);
                if changed
                    || self
                        .core_local
                        .is_some_and(|(_, p)| p.identity().0 != *identity.peer().as_bytes())
                {
                    self.retire_identity()?;
                    return Ok(Progress::Retired);
                }
            }
            pils::Progress::Inbound(pc::Inbound::Complete(completion)) => {
                if let Some(i) = self
                    .signs
                    .iter()
                    .position(|s| s.operation == completion.operation())
                {
                    let sign = self.signs.remove(i);
                    match completion {
                        pc::Completion::Signature {
                            peer, signature, ..
                        } => match self.service.signed(
                            &sign.request,
                            *peer.as_bytes(),
                            *signature.as_bytes(),
                        ) {
                            Ok(()) => {
                                self.report.signatures = self.report.signatures.saturating_add(1)
                            }
                            Err(ProtocolError::Stale | ProtocolError::Cancelled) => {}
                            Err(e) => return Err(e.into()),
                        },
                        _ => {
                            self.retire_identity()?;
                            return Err(ProtocolError::Authentication.into());
                        }
                    }
                }
            }
            pils::Progress::Lost { .. } => {
                self.report.pils_losses = self.report.pils_losses.saturating_add(1);
                self.pils_identity = None;
                self.retire_identity()?;
                return Ok(Progress::Retired);
            }
            pils::Progress::Closed => return Err(ProtocolError::Closed.into()),
            _ => {}
        }
        Ok(Progress::Activity)
    }
    fn poll_core(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        let result = {
            let mut drive = std::pin::pin!(self.core.drive(None));
            drive.as_mut().poll(cx)
        };
        match result {
            Poll::Ready(Ok(p)) => Poll::Ready(self.handle_core(p)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_pils(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        let result = {
            let mut drive = std::pin::pin!(self.pils.drive(None));
            drive.as_mut().poll(cx)
        };
        match result {
            Poll::Ready(Ok(p)) => Poll::Ready(self.handle_pils(p)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
    fn subscriber_frame(&mut self, index: usize) -> Result<(), Error> {
        let sub = self.subscribers[index]
            .as_mut()
            .ok_or(ProtocolError::Stale)?;
        let frame = sub.framed.frame().ok_or(ProtocolError::NotReady)?;
        let valid = nse::decode_start(frame);
        if valid.is_err() {
            let unknown = official::Frame::decode(frame)?.header().message_type()
                != official::message_type::NSE_START;
            if self.options.tolerant && unknown {
                let _released = sub.framed.release_frame();
                return Ok(());
            }
            return Err(ProtocolError::Malformed.into());
        }
        if let Some(id) = sub.id {
            if sub.framed.queued_frames() == 0 {
                self.service.unsubscribe(id)?;
                sub.id = Some(self.service.subscribe(frame)?);
            } else {
                sub.refresh = true;
            }
        } else {
            sub.id = Some(self.service.subscribe(frame)?);
        }
        if !sub.framed.release_frame() {
            return Err(ProtocolError::NotReady.into());
        }
        Ok(())
    }
    fn poll_subscribers(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        let len = self.subscribers.len();
        for offset in 0..len {
            let i = (self.subscriber_cursor + offset) % len;
            if self.subscribers[i].is_none() {
                continue;
            }
            if self.subscribers[i]
                .as_ref()
                .is_some_and(|s| s.framed.frame().is_some())
            {
                if self.subscriber_frame(i).is_err() {
                    self.close_subscriber(i);
                    return Poll::Ready(Ok(Progress::SubscriberClosed));
                }
                self.subscriber_cursor = (i + 1) % len;
                return Poll::Ready(Ok(Progress::Activity));
            }
            let write = self.subscribers[i]
                .as_mut()
                .ok_or(ProtocolError::Stale)?
                .framed
                .poll_write(cx);
            match write {
                Poll::Ready(Ok(p)) => {
                    if p.complete {
                        self.service.notified(&p.origin)?;
                        self.report.estimates = self.report.estimates.saturating_add(1);
                        let sub = self.subscribers[i].as_mut().ok_or(ProtocolError::Stale)?;
                        if sub.refresh {
                            if let Some(id) = sub.id {
                                self.service.unsubscribe(id)?;
                            }
                            sub.id = Some(self.service.subscribe(&[0, 4, 1, 65])?);
                            sub.refresh = false;
                        }
                    }
                    self.subscriber_cursor = (i + 1) % len;
                    return Poll::Ready(Ok(if p.complete {
                        Progress::EstimateWritten
                    } else {
                        Progress::Activity
                    }));
                }
                Poll::Ready(Err(_)) => {
                    self.close_subscriber(i);
                    return Poll::Ready(Ok(Progress::SubscriberClosed));
                }
                Poll::Pending => {}
            }
            match self.subscribers[i]
                .as_mut()
                .ok_or(ProtocolError::Stale)?
                .framed
                .poll_read(cx)
            {
                Poll::Ready(Ok(ReadStep::Eof)) | Poll::Ready(Err(_)) => {
                    self.close_subscriber(i);
                    return Poll::Ready(Ok(Progress::SubscriberClosed));
                }
                Poll::Ready(Ok(_)) => {
                    self.subscriber_cursor = (i + 1) % len;
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
    /// Admit one actual canonically initialized stream. Original diagnostics are
    /// observed first; ACL/kernel credentials and all framing allocation precede
    /// any pure subscriber or START. A false/error result closes that exact
    /// unadmitted stream and does not resume an EMFILE-suspended listener.
    pub fn admit(
        &mut self,
        accepted: AcceptedConnection,
        observe: &mut impl FnMut(SocketEvent),
    ) -> Result<bool, Error> {
        let (connection, peer, diagnostics) = accepted.into_parts();
        for diagnostic in diagnostics {
            observe(SocketEvent::Diagnostic(diagnostic));
        }
        let result = (|| -> Result<bool, Error> {
            if self.closed {
                return Err(ProtocolError::Closed.into());
            }
            let allowed = match peer {
                PeerAddress::Unix => self.unix.allows(&connection)?,
                PeerAddress::Tcp(address) => self.options.access.allows(address.ip()),
            };
            if !allowed {
                drop(connection);
                self.report.rejected = self.report.rejected.saturating_add(1);
                return Ok(false);
            }
            let slot = self
                .subscribers
                .iter()
                .position(Option::is_none)
                .ok_or(ProtocolError::Capacity)?;
            self.attach(slot, connection)?;
            self.report.accepted = self.report.accepted.saturating_add(1);
            Ok(true)
        })();
        if result.is_err() {
            self.report.admission_failures = self.report.admission_failures.saturating_add(1);
        }
        result
    }
    fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(SocketEvent),
    ) -> Poll<Result<Progress, Error>> {
        if !self.accept.ready() {
            return Poll::Pending;
        }
        if self.subscribers.iter().all(Option::is_some) {
            return Poll::Pending;
        }
        for offset in 0..listeners.len() {
            let i = (self.listener_cursor + offset) % listeners.len();
            match listeners[i].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    observe(self.accept.failed(e));
                    self.listener_cursor = (i + 1) % listeners.len();
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(accepted)) => {
                    let peer = accepted.peer();
                    self.listener_cursor = (i + 1) % listeners.len();
                    return Poll::Ready(Ok(match self.admit(accepted, observe) {
                        Ok(true) => Progress::Accepted,
                        Ok(false) => Progress::AdmissionRejected { peer },
                        Err(error) => Progress::AdmissionFailed { peer, error },
                    }));
                }
            }
        }
        Poll::Pending
    }
    fn attach(&mut self, index: usize, connection: Connection) -> Result<(), Error> {
        let mut framed = Framed::new(
            connection,
            FrameLimits {
                frame_bytes: nse::ESTIMATE_LEN,
                ordinary: Budget {
                    frames: 1,
                    bytes: nse::ESTIMATE_LEN,
                },
                reserved: Budget::default(),
                accounting: Accounting::Retained,
                io_slice_bytes: self.limits.io_slice_bytes,
            },
        )?;
        framed.reserve(nse::ESTIMATE_LEN, Class::Ordinary)?;
        self.subscribers[index] = Some(Subscriber {
            framed,
            id: None,
            refresh: false,
        });
        Ok(())
    }
    fn notification(&mut self, now: u64) -> Result<bool, Error> {
        if self.notification_bytes.is_none() {
            self.notification_bytes = Some(bytes(nse::ESTIMATE_LEN)?);
        }
        let Some(notification) = self.service.next_notification(now)? else {
            return Ok(false);
        };
        let sub = self
            .subscribers
            .iter_mut()
            .flatten()
            .find(|s| s.id == Some(notification.subscriber()))
            .ok_or(ProtocolError::Stale)?;
        let mut output = self
            .notification_bytes
            .take()
            .ok_or(ProtocolError::NotReady)?;
        let n = notification.encode(&mut output)?;
        output.truncate(n);
        sub.framed
            .enqueue_owned(OwnedFrame::new(output), notification, Class::Ordinary)
            .map_err(|r| r.reason)?;
        Ok(true)
    }
    fn effects(&mut self, now: u64, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        match self.activate(now) {
            Ok(Some(progress)) => return Poll::Ready(Ok(progress)),
            Ok(None) => {}
            Err(Error::Backend(error)) => {
                self.backend_fault = true;
                self.retire_identity()?;
                return Poll::Ready(Err(Error::Backend(error)));
            }
            Err(error) => return Poll::Ready(Err(error)),
        }
        if self.notification(now)? {
            return Poll::Ready(Ok(Progress::Activity));
        }
        if self.service.identity().is_none() {
            return Poll::Pending;
        }
        if self.persist.is_none() && now >= self.persist_at {
            self.persist = self.service.next_persist()?;
        }
        if let Some(request) = self.persist {
            match self.store.commit(*request.bytes()) {
                Ok(()) => {
                    self.service.persisted(&request, Ok(()))?;
                    self.persist = None;
                    self.persist_at = now.saturating_add(self.limits.checkpoint_micros);
                    self.report.durable = self.report.durable.saturating_add(1);
                    return Poll::Ready(Ok(Progress::Durable));
                }
                Err(error) => {
                    self.backend_fault = true;
                    self.retire_identity()?;
                    return Poll::Ready(Err(error.into()));
                }
            }
        }
        if self.waiting_sign.is_none() && self.signs.len() < P {
            self.waiting_sign = self.service.next_sign()?;
        }
        if let Some(request) = self.waiting_sign {
            let identity = self.pils_identity.ok_or(ProtocolError::NotReady)?;
            match self
                .pils
                .sign(&request.payload()?, KeyTarget::Exact(identity))
            {
                Ok(operation) => {
                    self.signs.push(Sign { request, operation });
                    self.waiting_sign = None;
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Err(pils::Error::Protocol(ProtocolError::Capacity | ProtocolError::WouldBlock)) => {
                }
                Err(error) => return Poll::Ready(Err(error.into())),
            }
        }
        if self.waiting_send.is_none() && self.sends.len() < P {
            self.waiting_send = self.service.next_transmission()?;
        }
        if let Some(request) = self.waiting_send {
            if let Some(peer) = self.peers.iter().find(|p| p.nse == request.peer()) {
                let mut output = bytes(flood::MESSAGE_LEN)?;
                let n = request.encode(&mut output)?;
                output.truncate(n);
                let message = core::Message::try_from_owned(output).map_err(|r| r.reason)?;
                match self.core.send(peer.core, 0, u64::MAX, message) {
                    Ok(operation) => {
                        self.sends.push(Send {
                            request,
                            operation,
                            epoch: peer.epoch,
                        });
                        self.waiting_send = None;
                        // The actual original CORE SendId/source is retained.
                        // Count this local admission once; later whole writes
                        // and loss remain independent original observations.
                        let _observed = self.service.transmission_admitted(&request);
                        return Poll::Ready(Ok(Progress::Activity));
                    }
                    Err(r)
                        if matches!(
                            r.reason,
                            ProtocolError::Capacity | ProtocolError::WouldBlock
                        ) => {}
                    Err(r) => return Poll::Ready(Err(r.reason.into())),
                }
            } else {
                self.waiting_send = None;
            }
        }
        if let Some(request) = self.service.work_request() {
            let progress =
                self.service
                    .work(&request, self.limits.work_budget, now, &mut self.memory)?;
            self.report.work_calls = self.report.work_calls.saturating_add(1);
            if matches!(progress, pure::WorkProgress::Found(_)) {
                self.persist_at = now;
                self.report.proofs = self.report.proofs.saturating_add(1);
            }
            return Poll::Ready(Ok(Progress::Work(progress)));
        }
        let selected = self.service.next_alarm(now, &mut NoRandom)?;
        if self.alarm != selected {
            self.alarm = selected;
            self.sleep = None;
        }
        if let Some(alarm) = self.alarm {
            if now >= alarm.deadline() {
                let progress = self.service.alarm_fired(&alarm, now)?;
                if progress == pure::AlarmProgress::Round {
                    self.report.rounds = self.report.rounds.saturating_add(1);
                }
                self.alarm = None;
                self.sleep = None;
                return Poll::Ready(Ok(Progress::Alarm(progress)));
            }
            if self.sleep.is_none() {
                self.sleep = Some(Box::pin(
                    Deadline::at(
                        self.clock.clone(),
                        gnunet_types::AbsoluteTime::from_micros(alarm.deadline()),
                    )
                    .map_err(Error::Clock)?,
                ));
            }
            match self
                .sleep
                .as_mut()
                .ok_or(ProtocolError::NotReady)?
                .as_mut()
                .poll(cx)
            {
                Poll::Ready(Ok(())) => {
                    self.sleep = None;
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Err(error)) => {
                    self.clock_error = Some(error);
                    return Poll::Ready(Err(Error::Clock(error)));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
    /// Explicitly settle the original unknown raw8 commit before reactivation.
    /// The original pure identity barrier remains in place throughout recovery.
    pub fn recover_backend(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if !self.backend_fault {
            return Err(ProtocolError::NotReady.into());
        }
        let _settled = self.store.recover()?;
        let _saved = self.store.loaded()?;
        self.persist = None;
        self.backend_fault = false;
        Ok(())
    }
    /// Permanently stop original physical clients/subscribers before pure authority.
    pub fn close(&mut self) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        let core_closed = self.core.close();
        let _pils = self.pils.close();
        for i in 0..self.subscribers.len() {
            self.close_subscriber(i);
        }
        self.subscription = None;
        self.sleep = None;
        self.wait = None;
        // Permanent closure is set before a fallible flush, so Drop cannot replay
        // a failed original native commit after this close attempt returns.
        self.closed = true;
        let flush = (|| {
            if self.backend_fault {
                return Ok(());
            }
            if self.persist.is_none() {
                self.persist = self.service.next_persist()?;
            }
            if let Some(request) = self.persist {
                self.store.commit(*request.bytes())?;
                self.service.persisted(&request, Ok(()))?;
                self.persist = None;
                self.report.durable = self.report.durable.saturating_add(1);
            }
            Ok::<_, Error>(())
        })();
        self.service.close();
        match (core_closed.map_err(Error::from), flush) {
            (Ok(_), result) => result,
            (Err(original), Ok(())) => Err(original),
            (Err(original), Err(cleanup)) => Err(Error::Cleanup {
                original: Box::new(original),
                cleanup: Box::new(cleanup),
            }),
        }
    }
    fn poll_drive(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(SocketEvent),
        deadline: Option<Instant>,
    ) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        let now = match self.now(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(now) => now?,
        };
        if self.backend_fault {
            return Poll::Ready(Ok(Progress::BackendQuiescent));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        for offset in 0..5 {
            let group = (self.cursor + offset) % 5;
            let result = match group {
                0 => self.poll_core(cx),
                1 => self.poll_pils(cx),
                2 => self.poll_subscribers(cx),
                3 => self.poll_accept(cx, listeners, observe),
                _ => self.effects(now, cx),
            };
            if result.is_ready() {
                self.cursor = (group + 1) % 5;
                return result;
            }
        }
        if let Some(deadline) = deadline {
            let timer = self
                .wait
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
            timer.as_mut().reset(deadline);
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
        }
        Poll::Pending
    }
    /// Drive one bounded native action. Dropping the future preserves all original
    /// physical streams, pure leases, backend outcomes and partial cursors.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        observe: &mut impl FnMut(SocketEvent),
        deadline: Option<Instant>,
    ) -> Result<Progress, Error> {
        poll_fn(|cx| {
            // This scheduling state belongs to the Host, so a containing owner
            // may drop/recreate a singly-polled drive without restarting its
            // yield forever. Pending here consumes no original effect/event.
            if self.yield_due {
                self.yield_due = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let result = self.poll_drive(cx, listeners, observe, deadline);
            if result.is_ready() {
                self.yield_due = true;
            }
            result
        })
        .await
    }
}
impl<const P: usize, const S: usize> Drop for Host<'_, P, S> {
    fn drop(&mut self) {
        let _closed = self.close();
    }
}
