//! Actual ARM IPC/native reactor. All OS owners survive a canceled Driver::drive.
//! Managed listener readiness never accepts; accepted control sockets use a
//! different owner. Ordinary work precedes source IDLE restart callbacks.
use crate::{
    framed::{self, FramedConnection, Received},
    listeners::ManagedListeners,
    registry::{Recipe, Registry},
};
use gnunet_arm_core::wire::ServiceInfo;
use gnunet_arm_service_core::{
    ChildId, ClientId, NativeEffect, NativeTicket, Owner, OwnerId, Phase, ServiceId, SpawnOutcome,
    TimerAction, TimerEffect, TimerId,
};
use gnunet_config::Configuration;
use gnunet_service_runtime::{
    BoundListeners,
    process::{
        self, ChildExit, ChildRegistry, EnvironmentSnapshot, LaunchError, NativeCommand,
        OriginalChild, ProcessLimits, Reaped, SpawnResult,
    },
    service::{Listener, PeerAddress, ServiceOptions},
};
use gnunet_service_runtime::{
    accepted::{AcceptError, AcceptState, SocketEvent},
    connection::Connection,
};
use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    io,
    os::fd::AsFd,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::{Instant, Sleep};
/// Host/resource failure. Native authority and leased tickets remain owned.
#[derive(Debug)]
pub enum Error {
    /// Formal state rejected this exact operation.
    Core(gnunet_arm_service_core::Error),
    /// Actual managed listener lifecycle failed.
    Listener(crate::listeners::Error),
    /// Native preparation, wait or signal failed.
    Native(LaunchError),
    /// Native control listener accept failed.
    Io(io::Error),
    /// UTC could not be obtained; original observation is retained for retry.
    Clock(io::Error),
    /// Explicit host metadata or transport capacity is exhausted.
    Capacity,
    /// Actual shared spawn call refused the explicit finite child/resource profile; no child exists.
    AdmissionCapacity,
    /// Registry/owner/original native capability do not agree.
    Mapping,
    /// A pre-existing foreign completion was recovered without acknowledging it as this daemon child.
    ForeignCompletion(Reaped),
    /// Invalid driver configuration or lifecycle phase.
    State,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ARM reactor: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<gnunet_arm_service_core::Error> for Error {
    fn from(e: gnunet_arm_service_core::Error) -> Self {
        Self::Core(e)
    }
}
impl From<crate::listeners::Error> for Error {
    fn from(e: crate::listeners::Error) -> Self {
        Self::Listener(e)
    }
}
impl From<LaunchError> for Error {
    fn from(e: LaunchError) -> Self {
        Self::Native(e)
    }
}
/// Source absolute UTC clock, in microseconds. It is not an invented wire field.
pub trait Clock {
    /// Obtain source handling time without mutating the process-wide time profile.
    fn utc(&mut self) -> io::Result<u64>;
}
/// Real system UTC; a pre-epoch clock is a visible error rather than time zero.
pub struct SystemClock;
impl Clock for SystemClock {
    fn utc(&mut self) -> io::Result<u64> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        Ok(u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX))
    }
}
/// Finite memory and work profile, separate from official configuration keys.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneously retained control streams.
    pub clients: usize,
    /// Maximum registry/native mapping entries, at least Registry::services().len().
    pub services: usize,
    /// Maximum complete official input frame, at most65535.
    pub frame_bytes: usize,
    /// Durable remaining TX bytes per client.
    pub tx_bytes: usize,
    /// Durable envelope metadata per client.
    pub tx_frames: usize,
    /// Maximum actual socket read/write slice per syscall.
    pub io_slice: usize,
    /// Settlement operations before yielding without polling unrelated I/O.
    pub settlement_budget: usize,
    /// Retained diagnostic observations; excess increments a visible count.
    pub diagnostics: usize,
    /// Shared source-native process bounds.
    pub process: ProcessLimits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 32,
            services: 256,
            frame_bytes: 65535,
            tx_bytes: 262140,
            tx_frames: 1025,
            io_slice: 65535,
            settlement_budget: 64,
            diagnostics: 64,
            process: ProcessLimits::default(),
        }
    }
}
/// Actual native/stream observations; no application readiness is inferred.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    /// Actually admitted control streams.
    pub accepted: u64,
    /// Actual control descriptor closes.
    pub closed: u64,
    /// Explicit local resource closes, distinct from optional source notification drops.
    pub resource_closes: u64,
    /// Actually dispatched official input frames.
    pub received: u64,
    /// Complete borrowed envelopes copied into durable TX.
    pub handed_off: u64,
    /// Actual shared-process admitted children.
    pub spawned: u64,
    /// Actual no-child refusals.
    pub spawn_refused: u64,
    /// Actual pipe/native TERM attempts, including OS refusal.
    pub term_attempts: u64,
    /// Actual forced native SIGKILL attempts; never a death/reap receipt.
    pub kill_attempts: u64,
    /// Actual consuming wait observations acknowledged by core.
    pub reaped: u64,
    /// Actual original IDLE timer registrations dispatched into the owner.
    pub timer_callbacks: u64,
    /// Diagnostic observations omitted because caller storage is full.
    pub diagnostics_omitted: u64,
}
/// Bounded nonfatal diagnostic, corresponding to source logging sites.
#[derive(Debug)]
pub enum Diagnostic {
    /// Actual source-nonfatal accepted-socket initialization diagnostic.
    AcceptedSocket(gnunet_native::network::Diagnostic),
    /// Fatal initialization closed the accepted socket; earlier warnings remain.
    AcceptedSocketFailure(gnunet_native::network::InitializationError),
    /// Native accept failed; the listener remains owned. A raw EMFILE only
    /// changes the service suspension reason and is not logged as a warning.
    Accept(io::Error),
    /// Actual no-child refusal diagnostic.
    Spawn(Option<io::Error>),
    /// Actual finite host preparation refusal, before any child existed.
    Admission(Error),
    /// A real signal attempt failed; source still transitions after the attempt.
    Signal(LaunchError),
    /// A malformed/truncated/native-failed peer was logically retired. The
    /// self-stop requester's persisted descriptor remains in external State.
    Peer(framed::Error),
}
struct Session<'scope> {
    id: ClientId<'scope>,
    io: FramedConnection,
    send_first: bool,
}
struct Child<'scope> {
    core: ChildId<'scope>,
    original: OriginalChild,
    service: usize,
}
#[derive(Clone, Copy)]
enum Native<'scope> {
    Spawn {
        ticket: NativeTicket<'scope>,
        child: ChildId<'scope>,
        service: ServiceId<'scope>,
        pipe: bool,
    },
    Term {
        ticket: NativeTicket<'scope>,
        child: ChildId<'scope>,
    },
}
struct Timer<'scope> {
    id: TimerId<'scope>,
    at_utc: u64,
    sleep: Option<Pin<Box<Sleep>>>,
}
/// Caller-owned physical reactor state. Dropping a Driver borrow does not drop
/// this value, its partial stream cursors, leased operations or native mappings.
/// The independent ChildRegistry must be retained and drained after final use.
pub struct State<'scope, 'registry> {
    owner: Option<OwnerId<'scope>>,
    registry: Option<&'registry Registry>,
    control: Option<BoundListeners>,
    control_accept: AcceptState,
    sessions: Vec<Session<'scope>>,
    next_session: usize,
    next_ordinary: usize,
    persisted: Vec<Connection>,
    children: Vec<Child<'scope>>,
    services: Vec<ServiceId<'scope>>,
    pending_native: Option<Native<'scope>>,
    spawn_outcome: Option<SpawnOutcome>,
    term_attempted: bool,
    pending_reap: Option<Reaped>,
    pending_usage: Option<process::ResourceUsage>,
    resource_event: Option<ResourceEvent>,
    unix_access: gnunet_service_runtime::credentials::UnixAccess,
    retired: bool,
    timer: Option<Timer<'scope>>,
    pending_timer: Option<TimerEffect<'scope>>,
    scanning: bool,
    shutdown_requested: bool,
    shutdown_sending: bool,
    initialized: bool,
    diagnostics: VecDeque<Diagnostic>,
    limits: Limits,
    counters: Counters,
}
impl<'scope, 'registry> State<'scope, 'registry> {
    /// Reserve complete metadata before connecting any core client. Control
    /// listener ownership is transferred once; created-path guards stay here.
    pub fn new(control: BoundListeners, limits: Limits) -> Result<Self, Error> {
        if limits.clients == 0
            || limits.services == 0
            || !(4..=65535).contains(&limits.frame_bytes)
            || limits.tx_bytes < 4
            || limits.tx_frames == 0
            || limits.io_slice == 0
            || limits.settlement_budget == 0
        {
            return Err(Error::Capacity);
        }
        let mut sessions = Vec::new();
        sessions
            .try_reserve_exact(limits.clients)
            .map_err(|_| Error::Capacity)?;
        let mut persisted = Vec::new();
        persisted
            .try_reserve_exact(limits.clients)
            .map_err(|_| Error::Capacity)?;
        let mut children = Vec::new();
        children
            .try_reserve_exact(limits.services)
            .map_err(|_| Error::Capacity)?;
        let mut services = Vec::new();
        services
            .try_reserve_exact(limits.services)
            .map_err(|_| Error::Capacity)?;
        let mut diagnostics = VecDeque::new();
        diagnostics
            .try_reserve_exact(limits.diagnostics)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            owner: None,
            registry: None,
            control: Some(control),
            control_accept: AcceptState::default(),
            sessions,
            next_session: 0,
            next_ordinary: 0,
            persisted,
            children,
            services,
            pending_native: None,
            spawn_outcome: None,
            term_attempted: false,
            pending_reap: None,
            pending_usage: None,
            resource_event: None,
            unix_access: Default::default(),
            retired: false,
            timer: None,
            pending_timer: None,
            scanning: false,
            shutdown_requested: false,
            shutdown_sending: false,
            initialized: false,
            diagnostics,
            limits,
            counters: Counters::default(),
        })
    }
    /// Set explicit kernel Unix admission before this original state is bound
    /// to any formal owner. Replacing a live source policy is refused.
    pub fn set_unix_access(
        &mut self,
        access: gnunet_service_runtime::credentials::UnixAccess,
    ) -> Result<(), Error> {
        if self.initialized || self.owner.is_some() || self.retired {
            return Err(Error::State);
        }
        self.unix_access = access;
        Ok(())
    }
    /// Clock-free emergency physical IO retirement. This does not acknowledge
    /// pure listener/native/timer effects or claim managed children were reaped.
    /// The original dedicated ChildRegistry must still be signaled/drained.
    pub fn retire_io(&mut self) -> RetiredIo {
        self.retired = true;
        let report = RetiredIo {
            clients: self.sessions.len(),
            persisted: self.persisted.len(),
            control: self.control.is_some(),
        };
        drop(self.control.take());
        self.sessions.clear();
        self.persisted.clear();
        self.timer = None;
        self.pending_timer = None;
        report
    }
    /// One real consuming wait4 observation retained independently from the
    /// formal acknowledgment. No later reap proceeds until caller takes it.
    pub fn take_resource_event(&mut self) -> Option<ResourceEvent> {
        self.resource_event.take()
    }
    /// Actual cumulative observations, retained across temporary driver borrows.
    pub fn counters(&self) -> Counters {
        self.counters
    }
    /// Consume one bounded source diagnostic.
    pub fn take_diagnostic(&mut self) -> Option<Diagnostic> {
        self.diagnostics.pop_front()
    }
    /// Read the immutable registered service for an actual original child.
    /// Cleanup uses this after a wait error; a bare/reused PID grants no match.
    pub fn service_for_child(&self, child: &OriginalChild) -> Option<usize> {
        self.children
            .iter()
            .find(|c| c.original == *child)
            .map(|c| c.service)
    }
    /// Original actual native mappings, independently retained in ChildRegistry.
    pub fn children(&self) -> impl Iterator<Item = &OriginalChild> {
        self.children.iter().map(|c| &c.original)
    }
    /// Persisted requester sockets retained after generic cleanup, closing only
    /// when this external State is explicitly dropped (foreground process exit).
    pub fn persisted_count(&self) -> usize {
        self.persisted.len()
    }
    /// Number of active control sessions, excluding persisted retired sockets.
    pub fn client_count(&self) -> usize {
        self.sessions.len()
    }
    fn diagnostic(&mut self, d: Diagnostic) {
        if self.diagnostics.len() < self.limits.diagnostics {
            self.diagnostics.push_back(d);
        } else {
            self.counters.diagnostics_omitted = self.counters.diagnostics_omitted.saturating_add(1);
        }
    }
}
/// Actual clock-free emergency descriptor ownership retirement, not child death.
#[derive(Clone, Copy, Debug)]
pub struct RetiredIo {
    /// Actual active connection owners dropped.
    pub clients: usize,
    /// Actual persisted self-stop connection owners dropped.
    pub persisted: usize,
    /// Actual control BoundListeners owner was consumed.
    pub control: bool,
}
/// Exact original wait4 resource receipt. Service is an immutable registry index;
/// no arbitrary PID/name can be substituted by the foreground logger.
#[derive(Debug)]
pub struct ResourceEvent {
    /// Original registered service index.
    pub service: usize,
    /// Actual consuming wait observation for its original child.
    pub event: Reaped,
    /// Actual OS-native rusage, never estimated from signals or elapsed time.
    pub usage: process::ResourceUsage,
}
/// One completed source callback settlement or completed generic runtime cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Activity {
    /// At least one actual operation progressed; calling again continues driving.
    Progress,
    /// Managed cleanup completed; persisted requester sockets remain in State until drop.
    Closed,
}
/// Borrowed driver; native ownership is always in external State/ChildRegistry.
pub struct Driver<'view, 'scope, 'spec, 'slots, 'bytes, C> {
    owner: &'view mut Owner<'scope, 'spec, 'slots, 'bytes>,
    registry: &'spec Registry,
    managed: &'view mut ManagedListeners<'scope>,
    children: &'view mut ChildRegistry,
    state: &'view mut State<'scope, 'spec>,
    config: &'view Configuration,
    helper: &'view Path,
    environment: &'view EnvironmentSnapshot,
    options: &'view ServiceOptions,
    rows: &'view mut [ServiceInfo<'spec>],
    clock: &'view mut C,
}
impl<'view, 'scope, 'spec, 'slots, 'bytes, C: Clock>
    Driver<'view, 'scope, 'spec, 'slots, 'bytes, C>
{
    /// Bind exact original service identities and prepare real SIGCHLD observation.
    /// ChildRegistry is dedicated to this daemon for the complete State lifetime:
    /// do not mix another launcher/consumer's children or completed-event queue.
    /// Unrelated visible live children are refused before any consuming wait;
    /// unexpected completed credit is returned as Error::ForeignCompletion.
    /// The caller must call ChildRegistry::prepare before registry enumeration to
    /// reproduce the source's complete startup order; this call only validates it
    /// again. No privilege/daemon/readiness success is implied.
    #[expect(
        clippy::too_many_arguments,
        reason = "Explicit borrowed owners avoid a self-referential runtime"
    )]
    pub fn new(
        owner: &'view mut Owner<'scope, 'spec, 'slots, 'bytes>,
        registry: &'spec Registry,
        managed: &'view mut ManagedListeners<'scope>,
        children: &'view mut ChildRegistry,
        state: &'view mut State<'scope, 'spec>,
        config: &'view Configuration,
        helper: &'view Path,
        environment: &'view EnvironmentSnapshot,
        options: &'view ServiceOptions,
        rows: &'view mut [ServiceInfo<'spec>],
        clock: &'view mut C,
    ) -> Result<Self, Error> {
        if state.retired {
            return Err(Error::State);
        }
        if let Some(original) = state.owner {
            if original != owner.identity() {
                return Err(Error::Mapping);
            }
        } else {
            state.owner = Some(owner.identity());
        }
        if children.children().any(|original| {
            !state
                .children
                .iter()
                .any(|owned| owned.original == *original)
        }) {
            return Err(Error::Mapping);
        }
        children.prepare()?;
        if let Some(original) = state.registry {
            if !std::ptr::eq(original, registry) {
                return Err(Error::Mapping);
            }
        } else {
            state.registry = Some(registry);
        }
        if registry.services().len() > state.limits.services
            || rows.len() < registry.services().len()
        {
            return Err(Error::Capacity);
        }
        if !state.initialized {
            if owner.phase() != Phase::Configuring {
                return Err(Error::State);
            }
            for (index, service) in registry.services().iter().enumerate() {
                let id = owner.service(index).ok_or(Error::Mapping)?;
                let info = owner.info(id)?;
                if info.name != service.name || info.binary != service.binary {
                    return Err(Error::Mapping);
                }
                if let Some(original) = state.services.get(index) {
                    if *original != id {
                        return Err(Error::Mapping);
                    }
                } else {
                    state.services.push(id);
                }
            }
            managed.attach(owner)?;
            state.initialized = true;
        } else {
            for (index, id) in state.services.iter().copied().enumerate() {
                if !owner.owns_service(id) || index >= registry.services().len() {
                    return Err(Error::Mapping);
                }
            }
        }
        Ok(Self {
            owner,
            registry,
            managed,
            children,
            state,
            config,
            helper,
            environment,
            options,
            rows,
            clock,
        })
    }
    /// Request actual generic manual shutdown. Listener close and native TERM
    /// remain subsequent real operations; this does not report them completed.
    pub fn shutdown(&mut self) {
        self.state.shutdown_requested = true;
    }
    /// Escalate only the original still-owned children through the shared
    /// native signal port. The control pipe is bypassed: signal9 cannot be
    /// delegated to an application handler. Actual waits remain separate.
    pub fn kill_remaining(&mut self) {
        for index in 0..self.state.children.len() {
            let original = self.state.children[index].original.clone();
            if self.children.owns(&original) {
                if let Err(error) = self.children.signal_native(&original, libc::SIGKILL) {
                    self.state.diagnostic(Diagnostic::Signal(error))
                }
                self.state.counters.kill_attempts =
                    self.state.counters.kill_attempts.saturating_add(1);
            }
        }
    }
    /// Borrow current observations without transferring native authority.
    pub fn counters(&self) -> Counters {
        self.state.counters
    }
    /// Admit one already accepted physical connection after peer policy. This is
    /// also a safe embedding port; it performs no fake listener readiness.
    pub fn admit(&mut self, stream: Connection, peer: PeerAddress) -> Result<bool, Error> {
        if matches!(peer, PeerAddress::Unix)
            && !self.state.unix_access.allows(&stream).map_err(Error::Io)?
        {
            drop(stream);
            return Ok(false);
        }
        if let PeerAddress::Tcp(address) = peer
            && !self.options.access.allows(address.ip())
        {
            drop(stream);
            return Ok(false);
        }
        if self.state.sessions.len() + self.state.persisted.len() >= self.state.limits.clients {
            drop(stream);
            return Err(Error::Capacity);
        }
        let l = self.state.limits;
        let io = FramedConnection::new(stream, l.frame_bytes, l.tx_bytes, l.tx_frames, l.io_slice)
            .map_err(|_| Error::Capacity)?;
        let id = self.owner.connect()?;
        self.state.sessions.push(Session {
            id,
            io,
            send_first: false,
        });
        self.state.counters.accepted = self.state.counters.accepted.saturating_add(1);
        Ok(true)
    }
    /// Consume one bounded nonfatal actual diagnostic.
    pub fn take_diagnostic(&mut self) -> Option<Diagnostic> {
        self.state.take_diagnostic()
    }
    /// Consume one actual resource record so its caller can write it before
    /// the next consuming reap. Canceling drive does not discard this receipt.
    pub fn take_resource_event(&mut self) -> Option<ResourceEvent> {
        self.state.take_resource_event()
    }
    /// Current official service state, from the original formal owner.
    pub fn service_info(
        &self,
        index: usize,
    ) -> Result<gnunet_arm_service_core::ServiceInfo<'spec>, Error> {
        let id = *self.state.services.get(index).ok_or(Error::Mapping)?;
        self.owner.info(id).map_err(Error::from)
    }
    /// Current startup/shutdown phase; no native readiness is inferred.
    pub fn phase(&self) -> Phase {
        self.owner.phase()
    }
    /// Number of active control sessions, excluding persisted retired sockets.
    pub fn client_count(&self) -> usize {
        self.state.sessions.len()
    }
    fn close(&mut self, index: usize, resource: bool) -> Result<(), Error> {
        let session = self.state.sessions.remove(index);
        if self.state.next_session > index {
            self.state.next_session -= 1;
        }
        if self.state.next_session >= self.state.sessions.len() {
            self.state.next_session = 0;
        }
        let persisted = self.owner.client_persisted(session.id)?;
        self.owner.disconnect(session.id)?;
        if persisted {
            // service.c:finish_client_drop frees only the network handle for a
            // persisted requester. Retain its actual descriptor until the
            // enclosing process State ends, without resuming EMFILE acceptance.
            self.state.persisted.push(session.io.into_connection());
        } else {
            drop(session);
            self.state.control_accept.client_closed();
            self.state.counters.closed = self.state.counters.closed.saturating_add(1);
            self.state.counters.resource_closes = self
                .state
                .counters
                .resource_closes
                .saturating_add(u64::from(resource));
        }
        Ok(())
    }
    fn utc(&mut self) -> Result<u64, Error> {
        self.clock.utc().map_err(Error::Clock)
    }
    fn spawn_service(
        &mut self,
        service: ServiceId<'scope>,
        pipe: bool,
    ) -> Result<SpawnResult, Error> {
        let index = self
            .state
            .services
            .iter()
            .position(|id| *id == service)
            .ok_or(Error::Mapping)?;
        let entry = self.registry.services().get(index).ok_or(Error::Mapping)?;
        let (filename, argv) = match &entry.recipe {
            Recipe::Gnunet(command) => {
                let argv = process::parse_command(
                    command,
                    self.state.limits.process.launch.max_arguments,
                )?;
                let filename = argv.first().cloned().unwrap_or_default();
                (filename, argv)
            }
            Recipe::Simple {
                filename,
                argv0,
                options,
            } => (filename.clone(), vec![argv0.clone(), options.clone()]),
        };
        if self.state.children.len() == self.state.limits.services {
            return Err(Error::Capacity);
        }
        let mut listeners = Vec::new();
        listeners
            .try_reserve_exact(self.managed.len())
            .map_err(|_| Error::Capacity)?;
        for i in 0..self.managed.len() {
            if self.managed.service_index(i) == Some(index) {
                let id = self.managed.id(i).ok_or(Error::Mapping)?;
                listeners.push(self.managed.descriptor(id).ok_or(Error::Mapping)?);
            }
        }
        let command = NativeCommand {
            filename,
            argv,
            environment: self.environment.clone(),
            environment_changes: Vec::new(),
            cwd: None,
            stdio: 6 | if pipe { 8 } else { 0 },
            stdio_snapshot: None,
            listeners,
            mappings: Vec::new(),
        };
        process::spawn(
            self.config,
            self.helper,
            command,
            self.state.limits.process,
            self.children,
        )
        .map_err(|error| match error {
            LaunchError::Capacity => Error::AdmissionCapacity,
            other => Error::Native(other),
        })
    }
    fn native(&mut self) -> Result<bool, Error> {
        if self.state.pending_native.is_none() {
            self.state.pending_native = self.owner.take_native()?.map(|effect| match effect {
                NativeEffect::Spawn {
                    ticket,
                    child,
                    service,
                    pipe_control,
                    ..
                } => Native::Spawn {
                    ticket,
                    child,
                    service,
                    pipe: pipe_control,
                },
                NativeEffect::Term { ticket, child } => Native::Term { ticket, child },
            });
        }
        let Some(effect) = self.state.pending_native else {
            return Ok(false);
        };
        match effect {
            Native::Spawn {
                ticket,
                child,
                service,
                pipe,
            } => {
                if !self.owner.native_current(ticket) {
                    return Err(Error::Mapping);
                }
                if self.state.spawn_outcome.is_none() {
                    match self.spawn_service(service, pipe) {
                        Ok(SpawnResult::Admitted(receipt)) => {
                            self.state.children.push(Child {
                                core: child,
                                original: receipt.child,
                                service: self
                                    .state
                                    .services
                                    .iter()
                                    .position(|id| *id == service)
                                    .ok_or(Error::Mapping)?,
                            });
                            self.state.spawn_outcome = Some(SpawnOutcome::Admitted);
                            self.state.counters.spawned =
                                self.state.counters.spawned.saturating_add(1);
                        }
                        Ok(SpawnResult::Refused { error }) => {
                            self.state.spawn_outcome = Some(SpawnOutcome::Failed);
                            self.state.counters.spawn_refused =
                                self.state.counters.spawn_refused.saturating_add(1);
                            self.state.diagnostic(Diagnostic::Spawn(error));
                        }
                        Err(error @ Error::AdmissionCapacity) => {
                            // A real no-child resource/preparation refusal is a
                            // visible host profile, never a retry that blocks
                            // original child cleanup or a manufactured admission.
                            self.state.spawn_outcome = Some(SpawnOutcome::Failed);
                            self.state.counters.spawn_refused =
                                self.state.counters.spawn_refused.saturating_add(1);
                            self.state.diagnostic(Diagnostic::Admission(error));
                        }
                        Err(error) => return Err(error),
                    }
                }
                let utc = self.utc()?;
                let outcome = self.state.spawn_outcome.ok_or(Error::State)?;
                let report = self.owner.spawned(ticket, outcome, utc)?;
                self.state.spawn_outcome = None;
                self.state.pending_native = None;
                let _closures = report.resource_closures;
            }
            Native::Term { ticket, child } => {
                if !self.owner.native_current(ticket) {
                    return Err(Error::Mapping);
                }
                if !self.state.term_attempted {
                    let original = self
                        .state
                        .children
                        .iter()
                        .find(|c| c.core == child)
                        .ok_or(Error::Mapping)?
                        .original
                        .clone();
                    if !self.children.owns(&original) {
                        return Err(Error::Mapping);
                    }
                    match self.children.signal(&original, libc::SIGTERM) {
                        Ok(_attempt) => {}
                        Err(error) => self.state.diagnostic(Diagnostic::Signal(error)),
                    }
                    self.state.term_attempted = true;
                    self.state.counters.term_attempts =
                        self.state.counters.term_attempts.saturating_add(1);
                }
                self.owner.term_attempted(ticket)?;
                self.state.term_attempted = false;
                self.state.pending_native = None;
            }
        }
        Ok(true)
    }
    fn timer(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if self.state.pending_timer.is_none() {
            self.state.pending_timer = self.owner.take_timer()?;
        }
        let Some(effect) = self.state.pending_timer else {
            return Ok(false);
        };
        if !self.owner.timer_current(effect.ticket) {
            return Err(Error::Mapping);
        }
        match effect.action {
            TimerAction::Arm { at_utc } => {
                if self.state.timer.is_none() {
                    let now = self.utc()?;
                    let sleep = if at_utc == u64::MAX {
                        None
                    } else {
                        let duration = Duration::from_micros(at_utc.saturating_sub(now));
                        let deadline = Instant::now()
                            .checked_add(duration)
                            .ok_or(Error::Capacity)?;
                        Some(Box::pin(tokio::time::sleep_until(deadline)))
                    };
                    self.state.timer = Some(Timer {
                        id: effect.id,
                        at_utc,
                        sleep,
                    });
                    if let Some(timer) = self.state.timer.as_mut()
                        && let Some(sleep) = timer.sleep.as_mut()
                    {
                        // Poll installs the actual timer entry before acknowledging
                        // the registration. A ready result is still IDLE work.
                        let _readiness = sleep.as_mut().poll(cx);
                    }
                } else if self.state.timer.as_ref().is_none_or(|t| t.id != effect.id) {
                    return Err(Error::Mapping);
                }
            }
            TimerAction::Cancel => {
                if self.state.timer.as_ref().is_some_and(|t| t.id != effect.id) {
                    return Err(Error::Mapping);
                }
                drop(self.state.timer.take());
            }
        }
        self.owner.timer_applied(effect.ticket)?;
        self.state.pending_timer = None;
        Ok(true)
    }
    fn reap(&mut self) -> Result<bool, Error> {
        if self.state.resource_event.is_some() {
            return Ok(false);
        }
        if self.state.pending_reap.is_none() {
            // This is a dedicated daemon registry. A visible unrelated original
            // must not be consumed by a different source service owner.
            if self.children.children().any(|original| {
                !self
                    .state
                    .children
                    .iter()
                    .any(|owned| owned.original == *original)
            }) {
                return Err(Error::Mapping);
            }
            let _observed = self.children.reap_completed()?;
            if let Some((event, usage)) = self.children.take_completed_with_usage() {
                self.state.pending_reap = Some(event);
                self.state.pending_usage = usage;
            }
        }
        let Some(reap) = self.state.pending_reap.as_ref() else {
            return Ok(false);
        };
        let Some(index) = self
            .state
            .children
            .iter()
            .position(|c| c.original == reap.child)
        else {
            // Preserve the actual observation as an explicit error capability;
            // never silently count it as this formal daemon's successful reap.
            let event = self.state.pending_reap.take().ok_or(Error::State)?;
            return Err(Error::ForeignCompletion(event));
        };
        let id = self.state.children[index].core;
        if let Some(usage) = self.state.pending_usage.take() {
            self.state.resource_event = Some(ResourceEvent {
                service: self.state.children[index].service,
                event: reap.clone(),
                usage,
            });
        }
        let exit = match reap.exit {
            ChildExit::Exited(code) => gnunet_arm_service_core::Exit::Exited(code as u32),
            ChildExit::Signaled { signal, .. } => {
                gnunet_arm_service_core::Exit::Signaled(signal as u32)
            }
        };
        let utc = self.utc()?;
        let report = self.owner.reaped(id, exit, utc)?;
        let _closures = report.resource_closures;
        self.state.children.remove(index);
        self.state.pending_reap = None;
        self.state.counters.reaped = self.state.counters.reaped.saturating_add(1);
        // Actual reaped(nonzero) requested an IDLE task; settle its cancellation
        // before allowing any unrelated callback to run.
        Ok(true)
    }
    fn handoff(&mut self) -> Result<bool, Error> {
        let Some(frame) = self.owner.frame() else {
            return Ok(false);
        };
        let id = frame.client;
        let ticket = frame.ticket;
        let index = self
            .state
            .sessions
            .iter()
            .position(|session| session.id == id)
            .ok_or(Error::Mapping)?;
        if let Err(error) = self.state.sessions[index].io.enqueue(frame.bytes) {
            self.state.diagnostic(Diagnostic::Peer(error));
            self.close(index, true)?;
        } else {
            self.owner.release_frame(ticket)?;
            self.state.counters.handed_off = self.state.counters.handed_off.saturating_add(1);
            self.owner
                .set_mq_length(id, self.state.sessions[index].io.mq_length())?;
        }
        Ok(true)
    }
    fn settle(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let resource_client = self.owner.resource_closures().next();
        if let Some(client) = resource_client {
            let index = self
                .state
                .sessions
                .iter()
                .position(|s| s.id == client)
                .ok_or(Error::Mapping)?;
            self.close(index, true)?;
            return Ok(true);
        }
        if self.managed.apply_next(self.owner)? {
            return Ok(true);
        }
        if self.timer(cx)? {
            return Ok(true);
        }
        let source_callback = matches!(self.owner.phase(), Phase::Configuring | Phase::Starting)
            || self.state.scanning
            || self.state.shutdown_sending;
        // A request/demand callback's actual native effect completes before an
        // unrelated child-death callback, just like the source synchronous body.
        if self.native()? {
            return Ok(true);
        }
        if self.state.shutdown_sending {
            // shutdown_task's complete synchronous TERM pass precedes the
            // next child_death callback; no consuming wait runs in its middle.
            self.state.shutdown_sending = false;
            return Ok(true);
        }
        if !source_callback && self.reap()? {
            return Ok(true);
        }
        if self.handoff()? {
            return Ok(true);
        }
        if self.owner.take_shutdown_request() {
            self.state.shutdown_requested = true;
        }
        if self.state.shutdown_requested
            && !matches!(self.owner.phase(), Phase::Draining | Phase::Closed)
        {
            let utc = self.utc()?;
            self.state.scanning = false;
            self.state.shutdown_sending = true;
            self.owner.begin_shutdown(utc);
            return Ok(true);
        }
        if matches!(self.owner.phase(), Phase::Configuring | Phase::Starting) {
            let _more = self.owner.startup_next()?;
            return Ok(true);
        }
        if self.state.scanning && self.owner.phase() == Phase::Serving {
            let utc = self.utc()?;
            let _next = self.owner.restart(utc)?;
            // An automatic spawn pauses this source scan until its real native
            // acknowledgment. Do not reinterpret Some(now) as a timer callback.
            self.state.pending_native = self.owner.take_native()?.map(|effect| match effect {
                NativeEffect::Spawn {
                    ticket,
                    child,
                    service,
                    pipe_control,
                    ..
                } => Native::Spawn {
                    ticket,
                    child,
                    service,
                    pipe: pipe_control,
                },
                NativeEffect::Term { ticket, child } => Native::Term { ticket, child },
            });
            self.state.scanning = self.state.pending_native.is_some();
            return Ok(true);
        }
        if let Some(ticket) = self.owner.take_runtime_shutdown() {
            drop(self.state.control.take());
            while let Some(session) = self.state.sessions.first() {
                let persisted = self.owner.client_persisted(session.id)?;
                let session = self.state.sessions.remove(0);
                if persisted {
                    self.state.persisted.push(session.io.into_connection());
                } else {
                    drop(session);
                    self.state.counters.closed = self.state.counters.closed.saturating_add(1);
                }
            }
            self.state.timer = None;
            self.owner.runtime_shutdown_applied(ticket)?;
            return Ok(true);
        }
        Ok(false)
    }
    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Error>> {
        if !self.state.control_accept.ready() {
            return Poll::Pending;
        }
        let Some(control) = self.state.control.as_ref() else {
            return Poll::Pending;
        };
        for listener in control.listeners() {
            if let Poll::Ready(result) = listener.poll_canonical_connection(cx) {
                let accepted = match result {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        match self.state.control_accept.failed(error) {
                            SocketEvent::Failed(AcceptError::Initialization(error)) => self
                                .state
                                .diagnostic(Diagnostic::AcceptedSocketFailure(error)),
                            SocketEvent::Failed(error @ AcceptError::Accept(_))
                                if error.is_emfile() => {}
                            SocketEvent::Failed(AcceptError::Accept(error)) => {
                                self.state.diagnostic(Diagnostic::Accept(error))
                            }
                            SocketEvent::Diagnostic(diagnostic) => self
                                .state
                                .diagnostic(Diagnostic::AcceptedSocket(diagnostic)),
                        }
                        return Poll::Ready(Ok(true));
                    }
                };
                let (stream, peer, diagnostics) = accepted.into_parts();
                for diagnostic in diagnostics {
                    self.state
                        .diagnostic(Diagnostic::AcceptedSocket(diagnostic));
                }
                match self.admit(stream, peer) {
                    Ok(_admitted) => return Poll::Ready(Ok(true)),
                    Err(
                        Error::Capacity
                        | Error::Core(
                            gnunet_arm_service_core::Error::Capacity
                            | gnunet_arm_service_core::Error::Exhausted,
                        ),
                    ) => return Poll::Ready(Ok(true)),
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        }
        Poll::Pending
    }
    fn ordinary_ready(&self) -> Result<bool, Error> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        for session in &self.state.sessions {
            if session.io.ordinary_ready().map_err(Error::Io)? {
                return Ok(true);
            }
        }
        if matches!(self.owner.phase(), Phase::Serving | Phase::Draining) {
            if self.owner.phase() == Phase::Serving && self.managed.ordinary_ready()? {
                return Ok(true);
            }
            if self.state.control_accept.ready()
                && let Some(control) = self.state.control.as_ref()
            {
                for listener in control.listeners() {
                    let fd = match listener {
                        Listener::Unix(s) => s.as_fd(),
                        Listener::Tcp(s) => s.as_fd(),
                    };
                    let mut descriptors = [PollFd::new(fd, PollFlags::POLLIN)];
                    poll(&mut descriptors, PollTimeout::ZERO).map_err(|e| Error::Io(e.into()))?;
                    let flags = descriptors[0].revents().unwrap_or(PollFlags::empty());
                    if flags.contains(PollFlags::POLLNVAL) {
                        return Err(Error::Io(io::Error::from_raw_os_error(
                            nix::errno::Errno::EBADF as i32,
                        )));
                    }
                    if flags.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }
    fn receive_session(&mut self, index: usize, cx: &mut Context<'_>) -> Result<bool, Error> {
        let id = self.state.sessions[index].id;
        let now = self.utc()?;
        let buffered = self.state.sessions[index].io.buffered_bytes();
        match self.state.sessions[index].io.poll_receive(cx) {
            Poll::Ready(Ok(Received::Frame(bytes))) => {
                match self.owner.receive(id, bytes, now, self.rows) {
                    Ok(()) => {
                        if let Err(error) = self.state.sessions[index].io.consume_frame() {
                            self.state.diagnostic(Diagnostic::Peer(error));
                            self.close(index, false)?;
                        }
                        self.state.counters.received =
                            self.state.counters.received.saturating_add(1);
                    }
                    Err(gnunet_arm_service_core::Error::Busy) => {
                        return Ok(self.state.sessions[index].io.buffered_bytes() != buffered);
                    }
                    Err(gnunet_arm_service_core::Error::Malformed) => self.close(index, false)?,
                    Err(
                        gnunet_arm_service_core::Error::Capacity
                        | gnunet_arm_service_core::Error::Exhausted,
                    ) => self.close(index, true)?,
                    Err(error) => return Err(error.into()),
                }
                Ok(true)
            }
            Poll::Ready(Ok(Received::Eof { partial })) => {
                if partial {
                    self.state
                        .diagnostic(Diagnostic::Peer(framed::Error::Malformed));
                }
                self.close(index, false)?;
                Ok(true)
            }
            Poll::Ready(Err(error)) => {
                self.state.diagnostic(Diagnostic::Peer(error));
                self.close(index, false)?;
                Ok(true)
            }
            Poll::Pending => Ok(self.state.sessions[index].io.buffered_bytes() != buffered),
        }
    }
    fn send_session(&mut self, index: usize, cx: &mut Context<'_>) -> Result<bool, Error> {
        let id = self.state.sessions[index].id;
        match self.state.sessions[index].io.poll_send(cx) {
            Poll::Ready(Ok(true)) => {
                self.owner
                    .set_mq_length(id, self.state.sessions[index].io.mq_length())?;
                Ok(true)
            }
            Poll::Ready(Err(error)) => {
                self.state.diagnostic(Diagnostic::Peer(error));
                self.close(index, false)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    fn poll_sessions(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let count = self.state.sessions.len();
        let first = self.state.next_session;
        for index in (first..count).chain(0..first) {
            let id = self.state.sessions[index].id;
            let send_first = self.state.sessions[index].send_first;
            for receive in [!send_first, send_first] {
                let progress = if receive {
                    self.receive_session(index, cx)?
                } else {
                    self.send_session(index, cx)?
                };
                if progress {
                    let count = self.state.sessions.len();
                    self.state.next_session = if count == 0 {
                        0
                    } else if self.state.sessions.get(index).is_some_and(|s| s.id == id) {
                        self.state.sessions[index].send_first = receive;
                        if index + 1 == count { 0 } else { index + 1 }
                    } else {
                        index % count
                    };
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    /// Poll one full ordinary callback settlement. At a cooperative budget yield,
    /// no unrelated I/O or IDLE callback is polled ahead of unfinished effects.
    pub fn poll_drive(&mut self, cx: &mut Context<'_>) -> Poll<Result<Activity, Error>> {
        let mut progressed = false;
        loop {
            for _ in 0..self.state.limits.settlement_budget {
                match self.settle(cx) {
                    Ok(true) => progressed = true,
                    Ok(false) => break,
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            // Check settlement once more to distinguish budget from idle. It
            // performs at most one operation and retains all effects on errors.
            match self.settle(cx) {
                Ok(true) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => return Poll::Ready(Err(error)),
                Ok(false) => {}
            }
            if self.owner.phase() == Phase::Closed {
                return Poll::Ready(Ok(Activity::Closed));
            }
            if progressed {
                return Poll::Ready(Ok(Activity::Progress));
            }
            // C appends each continuation to its ready FIFO. Rotate ordinary
            // sources and stream directions after actual work, retaining this
            // scheduling state in the caller-owned State across cancellation.
            let first = self.state.next_ordinary;
            for lane in (first..3).chain(0..first) {
                let work = match lane {
                    0 if matches!(self.owner.phase(), Phase::Serving | Phase::Draining) => {
                        match self.poll_accept(cx) {
                            Poll::Ready(result) => result,
                            Poll::Pending => Ok(false),
                        }
                    }
                    1 => self.poll_sessions(cx),
                    2 if self.owner.phase() == Phase::Serving => {
                        match self.managed.poll_event(cx) {
                            Poll::Ready(Ok(_event)) => self
                                .managed
                                .deliver(self.owner)
                                .map(|()| true)
                                .map_err(Error::from),
                            Poll::Ready(Err(error)) => Err(error.into()),
                            Poll::Pending => Ok(false),
                        }
                    }
                    _ => Ok(false),
                };
                match work {
                    Ok(true) => {
                        self.state.next_ordinary = (lane + 1) % 3;
                        progressed = true;
                        break;
                    }
                    Ok(false) => {}
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            if progressed {
                continue;
            }
            if let Poll::Ready(signal) = self.children.poll_child_signal(cx) {
                if let Err(error) = signal {
                    return Poll::Ready(Err(error.into()));
                }
                match self.reap() {
                    Ok(true) => {
                        progressed = true;
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            // Source IDLE priority: only after no ordinary ready callback.
            // Tokio's cached hint may lag a real queued descriptor. Give the
            // runtime a chance to refresh it before dispatching IDLE. This
            // probes only enabled tasks, never an empty always-writable stream.
            if self.state.timer.is_some() {
                match self.ordinary_ready() {
                    Ok(true) => {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Ok(false) => {}
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            let due = if let Some(timer) = self.state.timer.as_ref() {
                timer.at_utc != u64::MAX
            } else {
                false
            };
            if due {
                let now = match self.utc() {
                    Ok(now) => now,
                    Err(error) => return Poll::Ready(Err(error)),
                };
                if let Some(timer) = self.state.timer.as_mut() {
                    if now >= timer.at_utc {
                        let id = timer.id;
                        if let Err(error) = self.owner.timer_fired(id) {
                            return Poll::Ready(Err(error.into()));
                        }
                        self.state.timer = None;
                        self.state.scanning = true;
                        self.state.counters.timer_callbacks =
                            self.state.counters.timer_callbacks.saturating_add(1);
                        progressed = true;
                        continue;
                    }
                    if let Some(sleep) = timer.sleep.as_mut()
                        && sleep.as_mut().poll(cx).is_ready()
                    {
                        // A backward source UTC change does not expire the
                        // registration. Retain its identity and re-arm its hint.
                        let delta = Duration::from_micros(timer.at_utc.saturating_sub(now));
                        let Some(deadline) = Instant::now().checked_add(delta) else {
                            return Poll::Ready(Err(Error::Capacity));
                        };
                        sleep.as_mut().reset(deadline);
                        let _registered = sleep.as_mut().poll(cx);
                    }
                }
            }
            return Poll::Pending;
        }
    }
    /// Wait for one actual complete callback settlement. Cancellation retains all
    /// owned RX/TX, timer registrations, native leases and consuming wait events.
    pub async fn drive(&mut self) -> Result<Activity, Error> {
        std::future::poll_fn(|cx| self.poll_drive(cx)).await
    }
}
