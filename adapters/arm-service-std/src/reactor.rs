//! Actual ARM IPC/native reactor. All OS owners survive a canceled Driver::drive.
//! Managed listener readiness never accepts; accepted control sockets use a
//! different owner. Ordinary work precedes source IDLE restart callbacks.
mod children;
mod clients;
mod drive;
mod timers;

use crate::{
    framed::{self, FramedConnection, Received},
    listeners::ManagedListeners,
    process::{
        self, ChildRegistry, LaunchError, OriginalChild, ProcessLimits, Reaped, SpawnResult,
    },
    registry::Registry,
};
use gnunet_arm_core::wire::ServiceInfo;
use gnunet_arm_service_core::{
    ChildId, ClientId, NativeEffect, NativeTicket, Owner, OwnerId, Phase, ServiceId, SpawnOutcome,
    TimerAction, TimerEffect, TimerId,
};
use gnunet_service_runtime::{
    BoundListeners,
    service::{PeerAddress, ServiceOptions},
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
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Listener(error) => Some(error),
            Self::Native(error) => Some(error),
            Self::Io(error) | Self::Clock(error) => Some(error),
            _ => None,
        }
    }
}
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
    /// Actual qualified child '.' observations on the native startup transport.
    /// This is independent of formal STARTED and is not inferred on Unix.
    pub startup_ready: u64,
    /// Native termination requests accepted after post-admission setup failure;
    /// neither process death nor consuming reap is implied.
    pub preparation_retired: u64,
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
    /// Actual forced native termination attempts; never a death/reap receipt.
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
    /// Original cooperative-control, exit-observation or native stop diagnostic.
    Signal(LaunchError),
    /// Original native startup/bootstrap failure, distinct from process admission.
    Startup(LaunchError),
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
    control: process::Control,
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
    next_child: usize,
    persisted: Vec<Connection>,
    children: Vec<Child<'scope>>,
    services: Vec<ServiceId<'scope>>,
    pending_native: Option<Native<'scope>>,
    spawn_outcome: Option<SpawnOutcome>,
    term_attempted: bool,
    native_waiting: bool,
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
            next_child: 0,
            persisted,
            children,
            services,
            pending_native: None,
            spawn_outcome: None,
            term_attempted: false,
            native_waiting: false,
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
    /// One real consuming exit/resource observation retained independently from the
    /// formal acknowledgment. No later reap proceeds until caller takes it.
    pub fn take_resource_event(&mut self) -> Option<ResourceEvent> {
        self.resource_event.take()
    }
    /// Move auxiliary native owners out of scoped core mappings after terminal
    /// service failure. The caller reserves backing before starting children.
    #[cfg(feature = "service")]
    pub(crate) fn retain_native(
        &mut self,
        registry: &ChildRegistry,
        retained: &mut Vec<process::RetainedChild>,
    ) {
        for child in self.children.drain(..) {
            if registry.owns(&child.original) {
                retained.push(process::RetainedChild {
                    original: child.original,
                    _control: child.control,
                });
            }
        }
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
/// Exact original native resource observation. Service is an immutable registry index;
/// no arbitrary PID/name can be substituted by the foreground logger.
#[derive(Debug)]
pub struct ResourceEvent {
    /// Original registered service index.
    pub service: usize,
    /// Actual consuming wait observation for its original child.
    pub event: Reaped,
    /// Actual native counters/query errors, never inferred from signals or elapsed time.
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
    launch: process::LaunchContext<'view>,
    options: &'view ServiceOptions,
    rows: &'view mut [ServiceInfo<'spec>],
    clock: &'view mut C,
}
impl<'view, 'scope, 'spec, 'slots, 'bytes, C: Clock>
    Driver<'view, 'scope, 'spec, 'slots, 'bytes, C>
{
    /// Bind exact service identities and prepare native child-exit observation.
    /// ChildRegistry is dedicated to this daemon for the complete State lifetime:
    /// do not mix another launcher/consumer's children or completed-event queue.
    /// Unrelated visible live children are refused before any consuming wait;
    /// unexpected completed credit is returned as Error::ForeignCompletion.
    /// LaunchContext carries the native platform's explicit inputs. Unix callers
    /// prepare SIGCHLD before registry enumeration; Windows retains individual
    /// original-handle waits. No privilege, daemon or readiness success is implied.
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
        launch: process::LaunchContext<'view>,
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
        process::prepare(children)?;
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
            launch,
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
    /// Borrow current observations without transferring native authority.
    pub fn counters(&self) -> Counters {
        self.state.counters
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
    fn utc(&mut self) -> Result<u64, Error> {
        self.clock.utc().map_err(Error::Clock)
    }
}
