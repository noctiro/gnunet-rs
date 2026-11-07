//! Caller-driven numeric TCP entry with a configured, PILS-matched existing local capability.
//! Replay recovery is bound to the original durable ledger/frontier pair. Reconnect or a replacement key never clears an unprotected epoch.
mod generation;
mod identity;
mod observation;
mod publication;
use crate::statistics::{NoStatistics, StatisticsFactory};
pub use observation::{Failure as StatisticsFailure, Report as StatisticsReport};
mod replay;
mod reversal;
use crate::{addresses, dial::Dial, listeners::Listeners, settings::Settings};
use gnunet_client_host::EndpointSource;
pub use gnunet_config::ProcessEnvironment;
use gnunet_config::{Configuration, ProjectData};
use gnunet_pils::client::{self as pc, Instance};
use gnunet_pils_host::client::{self as pils, Client};
use gnunet_resolver_broker::{FamilyProfile, LiveConfiguration, broker};
use gnunet_service_runtime::{
    Activation,
    accepted::SocketEvent,
    clock::{RuntimeClock, SystemClock},
    connection::Connection,
};
use gnunet_tcp_communicator_host::{Capacity, CreateId, OwnedFailure};
use gnunet_types::Error;
pub use reversal::{CancelledWrite, Event as ReversalEvent, Failure as ReversalFailure};
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    path::{Path, PathBuf},
    sync::Arc,
    task::Poll,
};
type Failure = Box<dyn StdError>;
/// Explicit finite active resources; reused backing has no total-generation limit.
#[derive(Clone, Copy)]
pub struct Limits {
    /// Simultaneous original peer owners.
    pub sessions: usize,
    /// Physical shared MQ storage.
    pub ipc: Capacity,
    /// Waiting sends per session.
    pub pending_sends: usize,
    /// Waiting original CREATE requests.
    pub commands: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            sessions: 64,
            ipc: Capacity {
                ipc_bytes: 4 * 1024 * 1024,
                ipc_frames: 256,
                callbacks: 8,
            },
            pending_sends: 8,
            commands: 64,
        }
    }
}
/// Caller authorization to read an existing IKM. It is never created here.
pub struct LocalKeyCapability {
    /// Official configured existing private-key file.
    pub ikm_file: PathBuf,
}
/// Original numeric/inherited listeners and fenced new-format backend.
pub struct LocalStartup<'a> {
    /// Official snapshot, no hidden reload.
    pub config: &'a Configuration,
    /// Unique inherited TCP descriptors.
    pub activation: Activation,
    /// New-format Rust state; never C sqlite.
    pub state_directory: PathBuf,
    /// Explicit optional-platform capability.
    pub local_key: LocalKeyCapability,
    /// Finite caller bounds.
    pub limits: Limits,
}
/// Actual original listeners prepared before the enclosing process applies
/// USERNAME. This entry never changes process identity inside async polling.
pub struct PreparedStartup<'a> {
    /// Official immutable configuration.
    pub config: &'a Configuration,
    /// Same prebound/adopted TCP descriptors, registered under the actual user.
    pub listeners: Listeners,
    /// Explicit independent Rust frontier namespace.
    pub state_directory: PathBuf,
    /// Existing configured IKM, loaded only after a real PILS announcement.
    pub local_key: LocalKeyCapability,
    /// Fixed resources of the existing multi-session pool.
    pub limits: Limits,
}
/// Synchronous original observations, all driven by the same foreground task.
/// The failure probe is consulted between IO classes and after callbacks, so a
/// failed selected Logger can fence new work without discarding original debt.
pub struct Observers<'a> {
    /// Canonical accept/setup facts.
    pub socket: &'a mut dyn FnMut(SocketEvent),
    /// Original PILS progress; implementations must not log private payloads.
    pub pils: &'a mut dyn for<'p> FnMut(&pils::Progress<'p>),
    /// Original TCP/IPC retry and failure owners.
    pub diagnostic: &'a mut dyn FnMut(Diagnostic),
    /// Actual shared Resolver observations.
    pub resolver: &'a mut dyn FnMut(gnunet_resolver_broker::DriverEvent),
    /// Original address/NAT observations. Borrowed events keep exact source and
    /// allocation facts; ADD/DEL admission is never reported as socket write.
    pub addresses: &'a mut dyn for<'id> FnMut(&addresses::Event<'id>),
    /// Permanently latched process output failure; no new authority is minted.
    pub failed: &'a dyn Fn() -> bool,
}
/// Independent actual Resolver retirement failure plus the original task cause.
#[derive(Debug)]
pub struct RetirementFailure {
    /// Original startup/runtime/clock/peer failure, if any.
    pub original: Option<Box<dyn StdError>>,
    /// Actual disconnect refusal after original clients have been disposed.
    pub resolver: gnunet_resolver_broker::BrokerError,
}
impl std::fmt::Display for RetirementFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(original) = &self.original {
            write!(f, "{original}; ")?;
        }
        write!(f, "independent TCP Resolver retirement: {}", self.resolver)
    }
}
impl StdError for RetirementFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.original.as_deref().or(Some(&self.resolver))
    }
}
#[derive(Debug)]
struct IndependentFailure {
    original: Failure,
    cleanup: Failure,
}
impl std::fmt::Display for IndependentFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; independent retirement: {}",
            self.original, self.cleanup
        )
    }
}
impl StdError for IndependentFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.original.as_ref())
    }
}
fn independent(original: Result<(), Failure>, cleanup: Failure) -> Failure {
    match original {
        Ok(()) => cleanup,
        Err(original) => Box::new(IndependentFailure { original, cleanup }),
    }
}
/// One actual process Resolver context, driver, live configuration and clock.
/// Cloning the context shares this original broker; it does not create another
/// driver. PROGRAM uses that clone for its real configuration connect read point.
pub struct Services {
    live: LiveConfiguration,
    context: gnunet_resolver_broker::Context<128, 256>,
    resolver: gnunet_resolver_broker::Driver<128, 256>,
    source: Arc<dyn RuntimeClock>,
}
impl Services {
    /// Reserve one original broker and subscription. No connection, worker,
    /// private key or peer protocol effect is created by this constructor.
    pub fn new(config: &Configuration, source: Arc<dyn RuntimeClock>) -> Result<Self, Failure> {
        let native = gnunet_resolver_broker::native_profile()?;
        let family = FamilyProfile::new(
            native.encode(gnunet_resolver_broker::Family::V4),
            native.encode(gnunet_resolver_broker::Family::V6),
        )?;
        let live = LiveConfiguration::new(config.duplicate()?);
        let (context, resolver) =
            broker::<128, 256>(live.clone(), Default::default(), family, source.clone())?;
        Ok(Self {
            live,
            context,
            resolver,
            source,
        })
    }
    /// A clone of this same broker for PROGRAM's actual ResolverConnect call.
    #[must_use]
    pub fn context(&self) -> gnunet_resolver_broker::Context<128, 256> {
        self.context.clone()
    }
    /// Resolve and prebind through this exact process broker before USERNAME.
    /// Numeric/inherited bindings perform no DNS connect or lookup. The returned
    /// original descriptors and this same Services owner continue into PROGRAM.
    pub async fn prepare_listeners<S: Future<Output = io::Result<()>> + ?Sized>(
        &mut self,
        settings: &Settings,
        activation: Activation,
        shutdown: std::pin::Pin<&mut S>,
        observers: crate::bind_resolution::Observers<'_>,
    ) -> Result<Option<crate::listeners::PreparedListeners>, Failure> {
        if settings.hostname.is_some() && activation.sockets.is_empty() {
            self.context.connect_live(self.live.clone())?;
        }
        crate::bind_resolution::prepare(
            settings,
            activation,
            &mut self.resolver,
            shutdown,
            crate::bind_resolution::Limits::default(),
            observers,
        )
        .await
        .map_err(|error| Box::new(error) as Failure)
    }
    /// Retire this same broker before any foreground client is admitted, for
    /// example after listener registration fails. This samples no new clock;
    /// an actual refusal is returned before the original driver drops.
    pub fn close(mut self) -> Result<(), gnunet_resolver_broker::BrokerError> {
        self.resolver.disconnect()
    }
}
/// Actual local TRANSPORT-source transitions. These carry no replacement
/// authority and never claim peer delivery, callback replay or persistent reset.
#[derive(Debug)]
pub enum TransportEvent {
    /// Original shared MQ failed after its real host callback cleanup succeeded.
    Lost(OwnedFailure),
    /// A genuinely connected replacement MQ entered the original Pool.
    Attached {
        /// Original manager's fresh physical callback generation.
        generation: u64,
    },
    /// REGISTER/current queue replay flags settled and the real MQ FIFO drained.
    /// This is whole local writing, not a remote validation or application ACK.
    Reannounced {
        /// Same attached replacement generation.
        generation: u64,
    },
    /// Old CREATE result ownership retired, without notifying a new MQ.
    CreateRetired {
        /// Original process/source/serial capability, never reusable here.
        id: CreateId,
        /// The original native or NAT request had really been admitted.
        native_admitted: bool,
        /// Independent original registry-intent cancellation refusal.
        cancellation: Option<Error>,
    },
    /// Original acquisition was canceled on Stop with an unobserved native error.
    DialRetired(io::Error),
}
/// Local generation transitions; neither is a peer handshake or delivery ACK.
#[derive(Clone, Copy, Debug)]
pub enum IdentityEvent {
    /// A verified same-observer change fenced new admission in the old owner.
    Retiring {
        /// Original immutable local identity.
        previous: [u8; 32],
        /// Newly verified public identity, subject to further coalescing.
        next: [u8; 32],
    },
    /// Actual key match, durable epoch and local service composition are ready.
    Ready {
        /// Current verified public identity; no reachability is implied.
        peer: [u8; 32],
    },
}
/// Original failures transferred to the enclosing foreground observer.
#[derive(Debug)]
pub enum Diagnostic {
    /// Failed native admission, after original socket disposal.
    Admission(crate::AdmissionError),
    /// Original peer failure, before its isolated retirement.
    Peer(OwnedFailure),
    /// Actual service retry notice and original errno.
    Retry(crate::dial::Retry),
    /// Actual original reversal/prototype progress and isolated errors.
    Reversal(ReversalEvent),
    /// Actual source loss, local reattachment and original callback retirement.
    Transport(TransportEvent),
    /// Actual healthy identity retirement and verified next-generation readiness.
    Identity(IdentityEvent),
    /// Actual replay worker initialization, persistence and retirement outcome.
    Replay(gnunet_tcp_replay_host::Progress),
    /// Original task retirement during clock-free history drain.
    History(gnunet_tcp_communicator_host::history::HistoryProgress),
}
/// Actual observations. Established TCP is not TRANSPORT validation or delivery.
#[derive(Debug, Default)]
pub struct Report {
    /// Actual canonical accepts admitted.
    pub accepted: u64,
    /// Real CREATE requests claimed once.
    pub creates: u64,
    /// Actual native outbound admissions, not authenticated delivery.
    pub outbound: u64,
    /// Actual refused admissions.
    pub rejected: u64,
    /// Original physical generations fully returned.
    pub retired: u64,
    /// Verified public identity announcements on the original observer.
    pub identity_updates: u64,
    /// Original local TRANSPORT losses with successful host callback cleanup.
    pub transport_losses: u64,
    /// Actual replacement TRANSPORT connections attached to the same Pool.
    pub transport_attachments: u64,
    /// Replacement REGISTER/current peer queue writes settled locally.
    pub transport_reannounced: u64,
    /// Old claimed CREATE result tokens retired without replay to a new source.
    pub creates_retired: u64,
    /// Actual durable generations admitted and subsequently retired.
    pub generations: u64,
    /// Every admitted generation was cleaned after actual resource retirement.
    pub clean: bool,
}
impl Report {
    fn merge(&mut self, next: Self) {
        if next.generations != 0 {
            self.clean = (self.generations == 0 || self.clean) && next.clean;
        }
        self.accepted = self.accepted.saturating_add(next.accepted);
        self.creates = self.creates.saturating_add(next.creates);
        self.outbound = self.outbound.saturating_add(next.outbound);
        self.rejected = self.rejected.saturating_add(next.rejected);
        self.retired = self.retired.saturating_add(next.retired);
        self.identity_updates = self.identity_updates.saturating_add(next.identity_updates);
        self.transport_losses = self.transport_losses.saturating_add(next.transport_losses);
        self.transport_attachments = self
            .transport_attachments
            .saturating_add(next.transport_attachments);
        self.transport_reannounced = self
            .transport_reannounced
            .saturating_add(next.transport_reannounced);
        self.creates_retired = self.creates_retired.saturating_add(next.creates_retired);
        self.generations = self.generations.saturating_add(next.generations);
    }
}
/// Load standard installation defaults and the selected/default official config.
pub fn configuration(selected: Option<&Path>) -> Result<Configuration, Failure> {
    let project = Arc::new(ProjectData::default());
    let mut config = Configuration::create(project.clone(), Default::default())?;
    let discovered = gnunet_config::default_filename(&project)?;
    let selected = selected
        .map(Path::to_path_buf)
        .or_else(|| discovered.filter(|p| p.is_file()));
    config.load(selected.as_deref())?;
    Ok(config)
}
/// Run numeric/inherited TCP with an actual matched PILS local capability.
/// Absence of this capability is explicit unsupported work, not an implicit key read.
pub async fn foreground_local(
    setup: LocalStartup<'_>,
    ready: impl FnMut(&Listeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_pils: impl for<'a> FnMut(&pils::Progress<'a>),
    diagnose: impl FnMut(Diagnostic),
) -> Result<Report, Failure> {
    foreground_local_with_clock(
        setup,
        ready,
        shutdown,
        observe_socket,
        observe_pils,
        diagnose,
        Arc::new(SystemClock),
    )
    .await
}
/// Same entry with one explicit canonical process UTC/offset source for all ports.
pub async fn foreground_local_with_clock(
    setup: LocalStartup<'_>,
    ready: impl FnMut(&Listeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    mut observe_socket: impl FnMut(SocketEvent),
    mut observe_pils: impl for<'a> FnMut(&pils::Progress<'a>),
    mut diagnose: impl FnMut(Diagnostic),
    source: Arc<dyn RuntimeClock>,
) -> Result<Report, Failure> {
    let LocalStartup {
        config,
        activation,
        state_directory,
        local_key,
        limits,
    } = setup;
    if config.get(b"communicator-tcp", b"USERNAME").is_some() {
        return Err("use the process-prepared TCP entry for configured USERNAME".into());
    }
    let settings = Settings::parse(config)?;
    let listeners = Listeners::bind(&settings, activation)?;
    let mut resolver = |_| {};
    let mut addresses = |_: &addresses::Event<'_>| {};
    let failed = || false;
    foreground_prepared_with_clock(
        PreparedStartup {
            config,
            listeners,
            state_directory,
            local_key,
            limits,
        },
        ready,
        shutdown,
        Observers {
            socket: &mut observe_socket,
            pils: &mut observe_pils,
            diagnostic: &mut diagnose,
            resolver: &mut resolver,
            addresses: &mut addresses,
            failed: &failed,
        },
        source,
    )
    .await
}
/// Run a prepared embedding with one newly reserved explicit process broker.
/// The normal PROGRAM path instead constructs Services once and supplies the
/// same actual context to its scheduler and foreground owner.
pub async fn foreground_prepared_with_clock(
    setup: PreparedStartup<'_>,
    ready: impl FnMut(&Listeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observers: Observers<'_>,
    source: Arc<dyn RuntimeClock>,
) -> Result<Report, Failure> {
    let services = Services::new(setup.config, source)?;
    foreground_prepared_with_services(setup, ready, shutdown, observers, services).await
}
/// Run the original pool after the enclosing, single-threaded process prepared
/// TCP listeners and applied its configured identity. Private-key loading,
/// KeyRing/Pool creation and durable epoch admission still require an actual
/// current PILS identity and the existing local provider's exact Matched check.
/// Explicit embedding path without a native statistics publisher. The standard
/// executable uses the app-injected factory entry below.
pub async fn foreground_prepared_with_services(
    setup: PreparedStartup<'_>,
    ready: impl FnMut(&Listeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observers: Observers<'_>,
    services: Services,
) -> Result<Report, Failure> {
    foreground_prepared_with_services_and_statistics(
        setup,
        ready,
        shutdown,
        observers,
        services,
        NoStatistics,
    )
    .await
    .map(|report| report.tcp)
}
/// Drive the real caller-supplied publisher on these same original process ports.
/// Statistics failures fence only that diagnostic source and are retained through
/// actual TCP/worker retirement; they never fabricate peer or native success.
#[expect(
    clippy::too_many_lines,
    reason = "One process scope retains original capability acquisition, Resolver and publisher cleanup across the identity generation call"
)]
pub async fn foreground_prepared_with_services_and_statistics<F: StatisticsFactory>(
    setup: PreparedStartup<'_>,
    mut ready: impl FnMut(&Listeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observers: Observers<'_>,
    services: Services,
    statistics_factory: F,
) -> Result<StatisticsReport<F::Report>, Failure> {
    let PreparedStartup {
        config,
        listeners,
        state_directory,
        local_key,
        limits,
    } = setup;
    let Observers {
        socket: observe_socket,
        pils: observe_pils,
        diagnostic: diagnose,
        resolver: observe_resolver,
        addresses: observe_addresses,
        failed,
    } = observers;
    let Services {
        live,
        context,
        mut resolver,
        source,
    } = services;
    let mut statistics: Option<observation::Owner<F::Driver>> = None;
    let mut statistics_factory = Some(statistics_factory);
    let mut last_metrics = None;
    let result = async {
        if failed() { return Ok(Report::default()); }
        if limits.sessions == 0 || limits.sessions>4096
            || limits.commands == 0
            || limits.pending_sends == 0
            || limits.ipc.callbacks == 0
        {
            return Err(Error::Capacity.into());
        }
        let settings = Settings::parse(config)?;
        let endpoint = |section: &'static [u8]| {
            EndpointSource::live(live.clone(), section, context.resolution_context())
        };
        let mut instance = Instance::new();
        let mut pils = Client::<32>::new(
            &mut instance,
            endpoint(b"pils"),
            settings.identity_profile,
            pils::Limits::default(),
            gnunet_pils::HelloLimits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 4096,
                maximum_addresses: 64,
            },
        )?;
        let mut ps = Dial::new(endpoint(b"peerstore"));
        let mut tr = Dial::new(endpoint(b"transport"));
        let mut connections: [Option<Connection>; 2] = [None, None];
        let mut shutdown = std::pin::pin!(shutdown);
        let mut cursor = 0usize;
        let mut continuity: Option<identity::Continuity<'_>> = None;
        let mut namespace = None;
        let mut total = Report::default();
        loop {
        let identity = loop {
            if failed() { let _original = pils.close(); return Ok(total); }
            // The same original shutdown future is sampled without waiting before
            // every new capability/key read. A diagnostic can fail at the preceding
            // PILS callback; it must not allow load_existing on the next turn.
            let stopping = poll_fn(|cx| Poll::Ready(match shutdown.as_mut().poll(cx) {
                Poll::Ready(result) => Some(result), Poll::Pending => None,
            })).await;
            if failed() || stopping.is_some() {
                let _original = pils.close();
                if let Some(result) = stopping { result?; }
                return Ok(total);
            }
            if let Some(original) = &mut continuity {
                poll_fn(|cx| Poll::Ready(original.guard(cx))).await?;
            }
            if let Some(identity) = pils.identity() {
                if let Some(original) = &continuity { original.verify(identity, source.as_ref())?; }
                if pils.local_key_status() != pc::LocalKeyStatus::Matched {
                    let master = gnunet_pils_host::identity::load_existing(&local_key.ikm_file)?;
                    if pils.enable_local_key(master)? != pc::LocalKeyStatus::Matched {
                        return Err(Error::Authentication.into());
                    }
                }
                if connections.iter().all(Option::is_some) {
                    break identity;
                }
            }
            #[expect(
                clippy::large_enum_variant,
                reason = "Original bounded PILS secret/loss progress is returned without a new fallible allocation after consumption"
            )]
            enum Initial<'a> {
                Stop,
                Activity,
                Pils(pils::Progress<'a>),
                Connection(usize, Connection),
            }
            let event = {
                let mut driving = std::pin::pin!(pils.drive(None));
                let mut resolving = std::pin::pin!(resolver.drive_waiting(None, &mut *observe_resolver));
                poll_fn(|cx| {
                    if failed() { return Poll::Ready(Ok(Initial::Stop)); }
                    if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
                        return Poll::Ready(
                            result
                                .map(|()| Initial::Stop)
                                .map_err(|e| Box::new(e) as Failure),
                        );
                    }
                    if let Some(original) = &mut continuity { original.guard(cx)?; }
                    let activity = match resolving.as_mut().poll(cx) {
                        Poll::Ready(Ok(_)) => true,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e) as Failure)),
                        Poll::Pending => false,
                    };
                    if failed() { return Poll::Ready(Ok(Initial::Stop)); }
                    for offset in 0..4 {
                        let part = (cursor + offset) % 4;
                        match part {
                            0 => {
                                if let Poll::Ready(result) = driving.as_mut().poll(cx) {
                                    cursor = 1;
                                    return Poll::Ready(
                                        result
                                            .map(Initial::Pils)
                                            .map_err(|e| Box::new(e) as Failure),
                                    );
                                }
                            }
                            3 => {
                                if let Some(owner) = &mut statistics
                                    && (owner.guard(cx, failed()) || owner.poll(cx, failed())) {
                                    cursor = 0;
                                    return Poll::Ready(Ok(Initial::Activity));
                                }
                            }
                            index => {
                                let n = index - 1;
                                if connections[n].is_some() {
                                    continue;
                                }
                                let dial = if n == 0 { &mut ps } else { &mut tr };
                                if let Some(retry) = dial.take_retry() {
                                    diagnose(Diagnostic::Retry(retry));
                                }
                                if failed() { return Poll::Ready(Ok(Initial::Stop)); }
                                if let Poll::Ready(result) = dial.poll(cx) {
                                    cursor = (part + 1) % 4;
                                    return Poll::Ready(
                                        result
                                            .map(|c| Initial::Connection(n, c))
                                            .map_err(|e| Box::new(e) as Failure),
                                    );
                                }
                            }
                        }
                    }
                    if activity {
                        Poll::Ready(Ok(Initial::Activity))
                    } else {
                        Poll::Pending
                    }
                })
                .await?
            };
            match event {
                Initial::Stop => {
                    let _original = pils.close();
                    return Ok(total);
                }
                Initial::Activity => {}
                Initial::Pils(original) => identity::observe(original, observe_pils)?,
                Initial::Connection(index, connection) => connections[index] = Some(connection),
            }
            tokio::task::yield_now().await;
        };
        // The next generation borrows the same process listeners, observer,
        // writer fence and publisher only after the prior generation returned.
        if failed() { let _original = pils.close(); return Ok(total); }
        let stopping = poll_fn(|cx| Poll::Ready(match shutdown.as_mut().poll(cx) {
            Poll::Ready(result) => Some(result), Poll::Pending => None,
        })).await;
        if failed() || stopping.is_some() {
            let _original = pils.close();
            if let Some(result) = stopping { result?; }
            return Ok(total);
        }
        if namespace.is_none() { namespace = Some(replay::Namespace::open(&state_directory)?); }
        let original = continuity.get_or_insert_with(|| identity::Continuity::new(identity));
        original.verify(identity, source.as_ref())?;
        let exit = generation::run(generation::Input {
            config, settings: &settings, listeners: &listeners,
            namespace: namespace.as_ref().ok_or(Error::Conflict)?, continuity: original, limits, identity,
            connections: [connections[0].take().ok_or(Error::NotReady)?, connections[1].take().ok_or(Error::NotReady)?],
            transport: &mut tr,
            pils: &mut pils, resolver: &mut resolver, shutdown: shutdown.as_mut(), ready: &mut ready,
            observers: Observers { socket: &mut *observe_socket, pils: &mut *observe_pils, diagnostic: &mut *diagnose,
                resolver: &mut *observe_resolver, addresses: &mut *observe_addresses, failed },
            endpoint: &endpoint, source: source.clone(), live: &live, context: &context,
            statistics: &mut statistics, statistics_factory: &mut statistics_factory,
            last_metrics: &mut last_metrics,
        }).await?;
        total.merge(exit.report);
        if !exit.replacing { return Ok(total); }
        original.retire(last_metrics);
        poll_fn(|cx| Poll::Ready(original.guard(cx))).await?;
        ps.restart()?;
        tr.restart()?;
        }
    }.await;
    if let Some(owner) = &mut statistics {
        owner.begin_close(last_metrics, result.is_ok() && !failed());
    }
    // The same original worker has really joined. A normal publisher still
    // drains only its already frozen real snapshot and unchanged fixed5s hard.
    if let Some(owner) = &mut statistics {
        if result.is_err() || failed() {
            owner.abort();
        } else {
            owner.drain(&mut resolver, observe_resolver, failed).await;
        }
    }
    // No native publisher is polled after this actual broker disconnect.
    let resolver_close = resolver.disconnect().err();
    match statistics {
        Some(owner) => owner.finish(result, last_metrics, resolver_close),
        None => observation::absent::<F::Error, F::Report>(result, last_metrics, resolver_close),
    }
}

/// Observe only public connection/configuration failures, never secret results.
pub fn diagnose_pils(event: &pils::Progress<'_>) {
    use std::io::Write;
    match event {
        pils::Progress::Lost { cause, .. } => {
            let _diagnostic = writeln!(io::stderr().lock(), "PILS original MQ retired: {cause:?}");
        }
        pils::Progress::ConnectRetry { error, .. } => {
            let _diagnostic = writeln!(io::stderr().lock(), "PILS actual connect error: {error}");
        }
        pils::Progress::Unavailable(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "PILS unavailable: {error}");
        }
        _ => {}
    }
}
