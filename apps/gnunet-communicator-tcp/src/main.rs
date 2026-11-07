//! Normal configuration-only TCP communicator over the original actual pool.
#![deny(unsafe_code)]
mod settings;
mod statistics;
use gnunet_program_host::{
    getopt::Options,
    logging::Logger,
    program::{self, Defaults, Invocation, NlsDisabled, Preparation, StoppedReason},
    reporting::Reporter,
    shared_clock::SharedClock,
};
use gnunet_service_runtime::{Activation, accepted::SocketEvent};
use gnunet_service_startup::{
    ControlNotice, GroupsProfile, InheritedMode, InheritedResources, ParentControl,
    apply_privileges, configured_user, resolve_user,
};
use gnunet_tcp_communicator_runtime::{
    listeners::{Listeners, PreparedListeners},
    settings::Settings as NetworkSettings,
    startup::{self, Diagnostic, Limits, Observers, PreparedStartup, Services},
};
use std::{
    error::Error,
    fmt,
    future::Future,
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
    task::Poll,
};
type Failure = Box<dyn Error>;
type ProductReport = startup::StatisticsReport<gnunet_ipc_unix::producer::Report<6>>;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            // Only failures before selected Reporter ownership reach here.
            let _output = writeln!(io::stderr().lock(), "gnunet-communicator-tcp: {error}");
            ExitCode::FAILURE
        }
    }
}
#[derive(Debug)]
struct Stopped(program::Stopped);
impl fmt::Display for Stopped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP PROGRAM stopped: {:?}", self.0)
    }
}
impl Error for Stopped {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.0.reason {
            StoppedReason::Logging(error) => Some(error),
            StoppedReason::Malformed(error) => Some(error),
            _ => None,
        }
    }
}
fn prepare(
    clock: &SharedClock,
    logger: &mut Logger<'static>,
) -> Result<Preparation, program::Failure> {
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    program::prepare(
        config,
        Invocation {
            binary_name: b"gnunet-communicator-tcp",
            help: Some(b"GNUnet TCP communicator; normal -c configuration, -L level and -l logfile. Existing peer key must match the actual PILS identity; no key is created or replaced. Independent Rust state defaults to $GNUNET_DATA_HOME/tcp-rust-state."),
            select_default_filename: true, defaults: Defaults::Native,
        },
        Options::new(), std::env::args_os(), &program::Environment::capture(),
        &mut NlsDisabled, logger, clock,
        &mut io::stdout().lock(), &mut io::stderr().lock(),
    )
}
fn run() -> Result<ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "Fresh process exclusively adopts inherited descriptors before runtime, account lookup, key or state preparation"
    )]
    // SAFETY: first initialization operation, before competing descriptor
    // owners, tasks, runtime, NSS or any key/state operation exist.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => {
            return Err("TCP received the wrong inherited startup route".into());
        }
    };
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"gnunet-communicator-tcp", std::process::id(), false)?;
    let prepared = match prepare(&clock, &mut logger)? {
        Preparation::Ready(prepared) => *prepared,
        Preparation::Stopped(stopped) => {
            return if stopped.code == 0 && matches!(&stopped.reason, StoppedReason::Options) {
                Ok(ExitCode::SUCCESS)
            } else {
                Err(Box::new(Stopped(stopped)))
            };
        }
    };
    let reporter = Reporter::new(logger, clock.clone());
    let result = execute(
        prepared,
        activation,
        captured.parent_control,
        captured.control_notice,
        &reporter,
        &clock,
    );
    let flush = io::stdout().flush().err();
    if let Err(error) = &result {
        reporter.warning(
            "tcp.foreground.failed",
            format_args!("TCP foreground: {error}"),
        );
    }
    let mut failures = FinalFailure {
        original: result.err(),
        flush,
        logging: reporter.take_error(),
    };
    if failures.original.is_some() || failures.flush.is_some() || failures.logging.is_some() {
        // Independent typed causes remain together. A broken selected Logger
        // is never replaced with an unselected diagnostic sink.
        reporter.warning("tcp.final.failed", format_args!("{failures:?}"));
        if let Some(error) = reporter.take_error() {
            failures.logging = Some(error);
        }
        // Keep any independent failure of this last selected write as an
        // actual owned cause too; do not retry it to a different output.
        drop(failures);
        return Ok(ExitCode::FAILURE);
    }
    Ok(ExitCode::SUCCESS)
}
fn execute(
    prepared: program::Prepared,
    activation: Activation,
    parent: Option<ParentControl>,
    notice: Option<ControlNotice>,
    reporter: &Reporter,
    clock: &SharedClock,
) -> Result<(), Failure> {
    let main = prepared.main();
    if !main.arguments.is_empty() {
        return Err("TCP communicator accepts no positional arguments".into());
    }
    clock.testing_skew(main.config)?;
    if let Some(notice) = notice {
        reporter.warning(
            "tcp.parent.notice",
            format_args!("TCP parent-control declaration: {notice:?}"),
        );
    }
    if reporter.failed() {
        return Ok(());
    }
    let selected = settings::Settings::parse(main.config)?;
    let network = NetworkSettings::parse(main.config)?;
    let config = main.config.duplicate()?;
    // One original current-thread runtime and Services broker span actual
    // hostname prebinding, USERNAME, then normal PROGRAM. No resolver/FD is
    // reconstructed after the privilege boundary.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(serve(
            prepared,
            Startup {
                config,
                selected,
                network,
                activation,
                parent,
            },
            reporter,
            clock,
        ))
}
struct Startup {
    config: gnunet_config::Configuration,
    selected: settings::Settings,
    network: NetworkSettings,
    activation: Activation,
    parent: Option<ParentControl>,
}

fn shutdown(
    reporter: Reporter,
    parent: Option<ParentControl>,
) -> io::Result<impl Future<Output = io::Result<()>>> {
    let interrupt_kind = tokio::signal::unix::SignalKind::interrupt();
    let terminate_kind = tokio::signal::unix::SignalKind::terminate();
    let mut interrupt = tokio::signal::unix::signal(interrupt_kind)?;
    let mut terminate = tokio::signal::unix::signal(terminate_kind)?;
    let mut control = parent
        .map(|control| control.register().map_err(|error| error.error))
        .transpose()?;
    Ok(std::future::poll_fn(move |cx| {
        reporter.register(cx);
        if reporter.failed() {
            return Poll::Ready(Ok(()));
        }
        if let Some(parent) = &mut control {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(signal)))
                    if i32::from(signal) == interrupt_kind.as_raw_value()
                        || i32::from(signal) == terminate_kind.as_raw_value() =>
                {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(signal))) => {
                    reporter.debug(
                        "tcp.parent.signal",
                        format_args!("TCP ignored parent signal {signal}"),
                    );
                    if reporter.failed() {
                        return Poll::Ready(Ok(()));
                    }
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Ok(None)) => control = None,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        if interrupt.poll_recv(cx).is_ready() || terminate.poll_recv(cx).is_ready() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }))
}
async fn serve(
    prepared: program::Prepared,
    startup: Startup,
    reporter: &Reporter,
    clock: &SharedClock,
) -> Result<(), Failure> {
    let Startup {
        config,
        selected,
        network,
        activation,
        parent,
    } = startup;
    if reporter.failed() {
        return Ok(());
    }
    let mut services = Services::new(&config, Arc::new(clock.clone()))?;
    let shutdown = match shutdown(reporter.clone(), parent) {
        Ok(shutdown) => shutdown,
        Err(error) => return retire_services(services, Some(Box::new(error))),
    };
    let mut shutdown = Box::pin(shutdown);
    let mut binding = |event: gnunet_tcp_communicator_runtime::bind_resolution::Event<'_>| {
        use gnunet_tcp_communicator_runtime::bind_resolution::Event;
        match event {
            Event::Resolver(event) => reporter.debug(
                "tcp.bind.resolver",
                format_args!("TCP BINDTO Resolver: {event:?}"),
            ),
            Event::BindFailed { address, error } => reporter.warning(
                "tcp.bind.refused",
                format_args!("TCP BINDTO {address}: {error}"),
            ),
            Event::Native(error) => reporter.warning(
                "tcp.bind.resolver.io",
                format_args!("TCP BINDTO original Resolver socket: {error}"),
            ),
            Event::Connection(error) => reporter.warning(
                "tcp.bind.resolver.connection",
                format_args!("TCP BINDTO original Resolver endpoint: {error}"),
            ),
        }
    };
    let failed = || reporter.failed();
    let listeners = match services
        .prepare_listeners(
            &network,
            activation,
            shutdown.as_mut(),
            gnunet_tcp_communicator_runtime::bind_resolution::Observers {
                event: &mut binding,
                failed: &failed,
            },
        )
        .await
    {
        Ok(Some(listeners)) => listeners,
        Ok(None) => return retire_services(services, None),
        Err(error) => return retire_services(services, Some(error)),
    };
    // Observe the same original Stop before both NSS and privilege providers.
    match stop_requested(shutdown.as_mut(), reporter).await {
        Ok(true) => return retire_services(services, None),
        Err(error) => return retire_services(services, Some(Box::new(error))),
        Ok(false) => {}
    }
    // The same actual descriptors are all bound before changing identity. No
    // key/frontier operation or peer protocol admission precedes this boundary.
    let user = (|| -> Result<_, Failure> {
        configured_user(&config, b"communicator-tcp")?
            .map(|name| resolve_user(&name))
            .transpose()
            .map_err(|error| Box::new(error) as Failure)
    })();
    let user = match user {
        Ok(user) => user,
        Err(error) => return retire_services(services, Some(error)),
    };
    match stop_requested(shutdown.as_mut(), reporter).await {
        Ok(true) => return retire_services(services, None),
        Err(error) => return retire_services(services, Some(Box::new(error))),
        Ok(false) => {}
    }
    let privileges = match apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups) {
        Ok(applied) => applied,
        Err(error) => return retire_services(services, Some(Box::new(error))),
    };
    if user.is_some() {
        reporter.debug(
            "tcp.identity.applied",
            format_args!("TCP configured process identity: {privileges:?}"),
        );
    }
    if reporter.failed() {
        return retire_services(services, None);
    }
    let mut context = services.context();
    let stop = std::rc::Rc::new(std::cell::Cell::new(false));
    let product = product(
        config,
        selected,
        listeners,
        shutdown,
        reporter.clone(),
        stop.clone(),
        services,
    );
    gnunet_program_host::foreground::run(prepared, &mut context, clock.clone(), stop, product)
        .await
        .map(|_report| ())
}
async fn stop_requested<S: Future<Output = io::Result<()>> + ?Sized>(
    mut shutdown: std::pin::Pin<&mut S>,
    reporter: &Reporter,
) -> io::Result<bool> {
    std::future::poll_fn(|cx| {
        if reporter.failed() {
            return Poll::Ready(Ok(true));
        }
        Poll::Ready(match shutdown.as_mut().poll(cx) {
            Poll::Ready(result) => result.map(|()| true),
            Poll::Pending => Ok(false),
        })
    })
    .await
}
fn retire_services(services: Services, original: Option<Failure>) -> Result<(), Failure> {
    match services.close() {
        Err(resolver) => Err(Box::new(startup::RetirementFailure { original, resolver })),
        Ok(()) => original.map_or(Ok(()), Err),
    }
}

async fn product<S: Future<Output = io::Result<()>> + 'static>(
    config: gnunet_config::Configuration,
    selected: settings::Settings,
    listeners: PreparedListeners,
    shutdown: S,
    reporter: Reporter,
    stop: std::rc::Rc<std::cell::Cell<bool>>,
    services: Services,
) -> Result<ProductReport, Failure> {
    if stop.get() || reporter.failed() {
        services.close()?;
        return Ok(ProductReport::default());
    }
    let listeners = match listeners.finish() {
        Ok(listeners) => listeners,
        Err(error) => {
            return match services.close() {
                Ok(()) => Err(Box::new(error)),
                Err(resolver) => Err(Box::new(startup::RetirementFailure {
                    original: Some(Box::new(error)),
                    resolver,
                })),
            };
        }
    };
    let ready = |listeners: &Listeners, peer: [u8; 32]| {
        if reporter.failed() {
            return Err(io::Error::other("selected TCP Logger failed"));
        }
        let mut output = io::stdout().lock();
        let key: String = peer.iter().map(|byte| format!("{byte:02x}")).collect();
        writeln!(output, "READY {key} {:?}", listeners.addresses())?;
        output.flush()
    };
    let mut socket = |event| observe_socket(&reporter, event);
    let mut pils = |event: &gnunet_pils_host::client::Progress<'_>| observe_pils(&reporter, event);
    let mut diagnostic = |event| observe_diagnostic(&reporter, event);
    let mut addresses = |event: &gnunet_tcp_communicator_runtime::addresses::Event<'_>| {
        observe_addresses(&reporter, event)
    };
    let mut resolver = |event| {
        reporter.debug(
            "tcp.resolver.activity",
            format_args!("TCP Resolver: {event:?}"),
        )
    };
    let failed = || reporter.failed() || stop.get();
    let mut statistics_instance = gnunet_ipc_unix::handle::Instance::new();
    let report = startup::foreground_prepared_with_services_and_statistics(
        PreparedStartup {
            config: &config,
            listeners,
            state_directory: selected.directory,
            local_key: selected.key,
            limits: Limits::default(),
        },
        ready,
        shutdown,
        Observers {
            socket: &mut socket,
            pils: &mut pils,
            diagnostic: &mut diagnostic,
            resolver: &mut resolver,
            addresses: &mut addresses,
            failed: &failed,
        },
        services,
        statistics::Factory::new(&mut statistics_instance),
    )
    .await?;
    let mut output = io::stdout().lock();
    let written = writeln!(output, "STOPPED {report:?}").and_then(|()| output.flush());
    match written {
        Ok(()) => Ok(report),
        Err(error) => Err(Box::new(CompletionOutput { report, error })),
    }
}
fn observe_socket(reporter: &Reporter, event: SocketEvent) {
    match event {
        SocketEvent::Failed(error) => {
            reporter.warning("tcp.socket.failed", format_args!("TCP socket: {error:?}"))
        }
        SocketEvent::Diagnostic(event) => {
            reporter.debug("tcp.socket.activity", format_args!("TCP socket: {event:?}"))
        }
    }
}
fn observe_pils(reporter: &Reporter, event: &gnunet_pils_host::client::Progress<'_>) {
    use gnunet_pils_host::client::Progress;
    match event {
        Progress::Lost { cause, .. } => reporter.warning(
            "tcp.pils.lost",
            format_args!("PILS original source retired: {cause:?}"),
        ),
        Progress::ConnectRetry { error, .. } => {
            reporter.warning("tcp.pils.retry", format_args!("PILS connect: {error}"))
        }
        Progress::Unavailable(error) => reporter.warning(
            "tcp.pils.unavailable",
            format_args!("PILS unavailable: {error}"),
        ),
        _ => {}
    }
}
fn observe_diagnostic(reporter: &Reporter, event: Diagnostic) {
    match event {
        Diagnostic::Admission(error) => reporter.warning(
            "tcp.admission.refused",
            format_args!("TCP admission: {error}"),
        ),
        Diagnostic::Peer(error) => reporter.warning(
            "tcp.peer.failed",
            format_args!("TCP original peer: {error}"),
        ),
        Diagnostic::Retry(retry) => reporter.warning(
            "tcp.service.retry",
            format_args!("TCP service retry: {retry:?}"),
        ),
        Diagnostic::Transport(event) => match &event {
            startup::TransportEvent::Lost(_)
            | startup::TransportEvent::CreateRetired { .. }
            | startup::TransportEvent::DialRetired(_) => reporter.warning(
                "tcp.transport.retired",
                format_args!("TCP original TRANSPORT source: {event:?}"),
            ),
            _ => reporter.message(
                gnunet_program_host::policy::Level::INFO,
                "tcp.transport.activity",
                format_args!("TCP local TRANSPORT recovery: {event:?}"),
            ),
        },
        Diagnostic::Identity(event) => reporter.message(
            gnunet_program_host::policy::Level::INFO,
            "tcp.identity.generation",
            format_args!("TCP local identity generation: {event:?}"),
        ),
        Diagnostic::Replay(event) => match &event {
            gnunet_tcp_communicator_runtime::replay::Progress::Failed { .. } => reporter.warning(
                "tcp.replay.failed",
                format_args!("TCP original replay ledger: {event:?}"),
            ),
            _ => reporter.debug(
                "tcp.replay.activity",
                format_args!("TCP original replay ledger: {event:?}"),
            ),
        },
        Diagnostic::History(event) => reporter.debug(
            "tcp.history.activity",
            format_args!("TCP original replay task: {event:?}"),
        ),
        Diagnostic::Reversal(event) => match &event {
            startup::ReversalEvent::Failed(_)
            | startup::ReversalEvent::Handoff { result: Err(_), .. }
            | startup::ReversalEvent::ParentRetired {
                original: Some(_), ..
            }
            | startup::ReversalEvent::ParentRetired {
                cancellation: Some(_),
                ..
            } => reporter.warning(
                "tcp.reversal.failed",
                format_args!("TCP original reversal: {event:?}"),
            ),
            _ => reporter.debug(
                "tcp.reversal.activity",
                format_args!("TCP original reversal: {event:?}"),
            ),
        },
    }
}
#[derive(Debug)]
struct FinalFailure {
    original: Option<Failure>,
    flush: Option<io::Error>,
    logging: Option<io::Error>,
}

#[derive(Debug)]
struct CompletionOutput {
    report: ProductReport,
    error: io::Error,
}
impl fmt::Display for CompletionOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP completed {:?}; terminal output: {}",
            self.report, self.error
        )
    }
}
impl Error for CompletionOutput {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

fn observe_addresses(
    reporter: &Reporter,
    event: &gnunet_tcp_communicator_runtime::addresses::Event<'_>,
) {
    use gnunet_nat_client_host::{Cause, Progress};
    use gnunet_tcp_communicator_runtime::addresses::Event;
    match event {
        Event::Failed(error) => reporter.warning(
            "tcp.address.failed",
            format_args!("TCP address owner: {error}"),
        ),
        Event::ScanFailed(error) => reporter.warning(
            "tcp.address.scan.failed",
            format_args!("TCP interface scan: {error}"),
        ),
        Event::Nat(Progress::Ended(end))
            if !matches!(&end.source.cause, Cause::Closed | Cause::Cancelled) =>
        {
            reporter.warning(
                "tcp.address.nat.lost",
                format_args!("TCP original NAT source retired: {end:?}"),
            )
        }
        Event::Aborted => reporter.warning(
            "tcp.address.aborted",
            format_args!("TCP original publication/Pool aborted; dirty epoch retained"),
        ),
        Event::TransportRetired { .. } => reporter.message(
            gnunet_program_host::policy::Level::INFO,
            "tcp.address.transport.retired",
            format_args!("TCP address observation (local admissions only): {event:?}"),
        ),
        _ => reporter.debug(
            "tcp.address.activity",
            format_args!("TCP address observation (local admissions only): {event:?}"),
        ),
    }
}
