//! One original PROGRAM future owns all workers through their actual finally.
use crate::{
    Failure,
    control::Signals,
    early::Inherited,
    lifecycle::{Cleanup, Resolver},
    settings::{self, Settings},
};
use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution::SharedResolution};
use gnunet_config::Configuration;
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::Driver;
use gnunet_rest_host::{
    Context, Instances, Sources,
    http::{self, Event, Progress, Server},
};
use gnunet_service_runtime::{
    Activation, BoundListeners, accepted::SocketEvent, clock::RuntimeClock, service::ShutdownMode,
};
use std::{
    cell::Cell,
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

#[derive(Debug, Default)]
struct Observations {
    closed: u64,
    first_http_failure: Option<http::Report>,
    first_socket: Option<SocketEvent>,
}
fn observe(event: Event, reports: &Reporter, observations: &mut Observations) {
    match event {
        Event::Socket(SocketEvent::Failed(error)) if error.is_emfile() => {}
        Event::Socket(event) => {
            reports.debug("rest.socket", format_args!("REST actual socket={event:?}"));
            if observations.first_socket.is_none() {
                observations.first_socket = Some(event);
            }
        }
        Event::Closed(report) => {
            observations.closed = observations.closed.saturating_add(1);
            if report.failure.is_some() {
                reports.warning(
                    "rest.http.failed",
                    format_args!("REST original HTTP completion={report:?}"),
                );
                if observations.first_http_failure.is_none() {
                    observations.first_http_failure = Some(report);
                }
            }
        }
        other => reports.debug(
            "rest.http.activity",
            format_args!("REST actual event={other:?}"),
        ),
    }
}
/// Actual owned cleanup results, including successful reports when PROGRAM or
/// selected logging independently failed. No input/auth/token body is retained.
#[derive(Debug, Default)]
pub(super) struct Report {
    http_constructed: bool,
    canceled: usize,
    configuration:
        Option<Result<gnunet_rest_host::config::worker::Stopped, gnunet_rest_host::Error>>,
    #[cfg(feature = "oidc")]
    oidc: Option<gnunet_rest_host::oidc::persistence::Stopped>,
    observations: Observations,
}
impl Report {
    fn failed(&self) -> bool {
        let configuration = self
            .configuration
            .as_ref()
            .is_some_and(|result| match result {
                Ok(stopped) => stopped.failure.is_some(),
                Err(_) => true,
            });
        #[cfg(feature = "oidc")]
        let oidc = self.oidc.as_ref().is_some_and(|stopped| stopped.failed());
        #[cfg(not(feature = "oidc"))]
        let oidc = false;
        configuration || oidc
    }
}
#[derive(Debug, Default)]
struct Failures {
    task: Option<Failure>,
    resolver: Option<Failure>,
    retirement: Option<Failure>,
    logging: Option<io::Error>,
    output: Option<io::Error>,
    report: Report,
}
impl Failures {
    fn finish(self) -> Result<Report, Failure> {
        if self.task.is_none()
            && self.resolver.is_none()
            && self.retirement.is_none()
            && self.logging.is_none()
            && self.output.is_none()
            && !self.report.failed()
        {
            Ok(self.report)
        } else {
            Err(Box::new(self))
        }
    }
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "REST original lifecycle={self:?}")
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        #[cfg(feature = "oidc")]
        let oidc = self
            .report
            .oidc
            .as_ref()
            .filter(|stopped| stopped.failed())
            .map(|stopped| stopped as &dyn Error);
        #[cfg(not(feature = "oidc"))]
        let oidc: Option<&dyn Error> = None;
        self.task
            .as_deref()
            .or(self.resolver.as_deref())
            .or(self.retirement.as_deref())
            .or_else(|| self.logging.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.output.as_ref().map(|e| e as &dyn Error))
            .or(match self.report.configuration.as_ref() {
                Some(Err(error)) => Some(error as &dyn Error),
                // Worker failures remain owned in the typed report; they do
                // not implement the standard Error trait used by this chain.
                Some(Ok(_)) | None => None,
            })
            .or(oidc)
    }
}
struct Bound {
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
}
struct Control {
    signals: Option<Signals>,
    stop: Rc<Cell<bool>>,
    reports: Reporter,
    grace: Duration,
    retirement: Option<Bound>,
    retirement_error: Option<Failure>,
    expired: bool,
    startup_stopped: bool,
    signal_error: Option<Failure>,
}
impl Control {
    fn stopped(&self) -> bool {
        self.stop.get() || self.reports.failed() || self.startup_stopped
    }
    fn arm(&mut self) {
        if self.retirement.is_some() || self.retirement_error.is_some() {
            return;
        }
        match Instant::now().checked_add(self.grace) {
            Some(hard) => {
                self.retirement = Some(Bound {
                    hard,
                    alarm: Box::pin(tokio::time::sleep_until(hard)),
                })
            }
            None => self.retirement_error = Some("REST original retirement target overflow".into()),
        }
    }
    fn guard(&mut self, cx: &mut TaskContext<'_>) -> bool {
        if self.expired {
            return true;
        }
        if self.retirement.as_mut().is_some_and(|bound| {
            bound.alarm.as_mut().poll(cx).is_ready() || Instant::now() >= bound.hard
        }) {
            self.expired = true;
            self.retirement_error.get_or_insert_with(|| "REST original native retirement deadline elapsed; original worker join remains required".into());
        }
        self.expired
    }
    fn poll_stop(&mut self, cx: &mut TaskContext<'_>) -> Result<bool, Failure> {
        self.reports.register(cx);
        if self.stopped() {
            self.arm();
            let _expired = self.guard(cx);
            return Ok(true);
        }
        let signals = self
            .signals
            .as_mut()
            .ok_or("original REST signal owner absent")?;
        match signals.poll(cx) {
            Poll::Ready(result) => {
                result?;
                self.arm();
                let _expired = self.guard(cx);
                Ok(true)
            }
            Poll::Pending => Ok(false),
        }
    }
    async fn checkpoint(&mut self) -> Result<bool, Failure> {
        poll_fn(|cx| Poll::Ready(self.poll_stop(cx))).await
    }
}
/// A started persistent-provider constructor is itself an original owned job.
/// Stop before its first poll prevents starting it. Stop after it started is
/// latched while that exact future finishes and returns its real owner/error.
#[cfg(feature = "oidc")]
async fn initialize<F, T>(future: F, control: &mut Control) -> Result<Option<T>, Failure>
where
    F: Future<Output = Result<T, Failure>>,
{
    let mut original = std::pin::pin!(future);
    let mut started = false;
    poll_fn(|cx| {
        let _expired = control.guard(cx);
        if !control.startup_stopped {
            match control.poll_stop(cx) {
                Ok(true) => control.startup_stopped = true,
                Ok(false) => {}
                Err(error) => {
                    control.startup_stopped = true;
                    control.arm();
                    let _expired = control.guard(cx);
                    control.signal_error = Some(error);
                }
            }
        }
        if control.stopped() && !started {
            return Poll::Ready(Ok(None));
        }
        started = true;
        original.as_mut().poll(cx).map(|result| result.map(Some))
    })
    .await
}
pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    inherited: Inherited,
    reports: Reporter,
) -> Result<Report, Failure> {
    let config = prepared.main().config.duplicate()?;
    let runtime: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config.duplicate()?);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<64, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime,
    )?;
    let resolution = context.resolution_context();
    let stop = Rc::new(Cell::new(false));
    let original = run(Run {
        config,
        settings,
        inherited,
        resolver,
        live,
        resolution,
        reports,
        stop: stop.clone(),
    });
    gnunet_program_host::foreground::run(prepared, &mut context, clock, stop, original).await
}
struct Run {
    config: Configuration,
    settings: Settings,
    inherited: Inherited,
    resolver: Driver<64, 256>,
    live: LiveConfiguration,
    resolution: SharedResolution,
    reports: Reporter,
    stop: Rc<Cell<bool>>,
}
async fn run(input: Run) -> Result<Report, Failure> {
    let Run {
        config,
        settings,
        inherited,
        resolver,
        live,
        resolution,
        reports,
        stop,
    } = input;
    let cleanup = Cleanup::default();
    let mut resolver = Resolver::new(resolver, cleanup.clone());
    let mut configuration_driver = None;
    #[cfg(feature = "oidc")]
    let mut oidc_driver = None;
    let mut control = Control {
        signals: None,
        stop,
        reports: reports.clone(),
        grace: settings.grace,
        retirement: None,
        retirement_error: None,
        expired: false,
        startup_stopped: false,
        signal_error: None,
    };
    let mut failures = Failures::default();
    // This is the finally boundary, before either worker can start. Every later
    // ? unwinds only the inner body and preserves these original driver owners.
    let outcome: Result<(), Failure> = async {
        control.signals = Some(Signals::new(inherited.parent)?);
        if control.checkpoint().await? {
            return Ok(());
        }
        let policy = settings::policy(&config)?;
        let identity = gnunet_identity_client_host::Instance::new();
        let namestore = gnunet_namestore_client_host::Instance::new();
        let reclaim = gnunet_reclaim_client_host::Instance::new();
        let mut unicode = gnunet_idna::Workspace::new();
        let idna = gnunet_idna::Backend::new(
            &mut unicode,
            gnunet_idna::Limits::GNUNET,
            gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
        );
        let profile = if cfg!(target_endian = "little") {
            gnunet_gnsrecord_text::Profile::LITTLE_255
        } else {
            gnunet_gnsrecord_text::Profile::BIG_255
        };
        let target = settings::configuration_target(&config)?;
        if control.checkpoint().await? {
            return Ok(());
        }
        let (configuration_port, driver) = gnunet_rest_host::config::Driver::start(
            live.clone(),
            target,
            resolution.clock(),
            Default::default(),
        )?;
        configuration_driver = Some(driver);
        // The existing external configured GNS CLIENT remains unchanged.
        let gns = gnunet_rest_host::gns::Gns::new(
            EndpointSource::live(live.clone(), b"gns", resolution.clone()),
            live.clone(),
            Default::default(),
        );
        #[cfg(feature = "oidc")]
        let oidc_provider =
            match initialize(settings::oidc(&config, resolution.clock()), &mut control).await? {
                Some(Some(settings::Oidc { provider, driver })) => {
                    oidc_driver = Some(driver);
                    Some(provider)
                }
                Some(None) => None,
                None => return Ok(()),
            };
        #[cfg(not(feature = "oidc"))]
        if settings::oidc_enabled(&config)? {
            return Err("OIDC_ENABLED requires the explicit oidc build feature".into());
        }
        if control.checkpoint().await? {
            return Ok(());
        }
        let handlers = Context::new(
            Instances {
                identity: &identity,
                namestore: &namestore,
                reclaim: &reclaim,
            },
            Sources {
                identity: EndpointSource::live(live.clone(), b"identity", resolution.clone()),
                namestore: EndpointSource::live(live.clone(), b"namestore", resolution.clone()),
                reclaim: EndpointSource::live(live, b"reclaim", resolution),
            },
            &idna,
            profile,
            settings.handlers,
        )?
        .with_consume_profile(settings.consume_profile)
        .with_configuration(&configuration_port)?
        .with_gns(&gns)?;
        #[cfg(feature = "oidc")]
        let handlers = match &oidc_provider {
            Some(provider) => handlers.with_oidc(provider)?,
            None => handlers,
        };
        serve(Serving {
            config: &config,
            settings: &settings,
            activation: inherited.activation,
            handlers: &handlers,
            policy: &policy,
            resolver: &mut resolver,
            configuration: configuration_driver
                .as_mut()
                .ok_or("original CONFIG driver absent")?,
            #[cfg(feature = "oidc")]
            oidc: &mut oidc_driver,
            control: &mut control,
            report: &mut failures.report,
        })
        .await
    }
    .await;
    failures.task = outcome.err();
    // HTTP jobs and handlers are already physically closed/dropped. Close the
    // same Resolver now; file-worker settlement requires no replacement MQ.
    resolver.close();
    failures.resolver = cleanup.take_error();
    control.arm();
    join(Joining {
        configuration: &mut configuration_driver,
        #[cfg(feature = "oidc")]
        oidc: &mut oidc_driver,
        control: &mut control,
        report: &mut failures.report,
    })
    .await;
    failures.retirement = control.retirement_error.take();
    if let Some(error) = control.signal_error.take() {
        failures.task = Some(Box::new(StartupSignal {
            original: failures.task.take(),
            signal: error,
        }));
    }
    failures.output = {
        let mut out = io::stdout().lock();
        writeln!(out, "STOPPED rest physically-canceled-jobs={} remote-mutation-rollback=not-claimed original-worker-reports=retained hidden-tasks=0", failures.report.canceled).and_then(|()| out.flush()).err()
    };
    failures.logging = reports.take_error();
    failures.finish()
}
#[derive(Debug)]
struct StartupSignal {
    original: Option<Failure>,
    signal: Failure,
}
impl fmt::Display for StartupSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "REST original={:?}; independent startup signal={}",
            self.original, self.signal
        )
    }
}
impl Error for StartupSignal {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref().or(Some(self.signal.as_ref()))
    }
}
struct Serving<'a, 'id, 'unicode> {
    config: &'a Configuration,
    settings: &'a Settings,
    activation: Activation,
    handlers: &'a Context<'id, gnunet_idna::Backend<'unicode>>,
    policy: &'a http::Policy,
    resolver: &'a mut Resolver,
    configuration: &'a mut gnunet_rest_host::config::Driver,
    #[cfg(feature = "oidc")]
    oidc: &'a mut Option<gnunet_rest_host::oidc::persistence::Driver>,
    control: &'a mut Control,
    report: &'a mut Report,
}
async fn serve(input: Serving<'_, '_, '_>) -> Result<(), Failure> {
    let Serving {
        config,
        settings,
        activation,
        handlers,
        policy,
        resolver,
        configuration,
        #[cfg(feature = "oidc")]
        oidc,
        control,
        report,
    } = input;
    if control.checkpoint().await? {
        return Ok(());
    }
    let mut server = Server::new(
        handlers,
        policy,
        settings.http,
        settings.options.clone(),
        settings.unix,
    )?;
    report.http_constructed = true;
    let outcome: Result<(), Failure> = async {
        let mut bound = Vec::new();
        bound.try_reserve_exact(2)?;
        if !activation.sockets.is_empty() {
            if control.checkpoint().await? { return Ok(()); }
            bound.push(BoundListeners::bind(config, b"rest", activation).await?);
        } else {
            let mut first = None;
            for v6 in [false, true] {
                let binding = settings::listener_config(config, v6)?;
                if control.checkpoint().await? { return Ok(()); }
                match BoundListeners::bind(&binding, b"rest", Activation::default()).await {
                    Ok(owner) => bound.push(owner),
                    Err(error) => {
                        control.reports.warning("rest.listener.alternate", format_args!("REST alternate v6={v6}: {error}"));
                        if first.is_none() { first = Some(error); }
                    }
                }
            }
            if bound.is_empty() { return Err(first.unwrap_or_else(|| "REST bound no listener".into())); }
        }
        for owner in &bound {
            for error in owner.failures() {
                control.reports.warning("rest.listener.alternate", format_args!("REST alternate listener: {error}"));
            }
        }
        if control.checkpoint().await? { return Ok(()); }
        {
            let mut out = io::stdout().lock();
            writeln!(out,"READY rest http=1.1 handlers=identity,namestore,reclaim,copying,config,gns config=file-worker gns=external-client openid=explicit-conditional tls=no native-ready=per-request hidden-tasks=0")?;
            out.flush()?;
        }
        let listeners: Vec<_> = bound.iter().flat_map(BoundListeners::listeners).collect();
        let mut cursor = 0;
        let mut soft_requested = false;
        loop {
            enum Turn { Stop, Expired, Server(Progress), Activity }
            let selected: Result<Turn, Failure> = poll_fn(|cx| {
                // The same original native target precedes canonical/provider IO.
                if control.guard(cx) { return Poll::Ready(Ok(Turn::Expired)); }
                if control.poll_stop(cx)? { return Poll::Ready(Ok(Turn::Stop)); }
                let classes = if cfg!(feature = "oidc") { 4 } else { 3 };
                for offset in 0..classes {
                    if control.guard(cx) { return Poll::Ready(Ok(Turn::Expired)); }
                    if control.stopped() { return Poll::Ready(Ok(Turn::Stop)); }
                    let class = (cursor + offset) % classes;
                    let step = match class {
                        0 => configuration.poll(cx).map(|r| r.map(|_| Turn::Activity).map_err(|e| Box::new(e) as Failure)),
                        1 => resolver.poll(cx, &control.reports).map(|r| r.map(|_| Turn::Activity).map_err(|e| Box::new(e) as Failure)),
                        2 => {
                            let deadline = control.retirement.as_ref().map(|b| b.hard);
                            let reports = control.reports.clone();
                            server.poll(cx, &listeners, deadline, &mut |event| observe(event, &reports, &mut report.observations))
                                .map(|r| r.map(Turn::Server).map_err(|e| Box::new(e) as Failure))
                        }
                        #[cfg(feature = "oidc")]
                        _ => match oidc.as_mut() {
                            Some(driver) => driver.poll(cx).map(|r| r.map(|_| Turn::Activity).map_err(|e| Box::new(e) as Failure)),
                            None => Poll::Pending,
                        },
                        #[cfg(not(feature = "oidc"))]
                        _ => Poll::Pending,
                    };
                    if step.is_ready() {
                        cursor = (class + 1) % classes;
                        return step;
                    }
                }
                Poll::Pending
            }).await;
            match selected? {
                Turn::Activity | Turn::Server(Progress::Activity) => {}
                Turn::Stop if control.retirement.is_some() && !control.stopped()
                    && settings.options.shutdown == ShutdownMode::Soft => {
                    // poll_stop armed this once for the first signal. A separate
                    // flag distinguishes that first request from a second signal.
                    if server_stopping(&mut soft_requested) { break; }
                    server.request_shutdown(ShutdownMode::Soft);
                }
                Turn::Stop | Turn::Expired | Turn::Server(Progress::Stopped | Progress::WaitDeadline) => break,
            }
        }
        Ok(())
    }.await;
    // Exactly the same server physically drops each original native request.
    // Worker drivers remain separately owned and will consume actual receipts.
    report.canceled = server.close_all();
    drop(server);
    outcome
}
fn server_stopping(requested: &mut bool) -> bool {
    let old = *requested;
    *requested = true;
    old
}
struct Joining<'a> {
    configuration: &'a mut Option<gnunet_rest_host::config::Driver>,
    #[cfg(feature = "oidc")]
    oidc: &'a mut Option<gnunet_rest_host::oidc::persistence::Driver>,
    control: &'a mut Control,
    report: &'a mut Report,
}
async fn join(input: Joining<'_>) {
    let Joining {
        configuration,
        #[cfg(feature = "oidc")]
        oidc,
        control,
        report,
    } = input;
    let mut configuration = configuration
        .as_mut()
        .map(|driver| Box::pin(driver.shutdown()));
    #[cfg(feature = "oidc")]
    let mut oidc = oidc.take().map(|driver| Box::pin(driver.shutdown()));
    // These are actual original shutdown futures, retained beyond a diagnostic
    // hard deadline until real OS/worker progress permits their physical join.
    poll_fn(|cx| {
        control.reports.register(cx);
        let _expired = control.guard(cx);
        if let Some(original) = configuration.as_mut()
            && let Poll::Ready(result) = original.as_mut().poll(cx)
        {
            report.configuration = Some(result);
            configuration = None;
        }
        #[cfg(feature = "oidc")]
        if let Some(original) = oidc.as_mut()
            && let Poll::Ready(result) = original.as_mut().poll(cx)
        {
            report.oidc = Some(result);
            oidc = None;
        }
        #[cfg(feature = "oidc")]
        let oidc_done = oidc.is_none();
        #[cfg(not(feature = "oidc"))]
        let oidc_done = true;
        if configuration.is_none() && oidc_done {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;
}
