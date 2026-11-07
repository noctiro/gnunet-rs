//! One explicit PROGRAM task, shared Resolver and original native EXIT owners.
use crate::{
    Failure,
    announcement::{self, Owner as Announcements},
    dns_advertisement,
    early::Inherited,
    lifecycle::{Cleanup, Stage},
    network,
    settings::Settings,
};
use gnunet_exit::engine::{Engine, Service};
use gnunet_exit_host::runtime::{Driver, Event, OsEntropy, Progress};
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{Context as ResolverContext, Driver as ResolverDriver, Reply};
use gnunet_service_startup::{ControlReceiver, ParentControl};
use gnunet_tun_host::{Action, Ipv6End, Ipv6Progress, Ipv6State, Ipv6Watch, Ipv6WatchOptions};
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    io::{self, Write},
    net::IpAddr,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::Instant,
};
pub(super) type Exit<'cfg, 'id, 'slots> = Driver<'cfg, 'id, 'slots, OsEntropy>;
pub(super) struct Stop {
    interrupt: Signal,
    terminate: Signal,
    parent: Option<ControlReceiver>,
    requested: bool,
    external: Rc<Cell<bool>>,
    pub reports: Reporter,
    pub cleanup: Cleanup,
    grace: std::time::Duration,
    hard: Option<Instant>,
}
impl Stop {
    fn new(
        parent: Option<ParentControl>,
        external: Rc<Cell<bool>>,
        reports: Reporter,
        cleanup: Cleanup,
        grace: std::time::Duration,
    ) -> Result<Self, Failure> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            parent: parent
                .map(|p| p.register().map_err(|e| e.error))
                .transpose()?,
            requested: false,
            external,
            reports,
            cleanup,
            grace,
            hard: None,
        })
    }
    fn request(&mut self) -> Result<(), Failure> {
        if !self.requested {
            self.requested = true;
            self.hard = Some(network::target(self.grace)?);
        }
        Ok(())
    }
    pub fn check(&mut self) -> Result<(), Failure> {
        if self.external.get() || self.reports.failed() {
            self.request()?;
        }
        if self.requested {
            Err(io::Error::new(io::ErrorKind::Interrupted, "EXIT shutdown requested").into())
        } else {
            Ok(())
        }
    }
    pub fn hard(&self) -> Option<Instant> {
        self.hard
    }
    pub async fn check_now(&mut self) -> Result<(), Failure> {
        poll_fn(|cx| match self.poll(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "EXIT stopped before new admission",
            )
            .into())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Ready(Ok(())),
        })
        .await
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        self.reports.register(cx);
        if self.external.get() || self.reports.failed() {
            self.request()?;
        }
        if self.requested {
            return Poll::Ready(Ok(()));
        }
        if let Some(control) = &mut self.parent {
            match control.poll_signal(cx) {
                Poll::Ready(Ok(Some(n)))
                    if i32::from(n) == SignalKind::interrupt().as_raw_value()
                        || i32::from(n) == SignalKind::terminate().as_raw_value() =>
                {
                    self.request()?;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => {}
            }
        }
        if self.interrupt.poll_recv(cx).is_ready() || self.terminate.poll_recv(cx).is_ready() {
            self.request()?;
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
}
pub(super) fn observe(event: Event<'_>, reports: &Reporter, cleanup: &Cleanup) {
    match event {
        Event::TunLost(loss) => {
            reports.warning(
                "exit.packet.lost",
                format_args!("EXIT actual original packet source loss: {loss:?}"),
            );
            cleanup.retain(Stage::Tun, Box::new(crate::lifecycle::TunLoss(loss)));
        }
        Event::CadetLost { report, cause } => reports.warning(
            "exit.cadet.lost",
            format_args!(
                "EXIT actual CADET loss={report:?} cause={cause:?}; original data not replayed"
            ),
        ),
        Event::ConnectRetry { error, retry_after } => reports.warning(
            "exit.cadet.retry",
            format_args!("EXIT actual CADET connection refusal={error}; retry={retry_after:?}"),
        ),
        Event::DnsFailed { job, error } => reports.warning(
            "exit.dns.failed",
            format_args!("EXIT actual original DNS job={job:?} error={error}"),
        ),
        Event::Activity => {}
        other => reports.debug(
            "exit.runtime.activity",
            format_args!("EXIT actual original runtime event: {other:?}"),
        ),
    }
}
fn observe_announcement(event: announcement::Event<'_>, reports: &Reporter) {
    match event {
        announcement::Event::Started { family, generation, job } => reports.debug(
            "exit.regex.started",
            format_args!("EXIT original REGEX family={family:?} generation={generation} job={job:?}; no remote publication ACK"),
        ),
        announcement::Event::Native { family, generation, progress } => reports.debug(
            "exit.regex.native",
            format_args!("EXIT original REGEX family={family:?} generation={generation} progress={progress:?}; no remote publication ACK"),
        ),
        announcement::Event::Cancelled { family, generation, end } => reports.debug(
            "exit.regex.cancelled",
            format_args!("EXIT original REGEX family={family:?} generation={generation} end={end:?}; no remote publication ACK"),
        ),
    }
}
fn resolver_event(event: gnunet_resolver_broker::DriverEvent, reports: &Reporter) {
    match event {
        gnunet_resolver_broker::DriverEvent::Lost { .. }
        | gnunet_resolver_broker::DriverEvent::Unavailable
        | gnunet_resolver_broker::DriverEvent::SocketRetry { .. } => reports.warning(
            "exit.resolver.failed",
            format_args!("EXIT actual Resolver: {event:?}"),
        ),
        _ => reports.debug(
            "exit.resolver.activity",
            format_args!("EXIT actual Resolver: {event:?}"),
        ),
    }
}
struct Resolver {
    driver: Option<ResolverDriver<128, 256>>,
    reports: Reporter,
    cleanup: Cleanup,
    closed: bool,
}
impl Resolver {
    fn driver_mut(&mut self) -> Result<&mut ResolverDriver<128, 256>, Failure> {
        self.driver
            .as_mut()
            .ok_or_else(|| "original EXIT Resolver retired".into())
    }
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Some(mut driver) = self.driver.take() {
            if let Err(error) = driver.disconnect() {
                self.reports.warning(
                    "exit.resolver.close.failed",
                    format_args!("EXIT actual Resolver close failure: {error}"),
                );
                self.cleanup.retain(Stage::Resolver, Box::new(error));
            }
            // Physical owner is dropped even when its logical disconnect failed.
            drop(driver);
        }
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        self.close();
    }
}
/// Drop also performs physical cleanup if PROGRAM's own clock fails before
/// polling the task again. No further clock sample is required for this path.
struct Owners<'cfg, 'id, 'slots> {
    exit: Exit<'cfg, 'id, 'slots>,
    announcements: Announcements<'cfg, 'id>,
    dns_advertisement: Option<dns_advertisement::Owner<'cfg>>,
    binding_count: usize,
    requires_tun: bool,
    resolver: Resolver,
    watch: Option<Ipv6Watch>,
    routes: Vec<Action>,
    done: bool,
    reports: Reporter,
    cleanup: Cleanup,
}
impl Owners<'_, '_, '_> {
    fn cancel_watch(&mut self) -> Result<(), Failure> {
        if let Some(mut watch) = self.watch.take() {
            let result = watch.cancel();
            self.reports.debug(
                "exit.ipv6.closed",
                format_args!("EXIT actual IPv6 observer cleanup: {result:?}"),
            );
            if let Ipv6Progress::Complete(value) = result
                && let Some(e) = value.close_error
            {
                return Err(e.into());
            }
        }
        Ok(())
    }
}
impl Owners<'_, '_, '_> {
    fn close_dns_advertisement(&mut self) {
        if let Some(owner) = &mut self.dns_advertisement {
            let (report, failure) = owner.close();
            if let Some(report) = report {
                self.cleanup.dns_advertisement(report);
            }
            if let Some(error) = failure {
                self.cleanup.retain(Stage::Advertisement, error);
            }
        }
    }
    fn shutdown(&mut self) {
        if self.done {
            return;
        }
        self.close_dns_advertisement();
        let reports = self.reports.clone();
        let cleanup = self.cleanup.clone();
        let regex = self
            .announcements
            .close(&mut |event| observe_announcement(event, &reports));
        if let Err(error) = self.cancel_watch() {
            cleanup.retain(Stage::Watch, error);
        }
        let closed = self
            .exit
            .shutdown(|event| observe(event, &reports, &cleanup));
        if let Some(error) = closed.failure {
            cleanup.retain(Stage::Shutdown, Box::new(error));
        }
        if !closed.quiescent {
            cleanup.retain(Stage::Debt, gnunet_types::Error::OutcomeUnknown.into());
        }
        if let Some(error) = self.exit.entropy_mut().take_failure() {
            cleanup.retain(
                Stage::Entropy,
                Box::new(gnunet_exit_host::runtime::Error::Entropy(error)),
            );
        }
        cleanup.facts(crate::lifecycle::Facts {
            native: closed.report,
            quiescent: closed.quiescent,
            regex,
            unremoved_routes: self.routes.len(),
        });
        self.done = true;
    }
}
impl Drop for Owners<'_, '_, '_> {
    fn drop(&mut self) {
        self.shutdown();
        self.resolver.close();
    }
}
pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    inherited: Inherited,
    reports: Reporter,
    cleanup: Cleanup,
) -> Result<(), Failure> {
    let live = gnunet_client_host::LiveConfiguration::new(prepared.main().config.duplicate()?);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<128, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        Arc::new(clock.clone()),
    )?;
    let task_context = context.clone();
    let stop = Rc::new(Cell::new(false));
    gnunet_program_host::foreground::run(
        prepared,
        &mut context,
        clock,
        stop.clone(),
        run(Inputs {
            settings,
            inherited,
            live,
            context: task_context,
            resolver,
            reports,
            cleanup,
            external: stop,
        }),
    )
    .await
}
async fn resolve(
    settings: &Settings,
    context: &ResolverContext<128, 256>,
    resolver: &mut ResolverDriver<128, 256>,
    stop: &mut Stop,
) -> Result<Vec<Service>, Failure> {
    let reports = stop.reports.clone();
    let mut result = Vec::new();
    result.try_reserve_exact(settings.redirects.len())?;
    for redirect in &settings.redirects {
        stop.check_now().await?;
        let literal = match redirect.host.as_str() {
            "localhost4" => Some(IpAddr::V4(
                settings
                    .ipv4
                    .ok_or("localhost4 requires enabled IPV4ADDR")?
                    .0,
            )),
            "localhost6" => Some(IpAddr::V6(
                settings
                    .ipv6
                    .ok_or("localhost6 requires enabled IPV6ADDR")?
                    .0,
            )),
            name => name.parse::<IpAddr>().ok(),
        };
        let ip = if let Some(ip) = literal {
            ip
        } else {
            let mut query = context.ip_get(
                redirect.host.as_bytes(),
                gnunet_resolver_broker::Family::Any,
                gnunet_types::Duration(u64::try_from(settings.lookup.as_micros())?),
            )?;
            let until = network::target(settings.lookup)?;
            let mut alarm = std::pin::pin!(tokio::time::sleep_until(until));
            loop {
                enum Callback {
                    Address(IpAddr),
                    Complete(String),
                    Activity,
                }
                let callback = {
                    let mut next = std::pin::pin!(query.next());
                    let mut driving = std::pin::pin!(
                        resolver.drive_waiting(Some(until), |e| resolver_event(e, &reports))
                    );
                    poll_fn(|cx| {
                        match stop.poll(cx) {
                            Poll::Ready(Ok(())) => {
                                return Poll::Ready(Err(
                                    "shutdown during service hostname lookup".into()
                                ));
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => {}
                        }
                        if alarm.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(Err(
                                "service hostname lookup reached its original deadline".into(),
                            ));
                        }
                        // Poll the original shared MQ even when callbacks are ready.
                        let progress = match driving.as_mut().poll(cx) {
                            Poll::Ready(Ok(_)) => true,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                            Poll::Pending => false,
                        };
                        if reports.failed() {
                            return Poll::Ready(Err(
                                "EXIT selected Logger failed during service lookup".into(),
                            ));
                        }
                        match next.as_mut().poll(cx) {
                            Poll::Ready(Ok(Some(value))) => Poll::Ready(match value.reply()? {
                                Reply::Address(ip) => Ok(Callback::Address(ip)),
                                Reply::Complete(c) => Ok(Callback::Complete(format!("{c:?}"))),
                                Reply::Hostname(_) => {
                                    Err("unexpected reverse callback in forward service lookup"
                                        .into())
                                }
                            }),
                            Poll::Ready(Ok(None)) => {
                                Poll::Ready(Err("service query closed without an address".into()))
                            }
                            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                            Poll::Pending if progress => Poll::Ready(Ok(Callback::Activity)),
                            Poll::Pending => Poll::Pending,
                        }
                    })
                    .await?
                };
                match callback {
                    Callback::Address(ip) if settings.enabled(ip) => {
                        query.cancel()?;
                        break ip;
                    }
                    Callback::Address(_) | Callback::Activity => {}
                    Callback::Complete(reason) => {
                        return Err(format!(
                            "no enabled address for service {}: {reason}",
                            redirect.host
                        )
                        .into());
                    }
                }
                tokio::task::yield_now().await;
            }
        };
        result.push(settings.service(redirect, ip)?);
    }
    Ok(result)
}
fn bindings_written(driver: &Exit<'_, '_, '_>, count: usize) -> Result<bool, Failure> {
    for index in 0..count {
        if !driver.binding_status(index)?.announced {
            return Ok(false);
        }
    }
    Ok(true)
}
fn dns_port_written(driver: &Exit<'_, '_, '_>, count: usize) -> Result<bool, Failure> {
    for index in 0..count {
        let current = driver.binding_status(index)?;
        if matches!(current.binding.target, gnunet_exit::engine::Target::Dns) {
            return Ok(current.announced);
        }
    }
    Err(gnunet_types::Error::NotFound.into())
}
enum Turn {
    Stop,
    Step(Progress),
    RenewWatch,
}
async fn turn(
    owners: &mut Owners<'_, '_, '_>,
    stop: &mut Stop,
    until: Option<Instant>,
    interruptible: bool,
) -> Result<Turn, Failure> {
    let reports = owners.reports.clone();
    let cleanup = owners.cleanup.clone();
    let exit = &mut owners.exit;
    let binding_count = owners.binding_count;
    let requires_tun = owners.requires_tun;
    let mut resolving = std::pin::pin!(
        owners
            .resolver
            .driver_mut()?
            .drive_waiting(until, |e| resolver_event(e, &reports))
    );
    let watch = &mut owners.watch;
    let announcements = &mut owners.announcements;
    let dns_advertisement = &mut owners.dns_advertisement;
    poll_fn(|cx| {
        reports.register(cx);
        let guarded =
            exit.poll_native_guard(cx, &mut |event| observe(event, &reports, &cleanup))?;
        if let Some(target) = until
            && Instant::now() >= target
        {
            return Poll::Ready(Ok(Turn::Step(Progress::WaitDeadline)));
        }
        if requires_tun && !exit.tun_source_current() {
            return Poll::Ready(Err("original EXIT packet source retired".into()));
        }
        if interruptible {
            match stop.poll(cx) {
                Poll::Ready(Ok(())) => return Poll::Ready(Ok(Turn::Stop)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }
        let mut progressed = guarded;
        if let Some(watch) = watch {
            match watch.poll(cx) {
                Poll::Ready(Ipv6Progress::Observed(sample)) => {
                    if sample.state != Ipv6State::Ready {
                        return Poll::Ready(Err(format!(
                            "configured IPv6 source is no longer ready: {sample:?}"
                        )
                        .into()));
                    }
                    progressed = true;
                }
                Poll::Ready(Ipv6Progress::Complete(mut done)) => {
                    if let Some(e) = done.close_error.take() {
                        return Poll::Ready(Err(e.into()));
                    }
                    if matches!(done.reason, Ipv6End::Deadline) {
                        return Poll::Ready(Ok(Turn::RenewWatch));
                    }
                    return Poll::Ready(Err(format!("IPv6 observer source lost: {done:?}").into()));
                }
                Poll::Ready(Ipv6Progress::Finished) => {
                    return Poll::Ready(Err(
                        "IPv6 observer completion was consumed unexpectedly".into()
                    ));
                }
                Poll::Ready(Ipv6Progress::Activity { .. } | Ipv6Progress::WaitDeadline) => {
                    progressed = true
                }
                Poll::Pending => {}
            }
        }
        if interruptible {
            if reports.failed() {
                return Poll::Ready(Ok(Turn::Stop));
            }
            match resolving.as_mut().poll(cx) {
                Poll::Ready(Ok(_)) => progressed = true,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Pending => {}
            }
            if reports.failed() {
                return Poll::Ready(Ok(Turn::Stop));
            }
        }
        // A cancelled drive wait retains all original Driver cursors. Drop
        // this bounded polling future before checking the resulting source state.
        let exit_step = {
            let mut driving =
                std::pin::pin!(exit.drive(until, |event| observe(event, &reports, &cleanup)));
            driving.as_mut().poll(cx)
        };
        let step = match exit_step {
            Poll::Ready(Ok(p @ (Progress::Stopped | Progress::WaitDeadline))) => {
                return Poll::Ready(Ok(Turn::Step(p)));
            }
            Poll::Ready(Ok(p)) => Some(p),
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Pending => None,
        };
        if interruptible && reports.failed() {
            return Poll::Ready(Ok(Turn::Stop));
        }
        let ports_ready = bindings_written(exit, binding_count)?;
        if interruptible && ports_ready && (!requires_tun || exit.tun_source_current()) {
            announcements.enable();
        } else {
            announcements.pause(&mut |event| observe_announcement(event, &reports));
        }
        if interruptible && reports.failed() {
            return Poll::Ready(Ok(Turn::Stop));
        }
        if interruptible {
            match announcements.poll(cx, &mut |event| observe_announcement(event, &reports)) {
                Poll::Ready(Ok(activity)) => progressed |= activity,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }
        if interruptible && reports.failed() {
            return Poll::Ready(Ok(Turn::Stop));
        }
        if interruptible && let Some(owner) = dns_advertisement.as_mut() {
            // Re-read the actual DNS port after this turn's CADET input/loss.
            // No new ad IO follows a known canceled/retired source.
            owner.readiness(
                dns_port_written(exit, binding_count)?
                    && (!requires_tun || exit.tun_source_current()),
            )?;
            match owner.poll(cx) {
                Poll::Ready(Ok(activity)) => progressed |= activity,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
        }
        if let Some(step) = step {
            Poll::Ready(Ok(Turn::Step(step)))
        } else if progressed {
            Poll::Ready(Ok(Turn::Step(Progress::Activity)))
        } else {
            Poll::Pending
        }
    })
    .await
}
struct Inputs {
    settings: Settings,
    inherited: Inherited,
    live: gnunet_client_host::LiveConfiguration,
    context: ResolverContext<128, 256>,
    resolver: ResolverDriver<128, 256>,
    reports: Reporter,
    cleanup: Cleanup,
    external: Rc<Cell<bool>>,
}
async fn run(input: Inputs) -> Result<(), Failure> {
    let Inputs {
        settings,
        inherited,
        live,
        context,
        resolver,
        reports,
        cleanup,
        external,
    } = input;
    let mut resolver = Resolver {
        driver: Some(resolver),
        reports: reports.clone(),
        cleanup: cleanup.clone(),
        closed: false,
    };
    let mut stop = Stop::new(
        inherited.parent,
        external,
        reports.clone(),
        cleanup.clone(),
        settings.shutdown,
    )?;
    stop.check()?;
    let services = resolve(&settings, &context, resolver.driver_mut()?, &mut stop).await?;
    let bindings = settings.bindings(&services)?;
    let engine = Engine::new(settings.config(&services), settings.core)?;
    let source = gnunet_client_host::EndpointSource::live(
        live.clone(),
        b"cadet",
        context.resolution_context(),
    );
    let regex_instance = gnunet_regex_client_host::Instance::new();
    let announcements = Announcements::new(
        &regex_instance,
        gnunet_client_host::EndpointSource::live(
            live.clone(),
            b"regex",
            context.resolution_context(),
        ),
        &settings.advertising,
    );
    let mut instance = gnunet_cadet_host::Instance::new();
    let mut ports = Vec::new();
    ports.try_reserve_exact(settings.native.ports)?;
    ports.resize_with(settings.native.ports, gnunet_cadet_host::PortSlot::new);
    let mut channels = Vec::new();
    channels.try_reserve_exact(settings.native.channels)?;
    channels.resize_with(
        settings.native.channels,
        gnunet_cadet_host::ChannelSlot::new,
    );
    let cadet = gnunet_cadet_host::Client::new(
        &mut instance,
        source,
        &mut ports,
        &mut channels,
        settings.cadet,
    )?;
    stop.check()?;
    let mut routes = Vec::new();
    routes.try_reserve_exact(settings.routes.len())?;
    let startup = network::target(settings.startup)?;
    let mut dns_pils = gnunet_pils::client::Instance::new();
    let mut dns_dht = gnunet_dht_client_host::Instance::new();
    let dns_advertisement = if settings.dns.is_some() {
        Some(dns_advertisement::Owner::new(
            &mut dns_pils,
            &mut dns_dht,
            gnunet_client_host::EndpointSource::live(
                live.clone(),
                b"pils",
                context.resolution_context(),
            ),
            gnunet_client_host::EndpointSource::live(live, b"dht", context.resolution_context()),
            startup,
            settings.pils_profile,
        )?)
    } else {
        None
    };
    let (tun, tun_description) =
        network::open(&settings, inherited.tun, &mut stop, startup).await?;
    let exit = match Exit::try_new(
        gnunet_exit_host::runtime::Parts {
            engine,
            cadet,
            tun,
            entropy: OsEntropy::default(),
        },
        &bindings,
        settings.dns,
        settings.native,
    ) {
        Ok(exit) => exit,
        Err(rejected) => {
            let mut parts = rejected.parts;
            if let Err(error) = parts.cadet.close() {
                cleanup.retain(Stage::Constructor, Box::new(error));
            }
            if let Some(mut source) = parts.tun {
                let loss = source.close();
                if loss.close_error.is_some() {
                    cleanup.retain(
                        Stage::Constructor,
                        Box::new(crate::lifecycle::TunLoss(loss)),
                    );
                }
                if let Some(report) = source.reap_helper().await {
                    cleanup.helper(report);
                }
            }
            return Err(Box::new(rejected.error));
        }
    };
    let mut owners = Owners {
        exit,
        announcements,
        dns_advertisement,
        binding_count: bindings.len(),
        requires_tun: settings.ipv4.is_some() || settings.ipv6.is_some(),
        resolver,
        watch: None,
        routes,
        done: false,
        reports: reports.clone(),
        cleanup: cleanup.clone(),
    };
    let outcome = async {
        owners.watch = network::configure(
            &mut owners.exit, &settings, &mut stop, &mut owners.routes,
        ).await?;
        let mut ready = false;
        loop {
            let ports_ready = bindings_written(&owners.exit, bindings.len())?;
            let sources_ready = ports_ready
                && (!owners.requires_tun || owners.exit.tun_source_current());
            if sources_ready {
                // network::configure has already returned actual TUN/DAD/route
                // readiness. Only now may either original REGEX job open its MQ.
                owners.announcements.enable();
            } else {
                owners.announcements.pause(&mut |event|observe_announcement(event,&reports));
            }
            stop.check()?;
            // Forwarding readiness remains independent of transient advertiser
            // dependencies. Its separate report says only actual local PUT facts.
            if !ready && sources_ready && owners.announcements.submitted() {
                stop.check()?;
                let mut output = io::stdout().lock();
                writeln!(
                    output,
                    "READY exit wire=0.29.1 cadet_ports_written={} tun={} ipv4_native_observed={} ipv6_dad={} explicit_routes_kernel_ack={} dns={} regex_local=({}) dns_advertisement_local={:?} advertisement_ack=none remote_reachability=unasserted",
                    bindings.len(),
                    tun_description,
                    settings.ipv4.is_some(),
                    if settings.ipv6.is_some() { "observed-ready" } else { "disabled" },
                    owners.routes.len(),
                    if settings.dns.is_some() { "literal-configured" } else { "disabled" },
                    owners.announcements.report(),
                    owners.dns_advertisement.as_ref().map(|owner| owner.report()),
                )?;
                output.flush()?;
                ready = true;
            }
            match turn(
                &mut owners, &mut stop, if ready { None } else { Some(startup) }, true,
            ).await? {
                Turn::Stop => return Ok::<(), Failure>(()),
                Turn::RenewWatch => {
                    let (address, prefix) = settings.ipv6.ok_or("IPv6 observer has no configured address")?;
                    owners.watch = Some(owners.exit.watch_tun_ipv6(
                        address, prefix, network::target(settings.watch)?, Ipv6WatchOptions::default(),
                    )?);
                }
                Turn::Step(Progress::Activity) => {},
                Turn::Step(Progress::Stopped) => return Err("EXIT sources stopped before a process shutdown request".into()),
                Turn::Step(Progress::WaitDeadline) => return Err("CADET ports or required local REGEX submissions did not complete before the original startup deadline".into()),
            }
            tokio::task::yield_now().await;
        }
    }.await;
    // One original native retirement bound; repeated turns never renew it.
    let until = stop
        .hard()
        .map(Ok)
        .unwrap_or_else(|| network::target(settings.shutdown));
    owners.close_dns_advertisement();
    let _regex_cleanup = owners
        .announcements
        .close(&mut |event| observe_announcement(event, &reports));
    if let Err(error) = owners.cancel_watch() {
        cleanup.retain(Stage::Watch, error);
    }
    match &until {
        Ok(until) => {
            if let Err(error) =
                network::cleanup(&mut owners.exit, &mut owners.routes, &mut stop, *until).await
            {
                cleanup.retain(Stage::Routes, error);
            }
        }
        Err(_) => cleanup.retain(
            Stage::Routes,
            "original EXIT shutdown deadline overflow".into(),
        ),
    }
    owners.exit.request_shutdown();
    if let Ok(until) = until {
        loop {
            match turn(&mut owners, &mut stop, Some(until), false).await {
                Ok(Turn::Step(Progress::Activity)) => tokio::task::yield_now().await,
                Ok(Turn::Step(Progress::Stopped | Progress::WaitDeadline)) => break,
                Ok(Turn::Stop | Turn::RenewWatch) => {
                    cleanup.retain(Stage::Drain, "unexpected retirement callback".into());
                    break;
                }
                Err(error) => {
                    cleanup.retain(Stage::Drain, error);
                    break;
                }
            }
        }
    } else {
        cleanup.retain(
            Stage::Drain,
            "original EXIT shutdown deadline overflow".into(),
        );
    }
    owners.shutdown();
    if let Some(report) = owners.exit.reap_helper().await {
        cleanup.helper(report);
    }
    owners.resolver.close();
    if let Err(error) = cleanup.output() {
        cleanup.retain(Stage::Output, Box::new(error));
    }
    outcome
}
