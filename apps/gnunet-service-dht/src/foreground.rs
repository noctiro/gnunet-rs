//! Actual standard SERVICE lifetime over one native DHT owner and one Resolver.
use crate::{
    Cause,
    control::Signals,
    lifecycle::{Cleanup, Resolver},
    settings::Settings,
};
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_dht_service_host::{
    Error as HostError, Event, Instances, Ports, Progress, Report, Server,
};
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{LiveConfiguration, broker, native_profile};
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
pub(super) struct Inputs<'a> {
    pub config: &'a Configuration,
    pub settings: &'a Settings,
    pub bound: &'a BoundListeners,
    pub parent: Option<ParentControl>,
    pub clock: SharedClock,
    pub reports: Reporter,
    pub child: &'a mut ChildReady,
    pub cleanup: Cleanup,
}
#[derive(Debug)]
enum Reason {
    Signal,
    Logger,
    NativeClosed,
    Failed,
    Grace,
    SecondSignal,
}
#[derive(Debug, Default)]
struct Failures {
    original: Option<Cause>,
    running: Option<HostError>,
    resolver: Option<gnunet_resolver_broker::BrokerError>,
    signal: Option<io::Error>,
    cleanup: Option<HostError>,
    resolver_close: Option<Cause>,
    logging: Option<io::Error>,
    output: Option<io::Error>,
    timeout: bool,
    reason: Option<Reason>,
    report: Report,
}
impl Failures {
    fn failed(&self) -> bool {
        self.original.is_some()
            || self.running.is_some()
            || self.resolver.is_some()
            || self.signal.is_some()
            || self.cleanup.is_some()
            || self.resolver_close.is_some()
            || self.logging.is_some()
            || self.output.is_some()
            || self.timeout
            || !self.report.quiescent
    }
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DHT original lifecycle={self:?}")
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.running.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.resolver.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.signal.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.cleanup.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_close.as_deref())
            .or_else(|| self.logging.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.output.as_ref().map(|e| e as &dyn Error))
    }
}
struct Grace {
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
}
impl Grace {
    fn new(duration: std::time::Duration) -> Result<Self, Cause> {
        let hard = Instant::now()
            .checked_add(duration)
            .ok_or("DHT original cleanup target overflow")?;
        Ok(Self {
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
        })
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> bool {
        Instant::now() >= self.hard || self.alarm.as_mut().poll(cx).is_ready()
    }
}
struct Random;
impl gnunet_crypto::Entropy for Random {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), gnunet_types::Error> {
        getrandom::fill(output).map_err(|_| gnunet_types::Error::EntropyUnavailable)
    }
}
fn observe(event: Event, reports: &Reporter, ready: &mut Option<[u8; 32]>) {
    match event {
        Event::Ready { peer } => {
            *ready = Some(peer);
            reports.debug(
                "dht.ready",
                format_args!("DHT original PILS identity and enabled underlays ready"),
            );
        }
        Event::Error { provider, cause } => reports.warning(
            "dht.source",
            format_args!("DHT original {provider:?}: {cause}"),
        ),
        Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(error))
            if error.is_emfile() => {}
        Event::Socket(event) => reports.debug("dht.socket", format_args!("DHT socket {event:?}")),
        Event::Send(fact) => {
            reports.debug("dht.send", format_args!("DHT original local send {fact:?}"))
        }
        Event::Closed => reports.debug(
            "dht.closed",
            format_args!("DHT original source returns drained"),
        ),
        Event::Activity(_) | Event::Client { .. } => {}
    }
}
fn stopped(
    signals: &mut Signals,
    reports: &Reporter,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    reports.register(cx);
    if reports.failed() {
        Poll::Ready(Ok(()))
    } else {
        signals.poll(cx)
    }
}
pub(super) async fn run(input: Inputs<'_>) -> Result<(), Cause> {
    let Inputs {
        config,
        settings,
        bound,
        parent,
        clock,
        reports,
        child,
        cleanup,
    } = input;
    let mut signals = Signals::new(parent)?;
    let already_stopped = poll_fn(|cx| {
        Poll::Ready(match stopped(&mut signals, &reports, cx) {
            Poll::Ready(r) => r.map(|()| true),
            Poll::Pending => Ok(false),
        })
    })
    .await?;
    if already_stopped {
        return Ok(());
    }
    let live = LiveConfiguration::new(config.duplicate()?);
    let source_clock: Arc<dyn RuntimeClock> = Arc::new(clock);
    let (context, driver) = broker::<128, 256>(
        live.clone(),
        settings.resolver,
        native_profile()?,
        source_clock.clone(),
    )?;
    let mut resolver = Resolver::new(driver, cleanup.clone());
    let source = |name: &'static [u8]| {
        EndpointSource::live(live.clone(), name, context.resolution_context())
    };
    let ports = Ports {
        core: source(b"core"),
        pils: source(b"pils"),
        nse: source(b"nse"),
        peerstore: source(b"peerstore"),
        transport: source(b"transport"),
        clock: source_clock,
        options: settings.options.clone(),
        unix: settings.access,
    };
    let mut instances = Instances::default();
    let mut server = Server::new(&mut instances, ports, settings.native, settings.blocks()?)?;
    let listeners = bound.listeners();
    let mut random = Random;
    let mut failures = Failures::default();
    let mut ready = None;
    let mut announced = false;
    let mut resolver_first = false;
    // No fallible post-Server exit escapes the actual same-owner finally below.
    let outcome: Result<(), Cause> = async {
        loop {
            enum Turn {
                Host(Result<Progress, HostError>),
                Resolver(gnunet_resolver_broker::BrokerError),
                Signal(io::Result<()>),
                Guard(HostError),
                Activity,
                Logger,
            }
            let turn = poll_fn(|cx| {
                reports.register(cx);
                if reports.failed() {
                    return Poll::Ready(Turn::Logger);
                }
                if let Poll::Ready(signal) = signals.poll(cx) {
                    return Poll::Ready(Turn::Signal(signal));
                }
                // These original hard guards cannot be hidden by a perpetually
                // ready Resolver or by canonical stabilization remaining Pending.
                match server.poll_native_guard(cx) {
                    Err(error) => return Poll::Ready(Turn::Guard(error)),
                    Ok(Some(event)) => {
                        observe(event, &reports, &mut ready);
                        return Poll::Ready(Turn::Activity);
                    }
                    Ok(None) => {}
                }
                for offset in 0..2 {
                    if reports.failed() {
                        return Poll::Ready(Turn::Logger);
                    }
                    let resolving = (offset == 0) == resolver_first;
                    if resolving {
                        match resolver.poll(cx, &reports) {
                            Poll::Ready(Err(error)) => return Poll::Ready(Turn::Resolver(error)),
                            Poll::Ready(Ok(_)) => {
                                resolver_first = false;
                                return Poll::Ready(Turn::Activity);
                            }
                            Poll::Pending => {}
                        }
                    } else {
                        match server.poll(cx, &listeners, None, &mut random, &mut |event| {
                            observe(event, &reports, &mut ready)
                        }) {
                            Poll::Ready(result) => {
                                resolver_first = true;
                                return Poll::Ready(Turn::Host(result));
                            }
                            Poll::Pending => {}
                        }
                    }
                }
                Poll::Pending
            })
            .await;
            match turn {
                Turn::Logger => {
                    failures.reason = Some(Reason::Logger);
                    break;
                }
                Turn::Signal(result) => {
                    failures.signal = result.err();
                    failures.reason = Some(Reason::Signal);
                    break;
                }
                Turn::Guard(error) | Turn::Host(Err(error)) => {
                    failures.running = Some(error);
                    failures.reason = Some(Reason::Failed);
                    break;
                }
                Turn::Resolver(error) => {
                    failures.resolver = Some(error);
                    failures.reason = Some(Reason::Failed);
                    break;
                }
                Turn::Host(Ok(Progress::Closed)) => {
                    failures.reason = Some(Reason::NativeClosed);
                    break;
                }
                Turn::Host(Ok(Progress::Ready | Progress::Activity)) | Turn::Activity => {}
            }
            if !announced && server.is_ready() {
                let stop = poll_fn(|cx| {
                    Poll::Ready(match stopped(&mut signals, &reports, cx) {
                        Poll::Ready(r) => r.map(|()| true),
                        Poll::Pending => Ok(false),
                    })
                })
                .await?;
                if stop {
                    failures.reason = Some(if reports.failed() {
                        Reason::Logger
                    } else {
                        Reason::Signal
                    });
                    break;
                }
                let peer = ready.ok_or("DHT readiness did not retain the actual identity event")?;
                {
                    let mut out = io::stdout().lock();
                    write!(out, "READY dht peer=")?;
                    for byte in peer {
                        write!(out, "{byte:02x}")?;
                    }
                    writeln!(
                        out,
                        " wire=0.29.1 listeners={} core-underlay={} ip-underlay={}",
                        listeners.len(),
                        settings.native.underlays.gnunet,
                        settings.native.underlays.ip.is_some()
                    )?;
                    out.flush()?;
                }
                // Parent notification follows successful complete actual stdout
                // flush and real native readiness; no fake provider ACK is used.
                child.ready()?;
                announced = true;
            }
        }
        Ok(())
    }
    .await;
    failures.original = outcome.err();
    // Capture once at the first cleanup transition, before physical close.
    let grace = Grace::new(settings.shutdown_grace);
    server.begin_close();
    let closing: Result<(), Cause> = async {
        let mut grace = grace?;
        let mut resolver_live = failures.resolver.is_none();
        while !server.is_closed() {
            enum End {
                Progress(Result<Progress, HostError>),
                Resolver(gnunet_resolver_broker::BrokerError),
                Signal(io::Result<()>),
                Expired,
                Activity,
            }
            let step = poll_fn(|cx| {
                if grace.guard(cx) {
                    return Poll::Ready(End::Expired);
                }
                reports.register(cx);
                if let Poll::Ready(signal) = signals.poll(cx) {
                    return Poll::Ready(End::Signal(signal));
                }
                // Even a permanently failed Logger or clock cannot suppress the
                // original clock-free local-return drain.
                match server.poll_close(cx, &mut |event| observe(event, &reports, &mut ready)) {
                    Poll::Ready(result) => return Poll::Ready(End::Progress(result)),
                    Poll::Pending => {}
                }
                if resolver_live && !reports.failed() {
                    match resolver.poll(cx, &reports) {
                        Poll::Ready(Err(error)) => return Poll::Ready(End::Resolver(error)),
                        Poll::Ready(Ok(_)) => return Poll::Ready(End::Activity),
                        Poll::Pending => {}
                    }
                }
                Poll::Pending
            })
            .await;
            match step {
                End::Expired => {
                    failures.timeout = true;
                    failures.reason = Some(Reason::Grace);
                    break;
                }
                End::Signal(result) => {
                    if let Err(error) = result
                        && failures.signal.is_none()
                    {
                        failures.signal = Some(error);
                    }
                    failures.reason = Some(Reason::SecondSignal);
                    break;
                }
                End::Resolver(error) => {
                    if failures.resolver.is_none() {
                        failures.resolver = Some(error);
                    }
                    resolver_live = false;
                }
                End::Progress(Err(error)) => {
                    if failures.cleanup.is_none() {
                        failures.cleanup = Some(error);
                    }
                    break;
                }
                End::Progress(Ok(Progress::Closed)) => break,
                End::Progress(Ok(_)) | End::Activity => {}
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = closing {
        if failures.original.is_none() {
            failures.original = Some(error);
        } else if failures.resolver_close.is_none() {
            failures.resolver_close = Some(error);
        }
    }
    failures.report = server.into_report();
    resolver.close();
    let resolver_close = cleanup.take_error();
    if failures.resolver_close.is_none() {
        failures.resolver_close = resolver_close;
    } else if let Some(error) = resolver_close {
        failures.original = Some(Box::new(Pair {
            original: failures.original.take(),
            independent: error,
        }));
    }
    {
        let mut out = io::stdout().lock();
        failures.output = writeln!(out, "STOPPED dht original={:?}", failures.report)
            .and_then(|()| out.flush())
            .err();
    }
    reports.debug(
        "dht.stopped",
        format_args!(
            "DHT actual report={:?}; reason={:?}",
            failures.report, failures.reason
        ),
    );
    failures.logging = reports.take_error();
    if failures.failed() {
        Err(Box::new(failures))
    } else {
        Ok(())
    }
}
#[derive(Debug)]
struct Pair {
    original: Option<Cause>,
    independent: Cause,
}
impl fmt::Display for Pair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DHT original={:?}; independent cleanup={}",
            self.original, self.independent
        )
    }
}
impl Error for Pair {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref().or(Some(self.independent.as_ref()))
    }
}
