//! Same-clock GNS IPC, native dependency owners and unconditional retirement.
mod diagnostics;
use crate::{
    Cause,
    control::Signals,
    lifecycle::{Cleanup, Resolver},
    settings::Settings,
};
use diagnostics::{Failure, Observations, observe};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_config::Configuration;
use gnunet_gns_service_host::{
    self as host, Manager,
    auxiliary::{self, registry, system},
    native,
    server::{self, Event, Server},
};
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::{broker, native_profile};
use gnunet_service_runtime::{BoundListeners, clock::RuntimeClock, service::ShutdownMode};
use gnunet_service_startup::ControlReceiver;
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

struct Timer {
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
}
impl Timer {
    fn new(duration: Duration) -> Result<Self, Cause> {
        let hard = Instant::now()
            .checked_add(duration)
            .ok_or("GNS native target overflow")?;
        Ok(Self {
            hard,
            alarm: Box::pin(tokio::time::sleep_until(hard)),
        })
    }
    fn expired(&mut self, cx: &mut Context<'_>) -> bool {
        Instant::now() >= self.hard || self.alarm.as_mut().poll(cx).is_ready()
    }
}
pub(super) struct Inputs<'a> {
    pub config: &'a Configuration,
    pub settings: &'a Settings,
    pub bound: &'a BoundListeners,
    pub parent: Option<ControlReceiver>,
    pub clock: SharedClock,
    pub reports: Reporter,
    pub cleanup: Cleanup,
}
pub(super) async fn run(
    input: Inputs<'_>,
    notify_ready: impl Future<Output = Result<(), Cause>>,
) -> Result<(), Cause> {
    let Inputs {
        config,
        settings,
        bound,
        parent,
        clock,
        reports,
        cleanup,
    } = input;
    let mut signals = Signals::new(parent)?;
    let pre_stopped = poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Ok(true));
        }
        Poll::Ready(match signals.poll_stop(cx) {
            Poll::Ready(result) => result.map(|()| true),
            Poll::Pending => Ok(false),
        })
    })
    .await?;
    if pre_stopped {
        return Ok(());
    }
    // Prepare any explicit registry files before starting live MQ work.
    let mut observations = Observations::default();
    let files_registry = (settings.protocols.is_some() || settings.services.is_some()).then(|| {
        registry::Files::from_paths(
            settings.protocols.as_deref(),
            settings.services.as_deref(),
            settings.registry,
        )
        .map_err(Arc::new)
    });
    let source_clock: Arc<dyn RuntimeClock> = Arc::new(clock);
    let (dns, nameserver_lookup) = settings.dns(source_clock.clone())?;
    let stopped = poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Ok(true));
        }
        Poll::Ready(match signals.poll_stop(cx) {
            Poll::Ready(result) => result.map(|()| true),
            Poll::Pending => Ok(false),
        })
    })
    .await?;
    if stopped {
        return Ok(());
    }
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, driver) = broker::<128, 256>(
        live.clone(),
        settings.resolver,
        native_profile()?,
        source_clock.clone(),
    )?;
    let mut resolver = Resolver::new(driver, cleanup);
    let resolution = context.resolution_context();
    let interception_source = settings
        .interception
        .map(|_| EndpointSource::live(live.clone(), b"dns", resolution.clone()));
    let sources = native::Sources {
        namecache: EndpointSource::live(live.clone(), b"namecache", resolution.clone()),
        revocation: EndpointSource::live(live.clone(), b"revocation", resolution.clone()),
        dht: EndpointSource::live(live, b"dht", resolution),
    };
    let system = system::Factory::new(context, source_clock.clone(), settings.system)?;
    let auxiliary = match files_registry {
        Some(files) => auxiliary::Auxiliary::with_registry(system, dns, files)?,
        None => auxiliary::Auxiliary::with_system_registry(system, dns)?,
    }
    .with_nameserver_lookup(nameserver_lookup);
    if let Some(error) = auxiliary.registry_preparation_error() {
        observations.initial_registry = Some(Arc::clone(error));
        reports.warning(
            "gns.registry.unavailable",
            format_args!("GNS protocol and service registry unavailable ({error})"),
        );
    }
    let mut domains = native::Domains::new();
    let provider = native::NativeProvider::new(
        &mut domains,
        sources,
        source_clock.clone(),
        settings.native,
        auxiliary,
    )
    .map_err(native::Error::into_owned)?;
    let mut instance = host::Instance::new();
    let mut manager =
        Manager::new_with_refresh(&mut instance, provider, settings.core, settings.refresh)?;
    let mut frontend = server::Instance::new();
    let mut server = Server::new(
        &mut frontend,
        &mut manager,
        source_clock,
        settings.options.clone(),
        settings.access,
        settings.frontend,
    )?;
    if let (Some(source), Some(limits)) = (interception_source, settings.interception) {
        server.enable_interception(source, config.duplicate()?, limits)?;
    }
    let listeners = bound.listeners();
    let mut failure = Failure {
        observations,
        ..Failure::default()
    };
    let mut recover: Option<Timer> = None;
    let mut resolver_backoff: Option<Timer> = None;
    let mut grace: Option<Timer> = None;
    let mut cursor = false;
    let mut stopping = false;
    let outcome: Result<(), Cause> = async {
        let stopped = poll_fn(|cx| {
            reports.register(cx);
            if reports.failed() {
                return Poll::Ready(Ok(true));
            }
            Poll::Ready(match signals.poll_stop(cx) {
                Poll::Ready(r) => r.map(|()| true),
                Poll::Pending => Ok(false),
            })
        })
        .await?;
        if stopped {
            return Ok(());
        }
        {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "READY gns wire=0.29.1 listeners=bound dependency-clients=configured"
            )?;
            out.flush()?;
        }
        gnunet_program_host::service::acknowledge_ready(
            notify_ready,
            &mut signals,
            &reports,
            settings.shutdown_grace,
        )
        .await?;
        loop {
            enum Turn {
                Activity,
                Stop,
                Expired,
                Stopped,
                Failed,
            }
            let turn = poll_fn(|cx| -> Poll<Result<Turn, Cause>> {
                if grace.as_mut().is_some_and(|g| g.expired(cx)) {
                    return Poll::Ready(Ok(Turn::Expired));
                }
                reports.register(cx);
                if reports.failed() {
                    return Poll::Ready(Ok(Turn::Stop));
                }
                if let Poll::Ready(result) = signals.poll_stop(cx) {
                    match result {
                        Ok(()) => {}
                        Err(error) => failure.signal = Some(error),
                    }
                    return Poll::Ready(Ok(Turn::Stop));
                }
                // Native source/query guards precede any canonical-capability use.
                if let Some(event) = server.poll_native_guard(cx)? {
                    let stopped = matches!(event, Event::Stopped);
                    if observe(event, &reports, &mut failure.observations)
                        && !stopping
                        && recover.is_none()
                    {
                        recover = Some(Timer::new(Duration::from_secs(1))?);
                    }
                    return Poll::Ready(Ok(if stopped {
                        Turn::Stopped
                    } else {
                        Turn::Activity
                    }));
                }
                if recover.as_mut().is_some_and(|timer| timer.expired(cx)) {
                    recover = None;
                    if let Err(error) = server.recover_clock() {
                        failure.observations.frontend(error, &reports);
                        recover = Some(Timer::new(Duration::from_secs(1))?);
                    }
                    if !reports.failed()
                        && let Err(error) = server.provider_mut().recover_cache_ports()
                    {
                        failure.observations.native(error, &reports);
                        recover = Some(Timer::new(Duration::from_secs(1))?);
                    }
                    if !reports.failed()
                        && let Err(error) = server.provider_mut().recover_dht_ports()
                    {
                        failure.observations.native(error, &reports);
                        recover = Some(Timer::new(Duration::from_secs(1))?);
                    }
                    return Poll::Ready(Ok(Turn::Activity));
                }
                let mut activity = false;
                for offset in 0..2 {
                    if reports.failed() {
                        return Poll::Ready(Ok(Turn::Stop));
                    }
                    if grace.as_mut().is_some_and(|g| g.expired(cx)) {
                        return Poll::Ready(Ok(Turn::Expired));
                    }
                    if (usize::from(cursor) + offset) % 2 == 0 {
                        if resolver_backoff
                            .as_mut()
                            .is_some_and(|timer| !timer.expired(cx))
                        {
                            continue;
                        }
                        resolver_backoff = None;
                        match resolver.poll(cx, &reports) {
                            Poll::Pending => {}
                            Poll::Ready(Ok(_)) => activity = true,
                            Poll::Ready(Err(error)) => {
                                reports.warning(
                                    "gns.resolver.failed",
                                    format_args!(
                                        "GNS shared Resolver remains the original owner: {error}"
                                    ),
                                );
                                failure.observations.resolver_errors =
                                    failure.observations.resolver_errors.saturating_add(1);
                                if failure.observations.first_resolver.is_none() {
                                    failure.observations.first_resolver = Some(error)
                                }
                                resolver_backoff = Some(Timer::new(Duration::from_secs(1))?);
                                if !stopping {
                                    recover = Some(Timer::new(Duration::from_secs(1))?);
                                }
                                activity = true;
                            }
                        }
                    } else if let Poll::Ready(result) = server.poll(cx, &listeners) {
                        match result {
                            Ok(event) => {
                                let stopped = matches!(event, Event::Stopped);
                                if observe(event, &reports, &mut failure.observations)
                                    && !stopping
                                    && recover.is_none()
                                {
                                    recover = Some(Timer::new(Duration::from_secs(1))?);
                                }
                                if stopped {
                                    return Poll::Ready(Ok(Turn::Stopped));
                                }
                                activity = true;
                            }
                            Err(error) => {
                                failure.running = Some(error);
                                return Poll::Ready(Ok(Turn::Failed));
                            }
                        }
                    }
                }
                if activity {
                    Poll::Ready(Ok(Turn::Activity))
                } else {
                    Poll::Pending
                }
            })
            .await?;
            cursor = !cursor;
            match turn {
                Turn::Activity => tokio::task::yield_now().await,
                Turn::Stopped | Turn::Failed => break,
                Turn::Expired => {
                    server.force_stop();
                    break;
                }
                Turn::Stop => {
                    stopping = true;
                    recover = None;
                    if !reports.failed()
                        && failure.signal.is_none()
                        && grace.is_none()
                        && settings.options.shutdown == ShutdownMode::Soft
                    {
                        grace = Some(Timer::new(settings.shutdown_grace)?);
                        server.request_stop(ShutdownMode::Soft);
                    } else {
                        server.force_stop();
                        break;
                    }
                }
            }
        }
        Ok(())
    }
    .await;
    failure.original = outcome.err();
    // No post-Server error path bypasses retirement. No fresh query/provider is
    // admitted here; original operation/native deadlines remain unchanged.
    server.force_stop();
    while !failure.observations.local_closed {
        let result = poll_fn(|cx| {
            if let Some(event) = server.poll_native_guard(cx)? {
                return Poll::Ready(Ok(event));
            }
            reports.register(cx);
            match server.poll(cx, &[]) {
                Poll::Ready(result) => Poll::Ready(result),
                Poll::Pending => {
                    // Only the still-original Driver's retained debts are driven.
                    // A failed logger gates all further Resolver/native admissions.
                    if !reports.failed() {
                        let ready = resolver_backoff
                            .as_mut()
                            .is_none_or(|timer| timer.expired(cx));
                        if ready {
                            match resolver.poll(cx, &reports) {
                                Poll::Ready(Err(error)) => {
                                    failure.observations.resolver_errors =
                                        failure.observations.resolver_errors.saturating_add(1);
                                    if failure.observations.first_resolver.is_none() {
                                        failure.observations.first_resolver = Some(error)
                                    }
                                    resolver_backoff =
                                        Some(Timer::new(Duration::from_secs(1)).map_err(|_| {
                                            server::Error::Protocol(Fault::Overflow)
                                        })?);
                                    cx.waker().wake_by_ref();
                                }
                                Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                                Poll::Pending => {}
                            }
                        }
                    }
                    Poll::Pending
                }
            }
        })
        .await;
        match result {
            Ok(event) => {
                observe(event, &reports, &mut failure.observations);
            }
            Err(error) => {
                failure.cleanup_errors = failure.cleanup_errors.saturating_add(1);
                if failure.cleanup.is_none() {
                    failure.cleanup = Some(error)
                }
                // All original hard guards still execute on the next turn. This is
                // bounded by existing operation bounds, never a renewed grace.
                tokio::task::yield_now().await;
            }
        }
    }
    failure.observations.provider = Some(server.manager().provider().report().into_owned());
    failure.observations.refresh = Some(server.manager().refresh_stats());
    drop(server);
    resolver.close();
    failure.output = {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "STOPPED gns local-operations-closed={} shared-provider={:?} optional-refresh={:?}",
            failure.observations.local_closed,
            failure.observations.provider,
            failure.observations.refresh
        )
        .and_then(|()| out.flush())
        .err()
    };
    reports.debug(
        "gns.stopped",
        format_args!("GNS actual retirement {:?}", failure.observations),
    );
    failure.logging = reports.take_error();
    if failure.failed() {
        Err(Box::new(failure))
    } else {
        Ok(())
    }
}
