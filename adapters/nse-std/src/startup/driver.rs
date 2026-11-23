//! Caller-driven NSE, Resolver and statistics lifetime with one readiness phase.
use super::{
    AdmissionFailure, LocalEndpoints, Report,
    embedded::settings as embedded_settings,
    reporting::{ForegroundFailures, StatisticsErrors, abort_statistics},
    settings, unix_access,
};
use crate::{
    Host, Instances, Limits, Ports, Progress, histogram, proof,
    statistics::{Statistics, StatisticsFactory},
};
use gnunet_client_host::EndpointSource;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_nse::owner;
use gnunet_resolver_broker::{LiveConfiguration, broker};
use gnunet_service_runtime::{
    BoundListeners, accepted::SocketEvent, clock::RuntimeClock, service::ShutdownMode,
    service_options,
};
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    sync::Arc,
    task::Poll,
    time::Duration,
};
pub(super) fn poll_ports<H, R>(
    cx: &mut std::task::Context<'_>,
    mut driving: std::pin::Pin<&mut H>,
    mut resolving: std::pin::Pin<&mut R>,
) -> Poll<Result<Option<Progress>, Box<dyn Error>>>
where
    H: Future<Output = Result<Progress, crate::Error>>,
    R: Future<
        Output = Result<gnunet_resolver_broker::Progress, gnunet_resolver_broker::BrokerError>,
    >,
{
    // Give the process Resolver one bounded poll even when work/notifications
    // keep the Host ready. Resolver completion starts a new turn after polling
    // the Host; original errors retain their actual cause.
    let resolver_progress = if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
        match result {
            Ok(_) => true,
            Err(error) => return Poll::Ready(Err(Box::new(error) as Box<dyn Error>)),
        }
    } else {
        false
    };
    if let Poll::Ready(result) = driving.as_mut().poll(cx) {
        return Poll::Ready(result.map(Some).map_err(|e| Box::new(e) as Box<dyn Error>));
    }
    // The Host still gets its bounded poll when Resolver work completes. Return
    // to the owner loop so that it replaces the completed Resolver future.
    if resolver_progress {
        Poll::Ready(Ok(Some(Progress::Activity)))
    } else {
        Poll::Pending
    }
}
pub(super) enum Sources<'a> {
    Configured,
    Embedded {
        endpoints: &'a LocalEndpoints,
        proof_file: PathBuf,
    },
}

pub(super) struct Foreground<'a> {
    pub(super) config: &'a Configuration,
    pub(super) bound: &'a BoundListeners,
    pub(super) limits: Limits,
    pub(super) clock: Arc<dyn RuntimeClock>,
    pub(super) sources: Sources<'a>,
}

#[expect(
    clippy::too_many_arguments,
    reason = "Original readiness, cancellation, diagnostics and publisher stay independently owned"
)]
pub(super) async fn run_foreground<F: StatisticsFactory>(
    input: Foreground<'_>,
    mut ready: impl FnMut(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    mut observe: impl FnMut(SocketEvent),
    mut diagnostic: impl FnMut(AdmissionFailure) -> Result<(), Box<dyn Error>>,
    diagnostic_failed: impl Fn() -> bool,
    statistics_factory: F,
    notification: Option<impl Future<Output = Result<(), Box<dyn Error>>>>,
) -> Result<Report<F::Report>, Box<dyn Error>> {
    let Foreground {
        config,
        bound,
        limits,
        clock,
        sources,
    } = input;
    let embedded = matches!(&sources, Sources::Embedded { .. });
    let mut shutdown = std::pin::pin!(shutdown);
    if embedded
        && let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await
    {
        result?;
        return Ok(Report::default());
    }
    let unix = unix_access(config)?;
    let options = service_options(config, b"NSE", ShutdownMode::Immediate)?;
    let (settings, proof_file, core, pils, process) = match sources {
        Sources::Configured => {
            let settings = settings(config)?;
            let proof_file = config.get_filename(b"NSE", b"PROOFFILE", &ProcessEnvironment)?;
            let family = gnunet_resolver_broker::native_profile()?;
            let live = LiveConfiguration::new(config.duplicate()?);
            let (context, resolver) =
                broker::<128, 256>(live.clone(), Default::default(), family, clock.clone())?;
            let core = EndpointSource::live(live.clone(), b"core", context.resolution_context());
            let pils = EndpointSource::live(live.clone(), b"pils", context.resolution_context());
            (
                settings,
                proof_file,
                core,
                pils,
                Some((live, context, resolver)),
            )
        }
        Sources::Embedded {
            endpoints,
            proof_file,
        } => {
            let settings = embedded_settings(config)?;
            let core = EndpointSource::unix_with_clock(endpoints.core.clone(), clock.clone());
            let pils = EndpointSource::unix_with_clock(endpoints.pils.clone(), clock.clone());
            (settings, proof_file, core, pils, None)
        }
    };
    let store = proof::Store::open(proof_file)?;
    let mut nse_instance = owner::Instance::new();
    let mut core_instance = gnunet_core_client_host::Instance::new();
    let mut pils_instance = gnunet_pils::client::Instance::new();
    let mut host = Host::<64, 32>::new_with_access(
        Instances {
            nse: &mut nse_instance,
            core: &mut core_instance,
            pils: &mut pils_instance,
        },
        Ports {
            core,
            pils,
            clock: clock.clone(),
        },
        settings,
        limits,
        options,
        unix,
        store,
    )?;
    let mut histogram_report = match (!embedded)
        .then(|| histogram::Recorder::configured(config))
        .flatten()
    {
        Some(Ok(recorder)) => {
            host.histogram = Some(recorder);
            None
        }
        Some(Err(error)) => Some(histogram::Report::refused(error)),
        None => None,
    };
    let mut statistics_errors = StatisticsErrors::default();
    let statistics_grace = Duration::from_secs(5);
    // The caller constructs the concrete publisher on these actual same
    // process sources; the NSE host has no native statistics dependency.
    let (mut resolver, mut statistics) = match process {
        Some((live, context, resolver)) => {
            let statistics = match statistics_factory.create(
                live,
                context.resolution_context(),
                clock,
                host.metrics(),
            ) {
                Ok(publisher) => publisher,
                Err(error) => {
                    statistics_errors.record(error);
                    None
                }
            };
            (Some(resolver), statistics)
        }
        None => (None, None),
    };
    let listeners = bound.listeners();
    let mut notification = std::pin::pin!(notification);
    let mut announced = false;
    let outcome = loop {
        // Refresh observes real domain coordinates only; it performs no new IO
        // and never extends an already admitted original mutation/hard target.
        if diagnostic_failed() {
            abort_statistics(&mut statistics, &mut statistics_errors);
            break Ok(());
        }
        let observed = statistics.as_ref().map(|_| host.metrics());
        let selected = {
            let active_listeners = if !embedded || announced {
                listeners.as_slice()
            } else {
                &[]
            };
            let mut driving = std::pin::pin!(host.drive(active_listeners, &mut observe, None));
            let mut resolving = std::pin::pin!(async {
                match resolver.as_mut() {
                    Some(resolver) => resolver.drive_waiting(None, |_| {}).await,
                    None => std::future::pending().await,
                }
            });
            poll_fn(|cx| {
                // No canonical wait/IO precedes this original native guard.
                if let Some(publisher) = statistics.as_mut()
                    && !publisher.is_closed()
                    && let Poll::Ready(Err(error)) = publisher.poll_native_guard(cx)
                {
                    statistics_errors.record(error);
                }
                if diagnostic_failed() {
                    abort_statistics(&mut statistics, &mut statistics_errors);
                    return Poll::Ready(Ok(None));
                }
                if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
                    return Poll::Ready(
                        result
                            .map(|()| None)
                            .map_err(|e| Box::new(e) as Box<dyn Error>),
                    );
                }
                if let Some(publisher) = statistics.as_mut()
                    && !publisher.is_closed()
                    && let Some(observed) = observed
                    && let Err(error) = publisher.refresh(observed)
                {
                    statistics_errors.record(error);
                }
                // Give the bounded original publisher a turn even when NSE's
                // proof/round/notification work remains ready. Failure fences
                // this publisher; it does not change NSE history or stop peers.
                let mut stats_progress = false;
                if let Some(publisher) = statistics.as_mut()
                    && !publisher.is_closed()
                {
                    match publisher.poll(cx) {
                        Poll::Ready(Err(error)) => {
                            statistics_errors.record(error);
                            stats_progress = true;
                        }
                        Poll::Ready(Ok(_)) => stats_progress = true,
                        Poll::Pending => {}
                    }
                }
                if diagnostic_failed() {
                    abort_statistics(&mut statistics, &mut statistics_errors);
                    return Poll::Ready(Ok(None));
                }
                let result = poll_ports(cx, driving.as_mut(), resolving.as_mut());
                // The host observer may have failed during this exact poll.
                // Preserve an actual owned admission/error cause before the
                // stop gate, but never run a later class or Ready callback.
                if diagnostic_failed() {
                    abort_statistics(&mut statistics, &mut statistics_errors);
                    return match result {
                        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        Poll::Ready(Ok(Some(Progress::AdmissionFailed { error, .. }))) => {
                            Poll::Ready(Err(Box::new(error) as Box<dyn Error>))
                        }
                        _ => Poll::Ready(Ok(None)),
                    };
                }
                match result {
                    Poll::Pending if stats_progress => Poll::Ready(Ok(Some(Progress::Activity))),
                    other => other,
                }
            })
            .await
        };
        match selected {
            Ok(None) => break Ok(()),
            Ok(Some(Progress::Activated(peer))) => {
                if embedded
                    && let Poll::Ready(result) =
                        poll_fn(|cx| Poll::Ready(shutdown.as_mut().poll(cx))).await
                {
                    break result.map_err(Into::into);
                }
                if let Err(error) = ready(bound, peer) {
                    break Err(Box::new(error) as Box<dyn Error>);
                }
                announced = true;
                if let Some(mut original) = notification.as_mut().as_pin_mut() {
                    let Some(deadline) =
                        tokio::time::Instant::now().checked_add(Duration::from_secs(10))
                    else {
                        break Err(
                            Box::new(io::Error::other("NSE readiness deadline overflow"))
                                as Box<dyn Error>,
                        );
                    };
                    let mut alarm = std::pin::pin!(tokio::time::sleep_until(deadline));
                    let acknowledged = poll_fn(|cx| {
                        if diagnostic_failed() {
                            return Poll::Ready(Err(Box::new(io::Error::other(
                                "NSE diagnostic failed during readiness",
                            ))
                                as Box<dyn Error>));
                        }
                        if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
                            let cause = match result {
                                Ok(()) => io::Error::new(
                                    io::ErrorKind::Interrupted,
                                    "NSE stopped before readiness acknowledgement",
                                ),
                                Err(cause) => cause,
                            };
                            return Poll::Ready(Err(Box::new(cause) as Box<dyn Error>));
                        }
                        if alarm.as_mut().poll(cx).is_ready() {
                            return Poll::Ready(Err(Box::new(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "NSE readiness acknowledgement deadline",
                            ))
                                as Box<dyn Error>));
                        }
                        original.as_mut().poll(cx)
                    })
                    .await;
                    if let Err(error) = acknowledged {
                        break Err(error);
                    }
                    notification.set(None);
                }
            }
            Ok(Some(Progress::AdmissionFailed { peer, error })) => {
                if let Err(output) = diagnostic(AdmissionFailure { peer, error }) {
                    break Err(output);
                }
            }
            Ok(Some(Progress::Closed)) => break Ok(()),
            Ok(Some(Progress::BackendQuiescent)) => {
                break Err("NSE proof backend requires explicit recovery".into());
            }
            Ok(Some(_)) => {}
            Err(error) => break Err(error),
        }
    };
    // Close original physical CORE/PILS/subscribers and perform their exact
    // proof flush before reading final metrics. No ? can bypass another owner.
    let histogram_drain = host.histogram.take().map(histogram::Recorder::stop);
    let closed = host.close();
    let host_report = host.report();
    let final_metrics = host.metrics();
    let mut resolver_drain = None;
    if outcome.is_err() || closed.is_err() || diagnostic_failed() {
        abort_statistics(&mut statistics, &mut statistics_errors);
    } else if let Some(publisher) = statistics.as_mut()
        && !publisher.is_closed()
    {
        if let Err(error) = publisher.begin_close(final_metrics, statistics_grace) {
            statistics_errors.record(error);
        }
        // Producer retains its own original final hard and all partial cursors.
        // A canceled wait below does not replace/retry an admitted mutation.
        poll_fn(|cx| {
            if let Some(publisher) = statistics.as_mut()
                && !publisher.is_closed()
                && let Poll::Ready(Err(error)) = publisher.poll_native_guard(cx)
            {
                statistics_errors.record(error);
            }
            if diagnostic_failed() {
                abort_statistics(&mut statistics, &mut statistics_errors);
            }
            if statistics.as_ref().is_none_or(Statistics::is_closed) {
                return Poll::Ready(());
            }
            let mut changed = false;
            if let Some(publisher) = statistics.as_mut() {
                match publisher.poll(cx) {
                    Poll::Ready(Err(error)) => {
                        statistics_errors.record(error);
                        changed = true;
                    }
                    Poll::Ready(Ok(_)) => changed = true,
                    Poll::Pending => {}
                }
            }
            if diagnostic_failed() {
                abort_statistics(&mut statistics, &mut statistics_errors);
            }
            if statistics.as_ref().is_none_or(Statistics::is_closed) {
                return Poll::Ready(());
            }
            // End the original drive borrow before any abort or disconnect.
            let result = if let Some(resolver) = resolver.as_mut() {
                let mut resolving = std::pin::pin!(resolver.drive_waiting(None, |_| {}));
                resolving.as_mut().poll(cx)
            } else {
                Poll::Pending
            };
            match result {
                Poll::Ready(Err(error)) => {
                    resolver_drain = Some(error);
                    abort_statistics(&mut statistics, &mut statistics_errors);
                }
                Poll::Ready(Ok(_)) => changed = true,
                Poll::Pending => {}
            }
            if diagnostic_failed() {
                abort_statistics(&mut statistics, &mut statistics_errors);
            }
            if changed {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await;
    }
    abort_statistics(&mut statistics, &mut statistics_errors);
    let statistics_report = statistics.as_ref().map(Statistics::report);
    drop(statistics);
    let (resolver_close, resolver_io, resolver_connect) = match resolver {
        Some(mut resolver) => (
            resolver.disconnect().err(),
            resolver.take_io_error(),
            resolver.take_connect_error(),
        ),
        None => (None, None, None),
    };
    if let Some(drain) = histogram_drain {
        histogram_report = Some(drain.finish().await);
    }
    let report = Report {
        host: host_report,
        statistics: statistics_report,
        histogram: histogram_report,
    };
    let failures = ForegroundFailures {
        original: outcome.err(),
        host_close: closed.err(),
        statistics: statistics_errors.first,
        statistics_cleanup: statistics_errors.cleanup,
        resolver_drain,
        resolver_close,
        resolver_io,
        resolver_connect,
        report,
    };
    failures.finish()
}
