//! Original communicator, statistics and Resolver owners through bounded shutdown.
use super::{Failure, failure::Failures, observation, reporting::Reports, settings::Settings};
use crate::{
    Progress, Runtime, Sources,
    frame_pool::FramePool,
    statistics::{self, StatisticsFactory},
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_program_host::policy::Level;
use gnunet_resolver_broker::Driver;
use gnunet_service_startup::{ParentControl, StopError, StopSignals};
use std::{
    cell::{Cell, RefCell},
    future::poll_fn,
    rc::Rc,
    task::Poll,
};
pub(super) async fn run_native<F: StatisticsFactory>(
    settings: Settings,
    parent: Option<ParentControl>,
    mut resolver: Driver<64, 256>,
    live: LiveConfiguration,
    resolution: gnunet_client_host::resolution::SharedResolution,
    reports: Rc<RefCell<Reports>>,
    stopping: Rc<Cell<bool>>,
) -> Result<(), Failure> {
    // This outer scope retains the real Resolver even on every constructor error.
    let result = async {
        if stopping.get() {
            return Ok(());
        }
        let mut signals = StopSignals::for_client(parent)?;
        if let Poll::Ready(stopped) = poll_fn(|cx| Poll::Ready(signals.poll_stop(cx))).await {
            return stopped.map_err(|error| Box::new(error) as Failure);
        }
        let mut statistics_storage = F::storage();
        let configured = settings.configured;
        let profile = configured.profile;
        let source =
            |name: &'static [u8]| EndpointSource::live(live.clone(), name, resolution.clone());
        let mut section = Vec::new();
        section.try_reserve_exact(profile.section().len())?;
        section.extend_from_slice(profile.section());
        let sources = Sources {
            transport: source(b"transport"),
            pils: source(b"pils"),
            nat: Some(crate::Nat {
                source: source(b"nat"),
                profiles: gnunet_nat_client_host::Profiles::same(
                    gnunet_nat_client_host::native_profile()?,
                ),
                section,
                addresses: configured.nat_addresses,
            }),
        };
        let statistics_clock = sources.transport.clock();
        let pool = FramePool::new(profile, configured.limits, configured.frame_pool_bytes)?;
        let (tls, directory_sync) = configured.prepare_tls()?;
        reports.borrow_mut().log(
            "quic.credentials.publication",
            Level::DEBUG,
            format_args!("TLS pair directory observations: {:?}", directory_sync),
        );
        if stopping.get() || reports.borrow().failed() {
            return Ok(());
        }
        if let Poll::Ready(stopped) = poll_fn(|cx| Poll::Ready(signals.poll_stop(cx))).await {
            return stopped.map_err(|error| Box::new(error) as Failure);
        }
        let bind = configured.bind.socket()?;
        pool.run(sources, bind, tls, Default::default(), async |runtime| {
            let statistics_config = statistics::Configuration {
                profile,
                live,
                resolution,
                clock: statistics_clock,
                initial: runtime.metrics(),
            };
            serve::<F>(
                runtime,
                &mut resolver,
                &mut signals,
                &reports,
                &stopping,
                &mut statistics_storage,
                statistics_config,
            )
            .await
        })
        .await
    }
    .await;
    let disconnect = resolver.disconnect().err().map(|e| Box::new(e) as Failure);
    Failures {
        original: result.err(),
        disconnect,
        ..Default::default()
    }
    .finish()
}
struct Turn {
    native: Option<Result<Progress, crate::Fault>>,
    signal: Option<Result<(), StopError>>,
    resolver: Option<Result<(), Failure>>,
}
async fn serve<F: StatisticsFactory>(
    runtime: &mut Runtime<'_, '_, '_, '_, '_>,
    resolver: &mut Driver<64, 256>,
    signals: &mut StopSignals,
    reports: &Rc<RefCell<Reports>>,
    stopping: &Cell<bool>,
    statistics_storage: &mut F::Storage,
    statistics_config: statistics::Configuration,
) -> Result<(), Failure> {
    let mut statistics = observation::create::<F>(statistics_storage, statistics_config);
    let mut failure = Failures::default();
    let mut resolver_failed = false;
    loop {
        let turn = {
            let mut resolving =
                std::pin::pin!(
                    resolver.drive_waiting(None, |event| reports.borrow_mut().log(
                        "quic.resolver.activity",
                        Level::DEBUG,
                        format_args!("Resolver: {event:?}")
                    ))
                );
            poll_fn(|cx| {
                let observed = statistics.guard(cx, stopping.get() || reports.borrow().failed());
                if stopping.get() || reports.borrow().failed() {
                    return Poll::Ready(Turn {
                        native: None,
                        signal: None,
                        resolver: None,
                    });
                }
                let native = match runtime.poll(cx, None, |event| reports.borrow_mut().event(event))
                {
                    Poll::Ready(result) => Some(result),
                    Poll::Pending => None,
                };
                if reports.borrow().failed()
                    || matches!(&native, Some(Err(_)) | Some(Ok(Progress::Stopped)))
                {
                    statistics.abort();
                    return Poll::Ready(Turn {
                        native,
                        signal: None,
                        resolver: None,
                    });
                }
                let signal = match signals.poll_stop(cx) {
                    Poll::Ready(result) => Some(result),
                    Poll::Pending => None,
                };
                if signal.is_some() || stopping.get() || reports.borrow().failed() {
                    return Poll::Ready(Turn {
                        native,
                        signal,
                        resolver: None,
                    });
                }
                statistics.refresh(runtime.metrics());
                let observed = statistics.poll(cx, reports.borrow().failed()) || observed;
                if reports.borrow().failed() {
                    statistics.abort();
                    return Poll::Ready(Turn {
                        native,
                        signal,
                        resolver: None,
                    });
                }
                let resolved = match resolving.as_mut().poll(cx) {
                    Poll::Ready(result) => Some(
                        result
                            .map(|_| ())
                            .map_err(|error| Box::new(error) as Failure),
                    ),
                    Poll::Pending => None,
                };
                if reports.borrow().failed() {
                    statistics.abort();
                }
                if native.is_some()
                    || signal.is_some()
                    || resolved.is_some()
                    || observed
                    || reports.borrow().failed()
                {
                    Poll::Ready(Turn {
                        native,
                        signal,
                        resolver: resolved,
                    })
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        if let Some(Err(error)) = turn.resolver {
            failure.resolver = Some(error);
            resolver_failed = true;
        }
        let stopped = match turn.native {
            Some(Err(error)) => {
                failure.original = Some(error.into());
                true
            }
            Some(Ok(Progress::Stopped)) => true,
            _ => false,
        };
        let signaled = match turn.signal {
            Some(Err(error)) => {
                failure.signal = Some(error);
                true
            }
            Some(Ok(())) => true,
            None => false,
        };
        if stopped || signaled || resolver_failed || reports.borrow().failed() || stopping.get() {
            break;
        }
        tokio::task::yield_now().await;
    }
    let abort_observation = failure.original.is_some()
        || failure.signal.is_some()
        || resolver_failed
        || reports.borrow().failed()
        || stopping.get();
    if abort_observation {
        statistics.abort();
    }
    // Keep the SAME original Runtime, caller slabs and first native close grace.
    runtime.begin_close(|event| reports.borrow_mut().event(event));
    let closed = {
        let mut shutting =
            std::pin::pin!(runtime.shutdown(|event| reports.borrow_mut().event(event)));
        loop {
            let mut resolving =
                std::pin::pin!(
                    resolver.drive_waiting(None, |event| reports.borrow_mut().log(
                        "quic.resolver.cleanup",
                        Level::DEBUG,
                        format_args!("Resolver cleanup: {event:?}")
                    ))
                );
            let (closed, resolved) = poll_fn(|cx| {
                statistics.guard(cx, abort_observation || reports.borrow().failed());
                let closed = match shutting.as_mut().poll(cx) {
                    Poll::Ready(closed) => Some(closed),
                    Poll::Pending => None,
                };
                if reports.borrow().failed() {
                    statistics.abort();
                }
                if closed.is_some() {
                    return Poll::Ready((closed, None));
                }
                let changed = statistics.poll(cx, abort_observation || reports.borrow().failed());
                let resolved = if resolver_failed || reports.borrow().failed() {
                    None
                } else {
                    match resolving.as_mut().poll(cx) {
                        Poll::Ready(result) => Some(
                            result
                                .map(|_| ())
                                .map_err(|error| Box::new(error) as Failure),
                        ),
                        Poll::Pending => None,
                    }
                };
                if reports.borrow().failed() {
                    statistics.abort();
                }
                if resolved.is_some() || changed {
                    Poll::Ready((None, resolved))
                } else {
                    Poll::Pending
                }
            })
            .await;
            if let Some(Err(error)) = resolved {
                failure.resolver = Some(error);
                resolver_failed = true;
                statistics.abort();
            }
            if let Some(closed) = closed {
                break closed;
            }
            tokio::task::yield_now().await;
        }
    };
    // The real shutdown took/dropped original rows and returned their slab loans.
    // Count that actual inventory; never infer zero from an error or logger text.
    let final_metrics = runtime.metrics();
    if abort_observation || closed.cleanup.is_some() || resolver_failed || reports.borrow().failed()
    {
        statistics.abort();
    } else {
        statistics.begin_close(final_metrics);
    }
    while !statistics.closed() {
        let mut resolving =
            std::pin::pin!(
                resolver.drive_waiting(None, |event| reports.borrow_mut().log(
                    "quic.resolver.statistics",
                    Level::DEBUG,
                    format_args!("Resolver statistics retirement: {event:?}")
                ))
            );
        let resolved = poll_fn(|cx| {
            statistics.guard(cx, reports.borrow().failed());
            if statistics.closed() {
                return Poll::Ready(None);
            }
            let changed = statistics.poll(cx, reports.borrow().failed());
            if reports.borrow().failed() {
                statistics.abort();
            }
            if statistics.closed() {
                return Poll::Ready(None);
            }
            let resolved = if resolver_failed || reports.borrow().failed() {
                None
            } else {
                match resolving.as_mut().poll(cx) {
                    Poll::Ready(result) => Some(
                        result
                            .map(|_| ())
                            .map_err(|error| Box::new(error) as Failure),
                    ),
                    Poll::Pending => None,
                }
            };
            if reports.borrow().failed() {
                statistics.abort();
            }
            if changed || resolved.is_some() || statistics.closed() {
                Poll::Ready(resolved)
            } else {
                Poll::Pending
            }
        })
        .await;
        if let Some(Err(error)) = resolved {
            failure.resolver = Some(error);
            resolver_failed = true;
            statistics.abort();
        }
        tokio::task::yield_now().await;
    }
    let report = statistics.report();
    reports
        .borrow_mut()
        .stopped(&closed, final_metrics, report.as_ref());
    statistics.finish(failure.finish(), closed, final_metrics)
}
