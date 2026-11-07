//! One fresh native allocation session. Healthy PID changes rotate Engine inside
//! Owner and retain the actual PILS source. A genuine unusable native source
//! returns only after every old physical owner and public stamp has retired.
use crate::{
    Failure, Failures,
    foreground::{Entropy, Signals},
    generation::Reservations,
    owner::{self, Owner, Sources},
    settings::Settings,
    statistics::Publisher,
    time::Clock,
};
use gnunet_service_runtime::service::Listener;
use std::{
    future::{Future, poll_fn},
    task::Poll,
};
use tokio::time::Instant;
/// Actual source-session exit, carrying no native token into a replacement.
pub(crate) enum End {
    /// Original process shutdown request; no replacement source is admitted.
    Stopped {
        failures: Vec<Failure>,
        foreign_failures: u64,
    },
    /// A failed native source was physically stopped. Future caller requests
    /// may use fresh brands after supervisor backoff; old requests never replay.
    Restart {
        failure: Failure,
        foreign_failures: u64,
        stable: bool,
    },
    /// Actual failure cannot safely authorize a new source/session.
    Failed {
        failure: Failure,
        foreign_failures: u64,
    },
}
/// Shared process ports; no listener, Resolver, clock or worker is replaced here.
pub(crate) struct Inputs<'a, 'listen, 'stats> {
    pub sources: &'a Sources,
    pub settings: &'a Settings,
    pub listeners: &'a [Listener<'listen>],
    pub resolver: &'a mut gnunet_resolver_broker::Driver<64, 1024>,
    pub clock: Clock,
    pub generation: &'a mut Reservations,
    pub signals: &'a mut Signals,
    pub statistics: &'a mut Publisher<'stats>,
    pub foreign_base: u64,
}
/// A new set of actual allocation brands is created for this call and cannot
/// escape through End. All callbacks are consumed while their brands still live.
pub(crate) async fn run(input: Inputs<'_, '_, '_>) -> End {
    let Inputs {
        sources,
        settings,
        listeners,
        resolver,
        clock,
        generation,
        signals,
        statistics,
        foreign_base,
    } = input;
    let started = Instant::now();
    let mut pils_id = gnunet_pils::client::Instance::new();
    let mut validated_id = gnunet_peerstore_client_host::Instance::new();
    let mut publication_id = gnunet_peerstore_client_host::Instance::new();
    let mut hello_id = gnunet_peerstore_client_host::Instance::new();
    let mut query_id = gnunet_peerstore_client_host::Instance::new();
    let nat_id = gnunet_nat_client_host::Instance::new();
    let constructing = (|| -> Result<_, Failure> {
        let mut monitors = Vec::new();
        monitors
            .try_reserve_exact(settings.discovery.peers)
            .map_err(|_| gnunet_types::Error::Capacity)?;
        monitors.resize_with(
            settings.discovery.peers,
            gnunet_peerstore_client_host::Instance::new,
        );
        let sources = Sources {
            pils: sources.pils.duplicate()?,
            peerstore: sources.peerstore.duplicate()?,
            nat: sources.nat.duplicate()?,
        };
        Ok((monitors, sources, Entropy::open()?, Entropy::open()?))
    })();
    let (mut monitor_ids, sources, entropy, mut dv_entropy) = match constructing {
        Ok(v) => v,
        Err(failure) => {
            return End::Failed {
                failure,
                foreign_failures: 0,
            };
        }
    };
    let dv_endpoint = match sources.pils.duplicate() {
        Ok(endpoint) => endpoint,
        Err(error) => {
            return End::Failed {
                failure: Box::new(error),
                foreign_failures: 0,
            };
        }
    };
    let owner = Owner::new(
        owner::Instances {
            pils: &mut pils_id,
            validated: &mut validated_id,
            publications: &mut publication_id,
            hello: &mut hello_id,
            queries: &mut query_id,
            monitors: &mut monitor_ids,
            nat: &nat_id,
        },
        sources,
        clock,
        settings,
        entropy,
    );
    let mut owner = match owner {
        Ok(o) => o,
        Err(failure) => {
            return End::Failed {
                failure,
                foreign_failures: 0,
            };
        }
    };
    let reports = signals.reports();
    let mut service = crate::dv_control::Service::new(
        settings,
        listeners,
        resolver,
        signals,
        statistics,
        foreign_base,
    );
    let served = crate::dv_program::serve(
        &mut service,
        &mut owner,
        generation,
        &dv_endpoint,
        &mut dv_entropy,
    )
    .await;
    let ever_ready = service.ever_ready;
    drop(service);
    let outcome = served.result;
    let mut observing = |event| reports.observe(event);
    let mut restart = outcome.is_err() && served.allow_restart && owner.native_restart_requested();
    let stable = ever_ready && started.elapsed() >= settings.recovery;
    let mut cleanup = owner.stop(&mut observing);
    let foreign_failures = owner.statistics().foreign_address_failures;
    // Actual worker completion is mandatory even when its old publication is
    // expired/cancelled. A socket timer cannot cancel a real fsync/rename. The
    // process Resolver and statistics remain fairly driven during this wait.
    let drain = owner.take_reservation_drain();
    match drain {
        Err(e) => {
            cleanup.push(Box::new(e) as Failure);
            restart = false;
        }
        Ok(Some(mut drain)) => {
            let mut resolver_broken = false;
            loop {
                enum DrainTurn {
                    Stamp,
                    Resolver(Failure),
                    Activity,
                }
                let mut actual_stamp = None;
                let result = {
                    let mut resolving = (!resolver_broken).then(|| {
                        Box::pin(resolver.drive_waiting(None, |e| {
                            reports
                                .diagnostic(format_args!("TRANSPORT stamp-drain Resolver: {e:?}"))
                        }))
                    });
                    poll_fn(|cx| {
                        // Return an actual receipt immediately; never consume
                        // it then replace it with an unrelated source error.
                        if let Poll::Ready(result) = drain.poll(cx, generation) {
                            actual_stamp = Some(result);
                            return Poll::Ready(DrainTurn::Stamp);
                        }
                        let stats = statistics.poll(cx);
                        let resolution = match &mut resolving {
                            Some(future) => future.as_mut().poll(cx),
                            None => Poll::Pending,
                        };
                        if let Poll::Ready(Err(error)) = resolution {
                            return Poll::Ready(DrainTurn::Resolver(Box::new(error)));
                        }
                        if stats.is_ready() || resolution.is_ready() {
                            return Poll::Ready(DrainTurn::Activity);
                        }
                        Poll::Pending
                    })
                    .await
                };
                match result {
                    DrainTurn::Activity => tokio::task::yield_now().await,
                    DrainTurn::Resolver(error) => {
                        cleanup.push(error);
                        resolver_broken = true;
                        restart = false;
                        // The disk job is independent and cannot be abandoned
                        // or replayed just because Resolver stopped working.
                    }
                    DrainTurn::Stamp => {
                        let Some(actual) = actual_stamp else {
                            cleanup.push(Box::new(gnunet_types::Error::OutcomeUnknown));
                            restart = false;
                            break;
                        };
                        match actual {
                            Ok(outcome) => {
                                let failure = match &outcome {
                                    crate::epoch::ReservationOutcome::Failed { error, .. } => {
                                        Some(error.boxed())
                                    }
                                    crate::epoch::ReservationOutcome::Mismatched { .. } => {
                                        Some(Box::new(gnunet_types::Error::Stale) as Failure)
                                    }
                                    _ => None,
                                };
                                observing(owner::Event::ReservationRetired(outcome));
                                if let Some(error) = failure {
                                    cleanup.push(error);
                                    restart = false;
                                }
                            }
                            Err(error) => {
                                cleanup.push(Box::new(error));
                                restart = false;
                            }
                        }
                        break;
                    }
                }
            }
        }
        Ok(None) => {}
    }
    drop(owner); // all old borrowed brands can now retire before End escapes
    match outcome {
        Ok(()) => End::Stopped {
            failures: cleanup,
            foreign_failures,
        },
        Err(original) => {
            let failure = Box::new(Failures {
                original: Some(original),
                cleanup,
            }) as Failure;
            if restart {
                End::Restart {
                    failure,
                    foreign_failures,
                    stable,
                }
            } else {
                End::Failed {
                    failure,
                    foreign_failures,
                }
            }
        }
    }
}
