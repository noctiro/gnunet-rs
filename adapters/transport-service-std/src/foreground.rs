//! Standard independent TRANSPORT SERVICE/PROGRAM. External communicators use
//! the official listener; this foreground does not start a private aggregate
//! node, an embedded PEERSTORE, hidden Resolver, key loader or network transport.
pub use crate::reporting::{Notice, Reports};
use crate::{Failure, Failures, generation::Reservations, owner, settings::Settings, time::Clock};
use gnunet_program_host::{program::Prepared, shared_clock::SharedClock};
use gnunet_service_runtime::{Activation, BoundListeners, clock::RuntimeClock};
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io::Read,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    signal::unix::{Signal, SignalKind},
    time::Instant,
};
/// First-operation inherited descriptor ownership, adopted once by PROGRAM.
pub struct Inherited {
    /// Original parent-transferred service listener ownership.
    pub activation: Activation,
    /// Original parent control descriptor, if one was actually transferred.
    pub parent: Option<ParentControl>,
}
/// Actual service listeners prepared across the explicit process identity
/// transition, plus the original parent-control owner. The standard binary
/// completes deferred Unix binding before creating its reservation worker.
/// Neither this container nor the scheduler changes process identity.
pub struct Listening {
    /// Original inherited/prebound sockets and guarded new Unix endpoint.
    pub bound: BoundListeners,
    /// Original parent control descriptor, never reconstructed from a number.
    pub parent: Option<ParentControl>,
}
pub(crate) struct Signals {
    reports: Reports,
    reporting_stop: bool,
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    pub(crate) fn new(parent: Option<ParentControl>, reports: Reports) -> Result<Self, Failure> {
        Ok(Self {
            reports,
            reporting_stop: false,
            parent: parent
                .map(|p| p.register().map_err(|e| e.error))
                .transpose()?,
            interrupt: tokio::signal::unix::signal(SignalKind::interrupt())?,
            terminate: tokio::signal::unix::signal(SignalKind::terminate())?,
        })
    }
    pub(crate) fn reports(&self) -> Reports {
        self.reports.clone()
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        self.reports.register(cx);
        if self.reports.failed() && !self.reporting_stop {
            self.reporting_stop = true;
            return Poll::Ready(Ok(()));
        }
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(s)))
                    if i32::from(s) == SignalKind::interrupt().as_raw_value()
                        || i32::from(s) == SignalKind::terminate().as_raw_value() =>
                {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(Box::new(e))),
                Poll::Pending => {}
            }
        }
        for signal in [&mut self.interrupt, &mut self.terminate] {
            match signal.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err("TRANSPORT signal stream ended".into()));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
pub(crate) struct Entropy(std::fs::File);
impl Entropy {
    pub(crate) fn open() -> Result<Self, Failure> {
        Ok(Self(std::fs::File::open("/dev/urandom")?))
    }
}
impl gnunet_crypto::Entropy for Entropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), gnunet_types::Error> {
        self.0
            .read_exact(bytes)
            .map_err(|_| gnunet_types::Error::EntropyUnavailable)
    }
}
/// Run one actual service task in the existing PROGRAM scheduler/Resolver.
/// An admitted disk job remains owned until its real worker completion/join.
/// Socket grace cannot cancel a blocking filesystem fsync or synchronous stdio.
pub async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    listening: Listening,
    generation: Reservations,
) -> Result<(), Failure> {
    let reports = Reports::stderr();
    let reporting = reports.clone();
    let generation = Rc::new(RefCell::new(Some(generation)));
    let initialized = (|| -> Result<_, Failure> {
        let runtime: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
        let live =
            gnunet_resolver_broker::LiveConfiguration::new(prepared.main().config.duplicate()?);
        let (context, resolver) = gnunet_resolver_broker::broker::<64, 1024>(
            live.clone(),
            settings.resolver,
            gnunet_resolver_broker::native_profile()?,
            runtime.clone(),
        )?;
        Ok((runtime, live, context, resolver))
    })();
    let (runtime, live, mut context, resolver) = match initialized {
        Ok(value) => value,
        Err(original) => {
            let mut cleanup = Vec::new();
            let owned = generation.borrow_mut().take();
            if let Some(mut owned) = owned {
                owned.begin_stop();
                if let Err(e) = owned.shutdown().await {
                    cleanup.push(Box::new(e) as Failure);
                }
            }
            return Err(Box::new(Failures {
                original: Some(original),
                cleanup,
            }));
        }
    };
    let generations = Rc::clone(&generation);
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stop = scope.clone();
            let generations = Rc::clone(&generations);
            if let Err(error) = scope.spawn(async move {
                let owned = generations.borrow_mut().take();
                let outcome = match owned {
                    Some(generation) => {
                        run(
                            live, settings, listening, resolver, runtime, generation, reporting,
                        )
                        .await
                    }
                    None => Err("TRANSPORT generation owner already consumed".into()),
                };
                *destination.borrow_mut() = Some(outcome);
                if let Err(e) = stop.shutdown() {
                    let original = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(e)],
                    })));
                }
            }) {
                *receiving.borrow_mut() = Some(Err(Box::new(error) as Failure));
                if let Err(e) = scope.shutdown() {
                    let original = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(e)],
                    })));
                }
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without TRANSPORT task completion".into()));
    let mut cleanup = Vec::new();
    let unconsumed = generation.borrow_mut().take();
    if let Some(mut generation) = unconsumed {
        generation.begin_stop();
        if let Err(e) = generation.shutdown().await {
            cleanup.push(Box::new(e) as Failure)
        }
    }
    match program {
        Ok(1) => {}
        Ok(code) => cleanup.push(format!("TRANSPORT PROGRAM returned {code}").into()),
        Err(e) => cleanup.push(Box::new(e)),
    }
    let outcome: Result<(), Failure> = if task.is_ok() && cleanup.is_empty() {
        Ok(())
    } else {
        Err(Box::new(Failures {
            original: task.err(),
            cleanup,
        }))
    };
    gnunet_program_host::service::retain_diagnostic(outcome, reports.take_failure())
}
/// Run the actual SERVICE driver over an already selected configuration and
/// original listeners. The caller alone owns process options, detach and UID
/// transitions. This does not construct a synthetic PROGRAM preparation.
pub async fn service(
    config: gnunet_config::Configuration,
    clock: SharedClock,
    settings: Settings,
    listening: Listening,
    mut generation: Reservations,
    reports: Reports,
) -> Result<(), Failure> {
    let initialized = (|| -> Result<_, Failure> {
        let runtime: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
        let live = gnunet_resolver_broker::LiveConfiguration::new(config);
        let (_context, resolver) = gnunet_resolver_broker::broker::<64, 1024>(
            live.clone(),
            settings.resolver,
            gnunet_resolver_broker::native_profile()?,
            runtime.clone(),
        )?;
        Ok((runtime, live, resolver))
    })();
    let outcome = match initialized {
        Ok((runtime, live, resolver)) => {
            run(
                live,
                settings,
                listening,
                resolver,
                runtime,
                generation,
                reports.clone(),
            )
            .await
        }
        Err(original) => {
            // No session exists, but the caller already opened this actual
            // reservation worker; initialization failure must really join it.
            generation.begin_stop();
            let cleanup = generation
                .shutdown()
                .await
                .err()
                .map(|error| Box::new(error) as Failure)
                .into_iter()
                .collect();
            Err(Box::new(Failures {
                original: Some(original),
                cleanup,
            }) as Failure)
        }
    };
    gnunet_program_host::service::retain_diagnostic(outcome, reports.take_failure())
}
async fn run(
    live: gnunet_client_host::LiveConfiguration,
    settings: Settings,
    listening: Listening,
    mut resolver: gnunet_resolver_broker::Driver<64, 1024>,
    clock: Arc<dyn RuntimeClock>,
    mut generation: Reservations,
    reports: Reports,
) -> Result<(), Failure> {
    let result = run_service(
        live,
        &settings,
        listening,
        &mut resolver,
        clock,
        &mut generation,
        reports,
    )
    .await;
    generation.begin_stop();
    let mut cleanup = Vec::new();
    if let Err(e) = generation.shutdown().await {
        cleanup.push(Box::new(e) as Failure)
    }
    if let Err(e) = resolver.disconnect() {
        cleanup.push(Box::new(e));
    }
    if result.is_ok() && cleanup.is_empty() {
        Ok(())
    } else {
        Err(Box::new(Failures {
            original: result.err(),
            cleanup,
        }))
    }
}
async fn run_service(
    live: gnunet_client_host::LiveConfiguration,
    settings: &Settings,
    listening: Listening,
    resolver: &mut gnunet_resolver_broker::Driver<64, 1024>,
    runtime: Arc<dyn RuntimeClock>,
    generation: &mut Reservations,
    reports: Reports,
) -> Result<(), Failure> {
    let Listening { bound, parent } = listening;
    let mut signals = Signals::new(parent, reports.clone())?;
    for failure in bound.failures() {
        reports.diagnostic(format_args!("TRANSPORT alternate listener: {failure}"));
    }
    let listeners = bound.listeners();
    let resolution = resolver.context().resolution_context();
    let pils = gnunet_client_host::EndpointSource::live(live.clone(), b"pils", resolution.clone());
    let peerstore =
        gnunet_client_host::EndpointSource::live(live.clone(), b"peerstore", resolution.clone());
    let nat = gnunet_client_host::EndpointSource::live(live.clone(), b"nat", resolution.clone());
    let [pils, peerstore, nat] =
        gnunet_client_host::EndpointSource::snapshot_all([&pils, &peerstore, &nat])?;
    let sources = owner::Sources {
        pils,
        peerstore,
        nat,
    };
    // One process coordinate owner survives native session reallocations. A
    // failed old time profile is never repaired by minting a fake new anchor.
    let native_clock = Clock::new(runtime)?;
    let mut stats_id = gnunet_ipc_unix::handle::Instance::new();
    let mut stats = crate::statistics::Publisher::new(&mut stats_id, live, resolution)?;
    let mut foreign_base = 0u64;
    let mut failures = Vec::new();
    failures
        .try_reserve_exact(32)
        .map_err(|_| gnunet_types::Error::Capacity)?;
    let result = loop {
        let session = crate::session::run(crate::session::Inputs {
            sources: &sources,
            settings,
            listeners: &listeners,
            resolver,
            clock: native_clock.clone(),
            generation,
            signals: &mut signals,
            statistics: &mut stats,
            foreign_base,
        })
        .await;
        match session {
            crate::session::End::Stopped {
                failures: cleanup,
                foreign_failures,
            } => {
                foreign_base = foreign_base.saturating_add(foreign_failures);
                break if cleanup.is_empty() {
                    Ok(())
                } else {
                    Err(Box::new(Failures {
                        original: None,
                        cleanup,
                    }) as Failure)
                };
            }
            crate::session::End::Failed {
                failure,
                foreign_failures,
            } => {
                foreign_base = foreign_base.saturating_add(foreign_failures);
                break Err(failure);
            }
            crate::session::End::Restart {
                failure,
                foreign_failures,
                stable,
            } => {
                foreign_base = foreign_base.saturating_add(foreign_failures);
                stats.refresh(owner::Statistics {
                    foreign_address_failures: foreign_base,
                });
                reports.diagnostic(format_args!(
                    "TRANSPORT original native session retired; fresh allocation pending: {failure}"
                ));
                if stable {
                    failures.clear();
                }
                // A finite consecutive-failure budget bounds metadata and
                // prevents an unavailable dependency from an idle retry spin.
                if failures.len() == 32 {
                    break Err(Box::new(Failures {
                        original: Some(failure),
                        cleanup: failures,
                    }) as Failure);
                }
                failures.push(failure);
                let shift = u32::try_from(failures.len().saturating_sub(1).min(8))
                    .map_err(|_| gnunet_types::Error::Overflow)?;
                let delay = std::time::Duration::from_millis(
                    100u64
                        .checked_shl(shift)
                        .ok_or(gnunet_types::Error::Overflow)?,
                )
                .min(std::time::Duration::from_secs(30));
                let hard = Instant::now()
                    .checked_add(delay)
                    .ok_or(gnunet_types::Error::Overflow)?;
                let mut alarm = Box::pin(tokio::time::sleep_until(hard));
                let waiting = loop {
                    enum Turn {
                        Resume,
                        Stop,
                        Activity,
                    }
                    let turn = {
                        let mut resolving =
                            std::pin::pin!(resolver.drive_waiting(Some(hard), |e| {
                                reports
                                    .diagnostic(format_args!("TRANSPORT reconnect Resolver: {e:?}"))
                            }));
                        poll_fn(|cx| {
                            if let Poll::Ready(result) = signals.poll(cx) {
                                return Poll::Ready(result.map(|()| Turn::Stop));
                            }
                            let statistics = stats.poll(cx);
                            let resolution = resolving.as_mut().poll(cx);
                            if let Poll::Ready(Err(error)) = resolution {
                                return Poll::Ready(Err(Box::new(error) as Failure));
                            }
                            if alarm.as_mut().poll(cx).is_ready() {
                                return Poll::Ready(Ok(Turn::Resume));
                            }
                            if statistics.is_ready() || resolution.is_ready() {
                                Poll::Ready(Ok(Turn::Activity))
                            } else {
                                Poll::Pending
                            }
                        })
                        .await
                    };
                    match turn {
                        Ok(Turn::Resume) => break Ok(true),
                        Ok(Turn::Stop) => break Ok(false),
                        Ok(Turn::Activity) => tokio::task::yield_now().await,
                        Err(error) => break Err(error),
                    }
                };
                match waiting {
                    Ok(true) => {}
                    Ok(false) => break Ok(()),
                    Err(original) => {
                        break Err(Box::new(Failures {
                            original: Some(original),
                            cleanup: failures,
                        }) as Failure);
                    }
                }
            }
        }
        // Every prior Owner/native brand has already dropped inside run().
        // Only new future requests can use the next freshly allocated session.
    };
    stats.refresh(owner::Statistics {
        foreign_address_failures: foreign_base,
    });
    let cleanup = stats.close().into_iter().collect::<Vec<_>>();
    if result.is_ok() && cleanup.is_empty() {
        Ok(())
    } else {
        Err(Box::new(Failures {
            original: result.err(),
            cleanup,
        }))
    }
}

impl Reports {
    pub(crate) fn observe(&self, event: owner::Event<'_>) {
        match event {
            owner::Event::Ready(identity) => self.message(
                gnunet_program_host::policy::Level::INFO,
                "transport.identity.ready",
                format_args!(
                    "TRANSPORT original PILS authority ready: {:?}",
                    identity.peer()
                ),
            ),
            owner::Event::Transport(gnunet_transport_host::Step::MonitorRetired(r)) => self
                .diagnostic(format_args!(
                    "TRANSPORT original observation source {:?} retired: {:?}",
                    r.client, r.reason
                )),
            owner::Event::NativeRetired(original) => self.diagnostic(format_args!(
                "TRANSPORT original native retirement: {original:?}"
            )),
            owner::Event::Transport(gnunet_transport_host::Step::InputRejected(r)) => {
                self.diagnostic(format_args!("TRANSPORT original input refused: {r:?}"))
            }
            owner::Event::Transport(gnunet_transport_host::Step::AddressRejected(r)) => {
                self.diagnostic(format_args!("TRANSPORT original ADD refused: {r:?}"))
            }
            owner::Event::ValidationFailed { reason, .. } => self.diagnostic(format_args!(
                "TRANSPORT original purpose35 failed: {}",
                match reason {
                    crate::pils::Reason::Cancelled => "cancelled",
                    crate::pils::Reason::Deadline => "deadline",
                    crate::pils::Reason::Lost(_) => "source lost",
                    crate::pils::Reason::Refused(_) => "refused",
                }
            )),
            owner::Event::EpochRetiring { previous, observed } => self.diagnostic(format_args!(
                "TRANSPORT old Engine physically retired for real PID change {:?} -> {:?}",
                previous.peer(),
                observed.peer()
            )),
            owner::Event::EpochStarted {
                identity,
                generation,
            } => self.diagnostic(format_args!(
                "TRANSPORT new Engine brand generation={generation} actual PID={:?}",
                identity.peer()
            )),
            owner::Event::ReservationRetired(crate::epoch::ReservationOutcome::Failed {
                error,
                ..
            }) => self.diagnostic(format_args!(
                "TRANSPORT original retired stamp failed: {error}"
            )),
            owner::Event::ReservationRetired(crate::epoch::ReservationOutcome::Mismatched {
                ..
            }) => self.diagnostic(format_args!(
                "TRANSPORT actual retired stamp receipt did not match its original job"
            )),
            owner::Event::ValidatedRetired(done) => {
                match done.outcome {
                    crate::validated::RetiredOutcome::Refused(code) => self.diagnostic(
                        format_args!("TRANSPORT original validated STORE raw refusal: {code}"),
                    ),
                    crate::validated::RetiredOutcome::Ended { reason, submission } => self
                        .diagnostic(format_args!(
                            "TRANSPORT original validated STORE retired: {reason:?}/{submission:?}"
                        )),
                    crate::validated::RetiredOutcome::Unknown => self.diagnostic(format_args!(
                        "TRANSPORT original validated STORE has unknown processing outcome"
                    )),
                    _ => {}
                }
                if let Some(error) = done.failure {
                    self.diagnostic(format_args!(
                        "TRANSPORT original retired validated STORE failed: {error}"
                    ));
                }
            }
            owner::Event::PublicationFailed { reason, .. } => self.diagnostic(format_args!(
                "TRANSPORT original publication job failed: {reason:?}"
            )),
            owner::Event::PilsRetired(crate::pils::Event::Failed { reason, .. }) => self
                .diagnostic(format_args!(
                    "TRANSPORT original PILS job retired: {reason:?}"
                )),
            owner::Event::PublicationRetired(crate::writer::Event::Refused { code, .. }) => {
                self.diagnostic(format_args!("TRANSPORT original STORE refused: {code}"))
            }
            owner::Event::PublicationRetired(crate::writer::Event::Ended {
                reason,
                submission,
                ..
            }) => self.diagnostic(format_args!(
                "TRANSPORT original STORE retired: {reason:?}/{submission:?}"
            )),
            owner::Event::HelloRetired(done) => {
                if let Err(e) = done.result {
                    self.diagnostic(format_args!("TRANSPORT original HELLO retired: {e}"));
                }
            }
            owner::Event::Nat(gnunet_nat_client_host::Progress::Ended(end)) => self.diagnostic(
                format_args!("TRANSPORT original NAT source retired: {:?}", end.source),
            ),
            owner::Event::Discovery(crate::discovery::Event::Cleanup { error, .. }) => self
                .diagnostic(format_args!(
                    "TRANSPORT discovery independent cleanup: {error}"
                )),
            _ => {}
        }
    }
}
