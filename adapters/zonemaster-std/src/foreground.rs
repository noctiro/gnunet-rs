//! Actual PROGRAM, SERVICE, same Resolver/clock and original native ownership.
//! A production public DHT factory is mandatory; no fallback sink exists.
use crate::{
    Failure, Identities, Owner, Sources,
    owner::{Event, Failures},
    publish, service,
    settings::Settings,
};
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::{ParentControl, StopSignals};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    rc::Rc,
    sync::Arc,
    task::Poll,
};
/// Actual terminal public facts collected while stopping this foreground.
/// Earlier normal-running notices have already been delivered to its Owner.
#[derive(Debug)]
pub struct Report {
    /// Per-original-job local write/retirement facts, never remote storage ACKs.
    pub publications: Vec<publish::Event>,
    /// Latest actual synchronized local expiration reservation at stop. This
    /// observation neither authorizes another seal nor asserts a remote ACK.
    pub latest_nonce_reservation: Option<crate::nonce::Receipt>,
}
/// A stopped foreground keeps its exact public report even when later PROGRAM,
/// Resolver, statistics or worker cleanup failed independently.
#[derive(Debug)]
pub struct ShutdownFailure {
    /// Actual original terminal public notices at stop.
    pub report: Report,
    /// Original and independent actual errors.
    pub failures: Failures,
}
impl std::fmt::Display for ShutdownFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; {} original public stop notices retained",
            self.failures,
            self.report.publications.len()
        )
    }
}
impl std::error::Error for ShutdownFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.failures)
    }
}
fn with_cleanup(result: Result<Report, Failure>, cleanup: Failure) -> Result<Report, Failure> {
    Err(match result {
        Ok(report) => Box::new(ShutdownFailure {
            report,
            failures: Failures {
                original: None,
                cleanup: vec![cleanup],
            },
        }) as Failure,
        Err(original) => Box::new(Failures {
            original: Some(original),
            cleanup: vec![cleanup],
        }) as Failure,
    })
}
/// Original once-adopted SERVICE listeners and parent control stream.
pub struct Inherited {
    /// Exact inherited listener/readiness ownership.
    pub activation: gnunet_service_runtime::Activation,
    /// Actual parent control descriptor, never a copied FD.
    pub parent: Option<ParentControl>,
}
fn diagnostic(reports: &Reporter, args: std::fmt::Arguments<'_>) {
    reports.warning("zonemaster.activity", args);
}
struct Signals {
    stop: StopSignals,
    #[cfg(windows)]
    ready: Option<gnunet_service_startup::ReadyWriter>,
}
impl Signals {
    fn new(parent: Option<ParentControl>) -> Result<Self, Failure> {
        #[cfg(unix)]
        let parent = parent
            .map(|parent| parent.register().map_err(|failure| failure.error))
            .transpose()?;
        #[cfg(windows)]
        let (parent, ready) = match parent.map(|parent| parent.register()).transpose()? {
            Some(parent) => (Some(parent.control), Some(parent.ready)),
            None => (None, None),
        };
        Ok(Self {
            stop: StopSignals::new(parent)?,
            #[cfg(windows)]
            ready,
        })
    }
    async fn ready(&mut self, reports: &Reporter) -> Result<(), Failure> {
        let notification = async {
            #[cfg(windows)]
            if let Some(writer) = &mut self.ready {
                writer
                    .signal(gnunet_service_startup::ReadyStatus::AcceptRegistered)
                    .await?;
            }
            Ok::<_, Failure>(())
        };
        gnunet_program_host::service::acknowledge_ready(
            notification,
            &mut self.stop,
            reports,
            std::time::Duration::from_secs(5),
        )
        .await?;
        #[cfg(windows)]
        drop(self.ready.take());
        Ok(())
    }
}

/// Run complete native composition with an explicitly installed actual DHT
/// producer. None refuses before Resolver, listeners, workers or native clients
/// start. The factory is owned by this run and may retain its instance brands.
pub async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    inherited: Inherited,
    factory: Option<Box<dyn publish::Factory>>,
    reports: Reporter,
) -> Result<Report, Failure> {
    let factory=factory.ok_or("ZONEMASTER production DHT publish binding is not installed; no publication service was started")?;
    let config = prepared.main().config.duplicate()?;
    let runtime_clock: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = gnunet_resolver_broker::LiveConfiguration::new(config.duplicate()?);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<64, 1024>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime_clock.clone(),
    )?;
    let deferred = Rc::new(RefCell::new(None));
    let resolver = ResolverOwner {
        driver: resolver,
        done: false,
        reports: reports.clone(),
        deferred: deferred.clone(),
    };
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stop = scope.clone();
            if let Err(error) = scope.spawn(async move {
                let outcome = run(Inputs {
                    config,
                    live,
                    settings,
                    inherited,
                    resolver,
                    clock: runtime_clock,
                    factory,
                    reports,
                })
                .await;
                *destination.borrow_mut() = Some(outcome);
                if let Err(error) = stop.shutdown() {
                    let original = destination
                        .borrow_mut()
                        .take()
                        .unwrap_or_else(|| Err("ZONEMASTER task report missing".into()));
                    *destination.borrow_mut() = Some(with_cleanup(original, Box::new(error)));
                }
            }) {
                *receiving.borrow_mut() = Some(Err(Box::new(error) as Failure));
                if let Err(error) = scope.shutdown() {
                    let original = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(Err(Box::new(Failures {
                        original,
                        cleanup: vec![Box::new(error)],
                    })));
                }
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without ZONEMASTER task completion".into()));
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("ZONEMASTER PROGRAM returned {code}").into()),
        Err(error) => Some(Box::new(error) as Failure),
    };
    let outcome = match (task, program) {
        (Ok(report), None) => Ok(report),
        (task, Some(program)) => with_cleanup(task, program),
        (Err(error), None) => Err(error),
    };
    let cleanup = deferred.borrow_mut().take();
    match cleanup {
        Some(error) => with_cleanup(outcome, Box::new(error)),
        None => outcome,
    }
}
struct ResolverOwner {
    driver: gnunet_resolver_broker::Driver<64, 1024>,
    done: bool,
    reports: Reporter,
    deferred: Rc<RefCell<Option<gnunet_resolver_broker::BrokerError>>>,
}
impl Drop for ResolverOwner {
    fn drop(&mut self) {
        if !self.done
            && let Err(error) = self.driver.disconnect()
        {
            diagnostic(
                &self.reports,
                format_args!("ZONEMASTER dropped task Resolver cleanup: {error}"),
            );
            self.deferred.borrow_mut().get_or_insert(error);
        }
    }
}
fn observe(event: service::Event, reports: &Reporter) {
    match event {
        service::Event::Accepted { diagnostics } | service::Event::Rejected { diagnostics } => {
            for d in diagnostics {
                diagnostic(reports, format_args!("ZONEMASTER accepted socket: {d:?}"));
            }
        }
        service::Event::Admission { error, diagnostics } => {
            for d in diagnostics {
                diagnostic(reports, format_args!("ZONEMASTER rejected socket: {d:?}"));
            }
            diagnostic(
                reports,
                format_args!("ZONEMASTER original socket admission: {error}"),
            );
        }
        service::Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(error))
            if error.is_emfile() => {}
        service::Event::Socket(event) => {
            diagnostic(reports, format_args!("ZONEMASTER socket: {event:?}"))
        }
        _ => {}
    }
}
struct Inputs {
    config: gnunet_config::Configuration,
    live: gnunet_client_host::LiveConfiguration,
    settings: Settings,
    inherited: Inherited,
    resolver: ResolverOwner,
    clock: Arc<dyn RuntimeClock>,
    factory: Box<dyn publish::Factory>,
    reports: Reporter,
}
async fn run(input: Inputs) -> Result<Report, Failure> {
    let Inputs {
        config,
        live,
        settings,
        inherited,
        resolver,
        clock,
        mut factory,
        reports,
    } = input;
    let mut resolver = resolver;
    let mut signals = Signals::new(inherited.parent)?;
    let resolution = resolver.driver.context().resolution_context();
    let endpoints = [
        b"namestore".as_slice(),
        b"namestore".as_slice(),
        b"namecache".as_slice(),
        b"dht".as_slice(),
    ]
    .map(|section| {
        config.duplicate().map(|c| {
            gnunet_client_host::EndpointSource::configuration(c, section, resolution.clone())
        })
    });
    let [monitor, inventory, cache, dht] = endpoints;
    let (monitor, inventory, cache, dht) = (monitor?, inventory?, cache?, dht?);
    let [monitor, inventory, cache, dht] =
        gnunet_client_host::EndpointSource::snapshot_all([&monitor, &inventory, &cache, &dht])?;
    // Normal SERVICE semantics, with no invented domain commands. Readiness
    // from this boundary attests local listener ownership alone.
    #[cfg(unix)]
    let bound =
        gnunet_service_runtime::BoundListeners::bind(&config, b"zonemaster", inherited.activation)
            .await?;
    #[cfg(windows)]
    let bound = if inherited.activation.is_empty() {
        gnunet_service_runtime::BoundListeners::bind(&config, b"zonemaster", inherited.activation)
            .await?
    } else {
        gnunet_service_runtime::BoundListeners::from_activation_with_access(
            inherited.activation,
            settings.unix,
        )?
    };
    for error in bound.failures() {
        diagnostic(
            &reports,
            format_args!("ZONEMASTER alternate listener: {error}"),
        );
    }
    let listeners = bound.listeners();
    let mut public = factory.open(publish::Inputs {
        source: dht,
        clock: clock.clone(),
        parallel: settings.owner.publications,
    })?;
    let namestore_id = gnunet_namestore_client_host::Instance::new();
    let cache_id = gnunet_namecache_client_host::Instance::new();
    let mut owner = Owner::new(
        Identities {
            namestore: &namestore_id,
            cache: &cache_id,
        },
        Sources {
            monitor,
            inventory,
            cache: settings.cache_enabled.then_some(cache),
            publish: public.as_mut(),
        },
        clock,
        settings.core,
        settings.owner,
        settings.nonce,
    )?;
    // Declared after Owner so cancellation of this foreground future drops all
    // accepted service clients before Owner's final actual CPU join.
    let mut server = service::Server::new(settings.service, settings.options, settings.unix)?;
    let mut stats_instance = gnunet_ipc_unix::handle::Instance::new();
    let mut stats = crate::statistics::Publisher::new(&mut stats_instance, live, resolution)?;
    let mut stats_errors = Vec::new();
    stats_errors
        .try_reserve_exact(4)
        .map_err(|_| gnunet_types::Error::Capacity)?;
    reports.message(
        gnunet_program_host::policy::Level::INFO,
        "zonemaster.ready",
        format_args!("ZONEMASTER local listeners and worker owner ready"),
    );
    let mut readiness = Some(signals.ready(&reports).await);
    let outcome = loop {
        if let Some(Err(error)) = readiness.take() {
            break Err(error);
        }
        enum Turn {
            Stop,
            Activity,
        }
        let result = {
            let mut resolving =
                std::pin::pin!(resolver.driver.drive_waiting(None, |event| diagnostic(
                    &reports,
                    format_args!("ZONEMASTER Resolver: {event:?}")
                )));
            poll_fn(|cx| {
                reports.register(cx);
                if reports.failed() {
                    return Poll::Ready(Err(std::io::Error::other(
                        "ZONEMASTER selected diagnostic owner failed",
                    )
                    .into()));
                }
                if let Poll::Ready(result) = signals.stop.poll_stop(cx) {
                    return Poll::Ready(result.map(|()| Turn::Stop).map_err(Into::into));
                }
                // All actual child native bounds are checked even when the
                // canonical source races forever. Neither stats nor Resolver
                // can mask an original source/partial/control/job deadline.
                let guarded = server.poll_native_guard(cx);
                let mut activity = guarded.is_some();
                if let Some(event) = guarded {
                    observe(event, &reports);
                }
                let owning = owner.poll(cx);
                let serving = server.poll(cx, &listeners);
                let mut original = None;
                let mut cleanup = Vec::new();
                if let Poll::Ready(result) = owning {
                    activity = true;
                    match result {
                        Ok(Event::Failure(error)) => diagnostic(
                            &reports,
                            format_args!("ZONEMASTER original provider/cleanup: {error}"),
                        ),
                        Ok(Event::Stopped) => {
                            original = Some("ZONEMASTER owner stopped unexpectedly".into())
                        }
                        Ok(_) => {}
                        Err(error) => original = Some(error),
                    }
                }
                if let Poll::Ready(result) = serving {
                    activity = true;
                    match result {
                        Ok(event) => observe(event, &reports),
                        Err(error) => {
                            if original.is_none() {
                                original = Some(error)
                            } else {
                                cleanup.push(error)
                            }
                        }
                    }
                }
                if let Err(error) = stats.admit(owner.metrics()) {
                    stats_errors.push(error);
                }
                if let Poll::Ready(result) = stats.poll(cx, None) {
                    activity = true;
                    if let Err(error) = result {
                        stats_errors.push(error);
                    }
                }
                if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                    activity = true;
                    if let Err(error) = result {
                        if original.is_none() {
                            original = Some(Box::new(error))
                        } else {
                            cleanup.push(Box::new(error));
                        }
                    }
                }
                if original.is_some() {
                    return Poll::Ready(Err(Box::new(Failures { original, cleanup }) as Failure));
                }
                if activity {
                    Poll::Ready(Ok(Turn::Activity))
                } else {
                    Poll::Pending
                }
            })
            .await
        };
        match result {
            Ok(Turn::Stop) => break Ok(()),
            Ok(Turn::Activity) => {}
            Err(error) => break Err(error),
        }
    };
    // Drop/stop every original service client, NAMESTORE/cache stream, DHT PUT,
    // CPU input/result and worker before disconnecting the shared Resolver.
    server.stop();
    let stopped = owner.stop();
    let mut cleanup = stopped.failures;
    let report = Report {
        publications: stopped.publications,
        latest_nonce_reservation: stopped.latest_nonce_reservation,
    };
    let metrics = owner.metrics();
    drop(owner);
    drop(public);
    cleanup.extend(stats_errors);
    // A u64 relative total needs at most three signed-i64 chunks; 16 names.
    for _ in 0..48 {
        match stats.admit(metrics) {
            Ok(true) => {}
            Ok(false) => break,
            Err(error) => {
                cleanup.push(error);
                break;
            }
        }
    }
    if let Err(error) = stats.destroy() {
        cleanup.push(error);
        if let Err(error) = stats.abort() {
            cleanup.push(error);
        }
    }
    let hard = match tokio::time::Instant::now().checked_add(settings.grace) {
        Some(hard) => hard,
        None => {
            cleanup.push(Box::new(gnunet_types::Error::Overflow));
            // Preserve the actual report and continue physical cleanup under
            // an immediate bound rather than returning through a lost report.
            tokio::time::Instant::now()
        }
    };
    let mut alarm = Box::pin(tokio::time::sleep_until(hard));
    while !stats.closed() {
        let result = {
            let mut resolving = std::pin::pin!(resolver.driver.drive_waiting(
                Some(hard),
                |event| diagnostic(
                    &reports,
                    format_args!("ZONEMASTER shutdown Resolver: {event:?}")
                )
            ));
            poll_fn(|cx| {
                if alarm.as_mut().poll(cx).is_ready() {
                    let cleanup = stats.abort().err().into_iter().collect();
                    return Poll::Ready(Err(Box::new(Failures {
                        original: Some(Box::new(gnunet_types::Error::Deadline)),
                        cleanup,
                    }) as Failure));
                }
                if let Poll::Ready(result) = stats.poll(cx, Some(hard)) {
                    return Poll::Ready(result);
                }
                if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                    return Poll::Ready(
                        result
                            .map(|_| ())
                            .map_err(|error| Box::new(error) as Failure),
                    );
                }
                Poll::Pending
            })
            .await
        };
        if let Err(error) = result {
            cleanup.push(error);
            if let Err(error) = stats.abort() {
                cleanup.push(error);
            }
            break;
        }
    }
    if let Err(error) = stats.check_report() {
        cleanup.push(error);
    }
    if let Err(error) = stats.abort() {
        cleanup.push(error);
    }
    drop(stats);
    if let Err(error) = resolver.driver.disconnect() {
        cleanup.push(Box::new(error));
    }
    resolver.done = true;
    drop(listeners);
    drop(bound);
    if outcome.is_ok() && cleanup.is_empty() {
        Ok(report)
    } else {
        Err(Box::new(ShutdownFailure {
            report,
            failures: Failures {
                original: outcome.err(),
                cleanup,
            },
        }))
    }
}
