//! Actual standard PROGRAM foreground for raw QUIC and HTTP3 communicators.
//! Runtime, Resolver, external frame loans and original shutdown remain in this
//! one scoped task. There is no detached actor, fallback DNS or C transport FFI.
mod control;
mod credentials;
mod observation;
mod reporting;
use crate::statistics::{self, NoStatistics, StatisticsFactory};
mod resources;
mod settings;
use crate::{Buffers, Instance, Progress, Runtime, Sources, tls::Profile};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_program_host::{
    logging::Logger,
    policy::Level,
    program::{self, Defaults, Invocation, NlsDisabled, Preparation, Prepared},
    shared_clock::SharedClock,
};
use gnunet_resolver_broker::Driver;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::ParentControl;
use reporting::Reports;
use settings::Settings;
use std::{
    cell::{Cell, RefCell},
    error::Error,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::Context,
    task::Poll,
};
/// Original native/configuration cause, without credential bytes.
pub type Failure = Box<dyn Error>;
#[derive(Debug, Default)]
struct Failures {
    original: Option<Failure>,
    signal: Option<io::Error>,
    resolver: Option<Failure>,
    disconnect: Option<Failure>,
    cleanup: Option<crate::Fault>,
    diagnostic: Option<io::Error>,
    program: Option<Failure>,
    task: Option<Failure>,
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.original.is_none()
            && self.signal.is_none()
            && self.resolver.is_none()
            && self.disconnect.is_none()
            && self.cleanup.is_none()
            && self.diagnostic.is_none()
            && self.program.is_none()
            && self.task.is_none()
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("communicator failures")?;
        for (name, error) in [
            ("original", self.original.as_deref()),
            ("resolver", self.resolver.as_deref()),
            ("resolver-close", self.disconnect.as_deref()),
            ("program", self.program.as_deref()),
            ("task", self.task.as_deref()),
        ] {
            if let Some(e) = error {
                write!(f, "; {name}: {e}")?
            }
        }
        if let Some(e) = &self.signal {
            write!(f, "; signal: {e}")?
        }
        if let Some(e) = &self.cleanup {
            write!(f, "; native cleanup: {e}")?
        }
        if let Some(e) = &self.diagnostic {
            write!(f, "; diagnostic: {e}")?
        }
        Ok(())
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or(self.task.as_deref())
            .or(self.program.as_deref())
    }
}
/// Run only after the binary has performed its sole unsafe initial inherited-FD
/// capture. The communicator has no SERVICE listener; that boundary must reject
/// inherited listener/readiness FDs and pass through only original parent control.
/// This routine does not fork or reinterpret -v as verbosity. Shared PROGRAM
/// owns the actual standard option table, GNUNET_ARGS, locale/config and logger.
pub fn run(profile: Profile, parent: Option<ParentControl>) -> Result<(), Failure> {
    run_with_statistics::<NoStatistics>(profile, parent)
}
/// Standard apps inject the real native publisher. Explicit embeddings may use
/// the no-publisher entry above; it does not claim observation publication.
pub fn run_with_statistics<F: StatisticsFactory>(
    profile: Profile,
    parent: Option<ParentControl>,
) -> Result<(), Failure> {
    #[cfg(not(feature = "h3-profile"))]
    if profile == Profile::Http3 {
        return Err("HTTP3 binary requires h3-profile".into());
    }
    let clock = SharedClock::native(1024)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(settings::binary(profile), std::process::id(), false)?;
    let preparation = program::prepare(
        config,
        Invocation {
            binary_name: settings::binary(profile),
            help: Some(b"GNUnet QUIC communicator. Claimed peer identity does not establish authentication."),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        Default::default(),
        std::env::args_os(),
        &program::Environment::capture(),
        &mut NlsDisabled,
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    let reports = Rc::new(RefCell::new(Reports::new(logger, clock.clone(), profile)));
    let result = (|| {
        let prepared = match preparation? {
            Preparation::Ready(p) => *p,
            Preparation::Stopped(s)
                if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) =>
            {
                return Ok(());
            }
            Preparation::Stopped(s) => {
                return Err(
                    format!("PROGRAM stopped: {:?} (source code {})", s.reason, s.code).into(),
                );
            }
        };

        if !prepared.main().arguments.is_empty() {
            return Err("QUIC/HTTP3 communicators accept no positional arguments".into());
        }
        let settings = Settings::read(prepared.main().config, profile)?;
        let user = gnunet_service_startup::configured_user(
            prepared.main().config,
            settings::section(profile),
        )?
        .map(|n| gnunet_service_startup::resolve_user(&n))
        .transpose()?;
        let privilege = gnunet_service_startup::apply_privileges(
            user.as_ref(),
            gnunet_service_startup::GroupsProfile::WithInitgroups,
        )?;
        if user.is_some() {
            reports.borrow_mut().log(
                "quic.process.identity",
                Level::INFO,
                format_args!("process identity applied: {privilege:?}"),
            )
        }
        if reports.borrow().failed() {
            return Ok(());
        }
        // All sockets, configured credential IO, TLS entropy and Tokio signal owners
        // are constructed only after the real process identity has been applied.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(scheduled::<F>(
                prepared,
                clock,
                settings,
                parent,
                Rc::clone(&reports),
            ))
    })();
    if let Err(error) = &result {
        reports
            .borrow_mut()
            .log("quic.program.failed", Level::ERROR, format_args!("{error}"))
    }
    let diagnostic = reports.borrow_mut().take_failure();
    gnunet_program_host::service::retain_diagnostic(result, diagnostic)
}
// Retain the actual task future outside PROGRAM's task wrapper. If the shared
// scheduler itself fails/cancels its wrapper, the original source future remains
// pinned and is driven through clock-independent shutdown, rather than silently
// being replaced by a Drop-only cleanup claim. There is one process-level Box.
struct NativeTask<F> {
    future: Pin<Box<F>>,
    result: Option<Result<(), Failure>>,
}
impl<F: Future<Output = Result<(), Failure>>> NativeTask<F> {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if self.result.is_some() {
            return Poll::Ready(());
        }
        match self.future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.result = Some(result);
                Poll::Ready(())
            }
        }
    }
}
async fn scheduled<F: StatisticsFactory>(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    parent: Option<ParentControl>,
    reports: Rc<RefCell<Reports>>,
) -> Result<(), Failure> {
    let config = prepared.main().config.duplicate()?;
    let actual: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<64, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        actual,
    )?;
    let resolution = context.resolution_context();
    let stopping = Rc::new(Cell::new(false));
    let native = Rc::new(RefCell::new(NativeTask {
        future: Box::pin(run_native::<F>(
            settings,
            parent,
            resolver,
            live,
            resolution,
            reports,
            Rc::clone(&stopping),
        )),
        result: None,
    }));
    let admitted = Rc::new(RefCell::new(None));
    let shutdown = Rc::new(RefCell::new(None));
    let task = Rc::clone(&native);
    let admission = Rc::clone(&admitted);
    let shutdown_error = Rc::clone(&shutdown);
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let stopping = scope.clone();
            let cleanup_error = Rc::clone(&shutdown_error);
            let work = async move {
                poll_fn(|cx| task.borrow_mut().poll(cx)).await;
                if let Err(error) = stopping.shutdown() {
                    *cleanup_error.borrow_mut() = Some(Box::new(error) as Failure)
                }
            };
            if let Err(error) = scope.spawn(work) {
                *admission.borrow_mut() = Some(Box::new(error) as Failure);
                if let Err(error) = scope.shutdown() {
                    *shutdown_error.borrow_mut() = Some(Box::new(error) as Failure)
                }
            }
        })
        .await;
    // May also be reached before the task's first poll. In that case no credentials,
    // socket or native sources are constructed; the retained Resolver is retired.
    stopping.set(true);
    poll_fn(|cx| native.borrow_mut().poll(cx)).await;
    let task = native
        .borrow_mut()
        .result
        .take()
        .unwrap_or_else(|| Err("communicator task lost its original completion".into()))
        .err();
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("communicator PROGRAM returned source code {code}").into()),
        Err(e) => Some(Box::new(e) as Failure),
    };
    let admission = admitted.borrow_mut().take();
    let shutdown = shutdown.borrow_mut().take();
    let original = Failures {
        original: admission,
        task: shutdown,
        ..Default::default()
    }
    .finish()
    .err();
    Failures {
        original,
        program,
        task,
        ..Default::default()
    }
    .finish()
}
async fn run_native<F: StatisticsFactory>(
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
        let mut signals = control::Signals::new(parent)?;
        let mut statistics_storage = F::storage();
        let instance = Instance::new();
        let mut pils = gnunet_pils::client::Instance::new();
        let source =
            |name: &'static [u8]| EndpointSource::live(live.clone(), name, resolution.clone());
        let mut section = Vec::new();
        section.try_reserve_exact(settings::section(settings.profile).len())?;
        section.extend_from_slice(settings::section(settings.profile));
        let sources = Sources {
            transport: source(b"transport"),
            pils: source(b"pils"),
            nat: Some(crate::Nat {
                source: source(b"nat"),
                profiles: gnunet_nat_client_host::Profiles::same(
                    gnunet_nat_client_host::native_profile()?,
                ),
                section,
                addresses: settings.nat_addresses,
            }),
        };
        let statistics_clock = sources.transport.clock();
        let (mut bodies, body_bytes) = resources::bodies(&settings)?;
        let tls = credentials::prepare(settings.profile, settings.pair.as_ref())?;
        let bind = settings.bind.socket()?;
        match settings.profile {
            Profile::Raw => {
                let mut loans = Vec::new();
                loans.try_reserve_exact(bodies.len())?;
                for b in &mut bodies {
                    loans.push(Some(&mut b[..]))
                }
                resources::loans(&settings, body_bytes, 0, loans.capacity())?;
                let mut runtime = Runtime::new(
                    &instance,
                    &mut pils,
                    sources,
                    bind,
                    tls,
                    Buffers::Raw(&mut loans),
                    settings.limits,
                )?;
                let statistics_config = statistics::Configuration {
                    profile: settings.profile,
                    live: live.clone(),
                    resolution: resolution.clone(),
                    clock: statistics_clock.clone(),
                    initial: runtime.metrics(),
                };
                serve::<F>(
                    &mut runtime,
                    &mut resolver,
                    &mut signals,
                    &reports,
                    &stopping,
                    &mut statistics_storage,
                    statistics_config,
                )
                .await
            }
            Profile::Http3 => {
                #[cfg(not(feature = "h3-profile"))]
                {
                    Err("HTTP3 foreground requires h3-profile".into())
                }
                #[cfg(feature = "h3-profile")]
                {
                    let mut slots = Vec::new();
                    slots.try_reserve_exact(bodies.len())?;
                    for b in &mut bodies {
                        slots.push(gnunet_transport_quic::h3::Slot::new(&mut b[..]))
                    }
                    let slots_capacity = slots.capacity();
                    let mut loans = Vec::new();
                    loans.try_reserve_exact(settings.limits.backend.connections)?;
                    for group in slots.chunks_mut(settings.limits.h3_polls + 2) {
                        loans.push(Some(group))
                    }
                    resources::loans(&settings, body_bytes, slots_capacity, loans.capacity())?;
                    let mut runtime = Runtime::new(
                        &instance,
                        &mut pils,
                        sources,
                        bind,
                        tls,
                        Buffers::Http3(&mut loans),
                        settings.limits,
                    )?;
                    let statistics_config = statistics::Configuration {
                        profile: settings.profile,
                        live: live.clone(),
                        resolution: resolution.clone(),
                        clock: statistics_clock,
                        initial: runtime.metrics(),
                    };
                    serve::<F>(
                        &mut runtime,
                        &mut resolver,
                        &mut signals,
                        &reports,
                        &stopping,
                        &mut statistics_storage,
                        statistics_config,
                    )
                    .await
                }
            }
        }
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
    signal: Option<io::Result<()>>,
    resolver: Option<Result<(), Failure>>,
}
async fn serve<F: StatisticsFactory>(
    runtime: &mut Runtime<'_, '_, '_, '_, '_>,
    resolver: &mut Driver<64, 256>,
    signals: &mut control::Signals,
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
                let signal = match signals.poll(cx) {
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
