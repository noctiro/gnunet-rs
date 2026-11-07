//! One PROGRAM task drives actual TOPOLOGY providers plus the shared Resolver.
use crate::{
    Failure,
    control::Signals,
    early::Inherited,
    reporting::{Cleanup, Reports},
    settings::Settings,
};
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_config::Configuration;
use gnunet_program_host::{program::Prepared, shared_clock::SharedClock};
use gnunet_resolver_broker::Driver;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_topology_host::{Event, Progress, Runtime};
use std::{
    cell::RefCell,
    future::{Future, poll_fn},
    io::{self, Write},
    rc::Rc,
    sync::Arc,
    task::Poll,
};
use tokio::time::Instant;
#[derive(Debug, Default)]
struct Failures {
    program: Option<Failure>,
    task: Option<Failure>,
    native: Option<Failure>,
    resolver: Option<Failure>,
    cleanup: Option<Failure>,
    statistics: Option<Failure>,
    report: Option<io::Error>,
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.program.is_none()
            && self.task.is_none()
            && self.native.is_none()
            && self.resolver.is_none()
            && self.cleanup.is_none()
            && self.statistics.is_none()
            && self.report.is_none()
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TOPOLOGY failures: {self:?}")
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.program
            .as_deref()
            .or(self.task.as_deref())
            .or(self.native.as_deref())
            .or(self.resolver.as_deref())
            .or(self.cleanup.as_deref())
            .or(self.statistics.as_deref())
            .or(self
                .report
                .as_ref()
                .map(|error| error as &dyn std::error::Error))
    }
}
fn observe(reports: &Reports, event: Event<'_>) {
    match event {
        Event::Cleanup(owner, error) => reports.provider_cleanup(owner, error),
        Event::Lost(_) | Event::Io(..) | Event::Port(..) => reports.warning(
            "topology.provider.event",
            format_args!("topology actual event={event:?}"),
        ),
        _ => reports.debug(
            "topology.provider.event",
            format_args!("topology actual event={event:?}"),
        ),
    }
}
struct Owners<'id> {
    runtime: Runtime<'id>,
    statistics: crate::statistics::Forwarder<'id>,
    resolver: Driver<64, 256>,
    resolver_closed: bool,
    reports: Reports,
}
impl Drop for Owners<'_> {
    fn drop(&mut self) {
        if let Err(error) = self
            .runtime
            .close(&mut |event| observe(&self.reports, event))
        {
            self.reports.cleanup(Cleanup::Runtime, Box::new(error));
        }
        if let Some(error) = self.runtime.take_cleanup_error() {
            self.reports
                .cleanup(Cleanup::DeferredRuntime, Box::new(error));
        }
        if let Some(error) = self.statistics.close() {
            self.reports.cleanup(Cleanup::Statistics, error);
        }
        if !self.resolver_closed {
            let result = self.resolver.disconnect();
            self.resolver_closed = true;
            if let Err(error) = result {
                self.reports.cleanup(Cleanup::Resolver, Box::new(error));
            }
        }
    }
}
pub(super) async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    inherited: Inherited,
    reports: Reports,
) -> Result<(), Failure> {
    let config = prepared.main().config.duplicate()?;
    let runtime: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config.duplicate()?);
    let (mut program_context, resolver) = gnunet_resolver_broker::broker::<64, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime.clone(),
    )?;
    let resolution = program_context.resolution_context();
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let task_reports = reports.clone();
    let program = prepared
        .run_scheduled(&mut program_context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stopping = scope.clone();
            let reports = task_reports.clone();
            if let Err(error) = scope.spawn(async move {
                let completed = run(
                    config, settings, inherited, resolver, live, resolution, reports,
                )
                .await;
                *destination.borrow_mut() = Some(completed);
                if let Err(error) = stopping.shutdown() {
                    let prior = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(error)),
                            task: prior,
                            ..Default::default()
                        }
                        .finish(),
                    );
                }
            }) {
                *receiving.borrow_mut() = Some(Err(error.into()));
                if let Err(cleanup) = scope.shutdown() {
                    let prior = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(cleanup)),
                            task: prior,
                            ..Default::default()
                        }
                        .finish(),
                    );
                }
            }
        })
        .await;
    let task = match result.borrow_mut().take() {
        Some(outcome) => outcome.err(),
        None => Some("PROGRAM ended without TOPOLOGY task completion".into()),
    };
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("TOPOLOGY PROGRAM returned source code {code}").into()),
        Err(error) => Some(Box::new(error) as Failure),
    };
    Failures {
        program,
        task,
        ..Default::default()
    }
    .finish()
}
async fn run(
    _config: Configuration,
    settings: Settings,
    inherited: Inherited,
    resolver: Driver<64, 256>,
    live: LiveConfiguration,
    resolution: gnunet_client_host::resolution::SharedResolution,
    reports: Reports,
) -> Result<(), Failure> {
    let mut signals = Signals::new(inherited.parent)?;
    let mut core = gnunet_core_client_host::Instance::new();
    let mut pils = gnunet_pils::client::Instance::new();
    let mut peerstore = gnunet_peerstore_client_host::Instance::new();
    let mut monitor = gnunet_peerstore_client_host::Instance::new();
    let mut statistics_instance = gnunet_ipc_unix::handle::Instance::new();
    let source =
        |section: &'static [u8]| EndpointSource::live(live.clone(), section, resolution.clone());
    let runtime = Runtime::new(
        gnunet_topology_host::Instances {
            core: &mut core,
            pils: &mut pils,
            peerstore: &mut peerstore,
            monitor: &mut monitor,
        },
        gnunet_topology_host::Sources {
            core: source(b"core"),
            pils: source(b"pils"),
            peerstore: source(b"peerstore"),
            transport: source(b"transport"),
        },
        settings.limits,
    )?;
    let statistics = crate::statistics::Forwarder::new(
        &mut statistics_instance,
        live,
        resolution,
        reports.clone(),
    )?;
    let mut owners = Owners {
        runtime,
        statistics,
        resolver,
        resolver_closed: false,
        reports: reports.clone(),
    };
    let startup = Instant::now()
        .checked_add(settings.startup)
        .ok_or("TOPOLOGY startup bound overflow")?;
    let mut ready = false;
    let mut cursor = 0usize;
    let outcome = loop {
        if reports.failed() {
            break Ok(());
        }
        owners.statistics.refresh(owners.runtime.statistics());
        if reports.failed() {
            break Ok(());
        }
        let current = owners.runtime.readiness();
        if !ready && current.complete() {
            let output = {
                let mut out = io::stdout().lock();
                writeln!(out,"READY topology wire=0.29.1 core=observed pils=verified-current peerstore=actual-sync transport=attached signature-address-coverage={:?} hidden-tasks=0",settings.limits.profile.coverage()).and_then(|()|out.flush())
            };
            if let Err(error) = output {
                break Err(Box::new(error) as Failure);
            }
            ready = true;
        }
        enum Turn {
            Signal,
            Resolver,
            Statistics,
            Runtime(Progress),
            Logging,
        }
        let wait = (!ready).then_some(startup);
        let (runtime, resolver, statistics) = (
            &mut owners.runtime,
            &mut owners.resolver,
            &mut owners.statistics,
        );
        let mut resolving = std::pin::pin!(resolver.drive_waiting(wait, |event| reports.debug(
            "topology.resolver.event",
            format_args!("topology Resolver={event:?}")
        )));
        let step = poll_fn(|cx| {
            reports.register(cx);
            if reports.failed() {
                return Poll::Ready(Ok(Turn::Logging));
            }
            if let Poll::Ready(result) = signals.poll(cx) {
                return Poll::Ready(
                    result
                        .map(|()| Turn::Signal)
                        .map_err(|e| Box::new(e) as Failure),
                );
            }
            for n in 0..3 {
                if (cursor + n).is_multiple_of(3) {
                    if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                        return Poll::Ready(
                            result
                                .map(|_| Turn::Resolver)
                                .map_err(|e| Box::new(e) as Failure),
                        );
                    }
                } else if (cursor + n) % 3 == 1 {
                    if let Poll::Ready(result) =
                        runtime.poll(cx, wait, &mut |event| observe(&reports, event))
                    {
                        return Poll::Ready(
                            result
                                .map(Turn::Runtime)
                                .map_err(|e| Box::new(e) as Failure),
                        );
                    }
                } else if statistics.poll(cx, wait).is_ready() {
                    return Poll::Ready(Ok(Turn::Statistics));
                }
            }
            Poll::Pending
        })
        .await;
        cursor = (cursor + 1) % 3;
        match step{Ok(Turn::Signal|Turn::Logging|Turn::Runtime(Progress::Stopped))=>break Ok(()),Ok(Turn::Runtime(Progress::WaitDeadline))if !ready=>break Err("TOPOLOGY actual source readiness did not complete before original startup deadline".into()),Ok(Turn::Resolver|Turn::Statistics|Turn::Runtime(_))=>{},Err(error)=>break Err(error)}
    };
    // Cleanup is clock-independent and closes every original provider before logs.
    let native = owners.runtime.close(&mut |event| observe(&reports, event));
    let cleanup = owners.runtime.take_cleanup_error();
    let statistics = owners.statistics.close();
    let resolver = owners.resolver.disconnect();
    owners.resolver_closed = true;
    let report = {
        let mut out = io::stdout().lock();
        writeln!(out,"STOPPED topology ready-observed={ready} original-sources=closed remote-delivery=not-claimed store-results=actual-events-only").and_then(|()|out.flush())
    };
    Failures {
        task: outcome.err(),
        native: native.err().map(|e| Box::new(e) as Failure),
        cleanup: cleanup.map(|e| Box::new(e) as Failure),
        statistics,
        resolver: resolver.err().map(|e| Box::new(e) as Failure),
        report: report.err(),
        ..Default::default()
    }
    .finish()
}
