//! Safe shared foreground; each binary performs once-only inherited-FD capture
//! before logging/config/runtime, then supplies that original owner here.
use crate::{
    manager::Failure,
    server::{self, Event, Mode, Progress, Server},
    startup::{Drive, Turn, turn},
};
use gnunet_config::Configuration;
use gnunet_program_host::{program::Prepared, reporting::Reporter, shared_clock::SharedClock};
use gnunet_resolver_broker::LiveConfiguration;
use gnunet_service_runtime::{
    Activation, BoundListeners, clock::RuntimeClock, service::ShutdownMode,
};
use gnunet_service_startup::ParentControl;
use std::{
    cell::RefCell,
    future::poll_fn,
    io::{self, Write},
    rc::Rc,
    sync::Arc,
    task::Poll,
};
use tokio::time::Instant;
mod process;
mod resolver;
mod signals;
pub use crate::startup::Settings;
pub use process::main;
use resolver::Resolver;
use signals::Signals;
/// Once-adopted parent descriptors supplied by the first operation in binary main.
pub struct Inherited {
    /// Actual listener inheritance, never copied raw descriptors.
    pub activation: Activation,
    /// Original optional parent-control source.
    pub parent: Option<ParentControl>,
}
fn diagnostic(reports: &Reporter, args: std::fmt::Arguments<'_>) {
    reports.warning("nat.activity", args);
}
fn observe(event: Event, reports: &Reporter) {
    match event {
        Event::Socket(gnunet_service_runtime::accepted::SocketEvent::Failed(e))
            if e.is_emfile() => {}
        Event::Socket(e) => diagnostic(reports, format_args!("NAT socket: {e:?}")),
        Event::AdmissionFailed { peer, error } => diagnostic(
            reports,
            format_args!("NAT original admission {peer:?}: {error}"),
        ),
        Event::Closed { source, cause } => diagnostic(
            reports,
            format_args!("NAT source={} closed: {cause:?}", source.serial()),
        ),
        Event::Discovery(crate::manager::Event::Failed { job, source, error }) => diagnostic(
            reports,
            format_args!("NAT job={job} source={source:?} failed: {error}"),
        ),
        Event::Discovery(crate::manager::Event::MappingUnknown { source, port }) => diagnostic(
            reports,
            format_args!(
                "NAT original source={} external-port={port} mapping outcome remains unknown",
                source.serial()
            ),
        ),
        Event::Discovery(crate::manager::Event::Helper(e)) => {
            diagnostic(reports, format_args!("NAT helper: {e:?}"))
        }
        _ => {}
    }
}
#[derive(Debug, Default)]
struct Failures {
    program: Option<Failure>,
    task: Option<Failure>,
    resolver: Option<Failure>,
    retirement: Option<Failure>,
    cleanup_report: Option<server::Report>,
    report: Option<io::Error>,
}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.program.is_none()
            && self.task.is_none()
            && self.resolver.is_none()
            && self.retirement.is_none()
            && self.cleanup_report.is_none()
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
        f.write_str("NAT foreground failures:")?;
        for (label, error) in [
            ("PROGRAM", self.program.as_deref()),
            ("task", self.task.as_deref()),
            ("Resolver cleanup", self.resolver.as_deref()),
            ("helper retirement", self.retirement.as_deref()),
        ] {
            if let Some(e) = error {
                write!(f, " {label}=({e})")?;
            }
        }
        if let Some(e) = &self.report {
            write!(f, " report=({e})")?;
        }
        if let Some(report) = &self.cleanup_report {
            write!(f, " cleanup remains unestablished: {report:?}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.program
            .as_deref()
            .or(self.task.as_deref())
            .or(self.resolver.as_deref())
            .or(self.retirement.as_deref())
            .or(self.report.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
struct Owners {
    server: Server,
    resolver: Resolver,
    reports: Reporter,
    done: bool,
}
impl Drop for Owners {
    fn drop(&mut self) {
        if !self.done {
            self.server
                .abort(&mut |event| observe(event, &self.reports));
            self.resolver.retain_report(self.server.report());
            diagnostic(
                &self.reports,
                format_args!(
                    "NAT dropped: original sources/helper stop requested; router cleanup/reap unestablished, report={:?}",
                    self.server.report()
                ),
            );
        }
    }
}
/// Shared actual PROGRAM task and original Resolver/clock; no constructor claims
/// NAT connectivity. READY is only successful local listener/owner setup.
pub async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
    inherited: Inherited,
    mode: Mode,
    reports: Reporter,
) -> Result<(), Failure> {
    let config = prepared.main().config.duplicate()?;
    let runtime_clock: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config.duplicate()?);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<64, 1024>(
        live,
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        runtime_clock.clone(),
    )?;
    let deferred = Rc::new(RefCell::new(resolver::Deferred::default()));
    let resolver = Resolver::new(resolver, deferred.clone());
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stop = scope.clone();
            if let Err(error) = scope.spawn(async move {
                let outcome = run(Inputs {
                    config,
                    settings,
                    inherited,
                    mode,
                    resolver,
                    clock: runtime_clock,
                    reports,
                })
                .await;
                *destination.borrow_mut() = Some(outcome);
                if let Err(error) = stop.shutdown() {
                    let task = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(error)),
                            task,
                            ..Failures::default()
                        }
                        .finish(),
                    );
                }
            }) {
                *receiving.borrow_mut() = Some(Err(error.into()));
                if let Err(error) = scope.shutdown() {
                    let task = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(error)),
                            task,
                            ..Failures::default()
                        }
                        .finish(),
                    );
                }
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without NAT task completion".into()))
        .err();
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("NAT PROGRAM returned {code}").into()),
        Err(e) => Some(Box::new(e) as Failure),
    };
    let deferred = std::mem::take(&mut *deferred.borrow_mut());
    Failures {
        program,
        task,
        resolver: deferred.resolver.map(|error| Box::new(error) as Failure),
        cleanup_report: deferred.report,
        ..Failures::default()
    }
    .finish()
}
struct Inputs {
    config: Configuration,
    settings: Settings,
    inherited: Inherited,
    mode: Mode,
    resolver: Resolver,
    clock: Arc<dyn RuntimeClock>,
    reports: Reporter,
}
async fn run(input: Inputs) -> Result<(), Failure> {
    let Inputs {
        config,
        settings,
        inherited,
        mode,
        mut resolver,
        clock,
        reports,
    } = input;
    let initialized = (|| -> Result<_, Failure> {
        let signals = Signals::new(inherited.parent)?;
        let shared = resolver.driver.context().resolution_context();
        let server = Server::new(
            config.duplicate()?,
            settings.discovery,
            settings.core,
            settings.native,
            server::Ports {
                options: settings.options.clone(),
                unix: settings.unix,
                clock,
                resolver: shared,
            },
            mode,
            Default::default(),
        )?;
        Ok((signals, server))
    })();
    let (mut signals, server) = match initialized {
        Ok(v) => v,
        Err(task) => {
            let cleanup = resolver.close().err().map(|e| Box::new(e) as Failure);
            return Failures {
                task: Some(task),
                resolver: cleanup,
                ..Failures::default()
            }
            .finish();
        }
    };
    let mut owners = Owners {
        server,
        resolver,
        reports: reports.clone(),
        done: false,
    };
    #[cfg(unix)]
    let binding = BoundListeners::bind(&config, mode.service(), inherited.activation).await;
    #[cfg(windows)]
    let binding = if inherited.activation.is_empty() {
        BoundListeners::bind(&config, mode.service(), inherited.activation).await
    } else {
        BoundListeners::from_activation_with_access(inherited.activation, settings.unix)
            .map_err(Into::into)
    };
    let bound = match binding {
        Ok(b) => b,
        Err(e) => {
            owners.server.abort(&mut |event| observe(event, &reports));
            let cleanup = owners
                .resolver
                .close()
                .err()
                .map(|e| Box::new(e) as Failure);
            owners.done = true;
            return Failures {
                task: Some(e),
                resolver: cleanup,
                ..Failures::default()
            }
            .finish();
        }
    };
    for error in bound.failures() {
        diagnostic(&reports, format_args!("NAT alternate listener: {error}"));
    }
    let ready: Result<bool, Failure> = async {
        let stopped = poll_fn(|cx| {
            Poll::Ready(match signals.stop.poll_stop(cx) {
                Poll::Ready(result) => result.map(|()| true),
                Poll::Pending => Ok(false),
            })
        })
        .await?;
        if stopped {
            return Ok(false);
        }
        if reports.failed() {
            return Err("NAT selected Logger failed before readiness".into());
        }
        {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "READY {} wire=0.29.1 local-listeners=yes connectivity=unproven backend=rust",
                String::from_utf8_lossy(mode.service())
            )
            .and_then(|()| out.flush())?;
        }
        signals.ready(&reports).await?;
        Ok(true)
    }
    .await;
    let outcome = if let Err(error) = ready {
        Err(error)
    } else if matches!(ready, Ok(false)) {
        Ok(())
    } else {
        async {
            let listeners = bound.listeners();
            let mut until = None;
            let mut resolver_first = false;
            loop {
                let next = turn(
                    Drive {
                        server: &mut owners.server,
                        resolver: &mut owners.resolver.driver,
                        listeners: &listeners,
                        until,
                        resolver_first,
                    },
                    |cx| {
                        reports.register(cx);
                        if reports.failed() {
                            return Poll::Ready(Err(
                                "NAT selected Logger failed during service operation".into(),
                            ));
                        }
                        signals.stop.poll_stop(cx).map_err(Into::into)
                    },
                    |event| observe(event, &reports),
                    |event| diagnostic(&reports, format_args!("NAT Resolver: {event:?}")),
                )
                .await;
                resolver_first = !resolver_first;
                match next {
                    Ok(Turn::Stop)
                        if until.is_none() && settings.options.shutdown == ShutdownMode::Soft =>
                    {
                        owners.server.request_shutdown(ShutdownMode::Soft);
                        until = Some(
                            Instant::now()
                                .checked_add(settings.grace)
                                .ok_or("NAT shutdown bound overflow")?,
                        );
                    }
                    Ok(Turn::Stop | Turn::Server(Progress::WaitDeadline)) => {
                        owners.server.abort(&mut |event| observe(event, &reports));
                        break Ok(());
                    }
                    Ok(Turn::Server(Progress::Stopped)) => break Ok(()),
                    Ok(Turn::Resolver | Turn::Server(Progress::Activity)) => {}
                    Err(e) => break Err(e),
                }
            }
        }
        .await
    };
    owners.server.abort(&mut |event| observe(event, &reports));
    let retirement = poll_fn(|cx| {
        owners
            .server
            .poll_retirement(cx, &mut |event| observe(event, &reports))
    })
    .await;
    let report = owners.server.report();
    let cleanup = owners.resolver.close();
    owners.done = true;
    drop(owners);
    drop(bound);
    let report_io = {
        let mut out = io::stdout().lock();
        writeln!(
            out,
            "STOPPED {} actual={report:?} resolver={cleanup:?}",
            String::from_utf8_lossy(mode.service())
        )
        .and_then(|()| out.flush())
    };
    Failures {
        task: outcome.err(),
        retirement: retirement.err(),
        cleanup_report: (report.pending != 0 || report.unresolved != 0).then_some(report),
        resolver: cleanup.err().map(|e| Box::new(e) as Failure),
        report: report_io.err(),
        ..Failures::default()
    }
    .finish()
}
