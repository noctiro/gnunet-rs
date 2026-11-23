//! Windows Resolver composition over native identity, endpoints and parent control.
use super::{Diagnostics, Failure, complete};
use gnunet_program_host::{
    logging::Logger,
    policy::Level,
    program::Environment,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_resolver_host::startup;
use std::{
    error::Error,
    fmt,
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
    task::Poll,
};
pub(super) fn run() -> Result<ExitCode, Failure> {
    use gnunet_service_startup::ReadyStatus;
    #[expect(
        unsafe_code,
        reason = "First fresh-process action before files, runtime or native/CRT ownership; inherited metadata is exclusively offered by the launcher"
    )]
    // SAFETY: capture precedes every competing native owner; failures exit startup.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"resolver", std::process::id(), true)?;
    let selected = match service::prepare(
        b"resolver",
        &gnunet_config::ProjectData::default(),
        std::env::args_os(),
        &Environment::capture(),
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )? {
        Preparation::Ready(selected) => selected,
        Preparation::Stopped { successful } => {
            return Ok(if successful {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            });
        }
    };
    let parent_role = captured.parent_control.as_ref().map(|parent| parent.role());
    if selected.daemonize_requested()
        && parent_role == Some(gnunet_service_startup::ParentRole::Supervisor)
    {
        #[expect(
            unsafe_code,
            reason = "Fresh process before runtime/handlers/registration; option output is flushed, temporary locks released and no process stderr capability or cached handle is held"
        )]
        // SAFETY: startup owns stream/console mutation. Selected logging holds a
        // separate file owner and no asynchronous task or handler has started.
        if let Err(error) = unsafe { gnunet_service_startup::daemon::detach_managed() } {
            return complete(Err(Box::new(error)), &mut logger, &clock);
        }
    }
    let activation = captured
        .activation
        .map(|incoming| gnunet_service_runtime::Activation::from_imported(incoming.materialize()?))
        .transpose()?
        .unwrap_or_default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if selected.daemonize_requested() && parent_role.is_none() {
        return complete(
            service::detach(&runtime, activation).map_err(|error| error as Failure),
            &mut logger,
            &clock,
        );
    }
    let parent = {
        let _entered = runtime.enter();
        captured
            .parent_control
            .map(|parent| parent.register())
            .transpose()?
    };
    let (mut parent_control, mut ready) = match parent {
        Some(parent) => (Some(parent.control), Some(parent.ready)),
        None => (None, None),
    };
    let diagnostics = Diagnostics::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        let config = startup::configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        startup::verify_configured_identity(&config)?;
        let access = startup::unix_access(&config)?;
        let bound = if activation.is_empty() {
            runtime.block_on(gnunet_service_runtime::BoundListeners::bind_configured(
                &config,
                b"resolver",
                access.into(),
            ))?
        } else {
            let _entered = runtime.enter();
            gnunet_service_runtime::BoundListeners::from_activation_with_access(activation, access)?
        };
        runtime.block_on(async {
            let mut signals = gnunet_service_runtime::signals::Termination::new()?;
            let shutdown = std::future::poll_fn(|cx| {
                if diagnostics.failed(cx) { return Poll::Ready(Ok(())); }
                if let Some(control) = &mut parent_control {
                    match control.poll_signal(cx) {
                        Poll::Ready(Ok(Some(2 | 15))) => return Poll::Ready(Ok(())),
                        Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                        Poll::Ready(Ok(None)) => parent_control = None,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                        Poll::Pending => {},
                    }
                }
                signals.poll_stop(cx)
            });
            let report = startup::serve_standalone(
                &config, bound, Arc::new(clock.clone()),
                |diagnostic| diagnostics.machine_input(diagnostic),
                |bound| {
                    let preparation = diagnostics.ready(bound);
                    async {
                        preparation?;
                        if let Some(ready) = &mut ready {
                            ready.signal(ReadyStatus::AcceptRegistered).await.map_err(io::Error::other)?;
                        }
                        // Control retains the physical connection through write
                        // completion. Release the one-shot outbox so control EOF
                        // can retire the last pipe owner during normal service life.
                        drop(ready.take());
                        Ok(())
                    }
                }, shutdown,
                |event| {
                    if matches!(&event, gnunet_resolver_host::SocketEvent::Failed(error) if error.is_emfile()) { return; }
                    let (level, site) = if matches!(&event, gnunet_resolver_host::SocketEvent::Failed(_)) {
                        (Level::WARNING, "resolver.socket.failed")
                    } else { (Level::DEBUG, "resolver.socket.activity") };
                    diagnostics.observe(site, level, format_args!("resolver socket: {event:?}"));
                },
            ).await;
            let report = service::retain_diagnostic(report, diagnostics.take_failure())?;
            let mut output = io::stdout().lock();
            writeln!(output, "STOPPED {report:?}")?;
            output.flush()?;
            Ok::<_, Failure>(())
        })
    })();
    let mut result = service::retain_diagnostic(result, diagnostics.take_failure());
    if result.is_err()
        && let Some(writer) = ready.as_mut().filter(|writer| writer.intent().is_none())
        && let Err(readiness) = runtime.block_on(writer.signal(ReadyStatus::InitializationFailed))
        && let Err(original) = result
    {
        result = Err(Box::new(StartupFailure {
            original,
            readiness,
        }));
    }
    let mut logger = diagnostics.logger.into_inner();
    complete(result, &mut logger, &clock)
}
#[derive(Debug)]
struct StartupFailure {
    original: Failure,
    readiness: gnunet_service_startup::ReadyFailure,
}
impl fmt::Display for StartupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; independent startup status failure: {}",
            self.original, self.readiness
        )
    }
}
impl Error for StartupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}
