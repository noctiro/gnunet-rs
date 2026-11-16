//! Windows identity, activation and parent readiness around the shared service.
use super::{Failure, configuration, finish, reporting};
use gnunet_program_host::{
    logging::Logger,
    program::Environment,
    reporting::Reporter,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_runtime::{Activation, BoundListeners};
use gnunet_service_startup::StopSignals;
use gnunet_service_startup::{ParentRole, ReadyStatus};
use gnunet_transport_service_host::{foreground, generation::Reservations, settings::Settings};
use std::{fmt, io, time::Duration};

#[derive(Debug)]
struct ReadinessFailure {
    original: Failure,
    notification: Failure,
}
impl fmt::Display for ReadinessFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TRANSPORT startup: {}; independent failure notification: {}",
            self.original, self.notification
        )
    }
}
impl std::error::Error for ReadinessFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}

pub(super) fn run() -> Result<std::process::ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "Sole fresh-process inheritance capture before competing native owners"
    )]
    // SAFETY: first startup action, before logger, files, runtime or threads.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"transport", std::process::id(), true)?;
    let selected = match service::prepare(
        b"transport",
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
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            });
        }
    };
    let role = captured.parent_control.as_ref().map(|parent| parent.role());
    if selected.daemonize_requested() && role == Some(ParentRole::Supervisor) {
        #[expect(
            unsafe_code,
            reason = "Exclusive startup owns console and stdio before runtime and stop subscriptions"
        )]
        // SAFETY: option output locks ended; no providers or cached stdio owners exist.
        if let Err(error) = unsafe { gnunet_service_startup::daemon::detach_managed() } {
            return finish(Err(error.into()), &Reporter::new(logger, clock));
        }
    }
    let activation = captured
        .activation
        .map(|incoming| Activation::from_imported(incoming.materialize()?))
        .transpose()?
        .unwrap_or_default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if selected.daemonize_requested() && role.is_none() {
        return finish(
            service::detach(&runtime, activation).map_err(|error| error as Failure),
            &Reporter::new(logger, clock),
        );
    }
    let connected = {
        let _entered = runtime.enter();
        captured
            .parent_control
            .map(|parent| parent.register())
            .transpose()?
    };
    let (parent, ready) = match connected {
        Some(parent) => (Some(parent.control), Some(parent.ready)),
        None => (None, None),
    };
    let ready = std::rc::Rc::new(std::cell::RefCell::new(ready));
    let reports = Reporter::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        if reports.failed() {
            return Err(io::Error::other("TRANSPORT logger failed before initialization").into());
        }
        let config = configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        let settings = Settings::read(&config)?;
        gnunet_service_startup::verify_configured_identity(&config, b"transport")?;
        let bound = if activation.is_empty() {
            runtime.block_on(BoundListeners::bind_configured(
                &config,
                b"transport",
                settings.unix.into(),
            ))?
        } else {
            let _entered = runtime.enter();
            BoundListeners::from_activation(activation)?
        };
        for error in bound.failures() {
            reports.warning(
                "transport.listener.alternate",
                format_args!("transport alternate listener: {error}"),
            );
        }
        let stop = {
            let _entered = runtime.enter();
            StopSignals::new(parent)?
        };
        let observations = reporting::notices(reports.clone(), || Ok(()));
        let notification = if ready.borrow().is_some() {
            Some(foreground::Readiness::new(signal_ready(
                ready.clone(),
                ReadyStatus::AcceptRegistered,
            )))
        } else {
            None
        };
        gnunet_service_runtime::private_parents(&settings.stamp_path)?;
        gnunet_service_runtime::private_parents(&settings.dv.store)?;
        let generation = Reservations::open(&settings.stamp_path)?;
        runtime.block_on(foreground::service(
            config,
            clock.clone(),
            settings,
            foreground::Listening {
                bound,
                stop,
                readiness: notification,
            },
            generation,
            observations,
        ))
    })();
    let result = service::retain_diagnostic(result, reports.take_error());
    let result = match result {
        Err(original) => {
            let unstarted = ready
                .borrow()
                .as_ref()
                .is_some_and(|writer| writer.intent().is_none());
            if unstarted {
                let notice = runtime.block_on(async {
                    tokio::time::timeout(
                        Duration::from_secs(5),
                        signal_ready(ready.clone(), ReadyStatus::InitializationFailed),
                    )
                    .await
                });
                let notification = match notice {
                    Ok(result) => result,
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TRANSPORT failure notification deadline",
                    )
                    .into()),
                };
                match notification {
                    Ok(()) => Err(original),
                    Err(notification) => Err(Box::new(ReadinessFailure {
                        original,
                        notification,
                    }) as Failure),
                }
            } else {
                Err(original)
            }
        }
        Ok(()) => Ok(()),
    };
    finish(result, &reports)
}

type Ready = std::rc::Rc<std::cell::RefCell<Option<gnunet_service_startup::ReadyWriter>>>;
async fn signal_ready(original: Ready, status: ReadyStatus) -> Result<(), Failure> {
    std::future::poll_fn(move |cx| -> std::task::Poll<Result<(), Failure>> {
        let mut state = original.borrow_mut();
        let Some(writer) = state.as_mut() else {
            return std::task::Poll::Ready(Err("TRANSPORT original ready owner consumed".into()));
        };
        writer.begin(status)?;
        let result = writer.poll_signal(cx).map(|result| {
            result
                .map(|_| ())
                .map_err(|cause| Box::new(cause) as Failure)
        });
        if matches!(result, std::task::Poll::Ready(Ok(()))) {
            drop(state.take());
        }
        result
    })
    .await
}
