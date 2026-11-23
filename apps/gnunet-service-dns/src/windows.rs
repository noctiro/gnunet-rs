//! Windows activation, configured identity and original parent readiness.
use super::{Failure, finish, foreground, settings, startup_check};
use gnunet_program_host::{
    logging::Logger,
    program::Environment,
    reporting::Reporter,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_runtime::{Activation, BoundListeners, LocalListenerAccess};
use gnunet_service_startup::{ParentRole, ReadyStatus};
use std::process::ExitCode;
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
            "DNS startup: {}; independent failure notification: {}",
            self.original, self.notification
        )
    }
}
impl std::error::Error for ReadinessFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}

pub(super) fn run() -> Result<ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "Sole fresh-process inheritance capture before competing native owners"
    )]
    // SAFETY: first startup action, before logger, files, runtime or threads.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"dns", std::process::id(), true)?;
    let selected = match service::prepare(
        b"dns",
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
            return if successful {
                Ok(ExitCode::SUCCESS)
            } else {
                Ok(ExitCode::FAILURE)
            };
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
    let (parent, mut ready) = match connected {
        Some(parent) => (Some(parent.control), Some(parent.ready)),
        None => (None, None),
    };
    let reports = Reporter::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        startup_check(&reports)?;
        let config = service::load_configuration(
            std::sync::Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config)?;
        settings.statistics.validate()?;
        gnunet_service_startup::verify_configured_identity(&config, b"dns")?;
        let bound = if activation.is_empty() {
            let access = if !settings.unix.match_uid && settings.unix.match_gid {
                LocalListenerAccess::Group
            } else {
                LocalListenerAccess::Owner
            };
            runtime.block_on(BoundListeners::bind_configured(&config, b"dns", access))?
        } else {
            let _entered = runtime.enter();
            BoundListeners::from_activation_with_access(activation, settings.unix)?
        };
        for error in bound.failures() {
            reports.warning(
                "dns.listener.alternate",
                format_args!("dns alternate listener: {error}"),
            );
        }
        runtime.block_on(foreground::run(
            foreground::Inputs {
                config,
                settings,
                bound,
                clock: clock.clone(),
                reports: reports.clone(),
            },
            parent,
            async {
                tokio::time::timeout(Duration::from_secs(5), async {
                    if let Some(writer) = &mut ready {
                        writer.signal(ReadyStatus::AcceptRegistered).await?;
                    }
                    drop(ready.take());
                    Ok::<(), Failure>(())
                })
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "DNS readiness submission deadline")
                })??;
                Ok(())
            },
        ))
    })();
    let result = service::retain_diagnostic(result, reports.take_error());
    let result = match result {
        Err(original) => {
            if let Some(writer) = ready.as_mut().filter(|writer| writer.intent().is_none()) {
                let notice = runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(5), async {
                        writer
                            .signal(ReadyStatus::InitializationFailed)
                            .await
                            .map(|_| ())
                            .map_err(|error| Box::new(error) as Failure)
                    })
                    .await
                });
                let notification = match notice {
                    Ok(result) => result,
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "DNS failure notification deadline",
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
