//! Windows identity, activation and parent readiness around the shared service.
use super::{Cause, finish, foreground, lifecycle, settings};
use gnunet_program_host::{
    logging::Logger,
    program::Environment,
    reporting::Reporter,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_runtime::{Activation, BoundListeners};
use gnunet_service_startup::{ParentRole, ReadyStatus};
use std::{fmt, io, time::Duration};

#[derive(Debug)]
struct ReadinessFailure {
    original: Cause,
    notification: Cause,
}
impl fmt::Display for ReadinessFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DHT startup: {}; independent failure notification: {}",
            self.original, self.notification
        )
    }
}
impl std::error::Error for ReadinessFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}

pub(super) fn run() -> Result<(), Cause> {
    #[expect(
        unsafe_code,
        reason = "Sole fresh-process inheritance capture before competing native owners"
    )]
    // SAFETY: first startup action, before logger, files, runtime or threads.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"dht", std::process::id(), true)?;
    let selected = match service::prepare(
        b"dht",
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
                Ok(())
            } else {
                Err("DHT SERVICE options failed".into())
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
            service::detach(&runtime, activation).map_err(|error| error as Cause),
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
    let cleanup = lifecycle::Cleanup::default();
    let result = (|| -> Result<(), Cause> {
        if reports.failed() {
            return Err(io::Error::other("DHT logger failed before initialization").into());
        }
        let config = service::load_configuration(
            std::sync::Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config)?;
        gnunet_service_startup::verify_configured_identity(&config, b"dht")?;
        let bound = if activation.is_empty() {
            runtime.block_on(BoundListeners::bind_configured(
                &config,
                b"dht",
                settings.access.into(),
            ))?
        } else {
            let _entered = runtime.enter();
            BoundListeners::from_activation(activation)?
        };
        for error in bound.failures() {
            reports.warning(
                "dht.listener.alternate",
                format_args!("dht alternate listener: {error}"),
            );
        }
        runtime.block_on(foreground::run(
            foreground::Inputs {
                config: &config,
                settings: &settings,
                bound: &bound,
                parent,
                clock: clock.clone(),
                reports: reports.clone(),
                cleanup: cleanup.clone(),
            },
            async {
                if let Some(writer) = &mut ready {
                    writer.signal(ReadyStatus::AcceptRegistered).await?;
                }
                drop(ready.take());
                Ok(())
            },
        ))
    })();
    let result = service::retain_diagnostic(cleanup.finish(result), reports.take_error());
    let result = match result {
        Err(original) => {
            if let Some(writer) = ready.as_mut().filter(|writer| writer.intent().is_none()) {
                let notice = runtime.block_on(async {
                    tokio::time::timeout(Duration::from_secs(5), async {
                        writer
                            .signal(ReadyStatus::InitializationFailed)
                            .await
                            .map(|_| ())
                            .map_err(|error| Box::new(error) as Cause)
                    })
                    .await
                });
                let notification = match notice {
                    Ok(result) => result,
                    Err(_) => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "DHT failure notification deadline",
                    )
                    .into()),
                };
                match notification {
                    Ok(()) => Err(original),
                    Err(notification) => Err(Box::new(ReadinessFailure {
                        original,
                        notification,
                    }) as Cause),
                }
            } else {
                Err(original)
            }
        }
        Ok(()) => Ok(()),
    };
    finish(result, &reports)
}
