//! Native Windows capture, identity, detach and original parent readiness.
use crate::{
    Failure, finish, foreground,
    lifecycle::{Cleanup, Stage},
    settings::Settings,
};
use gnunet_program_host::{
    logging::Logger,
    program::Environment,
    reporting::Reporter,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_runtime::{Activation, BoundListeners};
use gnunet_service_startup::{ParentRole, ReadyStatus};
use std::{io, process::ExitCode, sync::Arc, time::Duration};
pub(super) fn run() -> Result<ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "The fresh executable exclusively captures original inherited resources before logging, runtime or other handle ownership"
    )]
    // SAFETY: first and sole inheritance transfer in this fresh process.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
    if std::env::var_os("GNUNET_VPN_TUN_FD").is_some() {
        return Err(
            "Windows uses an explicit Wintun session; Unix TUN FD inheritance is unavailable"
                .into(),
        );
    }
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"vpn", std::process::id(), true)?;
    let selected = match service::prepare(
        b"vpn",
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
    let role = captured.parent_control.as_ref().map(|parent| parent.role());
    if selected.daemonize_requested() && role == Some(ParentRole::Supervisor) {
        #[expect(
            unsafe_code,
            reason = "Exclusive startup owns console and stdio before runtime, providers and termination subscriptions"
        )]
        // SAFETY: option-output borrows ended; no provider or cached stdio owner.
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
    let cleanup = Cleanup::default();
    let result = (|| -> Result<(), Failure> {
        if reports.failed() {
            return Err(io::Error::other("VPN logger failed before initialization").into());
        }
        let config = service::load_configuration(
            Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = Settings::read(&config)?;
        gnunet_service_startup::verify_configured_identity(&config, b"vpn")?;
        let bound = if activation.is_empty() {
            runtime.block_on(BoundListeners::bind_configured(
                &config,
                b"vpn",
                settings.direct_local_access(&config)?,
            ))?
        } else {
            let _entered = runtime.enter();
            BoundListeners::from_activation_with_access(activation, settings.service.unix)?
        };
        for error in bound.failures() {
            reports.warning(
                "vpn.listener.alternate",
                format_args!("VPN alternate listener: {error}"),
            );
        }
        runtime.block_on(foreground::run(
            foreground::Inputs {
                config: &config,
                settings: &settings,
                bound: &bound,
                parent,
                clock: Arc::new(clock.clone()),
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
    let result = service::retain_diagnostic(result, reports.take_error());
    if result.is_err()
        && let Some(writer) = ready.as_mut().filter(|writer| writer.intent().is_none())
    {
        let notification = runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                writer.signal(ReadyStatus::InitializationFailed),
            )
            .await
        });
        match notification {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => cleanup.retain(Stage::Readiness, Box::new(error)),
            Err(_) => cleanup.retain(
                Stage::Readiness,
                Box::new(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "VPN failure notification deadline",
                )),
            ),
        }
    }
    finish(cleanup.finish(result), &reports)
}
