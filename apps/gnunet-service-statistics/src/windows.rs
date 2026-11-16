//! Native Windows startup around the shared STATISTICS host and official store.
use super::{Failure, PhaseFailure, aggregate, complete, host, reporting, settings};
use gnunet_program_host::{
    logging::Logger,
    program::Environment,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_runtime::{Activation, BoundListeners};
use gnunet_service_startup::{ParentRole, ReadyStatus};
use std::{io, process::ExitCode, sync::Arc};

pub(super) fn run() -> Result<ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "First fresh-process operation before logger, filesystem/runtime or competing native ownership; failure exits startup"
    )]
    // SAFETY: exclusive offered inheritance is captured before unrelated owners.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"statistics", std::process::id(), true)?;
    let selected = match service::prepare(
        b"statistics",
        &gnunet::config::ProjectData::default(),
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
            reason = "Fresh service after flushed option output, before providers/runtime/handlers; no cached standard handles or competing console mutation"
        )]
        // SAFETY: temporary output locks have ended; startup owns console/stdio.
        if let Err(error) = unsafe { gnunet_service_startup::daemon::detach_managed() } {
            return complete(Err(Box::new(error)), &mut logger, &clock);
        }
    }
    // Native import may initialize provider threads; managed detachment finishes
    // first. No original listener is registered before this target-only import.
    let activation = captured
        .activation
        .map(|incoming| Activation::from_imported(incoming.materialize()?))
        .transpose()?
        .unwrap_or_default();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    if selected.daemonize_requested() && role.is_none() {
        return complete(
            service::detach(&runtime, activation).map_err(|error| error as Failure),
            &mut logger,
            &clock,
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
    let result = {
        let reports = reporting::Reports::new(&mut logger, &clock);
        let mut stage = "configuration";
        let result = (|| -> Result<(), Failure> {
            let config = settings::configuration(selected.configuration())?;
            stage = "clock configuration";
            clock.testing_skew(&config)?;
            stage = "settings";
            let settings = settings::Settings::read(&config)?;
            stage = "process identity";
            gnunet_service_startup::verify_configured_identity(&config, b"statistics")?;
            stage = "listener binding";
            let bound = if activation.is_empty() {
                runtime.block_on(BoundListeners::bind_configured(
                    &config,
                    b"statistics",
                    settings.access.into(),
                ))?
            } else {
                let _entered = runtime.enter();
                BoundListeners::from_activation(activation)?
            };
            for error in bound.failures() {
                reports.warning(
                    "statistics.listener.alternate",
                    format_args!("statistics alternate listener: {error}"),
                );
            }
            reports.startup_check()?;
            stage = "service";
            runtime.block_on(host::run(
                host::Inputs {
                    bound: &bound,
                    parent,
                    settings: &settings,
                    clock: Arc::new(clock.clone()),
                    reports: &reports,
                },
                || async {
                    if let Some(writer) = &mut ready {
                        writer
                            .signal(ReadyStatus::AcceptRegistered)
                            .await
                            .map_err(|error| gnunet::ipc::IpcError::Io(io::Error::other(error)))?;
                    }
                    // Preserve control as the service lifetime owner; successful
                    // ready admission does not retain a dead one-shot write outbox.
                    drop(ready.take());
                    Ok(())
                },
            ))
        })()
        .map_err(|source| Box::new(PhaseFailure { stage, source }) as Failure);
        service::retain_diagnostic(result, reports.take_failure())
    };
    let result = if result.is_err()
        && let Some(writer) = ready.as_mut().filter(|writer| writer.intent().is_none())
    {
        match runtime.block_on(writer.signal(ReadyStatus::InitializationFailed)) {
            Ok(_) => result,
            Err(error) => aggregate(result, vec![Box::new(error)]),
        }
    } else {
        result
    };
    complete(result, &mut logger, &clock)
}
