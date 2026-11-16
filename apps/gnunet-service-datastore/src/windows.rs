//! Native Windows bootstrap around the shared DATASTORE worker and service loop.
use super::{Failure, aggregate, complete, foreground, reporting, settings};
use gnunet_datastore_host::backend::Store;
use gnunet_program_host::{
    logging::Logger,
    program::Environment,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_runtime::{Activation, BoundListeners, private_parents};
use gnunet_service_startup::{ParentRole, ReadyStatus};
use std::{io, process::ExitCode, sync::Arc};

pub(super) fn run() -> Result<ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "Fresh process captures offered inheritance before filesystem, runtime or competing native owners"
    )]
    // SAFETY: this is the first initialization and capture; failure exits startup.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"datastore", std::process::id(), true)?;
    let selected = match service::prepare(
        b"datastore",
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
            reason = "Exclusive startup owns console and stdio before providers, runtime or signal subscriptions"
        )]
        // SAFETY: temporary output locks are released; no cached competing stdio owners exist.
        if let Err(error) = unsafe { gnunet_service_startup::daemon::detach_managed() } {
            return complete(Err(Box::new(error)), &mut logger, &clock);
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
        let result = (|| -> Result<(), Failure> {
            let config = settings::configuration(selected.configuration())?;
            clock.testing_skew(&config)?;
            let settings = settings::Settings::read(&config)?;
            // Windows keeps its primary token. Refuse an unmatched configured
            // account before binding listeners or opening writable storage.
            gnunet_service_startup::verify_configured_identity(&config, b"datastore")?;
            let bound = if activation.is_empty() {
                runtime.block_on(BoundListeners::bind_configured(
                    &config,
                    b"datastore",
                    settings.access.into(),
                ))?
            } else {
                let _entered = runtime.enter();
                BoundListeners::from_activation(activation)?
            };
            for error in bound.failures() {
                reports.warning(
                    "datastore.listener.alternate",
                    format_args!("datastore alternate listener: {error}"),
                );
            }
            reports.startup_check()?;
            private_parents(&settings.directory)?;
            let backend = Store::open(&settings.directory, settings.backend)?;
            reports.startup_check()?;
            runtime.block_on(foreground::run(
                foreground::Inputs {
                    bound: &bound,
                    parent,
                    backend,
                    settings: &settings,
                    clock: Arc::new(clock.clone()),
                    reports: &reports,
                },
                || async {
                    if let Some(writer) = &mut ready {
                        writer.signal(ReadyStatus::AcceptRegistered).await?;
                    }
                    drop(ready.take());
                    Ok(())
                },
            ))
        })();
        let cleanup = reports
            .take_failure()
            .map(|error| Box::new(error) as Failure)
            .into_iter()
            .collect();
        aggregate(result, cleanup)
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
