//! Unix capture, detach and privilege boundary around the common service.
use super::{Failure, early, finish, foreground, lifecycle, settings};
use std::{io, process::ExitCode};
pub(super) fn run() -> Result<ExitCode, Failure> {
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::Environment,
        reporting::Reporter,
        service::{self, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_runtime::BoundListeners;
    use gnunet_service_startup::{
        GroupsProfile, apply_privileges, configured_user,
        daemon::{self, Branch},
        resolve_user,
    };
    let early::Inherited {
        activation,
        parent,
        notice,
    } = early::capture()?;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"identity", std::process::id(), true)?;
    let selected = match service::prepare(
        b"identity",
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
    #[expect(
        unsafe_code,
        reason = "Sole detach after flushed option selection and before runtime, NSS, listeners, store, worker or Server"
    )]
    // SAFETY: fresh single-threaded startup; captured original descriptors are
    // unique, all temporary stdio/logger/clock borrows have ended, no active
    // runtime, path guard or worker crosses this one explicit fork point.
    let mut child = match unsafe { daemon::split(selected.daemonize_requested()) } {
        Ok(Branch::Parent(waiting)) => {
            drop(activation);
            drop(parent);
            let result = waiting
                .wait()
                .map(|_| ())
                .map_err(|error| Box::new(error) as Failure);
            let reports = Reporter::new(logger, clock);
            return finish(result, &reports);
        }
        Ok(Branch::Service(child)) => child,
        Err(error) => {
            logger.refresh_process_after_fork();
            let reports = Reporter::new(logger, clock);
            return finish(Err(Box::new(error)), &reports);
        }
    };
    if child.is_daemon() {
        logger.refresh_process_after_fork();
    }
    let reports = Reporter::new(logger, clock.clone());
    let result = (|| -> Result<lifecycle::Terminal, Failure> {
        if let Some(notice) = notice {
            reports.warning(
                "identity.parent.notice",
                format_args!("IDENTITY original parent-control declaration: {notice:?}"),
            );
        }
        if reports.failed() {
            return Err(io::Error::other(
                "IDENTITY selected Logger failed before configuration; original error retained",
            )
            .into());
        }
        let config = service::load_configuration(
            std::sync::Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config)?;
        let user = configured_user(&config, b"identity")?
            .as_deref()
            .map(resolve_user)
            .transpose()?;
        if reports.failed() {
            return Err(io::Error::other(
                "IDENTITY selected Logger failed before native preparation",
            )
            .into());
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let listeners = {
            let _entered = runtime.enter();
            BoundListeners::prepare_before_identity(&config, b"identity", activation)?
        };
        let privilege = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.message(
                Level::INFO,
                "identity.process.identity",
                format_args!("IDENTITY actual configured process identity: {privilege:?}"),
            );
        }
        if reports.failed() {
            return Err(io::Error::other(
                "IDENTITY selected Logger failed during process preparation; original error retained",
            )
            .into());
        }
        let bound = runtime.block_on(listeners.finish_with_access(settings.unix.into()))?;
        // The original SERVICE future is owned by this caller. There is no
        // PROGRAM task/scheduler that can drop it instead of running finally.
        let parent = {
            let _entered = runtime.enter();
            parent
                .map(|control| control.register().map_err(|failure| failure.error))
                .transpose()?
        };
        runtime.block_on(foreground::run(
            foreground::Inputs {
                config,
                settings,
                bound,
                parent,
                clock: std::sync::Arc::new(clock.clone()),
                reports: reports.clone(),
            },
            async {
                child.ready()?;
                Ok(())
            },
        ))
    })();
    let result = match result {
        Ok(terminal) => terminal.finish(reports.take_error()),
        Err(original) => service::retain_diagnostic(Err(original), reports.take_error()),
    };
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Failure);
    finish(result.map(|_| ()), &reports)
}
