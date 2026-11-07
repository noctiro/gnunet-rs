//! Standard official REVOCATION SERVICE and original process/worker owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod early;
#[cfg(unix)]
mod foreground;
#[cfg(unix)]
mod settings;
#[cfg(unix)]
mod statistics;
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            // Only errors before the selected service Reporter exists reach here.
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-revocation: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<ExitCode, Failure> {
    Err("native REVOCATION SERVICE requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<ExitCode, Failure> {
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::Environment,
        reporting::Reporter,
        service::{self, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_runtime::{BoundListeners, private_parents};
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
    let clock = SharedClock::native(1024)?;
    let mut logger = Logger::new(b"revocation", std::process::id(), true)?;
    let selected = match service::prepare(
        b"revocation",
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
        reason = "Fresh single-thread entry after option/log selection, before runtime/NSS/path/store/worker ownership"
    )]
    // SAFETY: option preparation released temporary stdio locks. Only original
    // captured FDs, selected Logger and unlocked SharedClock exist at this point.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(waiting)) => {
            drop(activation);
            drop(parent);
            return finish_logger(
                waiting
                    .wait()
                    .map(|_| ())
                    .map_err(|e| Box::new(e) as Failure),
                &mut logger,
                &clock,
            );
        }
        Ok(Branch::Service(child)) => child,
        Err(error) => {
            logger.refresh_process_after_fork();
            return finish_logger(Err(Box::new(error)), &mut logger, &clock);
        }
    };
    if child.is_daemon() {
        logger.refresh_process_after_fork();
    }
    let reports = Reporter::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = notice {
            reports.warning(
                "revocation.parent",
                format_args!("revocation original parent-control declaration: {notice:?}"),
            );
            startup_check(&reports)?;
        }
        let config = service::load_configuration(
            std::sync::Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config)?;
        settings.statistics.validate()?;
        let user = configured_user(&config, b"revocation")?
            .as_deref()
            .map(resolve_user)
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let listeners = {
            let _entered = runtime.enter();
            BoundListeners::prepare_before_identity(&config, b"revocation", activation)?
        };
        let identity = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.message(
                Level::INFO,
                "revocation.identity",
                format_args!("revocation configured process identity: {identity:?}"),
            );
            startup_check(&reports)?;
        }
        let bound = runtime.block_on(listeners.finish_with_access(
            gnunet_service_runtime::UnixListenerAccess {
                match_uid: settings.unix.match_uid,
                match_gid: settings.unix.match_gid,
            },
        ))?;
        for error in bound.failures() {
            reports.warning(
                "revocation.listener.alternate",
                format_args!("revocation alternate listener: {error}"),
            );
        }
        startup_check(&reports)?;
        // All adopted/TCP/new-Unix listeners exist under the correct ownership
        // before the marked inventory, its actual commit or either worker opens.
        private_parents(&settings.store)?;
        runtime.block_on(foreground::run(foreground::Inputs {
            config,
            settings,
            bound,
            parent,
            clock,
            reports: reports.clone(),
            child: &mut child,
        }))
    })();
    let result = service::retain_diagnostic(result, reports.take_error());
    let result = child.finish(result).map_err(|e| Box::new(e) as Failure);
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            reports.message(
                Level::ERROR,
                "revocation.failure",
                format_args!("gnunet-service-revocation: {original}"),
            );
            // A selected destination failure is an emergency reporting boundary,
            // never a substitute for the original service/cleanup error objects.
            if reports.failed() {
                let diagnostic = reports.take_error();
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-revocation: {original}; independent final logging failure: {diagnostic:?}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
#[cfg(unix)]
fn startup_check(reports: &gnunet_program_host::reporting::Reporter) -> Result<(), Failure> {
    if let Some(error) = reports.take_error() {
        return Err(Box::new(error));
    }
    if reports.failed() {
        return Err("REVOCATION selected diagnostic destination already failed".into());
    }
    Ok(())
}
#[cfg(unix)]
fn finish_logger(
    result: Result<(), Failure>,
    logger: &mut gnunet_program_host::logging::Logger<'_>,
    clock: &gnunet_program_host::shared_clock::SharedClock,
) -> Result<ExitCode, Failure> {
    use gnunet_program_host::{policy::Level, service};
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            if let Err(diagnostic) = service::diagnostic(
                logger,
                clock,
                "revocation.startup.failure",
                Level::ERROR,
                format_args!("gnunet-service-revocation: {original}"),
            ) {
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-revocation: {original}; independent logging failure: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
