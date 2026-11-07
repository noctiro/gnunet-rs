//! Standard CADET SERVICE startup over the existing actual local/peer owners.
#![deny(unsafe_code)]
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod foreground;
#[cfg(unix)]
mod identity;
#[cfg(unix)]
mod local;
#[cfg(unix)]
mod peer;
#[cfg(unix)]
mod settings;
#[cfg(unix)]
mod statistics;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-cadet: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<ExitCode, Failure> {
    Err("CADET SERVICE requires Unix".into())
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
    use gnunet_service_startup::{
        GroupsProfile, InheritedMode, InheritedResources, apply_privileges, configured_user,
        daemon::{self, Branch},
        resolve_user,
    };
    use std::sync::Arc;
    #[expect(
        unsafe_code,
        reason = "Fresh single-thread exec uniquely adopts original inherited descriptors before logger/runtime/path guards or competing owners"
    )]
    // SAFETY: first initialization action in this process; no repeated capture.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(a) => a,
        InheritedResources::CloseAfterBind(_) => {
            return Err("CADET received an incompatible inherited descriptor route".into());
        }
    };
    let parent = captured.parent_control;
    let notice = captured.control_notice;
    let clock = SharedClock::native(4096)?;
    let mut logger = Logger::new(b"cadet", std::process::id(), true)?;
    let selected = match service::prepare(
        b"cadet",
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
        reason = "Once-only explicit detach precedes runtime, account lookup, new listener path guards, PILS/CORE owners or monotime storage"
    )]
    // SAFETY: only original adopted descriptors, selected options/logger and
    // clock exist. Temporary stdio locks have dropped; no task/guard is active.
    let mut child = match unsafe { daemon::split(selected.daemonize_requested()) } {
        Ok(Branch::Parent(status)) => {
            drop(activation);
            drop(parent);
            let result = status
                .wait()
                .map(|_| ())
                .map_err(|e| Box::new(e) as Failure);
            return complete_before_reporter(result, &mut logger, &clock);
        }
        Ok(Branch::Service(child)) => child,
        Err(error) => {
            logger.refresh_process_after_fork();
            return complete_before_reporter(Err(Box::new(error)), &mut logger, &clock);
        }
    };
    if child.is_daemon() {
        logger.refresh_process_after_fork();
    }
    let reporter = Reporter::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = notice {
            reporter.warning(
                "cadet.parent.notice",
                format_args!("CADET original parent-control declaration: {notice:?}"),
            );
        }
        if reporter.failed() {
            return Err(io::Error::other(
                "CADET selected diagnostic source failed before native construction",
            )
            .into());
        }
        let config = service::load_configuration(
            std::sync::Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config)?;
        let user = configured_user(&config, b"cadet")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // Keep original activation sockets and prebind only new TCP endpoints.
        let listeners = {
            let _entered = runtime.enter();
            gnunet_service_runtime::BoundListeners::prepare_before_identity(
                &config, b"cadet", activation,
            )?
        };
        let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reporter.message(
                Level::INFO,
                "cadet.process.identity",
                format_args!("CADET actual configured process identity: {privileges:?}"),
            );
        }
        if reporter.failed() {
            return Err(io::Error::other(
                "CADET selected logger failed during process preparation; original error retained",
            )
            .into());
        }
        let bound = runtime.block_on(listeners.finish_with_access(
            gnunet_service_runtime::UnixListenerAccess {
                match_uid: settings.unix.match_uid,
                match_gid: settings.unix.match_gid,
            },
        ))?;
        runtime.block_on(foreground::run(
            &config,
            bound,
            parent,
            settings,
            Arc::new(clock.clone()),
            reporter.clone(),
            foreground::Ready::new(&mut child, reporter.clone()),
        ))
    })();
    let result = service::retain_diagnostic(result, reporter.take_error());
    let result = child.finish(result).map_err(|e| Box::new(e) as Failure);
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            reporter.message(
                Level::ERROR,
                "cadet.failure",
                format_args!("gnunet-service-cadet: {original}"),
            );
            if let Some(diagnostic) = reporter.take_error() {
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-cadet: {original}; independent selected logging error: {diagnostic}"
                );
            } else if reporter.failed() {
                let _actual = writeln!(io::stderr().lock(), "gnunet-service-cadet: {original}");
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
#[cfg(unix)]
fn complete_before_reporter(
    result: Result<(), Failure>,
    logger: &mut gnunet_program_host::logging::Logger<'_>,
    clock: &gnunet_program_host::shared_clock::SharedClock,
) -> Result<ExitCode, Failure> {
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            if let Err(diagnostic) = gnunet_program_host::service::diagnostic(
                logger,
                clock,
                "cadet.startup.failed",
                gnunet_program_host::policy::Level::ERROR,
                format_args!("gnunet-service-cadet: {original}"),
            ) {
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-cadet: {original}; independent diagnostic: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
