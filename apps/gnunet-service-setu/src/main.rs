//! Standard official SETU SERVICE over its original in-memory SETU/CADET owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod early;
#[cfg(unix)]
mod foreground;
#[cfg(unix)]
mod lifecycle;
#[cfg(unix)]
mod settings;
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[cfg(unix)]
            if error.downcast_ref::<lifecycle::Reported>().is_some() {
                return ExitCode::FAILURE;
            }
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-setu: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Cause> {
    Err("SETU native SERVICE requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<(), Cause> {
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::Environment,
        reporting::Reporter,
        service::{self, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_runtime::{BoundListeners, UnixListenerAccess};
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
    let mut logger = Logger::new(b"setu", std::process::id(), true)?;
    let selected = match service::prepare(
        b"setu",
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
                Err("SETU SERVICE options failed".into())
            };
        }
    };
    #[expect(
        unsafe_code,
        reason = "Only fresh single-threaded exec startup after flushed options, before runtime/NSS/path guards/SETU/native sources; original captured owners remain unique"
    )]
    // SAFETY: sole explicit detach point. No runtime, thread, account lookup,
    // listener path guard, SETU or CADET owner exists; no Logger/clock borrow
    // is held across fork. Selected logfile was lifted above stdio by setup.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(waiting)) => {
            drop(activation);
            drop(parent);
            let result = waiting
                .wait()
                .map(|_| ())
                .map_err(|error| Box::new(error) as Cause);
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
    let cleanup = lifecycle::Cleanup::default();
    let result = (|| -> Result<(), Cause> {
        if let Some(notice) = notice {
            reports.warning(
                "setu.parent.notice",
                format_args!("SETU parent-control declaration: {notice:?}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        let config = service::load_configuration(
            std::sync::Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config)?;
        let user = configured_user(&config, b"setu")?
            .as_deref()
            .map(resolve_user)
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let pending = {
            let _entered = runtime.enter();
            BoundListeners::prepare_before_identity(&config, b"setu", activation)?
        };
        let actual = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.message(
                Level::INFO,
                "setu.identity",
                format_args!("SETU configured process identity: {actual:?}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        let bound = runtime.block_on(pending.finish_with_access(UnixListenerAccess {
            match_uid: settings.access.match_uid,
            match_gid: settings.access.match_gid,
        }))?;
        for error in bound.failures() {
            reports.warning(
                "setu.listener.alternate",
                format_args!("SETU alternate listener: {error}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        runtime.block_on(foreground::run(foreground::Inputs {
            config: &config,
            settings: &settings,
            bound: &bound,
            parent,
            clock: clock.clone(),
            reports: reports.clone(),
            child: &mut child,
            cleanup: cleanup.clone(),
        }))
    })();
    let result = service::retain_diagnostic(cleanup.finish(result), reports.take_error());
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Cause);
    finish(result, &reports)
}
#[cfg(unix)]
fn finish(
    result: Result<(), Cause>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<(), Cause> {
    if let Err(error) = &result {
        reports.message(
            gnunet_program_host::policy::Level::ERROR,
            "setu.failure",
            format_args!("gnunet-service-setu: {error}"),
        );
    }
    gnunet_program_host::service::retain_diagnostic(result, reports.take_error())
        .map_err(|error| Box::new(lifecycle::Reported(error)) as Cause)
}
