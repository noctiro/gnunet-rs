//! Standard IDENTITY SERVICE over the original canonical store and Server.
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
mod lifecycle;
#[cfg(unix)]
mod settings;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            #[cfg(unix)]
            if error.downcast_ref::<lifecycle::Reported>().is_some() {
                return ExitCode::FAILURE;
            }
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-identity: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<ExitCode, Failure> {
    Err("native IDENTITY SERVICE requires Unix".into())
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
        let bound = runtime.block_on(listeners.finish_with_access(UnixListenerAccess {
            match_uid: settings.unix.match_uid,
            match_gid: settings.unix.match_gid,
        }))?;
        // The original SERVICE future is owned by this caller. There is no
        // PROGRAM task/scheduler that can drop it instead of running finally.
        runtime.block_on(foreground::run(
            config,
            settings,
            bound,
            parent,
            std::sync::Arc::new(clock.clone()),
            reports.clone(),
            &mut child,
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

#[cfg(unix)]
fn finish(
    result: Result<(), Failure>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<ExitCode, Failure> {
    use gnunet_program_host::{policy::Level, service};
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            reports.message(
                Level::ERROR,
                "identity.failed",
                format_args!("gnunet-service-identity: {original}"),
            );
            let original: Result<(), Failure> =
                service::retain_diagnostic(Err(original), reports.take_error());
            let original = match original {
                Err(original) if reports.failed() => {
                    let fallback = {
                        let mut err = io::stderr().lock();
                        writeln!(err, "gnunet-service-identity: {original}")
                            .and_then(|()| err.flush())
                    };
                    service::retain_diagnostic(Err(original), fallback.err())
                }
                other => other,
            };
            original
                .map(|()| ExitCode::SUCCESS)
                .map_err(|error| Box::new(lifecycle::Reported(error)) as Failure)
        }
    }
}
