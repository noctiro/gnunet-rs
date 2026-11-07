//! Official DNS SERVICE entry and explicit original process/source ownership.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(target_os = "linux")]
mod control;
#[cfg(target_os = "linux")]
mod early;
#[cfg(target_os = "linux")]
mod foreground;
#[cfg(target_os = "linux")]
mod settings;
#[cfg(target_os = "linux")]
mod statistics;
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            // Only initialization before the selected Reporter reaches here.
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-dns: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn run() -> Result<ExitCode, Failure> {
    Err("native DNS interception helper SERVICE requires Linux".into())
}
#[cfg(target_os = "linux")]
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
            return Ok(if successful {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            });
        }
    };
    #[expect(
        unsafe_code,
        reason = "Fresh single-thread process after option/log selection and before NSS/runtime/native sources"
    )]
    // SAFETY: temporary stdio guards are gone. Only original captured FDs,
    // selected Logger and unlocked SharedClock exist; no task/helper/thread yet.
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
                "dns.parent",
                format_args!("dns original parent-control declaration: {notice:?}"),
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
        let user = configured_user(&config, b"dns")?
            .as_deref()
            .map(resolve_user)
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        // The original inherited and TCP endpoints are prepared before USER.
        // No helper, DNSSTUB, source task or new Unix endpoint exists yet.
        let pending = {
            let _entered = runtime.enter();
            BoundListeners::prepare_before_identity(&config, b"dns", activation)?
        };
        let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.message(
                Level::INFO,
                "dns.identity",
                format_args!("dns configured process identity: {privileges:?}"),
            );
            startup_check(&reports)?;
        }
        let bound = runtime.block_on(pending.finish_with_access(UnixListenerAccess {
            match_uid: settings.unix.match_uid,
            match_gid: settings.unix.match_gid,
        }))?;
        for error in bound.failures() {
            reports.warning(
                "dns.listener.alternate",
                format_args!("dns alternate listener: {error}"),
            );
        }
        startup_check(&reports)?;
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
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Failure);
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            reports.message(
                Level::ERROR,
                "dns.failure",
                format_args!("gnunet-service-dns: {original}"),
            );
            if reports.failed() {
                let diagnostic = reports.take_error();
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-dns: {original}; independent final logging failure: {diagnostic:?}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
#[cfg(target_os = "linux")]
fn startup_check(reports: &gnunet_program_host::reporting::Reporter) -> Result<(), Failure> {
    if reports.failed() {
        Err("DNS selected diagnostic destination failed".into())
    } else {
        Ok(())
    }
}
#[cfg(target_os = "linux")]
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
                "dns.startup.failure",
                Level::ERROR,
                format_args!("gnunet-service-dns: {original}"),
            ) {
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-dns: {original}; independent logging failure: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
