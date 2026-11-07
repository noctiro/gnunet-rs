//! Independent official STATISTICS SERVICE, with explicit startup, protocol and storage owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
#[derive(Debug)]
struct PhaseFailure {
    stage: &'static str,
    source: Failure,
}
#[cfg(unix)]
impl std::fmt::Display for PhaseFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "statistics {}: {}", self.stage, self.source)
    }
}
#[cfg(unix)]
impl Error for PhaseFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod host;
#[cfg(unix)]
mod reporting;
#[cfg(unix)]
mod settings;
#[derive(Debug)]
struct Failures {
    original: Option<Failure>,
    cleanup: Vec<Failure>,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "STATISTICS original={:?}; independent cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref()
    }
}
fn aggregate(result: Result<(), Failure>, mut cleanup: Vec<Failure>) -> Result<(), Failure> {
    if cleanup.is_empty() {
        return result;
    }
    Err(Box::new(Failures {
        original: Some(result.err().unwrap_or_else(|| cleanup.remove(0))),
        cleanup,
    }))
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-statistics: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<ExitCode, Failure> {
    Err("the STATISTICS SERVICE requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<ExitCode, Failure> {
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::Environment,
        service::{self, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_runtime::{BoundListeners, UnixListenerAccess};
    use gnunet_service_startup::{
        GroupsProfile, InheritedMode, InheritedResources, apply_privileges, configured_user,
        daemon::{self, Branch},
        resolve_user,
    };
    use std::sync::Arc;
    #[expect(
        unsafe_code,
        reason = "First fresh exec-child operation exclusively adopts the original parent descriptors once"
    )]
    // SAFETY: no runtime, log file, worker or other descriptor owner exists yet.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => {
            return Err("unexpected STATISTICS inherited startup route".into());
        }
    };
    let parent = captured.parent_control;
    let notice = captured.control_notice;
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
    #[expect(
        unsafe_code,
        reason = "Fresh single thread after flushed option/log selection, before NSS, runtime, path guards, threads or active service owners"
    )]
    // SAFETY: temporary stdio guards are released. Only captured FDs, options,
    // selected Logger and unlocked SharedClock exist; no process side effects
    // from a runtime, NSS or database have started before this explicit boundary.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(waiting)) => {
            drop(activation);
            drop(parent);
            let result = waiting
                .wait()
                .map(|_| ())
                .map_err(|error| Box::new(error) as Failure);
            return complete(result, &mut logger, &clock);
        }
        Ok(Branch::Service(child)) => child,
        Err(error) => {
            logger.refresh_process_after_fork();
            return complete(Err(Box::new(error)), &mut logger, &clock);
        }
    };
    if child.is_daemon() {
        logger.refresh_process_after_fork();
    }
    let result = {
        let reports = reporting::Reports::new(&mut logger, &clock);
        let mut stage = "configuration";
        let result = (|| -> Result<(), Failure> {
            if let Some(notice) = notice {
                reports.warning(
                    "statistics.parent",
                    format_args!("statistics parent-control declaration: {notice:?}"),
                );
                reports.startup_check()?;
            }
            let config = settings::configuration(selected.configuration())?;
            stage = "clock configuration";
            clock.testing_skew(&config)?;
            stage = "settings";
            let settings = settings::Settings::read(&config)?;
            stage = "process identity";
            let user = configured_user(&config, b"statistics")?
                .as_deref()
                .map(resolve_user)
                .transpose()?;
            stage = "runtime";
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            // Original activation/TCP preparation precedes the USER transition;
            // no Unix endpoint, database, signal or active service task exists here.
            stage = "listener preparation";
            let listeners = {
                let _entered = runtime.enter();
                BoundListeners::prepare_before_identity(&config, b"statistics", activation)?
            };
            stage = "process credentials";
            let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
            if user.is_some() {
                reports.message(
                    Level::INFO,
                    "statistics.identity",
                    format_args!("statistics configured process identity: {privileges:?}"),
                );
                reports.startup_check()?;
            }
            // Target account owns every new Unix socket. All original actual
            // listeners finish before database loading or service admission.
            stage = "listener binding";
            let bound = runtime.block_on(listeners.finish_with_access(UnixListenerAccess {
                match_uid: settings.access.match_uid,
                match_gid: settings.access.match_gid,
            }))?;
            for error in bound.failures() {
                reports.warning(
                    "statistics.listener.alternate",
                    format_args!("statistics alternate listener: {error}"),
                );
            }
            reports.startup_check()?;
            stage = "service";
            runtime.block_on(host::run(host::Inputs {
                bound: &bound,
                parent,
                settings: &settings,
                clock: Arc::new(clock.clone()),
                reports: &reports,
                child: &mut child,
            }))
        })()
        .map_err(|source| Box::new(PhaseFailure { stage, source }) as Failure);
        // Running-service diagnostic failures stay latched through every actual
        // source and store cleanup; do not replace those original error objects.
        service::retain_diagnostic(result, reports.take_failure())
    };
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Failure);
    complete(result, &mut logger, &clock)
}
#[cfg(unix)]
fn complete(
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
                "statistics.failure",
                Level::ERROR,
                format_args!("gnunet-service-statistics: {original}"),
            ) {
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-statistics: {original}; independent logging failure: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
