//! Standard DATASTORE SERVICE with selected logging and original worker cleanup.
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
mod foreground;
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
            "DATASTORE original={:?}; independent cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl Error for Failures {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref()
    }
}
fn aggregate(result: Result<(), Failure>, cleanup: Vec<Failure>) -> Result<(), Failure> {
    let mut remaining = cleanup.into_iter();
    let Some(original) = result.err().or_else(|| remaining.next()) else {
        return Ok(());
    };
    let cleanup: Vec<_> = remaining.collect();
    if cleanup.is_empty() {
        return Err(original);
    }
    Err(Box::new(Failures {
        original: Some(original),
        cleanup,
    }))
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-datastore: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<ExitCode, Failure> {
    Err("DATASTORE SERVICE requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<ExitCode, Failure> {
    use gnunet_datastore_host::backend::Store;
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::Environment,
        service::{self, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_runtime::{BoundListeners, UnixListenerAccess, private_parents};
    use gnunet_service_startup::{
        GroupsProfile, InheritedMode, InheritedResources, apply_privileges, configured_user,
        daemon::{self, Branch},
        resolve_user,
    };
    use std::sync::Arc;
    #[expect(
        unsafe_code,
        reason = "First fresh process operation exclusively captures original parent descriptors before files, runtime or workers"
    )]
    // SAFETY: first initialization, before descriptor reuse, concurrency, another
    // capture, a runtime, log destination, store or other foreign-FD owner.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => {
            return Err("unexpected DATASTORE inherited startup route".into());
        }
    };
    let parent = captured.parent_control;
    let notice = captured.control_notice;
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
    #[expect(
        unsafe_code,
        reason = "Fresh single thread after option/logger selection and before NSS, runtime, path guards, stores or active workers"
    )]
    // SAFETY: stdio guards are released; the captured descriptors, selected
    // Logger and unlocked SharedClock have no active runtime/NSS/store workers.
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
        logger.refresh_process_after_fork()
    }
    let result = {
        let reports = reporting::Reports::new(&mut logger, &clock);
        let result = (|| -> Result<(), Failure> {
            if let Some(notice) = notice {
                reports.warning(
                    "datastore.parent",
                    format_args!("datastore parent-control declaration: {notice:?}"),
                );
                reports.startup_check()?;
            }
            let config = settings::configuration(selected.configuration())?;
            clock.testing_skew(&config)?;
            let settings = settings::Settings::read(&config)?;
            let user = configured_user(&config, b"datastore")?
                .as_deref()
                .map(resolve_user)
                .transpose()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let listeners = {
                let _entered = runtime.enter();
                BoundListeners::prepare_before_identity(&config, b"datastore", activation)?
            };
            let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
            if user.is_some() {
                reports.message(
                    Level::INFO,
                    "datastore.identity",
                    format_args!("datastore configured process identity: {privileges:?}"),
                );
                reports.startup_check()?
            }
            // Target credentials own new Unix sockets and the durable store.
            // The filesystem access policy matches the independent kernel checks.
            let bound = runtime.block_on(listeners.finish_with_access(UnixListenerAccess {
                match_uid: settings.access.match_uid,
                match_gid: settings.access.match_gid,
            }))?;
            for error in bound.failures() {
                reports.warning(
                    "datastore.listener.alternate",
                    format_args!("datastore alternate listener: {error}"),
                )
            }
            reports.startup_check()?;
            private_parents(&settings.directory)?;
            let backend = Store::open(&settings.directory, settings.backend)?;
            reports.startup_check()?;
            runtime.block_on(foreground::run(foreground::Inputs {
                bound: &bound,
                parent,
                backend,
                settings: &settings,
                clock: Arc::new(clock.clone()),
                reports: &reports,
                child: &mut child,
            }))
        })();
        let mut cleanup = Vec::new();
        if let Some(error) = reports.take_failure() {
            cleanup.push(Box::new(error) as Failure)
        }
        aggregate(result, cleanup)
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
                "datastore.failure",
                Level::ERROR,
                format_args!("gnunet-service-datastore: {original}"),
            ) {
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-datastore: {original}; independent logging failure: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
