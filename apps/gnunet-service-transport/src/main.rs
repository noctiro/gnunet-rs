//! Standard TRANSPORT SERVICE options, explicit detach and original T2 owners.
#![deny(unsafe_code)]
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
            // Only pre-selection/parser/logger errors use this fallback.
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-service-transport: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<ExitCode, Failure> {
    Err("native TRANSPORT SERVICE requires Unix startup/IPC ownership".into())
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
    use gnunet_service_startup::{
        GroupsProfile, InheritedMode, InheritedResources, apply_privileges, configured_user,
        daemon::{self, Branch},
        resolve_user,
    };
    use gnunet_transport_service_host::{foreground, generation::Reservations, settings::Settings};
    use std::{cell::RefCell, rc::Rc};
    #[expect(
        unsafe_code,
        reason = "First single-threaded exec-child initialization uniquely adopts the parent's original descriptors once"
    )]
    // SAFETY: first operation; no competing task/thread/listener/FD owner exists.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => {
            return Err("wrong inherited TRANSPORT descriptor route".into());
        }
    };
    let notice = captured.control_notice;
    let parent = captured.parent_control;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"transport", std::process::id(), true)?;
    let selected = match service::prepare(
        b"transport",
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
        reason = "Explicit fresh single-threaded detach follows flushed option/log selection and precedes runtime, NSS/account resolution, path guards, tasks and workers"
    )]
    // SAFETY: temporary stdio guards in prepare have dropped; no lock is held.
    // Only captured original FDs, options and this selected logger/clock exist.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let child = match branch {
        Ok(Branch::Parent(waiting)) => {
            // Original parent owns no Unix path guard/runtime. Only the child
            // continues with its inherited descriptor copies and selected file.
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
    // One explicit process callback owner. Logger and original once-only ready
    // writer stay owned here; no global logger or second native queue is added.
    let process = Rc::new(RefCell::new((logger, Some(child))));
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = notice {
            service::diagnostic(
                &mut process.borrow_mut().0,
                &clock,
                "transport.parent",
                Level::WARNING,
                format_args!("transport parent-control declaration: {notice:?}"),
            )?;
        }
        let config = configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        let settings = Settings::read(&config)?;
        let user = configured_user(&config, b"transport")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        // Preserve existing ordering: only synchronous TCP prebinding and
        // original activation adoption run in this entered runtime scope.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let listeners = {
            let _entered = runtime.enter();
            gnunet_service_runtime::BoundListeners::prepare_before_identity(
                &config,
                b"transport",
                activation,
            )?
        };
        let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            service::diagnostic(
                &mut process.borrow_mut().0,
                &clock,
                "transport.identity",
                Level::INFO,
                format_args!("transport configured process identity: {privileges:?}"),
            )?;
        }
        // The selected account creates new Unix paths. No existing inode is
        // chowned, no inherited socket is reopened, and no worker exists yet.
        let listening = foreground::Listening {
            bound: runtime.block_on(listeners.finish_with_access(
                gnunet_service_runtime::UnixListenerAccess {
                    match_uid: settings.unix.match_uid,
                    match_gid: settings.unix.match_gid,
                },
            ))?,
            parent,
        };
        gnunet_service_runtime::private_parents(&settings.stamp_path)?;
        gnunet_service_runtime::private_parents(&settings.dv.store)?;
        let generation = Reservations::open(&settings.stamp_path)?;
        let observing = Rc::clone(&process);
        let observed_clock = clock.clone();
        let reports = foreground::Reports::new(move |notice| {
            let mut owned = observing.borrow_mut();
            let (logger, child) = &mut *owned;
            match notice {
                foreground::Notice::Ready { peer } => {
                    service::diagnostic(
                        logger,
                        &observed_clock,
                        "transport.ready",
                        Level::INFO,
                        format_args!("TRANSPORT actual Owner ready: {peer:?}"),
                    )?;
                    let public: String = peer.0.iter().map(|byte| format!("{byte:02x}")).collect();
                    let mut output = io::stdout().lock();
                    writeln!(output, "READY {public}")?;
                    output.flush()?;
                    child
                        .as_mut()
                        .ok_or_else(|| io::Error::other("TRANSPORT ready owner consumed"))?
                        .ready()
                }
                foreground::Notice::Diagnostic {
                    level,
                    site,
                    message,
                } => service::diagnostic(logger, &observed_clock, site, level, message),
            }
        });
        // Actual SERVICE configuration is passed directly. No PROGRAM Prepared
        // is invented, and the original session/DV drain still owns its jobs.
        runtime.block_on(foreground::service(
            config,
            clock.clone(),
            settings,
            listening,
            generation,
            reports,
        ))
    })();
    let mut owned = process.borrow_mut();
    let (logger, child) = &mut *owned;
    let result = match child.take() {
        Some(child) => child
            .finish(result)
            .map_err(|error| Box::new(error) as Failure),
        None => Err(Box::new(gnunet_transport_service_host::Failures {
            original: result.err(),
            cleanup: vec!["TRANSPORT original child status owner missing".into()],
        }) as Failure),
    };
    complete(result, logger, &clock)
}
#[cfg(unix)]
fn configuration(
    selected: Option<&std::path::Path>,
) -> Result<gnunet_config::Configuration, Failure> {
    use gnunet_config::{Configuration, Environment, ProcessEnvironment, ProjectData};
    use std::sync::Arc;
    let project = Arc::new(ProjectData::default());
    let mut config = Configuration::create(project.clone(), Default::default())?;
    let selected = if let Some(path) = selected {
        Some(path.to_owned())
    } else {
        let raw = match ProcessEnvironment.variable(b"XDG_CONFIG_HOME") {
            Some(mut path) => {
                path.push(b'/');
                path.extend_from_slice(&project.config_file);
                path
            }
            None => project.user_config_file.clone(),
        };
        let path = config.expand_filename(&raw, &ProcessEnvironment)?;
        path.is_file().then_some(path)
    };
    config.load(selected.as_deref())?;
    Ok(config)
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
                "transport.failure",
                Level::ERROR,
                format_args!("gnunet-service-transport: {original}"),
            ) {
                let _reported = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-transport: {original}; independent logging failure: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
