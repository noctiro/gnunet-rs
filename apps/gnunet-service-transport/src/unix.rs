//! Unix capture, configured identity and explicit fresh-process detachment.
use super::{Failure, configuration, finish, reporting};
use gnunet_program_host::{
    logging::Logger,
    policy::Level,
    program::Environment,
    reporting::Reporter,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_startup::{
    GroupsProfile, InheritedMode, InheritedResources, StopSignals, apply_privileges,
    configured_user,
    daemon::{self, Branch},
    resolve_user,
};
use gnunet_transport_service_host::{foreground, generation::Reservations, settings::Settings};
use std::{io, process::ExitCode};
pub(super) fn run() -> Result<ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "Sole fresh-process capture precedes competing native owners"
    )]
    // SAFETY: first startup operation before logger, runtime, files or workers.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(activation) => activation,
        InheritedResources::CloseAfterBind(_) => {
            return Err("TRANSPORT received the wrong inherited route".into());
        }
    };
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
        reason = "Explicit single-thread startup before runtime, NSS, key leases and path guards"
    )]
    // SAFETY: option output locks have dropped; no runtime, task or private owner exists.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let child = match branch {
        Ok(Branch::Parent(parent)) => {
            drop(activation);
            drop(captured.parent_control);
            let result = parent
                .wait()
                .map(|_| ())
                .map_err(|error| Box::new(error) as Failure);
            return finish(result, &Reporter::new(logger, clock));
        }
        Ok(Branch::Service(child)) => child,
        Err(error) => {
            logger.refresh_process_after_fork();
            return finish(Err(Box::new(error)), &Reporter::new(logger, clock));
        }
    };
    if child.is_daemon() {
        logger.refresh_process_after_fork();
    }
    let child = std::rc::Rc::new(std::cell::RefCell::new(Some(child)));
    let reports = Reporter::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = captured.control_notice {
            reports.warning(
                "transport.parent",
                format_args!("transport parent-control declaration: {notice:?}"),
            );
        }
        let config = configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        let settings = Settings::read(&config)?;
        let user = configured_user(&config, b"TRANSPORT")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (listeners, stop) = {
            let _entered = runtime.enter();
            let parent = captured
                .parent_control
                .map(|parent| parent.register().map_err(|error| error.error))
                .transpose()?;
            (
                gnunet_service_runtime::BoundListeners::prepare_before_identity(
                    &config,
                    b"TRANSPORT",
                    activation,
                )?,
                StopSignals::new(parent)?,
            )
        };
        let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.message(
                Level::INFO,
                "transport.identity",
                format_args!("transport configured identity: {privileges:?}"),
            );
        }
        let bound = runtime.block_on(listeners.finish_with_access(settings.unix.into()))?;
        let status = child.clone();
        let observations = reporting::notices(reports.clone(), move || {
            status
                .borrow_mut()
                .as_mut()
                .ok_or_else(|| {
                    std::io::Error::other("TRANSPORT original child status owner missing")
                })?
                .ready()
        });
        gnunet_service_runtime::private_parents(&settings.stamp_path)?;
        gnunet_service_runtime::private_parents(&settings.dv.store)?;
        let generation = Reservations::open(&settings.stamp_path)?;
        runtime.block_on(foreground::service(
            config,
            clock.clone(),
            settings,
            foreground::Listening {
                bound,
                stop,
                readiness: None,
            },
            generation,
            observations,
        ))
    })();
    let result = service::retain_diagnostic(result, reports.take_error());
    let result = match child.borrow_mut().take() {
        Some(child) => child
            .finish(result)
            .map_err(|cause| Box::new(cause) as Failure),
        None => Err(Box::new(gnunet_transport_service_host::Failures {
            original: result.err(),
            cleanup: vec!["TRANSPORT original child status owner missing".into()],
        }) as Failure),
    };
    finish(result, &reports)
}
