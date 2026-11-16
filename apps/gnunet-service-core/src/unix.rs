//! Unix capture, configured identity and explicit fresh-process detachment.
use super::{Failure, finish, foreground};
use gnunet_core_host::startup;
use gnunet_program_host::{
    logging::Logger,
    policy::Level,
    program::Environment,
    reporting::Reporter,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_startup::{
    InheritedMode, InheritedResources, StopSignals,
    daemon::{self, Branch},
};
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
            return Err("CORE received the wrong inherited route".into());
        }
    };
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"core", std::process::id(), true)?;
    let selected = match service::prepare(
        b"core",
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
    let mut child = match branch {
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
    let reports = Reporter::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = captured.control_notice {
            reports.warning(
                "core.parent",
                format_args!("core parent-control declaration: {notice:?}"),
            );
        }
        let config = startup::configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let (process, stop) = {
            let _entered = runtime.enter();
            let parent = captured
                .parent_control
                .map(|parent| parent.register().map_err(|error| error.error))
                .transpose()?;
            (
                startup::prepare_process(&config, activation)?,
                StopSignals::new(parent)?,
            )
        };
        let process = process.apply_identity()?;
        if config.get(b"core", b"USERNAME").is_some() {
            reports.message(
                Level::INFO,
                "core.identity",
                format_args!("CORE configured identity: {:?}", process.privilege_report()),
            );
        }
        let service = runtime.block_on(process.finish())?;
        runtime.block_on(foreground::run(
            service,
            stop,
            clock.clone(),
            reports.clone(),
            async { child.ready().map_err(|error| Box::new(error) as Failure) },
        ))
    })();
    let result = service::retain_diagnostic(result, reports.take_error());
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Failure);
    finish(result, &reports)
}
