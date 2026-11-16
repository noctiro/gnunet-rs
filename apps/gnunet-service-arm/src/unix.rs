//! Fresh Unix descriptor capture and pre-runtime daemon fork.
use super::{Failure, complete};
use std::{io, process::ExitCode};
pub(super) fn run() -> Result<ExitCode, Failure> {
    use gnunet_program_host::{
        logging::Logger,
        program::Environment,
        service::{self, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_startup::{
        InheritedMode, InheritedResources,
        daemon::{self, Branch},
    };
    #[expect(
        unsafe_code,
        reason = "First fresh-exec operation exclusively captures original inherited descriptors/environment once"
    )]
    // SAFETY: no runtime, selected log file, extra fd owner, thread or service has
    // been created. The original parent exclusively transfers these descriptors.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    let inherited = match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => hold,
        InheritedResources::Listeners(_) => {
            return Err("ARM requires original CLOSE_LSOCKS route".into());
        }
    };
    let parent = captured.parent_control;
    let notice = captured.control_notice;
    let clock = SharedClock::native(128)?;
    let mut logger = Logger::new(b"arm", std::process::id(), true)?;
    let selected = match service::prepare(
        b"arm",
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
        reason = "Fresh single thread after flushed SERVICE selection, before NSS/runtime/listeners/children/active signal owners"
    )]
    // SAFETY: stdio guards ended; only original captured FDs, unlocked clock and
    // selected logger/options remain. No native runtime or worker was started.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(waiting)) => {
            drop(inherited);
            drop(parent);
            return complete(
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
            return complete(Err(Box::new(error)), &mut logger, &clock);
        }
    };
    if child.is_daemon() {
        logger.refresh_process_after_fork()
    }
    let result = gnunet_arm_service_host::service::run(gnunet_arm_service_host::service::Startup {
        selected: &selected,
        inherited,
        parent,
        notice,
        clock: &clock,
        logger: &mut logger,
        ready: &mut child,
    });
    let result = child.finish(result).map_err(|e| Box::new(e) as Failure);
    complete(result, &mut logger, &clock)
}
