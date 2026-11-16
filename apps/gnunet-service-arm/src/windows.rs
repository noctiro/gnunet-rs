//! Fresh native Windows capture, console policy and normal ARM SERVICE entry.
use super::{Failure, complete};
use gnunet_arm_service_host::service::Activation;
use gnunet_program_host::{
    logging::Logger,
    program::Environment,
    service::{self, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_startup::ParentRole;
use std::{io, process::ExitCode};

pub(super) fn run() -> Result<ExitCode, Failure> {
    #[expect(
        unsafe_code,
        reason = "First fresh-process action exclusively captures inherited immutable activation metadata and parent declarations before competing owners"
    )]
    // SAFETY: no runtime, provider, logger, stream owner or worker exists yet.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
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
    let role = captured.parent_control.as_ref().map(|parent| parent.role());
    if selected.daemonize_requested() && role == Some(ParentRole::Supervisor) {
        #[expect(
            unsafe_code,
            reason = "Exclusive fresh service owns console/stdio before provider materialization, runtime and native stop subscriptions"
        )]
        // SAFETY: output guards ended and no other owner caches standard handles.
        if let Err(error) = unsafe { gnunet_service_startup::daemon::detach_managed() } {
            return complete(Err(Box::new(error)), &mut logger, &clock);
        }
    }
    let activation = captured
        .activation
        .map(|incoming| Activation::from_imported(incoming.materialize()?))
        .transpose()?
        .unwrap_or_default();
    let result = gnunet_arm_service_host::service::run(gnunet_arm_service_host::service::Startup {
        selected: &selected,
        activation,
        parent: captured.parent_control,
        clock: &clock,
        logger: &mut logger,
    });
    complete(result, &mut logger, &clock)
}
