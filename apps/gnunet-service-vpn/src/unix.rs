//! Unix detach, inherited-descriptor capture and privilege transition.
use crate::{Failure, early, finish, foreground, lifecycle, settings};
use std::{io, process::ExitCode};
pub(super) fn run() -> Result<ExitCode, Failure> {
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::Environment,
        reporting::Reporter,
        service::{self, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_runtime::BoundListeners;
    use gnunet_service_startup::{
        GroupsProfile, apply_privileges, configured_user,
        daemon::{self, Branch},
        resolve_user,
    };
    use std::sync::Arc;
    // This remains the first foreign FD transfer, before unrelated allocations.
    let early::Inherited {
        tun,
        activation,
        parent,
        notice,
    } = early::capture()?;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"vpn", std::process::id(), true)?;
    let selected = match service::prepare(
        b"vpn",
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
        reason = "Explicit fresh single-threaded exec detach before runtime, NSS, listeners, TUN/route/CADET/REGEX owners; no logger/clock borrow crosses fork"
    )]
    // SAFETY: only captured original owned FDs, selected options/logger and an
    // unlocked SharedClock exist; temporary stdio locks have already dropped.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(status)) => {
            // Parent must not retain the child's original TUN or startup owners.
            drop(tun);
            drop(activation);
            drop(parent);
            let reports = Reporter::new(logger, clock);
            let result = status
                .wait()
                .map(|_| ())
                .map_err(|e| Box::new(e) as Failure);
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
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = notice {
            reports.warning(
                "vpn.parent.notice",
                format_args!("VPN original parent-control declaration: {notice:?}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        let config = service::load_configuration(
            Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config)?;
        let user = configured_user(&config, b"vpn")?
            .as_deref()
            .map(resolve_user)
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let pending = {
            let _entered = runtime.enter();
            BoundListeners::prepare_before_identity(&config, b"vpn", activation)?
        };
        let actual = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.message(
                Level::INFO,
                "vpn.identity",
                format_args!("VPN actual configured process identity: {actual:?}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        let bound = runtime.block_on(pending.finish_with_access(settings.service.unix.into()))?;
        for error in bound.failures() {
            reports.warning(
                "vpn.listener.alternate",
                format_args!("VPN actual alternate listener failure: {error}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        let parent = {
            let _entered = runtime.enter();
            parent
                .map(|parent| parent.register().map_err(|failure| failure.error))
                .transpose()?
        };
        // Only this post-identity branch can open/qualify/configure the real TUN.
        runtime.block_on(foreground::run(
            foreground::Inputs {
                config: &config,
                settings: &settings,
                bound: &bound,
                parent,
                tun,
                clock: Arc::new(clock.clone()),
                reports: reports.clone(),
                cleanup: cleanup.clone(),
            },
            async { child.ready().map_err(Into::into) },
        ))
    })();
    let result = cleanup.finish(service::retain_diagnostic(result, reports.take_error()));
    let result = child.finish(result).map_err(|e| Box::new(e) as Failure);
    finish(result, &reports)
}
