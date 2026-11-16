//! Unix capture, detach and privileges around the shared NAMESTORE loop.
use super::{Failure, early, finish, foreground, lifecycle, settings};
use std::io;
pub(super) fn run() -> Result<(), Failure> {
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
    let early::Inherited {
        activation,
        parent,
        notice,
    } = early::capture()?;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"namestore", std::process::id(), true)?;
    let selected = match service::prepare(
        b"namestore",
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
            return if successful {
                Ok(())
            } else {
                Err("NAMESTORE SERVICE options failed".into())
            };
        }
    };
    #[expect(
        unsafe_code,
        reason = "Only fresh single-threaded exec startup after flushed options, before runtime/NSS/path guards/NAMESTORE/native sources; original captured owners remain unique"
    )]
    // SAFETY: sole explicit detach point. No runtime, thread, account lookup,
    // listener path guard, NAMESTORE or NAMESTORE store/worker exists; no Logger/clock borrow
    // is held across fork. Selected logfile was lifted above stdio by setup.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
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
    let cleanup = lifecycle::Cleanup::default();
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = notice {
            reports.warning(
                "namestore.parent.notice",
                format_args!("NAMESTORE parent-control declaration: {notice:?}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        let config = service::load_configuration(
            std::sync::Arc::new(gnunet_config::ProjectData::default()),
            selected.configuration(),
        )?;
        clock.testing_skew(&config)?;
        let settings = settings::Settings::read(&config)?;
        let user = configured_user(&config, b"namestore")?
            .as_deref()
            .map(resolve_user)
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let pending = {
            let _entered = runtime.enter();
            BoundListeners::prepare_before_identity(&config, b"namestore", activation)?
        };
        let actual = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.message(
                Level::INFO,
                "namestore.identity",
                format_args!("NAMESTORE configured process identity: {actual:?}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        let bound = runtime.block_on(pending.finish_with_access(settings.unix.into()))?;
        for error in bound.failures() {
            reports.warning(
                "namestore.listener.alternate",
                format_args!("NAMESTORE alternate listener: {error}"),
            );
        }
        if reports.failed() {
            return Ok(());
        }
        let parent = {
            let _entered = runtime.enter();
            parent
                .map(|control| control.register().map_err(|failure| failure.error))
                .transpose()?
        };
        runtime.block_on(foreground::run(
            foreground::Inputs {
                config: &config,
                settings,
                bound: &bound,
                parent,
                clock: clock.clone(),
                reports: reports.clone(),
                cleanup: cleanup.clone(),
            },
            async {
                child.ready()?;
                Ok(())
            },
        ))
    })();
    let result = service::retain_diagnostic(cleanup.finish(result), reports.take_error());
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Failure);
    finish(result, &reports)
}
