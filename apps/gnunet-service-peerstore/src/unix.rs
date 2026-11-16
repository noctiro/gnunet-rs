//! Unix original descriptors, daemon split and account transition.
use super::{
    Failure, aggregate, control::Control, finish, foreground, hellos, reporting, settings,
};
use gnunet_program_host::reporting::Reporter;
use std::{io, process::ExitCode};
pub(super) fn run() -> Result<ExitCode, Failure> {
    use gnunet_peerstore_host::{backend::Wal, worker::Worker};
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::Environment,
        service::{self, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_service_runtime::{BoundListeners, private_parents};
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
            return Err("unexpected PEERSTORE inherited startup route".into());
        }
    };
    let parent = captured.parent_control;
    let notice = captured.control_notice;
    let clock = SharedClock::native(256)?;
    let mut logger = Logger::new(b"peerstore", std::process::id(), true)?;
    let selected = match service::prepare(
        b"peerstore",
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
        reason = "Fresh single thread after flushed option/log selection, before NSS, runtime, path guards, threads or active service owners"
    )]
    // SAFETY: temporary stdio guards are released. Only captured FDs, options,
    // selected Logger and unlocked SharedClock exist; no process side effects
    // from a runtime, NSS or store have started before this explicit boundary.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(waiting)) => {
            drop(activation);
            drop(parent);
            let result = waiting
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
    let reports = reporting::Reports::new(Reporter::new(logger, clock.clone()));
    let result = {
        let result = (|| -> Result<(), Failure> {
            if let Some(notice) = notice {
                reports.warning(
                    "peerstore.parent",
                    format_args!("peerstore parent-control declaration: {notice:?}"),
                );
                reports.startup_check()?;
            }
            let config = settings::configuration(selected.configuration())?;
            clock.testing_skew(&config)?;
            let settings = settings::Settings::read(&config)?;
            let user = configured_user(&config, b"peerstore")?
                .as_deref()
                .map(resolve_user)
                .transpose()?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            // Original activation/TCP preparation precedes the USER transition;
            // no Unix endpoint, WAL, worker, signal or native task exists here.
            let listeners = {
                let _entered = runtime.enter();
                BoundListeners::prepare_before_identity(&config, b"peerstore", activation)?
            };
            let privileges = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
            if user.is_some() {
                reports.message(
                    Level::INFO,
                    "peerstore.identity",
                    format_args!("peerstore configured process identity: {privileges:?}"),
                );
                reports.startup_check()?;
            }
            // Target account owns every new Unix socket. All original actual
            // listeners finish before either the WAL or its thread is opened.
            let bound = runtime.block_on(listeners.finish_with_access(settings.access.into()))?;
            for error in bound.failures() {
                reports.warning(
                    "peerstore.listener.alternate",
                    format_args!("peerstore alternate listener: {error}"),
                );
            }
            reports.startup_check()?;
            let mut control = {
                let _entered = runtime.enter();
                let parent = parent
                    .map(|parent| parent.register().map_err(|failure| failure.error))
                    .transpose()?;
                Control::new(parent)?
            };
            private_parents(&settings.directory)?;
            let mut wal = Wal::open(&settings.directory, settings.backend)?;
            if let Some(path) = &settings.hellos {
                hellos::import_hellos(&mut wal, path, settings.hello_files, &reports)?;
            }
            reports.startup_check()?;
            runtime.block_on(super::foreground::before_start(&mut control, &reports))?;
            let mut worker = Worker::start(wal, settings.worker)?;
            runtime.block_on(async {
                let result = foreground::run(
                    foreground::Inputs {
                        bound: &bound,
                        control,
                        worker: &mut worker,
                        settings: &settings,
                        clock: Arc::new(clock.clone()),
                        reports: &reports,
                    },
                    async {
                        child.ready()?;
                        Ok(())
                    },
                )
                .await;
                // Constructor/initialization failures may leave the actual
                // worker outside Server. Drain and join that same owner even
                // when the original result already failed; keep both causes.
                let mut cleanup = Vec::new();
                if worker.needs_join() {
                    match worker
                        .shutdown(|completion| reports.completion(completion))
                        .await
                    {
                        Ok(stopped) => {
                            if let Some(error) = stopped.failure {
                                cleanup.push(Box::new(error) as Failure);
                            }
                        }
                        Err(error) => cleanup.push(Box::new(error) as Failure),
                    }
                }
                aggregate(result, cleanup)
            })
        })();
        // Running-service diagnostic failures stay latched through every actual
        // source/WAL/worker cleanup; do not replace those original error objects.
        service::retain_diagnostic(result, reports.reporter().take_error())
    };
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Failure);
    finish(result, reports.reporter())
}
