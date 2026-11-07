//! Actual standard REGEX SERVICE frontend, parameterized by a real DHT Factory.
//!
//! NativeFactory provides the actual ordinary DHT binding, with no dummy backend.
//! It joins the admitted IPC/distributed Core, real PILS signer, shared Resolver,
//! caller's actual DHT provider, selected logging and official statistics owner.
#![deny(unsafe_code, missing_docs)]
mod control;
mod factory;
mod lifecycle;
mod native;
pub use native::NativeFactory;
mod reporting;
mod settings;
/// Bounded original STATISTICS owner, implemented independently from business IPC.
pub mod statistics;
pub use factory::{Context, Factory};
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
pub use lifecycle::{Errors, LifecycleFailure, Report};
pub use settings::Settings;
use std::{
    io::{self, Write},
    process::ExitCode,
    sync::Arc,
};
/// Original native/configuration/provider failure, retaining its source chain.
pub type Failure = Box<dyn std::error::Error>;
/// Run an actual REGEX service with the caller's production DHT factory.
///
/// # Safety
/// Call exactly once as the first initialization of a fresh single-threaded exec
/// child. No other thread, runtime/task, held application/global lock, path guard,
/// previous inherited-FD owner or constructed native provider may exist. Standard
/// option preparation precedes the optional explicit fork; no Factory instance,
/// account lookup, runtime, native client or listener path exists across it.
/// This operation may change process identity and must not be called from a
/// general asynchronous embedding. `F::storage/create` run only in the resulting
/// service process after its runtime, target-account listeners and Resolver exist.
#[expect(
    unsafe_code,
    reason = "Explicit process-entry Safety contract is necessary for once-only inherited descriptor adoption and fresh single-thread fork"
)]
pub unsafe fn run<F: Factory + 'static>() -> Result<ExitCode, Failure> {
    // SAFETY: guaranteed by this function's explicit fresh-exec contract; exact
    // inherited listeners/control descriptors are adopted before any competitors.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(a) => a,
        InheritedResources::CloseAfterBind(_) => {
            return Err("REGEX received an incompatible inherited startup route".into());
        }
    };
    let parent = captured.parent_control;
    let notice = captured.control_notice;
    let clock = SharedClock::native(1024)?;
    let mut logger = Logger::new(b"regex", std::process::id(), true)?;
    let selected = match service::prepare(
        b"regex",
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
    // SAFETY: no runtime, account lookup, path guard, task or native provider has
    // been created. The actual selected logger owns lifted descriptors and its
    // setup's temporary stdio locks are gone. Only this explicit entry may fork.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(parent_status)) => {
            drop(activation);
            drop(parent);
            let result = parent_status
                .wait()
                .map(|_| ())
                .map_err(|e| Box::new(e) as Failure);
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
    let diagnostics = reporting::Diagnostics::new(logger, clock.clone());
    let result = (|| -> Result<(), Failure> {
        if let Some(notice) = notice {
            diagnostics.message(
                "regex.parent.notice",
                Level::WARNING,
                format_args!("REGEX original parent-control declaration: {notice:?}"),
            )?;
        }
        let config = settings::configuration(selected.configuration())?;
        clock.testing_skew(&config)?;
        let settings = Settings::read(&config)?;
        // Explicitly selected actual account; no async helper changes identity.
        let user = configured_user(&config, b"regex")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let listeners = {
            let _entered = runtime.enter();
            gnunet_service_runtime::BoundListeners::prepare_before_identity(
                &config, b"regex", activation,
            )?
        };
        let actual_identity = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            diagnostics.message(
                "regex.process.identity",
                Level::INFO,
                format_args!("REGEX actual configured process identity: {actual_identity:?}"),
            )?;
        }
        let bound = runtime.block_on(listeners.finish_with_access(
            gnunet_service_runtime::UnixListenerAccess {
                match_uid: settings.unix.match_uid,
                match_gid: settings.unix.match_gid,
            },
        ))?;
        let report = runtime.block_on(lifecycle::run::<F>(lifecycle::Inputs {
            config,
            settings,
            bound,
            clock: Arc::new(clock.clone()),
            control: parent,
            child: &mut child,
            diagnostics: &diagnostics,
        }));
        let report = service::retain_diagnostic(report, diagnostics.take_failure())?;
        diagnostics.message(
            "regex.stopped",
            Level::INFO,
            format_args!("REGEX actual owners stopped: {report:?}"),
        )?;
        let mut output = io::stdout().lock();
        writeln!(output, "STOPPED regex {report:?}")?;
        output.flush()?;
        Ok(())
    })();
    let result = service::retain_diagnostic(result, diagnostics.take_failure());
    let result = child
        .finish(result)
        .map_err(|error| Box::new(error) as Failure);
    let mut logger = diagnostics.logger.into_inner();
    complete(result, &mut logger, &clock)
}
fn complete(
    result: Result<(), Failure>,
    logger: &mut Logger<'_>,
    clock: &SharedClock,
) -> Result<ExitCode, Failure> {
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            if let Err(diagnostic) = service::diagnostic(
                logger,
                clock,
                "regex.failure",
                Level::ERROR,
                format_args!("REGEX SERVICE: {original}"),
            ) {
                let _actual = writeln!(
                    io::stderr().lock(),
                    "REGEX SERVICE: {original}; independent selected logging error: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
