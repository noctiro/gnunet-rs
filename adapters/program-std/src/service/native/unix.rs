//! Unix inheritance, fork and identity around the shared service invocation.
use super::*;
use gnunet_service_runtime::Activation;
use gnunet_service_startup::{
    CapturedStartup, GroupsProfile, InheritedMode, InheritedResources, apply_privileges,
    configured_user,
    daemon::{self, Branch, ChildReady},
    resolve_user,
};
pub(super) type Ready<'a> = &'a mut ChildReady;
pub(super) async fn ready(original: Ready<'_>) -> Result<(), Failure> {
    original.ready().map_err(|error| error.into())
}
#[expect(
    unsafe_code,
    reason = "Exclusive process inheritance is transferred exactly once by the native entry"
)]
pub(super) unsafe fn capture() -> Result<CapturedStartup, Failure> {
    // SAFETY: native::main is the unique first startup action.
    Ok(unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners) }?)
}
pub(super) fn run<A: Application>(
    captured: CapturedStartup,
    selected: Selected,
    mut logger: Logger<'static>,
    clock: SharedClock,
) -> Result<(), Failure> {
    let InheritedResources::Listeners(activation) = captured.inherited else {
        return Err("wrong inherited service-listener route".into());
    };
    #[expect(
        unsafe_code,
        reason = "Sole detach point after option output, before runtime, NSS or application resources"
    )]
    // SAFETY: fresh single-threaded entry; option guards ended, no providers,
    // runtime, path guards or application owners exist across this fork.
    let branch = unsafe { daemon::split(selected.daemonize_requested()) };
    let mut child = match branch {
        Ok(Branch::Parent(waiting)) => {
            drop(activation);
            drop(captured.parent_control);
            let result = waiting.wait().map(|_| ()).map_err(|error| error.into());
            return finish::<A>(result, &Reporter::new(logger, clock));
        }
        Ok(Branch::Service(child)) => child,
        Err(error) => {
            logger.refresh_process_after_fork();
            return finish::<A>(Err(error.into()), &Reporter::new(logger, clock));
        }
    };
    if child.is_daemon() {
        logger.refresh_process_after_fork();
    }
    let reports = Reporter::new(logger, clock.clone());
    let result = serve::<A>(
        captured.parent_control,
        captured.control_notice,
        activation,
        selected,
        &reports,
        &clock,
        &mut child,
    );
    let result = super::super::retain_diagnostic(result, reports.take_error());
    let result = child.finish(result).map_err(|error| error.into());
    finish::<A>(result, &reports)
}
fn serve<A: Application>(
    parent: Option<gnunet_service_startup::ParentControl>,
    notice: Option<gnunet_service_startup::ControlNotice>,
    activation: Activation,
    selected: Selected,
    reports: &Reporter,
    clock: &SharedClock,
    child: &mut ChildReady,
) -> Result<(), Failure> {
    if let Some(notice) = notice {
        reports.warning(
            "service.parent.notice",
            format_args!("parent-control declaration: {notice:?}"),
        );
    }
    if reports.failed() {
        return Ok(());
    }
    let config = super::super::load_configuration(
        std::sync::Arc::new(gnunet_config::ProjectData::default()),
        selected.configuration(),
    )?;
    clock.testing_skew(&config)?;
    let settings = A::settings(&config)?;
    let user = configured_user(&config, A::SECTION)?
        .as_deref()
        .map(resolve_user)
        .transpose()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let pending = {
        let _entered = runtime.enter();
        BoundListeners::prepare_before_identity(&config, A::SECTION, activation)?
    };
    let actual = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
    if user.is_some() {
        reports.message(
            crate::policy::Level::INFO,
            "service.identity",
            format_args!("{} configured process identity: {actual:?}", A::BINARY),
        );
    }
    if reports.failed() {
        return Ok(());
    }
    let listeners = runtime.block_on(pending.finish_with_access(A::access(&settings).into()))?;
    for error in listeners.failures() {
        reports.warning(
            "service.listener.alternate",
            format_args!("alternate listener: {error}"),
        );
    }
    if reports.failed() {
        return Ok(());
    }
    let signals = {
        let _entered = runtime.enter();
        let parent = parent
            .map(|parent| parent.register().map_err(|failure| failure.error))
            .transpose()?;
        StopSignals::new(parent)?
    };
    runtime.block_on(A::serve(Context {
        config: &config,
        settings,
        listeners: &listeners,
        signals,
        clock: clock.clone(),
        reports: reports.clone(),
        readiness: Readiness { original: child },
    }))
}
