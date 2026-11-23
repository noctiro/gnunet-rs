//! Unix ARM launch and signal policy using the existing shared process port.
use super::*;
use gnunet_service_runtime::process as native;

/// Borrowed Unix launch inputs, retained by the process owner across drives.
#[derive(Clone, Copy)]
pub struct LaunchContext<'a> {
    /// Configuration used by native executable selection.
    pub config: &'a gnunet_config::Configuration,
    /// Absolute native exec-helper path.
    pub helper: &'a std::path::Path,
    /// Explicit child environment and working-directory snapshot.
    pub environment: &'a EnvironmentSnapshot,
}
pub(crate) struct Control;
pub(crate) fn spawn(
    request: Request<'_>,
    limits: ProcessLimits,
    children: &mut ChildRegistry,
) -> Result<SpawnResult, LaunchError> {
    let (filename, argv) = native_arguments(request.recipe, limits.launch.max_arguments)?;
    let command = native::NativeCommand {
        filename,
        argv,
        environment: request.context.environment.clone(),
        environment_changes: Vec::new(),
        cwd: None,
        stdio: 6 | if request.mode == ControlMode::Pipe {
            8
        } else {
            0
        },
        stdio_snapshot: None,
        listeners: request.listeners,
        mappings: Vec::new(),
    };
    native::spawn(
        request.context.config,
        request.context.helper,
        command,
        limits,
        children,
    )
    .map(|result| match result {
        native::SpawnResult::Refused { error } => SpawnResult::Refused { error },
        native::SpawnResult::Admitted(receipt) => SpawnResult::Admitted(Spawned {
            child: receipt.child,
            control: Control,
            diagnostic: None,
        }),
    })
}
pub(crate) fn prepare(children: &mut ChildRegistry) -> Result<(), LaunchError> {
    children.prepare()
}
pub(crate) fn reap_completed(children: &mut ChildRegistry) -> Result<(), LaunchError> {
    children.reap_completed().map(|_| ())
}
pub(crate) fn poll_exit(
    children: &mut ChildRegistry,
    cx: &mut Context<'_>,
) -> Poll<Result<(), LaunchError>> {
    children.poll_child_signal(cx)
}
pub(crate) fn exit(event: &Reaped) -> gnunet_arm_service_core::Exit {
    match event.exit {
        native::ChildExit::Exited(code) => gnunet_arm_service_core::Exit::Exited(code as u32),
        native::ChildExit::Signaled { signal, .. } => {
            gnunet_arm_service_core::Exit::Signaled(signal as u32)
        }
    }
}
pub(crate) fn poll_control(
    _control: &mut Control,
    _children: &mut ChildRegistry,
    _child: &OriginalChild,
    _cx: &mut Context<'_>,
) -> Poll<Result<ControlEvent, LaunchError>> {
    Poll::Pending
}
pub(crate) fn poll_stop(
    children: &mut ChildRegistry,
    child: &OriginalChild,
    _control: &mut Control,
    _cx: &mut Context<'_>,
) -> Poll<Result<(), LaunchError>> {
    Poll::Ready(children.signal(child, libc::SIGTERM).map(|_| ()))
}
pub(crate) fn kill(children: &mut ChildRegistry, child: &OriginalChild) -> Result<(), LaunchError> {
    children.signal_native(child, libc::SIGKILL)
}

pub(crate) fn take_signal_notice(_control: &mut Control) -> Option<LaunchError> {
    None
}

#[cfg(feature = "service")]
pub(crate) fn child_capacity(limits: ProcessLimits) -> usize {
    limits.launch.max_children
}
#[cfg(feature = "service")]
pub(crate) fn force_stop(
    children: &mut ChildRegistry,
    child: &OriginalChild,
) -> Result<(), LaunchError> {
    children.signal_native(child, libc::SIGTERM)
}
