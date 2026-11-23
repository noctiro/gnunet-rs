//! Windows ARM policy: native image selection and original-handle supervision.
use super::*;
use gnunet_native::process::{Console, LaunchLimits, Stdio};
use gnunet_native::socket_activation::Source;
use gnunet_service_runtime::process::RegistryError;
use gnunet_service_startup::{ParentRole, launch};
use std::{os::windows::io::AsSocket, sync::Arc};
mod account;
mod control;
pub(crate) use account::AccountPreparation;
pub(crate) use control::{Control, poll_control, poll_stop, take_signal_notice};

/// Borrowed native child context; Windows creates the selected image directly.
#[derive(Clone, Copy)]
pub struct LaunchContext<'a> {
    /// Explicit child environment and working-directory snapshot.
    pub environment: &'a EnvironmentSnapshot,
}
/// Finite Windows ARM launch bounds, separate from protocol/configuration keys.
#[derive(Clone, Copy, Debug)]
pub struct ProcessLimits {
    /// Native UTF-16, argument, environment and handle budgets.
    pub native: LaunchLimits,
    /// Active plus untaken completed children in the original registry.
    pub max_children: usize,
    /// Maximum original listeners published to one child.
    pub max_listeners: usize,
    /// Maximum local GNUnet command-text bytes before parsing.
    pub max_command_bytes: usize,
}
impl Default for ProcessLimits {
    fn default() -> Self {
        Self {
            native: LaunchLimits::default(),
            max_children: 64,
            max_listeners: 4096,
            max_command_bytes: 1024 * 1024,
        }
    }
}
fn registry_error(error: RegistryError) -> LaunchError {
    match error {
        RegistryError::Capacity => LaunchError::Capacity,
        RegistryError::Stale => LaunchError::Stale,
        RegistryError::Native(error) => LaunchError::Io(error),
    }
}
pub(crate) fn spawn(
    request: Request<'_>,
    limits: ProcessLimits,
    children: &mut ChildRegistry,
) -> Result<SpawnResult, LaunchError> {
    if !children.credit_available(limits.max_children)
        || request.listeners.len() > limits.max_listeners
    {
        return Err(LaunchError::Capacity);
    }
    if matches!(request.recipe, Recipe::Native { text, .. } if text.len() > limits.max_command_bytes)
    {
        return Err(LaunchError::Capacity);
    }
    let (filename, argv) =
        native_arguments(request.recipe, limits.native.arguments.saturating_add(1))?;
    let executable = match gnunet_service_runtime::process::resolve_executable(
        &filename,
        request.context.environment,
    ) {
        Ok(executable) => executable,
        Err(error) => return Ok(SpawnResult::Refused { error: Some(error) }),
    };
    let Some((argv0, arguments)) = argv.split_first() else {
        return Ok(SpawnResult::Refused {
            error: Some(io::ErrorKind::InvalidInput.into()),
        });
    };
    // Publish from private source descriptors. Managed-listener retirement can
    // close its own originals before the receiving child confirms import.
    let mut sources = Vec::new();
    sources
        .try_reserve_exact(request.listeners.len())
        .map_err(|_| LaunchError::Capacity)?;
    for original in &request.listeners {
        match socket2::SockRef::from(original).try_clone() {
            Ok(source) => sources.push(source),
            Err(error) => return Ok(SpawnResult::Refused { error: Some(error) }),
        }
    }
    let mut published = Vec::new();
    published
        .try_reserve_exact(sources.len())
        .map_err(|_| LaunchError::Capacity)?;
    published.extend(
        sources
            .iter()
            .zip(&request.listeners)
            .map(|(socket, original)| {
                let source = Source::new(socket.as_socket());
                match original.protection() {
                    Some(protection) => source.with_protection(protection),
                    None => source,
                }
            }),
    );
    // Reserve retained control backing before admitting the native process.
    let control_backing = control::Prepared::new();
    let launched = if let Some(profile) = request.profile {
        launch::launch_as(
            children,
            launch::AccountCommand {
                executable: &executable,
                argv0,
                arguments,
                profile,
                listeners: &published,
            },
            limits.native,
        )
    } else {
        let mut environment = Vec::new();
        environment
            .try_reserve_exact(request.context.environment.values().len())
            .map_err(|_| LaunchError::Capacity)?;
        environment.extend_from_slice(request.context.environment.values());
        launch::launch(
            children,
            launch::Command {
                executable: &executable,
                argv0,
                arguments,
                environment,
                directory: request.context.environment.current_dir(),
                stdio: [Stdio::Null, Stdio::Inherit, Stdio::Inherit],
                console: Console::Inherit,
                role: ParentRole::Supervisor,
                listeners: &published,
            },
            limits.native,
        )
    };
    let (child, initial, diagnostic) = match launched {
        Ok(parent) => (
            parent.child().clone(),
            control::Initial::Starting(parent),
            None,
        ),
        Err(failure) => {
            let Some(child) = failure.child.clone() else {
                if matches!(
                    failure.cause,
                    launch::LaunchCause::Registry(RegistryError::Capacity)
                ) {
                    return Err(LaunchError::Capacity);
                }
                return Ok(SpawnResult::Refused {
                    error: Some(io::Error::other(failure)),
                });
            };
            let failure = Arc::new(failure);
            let diagnostic = Some(LaunchError::Io(io::Error::other(failure.clone())));
            (child, control::Initial::Failed(failure), diagnostic)
        }
    };
    Ok(SpawnResult::Admitted(Spawned {
        child,
        diagnostic,
        control: control_backing.finish(initial, request.mode, sources),
    }))
}
pub(crate) fn prepare(_children: &mut ChildRegistry) -> Result<(), LaunchError> {
    // Native waits belong to each original process; there is no SIGCHLD owner.
    tokio::runtime::Handle::try_current()
        .map(|_| ())
        .map_err(|error| io::Error::other(error).into())
}
pub(crate) fn reap_completed(children: &mut ChildRegistry) -> Result<(), LaunchError> {
    children
        .reap_completed()
        .map(|_| ())
        .map_err(registry_error)
}
pub(crate) fn poll_exit(
    children: &mut ChildRegistry,
    cx: &mut Context<'_>,
) -> Poll<Result<(), LaunchError>> {
    children.poll_child_signal(cx).map_err(registry_error)
}
pub(crate) fn exit(event: &Reaped) -> gnunet_arm_service_core::Exit {
    gnunet_arm_service_core::Exit::Exited(event.exit_code)
}
pub(crate) fn kill(children: &mut ChildRegistry, child: &OriginalChild) -> Result<(), LaunchError> {
    children.terminate(child, 9).map_err(registry_error)
}

#[cfg(feature = "service")]
pub(crate) fn child_capacity(limits: ProcessLimits) -> usize {
    limits.max_children
}
#[cfg(feature = "service")]
pub(crate) fn force_stop(
    children: &mut ChildRegistry,
    child: &OriginalChild,
) -> Result<(), LaunchError> {
    children.terminate(child, 15).map_err(registry_error)
}
