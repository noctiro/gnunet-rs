//! ARM-self creation over the shared Windows producer and qualified bootstrap.
mod bootstrap;
mod environment;
use super::{CommandPlan, LibexecContext, Started, plan};
use crate::process::{self, RegistryError};
pub use crate::process::{ChildRegistry, EnvironmentSnapshot, LaunchError, Reaped};
use gnunet_arm_core::client::{StartupResult, StdioInheritance};
use gnunet_config::{BinaryPathCache, Configuration};
use gnunet_service_startup::{ParentFailure, ParentRole, launch};
use std::{
    future::poll_fn,
    io,
    sync::Arc,
    task::{Context, Poll},
};

/// Finite native launch bounds, independent of GNUnet wire/configuration values.
#[derive(Clone, Copy, Debug)]
pub struct LaunchLimits {
    /// Windows UTF-16 command/environment and inherited-handle bounds.
    pub native: process::LaunchLimits,
    /// Maximum GNUnet command text bytes before native argument decoding.
    pub max_command_bytes: usize,
    /// Maximum active or completed children retained by this launcher.
    pub max_children: usize,
}
impl Default for LaunchLimits {
    fn default() -> Self {
        Self {
            native: Default::default(),
            max_command_bytes: 1024 * 1024,
            max_children: 64,
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
pub(crate) use bootstrap::StartupSignal;
/// Local ARM launcher borrowing the caller's original process/wait authority.
/// Canceling an operation leaves its bootstrap with this launcher. Drop closes
/// remaining endpoints without terminating or waiting for original children.
pub struct LocalLauncher<'registry> {
    config: Configuration,
    limits: LaunchLimits,
    environment: EnvironmentSnapshot,
    libexec: LibexecContext<'registry>,
    registry: &'registry mut ChildRegistry,
    last_error: Option<io::Error>,
    bootstraps: Vec<bootstrap::Pending>,
}
impl<'registry> LocalLauncher<'registry> {
    /// Capture native environment/cwd. No helper, shell or child is started.
    pub fn new(
        config: Configuration,
        limits: LaunchLimits,
        registry: &'registry mut ChildRegistry,
    ) -> Result<Self, LaunchError> {
        Self::initialize(
            config,
            limits,
            EnvironmentSnapshot::system()?,
            registry,
            LibexecContext::Native,
        )
    }
    /// Use explicit native environment/cwd and a caller-owned libexec cache.
    pub fn with_environment(
        config: Configuration,
        limits: LaunchLimits,
        environment: EnvironmentSnapshot,
        registry: &'registry mut ChildRegistry,
        cache: &'registry mut BinaryPathCache,
    ) -> Result<Self, LaunchError> {
        Self::initialize(
            config,
            limits,
            environment,
            registry,
            LibexecContext::Scoped(cache),
        )
    }
    fn initialize(
        config: Configuration,
        limits: LaunchLimits,
        environment: EnvironmentSnapshot,
        registry: &'registry mut ChildRegistry,
        libexec: LibexecContext<'registry>,
    ) -> Result<Self, LaunchError> {
        if limits.max_command_bytes == 0
            || limits.max_children == 0
            || limits.native.command_units == 0
            || limits.native.environment_units == 0
            || limits.native.environment_entries == 0
        {
            return Err(LaunchError::InvalidInput);
        }
        let mut bootstraps = Vec::new();
        bootstraps
            .try_reserve_exact(limits.max_children)
            .map_err(|_| LaunchError::Capacity)?;
        Ok(Self {
            config,
            limits,
            environment,
            registry,
            libexec,
            last_error: None,
            bootstraps,
        })
    }
    pub(crate) fn prepare_if_runtime(&mut self) -> Result<(), LaunchError> {
        // Windows kernel exit observations are registered per original child.
        Ok(())
    }
    pub(crate) fn child_capacity_available(&self) -> bool {
        self.bootstraps.len() < self.limits.max_children
            && self.registry.credit_available(self.limits.max_children)
    }
    pub(crate) fn configure(&mut self, config: Configuration) -> Result<(), LaunchError> {
        self.config = config;
        Ok(())
    }
    pub(crate) fn poll_child_signal(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), LaunchError>> {
        // Failed bootstrap observations remain available through take_error and
        // the original operation; cancellation does not create a new callback.
        let progressed = self.poll_bootstraps(cx).unwrap_or(true);
        match self.registry.poll_child_signal(cx).map_err(registry_error) {
            Poll::Pending if progressed => Poll::Ready(Ok(())),
            result => result,
        }
    }
    fn poll_bootstraps(&mut self, cx: &mut Context<'_>) -> Result<bool, Arc<ParentFailure>> {
        let mut progressed = false;
        let mut index = 0;
        while index < self.bootstraps.len() {
            match self.bootstraps[index].poll(cx) {
                Poll::Pending => index += 1,
                Poll::Ready(outcome) => {
                    self.bootstraps.swap_remove(index);
                    if let Err(error) = outcome {
                        self.last_error = Some(io::Error::other(error.clone()));
                        return Err(error);
                    }
                    progressed = true;
                }
            }
        }
        Ok(progressed)
    }
    /// Number of original startup handshakes still requiring caller-driven I/O.
    pub fn pending_startups(&self) -> usize {
        self.bootstraps.len()
    }
    /// Settle pending startup handshakes without waiting for a live child's exit.
    /// A failure returns its actual cause and leaves other originals available
    /// for another call. Cancellation preserves the same drivers and observations;
    /// previously reported failures remain in their operation/take_error channel.
    pub async fn settle_startups(&mut self) -> Result<(), LaunchError> {
        poll_fn(|cx| match self.poll_bootstraps(cx) {
            Err(error) => Poll::Ready(Err(io::Error::other(error).into())),
            Ok(_) if self.bootstraps.is_empty() => Poll::Ready(Ok(())),
            Ok(_) => Poll::Pending,
        })
        .await
    }
    /// Last genuine preparation/spawn failure; separate from official result codes.
    pub fn take_error(&mut self) -> Option<io::Error> {
        self.last_error.take()
    }
    /// Consume one real original-process exit receipt.
    pub fn take_reaped(&mut self) -> Option<Reaped> {
        self.registry.take_reaped()
    }
    /// Number of admitted children whose original exit has not been reaped.
    pub fn pending_children(&self) -> usize {
        self.registry.pending_children()
    }
    /// Build official command text and native argv without invoking a shell.
    pub fn command_plan(&mut self) -> Result<Option<CommandPlan>, LaunchError> {
        if matches!(self.libexec, LibexecContext::Native) {
            self.environment = EnvironmentSnapshot::system()?;
        }
        let environment = environment::PlanEnvironment::new(&self.environment);
        let result = plan::prepare(
            &self.config,
            &environment,
            &mut self.libexec,
            self.limits.max_command_bytes,
            self.limits.native.arguments.saturating_add(1),
        );
        environment.finish(result)
    }
    pub(crate) fn start(&mut self, stdio: StdioInheritance) -> Result<Started, LaunchError> {
        self.last_error = None;
        self.reap_completed()?;
        if !self.child_capacity_available() {
            return Err(LaunchError::Capacity);
        }
        let Some(plan) = self.command_plan()? else {
            return Ok(Started {
                result: StartupResult::NotKnown,
                signal: None,
            });
        };
        let Some((argv0, arguments)) = plan.argv.split_first() else {
            return Ok(Started {
                result: StartupResult::Failed,
                signal: None,
            });
        };
        let executable = match process::resolve_executable(argv0, &self.environment) {
            Ok(executable) => executable,
            Err(error) => {
                self.last_error = Some(error);
                return Ok(Started {
                    result: StartupResult::Failed,
                    signal: None,
                });
            }
        };
        let mut environment = Vec::new();
        environment
            .try_reserve_exact(self.environment.values().len())
            .map_err(|_| LaunchError::Capacity)?;
        environment.extend_from_slice(self.environment.values());
        let inherited = |mask| {
            if stdio.0 & mask != 0 {
                process::Stdio::Inherit
            } else {
                process::Stdio::Null
            }
        };
        let observation = bootstrap::Prepared::new();
        let launched = launch::launch(
            self.registry,
            launch::Command {
                executable: &executable,
                argv0,
                arguments,
                environment,
                directory: self.environment.current_dir(),
                stdio: [inherited(1), inherited(2), inherited(4)],
                // ARM's own -d path detaches after fresh capture, keeping this PID.
                console: process::Console::Inherit,
                role: ParentRole::Supervisor,
                listeners: &[],
            },
            self.limits.native,
        );
        match launched {
            Ok(parent) => {
                let (pending, signal) = observation.finish(parent);
                self.bootstraps.push(pending);
                Ok(Started {
                    result: StartupResult::Starting,
                    signal: Some(signal),
                })
            }
            Err(failure) => {
                if failure.child.is_none()
                    && matches!(
                        failure.cause,
                        launch::LaunchCause::Registry(RegistryError::Capacity)
                    )
                {
                    return Err(LaunchError::Capacity);
                }
                // Failed setup is explicit retirement, never a Drop side effect.
                // No listener sources are exported by this local ARM-self path.
                let termination = failure
                    .child
                    .as_ref()
                    .and_then(|child| self.registry.terminate(child, 1).err());
                self.last_error = Some(io::Error::other(StartFailure {
                    failure,
                    termination,
                }));
                Ok(Started {
                    result: StartupResult::Failed,
                    signal: None,
                })
            }
        }
    }
    /// Reap only completed original children; never waits for a live process.
    pub fn reap_completed(&mut self) -> Result<usize, LaunchError> {
        self.registry.reap_completed().map_err(registry_error)
    }
    /// Explicitly wait/reap existing children without sending termination.
    /// Completed receipts remain available through [`Self::take_reaped`].
    pub async fn drain_children(&mut self) -> Result<(), LaunchError> {
        while self.registry.pending_children() != 0 || !self.bootstraps.is_empty() {
            poll_fn(|cx| {
                let _observed = self.poll_bootstraps(cx);
                Poll::Ready(())
            })
            .await;
            self.reap_completed()?;
            if self.registry.pending_children() != 0 || !self.bootstraps.is_empty() {
                poll_fn(|cx| self.poll_child_signal(cx)).await?;
            }
        }
        Ok(())
    }
}
#[derive(Debug)]
struct StartFailure {
    failure: launch::LaunchFailure,
    termination: Option<RegistryError>,
}
impl std::fmt::Display for StartFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.failure.fmt(f)?;
        if let Some(error) = &self.termination {
            write!(f, "; independent termination failure: {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for StartFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.failure)
    }
}
