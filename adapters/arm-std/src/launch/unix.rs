//! Actual official ARM-self command preparation and shared process-port callbacks.
use super::{CommandPlan, LibexecContext, Started, plan};
use crate::process;
pub use crate::process::{
    ChildExit, ChildRegistry, EnvironmentSnapshot, LaunchError, LaunchLimits, Reaped,
};
use gnunet_arm_core::client::{StartupResult, StdioInheritance};
use gnunet_config::{BinaryPathCache, Configuration, Environment};
use std::{io, os::fd::AsFd, path::PathBuf};
pub(crate) struct StartupSignal(process::readiness::RegisteredReadiness);
impl StartupSignal {
    pub(crate) fn poll_completion(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.0.poll_ready(cx).map_ok(|_| ())
    }
}
/// Source-like local launcher borrowing caller-owned wait/cache authority.
pub struct LocalLauncher<'registry> {
    config: Configuration,
    helper: PathBuf,
    limits: LaunchLimits,
    environment: EnvironmentSnapshot,
    libexec: LibexecContext<'registry>,
    registry: &'registry mut ChildRegistry,
    last_error: Option<io::Error>,
}
impl<'registry> LocalLauncher<'registry> {
    /// Own a configuration snapshot and actual native environment; no child starts.
    pub fn new(
        config: Configuration,
        helper: PathBuf,
        limits: LaunchLimits,
        registry: &'registry mut ChildRegistry,
    ) -> Result<Self, LaunchError> {
        Self::initialize(
            config,
            helper,
            limits,
            EnvironmentSnapshot::system()?,
            registry,
            LibexecContext::Native,
        )
    }
    /// Explicit environment snapshot for self-contained embeddings/fixtures.
    pub fn with_environment(
        config: Configuration,
        helper: PathBuf,
        limits: LaunchLimits,
        environment: EnvironmentSnapshot,
        registry: &'registry mut ChildRegistry,
        cache: &'registry mut BinaryPathCache,
    ) -> Result<Self, LaunchError> {
        Self::initialize(
            config,
            helper,
            limits,
            environment,
            registry,
            LibexecContext::Scoped(cache),
        )
    }
    fn initialize(
        config: Configuration,
        helper: PathBuf,
        limits: LaunchLimits,
        environment: EnvironmentSnapshot,
        registry: &'registry mut ChildRegistry,
        libexec: LibexecContext<'registry>,
    ) -> Result<Self, LaunchError> {
        if limits.max_command_bytes == 0
            || limits.max_arguments == 0
            || limits.max_children == 0
            || limits.max_environment_bytes == 0
        {
            return Err(LaunchError::InvalidInput);
        }
        Ok(Self {
            config,
            helper,
            limits,
            environment,
            libexec,
            registry,
            last_error: None,
        })
    }
    pub(crate) fn poll_child_signal(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), LaunchError>> {
        self.registry.poll_child_signal(cx)
    }
    pub(crate) fn child_capacity_available(&self) -> bool {
        self.registry.credit_available(self.limits.max_children)
    }
    pub(crate) fn prepare_if_runtime(&mut self) -> Result<(), LaunchError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            self.registry.prepare()?;
        }
        Ok(())
    }
    pub(crate) fn configure(&mut self, config: Configuration) -> Result<(), LaunchError> {
        self.config = config;
        Ok(())
    }
    /// Detailed last genuine command-check/spawn failure, if any. The source
    /// callback still carries NotKnown/StartFailed/Starting, never this diagnostic.
    pub fn take_error(&mut self) -> Option<io::Error> {
        self.last_error.take()
    }
    /// Original actual child wait result, consumed from the caller-owned registry.
    pub fn take_reaped(&mut self) -> Option<Reaped> {
        self.registry.take_reaped()
    }
    /// Number of created children not yet actually reaped by this owner.
    pub fn pending_children(&self) -> usize {
        self.registry.pending_children()
    }
    /// Build the official ARM command without shell expansion or spawning.
    pub fn command_plan(&mut self) -> Result<Option<CommandPlan>, LaunchError> {
        if matches!(self.libexec, LibexecContext::Native) {
            self.environment = EnvironmentSnapshot::system()?;
        }
        plan::prepare(
            &self.config,
            &self.environment,
            &mut self.libexec,
            self.limits.max_command_bytes,
            self.limits.max_arguments,
        )
    }
    pub(crate) fn start(&mut self, stdio: StdioInheritance) -> Result<Started, LaunchError> {
        let snapshot = process::StdioSnapshot::capture(stdio.0)?;
        self.last_error = None;
        self.reap_completed()?;
        if !self.child_capacity_available() {
            return Err(LaunchError::Capacity);
        }
        let (read, write) = match process::pipe() {
            Ok(pipe) => pipe,
            Err(error) => {
                self.last_error = Some(error);
                return Ok(Started {
                    result: StartupResult::Failed,
                    signal: None,
                });
            }
        };
        let read =
            process::readiness::RegisteredReadiness::new(read).map_err(|error| error.error)?;
        let Some(plan) = self.command_plan()? else {
            return Ok(Started {
                result: StartupResult::NotKnown,
                signal: Some(StartupSignal(read)),
            });
        };
        let Some(filename) = plan.argv.first().cloned() else {
            return Ok(Started {
                result: StartupResult::Failed,
                signal: Some(StartupSignal(read)),
            });
        };
        let command = process::NativeCommand {
            filename,
            argv: plan.argv,
            environment: self.environment.clone(),
            environment_changes: Vec::new(),
            cwd: if matches!(self.libexec, LibexecContext::Native) {
                None
            } else {
                Some(self.environment.current_dir()?)
            },
            stdio: stdio.0,
            stdio_snapshot: Some(snapshot),
            listeners: vec![write.as_fd()],
            mappings: Vec::new(),
        };
        let result = match process::spawn(
            &self.config,
            &self.helper,
            command,
            process::ProcessLimits {
                launch: self.limits,
                ..process::ProcessLimits::default()
            },
            self.registry,
        )? {
            process::SpawnResult::Admitted(spawned) => {
                if let Some(control) = spawned.control {
                    self.registry.close_control(&control)?;
                }
                StartupResult::Starting
            }
            process::SpawnResult::Refused { error } => {
                self.last_error = error;
                StartupResult::Failed
            }
        };
        Ok(Started {
            result,
            signal: Some(StartupSignal(read)),
        })
    }
    /// Reap completed children while this launcher borrows the external registry.
    pub fn reap_completed(&mut self) -> Result<usize, LaunchError> {
        self.registry.reap_completed()
    }
    /// Explicitly drain existing children without killing them. After dropping
    /// this launcher/host, the caller still owns the same registry/wait authority.
    pub async fn drain_children(&mut self) -> Result<(), LaunchError> {
        self.registry.drain_children().await
    }
}
