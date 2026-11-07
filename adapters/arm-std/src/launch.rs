//! Actual official ARM-self command preparation and shared process-port callbacks.
use crate::process;
pub use crate::process::{
    ChildExit, ChildRegistry, EnvironmentSnapshot, LaunchError, LaunchLimits, Reaped,
};
use gnunet_arm_core::client::{StartupResult, StdioInheritance};
use gnunet_config::{BinaryPathCache, Configuration, Environment, ProjectData};
use std::{
    ffi::OsString,
    io,
    os::{
        fd::AsFd,
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::PathBuf,
};
/// Exact concatenated native command and parser result, without shell expansion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPlan {
    /// Original eight-%s command string, including native quoting quirks.
    pub command: Vec<u8>,
    /// Actual native parser arguments, argv0 included.
    pub argv: Vec<OsString>,
    /// Actual source WEAKRANDOM/HOSTFILE daemon rule.
    pub daemonize: bool,
}
/// Shared official two-pass native command parser.
pub use crate::process::parse_command;
/// Actual local start result and exclusively owned signal read end. Starting
/// proves helper creation only, not successful target exec or service readiness.
pub(crate) struct Started {
    pub result: StartupResult,
    pub signal: Option<crate::process::readiness::RegisteredReadiness>,
}

/// Source-like local launcher with explicit environment, first-use libexec cache
/// and bounded real child registry. Dropping/canceling never signals a child.
enum LibexecContext<'registry> {
    Native,
    Scoped(&'registry mut BinaryPathCache),
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
    fn binary(&mut self, name: &[u8]) -> Result<Vec<u8>, LaunchError> {
        let project = ProjectData::default();
        let path = match &mut self.libexec {
            LibexecContext::Native => project.libexec_binary_path(name)?,
            LibexecContext::Scoped(cache) => {
                project.libexec_binary_path_with(name, &self.environment, cache)?
            }
        };
        Ok(path.into_os_string().into_vec())
    }

    /// Build exact official ARM command text/argv. Missing BINARY is None and maps
    /// to NotKnown only after a genuine readiness pipe was attempted by start.
    pub fn command_plan(&mut self) -> Result<Option<CommandPlan>, LaunchError> {
        if matches!(self.libexec, LibexecContext::Native) {
            self.environment = EnvironmentSnapshot::system()?;
        }
        let Some(binary) = self.config.get(b"arm", b"BINARY").map(<[u8]>::to_vec) else {
            return Ok(None);
        };
        let prefix = self
            .config
            .get(b"arm", b"PREFIX")
            .map(|v| self.config.expand_dollar(v, &self.environment))
            .transpose()?;
        let postfix = self
            .config
            .get(b"arm", b"OPTIONS")
            .map(|v| self.config.expand_dollar(v, &self.environment))
            .transpose()?;
        let config = match self
            .config
            .get_filename(b"arm", b"CONFIG", &self.environment)
        {
            Ok(p) => Some(p),
            Err(e @ gnunet_config::Error::Capacity)
            | Err(e @ gnunet_config::Error::Cycle)
            | Err(e @ gnunet_config::Error::Overflow) => return Err(e.into()),
            Err(_) => None,
        };
        let binary = self.binary(&binary)?;
        let daemonize = !(self.config.have_value(b"TESTING", b"WEAKRANDOM")
            && self
                .config
                .get_yesno(b"TESTING", b"WEAKRANDOM")
                .is_ok_and(|v| v)
            && !self.config.have_value(b"TESTING", b"HOSTFILE"));
        let mut command = Vec::new();
        let mut push = |v: &[u8]| -> Result<(), LaunchError> {
            if command
                .len()
                .checked_add(v.len())
                .is_none_or(|n| n > self.limits.max_command_bytes)
            {
                return Err(LaunchError::Capacity);
            }
            command
                .try_reserve(v.len())
                .map_err(|_| LaunchError::Capacity)?;
            command.extend_from_slice(v);
            Ok(())
        };
        if let Some(prefix) = prefix {
            push(&prefix)?;
            push(b" ")?;
            push(b"\"")?;
            push(&binary)?;
            push(b"\"")?;
        } else {
            push(&binary)?;
        }
        if let Some(config) = config {
            push(b" -c ")?;
            push(config.as_os_str().as_bytes())?;
        }
        if daemonize {
            push(b" -d")?;
        }
        if let Some(postfix) = postfix {
            push(b" ")?;
            push(&postfix)?;
        }
        let argv = parse_command(&command, self.limits.max_arguments)?;
        Ok(Some(CommandPlan {
            command,
            argv,
            daemonize,
        }))
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
                signal: Some(read),
            });
        };
        let Some(filename) = plan.argv.first().cloned() else {
            return Ok(Started {
                result: StartupResult::Failed,
                signal: Some(read),
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
            signal: Some(read),
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
