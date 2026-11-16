//! Platform launch and termination over original registry ownership.
use super::{Cause, Settings};
use gnunet_service_runtime::process as runtime;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as native;
#[cfg(windows)]
mod windows;
pub(super) use native::spawn;
#[cfg(windows)]
use windows as native;
#[cfg(unix)]
pub(super) type RegistryError = runtime::LaunchError;
#[cfg(windows)]
pub(super) type RegistryError = runtime::RegistryError;

/// Actual platform exit observation; Windows codes retain their full width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Exit {
    /// Unix normal exit status.
    Exited(i32),
    /// Unix signal termination and native core-dump flag.
    Signaled {
        /// Native signal.
        signal: i32,
        /// Native core-dump observation.
        core_dumped: bool,
    },
    /// Full unsigned Windows process exit word.
    Windows(u32),
}
impl Exit {
    /// Whether the original completed invocation exited with code zero.
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Exited(0) | Self::Windows(0))
    }
}
/// Native mechanism used for the first requested child stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopMethod {
    /// Unix SIGTERM while original wait ownership remains live.
    SignalTerm,
    /// Windows TerminateProcess on the original registry-held process handle.
    TerminateProcess,
}
#[derive(Clone, Copy)]
pub(super) enum StopKind {
    Terminate,
    Force,
}
#[cfg(unix)]
pub(super) const STOP_METHOD: StopMethod = StopMethod::SignalTerm;
#[cfg(windows)]
pub(super) const STOP_METHOD: StopMethod = StopMethod::TerminateProcess;

pub(super) fn registry_error(error: RegistryError) -> Cause {
    #[cfg(unix)]
    {
        Cause::Launch(error)
    }
    #[cfg(windows)]
    {
        Cause::Registry(error)
    }
}
pub(super) fn exit(event: runtime::Reaped) -> Exit {
    #[cfg(unix)]
    {
        match event.exit {
            runtime::ChildExit::Exited(code) => Exit::Exited(code),
            runtime::ChildExit::Signaled {
                signal,
                core_dumped,
            } => Exit::Signaled {
                signal,
                core_dumped,
            },
        }
    }
    #[cfg(windows)]
    {
        Exit::Windows(event.exit_code)
    }
}
pub(super) fn stop(
    registry: &mut runtime::ChildRegistry,
    child: &runtime::OriginalChild,
    kind: StopKind,
) -> Result<(), Cause> {
    #[cfg(unix)]
    {
        registry
            .signal_native(
                child,
                match kind {
                    StopKind::Terminate => libc::SIGTERM,
                    StopKind::Force => libc::SIGKILL,
                },
            )
            .map_err(registry_error)
    }
    #[cfg(windows)]
    {
        let _kind = kind;
        registry.terminate(child, 1).map_err(registry_error)
    }
}

pub(super) fn environment(
    values: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    cwd: std::path::PathBuf,
) -> Result<runtime::EnvironmentSnapshot, Cause> {
    #[cfg(unix)]
    {
        runtime::EnvironmentSnapshot::from_values(values, cwd).map_err(Cause::Launch)
    }
    #[cfg(windows)]
    {
        runtime::EnvironmentSnapshot::from_values(values, cwd, Default::default())
            .map_err(Cause::Io)
    }
}
