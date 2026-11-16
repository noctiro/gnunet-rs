//! Native child ownership, launch and original-resource supervision.
mod command;
#[cfg(windows)]
mod environment;
mod error;
#[cfg(windows)]
mod executable;
mod identity;
pub use command::compose_arguments;
pub use command::parse_command;
#[cfg(windows)]
pub use environment::EnvironmentSnapshot;
pub use error::LaunchError;
#[cfg(windows)]
pub use executable::resolve_executable;
pub use identity::OriginalChild;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use crate::readiness;
#[cfg(windows)]
pub use gnunet_native::process::Console;
#[cfg(windows)]
pub use gnunet_native::process::ExportedHandle;
#[cfg(windows)]
pub use gnunet_native::process::LaunchLimits;
#[cfg(windows)]
pub use gnunet_native::process::Spawn as NativeCommand;
#[cfg(windows)]
pub use gnunet_native::process::Stdio;
#[cfg(unix)]
pub use unix::ChildExit;
#[cfg(unix)]
pub use unix::ChildRegistry;
#[cfg(unix)]
pub use unix::ControlWriterToken;
#[cfg(unix)]
pub use unix::DescriptorMap;
#[cfg(unix)]
pub use unix::EnvironmentChange;
#[cfg(unix)]
pub use unix::EnvironmentSnapshot;
#[cfg(unix)]
pub use unix::LaunchLimits;
#[cfg(unix)]
pub use unix::NativeCommand;
#[cfg(unix)]
pub use unix::PipeWriteOutcome;
#[cfg(unix)]
pub use unix::ProcessLimits;
#[cfg(unix)]
pub use unix::Reaped;
#[cfg(unix)]
pub use unix::ResourceUsage;
#[cfg(unix)]
pub use unix::SignalAttempt;
#[cfg(unix)]
pub use unix::SignalReport;
#[cfg(unix)]
pub use unix::SpawnResult;
#[cfg(unix)]
pub use unix::Spawned;
#[cfg(unix)]
pub use unix::StdioSnapshot;
#[cfg(unix)]
pub use unix::helper_main;
#[cfg(unix)]
pub use unix::pipe;
#[cfg(unix)]
pub use unix::spawn;
#[cfg(windows)]
pub use windows::ChildRegistry;
#[cfg(windows)]
pub use windows::Reaped;
#[cfg(windows)]
pub use windows::RegistryError;

#[cfg(windows)]
pub use gnunet_native::process::ResourceUsage;
