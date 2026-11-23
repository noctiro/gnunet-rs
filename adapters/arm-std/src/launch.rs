//! Official ARM-self planning with platform-specific native child ownership.
use gnunet_arm_core::client::StartupResult;
use gnunet_config::BinaryPathCache;
use std::ffi::OsString;
mod plan;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub(crate) use unix::StartupSignal;
#[cfg(unix)]
pub use unix::{
    ChildExit, ChildRegistry, EnvironmentSnapshot, LaunchError, LaunchLimits, LocalLauncher, Reaped,
};
#[cfg(windows)]
pub(crate) use windows::StartupSignal;
#[cfg(windows)]
pub use windows::{
    ChildRegistry, EnvironmentSnapshot, LaunchError, LaunchLimits, LocalLauncher, Reaped,
};
/// GNUnet command description and native argument plan, without shell expansion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandPlan {
    /// Original command description before platform argument encoding.
    pub command: Vec<u8>,
    /// Actual arguments, including argv0. Executable and configuration paths
    /// remain literal. Configured prefix/options use the GNUnet text grammar.
    pub argv: Vec<OsString>,
    /// Actual source WEAKRANDOM/HOSTFILE daemon rule.
    pub daemonize: bool,
}
/// Shared official two-pass native command parser.
pub use crate::process::parse_command;

pub(crate) struct Started {
    pub result: StartupResult,
    pub signal: Option<StartupSignal>,
}
enum LibexecContext<'registry> {
    Native,
    Scoped(&'registry mut BinaryPathCache),
}
