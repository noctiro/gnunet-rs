//! Native launch errors shared by process preparation and command parsing.
use std::io;
/// Real preparation/OS resource errors, distinct from source callback outcomes.
#[derive(Debug)]
pub enum LaunchError {
    /// Explicit finite resource bound was reached; no business outcome invented.
    Capacity,
    /// Original child/writer belongs to a foreign registry or was actually retired.
    Stale,
    /// Native command/environment contained an unrepresentable NUL/key.
    InvalidInput,
    /// Original configuration expansion/resource failure.
    Configuration(gnunet_config::Error),
    /// Actual pipe/spawn/poll/wait error.
    Io(io::Error),
}
impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Capacity => f.write_str("native launch resource capacity"),
            Self::Stale => f.write_str("stale original child authority"),
            Self::InvalidInput => f.write_str("invalid native launch input"),
            Self::Configuration(e) => write!(f, "launch configuration: {e}"),
            Self::Io(e) => write!(f, "native launch I/O: {e}"),
        }
    }
}
impl std::error::Error for LaunchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Configuration(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for LaunchError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<gnunet_config::Error> for LaunchError {
    fn from(e: gnunet_config::Error) -> Self {
        Self::Configuration(e)
    }
}
