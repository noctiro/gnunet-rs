//! Platform-native packet owner, independent of the shared packet reactor.
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::OwnedTun;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    OwnedTun, WintunAdoptionError, WintunRecovery, WintunReopen, WintunReopenError,
    WintunReopenStage, WintunReplacement, WintunReplacementKind, WintunRestartError,
    WintunRestartStage, WintunScopeRetirement,
};
