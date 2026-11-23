//! Platform-native packet owner, independent of the shared packet reactor.
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::OwnedTun;
#[cfg(target_os = "freebsd")]
pub use unix::{
    FreeBsdRecovery, FreeBsdRecreate, FreeBsdRecreateStartError, FreeBsdRecreated, FreeBsdReopen,
    FreeBsdReopenError, FreeBsdReopenStage, FreeBsdReopenStartError, FreeBsdReopened,
    FreeBsdRestartError, FreeBsdRestartStage, FreeBsdRouteKey, FreeBsdUnconfirmedClose,
    FreeBsdVacancy,
};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{
    OwnedTun, WintunAdoptionError, WintunRecovery, WintunReopen, WintunReopenError,
    WintunReopenStage, WintunReplacement, WintunReplacementKind, WintunRestartError,
    WintunRestartStage, WintunScopeRetirement,
};
