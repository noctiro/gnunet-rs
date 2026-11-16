//! Owned verified native TUN/utun descriptors and caller-driven whole-packet I/O.
#![deny(unsafe_code)]
mod admin;
mod control;
#[cfg(unix)]
mod device;
#[cfg(unix)]
pub use device::{DeviceCleanupError, DeviceHandle, DeviceSetupError, IntoFdError};
#[cfg(target_os = "freebsd")]
pub use platform::InterfaceCleanupError;
#[cfg(unix)]
pub mod helper;
#[cfg(all(test, target_os = "freebsd"))]
#[path = "../tests/support/native_abi.rs"]
mod native_abi;
mod packet;
#[cfg(unix)]
mod platform;
mod reactor;
mod readiness;
mod recovery_budget;
pub use recovery_budget::RecoveryBudget;
#[cfg(unix)]
pub mod recovery;
mod route_types;
#[cfg(unix)]
mod routes;
#[cfg(windows)]
#[path = "routes/windows.rs"]
mod routes;
pub use admin::{AdminFailure, Ipv4Observation, NativeSnapshot, SnapshotOptions};
pub use control::{Action, ApplyFailure, Effect, EffectId, NativeApplied, Reported, Timing};
pub use packet::{Mode, PacketError, Version, decode, prefix, version};
pub use reactor::{
    AsyncTun, Loss, LossCause, ReadEvent, Received, RegistrationFailure, Unsent, WriteEvent,
    WriteId,
};
pub use readiness::{
    Ipv6Completion, Ipv6End, Ipv6Observation, Ipv6Progress, Ipv6State, Ipv6Target, Ipv6Watch,
    Ipv6WatchOptions,
};
pub use route_types::{RouteCompletion, RouteOutcome, RouteProgress, RouteSubmission};
pub use routes::{NativeRoute, RouteQuery};
mod route_query_types;
pub use route_query_types::{
    RouteQueryCompletion, RouteQueryEvidence, RouteQueryOutcome, RouteQueryProblem,
    RouteQueryProgress, RouteQuerySubmission, RouteQueryTarget, RouteRecord,
};
mod types;
use types::Stamp;
pub use types::{Epoch, Info, Limits};
mod owned;
pub use owned::OwnedTun;
#[cfg(windows)]
pub use owned::{
    WintunAdoptionError, WintunRecovery, WintunReopen, WintunReopenError, WintunReopenStage,
    WintunReplacement, WintunReplacementKind, WintunRestartError, WintunRestartStage,
    WintunScopeRetirement,
};

#[cfg(all(test, unix))]
mod model;

/// Explicit Windows provider provisioning and original native session types.
#[cfg(windows)]
pub use gnunet_native::wintun;
