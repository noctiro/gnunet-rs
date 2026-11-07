//! Process-local generic GNUnet startup ownership primitives.
//! Early capture is the sole foreign descriptor boundary; privilege operations
//! must run in the new service process before unrelated asynchronous work.
#![deny(unsafe_code, missing_docs)]
mod account;
pub use account::configured_user;
#[cfg(unix)]
mod control;
/// Explicit fresh-process detachment and once-only real child readiness.
#[cfg(unix)]
pub mod daemon;
#[cfg(unix)]
mod early;
#[cfg(unix)]
pub use control::ControlReceiver;
#[cfg(unix)]
mod privilege;
#[cfg(unix)]
mod ready;
#[cfg(unix)]
pub use early::{
    CapturedStartup, ControlNotice, InheritedMode, InheritedResources, ParentControl, RebindHold,
    ReleasePhase, ReleaseReport, capture_from_environment,
};
#[cfg(unix)]
pub use privilege::{
    GroupsProfile, Identity, PrivilegeError, PrivilegePlan, PrivilegeReport, PrivilegeRoute,
    PrivilegeStage, apply_privileges, resolve_user,
};
#[cfg(unix)]
pub use ready::{ReadyStatus, ReadyWriter};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{IdentityError, IdentityMismatch, verify_configured_identity};
