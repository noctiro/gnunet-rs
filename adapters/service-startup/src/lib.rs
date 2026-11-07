//! Process-local generic GNUnet startup ownership primitives.
//! Early capture is the sole foreign descriptor boundary; privilege operations
//! must run in the new service process before unrelated asynchronous work.
#![cfg(unix)]
#![deny(unsafe_code, missing_docs)]
mod control;
/// Explicit fresh-process detachment and once-only real child readiness.
pub mod daemon;
mod early;
pub use control::ControlReceiver;
mod privilege;
mod ready;
pub use early::{
    CapturedStartup, ControlNotice, InheritedMode, InheritedResources, ParentControl, RebindHold,
    ReleasePhase, ReleaseReport, capture_from_environment,
};
pub use privilege::{
    GroupsProfile, Identity, PrivilegeError, PrivilegePlan, PrivilegeReport, PrivilegeRoute,
    PrivilegeStage, apply_privileges, configured_user, resolve_user,
};
pub use ready::{ReadyStatus, ReadyWriter};
