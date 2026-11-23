//! Native service process startup separated from protocol and application state.
//! Unix captures foreign descriptors before competing owners; Windows captures
//! only locations and opens fresh native resources. Process identity mechanisms
//! remain explicit and outside the shared async service host.
#![deny(unsafe_code, missing_docs)]
mod account;
mod client;
mod ready_status;
pub use account::{configured_user, configured_user_with};
pub use client::{ClientError, ClientStartup};
pub use ready_status::ReadyStatus;
#[cfg(any(unix, windows))]
mod stop;
#[cfg(any(unix, windows))]
pub use stop::{StopError, StopSignals, StopSubscription};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use unix::CapturedStartup;
#[cfg(unix)]
pub use unix::ControlNotice;
#[cfg(unix)]
pub use unix::ControlReceiver;
#[cfg(unix)]
pub use unix::GroupsProfile;
#[cfg(unix)]
pub use unix::Identity;
#[cfg(unix)]
pub use unix::InheritedMode;
#[cfg(unix)]
pub use unix::InheritedResources;
#[cfg(unix)]
pub use unix::ParentControl;
#[cfg(unix)]
pub use unix::PrivilegeError;
#[cfg(unix)]
pub use unix::PrivilegePlan;
#[cfg(unix)]
pub use unix::PrivilegeReport;
#[cfg(unix)]
pub use unix::PrivilegeRoute;
#[cfg(unix)]
pub use unix::PrivilegeStage;
#[cfg(unix)]
pub use unix::ReadyWriter;
#[cfg(unix)]
pub use unix::RebindHold;
#[cfg(unix)]
pub use unix::ReleasePhase;
#[cfg(unix)]
pub use unix::ReleaseReport;
#[cfg(unix)]
pub use unix::apply_privileges;
#[cfg(unix)]
pub use unix::capture_from_environment;
#[cfg(unix)]
pub use unix::daemon;
#[cfg(unix)]
pub use unix::resolve_user;
#[cfg(windows)]
pub use windows::CapturedStartup;
#[cfg(windows)]
pub use windows::ConnectedParent;
#[cfg(windows)]
pub use windows::ControlError;
#[cfg(windows)]
pub use windows::ControlReceiver;
#[cfg(windows)]
pub use windows::ControlSender;
#[cfg(windows)]
pub use windows::IdentityError;
#[cfg(windows)]
pub use windows::IdentityMismatch;
#[cfg(windows)]
pub use windows::ParentBootstrap;
#[cfg(windows)]
pub use windows::ParentControl;
#[cfg(windows)]
pub use windows::ParentFailure;
#[cfg(windows)]
pub use windows::ParentRole;
#[cfg(windows)]
pub use windows::ReadyFailure;
#[cfg(windows)]
pub use windows::ReadyReceipt;
#[cfg(windows)]
pub use windows::ReadySubmission;
#[cfg(windows)]
pub use windows::ReadyWriter;
#[cfg(windows)]
pub use windows::capture_from_environment;
#[cfg(windows)]
pub use windows::daemon;
#[cfg(windows)]
pub use windows::launch;
#[cfg(windows)]
pub use windows::verify_configured_identity;
