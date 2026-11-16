//! Shared Unix startup mechanisms; native account/syscall differences stay inside their owning modules.
mod capture;
mod control;
/// Explicit fresh-process detachment and once-only original child readiness.
pub mod daemon;
mod privilege;
mod ready;
pub use capture::CapturedStartup;
pub use capture::ControlNotice;
pub use capture::InheritedMode;
pub use capture::InheritedResources;
pub use capture::ParentControl;
pub use capture::RebindHold;
pub use capture::ReleasePhase;
pub use capture::ReleaseReport;
pub use capture::capture_from_environment;
pub use control::ControlReceiver;
pub use privilege::GroupsProfile;
pub use privilege::Identity;
pub use privilege::PrivilegeError;
pub use privilege::PrivilegePlan;
pub use privilege::PrivilegeReport;
pub use privilege::PrivilegeRoute;
pub use privilege::PrivilegeStage;
pub use privilege::apply_privileges;
pub use privilege::resolve_user;
pub use ready::ReadyWriter;
