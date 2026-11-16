//! Windows process startup policy over native resources and shared status bytes.
mod capture;
mod control;
/// Explicit native detached re-exec with original-child readiness ownership.
pub mod daemon;
mod identity;
/// Explicit supervised process creation and original-child bootstrap ownership.
pub mod launch;
mod parent;
mod ready;
pub use capture::CapturedStartup;
pub use capture::ConnectedParent;
pub use capture::ParentControl;
pub use capture::ParentRole;
pub use capture::capture_from_environment;
pub use control::ControlError;
pub use control::ControlReceiver;
pub use control::ControlSender;
pub use identity::IdentityError;
pub use identity::IdentityMismatch;
pub use identity::verify_configured_identity;
pub use parent::ParentBootstrap;
pub use parent::ParentFailure;
pub use parent::ReadyReceipt;
pub use ready::ReadyFailure;
pub use ready::ReadySubmission;
pub use ready::ReadyWriter;
