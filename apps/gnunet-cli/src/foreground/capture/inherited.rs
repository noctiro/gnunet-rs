//! Captured parent control without any adopted SERVICE listener.
use gnunet_service_startup::ParentControl;
pub(crate) struct Inherited {
    pub(crate) parent: Option<ParentControl>,
    pub(crate) notice: Option<String>,
}
