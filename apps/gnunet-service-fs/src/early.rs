//! Once-only ownership transfer before any logging/config/runtime/cache opens.
use crate::Cause as Failure;
use gnunet_service_runtime::Activation;
use gnunet_service_startup::{ControlNotice, InheritedMode, InheritedResources, ParentControl};
pub(super) struct Inherited {
    pub activation: Activation,
    pub parent: Option<ParentControl>,
    pub notice: Option<ControlNotice>,
}
#[expect(
    unsafe_code,
    reason = "First single-threaded exec-child operation exclusively adopts parent-declared descriptors exactly once"
)]
pub(super) fn capture() -> Result<Inherited, Failure> {
    // SAFETY: first operation in main before configuration, logging, runtime,
    // cache or other FD owners; this is the sole inherited-descriptor capture.
    let captured =
        unsafe { gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)? };
    let activation = match captured.inherited {
        InheritedResources::Listeners(a) => a,
        InheritedResources::CloseAfterBind(_) => {
            return Err("wrong FS descriptor route".into());
        }
    };
    Ok(Inherited {
        activation,
        parent: captured.parent_control,
        notice: captured.control_notice,
    })
}
