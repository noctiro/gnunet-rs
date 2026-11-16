//! Once-only ownership transfer before any logging/config/runtime/store opens.
use crate::Failure;
use gnunet_service_runtime::Activation;
use gnunet_service_startup::ParentControl;
#[cfg(unix)]
use gnunet_service_startup::{ControlNotice, InheritedMode, InheritedResources};
pub(super) struct Inherited {
    pub activation: Activation,
    pub parent: Option<ParentControl>,
    #[cfg(unix)]
    pub notice: Option<ControlNotice>,
}
#[expect(
    unsafe_code,
    reason = "First single-threaded exec-child operation exclusively adopts parent-declared descriptors exactly once"
)]
pub(super) fn capture() -> Result<Inherited, Failure> {
    // SAFETY: first operation in main before configuration, logging, runtime,
    // storage or other FD owners; this is the sole inherited-descriptor capture.
    #[cfg(unix)]
    {
        // SAFETY: this fresh process performs the sole inheritance transfer
        // before logging, configuration, runtime or competing descriptor owners.
        let captured = unsafe {
            gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)?
        };
        let activation = match captured.inherited {
            InheritedResources::Listeners(a) => a,
            InheritedResources::CloseAfterBind(_) => {
                return Err("wrong REST descriptor route".into());
            }
        };
        Ok(Inherited {
            activation,
            parent: captured.parent_control,
            notice: captured.control_notice,
        })
    }
    #[cfg(windows)]
    {
        // SAFETY: same unique initial process transfer; capture failure exits.
        let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
        let activation = captured
            .activation
            .map(|incoming| Activation::from_imported(incoming.materialize()?))
            .transpose()?
            .unwrap_or_default();
        Ok(Inherited {
            activation,
            parent: captured.parent_control,
        })
    }
}
