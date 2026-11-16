//! Unique fresh-process capture before logging, runtime or identity providers.
use crate::Failure;
use gnunet_service_runtime::Activation;
use gnunet_service_startup::ParentControl;
pub(super) struct Captured {
    pub activation: Activation,
    pub parent: Option<ParentControl>,
    #[cfg(unix)]
    pub notice: Option<gnunet_service_startup::ControlNotice>,
}
#[expect(
    unsafe_code,
    reason = "Sole first-process initialization transfers original inherited native resources before competing owners exist"
)]
pub(super) fn capture() -> Result<Captured, Failure> {
    #[cfg(unix)]
    {
        use gnunet_service_startup::{InheritedMode, InheritedResources};
        // SAFETY: run calls this first, before logger/files/runtime/threads or
        // environment and descriptor-table mutation can compete with capture.
        let captured = unsafe {
            gnunet_service_startup::capture_from_environment(InheritedMode::AdoptListeners)
        }?;
        let InheritedResources::Listeners(activation) = captured.inherited else {
            return Err("TCP received the wrong inherited startup route".into());
        };
        Ok(Captured {
            activation,
            parent: captured.parent_control,
            notice: captured.control_notice,
        })
    }
    #[cfg(windows)]
    {
        // SAFETY: same unique first-initialization contract, before any native
        // resource owner, runtime, worker, logger or environment mutation exists.
        let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
        let activation = captured
            .activation
            .map(|incoming| Activation::from_imported(incoming.materialize()?))
            .transpose()?
            .unwrap_or_default();
        Ok(Captured {
            activation,
            parent: captured.parent_control,
        })
    }
}
