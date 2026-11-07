//! Single early transfer; no listener or duplicate stdin ownership is invented.
use crate::Cause;
use gnunet_service_startup::{ControlNotice, InheritedMode, InheritedResources, ParentControl};
use std::io::{self, Stdin};
pub(super) struct Early {
    pub stdin: Stdin,
    pub parent: Option<ParentControl>,
    pub notice: Option<ControlNotice>,
}
#[expect(
    unsafe_code,
    reason = "First inherited descriptor transfer in a fresh single-threaded process before any logger, runtime, stdin reader or other descriptor owner"
)]
pub(super) fn capture() -> Result<Early, Cause> {
    // SAFETY: the executable calls this before every other process-resource
    // operation. No prior capture, competing owner, thread or environment edit.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let offered = !hold.is_empty();
            let report = hold.abort();
            if offered {
                return Err(format!("zoneimport has no listening endpoint; inherited descriptors retired: {report:?}").into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected zoneimport activation mode".into());
        }
    }
    Ok(Early {
        stdin: io::stdin(),
        parent: captured.parent_control,
        notice: captured.control_notice,
    })
}
