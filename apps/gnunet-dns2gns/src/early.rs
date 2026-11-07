//! First inherited descriptor transfer before logger/runtime construction.
use crate::Cause;
use gnunet_service_startup::{ControlNotice, InheritedMode, InheritedResources, ParentControl};
pub(super) struct Early {
    pub parent: Option<ParentControl>,
    pub notice: Option<ControlNotice>,
}
#[expect(
    unsafe_code,
    reason = "Unique first startup transfer before logger, runtime, stdio reader or other fd owner in this fresh executable"
)]
pub(super) fn capture() -> Result<Early, Cause> {
    // SAFETY: called first by this single-threaded fresh executable. No prior
    // fd/env capture, threads, environment edits or competing resource owners.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let nonempty = !hold.is_empty();
            let report = hold.abort();
            if nonempty {
                return Err(format!(
                    "DNS2GNS PROGRAM binds its own UDP sockets; it accepts no inherited listening socket; retired inherited descriptors: {report:?}"
                )
                .into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected DNS2GNS activation mode".into());
        }
    }
    Ok(Early {
        parent: captured.parent_control,
        notice: captured.control_notice,
    })
}
