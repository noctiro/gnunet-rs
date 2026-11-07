//! First-operation parent FD ownership; a PROGRAM daemon has no IPC listener.
use crate::Failure;
use gnunet_service_startup::{ControlNotice, InheritedMode, InheritedResources, ParentControl};
pub(super) struct Inherited {
    pub parent: Option<ParentControl>,
    pub notice: Option<ControlNotice>,
}
#[expect(
    unsafe_code,
    reason = "Sole initial single-threaded transfer of parent-declared descriptors before unrelated native resources exist"
)]
pub(super) fn capture() -> Result<Inherited, Failure> {
    // SAFETY: first operation in run, before logging/configuration/runtime/native
    // owners, with no concurrent close/reuse/environment mutation or second capture.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let nonempty = !hold.is_empty();
            let report = hold.abort();
            if nonempty {
                return Err(format!("HOSTLIST has no IPC listener: refused inherited listener/readiness descriptors: {report:?}").into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected hostlist descriptor mode".into());
        }
    }
    Ok(Inherited {
        parent: captured.parent_control,
        notice: captured.control_notice,
    })
}
