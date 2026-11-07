//! Sole initial parent-declared descriptor transfer; this PROGRAM owns no listener.
use crate::Failure;
use gnunet_service_startup::{InheritedMode, InheritedResources, ParentControl};
pub(super) struct Inherited {
    pub parent: Option<ParentControl>,
    pub notice: Option<String>,
}
#[expect(
    unsafe_code,
    reason = "Sole single-threaded capture of explicitly inherited descriptors before any unrelated native owner or concurrent descriptor reuse"
)]
pub(super) fn capture() -> Result<Inherited, Failure> {
    // SAFETY: first operation in run, before logging/config/runtime/resources,
    // no concurrent environment mutation or second descriptor capture exists.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    let notice = captured
        .control_notice
        .map(|notice| format!("parent control declaration: {notice:?}"));
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let nonempty = !hold.is_empty();
            let report = hold.abort();
            if nonempty {
                return Err(format!(
                    "DATASTORE CLI has no service listener/readiness descriptor: {report:?}"
                )
                .into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected DATASTORE CLI descriptor mode".into());
        }
    }
    Ok(Inherited {
        parent: captured.parent_control,
        notice,
    })
}
