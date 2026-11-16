//! Sole initial parent-declared descriptor transfer; this PROGRAM owns no listener.
use super::Inherited;
use gnunet_service_startup::{InheritedMode, InheritedResources};
#[expect(
    unsafe_code,
    reason = "Sole single-threaded capture of explicitly inherited descriptors before any unrelated native owner or concurrent descriptor reuse"
)]
pub(crate) fn capture() -> Result<Inherited, Box<dyn std::error::Error>> {
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
                    "client program has no service listener/readiness descriptor: {report:?}"
                )
                .into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected client program descriptor mode".into());
        }
    }
    Ok(Inherited {
        parent: captured.parent_control,
        notice,
    })
}
