//! Native parent control capture; a client never imports service listeners.
use super::Inherited;
#[expect(
    unsafe_code,
    reason = "Sole fresh-process capture before PROGRAM configuration, logger, runtime or competing native owners"
)]
pub(crate) fn capture() -> Result<Inherited, Box<dyn std::error::Error>> {
    // SAFETY: first native initialization in this normal command; on failure
    // startup exits rather than attempting another capture or socket import.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
    if captured.activation.is_some() {
        return Err("client program cannot receive service listener activation".into());
    }
    Ok(Inherited {
        parent: captured.parent_control,
        notice: None,
    })
}
