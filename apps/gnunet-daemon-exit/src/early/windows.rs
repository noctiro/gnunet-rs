//! Original native parent transfer; this PROGRAM owns no listening endpoints.
use super::Inherited;
use crate::Failure;
#[expect(
    unsafe_code,
    reason = "Sole fresh executable initialization transfers inherited resources before logging, files, runtime or other native owners"
)]
pub(crate) fn capture() -> Result<Inherited, Failure> {
    // SAFETY: first operation in main, before competing handles or initialization.
    let captured = unsafe { gnunet_service_startup::capture_from_environment() }?;
    if std::env::var_os("GNUNET_EXIT_TUN_FD").is_some() {
        return Err(
            "Windows EXIT uses explicit Wintun sessions; Unix TUN FD inheritance is unavailable"
                .into(),
        );
    }
    let activation = captured
        .activation
        .map(|incoming| gnunet_service_runtime::Activation::from_imported(incoming.materialize()?))
        .transpose()?
        .unwrap_or_default();
    if !activation.is_empty() {
        return Err(
            "EXIT PROGRAM has no local IPC listener and refuses inherited listeners".into(),
        );
    }
    Ok(Inherited {
        parent: captured.parent_control,
    })
}
