//! First-operation capture for a client with no listening-service role.
use crate::Cause;
pub(super) use gnunet_service_startup::ClientStartup as Inherited;
#[expect(
    unsafe_code,
    reason = "Sole fresh-process inheritance capture before any competing native owner"
)]
pub(super) fn capture() -> Result<Inherited, Cause> {
    // SAFETY: first action in run, before configuration, logging, runtime or threads.
    Ok(unsafe { Inherited::capture() }?)
}
