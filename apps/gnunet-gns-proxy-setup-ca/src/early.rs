//! Capture original native inheritance before allocating other resources.
use crate::Cause;
use gnunet_service_startup::ClientStartup;
#[expect(
    unsafe_code,
    reason = "Once-only native inheritance capture is the fresh executable's first resource operation"
)]
pub(super) fn capture() -> Result<ClientStartup, Cause> {
    // SAFETY: fresh single-threaded executable before logger, files or runtime;
    // no competing inheritance capture or route/environment mutation exists.
    Ok(unsafe { ClientStartup::capture()? })
}
