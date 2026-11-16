//! Original inheritance and stdin captured before any logger or other file owner.
use crate::Cause;
use gnunet_service_startup::ParentControl;
use std::{fs::File, io};
pub(super) struct Early {
    pub stdin: io::Result<File>,
    pub parent: Option<ParentControl>,
    #[cfg(unix)]
    pub notice: Option<gnunet_service_startup::ControlNotice>,
}
#[expect(
    unsafe_code,
    reason = "Once-only native inheritance capture is the fresh executable's first resource operation"
)]
pub(super) fn capture() -> Result<Early, Cause> {
    // SAFETY: fresh single-threaded executable before logger, files or runtime;
    // no competing inheritance capture or route/environment mutation exists.
    let captured = unsafe { gnunet_service_startup::ClientStartup::capture()? };
    // A failed capture is retained and never retried after fd/handle allocation.
    // Help/version need not require a readable standard input route.
    let stdin = gnunet_native::stdio::stdin_file();
    Ok(Early {
        stdin,
        parent: captured.parent,
        #[cfg(unix)]
        notice: captured.notice,
    })
}
