//! Once-only original inheritance before configuration or runtime ownership.
use gnunet_service_startup::ParentControl;
pub(super) struct Inherited {
    #[cfg(unix)]
    pub tun: Option<std::os::fd::OwnedFd>,
    pub parent: Option<ParentControl>,
    #[cfg(unix)]
    pub notice: Option<gnunet_service_startup::ControlNotice>,
}
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(super) use unix::capture;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(super) use windows::capture;
