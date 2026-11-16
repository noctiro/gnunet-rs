//! Platform provisioning is separate from shared interception scheduling.
use crate::Failure;
use gnunet_dns_service_host::PacketSource;
#[cfg(unix)]
use gnunet_dns_service_host::{Helper, HelperOptions};
#[cfg(windows)]
pub(super) mod windows;
pub(super) enum Settings {
    #[cfg(unix)]
    Helper(HelperOptions),
    #[cfg(windows)]
    Windows(windows::Settings),
}
impl Settings {
    pub fn label(&self) -> &'static str {
        match self {
            #[cfg(unix)]
            Self::Helper(_) => "helper",
            #[cfg(windows)]
            Self::Windows(settings) => settings.label(),
        }
    }
}
pub(super) fn open<'id>(
    settings: Settings,
    upstream: &mut gnunet_dns_service_host::Upstream,
    exit: std::net::IpAddr,
) -> Result<PacketSource<'id>, Failure> {
    let _ = (&upstream, exit);
    match settings {
        #[cfg(unix)]
        Settings::Helper(options) => Ok(PacketSource::helper(Helper::spawn(options)?)),
        #[cfg(windows)]
        Settings::Windows(options) => windows::open(options, upstream, exit),
    }
}
