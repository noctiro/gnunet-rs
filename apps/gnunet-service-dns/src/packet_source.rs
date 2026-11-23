//! Platform provisioning is separate from shared interception scheduling.
use crate::Failure;
mod config;
pub(super) use config::read;
#[cfg(target_os = "linux")]
mod linux;
use gnunet_dns_service_host::PacketSource;
#[cfg(unix)]
use gnunet_dns_service_host::{Helper, HelperOptions};
#[cfg(windows)]
pub(super) mod windows;
#[derive(Clone, Copy)]
pub(super) enum Profile {
    Service,
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    Provider,
}
pub(super) enum Settings {
    #[cfg(unix)]
    Helper(HelperOptions),
    #[cfg(windows)]
    Windows(windows::Settings),
    #[cfg(target_os = "linux")]
    Transparent(linux::Settings),
    #[cfg(all(
        any(target_os = "macos", target_os = "ios"),
        feature = "apple-dns-proxy"
    ))]
    ApplicationFlows(gnunet_dns_service_host::FlowLimits),
}
impl Settings {
    pub fn label(&self) -> &'static str {
        match self {
            #[cfg(unix)]
            Self::Helper(_) => "helper",
            #[cfg(windows)]
            Self::Windows(settings) => settings.label(),
            #[cfg(target_os = "linux")]
            Self::Transparent(_) => "tproxy",
            #[cfg(all(
                any(target_os = "macos", target_os = "ios"),
                feature = "apple-dns-proxy"
            ))]
            Self::ApplicationFlows(_) => "application-flows",
        }
    }
}
pub(super) async fn open<'id>(
    settings: Settings,
    upstream: &mut gnunet_dns_service_host::Upstream,
    exit: std::net::IpAddr,
) -> Result<PacketSource<'id>, Failure> {
    let _ = (&upstream, exit);
    match settings {
        #[cfg(unix)]
        Settings::Helper(options) => Ok(PacketSource::helper(Helper::spawn(options)?)),
        #[cfg(windows)]
        Settings::Windows(options) => windows::open(options, upstream, exit).await,
        #[cfg(target_os = "linux")]
        Settings::Transparent(options) => linux::open(options, upstream, exit).await,
        #[cfg(all(
            any(target_os = "macos", target_os = "ios"),
            feature = "apple-dns-proxy"
        ))]
        Settings::ApplicationFlows(limits) => Ok(PacketSource::application_flows(limits)?),
    }
}
