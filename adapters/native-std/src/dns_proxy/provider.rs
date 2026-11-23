//! Native DNS provider callbacks connected to one bounded Rust controller.
//!
//! The system extension and app extension share receiver and retirement owners.
mod accepted;
#[cfg(target_os = "ios")]
#[expect(
    unsafe_code,
    reason = "The app extension lends its live provider, flows and exact Apple completion blocks"
)]
mod app_extension;
mod availability;
mod bridge;
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "The system extension supplies its registered Objective-C subclass"
)]
mod class;
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "CoreFoundation main-loop calls use exact SDK signatures and a retained empty-capture native block"
)]
mod entry;
mod lease;
#[expect(
    unsafe_code,
    reason = "Original retained NetworkExtension objects and their exact native blocks"
)]
mod native;
mod requests;
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "Security.framework reads only this process's OS-reported entitlement and releases each owned CoreFoundation value"
)]
mod security;

pub use accepted::{AcceptedFlow, TcpFlowLoan, UdpFlowLoan};
#[cfg(target_os = "ios")]
pub use app_extension::AppExtensionCallbacks;
pub use bridge::{Controller, Event, ProviderLimits, ShutdownHandle};
#[cfg(target_os = "macos")]
pub use entry::{run_system_extension, stop_run_loop};
pub use lease::{ProviderLease, Session};
pub use requests::{StartRequest, StopRequest};

/// Objective-C runtime name used by the system extension's NEProviderClasses.
#[cfg(target_os = "macos")]
pub const PROVIDER_CLASS_NAME: &str = "GNUnetDNSProxyProvider";
