//! Caller-driven production DNS interception SERVICE, actual privileged Rust
//! helper and DNSSTUB ports. No client protocol, resolver or task is hidden.
#![forbid(unsafe_code)]
pub use gnunet_dns_interception as core;
const UPSTREAM_SOCKETS: usize = 16;
/// Standard or provider-native DNSSTUB I/O over the shared bounded owner.
pub mod upstream;
pub use upstream::{Upstream, UpstreamRetirement};
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub mod flow_relay;
mod gateway;
pub mod packet;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use packet_source::{FlowLimits, FlowRetirement, RejectedFlow};
mod packet_source;
#[cfg(windows)]
pub use packet_source::{CaptureRetirement, WfpLimits, WfpRetirement};
pub use packet_source::{PacketExposure, PacketSource, Retirement};
#[cfg(target_os = "linux")]
pub use packet_source::{
    TransparentFamilies, TransparentInterfaces, TransparentPort, TransparentRetirement,
};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub mod platform;
mod server;
mod transport;
pub use gateway::{Gateway, GatewayLimits, GatewayProgress, GatewayReport, RejectedGateway};
pub use server::{Error, Event, Limits, Progress, Report, Server};
pub use transport::{Helper, HelperEvent, HelperExit, HelperOptions};
