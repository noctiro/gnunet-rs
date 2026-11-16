//! Caller-driven production DNS interception SERVICE, actual privileged Rust
//! helper and DNSSTUB ports. No client protocol, resolver or task is hidden.
#![forbid(unsafe_code)]
pub use gnunet_dns_interception as core;
const UPSTREAM_SOCKETS: usize = 16;
/// Bounded upstream profile shared by source preparation and gateway ownership.
pub type Upstream = gnunet_dnsstub_host::DnsStub<UPSTREAM_SOCKETS, { core::MAX_DNS_BYTES }, 4>;
mod gateway;
mod packet_source;
#[cfg(windows)]
pub use packet_source::CaptureRetirement;
pub use packet_source::{PacketExposure, PacketSource, Retirement};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
pub mod platform;
mod server;
mod transport;
pub use gateway::{Gateway, GatewayLimits, GatewayProgress, GatewayReport, RejectedGateway};
pub use server::{Error, Event, Limits, Progress, Report, Server};
pub use transport::{Helper, HelperEvent, HelperExit, HelperOptions};
