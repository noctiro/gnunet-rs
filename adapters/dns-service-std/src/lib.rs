//! Caller-driven production DNS interception SERVICE, actual privileged Rust
//! helper and DNSSTUB ports. No client protocol, resolver or task is hidden.
#![forbid(unsafe_code)]
#![cfg(unix)]
pub use gnunet_dns_interception as core;
mod gateway;
#[cfg(target_os = "linux")]
pub mod platform;
mod server;
mod transport;
pub use gateway::{Gateway, GatewayLimits, GatewayProgress, GatewayReport, RejectedGateway};
pub use server::{Error, Event, Limits, Progress, Report, Server};
pub use transport::{Helper, HelperEvent, HelperExit, HelperOptions};
