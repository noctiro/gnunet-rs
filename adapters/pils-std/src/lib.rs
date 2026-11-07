//! Explicitly polled native PILS service. Protocol/identity decisions live in gnunet-pils.
#![forbid(unsafe_code)]
/// Typed caller-driven native PILS client, separate from the service host.
#[cfg(feature = "client")]
pub mod client;
#[cfg(unix)]
pub mod identity;
/// Production shared-runtime service, independent of the optional CLIENT.
#[cfg(all(unix, feature = "service"))]
pub mod service;
/// Official foreground preparation and configuration.
#[cfg(all(unix, feature = "service"))]
pub mod startup;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{Host, Limits, Progress};
