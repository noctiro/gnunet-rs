//! Explicitly polled native PILS service. Protocol/identity decisions live in gnunet-pils.
#![forbid(unsafe_code)]
/// Typed caller-driven native PILS client, separate from the service host.
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "service")]
mod host;
pub mod identity;
/// Production shared-runtime service, independent of the optional CLIENT.
#[cfg(feature = "service")]
pub mod service;
/// Official foreground preparation and configuration.
#[cfg(feature = "service")]
pub mod startup;
#[cfg(feature = "service")]
pub use host::{Host, Limits, Progress};
