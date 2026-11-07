//! Real PT native composition. No host/GNS DNS substitutes for CADET discovery.
//! DNS exit discovery uses the original actual DHT client and shared process ports.
#![forbid(unsafe_code)]
pub mod discovery;
#[cfg(feature = "program")]
pub mod foreground;
pub mod metrics;
pub mod owner;
#[cfg(feature = "program")]
pub mod settings;
#[cfg(feature = "program")]
mod statistics;
pub use gnunet_pt as core;
pub use owner::{Event, Failure, Identities, Limits, Owner, Sources};
