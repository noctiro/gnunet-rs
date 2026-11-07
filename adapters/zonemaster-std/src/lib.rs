//! Native zonemaster, real bounded crypto workers and explicit public DHT port.
#![forbid(unsafe_code)]
#[cfg(feature = "program")]
pub mod foreground;
pub mod metrics;
pub mod nonce;
pub mod owner;
pub mod publish;
pub mod service;
#[cfg(feature = "program")]
pub mod settings;
#[cfg(feature = "program")]
mod statistics;
pub use owner::{Identities, Owner, Sources};
pub mod worker;
pub use gnunet_zonemaster as core;
/// Independent actual boundary failure, never a forged publication receipt.
pub type Failure = Box<dyn std::error::Error>;
