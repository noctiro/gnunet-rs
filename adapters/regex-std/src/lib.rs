//! Actual official REGEX MQ ownership over the supplied distributed Core.
//! No hidden DHT/PILS service, ACK, DONE or private cancel frame is created.
#![cfg(unix)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
/// Actual caller-owned DHT source contract; no default/network implementation.
pub mod dht;
/// One actual host/signer/provider coordinator.
pub mod driver;
/// Actual PILS-backed original signing owner.
pub mod pils;
mod server;
mod types;
pub use gnunet_regex_service as core;
pub use server::Server;
pub use types::*;
