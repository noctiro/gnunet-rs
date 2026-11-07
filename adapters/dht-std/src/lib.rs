//! Native official DHT service over original CORE/PILS/NSE/HELLO sources.
//! Callers retain the actual listeners, PROGRAM clock/Resolver and stop owner.
#![forbid(unsafe_code)]
#![cfg(unix)]
mod types;
pub use types::*;
mod budget;
mod discovery;
/// Bounded native direct-IP DHT underlay; UDP identity fields are claims only.
pub mod ip;
mod neighbours;
mod own_hello;
mod server;
mod signer;
pub use server::Server;
