//! Native official DHT service over original CORE/PILS/NSE/HELLO sources.
//! Callers retain the actual listeners, PROGRAM clock/Resolver and stop owner.
#![forbid(unsafe_code)]
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
#[cfg(feature = "startup")]
pub mod startup;
pub use server::Server;

#[cfg(test)]
mod test_support;
