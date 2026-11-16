//! Native host for the independent Rust TRANSPORT engine and owned replay store.
//! Physical IPC ownership, durable storage and protocol state remain separate.
#![forbid(unsafe_code)]
mod framed;
pub mod peerstore;
mod server;
#[cfg(test)]
mod test_support;
pub use server::dv_bridge;
pub use server::{
    AddressStore, DvRetirementWork, NativeGuardEvent, NativeLimits, NativeRetirement,
    RetirementCause, Server, Step,
};

#[cfg(test)]
mod framing_regression;

/// Caller-driven application address discovery and bounded source ports.
pub mod discovery;
