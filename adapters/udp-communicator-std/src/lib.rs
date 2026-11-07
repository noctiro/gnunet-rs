//! Rust-native UDP resources and explicitly fenced durable replay admission.
//! No production C backend or dependency on TRANSPORT service ownership.
#![forbid(unsafe_code)]
#![cfg(unix)]
#[cfg(feature = "transport")]
pub mod driver;
#[cfg(feature = "pils-client")]
pub mod identity;
pub mod replay;
pub mod socket;
#[cfg(feature = "transport")]
pub mod transport;

/// Bounded multi-peer dispatch on the original sockets and one TRANSPORT MQ.
#[cfg(feature = "transport")]
pub mod communicator;

/// Actual interface-bound clear LAN discovery on the original UDP sockets.
#[cfg(feature = "transport")]
pub mod discovery;

/// Actual public NAT burst composition for the normal communicator.
#[cfg(feature = "transport")]
pub use communicator::burst;
