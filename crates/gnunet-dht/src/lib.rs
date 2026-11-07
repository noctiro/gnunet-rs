//! Official DHT/R5N protocol mechanisms and bounded service state.
//!
//! The local service profile is a volatile cache and original-MQ operation
//! owner. Network routing/underlay and durable storage are separate capabilities
//! under construction; local admission is never a replication/storage ACK.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
/// Optional bounded local service and real volatile cache.
#[cfg(feature = "alloc")]
pub mod service;
/// Original peer-source routing, reverse routes and local service integration.
#[cfg(feature = "alloc")]
pub use service::network;

/// Exact purpose-6 path signing regions and verification.
pub mod path;
/// Allocation-free peer Bloom, XOR distance and R5N forwarding plans.
pub mod routing;
