//! GNUnet NAT: bounded pure protocol primitives and address-registration state.
//! No sockets, scheduler, subprocess, privilege or implicit success lives here.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
pub use gnunet_types::Error;
/// Portable Internet address fields, classification and binding policy.
pub mod address;
/// Public util burst datagrams and finite RTT synchronization; unauthenticated.
pub mod burst;
/// Exact official traversal ICMP packet formats; these are not authenticated.
pub mod icmp;
/// Actual bounded registration/provider/address state and notification queue.
#[cfg(feature = "alloc")]
pub mod state;
/// Standard STUN framing, padded attributes and transaction-bound observations.
pub mod stun;
