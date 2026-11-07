//! Official UDP communicator packet authentication and explicit session owners.
//! No socket, hidden randomness, clock, PILS daemon or production C backend.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
pub mod handshake;
mod identity;
#[cfg(feature = "alloc")]
pub mod receive;
#[cfg(feature = "alloc")]
pub mod send;
pub mod wire;
pub use identity::Identity;
/// Public peer identity bytes; these alone do not authenticate an endpoint.
pub type PeerId = [u8; 32];
