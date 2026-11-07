//! Bounded conditional GNUnet CONVERSATION protocol and authenticated ringing.
//!
//! Native CADET, local IPC, current identity and time are supplied by the real
//! owner. This core never reads a key file, starts a worker, opens a device or
//! treats a local write as a remote pickup or media-delivery receipt.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
pub mod crypto;
#[cfg(feature = "alloc")]
mod session;
pub use gnunet_wire::official::conversation as wire;
#[cfg(feature = "alloc")]
pub use session::*;
/// Actual network peer bytes; a caller's ringing ego key can be different.
pub type Peer = [u8; 32];
/// Actual CADET port hash.
pub type Port = [u8; 64];
