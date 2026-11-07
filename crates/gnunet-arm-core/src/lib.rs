//! Official GNUnet ARM codecs and explicit sans-I/O operation ownership.
//! Source baseline v0.29.1,346358e; no private wire or process execution.
#![no_std]
#![forbid(unsafe_code)]
mod transport;
pub mod wire;
pub use transport::{ConnectionEpoch, FrameSlot, FrameTicket};
pub mod client;
pub mod monitor;
