//! Official multi-peer CONSENSUS owners and bounded set/gradecast scheduling.
//! Native SET sources, authenticated peer facts, clocks and IO are caller-owned.
#![no_std]
#![forbid(unsafe_code)]
pub use gnunet_types::Error;
pub use gnunet_wire::official::consensus as wire;
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod session;
#[cfg(feature = "alloc")]
mod state;
#[cfg(feature = "alloc")]
mod types;
#[cfg(feature = "alloc")]
pub use session::Session;
#[cfg(feature = "alloc")]
pub use types::*;
