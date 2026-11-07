//! Bounded online DNS-to-NAMESTORE business state and public record conversion.
//! Native callbacks, keys, source lifetimes and owned record payloads remain in
//! the caller. A queued action is never a DNS response or mutation receipt.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
pub use gnunet_types::Error;
mod types;
pub use types::*;
#[cfg(feature = "alloc")]
#[path = "core.rs"]
mod state;
#[cfg(feature = "alloc")]
pub use state::{CacheState, Core, ZoneFacts};
// The independent source-only converter is supplied by its single author.
pub mod conversion;
