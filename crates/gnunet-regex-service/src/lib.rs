//! Official REGEX distributed-service state, with no native/DHT implementation.
#![no_std]
#![forbid(unsafe_code)]
mod metrics;
pub use metrics::{METRIC_NAMES, Metrics};
mod state;
pub use state::{StateBlock, StateEdge};
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "alloc")]
mod types;
#[cfg(feature = "alloc")]
pub use types::*;
#[cfg(feature = "alloc")]
mod core;
#[cfg(feature = "alloc")]
pub use core::Core;
