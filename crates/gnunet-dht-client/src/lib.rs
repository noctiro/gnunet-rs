//! Official DHT IPC client ownership, independent of service/network hosting.
//!
//! Default builds expose original-instance tokens and borrowed wire definitions
//! without allocating or creating runtime work. Explicit `alloc` enables the
//! bounded logical client: GET/filter/monitor intent survives MQ replacement,
//! while one-shot PUT/offer writes are never replayed after loss.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(feature = "alloc")]
extern crate alloc;
/// Exact public borrowed DHT application IPC definitions.
pub use gnunet_wire::official::dht::ipc;
mod identity;
pub use identity::{AttemptId, Epoch, GetId, HelloId, Instance, MonitorId, OperationId};
#[cfg(feature = "alloc")]
mod owner;
#[cfg(feature = "alloc")]
pub use owner::*;
