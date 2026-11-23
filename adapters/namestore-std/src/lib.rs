//! Actual caller-driven official NAMESTORE SERVICE using one explicit fenced
//! snapshot worker. No private identity runtime, GNS host, Resolver or task is
//! constructed. All private frames/snapshot bodies use erased owned storage.
#![cfg(any(unix, windows))]
#![forbid(unsafe_code)]
pub use gnunet_snapshot_host::{backend, worker};
/// Open and maintain the same authoritative snapshot used by the service.
pub mod database;
mod error;
pub use error::Error;
pub mod server;
mod snapshot;
pub use gnunet_namestore::critical_type;
