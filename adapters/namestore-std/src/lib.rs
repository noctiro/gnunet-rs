//! Actual caller-driven official NAMESTORE SERVICE using one explicit fenced
//! snapshot worker. No private identity runtime, GNS host, Resolver or task is
//! constructed. All private frames/snapshot bodies use erased owned storage.
#![cfg(unix)]
#![forbid(unsafe_code)]
pub use gnunet_snapshot_host::{backend, worker};
mod critical;
pub mod server;
pub use critical::critical_type;
