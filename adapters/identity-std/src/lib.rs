//! Bounded actual GNUnet v0.29.1 IDENTITY SERVICE with independent marked store.
#![cfg(unix)]
#![forbid(unsafe_code)]
/// Actual private Rust store, durable snapshot publication and retained uncertainty.
pub mod backend;
/// Actual accepted MQ, bounded snapshot cursors and original persistence receipts.
pub mod server;
/// Explicit single-worker ownership; no service constructor spawns a thread.
pub mod worker;
