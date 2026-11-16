//! Actual bounded Rust PEERSTORE WAL and official caller-driven IPC service.
#![forbid(unsafe_code)]
pub mod backend;
pub mod server;
pub mod worker;
