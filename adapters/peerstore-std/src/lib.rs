//! Actual bounded Rust PEERSTORE WAL and official caller-driven IPC service.
#![forbid(unsafe_code)]
#[cfg(unix)]
pub mod backend;
#[cfg(unix)]
pub mod server;
#[cfg(unix)]
pub mod worker;
