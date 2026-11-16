//! Official GNUnet local/TCP STATISTICS IPC on native hosts.
//!
//! One-shot clients retain original deadlines and retire canceled admitted I/O.
//! Persistent clients retain their own scheduling, reconnection and epoch state.
#![forbid(unsafe_code)]
#![cfg(any(unix, windows))]
mod client;
mod error;
mod framing;
pub mod handle;
pub mod producer;
pub mod server;
mod watch;
pub use client::StatisticsClient;
pub use error::IpcError;
/// Shared native address admission policy.
pub use gnunet_service_runtime::acl;
/// Official local address shaping shared by clients and hosts.
pub use gnunet_service_runtime::network;
pub use watch::StatisticsWatchClient;
