//! Caller-driven official SETI SERVICE over real local IPC and CADET channels.
//! Socket cursors, immutable output and original loss facts remain owned across
//! canceled waits. No resolver, task, thread or peer backend is created implicitly.
#![forbid(unsafe_code)]
/// Actual bounded IPC/CADET service coordinator.
pub mod server;
pub use server::{Close, CloseCause, Error, Event, Limits, Progress, Report, Server};
