//! Caller-owned fenced raw snapshot stores with explicit isolated namespaces.
//! Business state, secret interpretation, IPC and service runtimes stay outside.
#![cfg(unix)]
#![forbid(unsafe_code)]
/// Actual marker-qualified raw-body store and original durable receipts.
pub mod backend;
/// Explicit bounded single-worker admission, drain and actual thread join.
pub mod worker;
pub use backend::Namespace;
