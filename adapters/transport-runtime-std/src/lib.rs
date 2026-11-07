//! Explicit Rust TRANSPORT/public-PEERSTORE runtime and capability-scoped signing.
//!
//! Standard operation uses the actual verified PILS service for original
//! asynchronous signatures. Optional local IKM access is an explicit capability.
#![forbid(unsafe_code)]
/// Original purpose29 signing and durable own-record port boundaries used by
/// the foreground runtime's bounded own-address publisher.
pub mod own;
/// Native original purpose7 signing and actual-cursor cancellation ownership.
pub mod own_aggregate;
mod own_publisher;
/// Actual fenced Journal backend retaining original managed projection owners.
pub mod own_store;
mod runtime;
/// Official configuration and foreground lifecycle composition.
pub mod startup;
pub use runtime::{
    Error, Limits, LocalKeyCapability, LocalPorts, Policies, Progress, Report, Runtime,
    ServicePorts,
};
