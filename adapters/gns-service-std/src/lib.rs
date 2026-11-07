//! Owned GNS service business state around the actual pure resolver.
//!
//! Explicit business/dependency owners and the official GNS IPC frontend.
//! The installed SERVICE retains the process clock, broker and actual cleanup.
//! Full DNS security is supplied by the separately installed validating factory;
//! IPC readiness alone is no proof of runtime or mixed-node interoperability.
#![forbid(unsafe_code)]
#[expect(
    clippy::result_large_err,
    reason = "Original inline NAMECACHE orphan receipts preserve ownership without a new fallible allocation on error; auxiliary ports share this exact native error"
)]
pub mod auxiliary;
/// Actual DNS PRE_RESOLUTION callbacks sharing the business Manager.
pub mod interceptor;
pub mod manager;
#[expect(
    clippy::result_large_err,
    reason = "Keep the bounded original NAMECACHE completion and its source inline in native errors; avoid adding a heap allocation or discarding the actual outcome"
)]
pub mod native;
pub mod ports;
pub mod refresh;
pub mod server;
pub use gnunet_gns::{EffectId, Failure, Instance, Limits, Lookup, QueryId, Record};
pub use manager::{Cause, Event, Manager};
pub use ports::{Bounds, Close, NativeFailure, Operation, Provider, Shared, Value};
