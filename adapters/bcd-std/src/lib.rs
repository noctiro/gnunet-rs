//! Bounded normal GNS business-card HTTP consumer and real renderer ownership.
#![cfg(unix)]
#![forbid(unsafe_code)]
mod http;
/// Fixed-template renderer with original child wait and cleanup ownership.
pub mod provider;
mod request;
pub use http::{ConnectionCause, Event, Limits, Report, Server};
pub use request::{FIELD_NAMES, form};
