//! Actual installed testing-only UNIX communicator. Claimed sender identities
//! in datagrams are not authenticated. All native owners remain caller driven.
#![cfg(unix)]
#![deny(unsafe_code)]
#[cfg(feature = "embedded-config")]
mod configured;
/// Caller-owned embedded foreground.
pub mod embedded;
pub mod native;
mod runtime;
pub use runtime::*;
