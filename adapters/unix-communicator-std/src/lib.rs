//! Actual installed testing-only UNIX communicator. Claimed sender identities
//! in datagrams are not authenticated. All native owners remain caller driven.
#![cfg(unix)]
#![forbid(unsafe_code)]
pub mod native;
mod runtime;
pub use runtime::*;
