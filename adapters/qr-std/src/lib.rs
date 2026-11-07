//! Explicit real standard PNG/ZBar providers, with bounded owned image/results.
#![cfg(unix)]
#![deny(unsafe_code)]
#[expect(
    unsafe_code,
    reason = "The single standard POSIX/libpng/libzbar provider ABI and original opaque handles are confined to this module"
)]
mod provider;
mod types;
pub use provider::{Camera, scan_png};
pub use types::{Cleanup, Error, Limits, ProviderFailure, Symbol};
