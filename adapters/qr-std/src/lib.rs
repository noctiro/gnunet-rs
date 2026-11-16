//! Explicit real standard PNG/ZBar providers, with bounded owned image/results.
#![deny(unsafe_code)]
#[expect(
    unsafe_code,
    reason = "Native libpng/ZBar exports, caller-trusted loader calls and original opaque handles are confined to this module"
)]
mod provider;
mod types;
pub use provider::{Camera, scan_png};
pub use types::{Cleanup, Error, LibraryPaths, Limits, ProviderFailure, Symbol};
