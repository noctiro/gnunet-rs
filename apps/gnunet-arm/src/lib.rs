//! Official ARM CLI, with explicit host/installation boundaries.
#![deny(unsafe_code)]
/// Actual selected PROGRAM logging and original shared clock ownership.
pub mod diagnostics;
/// Explicit shared PROGRAM translation and comparison capabilities.
pub mod locale;
pub mod options;
pub mod runtime;
pub mod state;
