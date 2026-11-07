//! One shared configured URI selection and original-child dispatcher; no shell.
#![cfg(unix)]
#![forbid(unsafe_code)]
mod control;
mod dispatcher;
mod settings;
pub use dispatcher::{Bounds, Cause, CloseReport, DispatchFailure, Dispatcher, Report, Stop};
pub use settings::Settings;

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Pure source cases assert the installed producer's distinct argument selection; no child or provider is invoked"
)]
mod selection_tests;
