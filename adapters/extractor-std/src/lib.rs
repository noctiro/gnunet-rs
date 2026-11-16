//! Explicit optional GNU libextractor provider. This crate neither publishes
//! content nor starts a task: the caller owns the worker, source and deadlines.
#![cfg(any(unix, windows))]
#![deny(unsafe_code)]
mod authorization;
mod configuration;
#[expect(
    unsafe_code,
    reason = "The public GNU libextractor ABI and trusted native dependency calls are isolated to this module"
)]
mod native;
pub use authorization::Authorization;
pub use configuration::Configuration;
mod source;
mod types;
pub use native::Provider;
pub use source::{FileExtraction, SourceStamp};
pub use types::{
    Cause, Cleanup, Extraction, Failure, Format, Item, Limits, NativeError, Observation,
    PanicPayload, Selection,
};
