//! Explicit optional GNU libextractor provider. This crate neither publishes
//! content nor starts a task: the caller owns the worker, source and deadlines.
#![cfg(unix)]
#![deny(unsafe_code)]
#[expect(
    unsafe_code,
    reason = "The standard POSIX loader/libextractor callback ABI is isolated to this module"
)]
mod native;
mod source;
mod types;
pub use native::Provider;
pub use source::{FileExtraction, SourceStamp};
pub use types::{
    Cause, Cleanup, Extraction, Failure, Format, Item, Limits, NativeError, Observation,
    PanicPayload, Selection,
};
