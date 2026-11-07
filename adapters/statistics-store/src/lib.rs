//! Bounded GNUnet STATISTICS persistence using its official SET stream format.
//!
//! The host owns explicit database paths and limits. This adapter loads fresh
//! service state and saves snapshots using real filesystem operations; an IPC
//! processing-barrier confirmation is never treated as a durable commit.
#![forbid(unsafe_code)]

mod error;
mod store;

pub use error::{Cause, CommitOutcome, Stage, StoreError};
pub use store::{
    CommitBackend, Limits, LoadReport, LoadSource, NativeCommit, SaveOutcome, SaveReport, Store,
};
