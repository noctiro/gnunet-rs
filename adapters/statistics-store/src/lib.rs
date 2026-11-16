//! Bounded GNUnet STATISTICS persistence using its official SET stream format.
//!
//! The host owns explicit database paths and limits. This adapter loads fresh
//! service state and saves snapshots using real filesystem operations; an IPC
//! processing-barrier confirmation is never treated as a durable commit.
#![forbid(unsafe_code)]

mod commit;
mod error;
mod store;

pub use commit::{CommitBackend, DirectorySync, NativeCommit};
pub use error::{Cause, CommitOutcome, Stage, StoreError};
pub use store::{Limits, LoadReport, LoadSource, SaveOutcome, SaveReport, Store};
