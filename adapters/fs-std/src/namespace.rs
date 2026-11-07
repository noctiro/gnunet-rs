//! Managed namespace keys, acknowledged publication and persistent update graphs.
//! Local bookkeeping adds no GNUnet messages and never replays weighted PUTs.
pub mod graph;
pub mod key;
mod publication;
pub use publication::{AcceptedPending, Failure, FailureCause, PublishedNamespace};
