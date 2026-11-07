//! Caller-owned public DHT PUT boundary and its real bounded native binding.
//! No private local-cache material is accepted.
use crate::{
    Failure,
    core::{material::PublicPublication, schedule::Job},
};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;
/// One exact original public PUT. No local-only block type can be supplied.
pub struct Put {
    /// Actual prepared public-filtered block with original query/expiry.
    pub public: PublicPublication,
    /// Original worker/source/revision job.
    pub job: Job,
    /// Official GNS NAMERECORD block type, pinned value.
    pub block_type: u32,
    /// Official replication level5.
    pub replication: u32,
    /// Official DEMULTIPLEX_EVERYWHERE1.
    pub options: u32,
    /// Original finite local operation target, not block expiry.
    pub expires: u64,
    /// Original independent native hard deadline.
    pub hard: Instant,
}
/// Actual original DHT producer boundary; none claims remote storage or fsync.
#[derive(Debug)]
pub enum Event {
    /// Actual original API continuation/local submission boundary.
    Submitted {
        /// Same original job, never reissued under a fresh token.
        job: Job,
    },
    /// Original logical interest failed or retired. Its error can retain an
    /// actual canceled-write fact without claiming logical publication success.
    Lost {
        /// Exact original job.
        job: Job,
        /// Real original error, if known; not a fake wire result.
        error: Option<Failure>,
    },
}
/// Explicit actual public DHT boundary. Native binding uses the shared original
/// DHT client; embedding callers may provide another real owned producer.
pub trait Port {
    /// Same actual process clock as NAMESTORE/cache clients.
    fn clock(&self) -> Arc<dyn RuntimeClock>;
    /// Admit actual original public PUT; Ok is admission, never publication.
    fn put(&mut self, input: Put) -> Result<(), Failure>;
    /// Check/register only original native bounds before an enclosing canonical
    /// clock wait. No socket IO/decode/crypto/logical sample occurs here. Any
    /// returned loss/result is the actual original operation's already-settled
    /// fact; this hook has no fake default implementation.
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Result<Event, Failure>>;
    /// Poll original real continuation/loss with exact job/source ownership.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>>;
    /// Physically cancel/retire exact original native debt even on cleanup
    /// error; no remote erase, rollback or revocation is asserted.
    fn stop(&mut self, job: Job) -> Result<(), Failure>;
    /// Permanently close the actual whole producer, including idle MQ and
    /// pending native attempt ownership, before the enclosing CPU workers join.
    /// Original terminal facts remain retained; no remote withdrawal is claimed.
    fn close(&mut self) -> Result<(), Failure>;
    /// Take one already-retained original terminal event without clock samples
    /// or IO. After close, at most the configured parallel bound is retained.
    fn take_settled(&mut self) -> Option<Event>;
}

/// Exact inputs to an explicitly installed actual production DHT binding. The
/// same original Resolver/clock domain is selected by the enclosing PROGRAM.
pub struct Inputs {
    /// Actual configured DHT endpoint selector, not a new protocol.
    pub source: gnunet_client_host::EndpointSource,
    /// Same process canonical source.
    pub clock: Arc<dyn RuntimeClock>,
    /// Actual bounded original PUT parallelism.
    pub parallel: usize,
}
/// Explicit installation boundary. `DhtFactory` supplies the production binding.
/// A factory may borrow its original native instance brands for the whole run.
pub trait Factory {
    /// Construct a real bounded native producer; creation/queueing
    /// alone proves no remote availability or accepted publication.
    fn open<'a>(&'a mut self, input: Inputs) -> Result<Box<dyn Port + 'a>, Failure>;
}

mod native;
pub use native::{DhtFactory, NativeFailure, Reason};
