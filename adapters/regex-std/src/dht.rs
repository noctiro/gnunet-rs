//! Explicit original DHT provider contract for the real REGEX coordinator.
//!
//! The native implementation reuses the actual DHT client. A provider owns the
//! original operations, copied payloads, partial native frames and cancellation
//! debt. Merely implementing an interface or returning a numeric id does not
//! establish protocol interoperability. No default success provider is supplied.
mod native;
use gnunet_regex::Hash;
use gnunet_regex_service::{JobId, Reply};
use gnunet_service_runtime::clock::RuntimeClock;
pub use native::{Limits as NativeLimits, Native, PutRetirement};
use std::{
    error::Error,
    sync::Arc,
    task::{Context, Poll},
};
/// An actual provider error retained without replacing its source chain.
pub type Failure = Box<dyn Error>;
/// Exact public fields of one original state or accepting-block publication.
pub struct Put<'a> {
    /// Original state proof key, shared by the state and accepting artifact.
    pub key: Hash,
    /// Official block type22 or23.
    pub kind: u32,
    /// Original demultiplex/record-route flags.
    pub options: u32,
    /// Actual requested replication; not achieved remote copies.
    pub replication: u32,
    /// DHT record expiry, distinct from signed accepting expiry.
    pub expires: u64,
    /// Exact immutable block, to be retained by the real provider before return.
    pub block: &'a [u8],
}
/// Exact public fields of one persistent original branch query.
pub struct Get<'a> {
    /// Original requested state key.
    pub key: Hash,
    /// Official state22 or accepting23 type.
    pub kind: u32,
    /// Actual demultiplex/record-route flags.
    pub options: u32,
    /// Actual requested replication count.
    pub replication: u32,
    /// State remaining suffix plus NUL, or empty accepting query.
    pub xquery: &'a [u8],
}
/// One retained original provider event. The provider keeps this exact event
/// until `consume` succeeds; cancellation of a wait does not discard it.
#[must_use = "original provider observations require explicit consumption"]
pub enum Event<'a> {
    /// Actual independent source failure; safe readonly GET recovery retains
    /// original job identities. This is never a query no-match or completion.
    SourceFailure {
        /// Original source/connect/guard cause, retained until consumption.
        error: &'a (dyn Error + 'static),
    },
    /// An actual original response exceeded the native/Core resource profile.
    /// The query remains owned until the normal coordinator policy retires it.
    Rejected {
        /// Original query receiving this real response.
        job: JobId,
        /// Actual checked validation/resource refusal, never a fabricated answer.
        error: gnunet_regex_service::Error,
    },
    /// Actual original local DHT PUT transfer/API terminal, after its operation
    /// is quiescent. No remote acknowledgement is invented.
    /// It establishes neither durable storage nor successful replication.
    PutComplete(JobId),
    /// Actual repeated reply of the same admitted original GET. The provider
    /// preserves exact expiry/body/key and predecessor arrays in original order.
    Reply {
        /// Original REGEX job mapped to that actual original provider operation.
        job: JobId,
        /// Exact borrowed original result; no response is reconstructed by ids.
        reply: Reply<'a>,
    },
    /// Actual original operation failure, after the operation is quiescent.
    Failed {
        /// Original job, never a newly minted replacement or retry id.
        job: JobId,
        /// Real cause, retained separately from later cleanup errors.
        error: &'a (dyn Error + 'static),
    },
}
/// Caller-owned real DHT source. Every method acts on this same source/epoch;
/// a replacement provider cannot adopt old jobs or manufacture their receipts.
pub trait Provider {
    /// Same actual process clock supplied to the REGEX host and PILS source.
    fn clock(&self) -> Arc<dyn RuntimeClock>;
    /// Admit and own this exact original PUT, including a retained body. A local
    /// admission is not PutComplete. On error, use `quiescent` before releasing
    /// any original operation or reporting a known refusal to the pure core.
    fn put(&mut self, job: JobId, request: Put<'_>) -> Result<(), Failure>;
    /// Admit and own this exact persistent GET and suffix. Ok is original
    /// provider admission only; it is never a match, DONE or remote write.
    fn get(&mut self, job: JobId, request: Get<'_>) -> Result<(), Failure>;
    /// Request retirement of only this original job. Returning Ok does not
    /// itself prove a copied/partial native frame has drained or physically closed.
    fn retire(&mut self, job: &JobId) -> Result<(), Failure>;
    /// Inspect actual original native/callback ownership, including copied
    /// buffers. Available after close. Unknown or foreign ids must fail.
    fn quiescent(&self, job: &JobId) -> Result<bool, Failure>;
    /// Release only terminal bookkeeping after actual operation quiescence.
    /// False retains a real unconsumed observation for poll_next/consume; no
    /// callback or terminal fact may be erased here. Errors retain bookkeeping.
    /// Providers without owned terminal metadata use the pure default check.
    fn release(&mut self, job: &JobId) -> Result<bool, Failure> {
        self.quiescent(job)
    }
    /// Arm/check original native guards without waiting for a new canonical
    /// clock sample. True reports an actual native step, never completion.
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure>;
    /// Poll one retained actual event; no detached task or implicit Resolver.
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<'_>, Failure>>;
    /// Consume only the actual event most recently yielded. Return the original
    /// owned failure for Failed/SourceFailure and None for every other event.
    /// Err retains this same exact event and all original terminal facts for a
    /// later consumption attempt. The coordinator records an already committed
    /// pure mutation independently and never replays it after a consume refusal.
    fn consume(&mut self) -> Result<Option<Failure>, Failure>;
    /// Physically close this original source's attempts/streams/cursors and
    /// pending callbacks. Errors retain any remaining debt in this same owner;
    /// only actual per-job `quiescent` facts allow core retirement afterward.
    fn close(&mut self) -> Result<(), Failure>;
    /// True only when this permanently closed original source has no retained
    /// native attempts, streams, copied cursors, events or callbacks.
    fn is_closed(&self) -> bool;
}
