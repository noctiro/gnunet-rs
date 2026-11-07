//! Explicit production DHT query ownership for DNS-exit discovery. The concrete
//! native port reuses the caller's actual shared Resolver and canonical clock.
use crate::Failure;
use gnunet_pt::core::Discovery;
use gnunet_service_runtime::{clock::RuntimeClock, framing::OwnedFrame};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;
/// Exact official DNS exit GET, bound to one original caller operation.
#[derive(Clone, Copy, Debug)]
pub struct Query<'a> {
    /// Original core operation, never a network RID.
    pub original: Discovery<'a>,
    /// SHA512("dns").
    pub key: [u8; 64],
    /// Official GNUNET_BLOCK_TYPE_DNS=10.
    pub block_type: u32,
    /// Official replication=1.
    pub replication: u32,
    /// Official DEMULTIPLEX_EVERYWHERE=1.
    pub options: u32,
    /// Original absolute deadline.
    pub expires: u64,
    /// Original independent native deadline.
    pub hard: Instant,
}
/// Actual original-provider observations. A local GET whole write is no result.
pub enum Event<'a> {
    /// Actual complete raw result from this exact query/source.
    Result {
        /// Original admitted query.
        original: Discovery<'a>,
        /// Actual associated key, unchanged.
        query: [u8; 64],
        /// Actual raw result type.
        block_type: u32,
        /// Complete public advertisement block, not a decrypted zone.
        block: OwnedFrame,
    },
    /// Actual independent source failure. Safe readonly recovery keeps this
    /// same original operation and its unchanged deadlines.
    SourceFailure {
        /// Original admitted operation; no replacement query authority.
        original: Discovery<'a>,
        /// Original owned source/connect/protocol cause.
        error: Failure,
    },
    /// Original operation physically retired/lost.
    Ended {
        /// Exact original operation.
        original: Discovery<'a>,
        /// Real failure, if any; None is not a no-match proof.
        error: Option<Failure>,
    },
}
mod native;
pub use native::Native;

/// Caller must supply an actual bounded DHT owner. Implementations retain all
/// original MQ/operation/source/deadline bytes, never replay a completed query
/// under a stale token, and physically cancel/close before stop returns. They
/// must perform no host-DNS/static-peer/GNS substitute. [`Native`] supplies the
/// ordinary production binding without creating a task or a Resolver.
pub trait Port<'a> {
    /// Exact same process clock as DNS/VPN/CADET sources.
    fn clock(&self) -> Arc<dyn RuntimeClock>;
    /// Admit the actual GET with empty xquery. Returning Ok is admission only.
    fn start(&mut self, query: Query<'a>) -> Result<(), Failure>;
    /// Poll one real original result/loss without creating a task/Resolver.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<'a>, Failure>>;
    /// Physically retire the exact original provider operation; no fake receipt.
    fn stop(&mut self, original: Discovery<'a>) -> Result<(), Failure>;
}
