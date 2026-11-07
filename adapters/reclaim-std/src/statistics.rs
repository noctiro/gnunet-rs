//! Official RECLAIM metric policy over the shared original-MQ STATISTICS producer.
//! This module owns no independent connection, timer, mutation queue or replay state.
use crate::server::{METRIC_NAMES, Metrics};
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::{
    handle,
    producer::{self, Configuration, Metric, Producer, Snapshot},
};
use gnunet_service_runtime::clock::RuntimeClock;
/// Shared finite operation/frame policy, original failure and scheduling facts.
pub use producer::{Failure, Limits, Progress};
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
/// Diagnostic report for the 4 official RECLAIM coordinates. It grants no
/// processing, remote delivery or durable-storage receipt.
pub type Report = producer::Report<4>;
static METRICS: [Metric; 4] = [
    Metric::counter(METRIC_NAMES[0], true),
    Metric::counter(METRIC_NAMES[1], true),
    Metric::counter(METRIC_NAMES[2], true),
    Metric::counter(METRIC_NAMES[3], true),
];
fn snapshot(metrics: Metrics) -> Snapshot<4> {
    Snapshot::new(*metrics.values(), metrics.overflowed())
}
/// Domain metrics converted into the actual shared bounded producer. Original
/// source/epoch, hard deadlines, Unknown and destruction ownership stay there.
pub struct Owner<'id>(Producer<'id, 4>);
impl<'id> Owner<'id> {
    /// Retain the same explicit live configuration, Resolver and actual clock Arc.
    /// Initial cumulative observations form this source's non-delivery baseline.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original shared STATISTICS failure and independent cleanup without per-call boxing"
    )]
    pub fn new(
        instance: &'id mut handle::Instance,
        live: LiveConfiguration,
        resolution: SharedResolution,
        clock: Arc<dyn RuntimeClock>,
        initial: Metrics,
        limits: Limits,
    ) -> Result<Self, Failure> {
        Producer::new(
            instance,
            live,
            resolution,
            clock,
            Configuration {
                subsystem: b"reclaim",
                metrics: &METRICS,
                initial: snapshot(initial),
                limits,
            },
        )
        .map(Self)
    }
    /// Current shared producer accounting, separate from remote acceptance.
    #[must_use]
    pub fn report(&self) -> Report {
        self.0.report()
    }
    /// True only after physical source retirement or official statistics disable.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
    /// Supply actual RECLAIM observations; admission is not a local whole write.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original shared STATISTICS failure and independent cleanup without per-call boxing"
    )]
    pub fn refresh(&mut self, metrics: Metrics) -> Result<bool, Failure> {
        self.0.refresh(snapshot(metrics))
    }
    /// Check/register the original native hard before any canonical-clock wait.
    /// This performs no source read/write or logical clock sample.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Failure>> {
        self.0.poll_native_guard(cx)
    }
    /// Fairly poll the original shared producer and preserve its exact lifecycle.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<Progress, Failure>> {
        self.0.poll(cx, wait)
    }
    /// Freeze final actual metrics with the original finite drain hard target.
    /// Repeated calls cannot renew the original grace or replace its snapshot.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original shared STATISTICS failure and independent cleanup without per-call boxing"
    )]
    pub fn begin_close(&mut self, metrics: Metrics, grace: Duration) -> Result<(), Failure> {
        self.0.begin_close(snapshot(metrics), grace)
    }
    /// Physically retire the same publisher without a new logical clock sample.
    /// Original uncertain mutations are retained by the shared diagnostic report.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original shared STATISTICS failure and independent cleanup without per-call boxing"
    )]
    pub fn abort(&mut self) -> Result<(), Failure> {
        self.0.abort()
    }
}
