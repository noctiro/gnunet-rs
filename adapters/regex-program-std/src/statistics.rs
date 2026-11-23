//! Official REGEX metric policy over the shared original-MQ STATISTICS producer.
//! This module owns no independent connection, timer, mutation queue or replay state.
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::{
    handle,
    producer::{self, Configuration, Metric, Producer, Snapshot},
};
use gnunet_regex_service::{METRIC_NAMES, Metrics};
use gnunet_service_runtime::clock::RuntimeClock;
/// Shared finite operation/frame policy, original failure and scheduling facts.
pub use producer::{Failure, Limits, Progress};
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
/// Diagnostic report for the official REGEX and profiler counters. It grants no
/// processing, remote delivery or durable-storage receipt.
pub type Report = producer::Report<10>;
static METRICS: [Metric; 10] = [
    Metric::counter(METRIC_NAMES[0], false),
    Metric::counter(METRIC_NAMES[1], false),
    Metric::counter(METRIC_NAMES[2], false),
    Metric::counter(METRIC_NAMES[3], false),
    Metric::counter(METRIC_NAMES[4], false),
    Metric::counter(METRIC_NAMES[5], false),
    Metric::counter(METRIC_NAMES[6], false),
    Metric::counter(METRIC_NAMES[7], false),
    Metric::counter(METRIC_NAMES[8], false),
    Metric::counter(b"# regexes announced", false),
];
fn snapshot(metrics: Metrics, rounds_started: u64) -> Snapshot<10> {
    let mut values = [0; 10];
    values[..9].copy_from_slice(metrics.values());
    values[9] = rounds_started;
    Snapshot::new(values, false)
}

pub(crate) enum Namespace {
    Service,
    Profiler,
}
impl Namespace {
    fn key(self) -> &'static [u8] {
        match self {
            Self::Service => b"regex",
            Self::Profiler => b"regexprofiler",
        }
    }
}
/// Domain metrics converted into the actual shared bounded producer. Original
/// source/epoch, hard deadlines, Unknown and destruction ownership stay there.
pub struct Owner<'id> {
    producer: Producer<'id, 10>,
    rounds_started: u64,
}
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
        Self::with_namespace(
            instance,
            live,
            resolution,
            clock,
            initial,
            limits,
            Namespace::Service,
        )
    }
    #[expect(
        clippy::result_large_err,
        reason = "Return original STATISTICS and independent cleanup failures"
    )]
    pub(crate) fn with_namespace(
        instance: &'id mut handle::Instance,
        live: LiveConfiguration,
        resolution: SharedResolution,
        clock: Arc<dyn RuntimeClock>,
        initial: Metrics,
        limits: Limits,
        namespace: Namespace,
    ) -> Result<Self, Failure> {
        Producer::new(
            instance,
            live,
            resolution,
            clock,
            Configuration {
                subsystem: namespace.key(),
                metrics: &METRICS,
                initial: snapshot(initial, 0),
                limits,
            },
        )
        .map(|producer| Self {
            producer,
            rounds_started: 0,
        })
    }
    pub(crate) fn announcement_started(&mut self) {
        self.rounds_started = self.rounds_started.saturating_add(1);
    }
    /// Current shared producer accounting, separate from remote acceptance.
    #[must_use]
    pub fn report(&self) -> Report {
        self.producer.report()
    }
    /// True only after physical source retirement or official statistics disable.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.producer.is_closed()
    }
    /// Supply actual REGEX observations; admission is not a local whole write.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original shared STATISTICS failure and independent cleanup without per-call boxing"
    )]
    pub fn refresh(&mut self, metrics: Metrics) -> Result<bool, Failure> {
        self.producer
            .refresh(snapshot(metrics, self.rounds_started))
    }
    /// Check/register the original native hard before any canonical-clock wait.
    /// This performs no source read/write or logical clock sample.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Failure>> {
        self.producer.poll_native_guard(cx)
    }
    /// Fairly poll the original shared producer and preserve its exact lifecycle.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
    ) -> Poll<Result<Progress, Failure>> {
        self.producer.poll(cx, wait)
    }
    /// Freeze final actual metrics with the original finite drain hard target.
    /// Repeated calls cannot renew the original grace or replace its snapshot.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original shared STATISTICS failure and independent cleanup without per-call boxing"
    )]
    pub fn begin_close(&mut self, metrics: Metrics, grace: Duration) -> Result<(), Failure> {
        self.producer
            .begin_close(snapshot(metrics, self.rounds_started), grace)
    }
    /// Physically retire the same publisher without a new logical clock sample.
    /// Original uncertain mutations are retained by the shared diagnostic report.
    #[expect(
        clippy::result_large_err,
        reason = "Return the original shared STATISTICS failure and independent cleanup without per-call boxing"
    )]
    pub fn abort(&mut self) -> Result<(), Failure> {
        self.producer.abort()
    }
}
