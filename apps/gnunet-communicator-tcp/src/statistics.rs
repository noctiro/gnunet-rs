//! Concrete native STATISTICS publisher injected by the standard executable.
//! All source/epoch/Unknown/write/retirement logic stays in the shared Producer.
use gnunet_ipc_unix::{
    handle,
    producer::{self, Metric, Producer, Snapshot},
};
use gnunet_tcp_communicator_runtime::statistics::{
    LiveConfiguration, METRIC_NAMES, Metrics, RuntimeClock, SharedResolution, Statistics,
    StatisticsFactory,
};
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
static METRICS: [Metric; 6] = [
    Metric::gauge(METRIC_NAMES[0], false),
    Metric::counter(METRIC_NAMES[1], false),
    Metric::counter(METRIC_NAMES[2], false),
    Metric::counter(METRIC_NAMES[3], false),
    Metric::counter(METRIC_NAMES[4], false),
    Metric::counter(METRIC_NAMES[5], false),
];
fn snapshot(metrics: Metrics) -> Snapshot<6> {
    Snapshot::new(*metrics.values(), metrics.overflowed())
}
pub(super) struct Factory<'id> {
    instance: &'id mut handle::Instance,
}
impl<'id> Factory<'id> {
    pub(super) fn new(instance: &'id mut handle::Instance) -> Self {
        Self { instance }
    }
}
pub(super) struct Native<'id>(Producer<'id, 6>);
impl<'id> StatisticsFactory for Factory<'id> {
    type Error = producer::Failure;
    type Report = producer::Report<6>;
    type Driver = Native<'id>;
    fn create(
        self,
        live: LiveConfiguration,
        resolution: SharedResolution,
        clock: Arc<dyn RuntimeClock>,
        initial: Metrics,
    ) -> Result<Option<Self::Driver>, Self::Error> {
        Producer::new(
            self.instance,
            live,
            resolution,
            clock,
            producer::Configuration {
                subsystem: b"communicator-tcp",
                metrics: &METRICS,
                initial: snapshot(initial),
                limits: producer::Limits::default(),
            },
        )
        .map(|owner| Some(Native(owner)))
    }
}
impl Statistics for Native<'_> {
    type Error = producer::Failure;
    type Report = producer::Report<6>;
    fn refresh(&mut self, metrics: Metrics) -> Result<bool, Self::Error> {
        self.0.refresh(snapshot(metrics))
    }
    #[expect(
        clippy::result_large_err,
        reason = "Map the original native result without allocating another error wrapper"
    )]
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll_native_guard(cx).map(|step| step.map(|_| ()))
    }
    #[expect(
        clippy::result_large_err,
        reason = "Map the original native result without allocating another error wrapper"
    )]
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll(cx, None).map(|step| step.map(|_| ()))
    }
    fn begin_close(&mut self, metrics: Metrics, grace: Duration) -> Result<(), Self::Error> {
        self.0.begin_close(snapshot(metrics), grace)
    }
    fn abort(&mut self) -> Result<(), Self::Error> {
        self.0.abort()
    }
    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }
    fn report(&self) -> Self::Report {
        self.0.report()
    }
}
