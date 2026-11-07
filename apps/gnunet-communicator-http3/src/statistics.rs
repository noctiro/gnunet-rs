//! Real app-owned native gauge publisher; no statistics dependency in protocol/runtime.
use gnunet_ipc_unix::{
    handle,
    producer::{self, Metric, Producer, Snapshot},
};
use gnunet_quic_communicator_host::statistics::{
    Configuration, HTTP3_NAME, Metrics, Profile, RAW_NAME, Statistics, StatisticsFactory,
};
use std::{
    task::{Context, Poll},
    time::Duration,
};
static RAW: [Metric; 1] = [Metric::gauge(RAW_NAME, false)];
static HTTP3: [Metric; 1] = [Metric::gauge(HTTP3_NAME, false)];
fn snapshot(metrics: Metrics) -> Snapshot<1> {
    Snapshot::new([metrics.active()], metrics.overflowed())
}
pub(super) struct Factory;
pub(super) struct Native<'a>(Producer<'a, 1>);
impl StatisticsFactory for Factory {
    type Storage = handle::Instance;
    type Error = producer::Failure;
    type Report = producer::Report<1>;
    type Driver<'a> = Native<'a>;
    fn storage() -> Self::Storage {
        handle::Instance::new()
    }
    fn create<'a>(
        storage: &'a mut Self::Storage,
        config: Configuration,
    ) -> Result<Option<Native<'a>>, Self::Error> {
        // These are Rust standard-communicator subsystem labels. Pinned C has
        // the public gauge keys but never initializes its global stats handle.
        let (subsystem, metrics): (&'static [u8], &'static [Metric; 1]) = match config.profile {
            Profile::Raw => (b"communicator-quic", &RAW),
            Profile::Http3 => (b"communicator-http3", &HTTP3),
        };
        Producer::new(
            storage,
            config.live,
            config.resolution,
            config.clock,
            producer::Configuration {
                subsystem,
                metrics,
                initial: snapshot(config.initial),
                limits: producer::Limits::default(),
            },
        )
        .map(|driver| Some(Native(driver)))
    }
}
impl Statistics for Native<'_> {
    type Error = producer::Failure;
    type Report = producer::Report<1>;
    fn refresh(&mut self, metrics: Metrics) -> Result<bool, Self::Error> {
        self.0.refresh(snapshot(metrics))
    }
    #[expect(
        clippy::result_large_err,
        reason = "Preserve actual native and independent cleanup errors without another allocation"
    )]
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0
            .poll_native_guard(cx)
            .map(|result| result.map(|_| ()))
    }
    #[expect(
        clippy::result_large_err,
        reason = "Preserve actual native and independent cleanup errors without another allocation"
    )]
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.0.poll(cx, None).map(|result| result.map(|_| ()))
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
