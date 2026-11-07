//! Exact DNS counters delegated to the shared original-source producer.
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::{
    handle,
    producer::{self, Configuration, Metric, Producer, Snapshot},
};
use gnunet_service_runtime::clock::RuntimeClock;
pub(super) use producer::{Failure, Limits};
use std::sync::Arc;
pub(super) type Publisher<'id> = Producer<'id, 6>;
static METRICS: [Metric; 6] = [
    Metric::counter(b"# DNS requests answered via TUN interface", false),
    Metric::counter(b"# DNS exit failed (failed to open socket)", false),
    Metric::counter(
        b"# External DNS response discarded (no matching request)",
        false,
    ),
    Metric::counter(b"# Client response discarded (no matching request)", false),
    Metric::counter(b"# Non-DNS UDP packet received via TUN interface", false),
    Metric::counter(b"# DNS requests received via TUN interface", false),
];
pub(super) fn snapshot(values: [u64; 6]) -> Snapshot<6> {
    Snapshot::new(values, false)
}
#[expect(
    clippy::result_large_err,
    reason = "Keep original shared producer failure and independent native cleanup without allocating a per-call error"
)]
pub(super) fn new<'id>(
    instance: &'id mut handle::Instance,
    live: LiveConfiguration,
    resolution: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
) -> Result<Publisher<'id>, Failure> {
    Producer::new(
        instance,
        live,
        resolution,
        clock,
        Configuration {
            subsystem: b"dns",
            metrics: &METRICS,
            initial: snapshot([0; 6]),
            limits,
        },
    )
}
