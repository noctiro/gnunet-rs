//! Actual C-UNIX metrics published by the existing shared original-source owner.
//! Loss/Unknown, whole-write coordinates and bounded final drain stay in Producer.
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::{
    handle,
    producer::{self, Metric, Producer, Snapshot},
};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_unix_communicator_host::Statistics;
use std::{sync::Arc, time::Duration};

pub(super) type Forwarder<'id> = Producer<'id, 7>;
pub(super) type Report = producer::Report<7>;
pub(super) const FINAL_GRACE: Duration = Duration::from_secs(5);
static METRICS: [Metric; 7] = [
    Metric::gauge(b"# queues active", false),
    Metric::counter(b"# bytes sent", false),
    Metric::counter(b"# network transmission failures", false),
    Metric::counter(b"# transport transmission failures", false),
    // Existing Rust diagnostics: not additional official C metric requirements.
    Metric::counter(b"# invalid datagrams received", false),
    Metric::counter(b"# incoming IPC frames written", false),
    Metric::counter(b"# actual incoming callbacks", false),
];
/// Preserve the original Runtime's saturating u64 coordinates. These source
/// counters are lower bounds after saturation, not remote-delivery receipts.
pub(super) fn snapshot(observed: Statistics) -> Snapshot<7> {
    Snapshot::new(
        [
            observed.queues,
            observed.bytes_sent,
            observed.network_failures,
            observed.transport_failures,
            observed.invalid_inputs,
            observed.incoming_written,
            observed.incoming_callbacks,
        ],
        false,
    )
}
#[expect(
    clippy::result_large_err,
    reason = "Retain original shared producer IO/cleanup metadata without allocating an error wrapper after native failure"
)]
pub(super) fn new<'id>(
    instance: &'id mut handle::Instance,
    live: LiveConfiguration,
    resolution: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    initial: Statistics,
) -> Result<Forwarder<'id>, producer::Failure> {
    Producer::new(
        instance,
        live,
        resolution,
        clock,
        producer::Configuration {
            subsystem: b"C-UNIX",
            metrics: &METRICS,
            initial: snapshot(initial),
            limits: producer::Limits::default(),
        },
    )
}
