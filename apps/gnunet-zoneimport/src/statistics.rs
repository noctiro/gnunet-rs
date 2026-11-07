//! Thin domain snapshot policy; the shared producer owns all MQ/Unknown state.
use gnunet_ipc_unix::producer::{self, Metric, Snapshot};
use gnunet_zoneimport_host::metrics::{COUNT, GAUGES, Metrics, NAMES};
pub(super) type Owner<'id> = producer::Producer<'id, COUNT>;
pub(super) type Report = producer::Report<COUNT>;
pub(super) static METRICS: [Metric; COUNT] = metrics();
const fn metrics() -> [Metric; COUNT] {
    let mut definitions = [Metric::counter(NAMES[0], false); COUNT];
    let mut i = 0;
    while i < COUNT {
        definitions[i] = if GAUGES[i] {
            Metric::gauge(NAMES[i], false)
        } else {
            Metric::counter(NAMES[i], false)
        };
        i += 1;
    }
    definitions
}
pub(super) fn snapshot(metrics: Metrics) -> Snapshot<COUNT> {
    Snapshot::new(metrics.values, metrics.overflowed)
}
