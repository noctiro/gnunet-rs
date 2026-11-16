//! TOPOLOGY metric policy over the shared original-source STATISTICS producer.
use crate::{
    Failure,
    reporting::{Cleanup, Reports},
};
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::{
    handle,
    producer::{self, Metric, Producer, Snapshot},
};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_topology_host::Statistics;
use std::{
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;
pub(super) const FINAL_GRACE: Duration = Duration::from_secs(5);
static METRICS: [Metric; 4] = [
    Metric::gauge(b"# peers connected", false),
    Metric::counter(b"# connect requests issued to ATS", false),
    Metric::counter(b"# HELLO messages received", false),
    Metric::counter(b"# HELLO messages gossipped", false),
];
fn snapshot(observed: Statistics) -> Snapshot<4> {
    Snapshot::new(
        [
            observed.peers_connected,
            observed.connect_requests,
            observed.hellos_received,
            observed.hellos_gossipped,
        ],
        false,
    )
}
#[derive(Debug)]
struct Failed {
    original: Option<producer::Failure>,
    report: producer::Report<4>,
}
impl std::fmt::Display for Failed {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "TOPOLOGY statistics original={:?}; retirement={:?}",
            self.original, self.report
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_ref().map(|error| error as _)
    }
}
pub(super) struct Forwarder<'id> {
    producer: Producer<'id, 4>,
    original: Option<producer::Failure>,
    reports: Reports,
    retired: bool,
}
impl<'id> Forwarder<'id> {
    pub fn new(
        instance: &'id mut handle::Instance,
        live: LiveConfiguration,
        resolution: SharedResolution,
        clock: Arc<dyn RuntimeClock>,
        initial: Statistics,
        reports: Reports,
    ) -> Result<Self, Failure> {
        let producer = Producer::new(
            instance,
            live,
            resolution,
            clock,
            producer::Configuration {
                subsystem: b"topology",
                metrics: &METRICS,
                initial: snapshot(initial),
                limits: producer::Limits::default(),
            },
        )?;
        Ok(Self {
            producer,
            original: None,
            reports,
            retired: false,
        })
    }
    fn fail(&mut self, error: producer::Failure) {
        if self.original.is_none() {
            self.reports.warning(
                "topology.statistics.failed",
                format_args!("Statistics source stopped: {error}"),
            );
            self.original = Some(error);
        }
    }
    pub fn refresh(&mut self, observed: Statistics) {
        if !self.producer.is_closed()
            && let Err(error) = self.producer.refresh(snapshot(observed))
        {
            self.fail(error);
        }
    }
    pub fn is_closed(&self) -> bool {
        self.producer.is_closed()
    }
    pub fn begin_close(&mut self, observed: Statistics) {
        if !self.producer.is_closed()
            && let Err(error) = self.producer.begin_close(snapshot(observed), FINAL_GRACE)
        {
            self.fail(error);
        }
    }
    pub fn guard(&mut self, cx: &mut Context<'_>) -> bool {
        match self.producer.poll_native_guard(cx) {
            Poll::Ready(Err(error)) => {
                self.fail(error);
                true
            }
            Poll::Ready(Ok(_)) => true,
            Poll::Pending => false,
        }
    }
    pub fn poll(&mut self, cx: &mut Context<'_>, wait: Option<Instant>) -> Poll<()> {
        if self.producer.is_closed() {
            return Poll::Pending;
        }
        match self.producer.poll(cx, wait) {
            Poll::Ready(Err(error)) => {
                self.fail(error);
                Poll::Ready(())
            }
            Poll::Ready(Ok(_)) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
    pub fn close(&mut self) -> Option<Failure> {
        if self.retired {
            return None;
        }
        self.retired = true;
        if let Err(error) = self.producer.abort() {
            self.fail(error);
        }
        let report = self.producer.report();
        self.reports.debug(
            "topology.statistics.final",
            format_args!("Statistics original source: {report:?}"),
        );
        let original = self.original.take();
        if original.is_some() || report.unknown.is_some() || report.pending.is_some() {
            Some(Box::new(Failed { original, report }))
        } else {
            None
        }
    }
}
impl Drop for Forwarder<'_> {
    fn drop(&mut self) {
        if let Some(error) = self.close() {
            self.reports.cleanup(Cleanup::Statistics, error);
        }
    }
}
