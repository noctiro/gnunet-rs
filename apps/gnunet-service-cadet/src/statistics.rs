//! One original shared STATISTICS producer; no duplicated native handle logic.
use crate::foreground::{Failures, Stage};
use gnunet_cadet::statistics::{self as observed, COUNT};
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_ipc_unix::{
    handle,
    producer::{self, Metric, Producer},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    error::Error,
    fmt,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
const fn definitions() -> [Metric; COUNT] {
    let mut metrics = [Metric::counter(b"", false); COUNT];
    let mut i = 0;
    while i < COUNT {
        metrics[i] = if observed::GAUGES[i] {
            Metric::gauge(observed::NAMES[i], false)
        } else {
            Metric::counter(observed::NAMES[i], false)
        };
        i += 1;
    }
    metrics
}
static METRICS: [Metric; COUNT] = definitions();
fn snapshot(actual: &observed::Snapshot) -> producer::Snapshot<COUNT> {
    producer::Snapshot::new(*actual.values(), actual.overflowed())
}
#[derive(Debug)]
struct Errors {
    first: Option<producer::Failure>,
    cleanup: Option<producer::Failure>,
    report: Option<producer::Report<COUNT>>,
    actual: observed::Snapshot,
}
impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CADET original STATISTICS failure={:?}; independent cleanup={:?}; actual local report={:?}; final original owner snapshot={:?}",
            self.first, self.cleanup, self.report, self.actual
        )
    }
}
impl Error for Errors {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.first
            .as_ref()
            .or(self.cleanup.as_ref())
            .map(|e| e as &(dyn Error + 'static))
    }
}
pub(super) struct Owner<'id> {
    producer: Option<Producer<'id, COUNT>>,
    last: observed::Snapshot,
    first: Option<producer::Failure>,
    cleanup: Option<producer::Failure>,
    reporter: Reporter,
}
impl<'id> Owner<'id> {
    pub(super) fn new(
        instance: &'id mut handle::Instance,
        live: LiveConfiguration,
        resolution: SharedResolution,
        clock: Arc<dyn RuntimeClock>,
        limits: producer::Limits,
        reporter: Reporter,
    ) -> Self {
        let last = observed::Snapshot::new();
        let mut owner = Self {
            producer: None,
            last,
            first: None,
            cleanup: None,
            reporter,
        };
        match Producer::new(
            instance,
            live,
            resolution,
            clock,
            producer::Configuration {
                subsystem: b"cadet",
                metrics: &METRICS,
                initial: snapshot(&last),
                limits,
            },
        ) {
            Ok(producer) => owner.producer = Some(producer),
            Err(error) => owner.failure(error),
        }
        owner
    }
    fn failure(&mut self, error: producer::Failure) {
        if self.first.is_none() {
            self.reporter.warning(
                "cadet.statistics.failed",
                format_args!("CADET diagnostic publisher fenced: {error}"),
            );
            self.first = Some(error);
        }
        self.abort();
    }
    pub(super) fn observe(&mut self, actual: &observed::Snapshot) {
        self.last = *actual;
    }
    pub(super) fn observe_clients(&mut self, clients: usize) {
        self.last = self.last.with_native_clients(clients);
    }
    pub(super) fn native_guard(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(owner) = self.producer.as_mut().filter(|p| !p.is_closed()) else {
            return Poll::Pending;
        };
        match owner.poll_native_guard(cx) {
            Poll::Ready(Err(error)) => {
                self.failure(error);
                Poll::Ready(())
            }
            Poll::Ready(Ok(_)) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        // Original physical mutation deadline precedes any canonical wait.
        if self.native_guard(cx).is_ready() {
            return Poll::Ready(());
        }
        let Some(owner) = self.producer.as_mut().filter(|p| !p.is_closed()) else {
            return Poll::Pending;
        };
        if let Err(error) = owner.refresh(snapshot(&self.last)) {
            self.failure(error);
            return Poll::Ready(());
        }
        match owner.poll(cx, None) {
            Poll::Ready(Err(error)) => {
                self.failure(error);
                Poll::Ready(())
            }
            Poll::Ready(Ok(producer::Progress::Written { counter, value })) => {
                self.reporter.debug("cadet.statistics.written",format_args!("CADET original local statistics frame counter={counter} value={value:?}; remote processing unconfirmed"));
                Poll::Ready(())
            }
            Poll::Ready(Ok(_)) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
    pub(super) fn begin_close(&mut self, grace: Duration, force: bool) {
        if force {
            self.abort();
            return;
        }
        if let Some(owner) = &mut self.producer
            && let Err(error) = owner.begin_close(snapshot(&self.last), grace)
        {
            self.failure(error)
        }
    }
    pub(super) fn abort(&mut self) {
        if let Some(owner) = &mut self.producer
            && let Err(error) = owner.abort()
            && self.cleanup.is_none()
        {
            self.reporter.warning(
                "cadet.statistics.cleanup.failed",
                format_args!("CADET independent original publisher cleanup: {error}"),
            );
            self.cleanup = Some(error);
        }
    }
    pub(super) fn is_closed(&self) -> bool {
        self.producer.as_ref().is_none_or(|p| p.is_closed())
    }
    pub(super) fn finish(&mut self, failures: &mut Failures) {
        let report = self.producer.as_ref().map(|p| p.report());
        self.reporter.debug("cadet.statistics.report",format_args!("CADET final original owner snapshot={:?}; actual statistics local report={report:?}; remote processing/persistence unclaimed",self.last));
        if self.first.is_some() || self.cleanup.is_some() {
            failures.record(
                Stage::Statistics,
                Box::new(Errors {
                    first: self.first.take(),
                    cleanup: self.cleanup.take(),
                    report,
                    actual: self.last,
                }),
            );
        }
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        self.abort();
    }
}
