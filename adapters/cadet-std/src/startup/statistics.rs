//! Caller-supplied publication of observations from the original CADET owner.
use super::reports::Reports;
use crate::startup::foreground::{Failures, Stage};
pub use gnunet_cadet::statistics::{COUNT, GAUGES, NAMES, Snapshot};
pub use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
pub use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    error::Error,
    fmt,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
/// Sources of one diagnostic publisher, supplied when the Resolver has been constructed.
pub struct PublisherContext {
    /// Live configuration used by the original service and Resolver.
    pub live: LiveConfiguration,
    /// Resolution context paired with the service's original broker.
    pub resolution: SharedResolution,
    /// The service's original clock allocation.
    pub clock: Arc<dyn RuntimeClock>,
    /// Native deadline budget for each diagnostic publication operation.
    pub operation: Duration,
    /// Initial snapshot from this invocation.
    pub initial: Snapshot,
}

/// A single caller-driven diagnostic publisher for this invocation.
///
/// The publisher retains its original I/O and timers across canceled waits.
/// Any failure causes CADET to retire the publisher before further I/O.
pub trait Publisher {
    /// Supply the latest actual CADET observations.
    fn refresh(&mut self, snapshot: Snapshot) -> Result<(), Box<dyn Error>>;
    /// Check the original native deadline before any clock or I/O wait.
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Box<dyn Error>>>;
    /// Advance one bounded original I/O step.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Box<dyn Error>>>;
    /// Freeze the final snapshot and set one finite drain deadline.
    fn begin_close(&mut self, snapshot: Snapshot, grace: Duration) -> Result<(), Box<dyn Error>>;
    /// Retire the publisher without waiting on the service clock, even on error.
    /// Repeated calls leave it retired.
    fn abort(&mut self) -> Result<(), Box<dyn Error>>;
    /// Whether the publisher has no remaining native resources.
    fn is_closed(&self) -> bool;
    /// Return owned local observations of publication and retirement.
    fn report(&self) -> Box<dyn fmt::Debug>;
}

pub(super) type Factory<'id> =
    Box<dyn FnOnce(PublisherContext) -> Result<Box<dyn Publisher + 'id>, Box<dyn Error>> + 'id>;

#[derive(Debug)]
struct Errors {
    first: Option<Box<dyn Error>>,
    cleanup: Option<Box<dyn Error>>,
    report: Option<Box<dyn fmt::Debug>>,
    actual: Snapshot,
}
impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CADET STATISTICS failure={:?}, cleanup={:?}, local report={:?}, final snapshot={:?}",
            self.first, self.cleanup, self.report, self.actual
        )
    }
}
impl Error for Errors {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.first.as_deref().or(self.cleanup.as_deref())
    }
}
pub(super) struct Owner<'id> {
    publisher: Option<Box<dyn Publisher + 'id>>,
    last: Snapshot,
    first: Option<Box<dyn Error>>,
    cleanup: Option<Box<dyn Error>>,
    reporter: Reports,
}
impl<'id> Owner<'id> {
    pub(super) fn disabled(reporter: Reports) -> Self {
        Self {
            publisher: None,
            last: Snapshot::new(),
            first: None,
            cleanup: None,
            reporter,
        }
    }

    pub(super) fn new(
        publisher: Factory<'id>,
        context: PublisherContext,
        reporter: Reports,
    ) -> Self {
        let mut owner = Self::disabled(reporter);
        owner.last = context.initial;
        match publisher(context) {
            Ok(publisher) => owner.publisher = Some(publisher),
            Err(error) => owner.failure(error),
        }
        owner
    }
    fn failure(&mut self, error: Box<dyn Error>) {
        if self.first.is_none() {
            self.reporter.warning(
                "cadet.statistics.failed",
                format_args!("CADET diagnostic publisher fenced: {error}"),
            );
            self.first = Some(error);
        }
        self.abort();
    }
    pub(super) fn observe(&mut self, sample: impl FnOnce() -> Snapshot) {
        if self.reporter.configured() || self.publisher.is_some() {
            self.last = sample();
        }
    }
    pub(super) fn observe_clients(&mut self, clients: usize) {
        self.last = self.last.with_native_clients(clients);
    }
    pub(super) fn native_guard(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(owner) = self.publisher.as_mut().filter(|p| !p.is_closed()) else {
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
        let Some(owner) = self.publisher.as_mut().filter(|p| !p.is_closed()) else {
            return Poll::Pending;
        };
        if let Err(error) = owner.refresh(self.last) {
            self.failure(error);
            return Poll::Ready(());
        }
        match owner.poll(cx) {
            Poll::Ready(Err(error)) => {
                self.failure(error);
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
        if let Some(owner) = &mut self.publisher
            && let Err(error) = owner.begin_close(self.last, grace)
        {
            self.failure(error)
        }
    }
    pub(super) fn abort(&mut self) {
        if let Some(owner) = &mut self.publisher
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
        self.publisher.as_ref().is_none_or(|p| p.is_closed())
    }
    pub(super) fn finish(&mut self, failures: &mut Failures) {
        let report = self.publisher.as_ref().map(|p| p.report());
        self.reporter.debug(
            "cadet.statistics.report",
            format_args!(
                "CADET final snapshot={:?}, local publication report={report:?}",
                self.last
            ),
        );
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
