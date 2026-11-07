//! Source-independent observation ports. No statistics wire/native crate is a
//! dependency of the TCP host. The actual executable injects its own driver.
pub use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
pub use gnunet_service_runtime::clock::RuntimeClock;
pub use gnunet_tcp_communicator_core::metrics::{METRIC_NAMES, Metrics};
use std::{
    convert::Infallible,
    error::Error,
    fmt::Debug,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

/// One explicitly supplied observation publisher. TCP retains no connection,
/// epoch, setter or protocol model behind this port; its concrete driver does.
/// A returned failure must permanently fence that original source. Abort retires
/// its native resources on both success and error, retaining the real error and
/// unknown-byte report. No detached activity may outlive the supplied driver.
pub trait Statistics {
    /// Actual source/IO/retirement error with independent native facts retained.
    type Error: Error + 'static;
    /// Owned original source report, without a fabricated acknowledgement.
    type Report: Debug + 'static;
    /// Observe current business coordinates; this is not native admission.
    fn refresh(&mut self, metrics: Metrics) -> Result<bool, Self::Error>;
    /// Check/register original native hard bounds before canonical/provider wait.
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    /// One actual bounded IO/action turn, no new request or deadline on retry.
    /// Unit means only one concrete driver step; no remote success is implied.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    /// Freeze final actual coordinates and the original finite drain hard.
    fn begin_close(&mut self, metrics: Metrics, grace: Duration) -> Result<(), Self::Error>;
    /// Physically retire the same original source without canonical-clock wait.
    fn abort(&mut self) -> Result<(), Self::Error>;
    /// Whether the concrete source is physically closed or explicitly disabled.
    fn is_closed(&self) -> bool;
    /// The concrete driver's actual source/cursor/retirement observations.
    fn report(&self) -> Self::Report;
}
/// Caller-owned construction policy and storage. Called once after the actual
/// shared Resolver/clock and initial TCP owner exist. The standard executable
/// injects its real native factory; embeddings without statistics choose the
/// explicit NoStatistics option, not an implicit successful fake provider.
pub trait StatisticsFactory {
    /// Real constructor and driver error.
    type Error: Error + 'static;
    /// Real owned driver report.
    type Report: Debug + 'static;
    /// Original concrete publisher owner; no separate TCP-side queue exists.
    type Driver: Statistics<Error = Self::Error, Report = Self::Report>;
    /// Use exactly these actual shared sources and initial business snapshot.
    /// None explicitly opts out; it is not proof of publication or DISABLE.
    fn create(
        self,
        live: LiveConfiguration,
        resolution: SharedResolution,
        clock: Arc<dyn RuntimeClock>,
        initial: Metrics,
    ) -> Result<Option<Self::Driver>, Self::Error>;
}
/// Explicit absence for an embedding which has no observation publisher.
#[derive(Clone, Copy, Debug)]
pub struct NoStatistics;
/// Uninhabited driver: an absent publisher cannot fake ready/progress/success.
#[derive(Clone, Copy, Debug)]
pub enum AbsentStatistics {}
impl StatisticsFactory for NoStatistics {
    type Error = Infallible;
    type Report = ();
    type Driver = AbsentStatistics;
    fn create(
        self,
        _: LiveConfiguration,
        _: SharedResolution,
        _: Arc<dyn RuntimeClock>,
        _: Metrics,
    ) -> Result<Option<Self::Driver>, Self::Error> {
        Ok(None)
    }
}
impl Statistics for AbsentStatistics {
    type Error = Infallible;
    type Report = ();
    fn refresh(&mut self, _: Metrics) -> Result<bool, Infallible> {
        match *self {}
    }
    fn poll_native_guard(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        match *self {}
    }
    fn poll(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        match *self {}
    }
    fn begin_close(&mut self, _: Metrics, _: Duration) -> Result<(), Infallible> {
        match *self {}
    }
    fn abort(&mut self) -> Result<(), Infallible> {
        match *self {}
    }
    fn is_closed(&self) -> bool {
        match *self {}
    }
    fn report(&self) {
        match *self {}
    }
}

/// Bounded independent source errors. A concrete publisher permanently fences on
/// its first error, so a later abort can add at most one distinct cleanup error.
pub(crate) struct Errors<E> {
    pub first: Option<E>,
    pub cleanup: Option<E>,
}
impl<E> Default for Errors<E> {
    fn default() -> Self {
        Self {
            first: None,
            cleanup: None,
        }
    }
}
impl<E> Errors<E> {
    pub(crate) fn record(&mut self, error: E) {
        if self.first.is_none() {
            self.first = Some(error);
        } else if self.cleanup.is_none() {
            self.cleanup = Some(error);
        }
    }
}
/// Clock-free retirement of the original supplied source, retaining an
/// independent actual abort failure instead of treating it as a delivery receipt.
pub(crate) fn abort<D: Statistics>(owner: &mut Option<D>, errors: &mut Errors<D::Error>) {
    if let Some(owner) = owner
        && !owner.is_closed()
        && let Err(error) = owner.abort()
    {
        errors.record(error);
    }
}
