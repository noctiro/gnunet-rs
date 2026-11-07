//! Source-independent observation ports. No statistics wire/native crate is a
//! dependency of the NSE host. The actual executable injects its own driver.
use crate::Metrics;
pub use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
pub use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    convert::Infallible,
    error::Error,
    fmt::Debug,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

/// One explicitly supplied observation publisher. NSE retains no connection,
/// epoch, setter or protocol model behind this port; its concrete driver does.
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
/// shared Resolver/clock and initial NSE owner exist. The standard executable
/// injects its real native factory; embeddings without statistics choose the
/// explicit NoStatistics option, not an implicit successful fake provider.
pub trait StatisticsFactory {
    /// Real constructor and driver error.
    type Error: Error + 'static;
    /// Real owned driver report.
    type Report: Debug + 'static;
    /// Original concrete publisher owner; no separate NSE-side queue exists.
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
