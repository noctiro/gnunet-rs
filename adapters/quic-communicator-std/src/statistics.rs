//! Source-independent app publisher port. No statistics/IPC dependency in runtime.
pub use crate::{
    metrics::{HTTP3_NAME, Metrics, RAW_NAME},
    tls::Profile,
};
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
/// Actual same-source constructor inputs, not proof of publication or peer identity.
pub struct Configuration {
    /// Actual application profile of the original runtime.
    pub profile: Profile,
    /// The original process's live configuration.
    pub live: LiveConfiguration,
    /// Same original Resolver used by the communicator and PROGRAM.
    pub resolution: SharedResolution,
    /// Exact shared original clock Arc.
    pub clock: Arc<dyn RuntimeClock>,
    /// Actual original runtime inventory at publisher construction.
    pub initial: Metrics,
}
/// One caller-driven original diagnostic source. Error permanently fences that
/// source. Abort physically retires its native resources even if it returns an
/// independent error; no detached work may outlive the driver.
pub trait Statistics {
    /// Real source/IO/retirement failure with independent original facts.
    type Error: Error + 'static;
    /// Actual owned original source report, never an inferred ACK.
    type Report: Debug + 'static;
    /// Observe real current inventory; no native write is implied.
    fn refresh(&mut self, metrics: Metrics) -> Result<bool, Self::Error>;
    /// Original native hard first, without clock sample or IO.
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    /// One bounded original native step; unit does not mean remote success.
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;
    /// Freeze a final actual snapshot and independent finite drain hard once.
    fn begin_close(&mut self, metrics: Metrics, grace: Duration) -> Result<(), Self::Error>;
    /// Clock-free physical source retirement, retaining real uncertainty/errors.
    fn abort(&mut self) -> Result<(), Self::Error>;
    /// Whether the original source is physically retired/explicitly disabled.
    fn is_closed(&self) -> bool;
    /// Original known-write/unknown/Destroy metadata; no processing proof.
    fn report(&self) -> Self::Report;
}
/// Factory type selected by the real app. Its storage is created inside the
/// original post-USERNAME task, so borrowed drivers never escape into a second
/// owner or borrow a caller stack across PROGRAM's retained static task.
pub trait StatisticsFactory: 'static {
    /// Caller-owned native instance/storage, not a prestarted source.
    type Storage: 'static;
    /// Actual constructor/driver error.
    type Error: Error + 'static;
    /// Actual source report returned independently of communicator outcome.
    type Report: Debug + 'static;
    /// The one original driver borrowing that caller-owned stable storage.
    type Driver<'a>: Statistics<Error = Self::Error, Report = Self::Report>
    where
        Self: 'a;
    /// Reserve only local storage; no socket/worker/entropy effect is permitted.
    fn storage() -> Self::Storage;
    /// Construct once on actual shared sources. None is explicit absence, not ACK.
    fn create<'a>(
        storage: &'a mut Self::Storage,
        config: Configuration,
    ) -> Result<Option<Self::Driver<'a>>, Self::Error>;
}
/// Explicit embedding choice with no observation publisher.
pub struct NoStatistics;
/// Absent sources cannot manufacture activity or a publication completion.
pub enum Absent {}
impl StatisticsFactory for NoStatistics {
    type Storage = ();
    type Error = Infallible;
    type Report = ();
    type Driver<'a> = Absent;
    fn storage() {}
    fn create(_: &mut (), _: Configuration) -> Result<Option<Absent>, Infallible> {
        Ok(None)
    }
}
impl Statistics for Absent {
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
