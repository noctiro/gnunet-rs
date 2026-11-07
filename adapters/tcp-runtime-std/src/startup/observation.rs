//! App-injected statistics on the original Resolver/clock, independent of TCP success.
use super::Report as TcpReport;
use crate::statistics::{self, Metrics, Statistics, StatisticsFactory};
use gnunet_client_host::{LiveConfiguration, resolution::SharedResolution};
use gnunet_resolver_broker::{BrokerError, Driver, DriverEvent};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    error::Error,
    fmt::{self, Debug},
    future::{Future, poll_fn},
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
type Cause = super::Failure;
/// Actual independent business/source observations; neither is a remote ACK.
#[derive(Debug)]
pub struct Report<R> {
    /// The real original TCP lifecycle report.
    pub tcp: TcpReport,
    /// Last actual original Pool snapshot, captured before retirement/abort.
    pub metrics: Option<Metrics>,
    /// Original publisher report; None means no publisher was constructed.
    pub statistics: Option<R>,
}
impl<R> Default for Report<R> {
    fn default() -> Self {
        Self {
            tcp: TcpReport::default(),
            metrics: None,
            statistics: None,
        }
    }
}
/// All original errors plus both real reports, without masking one owner by another.
#[derive(Debug)]
pub struct Failure<E, R> {
    /// Original TCP/worker/frontier failure.
    pub original: Option<Cause>,
    /// Successful TCP result when an independent observation owner failed.
    pub completed: Option<TcpReport>,
    /// Last actual Pool snapshot, including an abort's still-live inventory.
    pub metrics: Option<Metrics>,
    /// First original constructor/IO/deadline failure of this one publisher.
    pub statistics: Option<E>,
    /// Independent original publisher retirement error.
    pub statistics_cleanup: Option<E>,
    /// Actual native write/unknown/Destroy report, never inferred from error text.
    pub statistics_report: Option<R>,
    /// Independent same-Resolver failure during observation retirement.
    pub resolver_drain: Option<BrokerError>,
    /// Actual original broker disconnect refusal.
    pub resolver_close: Option<BrokerError>,
}
impl<E: Debug, R: Debug> fmt::Display for Failure<E, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TCP/statistics original lifecycle: {self:?}")
    }
}
impl<E: Error + 'static, R: Debug + 'static> Error for Failure<E, R> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or(self.statistics.as_ref().map(|e| e as &dyn Error))
            .or(self.statistics_cleanup.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_drain.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_close.as_ref().map(|e| e as &dyn Error))
    }
}
pub(super) struct Owner<D: Statistics> {
    driver: Option<D>,
    errors: statistics::Errors<D::Error>,
    final_started: bool,
    resolver_drain: Option<BrokerError>,
}
pub(super) fn create<F: StatisticsFactory>(
    factory: F,
    live: LiveConfiguration,
    resolution: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    initial: Metrics,
) -> Owner<F::Driver> {
    let mut errors = statistics::Errors::default();
    let driver = match factory.create(live, resolution, clock, initial) {
        Ok(driver) => driver,
        Err(error) => {
            errors.record(error);
            None
        }
    };
    Owner {
        driver,
        errors,
        final_started: false,
        resolver_drain: None,
    }
}
impl<D: Statistics> Owner<D> {
    pub(super) fn abort(&mut self) {
        statistics::abort(&mut self.driver, &mut self.errors);
    }
    pub(super) fn closed(&self) -> bool {
        self.driver.as_ref().is_none_or(Statistics::is_closed)
    }
    /// Original native hard first; no fresh clock, setter, read or broker operation.
    pub(super) fn guard(&mut self, cx: &mut Context<'_>, failed: bool) -> bool {
        let mut changed = false;
        if let Some(driver) = &mut self.driver
            && !driver.is_closed()
            && let Poll::Ready(result) = driver.poll_native_guard(cx)
        {
            changed = true;
            if let Err(error) = result {
                self.errors.record(error);
                self.abort();
            }
        }
        if failed {
            self.abort();
        }
        changed
    }
    pub(super) fn refresh(&mut self, metrics: Metrics, failed: bool) {
        if failed {
            self.abort();
            return;
        }
        if !self.final_started
            && let Some(driver) = &mut self.driver
            && !driver.is_closed()
            && let Err(error) = driver.refresh(metrics)
        {
            self.errors.record(error);
            self.abort();
        }
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>, failed: bool) -> bool {
        let guarded = self.guard(cx, failed);
        if failed {
            return guarded;
        }
        let Some(driver) = &mut self.driver else {
            return guarded;
        };
        if driver.is_closed() {
            return guarded;
        }
        match driver.poll(cx) {
            Poll::Ready(Ok(())) => true,
            Poll::Ready(Err(error)) => {
                self.errors.record(error);
                self.abort();
                true
            }
            Poll::Pending => guarded,
        }
    }
    /// Freeze once, using only the last real original Pool snapshot. Never mint
    /// a gauge zero or restart an old relative mutation after Unknown.
    pub(super) fn begin_close(&mut self, metrics: Option<Metrics>, allow: bool) {
        if self.final_started {
            return;
        }
        self.final_started = true;
        if !allow {
            self.abort();
            return;
        }
        let Some(metrics) = metrics else {
            self.abort();
            return;
        };
        if let Some(driver) = &mut self.driver
            && !driver.is_closed()
            && let Err(error) = driver.begin_close(metrics, Duration::from_secs(5))
        {
            self.errors.record(error);
            self.abort();
        }
    }
    fn poll_retirement(
        &mut self,
        cx: &mut Context<'_>,
        resolver: &mut Driver<128, 256>,
        observe: &mut dyn FnMut(DriverEvent),
        failed: &dyn Fn() -> bool,
    ) -> bool {
        let mut changed = self.poll(cx, failed());
        if failed() {
            self.abort();
            return changed;
        }
        if self.closed() || self.resolver_drain.is_some() {
            return changed;
        }
        let result = {
            let mut resolving = std::pin::pin!(resolver.drive_waiting(None, observe));
            resolving.as_mut().poll(cx)
        };
        match result {
            Poll::Ready(Ok(_)) => changed = true,
            Poll::Ready(Err(error)) => {
                self.resolver_drain = Some(error);
                self.abort();
                changed = true;
            }
            Poll::Pending => {}
        }
        if failed() {
            self.abort();
        }
        changed
    }
    /// Keep the SAME original replay shutdown/worker-join future alive while
    /// registering native observation hard bounds and fairly servicing its broker.
    pub(super) async fn worker<F: Future<Output = Result<TcpReport, Cause>>>(
        &mut self,
        original: F,
        resolver: &mut Driver<128, 256>,
        observe: &mut dyn FnMut(DriverEvent),
        failed: &dyn Fn() -> bool,
    ) -> Result<TcpReport, Cause> {
        let mut original = std::pin::pin!(original);
        poll_fn(|cx| {
            self.guard(cx, failed());
            let result = original.as_mut().poll(cx);
            if failed() {
                self.abort();
            }
            if let Poll::Ready(result) = result {
                if result.is_err() {
                    self.abort();
                }
                return Poll::Ready(result);
            }
            if self.poll_retirement(cx, resolver, observe, failed) {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }
    pub(super) async fn drain(
        &mut self,
        resolver: &mut Driver<128, 256>,
        observe: &mut dyn FnMut(DriverEvent),
        failed: &dyn Fn() -> bool,
    ) {
        poll_fn(|cx| {
            self.guard(cx, failed());
            if self.closed() {
                return Poll::Ready(());
            }
            let changed = self.poll_retirement(cx, resolver, observe, failed);
            if self.closed() {
                return Poll::Ready(());
            }
            if changed {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }
    pub(super) fn finish(
        mut self,
        outcome: Result<TcpReport, Cause>,
        metrics: Option<Metrics>,
        resolver_close: Option<BrokerError>,
    ) -> Result<Report<D::Report>, Cause> {
        self.abort();
        let statistics_report = self.driver.as_ref().map(Statistics::report);
        drop(self.driver);
        let (completed, original) = match outcome {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(error)),
        };
        if original.is_none()
            && self.errors.first.is_none()
            && self.errors.cleanup.is_none()
            && self.resolver_drain.is_none()
            && resolver_close.is_none()
        {
            return completed
                .map(|tcp| Report {
                    tcp,
                    metrics,
                    statistics: statistics_report,
                })
                .ok_or_else(|| Box::new(gnunet_types::Error::Conflict) as Cause);
        }
        Err(Box::new(Failure {
            original,
            completed,
            metrics,
            statistics: self.errors.first,
            statistics_cleanup: self.errors.cleanup,
            statistics_report,
            resolver_drain: self.resolver_drain,
            resolver_close,
        }))
    }
}
/// No publisher was constructed (for example pre-Pool stop/refusal). This returns
/// only the real original business outcome and actual same-broker close result.
pub(super) fn absent<E: Error + 'static, R: Debug + 'static>(
    outcome: Result<TcpReport, Cause>,
    metrics: Option<Metrics>,
    resolver_close: Option<BrokerError>,
) -> Result<Report<R>, Cause> {
    let (completed, original) = match outcome {
        Ok(report) => (Some(report), None),
        Err(error) => (None, Some(error)),
    };
    if resolver_close.is_none() && original.is_none() {
        return completed
            .map(|tcp| Report {
                tcp,
                metrics,
                statistics: None,
            })
            .ok_or_else(|| Box::new(gnunet_types::Error::Conflict) as Cause);
    }
    Err(Box::new(Failure::<E, R> {
        original,
        completed,
        metrics,
        statistics: None,
        statistics_cleanup: None,
        statistics_report: None,
        resolver_drain: None,
        resolver_close,
    }))
}
