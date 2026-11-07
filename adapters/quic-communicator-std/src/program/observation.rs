//! One real app publisher; no IPC dependency or protocol model lives here.
use super::Failure;
use crate::{
    Closed,
    metrics::Metrics,
    statistics::{Configuration, Statistics, StatisticsFactory},
};
use std::{
    error::Error,
    fmt::{self, Debug},
    task::{Context, Poll},
    time::Duration,
};
pub(super) struct Owner<D: Statistics> {
    driver: Option<D>,
    first: Option<D::Error>,
    cleanup: Option<D::Error>,
}
pub(super) fn create<'a, F: StatisticsFactory>(
    storage: &'a mut F::Storage,
    config: Configuration,
) -> Owner<F::Driver<'a>> {
    match F::create(storage, config) {
        Ok(driver) => Owner {
            driver,
            first: None,
            cleanup: None,
        },
        Err(error) => Owner {
            driver: None,
            first: Some(error),
            cleanup: None,
        },
    }
}
impl<D: Statistics> Owner<D> {
    fn error(&mut self, error: D::Error) {
        if self.first.is_none() {
            self.first = Some(error);
        } else if self.cleanup.is_none() {
            self.cleanup = Some(error);
        }
    }
    pub(super) fn closed(&self) -> bool {
        self.driver.as_ref().is_none_or(Statistics::is_closed)
    }
    pub(super) fn abort(&mut self) {
        if let Some(driver) = &mut self.driver
            && !driver.is_closed()
            && let Err(error) = driver.abort()
        {
            self.error(error);
        }
    }
    pub(super) fn guard(&mut self, cx: &mut Context<'_>, failed: bool) -> bool {
        let mut changed = false;
        if let Some(driver) = &mut self.driver
            && !driver.is_closed()
            && let Poll::Ready(result) = driver.poll_native_guard(cx)
        {
            changed = true;
            if let Err(error) = result {
                self.error(error);
                self.abort();
            }
        }
        if failed {
            self.abort();
        }
        changed
    }
    pub(super) fn refresh(&mut self, metrics: Metrics) {
        if let Some(driver) = &mut self.driver
            && !driver.is_closed()
            && let Err(error) = driver.refresh(metrics)
        {
            self.error(error);
            self.abort();
        }
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>, failed: bool) -> bool {
        let changed = self.guard(cx, failed);
        if failed {
            return changed;
        }
        let Some(driver) = &mut self.driver else {
            return changed;
        };
        if driver.is_closed() {
            return changed;
        }
        match driver.poll(cx) {
            Poll::Ready(Ok(())) => true,
            Poll::Ready(Err(error)) => {
                self.error(error);
                self.abort();
                true
            }
            Poll::Pending => changed,
        }
    }
    pub(super) fn begin_close(&mut self, metrics: Metrics) {
        if let Some(driver) = &mut self.driver
            && !driver.is_closed()
            && let Err(error) = driver.begin_close(metrics, Duration::from_secs(5))
        {
            self.error(error);
            self.abort();
        }
    }
    pub(super) fn report(&self) -> Option<D::Report> {
        self.driver.as_ref().map(Statistics::report)
    }
    pub(super) fn finish(
        mut self,
        original: Result<(), Failure>,
        closed: Closed,
        metrics: Metrics,
    ) -> Result<(), Failure> {
        self.abort();
        let report = self.report();
        drop(self.driver);
        let original = original.err();
        if original.is_none()
            && closed.cleanup.is_none()
            && self.first.is_none()
            && self.cleanup.is_none()
        {
            return Ok(());
        }
        Err(Box::new(ObservationFailure {
            original,
            closed,
            metrics,
            first: self.first,
            cleanup: self.cleanup,
            report,
        }))
    }
}
#[derive(Debug)]
struct ObservationFailure<E, R> {
    original: Option<Failure>,
    closed: Closed,
    metrics: Metrics,
    first: Option<E>,
    cleanup: Option<E>,
    report: Option<R>,
}
impl<E: Debug, R: Debug> fmt::Display for ObservationFailure<E, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "communicator observation: original={:?}; original_closed={:?}; metrics={:?}; statistics={:?}; statistics_cleanup={:?}; actual_report={:?}",
            self.original, self.closed, self.metrics, self.first, self.cleanup, self.report
        )
    }
}
impl<E: Error + 'static, R: Debug + 'static> Error for ObservationFailure<E, R> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or(self.closed.cleanup.as_ref().map(|e| e as &dyn Error))
            .or(self.first.as_ref().map(|e| e as &dyn Error))
            .or(self.cleanup.as_ref().map(|e| e as &dyn Error))
    }
}
