//! Independent original service, cleanup and publisher observations.
use crate::{Report as HostReport, statistics::Statistics};
use gnunet_service_runtime::service::PeerAddress;
use std::{error::Error, io};
/// Independent real NSE and statistics-source observations. No field is a
/// remote-delivery, proof durability or STATISTICS disk acknowledgement.
#[derive(Clone, Copy, Debug)]
pub struct Report<R = ()> {
    /// Original CORE/PILS, service, proof and subscriber facts.
    pub host: HostReport,
    /// Original producer epoch, local writes, unknowns and actual destruction.
    pub statistics: Option<R>,
}
pub(super) struct StatisticsErrors<E> {
    pub(super) first: Option<E>,
    pub(super) cleanup: Option<E>,
}
impl<E> Default for StatisticsErrors<E> {
    fn default() -> Self {
        Self {
            first: None,
            cleanup: None,
        }
    }
}
impl<E> StatisticsErrors<E> {
    pub(super) fn record(&mut self, error: E) {
        if self.first.is_none() {
            self.first = Some(error);
        } else if self.cleanup.is_none() {
            self.cleanup = Some(error);
        }
    }
}
pub(super) fn abort_statistics<D: Statistics>(
    publisher: &mut Option<D>,
    errors: &mut StatisticsErrors<D::Error>,
) {
    if let Some(publisher) = publisher.as_mut()
        && let Err(error) = publisher.abort()
    {
        errors.record(error);
    }
}
#[derive(Debug)]
pub(super) struct ForegroundFailures<E, R> {
    pub(super) original: Option<Box<dyn Error>>,
    pub(super) host_close: Option<crate::Error>,
    pub(super) statistics: Option<E>,
    pub(super) statistics_cleanup: Option<E>,
    pub(super) resolver_drain: Option<gnunet_resolver_broker::BrokerError>,
    pub(super) resolver_close: Option<gnunet_resolver_broker::BrokerError>,
    pub(super) resolver_io: Option<io::Error>,
    pub(super) resolver_connect: Option<gnunet_resolver_broker::BrokerError>,
    pub(super) report: Report<R>,
}
impl<E: Error + 'static, R: std::fmt::Debug + 'static> ForegroundFailures<E, R> {
    pub(super) fn finish(self) -> Result<Report<R>, Box<dyn Error>> {
        if self.original.is_none()
            && self.host_close.is_none()
            && self.statistics.is_none()
            && self.statistics_cleanup.is_none()
            && self.resolver_drain.is_none()
            && self.resolver_close.is_none()
            && self.resolver_io.is_none()
            && self.resolver_connect.is_none()
        {
            Ok(self.report)
        } else {
            Err(Box::new(self))
        }
    }
}
impl<E: std::fmt::Debug, R: std::fmt::Debug> std::fmt::Display for ForegroundFailures<E, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NSE original={:?}; original host close={:?}; statistics={:?}; statistics cleanup={:?}; Resolver drain={:?}; close={:?}; IO={:?}; connection={:?}; actual reports={:?}",
            self.original,
            self.host_close,
            self.statistics,
            self.statistics_cleanup,
            self.resolver_drain,
            self.resolver_close,
            self.resolver_io,
            self.resolver_connect,
            self.report
        )
    }
}
impl<E: Error + 'static, R: std::fmt::Debug + 'static> Error for ForegroundFailures<E, R> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or(self.host_close.as_ref().map(|e| e as &dyn Error))
            .or(self.statistics.as_ref().map(|e| e as &dyn Error))
            .or(self.statistics_cleanup.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_drain.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_close.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_io.as_ref().map(|e| e as &dyn Error))
            .or(self.resolver_connect.as_ref().map(|e| e as &dyn Error))
    }
}
/// Exact original unadmitted subscriber failure. Its stream is already
/// physically closed; reporting it grants no client/protocol admission.
#[derive(Debug)]
pub struct AdmissionFailure {
    /// Actual original remote socket address.
    pub peer: PeerAddress,
    /// Actual original credential/resource cause, never a fabricated IO error.
    pub error: crate::Error,
}
