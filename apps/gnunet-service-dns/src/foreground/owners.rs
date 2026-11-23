//! Original service owners, independent failures and rejected composition cleanup.
use super::observe;
use crate::{
    Failure,
    statistics::{self, Publisher},
};
use gnunet_dns_service_host::{Gateway, GatewayReport, RejectedGateway, Retirement};
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::Driver as ResolverDriver;
use std::{future::poll_fn, io, task::Poll, time::Duration};
use tokio::time::Instant;

#[derive(Debug, Default)]
pub(super) struct Failures {
    pub(super) original: Option<Failure>,
    pub(super) cleanup: Option<Failure>,
    pub(super) statistics: Option<statistics::Failure>,
    pub(super) statistics_cleanup: Option<statistics::Failure>,
    pub(super) resolver_drain: Option<Failure>,
    pub(super) resolver_close: Option<Failure>,
    pub(super) resolver_io: Option<io::Error>,
    pub(super) resolver_connect: Option<gnunet_resolver_broker::BrokerError>,
    pub(super) retirement: Option<Failure>,
    pub(super) gateway: Option<GatewayReport>,
    pub(super) publisher: Option<gnunet_ipc_unix::producer::Report<6>>,
}
fn gateway_failed(report: &GatewayReport) -> bool {
    report.first.is_some()
        || report.cleanup.is_some()
        || report
            .source_retirement
            .as_ref()
            .is_none_or(Retirement::has_failure)
        || report
            .upstream_retirement
            .as_ref()
            .is_none_or(gnunet_dns_service_host::UpstreamRetirement::has_failure)
}
impl Failures {
    pub(super) fn finish(self) -> Result<(), Failure> {
        if self.original.is_none()
            && self.cleanup.is_none()
            && self.statistics.is_none()
            && self.statistics_cleanup.is_none()
            && self.resolver_drain.is_none()
            && self.resolver_close.is_none()
            && self.resolver_io.is_none()
            && self.resolver_connect.is_none()
            && self.retirement.is_none()
            && self
                .gateway
                .as_ref()
                .is_none_or(|report| !gateway_failed(report))
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DNS original={:?}; cleanup={:?}; statistics={:?}; statistics cleanup={:?}; Resolver drain={:?}; Resolver close={:?}; Resolver native IO={:?}; Resolver connection={:?}; retirement={:?}; original gateway report={:?}; publisher={:?}",
            self.original,
            self.cleanup,
            self.statistics,
            self.statistics_cleanup,
            self.resolver_drain,
            self.resolver_close,
            self.resolver_io,
            self.resolver_connect,
            self.retirement,
            self.gateway,
            self.publisher
        )
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.cleanup.as_deref())
            .or(self
                .statistics
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
            .or(self
                .statistics_cleanup
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
            .or(self.resolver_drain.as_deref())
            .or(self.resolver_close.as_deref())
            .or(self
                .resolver_io
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
            .or(self
                .resolver_connect
                .as_ref()
                .map(|e| e as &dyn std::error::Error))
            .or(self.retirement.as_deref())
            .or_else(|| {
                self.gateway
                    .as_ref()
                    .and_then(|report| report.first.as_ref().or(report.cleanup.as_ref()))
                    .map(|e| e as &dyn std::error::Error)
            })
    }
}
pub(super) struct Owners<'id, 'stats> {
    pub(super) gateway: Option<Gateway<'id>>,
    pub(super) statistics: Option<Publisher<'stats>>,
    pub(super) stats_error: Option<statistics::Failure>,
    pub(super) stats_cleanup: Option<statistics::Failure>,
    pub(super) resolver: ResolverDriver<8, 256>,
    pub(super) reports: Reporter,
    pub(super) done: bool,
}
impl Owners<'_, '_> {
    pub(super) fn statistics_failed(&mut self, error: statistics::Failure) {
        self.reports.warning(
            "dns.statistics.failure",
            format_args!("dns original statistics publisher: {error}"),
        );
        if self.stats_error.is_none() {
            self.stats_error = Some(error);
        } else if self.stats_cleanup.is_none() {
            self.stats_cleanup = Some(error);
        }
    }
    pub(super) fn refresh_statistics(&mut self) {
        if self.stats_error.is_some() {
            return;
        }
        let counts = self.gateway.as_ref().map_or([0; 6], Gateway::statistics);
        if let Some(publisher) = self.statistics.as_mut()
            && let Err(error) = publisher.refresh(statistics::snapshot(counts))
        {
            self.statistics_failed(error);
        }
    }
    pub(super) fn abort_statistics(&mut self) {
        if let Some(publisher) = self.statistics.as_mut()
            && let Err(error) = publisher.abort()
        {
            self.statistics_failed(error);
        }
    }
}
impl Drop for Owners<'_, '_> {
    fn drop(&mut self) {
        if !self.done {
            let reports = self.reports.clone();
            if let Some(gateway) = self.gateway.as_mut() {
                gateway.close(None, &mut |event| observe(&reports, event));
            }
            self.abort_statistics();
            let resolver = self.resolver.disconnect();
            let retirement = self
                .gateway
                .as_ref()
                .and_then(|gateway| gateway.report().source_retirement.as_ref());
            reports.warning("dns.interrupted", format_args!("dns SERVICE interrupted: packet source retirement={retirement:?}; Resolver={resolver:?}"));
        }
    }
}
#[derive(Debug)]
struct Rejected {
    original: gnunet_dns_service_host::Error,
    mq: Option<gnunet_dns_service_host::Error>,
    source: Option<Retirement>,
    deadline: Option<tokio::time::error::Elapsed>,
    upstream: Option<gnunet_dns_service_host::UpstreamRetirement>,
    upstream_deadline: Option<tokio::time::error::Elapsed>,
    bound: Option<gnunet_types::Error>,
}
impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "dns composition original={}; MQ cleanup={:?}; packet source retirement={:?}; unconfirmed retirement={:?}; upstream retirement={:?}; unconfirmed upstream retirement={:?}; bound={:?}",
            self.original,
            self.mq,
            self.source,
            self.deadline,
            self.upstream,
            self.upstream_deadline,
            self.bound
        )
    }
}
impl std::error::Error for Rejected {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
pub(super) async fn rejected(
    mut rejected: RejectedGateway<'_>,
    grace: Duration,
    reports: &Reporter,
) -> Failure {
    let original = rejected.error;
    let mq = rejected
        .server
        .close_all(&mut |event| observe(reports, event));
    rejected.packets.request_stop();
    let mut upstream_owner = rejected.upstream.take();
    if let Some(upstream) = upstream_owner.as_mut() {
        let _stopped = upstream.stop();
    }
    let now = Instant::now();
    let target = now.checked_add(grace);
    let until = target.unwrap_or(now);
    let outcome = tokio::time::timeout_at(
        until,
        poll_fn(|cx| {
            reports.register(cx);
            rejected.packets.poll_retirement(cx)
        }),
    )
    .await;
    let (source, deadline) = match outcome {
        Ok(exit) => (Some(exit), None),
        Err(error) => {
            let exit = poll_fn(|cx| {
                Poll::Ready(match rejected.packets.poll_retirement(cx) {
                    Poll::Ready(exit) => Some(exit),
                    Poll::Pending => None,
                })
            })
            .await;
            (exit, Some(error))
        }
    };
    let (upstream, upstream_deadline) = match upstream_owner.as_mut() {
        Some(owner) => {
            match tokio::time::timeout_at(until, poll_fn(|cx| owner.poll_retirement(cx))).await {
                Ok(receipt) => (Some(receipt), None),
                Err(error) => (None, Some(error)),
            }
        }
        None => (None, None),
    };
    Box::new(Rejected {
        original,
        mq,
        source,
        deadline,
        upstream,
        upstream_deadline,
        bound: target.is_none().then_some(gnunet_types::Error::Overflow),
    })
}
