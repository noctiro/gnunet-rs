//! Bounded provider/frontend observations and independent terminal causes.
use crate::Cause;
use gnunet_gns_service_host::{
    self as host, Shared,
    auxiliary::{self, dns, registry},
    interceptor::{self, SourceCause, SourceProgress},
    native::{
        self,
        diagnostics::{OwnedError, OwnedProviderReport, OwnedReport},
    },
    server::{self, Event},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_types::Error as Fault;
use std::{error::Error, fmt, io, sync::Arc};
type Backend<'a> = native::NativeProvider<'a, auxiliary::Auxiliary<'a, 128, 256>>;
#[derive(Debug, Default)]
pub(super) struct Observations {
    pub(super) errors: [Option<OwnedError>; 8],
    pub(super) error_counts: [u64; 8],
    pub(super) reports: [Option<OwnedReport>; 6],
    pub(super) report_counts: [u64; 6],
    // Optional preparation failures stay distinct from a real lookup miss.
    pub(super) initial_registry: Option<Arc<registry::Error>>,
    pub(super) initial_dns_bootstrap: Option<Arc<dns::Error>>,
    pub(super) first_frontend: Option<server::Error>,
    pub(super) frontend_errors: u64,
    pub(super) first_accept: Option<gnunet_service_runtime::accepted::AcceptError>,
    pub(super) accept_errors: u64,
    pub(super) first_socket_diagnostics: Option<gnunet_native::network::Diagnostics>,
    pub(super) socket_diagnostics: u64,
    pub(super) first_receipt: Option<Fault>,
    pub(super) receipt_errors: u64,
    pub(super) first_cache_status: Option<i32>,
    pub(super) cache_statuses: u64,
    pub(super) intercepted: u64,
    pub(super) interception_lookups: u64,
    pub(super) interception_forward_admitted: u64,
    pub(super) interception_drop_admitted: u64,
    pub(super) interception_answers_admitted: u64,
    pub(super) interception_reply_whole_writes: u64,
    pub(super) interception_retired: u64,
    pub(super) interception_errors: u64,
    pub(super) interception_losses: u64,
    pub(super) first_interception_error: Option<interceptor::Error>,
    pub(super) first_interception_loss: Option<SourceCause>,
    pub(super) first_clock: Option<Fault>,
    pub(super) clock_failures: u64,
    pub(super) first_resolver: Option<gnunet_resolver_broker::BrokerError>,
    pub(super) resolver_errors: u64,
    pub(super) accepted: u64,
    pub(super) queries: u64,
    pub(super) replies: u64,
    pub(super) whole_reply_writes: u64,
    pub(super) written_bytes: u64,
    pub(super) expired: u64,
    pub(super) late: u64,
    pub(super) closed_clients: u64,
    pub(super) discarded_frames: u64,
    pub(super) discarded_suffix_bytes: u64,
    pub(super) exposed_prefix_bytes: u64,
    pub(super) local_closed: bool,
    pub(super) provider: Option<OwnedProviderReport>,
    pub(super) first_refresh_native: Option<OwnedError>,
    pub(super) refresh_native_errors: u64,
    pub(super) refresh_native_omitted: u64,
    pub(super) first_refresh_reason: Option<Fault>,
    pub(super) refresh_refusals: u64,
    pub(super) first_refresh_status: Option<i32>,
    pub(super) refresh_status_failures: u64,
    pub(super) refresh_expired: u64,
    pub(super) refresh_late: u64,
    pub(super) refresh: Option<host::refresh::Stats>,
}
impl Observations {
    pub(super) fn native(&mut self, error: native::Error<'_>, reports: &Reporter) -> bool {
        let recover = error.requires_port_recovery();
        // Preserve the original cause before releasing its lifetime-bound token.
        let error = error.into_owned();
        reports.warning(
            "gns.dependency.failed",
            format_args!("GNS original dependency {error:?}"),
        );
        let i = match &error {
            OwnedError::CacheLoss { .. }
            | OwnedError::CacheLocal { .. }
            | OwnedError::CacheOrphan { .. } => 0,
            OwnedError::DhtLoss { .. } => 1,
            OwnedError::Revocation { .. } | OwnedError::RevocationStatus(_) => 2,
            OwnedError::Dns(_) => 3,
            OwnedError::Resolver(_) => 4,
            OwnedError::Clock(_) => 5,
            OwnedError::Ports(_) | OwnedError::Connect(_) => 6,
            OwnedError::Protocol(_) | OwnedError::Registry(_) => 7,
        };
        self.error_counts[i] = self.error_counts[i].saturating_add(1);
        if self.errors[i].is_none() {
            self.errors[i] = Some(error)
        }
        recover
    }
    pub(super) fn refresh_native(&mut self, error: native::Error<'_>, reports: &Reporter) -> bool {
        let recover = error.requires_port_recovery();
        let error = error.into_owned();
        reports.warning(
            "gns.refresh.native",
            format_args!("GNS original optional refresh dependency {error:?}"),
        );
        self.refresh_native_errors = self.refresh_native_errors.saturating_add(1);
        if self.first_refresh_native.is_none() {
            self.first_refresh_native = Some(error);
        } else {
            self.refresh_native_omitted = self.refresh_native_omitted.saturating_add(1);
        }
        recover
    }
    pub(super) fn refresh_reason(&mut self, error: Fault, reports: &Reporter) {
        self.refresh_refusals = self.refresh_refusals.saturating_add(1);
        self.first_refresh_reason.get_or_insert(error);
        reports.debug(
            "gns.refresh.refused",
            format_args!("GNS optional refresh stopped: {error}"),
        );
    }
    pub(super) fn refresh_status(&mut self, status: i32, reports: &Reporter) {
        if status != 1 {
            self.refresh_status_failures = self.refresh_status_failures.saturating_add(1);
            self.first_refresh_status.get_or_insert(status);
            reports.warning(
                "gns.refresh.cache.status",
                format_args!("GNS optional refresh actual NAMECACHE status {status}"),
            );
        }
    }
    pub(super) fn interception_error(&mut self, error: interceptor::Error, reports: &Reporter) {
        reports.warning(
            "gns.interception.failed",
            format_args!("GNS original interception cause: {error}"),
        );
        self.interception_errors = self.interception_errors.saturating_add(1);
        self.first_interception_error.get_or_insert(error);
    }
    pub(super) fn interception(&mut self, event: interceptor::Event<'_>, reports: &Reporter) {
        match event {
            interceptor::Event::Received(_) => {
                self.intercepted = self.intercepted.saturating_add(1)
            }
            interceptor::Event::Lookup(_) => {
                self.interception_lookups = self.interception_lookups.saturating_add(1)
            }
            interceptor::Event::Admitted { action, .. } => match action {
                interceptor::Action::Forward => {
                    self.interception_forward_admitted =
                        self.interception_forward_admitted.saturating_add(1)
                }
                interceptor::Action::Drop => {
                    self.interception_drop_admitted =
                        self.interception_drop_admitted.saturating_add(1)
                }
                interceptor::Action::Answer { .. } => {
                    self.interception_answers_admitted =
                        self.interception_answers_admitted.saturating_add(1)
                }
            },
            interceptor::Event::Retired(_) => {
                self.interception_retired = self.interception_retired.saturating_add(1)
            }
            interceptor::Event::Failed { error, .. } => self.interception_error(error, reports),
            interceptor::Event::Source(progress) => match progress {
                SourceProgress::Written(_) => {
                    self.interception_reply_whole_writes =
                        self.interception_reply_whole_writes.saturating_add(1)
                }
                SourceProgress::Lost { cause, .. } => {
                    self.interception_losses = self.interception_losses.saturating_add(1);
                    if !matches!(cause, SourceCause::Closed | SourceCause::Cancelled) {
                        reports.warning(
                            "gns.interception.lost",
                            format_args!("GNS original DNS source: {cause:?}"),
                        );
                        self.first_interception_loss.get_or_insert(cause);
                    }
                }
                SourceProgress::Retry { error, .. } => {
                    self.interception_error(interceptor::Error::Source(error.into()), reports)
                }
                SourceProgress::Unavailable(error) => {
                    self.interception_error(interceptor::Error::Source(error), reports)
                }
                SourceProgress::Connected(_)
                | SourceProgress::InitWritten(_)
                | SourceProgress::Dropping(_)
                | SourceProgress::Activity { .. }
                | SourceProgress::Wait
                | SourceProgress::Closed => {}
                SourceProgress::Request(_) => {
                    self.interception_error(interceptor::Error::Protocol(Fault::Conflict), reports)
                }
            },
            interceptor::Event::Stopped => {}
        }
    }
    pub(super) fn receipt(&mut self, error: Fault, reports: &Reporter) {
        reports.warning(
            "gns.receipt.failed",
            format_args!("GNS original receipt {error}"),
        );
        self.receipt_errors = self.receipt_errors.saturating_add(1);
        self.first_receipt.get_or_insert(error);
    }
    pub(super) fn frontend(&mut self, error: server::Error, reports: &Reporter) {
        reports.warning("gns.client.failed", format_args!("GNS IPC owner {error}"));
        self.frontend_errors = self.frontend_errors.saturating_add(1);
        if self.first_frontend.is_none() {
            self.first_frontend = Some(error)
        }
    }
    pub(super) fn report(&mut self, report: native::Report<'_>, reports: &Reporter) {
        let report = report.into_owned();
        reports.debug(
            "gns.dependency.closed",
            format_args!("GNS actual operation retirement {report:?}"),
        );
        let i = match &report {
            OwnedReport::Cache { .. } => 0,
            OwnedReport::Remote { .. } => 1,
            OwnedReport::Revocation { .. } => 2,
            OwnedReport::Dns(_) => 3,
            OwnedReport::System(_) => 4,
            OwnedReport::Registry { .. } => 5,
        };
        self.report_counts[i] = self.report_counts[i].saturating_add(1);
        if self.reports[i].is_none() {
            self.reports[i] = Some(report)
        }
    }
    pub(super) fn socket(&mut self, d: gnunet_native::network::Diagnostics, reports: &Reporter) {
        if d.is_empty() {
            return;
        }
        reports.warning(
            "gns.socket.diagnostic",
            format_args!("GNS actual accepted-socket diagnostics {d:?}"),
        );
        self.socket_diagnostics = self.socket_diagnostics.saturating_add(1);
        if self.first_socket_diagnostics.is_none() {
            self.first_socket_diagnostics = Some(d)
        }
    }
}
pub(super) fn observe(
    event: Event<'_, '_, Backend<'_>>,
    reports: &Reporter,
    state: &mut Observations,
) -> bool {
    let mut recover = false;
    match event {
        Event::Accepted { diagnostics, .. } => {
            state.accepted = state.accepted.saturating_add(1);
            state.socket(diagnostics, reports);
        }
        Event::Refused {
            address,
            reason,
            diagnostics,
        } => {
            state.socket(diagnostics, reports);
            reports.debug(
                "gns.client.refused",
                format_args!("GNS actual {address:?}: {reason}"),
            );
        }
        Event::AdmissionFailed {
            diagnostics, cause, ..
        } => {
            state.socket(diagnostics, reports);
            state.frontend(server::Error::Io(cause), reports);
        }
        Event::Accept(gnunet_service_runtime::accepted::SocketEvent::Failed(error)) => {
            if !error.is_emfile() {
                reports.warning(
                    "gns.accept.failed",
                    format_args!("GNS actual accept {error}"),
                );
            }
            state.accept_errors = state.accept_errors.saturating_add(1);
            if state.first_accept.is_none() {
                state.first_accept = Some(error)
            }
        }
        Event::Accept(gnunet_service_runtime::accepted::SocketEvent::Diagnostic(error)) => {
            reports.warning(
                "gns.accept.diagnostic",
                format_args!("GNS actual socket {error:?}"),
            );
        }
        Event::Read { .. } | Event::Ignored(_) => {}
        Event::Lookup { .. } => state.queries = state.queries.saturating_add(1),
        Event::Rejected { reason, .. } => state.receipt(reason, reports),
        Event::Reply { failure, .. } => {
            state.replies = state.replies.saturating_add(1);
            if let Some(failure) = failure {
                reports.debug(
                    "gns.lookup.result",
                    format_args!(
                        "GNS actual semantic failure {failure:?}; IPC result has zero records"
                    ),
                );
            }
        }
        Event::Written {
            bytes, complete, ..
        } => {
            state.written_bytes = state.written_bytes.saturating_add(bytes as u64);
            if complete {
                state.whole_reply_writes = state.whole_reply_writes.saturating_add(1)
            }
        }
        Event::Closed {
            cause,
            cancel_errors,
            pending_frames,
            pending_suffix_bytes,
            partial_prefix_bytes,
            ..
        } => {
            state.closed_clients = state.closed_clients.saturating_add(1);
            state.discarded_frames = state.discarded_frames.saturating_add(pending_frames as u64);
            state.discarded_suffix_bytes = state
                .discarded_suffix_bytes
                .saturating_add(pending_suffix_bytes as u64);
            state.exposed_prefix_bytes = state
                .exposed_prefix_bytes
                .saturating_add(partial_prefix_bytes as u64);
            if let Some(error) = cause {
                state.frontend(error, reports)
            }
            for error in cancel_errors {
                state.receipt(error, reports)
            }
        }
        Event::Interception(event) => state.interception(event, reports),
        Event::ClockFailed(error) => {
            state.clock_failures = state.clock_failures.saturating_add(1);
            state.first_clock.get_or_insert(error);
            reports.warning(
                "gns.clock.failed",
                format_args!("GNS canonical clock suspended: {error}"),
            );
            recover = true;
        }
        Event::Stopped => state.local_closed = true,
        Event::Manager(event) => match event {
            host::Event::Failed {
                cause,
                receipt_error,
                ..
            } => {
                match cause {
                    host::Cause::Native(e) => recover |= state.native(e, reports),
                    host::Cause::Protocol(e) => state.receipt(e, reports),
                    host::Cause::CacheStore(status) => {
                        state.cache_statuses = state.cache_statuses.saturating_add(1);
                        state.first_cache_status.get_or_insert(status);
                        reports.warning(
                            "gns.cache.status",
                            format_args!("GNS actual NAMECACHE status {status}"),
                        );
                    }
                }
                if let Some(error) = receipt_error {
                    state.receipt(error, reports)
                }
            }
            host::Event::GuardFailed { error, .. }
            | host::Event::LateRefusal { error, .. }
            | host::Event::RetireFailed { error, .. } => recover |= state.native(error, reports),
            host::Event::LateObservation { value, .. } => {
                state.late = state.late.saturating_add(1);
                if let Err(e) = value {
                    recover |= state.native(e, reports)
                }
            }
            host::Event::Ignored { reason, .. } => reports.debug(
                "gns.candidate.ignored",
                format_args!("GNS rejected candidate, original GET remains: {reason}"),
            ),
            host::Event::Expired { .. } => state.expired = state.expired.saturating_add(1),
            host::Event::Retired { report, .. } => state.report(report, reports),
            host::Event::Refresh(event) => {
                use host::refresh::Event as Refresh;
                match event {
                    Refresh::Failed { error, expired, .. } => {
                        if expired {
                            state.refresh_expired = state.refresh_expired.saturating_add(1);
                        }
                        recover |= state.refresh_native(error, reports);
                    }
                    Refresh::GuardFailed { error, .. } | Refresh::RetireFailed { error, .. } => {
                        recover |= state.refresh_native(error, reports)
                    }
                    Refresh::Retired { report, .. } => state.report(report, reports),
                    Refresh::Refused { reason, .. }
                    | Refresh::Ignored {
                        reason: Some(reason),
                        ..
                    } => state.refresh_reason(reason, reports),
                    Refresh::Stored { status, .. } => state.refresh_status(status, reports),
                    Refresh::LateObservation { value, .. } => {
                        state.refresh_late = state.refresh_late.saturating_add(1);
                        match value {
                            Err(error) => recover |= state.refresh_native(error, reports),
                            Ok(host::Value::Stored(status)) => {
                                state.refresh_status(status, reports)
                            }
                            _ => {}
                        }
                    }
                    Refresh::Expired { .. } | Refresh::Started { expired: true, .. } => {
                        state.refresh_expired = state.refresh_expired.saturating_add(1)
                    }
                    Refresh::Queued { .. }
                    | Refresh::Started { .. }
                    | Refresh::Ignored { reason: None, .. }
                    | Refresh::Selected { .. }
                    | Refresh::Retiring { .. }
                    | Refresh::Finished { .. } => {}
                }
            }
            host::Event::Shared(Shared::Failed(error)) => recover |= state.native(error, reports),
            host::Event::Started { .. }
            | host::Event::Observed { .. }
            | host::Event::Retiring { .. }
            | host::Event::Ready { .. }
            | host::Event::Shared(Shared::Activity | Shared::Recovered)
            | host::Event::Stopped => {}
        },
    }
    recover
}
#[derive(Debug, Default)]
pub(super) struct Failure {
    pub(super) original: Option<Cause>,
    pub(super) signal: Option<gnunet_service_startup::StopError>,
    pub(super) running: Option<server::Error>,
    pub(super) cleanup: Option<server::Error>,
    pub(super) cleanup_errors: u64,
    pub(super) output: Option<io::Error>,
    pub(super) logging: Option<io::Error>,
    pub(super) observations: Observations,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GNS original lifecycle and bounded observations {self:?}"
        )
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.signal.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.running.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.cleanup.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.output.as_ref().map(|e| e as &dyn Error))
            .or_else(|| self.logging.as_ref().map(|e| e as &dyn Error))
            .or_else(|| {
                self.observations
                    .first_interception_error
                    .as_ref()
                    .map(|e| e as &dyn Error)
            })
            .or(match self.observations.first_interception_loss.as_ref() {
                Some(SourceCause::Io(e)) => Some(e as &dyn Error),
                Some(SourceCause::Protocol(e) | SourceCause::Clock(e)) => Some(e as &dyn Error),
                _ => None,
            })
            .or_else(|| {
                self.observations
                    .errors
                    .iter()
                    .flatten()
                    .next()
                    .map(|e| e as &dyn Error)
            })
            .or_else(|| {
                self.observations
                    .first_resolver
                    .as_ref()
                    .map(|e| e as &dyn Error)
            })
    }
}
impl Failure {
    pub(super) fn failed(&self) -> bool {
        self.original.is_some()
            || self.signal.is_some()
            || self.running.is_some()
            || self.cleanup.is_some()
            || self.output.is_some()
            || self.logging.is_some()
            || self.observations.errors.iter().any(Option::is_some)
            || self.observations.first_resolver.is_some()
            || self.observations.first_clock.is_some()
            || self.observations.first_frontend.is_some()
            || self.observations.first_interception_error.is_some()
            || self.observations.first_interception_loss.is_some()
    }
}
