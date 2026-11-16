//! Independent terminal causes and bounded original source/effect observations.
use crate::Failure;
use gnunet_messenger_host::{self as api, domain};
use std::{fmt, io};
/// Owned terminal facts; copied coordinates grant no live Core authority.
#[derive(Clone, Copy)]
pub(crate) enum StopObservation {
    Native,
    Deadline(domain::HandleObservation),
    Initialization,
    Cancelled(domain::HandleObservation),
    Closed,
    Clock(gnunet_types::Error),
    Domain(domain::Error),
    Local(gnunet_types::Error),
}
impl fmt::Debug for StopObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => f.write_str("Native"),
            Self::Deadline(operation) => f.debug_tuple("Deadline").field(operation).finish(),
            Self::Initialization => f.write_str("Initialization"),
            Self::Cancelled(operation) => f.debug_tuple("Cancelled").field(operation).finish(),
            Self::Closed => f.write_str("Closed"),
            Self::Clock(error) => f.debug_tuple("Clock").field(error).finish(),
            Self::Domain(error) => f.debug_tuple("Domain").field(error).finish(),
            Self::Local(error) => f.debug_tuple("Local").field(error).finish(),
        }
    }
}
impl From<api::StopCause<'_>> for StopObservation {
    fn from(value: api::StopCause<'_>) -> Self {
        match value {
            api::StopCause::Native => Self::Native,
            api::StopCause::Deadline(operation) => Self::Deadline(operation.observation()),
            api::StopCause::Initialization => Self::Initialization,
            api::StopCause::Cancelled(operation) => Self::Cancelled(operation.observation()),
            api::StopCause::Closed => Self::Closed,
            api::StopCause::Clock(error) => Self::Clock(error),
            api::StopCause::Domain(error) => Self::Domain(error),
            api::StopCause::Local(error) => Self::Local(error),
        }
    }
}
#[derive(Default)]
pub(crate) struct Report {
    pub input_chunks: u64,
    pub retired_input_bytes: Option<usize>,
    pub input_closed: Option<bool>,
    pub input_cancelled: Option<bool>,
    pub output_written: u64,
    pub output_pending: usize,
    pub output_pending_rows: usize,
    pub output_uncertain: bool,
    pub output_closed: Option<bool>,
    pub output_flushed: Option<bool>,
    pub submitted: u64,
    pub completed: u64,
    pub local_written: u64,
    pub displayed: u64,
    pub stop: Option<StopObservation>,
    pub native_reason: Option<&'static str>,
    pub jobs: Vec<Job>,
    pub frames: Vec<Frame>,
    pub control: Option<(api::native::Kind, api::Exposure)>,
    pub record_sources: Vec<RecordSource>,
    pub domain_cleanup: Vec<(domain::HandleObservation, domain::Error)>,
    pub domain_observations: Vec<domain::EventObservation>,
    pub unresolved_layout: bool,
    pub recoveries: u64,
    pub recovery_native: Option<api::native::Error>,
    pub recovery_reason: Option<&'static str>,
    pub omitted_jobs: u64,
    pub omitted_frames: u64,
    pub omitted_record_sources: u64,
}
pub(crate) struct Job {
    pub operation: domain::HandleObservation,
    pub room: domain::HandleObservation,
    pub source: domain::HandleObservation,
    pub exposure: api::Exposure,
}
pub(crate) struct Frame {
    pub kind: api::native::Kind,
    pub submission: api::native::Submission,
}
pub(crate) struct RecordSource {
    pub operations: usize,
    pub exposed: usize,
    pub has_control: bool,
}
impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerReport")
            .field("input_chunks", &self.input_chunks)
            .field("retired_input_bytes", &self.retired_input_bytes)
            .field("input_closed", &self.input_closed)
            .field("input_cancelled", &self.input_cancelled)
            .field("output_written", &self.output_written)
            .field("output_pending", &self.output_pending)
            .field("output_pending_rows", &self.output_pending_rows)
            .field("output_uncertain", &self.output_uncertain)
            .field("output_closed", &self.output_closed)
            .field("output_flushed", &self.output_flushed)
            .field("submitted", &self.submitted)
            .field("completed", &self.completed)
            .field("local_written", &self.local_written)
            .field("displayed", &self.displayed)
            .field("stop", &self.stop)
            .field("native_reason", &self.native_reason)
            .field("jobs", &self.jobs)
            .field("frames", &self.frames)
            .field("control", &self.control)
            .field("record_sources", &self.record_sources)
            .field("domain_cleanup", &self.domain_cleanup)
            .field("domain_observations", &self.domain_observations)
            .field("unresolved_layout", &self.unresolved_layout)
            .field("recoveries", &self.recoveries)
            .field("recovery_native", &self.recovery_native)
            .field("recovery_reason", &self.recovery_reason)
            .field("omitted_jobs", &self.omitted_jobs)
            .field("omitted_frames", &self.omitted_frames)
            .field("omitted_record_sources", &self.omitted_record_sources)
            .finish()
    }
}
impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Job")
            .field("operation", &self.operation)
            .field("room", &self.room)
            .field("source", &self.source)
            .field("exposure", &self.exposure)
            .finish()
    }
}
impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("kind", &self.kind)
            .field("submission", &self.submission)
            .finish()
    }
}
impl fmt::Debug for RecordSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecordSource")
            .field("operations", &self.operations)
            .field("exposed", &self.exposed)
            .field("has_control", &self.has_control)
            .finish()
    }
}
impl Report {
    pub(crate) fn new(limits: api::Limits) -> Result<Self, Failure> {
        let limit = limits.operations;
        let observations = limits
            .core
            .rooms
            .checked_mul(2)
            .and_then(|rooms| rooms.checked_add(limits.core.events))
            .ok_or(gnunet_types::Error::Overflow)?;
        let cleanup = limits
            .core
            .rooms
            .checked_add(limits.operations)
            .ok_or(gnunet_types::Error::Overflow)?;
        let mut report = Self::default();
        report.jobs.try_reserve_exact(limit)?;
        report.frames.try_reserve_exact(limit)?;
        report.record_sources.try_reserve_exact(4)?;
        report.domain_observations.try_reserve_exact(observations)?;
        report.domain_cleanup.try_reserve_exact(cleanup)?;
        Ok(report)
    }
    pub(crate) fn record_source(&mut self, loss: &gnunet_namestore_client_host::Loss<'_>) {
        // Repeated physical recovery keeps a bounded detail inventory and an
        // explicit omitted count, rather than growing diagnostics indefinitely.
        if self.record_sources.len() == self.record_sources.capacity() {
            self.omitted_record_sources = self.omitted_record_sources.saturating_add(1);
        } else {
            self.record_sources.push(RecordSource {
                operations: loss.operations,
                exposed: loss.exposed,
                has_control: loss.control.is_some(),
            });
        }
    }
    pub(crate) fn capture(&mut self, loss: api::Loss<'_>, errors: &mut Failures) {
        self.capture_as(loss, errors, false);
    }
    pub(crate) fn capture_recovery(&mut self, loss: api::Loss<'_>, errors: &mut Failures) {
        self.recoveries = self.recoveries.saturating_add(1);
        self.capture_as(loss, errors, true);
    }
    fn capture_as(&mut self, loss: api::Loss<'_>, errors: &mut Failures, recovery: bool) {
        self.unresolved_layout |= loss.layout_need().is_some();
        for job in loss.jobs() {
            if self.jobs.len() == self.jobs.capacity() {
                self.omitted_jobs = self.omitted_jobs.saturating_add(1);
            } else {
                self.jobs.push(Job {
                    operation: job.operation().observation(),
                    room: job.room().observation(),
                    source: job.source().observation(),
                    exposure: job.exposure(),
                });
            }
        }
        let parts = loss.into_parts();
        self.stop = Some(parts.cause.into());
        self.control = parts.control.map(|v| (v.kind(), v.exposure()));
        self.domain_cleanup.clear();
        for (room, error) in parts.cleanup {
            self.domain_cleanup.push((room.observation(), error));
        }
        if errors.cleanup.is_none()
            && let Some((_, error)) = self.domain_cleanup.first()
        {
            errors.cleanup = Some(api::Error::Domain(*error));
        }
        self.domain_observations.clear();
        for event in parts.observations {
            self.domain_observations.push(event.observation());
        }
        if errors.api.is_none() {
            errors.api = parts.failure;
        }
        for original in parts.native.reports {
            if self.frames.len() == self.frames.capacity() {
                self.omitted_frames = self.omitted_frames.saturating_add(1);
            } else {
                self.frames.push(Frame {
                    kind: original.kind,
                    submission: original.submission,
                });
            }
        }
        use api::native::LossCause;
        let reason = match parts.native.cause {
            LossCause::Failure(error) => {
                if recovery {
                    if self.recovery_native.is_none() {
                        self.recovery_native = Some(error);
                    }
                } else if errors.native.is_none() {
                    errors.native = Some(error);
                }
                "Failure"
            }
            LossCause::Eof => "Eof",
            LossCause::InputDeadline => "InputDeadline",
            LossCause::InitialDeadline => "InitialDeadline",
            LossCause::FrameDeadline(_) => "FrameDeadline",
            LossCause::Cancelled(_) => "Cancelled",
            LossCause::Closed => "Closed",
        };
        self.native_reason = Some(reason);
        if recovery && self.recovery_reason.is_none() {
            self.recovery_reason = Some(reason);
        }
        if let Some(records) = parts.records {
            let (general, monitor) = records.into_sources();
            for loss in [general, monitor].into_iter().flatten() {
                self.record_source(&loss);
            }
        }
    }
}
#[derive(Default)]
pub(crate) struct Failures {
    pub original: Option<Failure>,
    pub entropy: Option<Failure>,
    pub api: Option<api::Error>,
    pub native: Option<api::native::Error>,
    pub records: Option<gnunet_namestore_client_host::LossCause>,
    pub resolver: Option<gnunet_resolver_broker::BrokerError>,
    pub resolver_close: Option<gnunet_resolver_broker::BrokerError>,
    pub cleanup: Option<api::Error>,
    pub input: Option<io::Error>,
    pub signal: Option<gnunet_service_startup::StopError>,
    pub output: Option<io::Error>,
    pub stdio: Option<gnunet_program_host::binary_io::RetiredSet<2>>,
    pub logging: Option<io::Error>,
    pub report: Option<Report>,
}
impl fmt::Debug for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessengerFailures")
            .field("original", &self.original)
            .field("entropy", &self.entropy)
            .field("api", &self.api)
            .field("native", &self.native)
            .field("records", &self.records)
            .field("resolver", &self.resolver)
            .field("resolver_close", &self.resolver_close)
            .field("cleanup", &self.cleanup)
            .field("input", &self.input)
            .field("signal", &self.signal)
            .field("output", &self.output)
            .field("stdio", &self.stdio)
            .field("logging", &self.logging)
            .field("report", &self.report)
            .finish()
    }
}
impl fmt::Display for Failures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Messenger original lifecycle: {self:?}")
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or(self.entropy.as_deref())
            .or(self.api.as_ref().map(|e| e as _))
            .or(self.native.as_ref().map(|e| e as _))
            .or(self.resolver.as_ref().map(|e| e as _))
            .or(self.resolver_close.as_ref().map(|e| e as _))
            .or(self.cleanup.as_ref().map(|e| e as _))
            .or(self.input.as_ref().map(|e| e as _))
            .or(self.signal.as_ref().map(|e| e as _))
            .or(self.output.as_ref().map(|e| e as _))
            .or(self.stdio.as_ref().map(|e| e as _))
            .or(self.logging.as_ref().map(|e| e as _))
    }
}
impl Failures {
    pub(crate) fn record_original(&mut self, next: Failure) {
        self.original = Some(match self.original.take() {
            Some(prior) => Box::new(ConcurrentFailure { prior, next }),
            None => next,
        });
    }
    pub(crate) fn failed(&self) -> bool {
        self.original.is_some()
            || self.entropy.is_some()
            || self.api.is_some()
            || self.native.is_some()
            || self.records.is_some()
            || self.resolver.is_some()
            || self.resolver_close.is_some()
            || self.cleanup.is_some()
            || self.input.is_some()
            || self.signal.is_some()
            || self.output.is_some()
            || self.stdio.is_some()
            || self.logging.is_some()
    }
    pub(crate) fn finish(mut self, report: Report) -> Result<Report, Failure> {
        if self.failed() {
            self.report = Some(report);
            Err(Box::new(self))
        } else {
            Ok(report)
        }
    }
}
#[derive(Debug)]
struct ConcurrentFailure {
    prior: Failure,
    next: Failure,
}
impl fmt::Display for ConcurrentFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original cause: {}; additional cause: {}",
            self.prior, self.next
        )
    }
}
impl std::error::Error for ConcurrentFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.prior.as_ref())
    }
}

// The entropy backend's no_std error is Copy but need not implement std::Error.
// Keep that actual value, rather than dropping it behind EntropyUnavailable.
#[derive(Debug)]
pub(crate) struct EntropyFailure<E>(pub E);
impl<E: fmt::Debug + fmt::Display> fmt::Display for EntropyFailure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original operating-system entropy failure: {}", self.0)
    }
}
impl<E: fmt::Debug + fmt::Display> std::error::Error for EntropyFailure<E> {}

#[derive(Debug)]
pub(crate) struct DiagnosticFailure {
    pub original: Option<Failure>,
    pub logging: io::Error,
}
impl fmt::Display for DiagnosticFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Messenger diagnostic failure: {self:?}")
    }
}
impl std::error::Error for DiagnosticFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref().or(Some(&self.logging))
    }
}

#[derive(Debug)]
pub(crate) struct ReportedFailure(pub Failure);
impl fmt::Display for ReportedFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for ReportedFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
