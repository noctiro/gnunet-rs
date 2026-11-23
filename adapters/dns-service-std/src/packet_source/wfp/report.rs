use super::StopRequest;
use gnunet_wfp_dns::device as record;
use gnunet_wfp_dns_host::device;
use std::{fmt, io};

/// Original service file's STOP and completion observations.
/// This is not a kernel-driver unload or native callback-cutoff receipt.
#[derive(Clone, Copy, Debug, Default)]
pub struct WfpRetirement {
    /// Actual successful STOP revoked capture and released upstream exclusions.
    pub stop_confirmed: bool,
    /// Original STOP failure, independent of completion observations.
    pub stop_error: Option<device::Error>,
    /// First original device-record operation failure.
    pub device_error: Option<device::Error>,
    /// The original event wait reported a failure.
    pub wait_failed: bool,
    /// An admitted injection still lacked its original completion at retirement.
    pub pending_packet: Option<usize>,
    /// Most recent original completion, including status and receive authorization.
    pub last_completion: Option<record::Completion>,
    /// The original packet FILE was actually closed.
    pub file_closed: bool,
    /// Original consuming FILE-close refusal, without retry.
    pub file_close_error: Option<device::Error>,
    /// A cancelled replacement open still owns its detached native attempt.
    pub detached_open: bool,
    /// The original retirement worker still owns native operations at shutdown expiry.
    pub detached_retirement: bool,
    /// Original native retirement could not be handed to or observed from its worker.
    pub retirement_worker_failed: bool,
}

impl WfpRetirement {
    /// Whether STOP, device I/O, waiting or completion retirement was unconfirmed.
    pub fn has_failure(&self) -> bool {
        !self.stop_confirmed
            || self.stop_error.is_some()
            || self.device_error.is_some()
            || self.wait_failed
            || self.pending_packet.is_some()
            || !self.file_closed
            || self.file_close_error.is_some()
            || self.detached_open
            || self.detached_retirement
            || self.retirement_worker_failed
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum CompletionStop {
    Requested(StopRequest),
    Closing,
    SourceLost(device::Error),
}

impl CompletionStop {
    const fn kind(self) -> io::ErrorKind {
        match self {
            Self::Requested(StopRequest::Cancelled) => io::ErrorKind::Interrupted,
            Self::Requested(StopRequest::Deadline) => io::ErrorKind::TimedOut,
            Self::Closing => io::ErrorKind::NotConnected,
            Self::SourceLost(_) => io::ErrorKind::Other,
        }
    }
}

impl fmt::Display for CompletionStop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested(reason) => write!(f, "{}", reason.fault()),
            Self::Closing => f.write_str("device file closing"),
            Self::SourceLost(error) => write!(f, "device source lost ({error})"),
        }
    }
}

#[derive(Debug)]
pub(super) struct CompletionFailure {
    pub completion: record::Completion,
    pub stop: Option<CompletionStop>,
    pub cancel_error: Option<device::Error>,
}

impl CompletionFailure {
    pub(super) fn into_io(self) -> io::Error {
        let kind = self.stop.map_or(io::ErrorKind::Other, CompletionStop::kind);
        io::Error::new(kind, self)
    }
}

impl fmt::Display for CompletionFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original WFP completion status={:#010x}, authorized={}",
            self.completion.status, self.completion.authorized
        )?;
        if let Some(stop) = self.stop {
            write!(f, ", stop={stop}")?;
        }
        if let Some(error) = &self.cancel_error {
            write!(f, ", revoke error={error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for CompletionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(error) = &self.cancel_error {
            return Some(error);
        }
        match &self.stop {
            Some(CompletionStop::SourceLost(error)) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(super) struct DiscardFailure {
    pub stop: StopRequest,
    pub error: device::Error,
}

impl fmt::Display for DiscardFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original WFP discard after {} failed ({})",
            self.stop.fault(),
            self.error
        )
    }
}

impl std::error::Error for DiscardFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

pub(super) fn device_error(error: device::Error) -> io::Error {
    io::Error::other(error)
}
