//! Public bounded burst policy, observed facts and independent failures.
use super::{Endian, Error, PeerId, Publication, local_order, native};
use std::time::Duration;
/// Local finite resource/ABI choices; no private protocol negotiation.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Whole original command lifetime, positive and at most the official60s.
    pub lifetime: Duration,
    /// Existing public utility descriptor, pacing and I/O bounds.
    pub scan: native::Limits,
    /// Explicit ABI of received native unsigned probe fields. Selection uses
    /// actual recvfrom endpoints, never this unauthenticated advertised port.
    pub remote_order: Endian,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            lifetime: Duration::from_secs(60),
            scan: native::Limits::default(),
            remote_order: local_order(),
        }
    }
}
/// Candidate admission failed before any queue or completion was published.
#[derive(Debug)]
pub enum Refusal {
    /// Original local protocol, capacity or deadline refusal.
    Protocol(Error),
    /// Original preparation failure on the newly selected scan socket.
    Socket(super::SocketError),
    /// Original address-classification provider failure for this candidate.
    Classification(std::io::Error),
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Refusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Protocol(e) => e,
            Self::Socket(e) => e,
            Self::Classification(e) => e,
        })
    }
}
/// Mutually exclusive original outcomes; a selection never proves authentication.
#[derive(Debug)]
pub enum Outcome {
    /// No utility owner was created before cancellation or native expiry.
    NotStarted(Error),
    /// Utility construction refused before producing a native owner.
    Preparation(native::Error),
    /// Original utility end and counters, independently of an outer interruption.
    Stopped {
        /// Actual original utility terminal cause.
        cause: native::Cause,
        /// Actual original utility counters.
        scan: native::Report,
        /// Outer cancellation/deadline, if independently observed.
        interrupted: Option<Error>,
    },
    /// A real selected socket was retired before candidate publication.
    Rejected {
        /// Actual original utility counters through selection.
        scan: native::Report,
        /// Original pre-publication refusal.
        reason: Refusal,
    },
    /// A selected socket became a candidate and queued the original 1254.
    Installed {
        /// Actual original utility counters through selection.
        scan: native::Report,
        /// Original MQ publication; enqueue is not a whole-write receipt.
        completion: Publication,
    },
    /// The consumed utility returned no terminal receipt. No successful stop,
    /// selection or cancellation is inferred from releasing its Rust owner.
    Unobserved {
        /// Last actual utility counters before consumption.
        scan: native::Report,
        /// Original outer interruption, if observed.
        interrupted: Option<Error>,
    },
}
/// Original local facts, without remote processing or authenticated reachability.
#[derive(Debug)]
pub struct Report {
    /// Original serial, scoped to this communicator/MQ.
    pub serial: u64,
    /// Original requested public peer, independent of probe assertions.
    pub peer: PeerId,
    /// Original finite RTT argument.
    pub rtt_us: u64,
    /// Exact terminal state and its associated receipts/owners.
    pub outcome: Outcome,
    /// Non-probe datagrams consumed before selecting a scan socket.
    pub ignored_scan_datagrams: u64,
}
impl Report {
    /// Actual counters; zero when utility construction never produced an owner.
    pub fn scan(&self) -> native::Report {
        match &self.outcome {
            Outcome::NotStarted(_) | Outcome::Preparation(_) => native::Report::default(),
            Outcome::Stopped { scan, .. }
            | Outcome::Rejected { scan, .. }
            | Outcome::Installed { scan, .. }
            | Outcome::Unobserved { scan, .. } => *scan,
        }
    }
    /// Whether a candidate, rather than an authenticated connection, was installed.
    pub fn candidate_installed(&self) -> bool {
        matches!(self.outcome, Outcome::Installed { .. })
    }
    /// Original 1254 publication, present only for an installed candidate.
    pub fn completion(&self) -> Option<&Publication> {
        match &self.outcome {
            Outcome::Installed { completion, .. } => Some(completion),
            _ => None,
        }
    }
    fn original_error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.outcome {
            Outcome::NotStarted(e) => Some(e),
            Outcome::Preparation(e) => Some(e),
            Outcome::Stopped {
                cause: native::Cause::Clock(e),
                ..
            } => Some(e),
            Outcome::Stopped {
                cause: native::Cause::Io { error, .. },
                ..
            } => Some(error),
            Outcome::Stopped { interrupted, .. } => interrupted.as_ref().map(|e| e as _),
            Outcome::Rejected { reason, .. } => Some(reason),
            Outcome::Unobserved { .. } => Some(&Error::OutcomeUnknown),
            Outcome::Installed { .. } => None,
        }
    }
}
/// Original fatal utility failure; ordinary per-attempt stops remain reports.
#[derive(Debug)]
pub struct Failure {
    /// Original scope and terminal observations.
    pub report: Report,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UDP original burst: {:?}", self.report)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.report.original_error()
    }
}
