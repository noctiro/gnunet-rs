//! Consuming static diagnostics. Numeric token projections cannot grant receipts.
use super::{Error, ProviderReport, Report, cache, dht, revocation};
use gnunet_types::Error as Fault;
use std::{fmt, io, sync::Arc};

/// Same original owned failure with lifetime-bound token fields projected only
/// to diagnostic serials. No token is recreated or promoted to static authority.
#[derive(Debug)]
pub enum OwnedError {
    /// Original protocol/resource category.
    Protocol(Fault),
    /// Original clock category.
    Clock(Fault),
    /// Original shared broker error, including native causes.
    Resolver(gnunet_resolver_broker::BrokerError),
    /// Original owned DNS error and actual spent work.
    Dns(crate::auxiliary::dns::Error),
    /// Original files preparation error retained across every affected effect.
    Registry(Arc<crate::auxiliary::registry::Error>),
    /// Original endpoint/clock/Resolver failure.
    Ports(gnunet_client_host::ConnectError),
    /// Original native connection failure.
    Connect(io::Error),
    /// Original NAMECACHE source loss and exposure.
    CacheLoss {
        /// Diagnostic serial of the original source, never a reconstructed capability.
        epoch: Option<u64>,
        /// Original operations affected by this source observation.
        operations: usize,
        /// Original operations with actual exposure recorded by their owner.
        exposed: usize,
        /// Original owned cause; absence does not imply a remote acknowledgement.
        cause: cache::LossCause,
    },
    /// Original local operation, with its actual physical exposure.
    CacheLocal {
        /// Diagnostic serial of the original operation.
        operation: u64,
        /// Actual local rejection category.
        reason: cache::LocalReason,
        /// Actual original native submission/exposure state.
        submission: cache::Submission,
    },
    /// An actual orphan callback, retaining its raw owned outcome.
    CacheOrphan {
        /// Diagnostic serial of the original operation.
        operation: u64,
        /// Diagnostic serial of the original source, never a reconstructed capability.
        epoch: Option<u64>,
        /// Original wire correlation value, for diagnostics only.
        request_id: u32,
        /// Actual original operation kind.
        kind: cache::Kind,
        /// Actual owned callback outcome.
        outcome: cache::Outcome,
    },
    /// Original dedicated MQ termination and owned cause.
    Revocation {
        /// Diagnostic serial of the original dedicated request.
        job: u64,
        /// Diagnostic serial of the original source, never a reconstructed capability.
        epoch: Option<u64>,
        /// Actual original native submission/exposure state.
        submission: revocation::Submission,
        /// Original owned cause; absence does not imply a remote acknowledgement.
        cause: revocation::Cause,
    },
    /// Original raw status outside its defined interpretation.
    RevocationStatus(u32),
    /// Original DHT source loss and retained usage; no mutation completion.
    DhtLoss {
        /// Diagnostic serial of the original source, never a reconstructed capability.
        epoch: u64,
        /// Original owned cause; absence does not imply a remote acknowledgement.
        cause: dht::LossCause,
        /// Original source-owned retained usage.
        retained: dht::Snapshot,
    },
}
impl Error<'_> {
    /// A genuine endpoint/clock port was fenced. The caller may explicitly
    /// recover those same ports after its Stop/Logger gate, preserving original
    /// operations, deadlines and Unknown mutations. This grants no retry receipt.
    pub fn requires_port_recovery(&self) -> bool {
        matches!(self, Self::Ports(_) | Self::Clock(_) | Self::Resolver(_))
            || matches!(
                self,
                Self::CacheLoss {
                    cause: cache::LossCause::Ports(_),
                    ..
                }
            )
    }
    /// Consume actual causes; erase only the borrowed token's authority. The
    /// returned serial fields are labels, never completion/cancellation proofs.
    pub fn into_owned(self) -> OwnedError {
        match self {
            Self::Protocol(error) => OwnedError::Protocol(error),
            Self::Clock(error) => OwnedError::Clock(error),
            Self::Resolver(error) => OwnedError::Resolver(error),
            Self::Dns(error) => OwnedError::Dns(error),
            Self::Registry(error) => OwnedError::Registry(error),
            Self::Ports(error) => OwnedError::Ports(error),
            Self::Connect(error) => OwnedError::Connect(error),
            Self::CacheLoss { report, cause } => OwnedError::CacheLoss {
                epoch: report.epoch.map(cache::Epoch::diagnostic),
                operations: report.operations,
                exposed: report.exposed,
                cause,
            },
            Self::CacheLocal {
                operation,
                reason,
                submission,
            } => OwnedError::CacheLocal {
                operation: operation.diagnostic(),
                reason,
                submission,
            },
            Self::CacheOrphan(done) => OwnedError::CacheOrphan {
                operation: done.operation.diagnostic(),
                epoch: done.epoch.map(cache::Epoch::diagnostic),
                request_id: done.request_id,
                kind: done.kind,
                outcome: done.outcome,
            },
            Self::Revocation(end) => OwnedError::Revocation {
                job: end.job.diagnostic(),
                epoch: end.epoch.map(revocation::Epoch::diagnostic),
                submission: end.submission,
                cause: end.cause,
            },
            Self::RevocationStatus(status) => OwnedError::RevocationStatus(status),
            Self::DhtLoss {
                epoch,
                cause,
                retained,
            } => OwnedError::DhtLoss {
                epoch: epoch.diagnostic(),
                cause,
                retained,
            },
        }
    }
}
impl fmt::Display for OwnedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "GNS protocol/resource: {error}"),
            Self::Clock(error) => write!(f, "GNS clock: {error}"),
            Self::Resolver(error) => write!(f, "GNS Resolver: {error}"),
            Self::Dns(error) => write!(f, "GNS DNS-only dependency: {error}"),
            Self::Registry(error) => write!(f, "GNS registry dependency: {error}"),
            Self::Ports(error) => write!(f, "GNS dependency ports: {error}"),
            Self::Connect(error) => write!(f, "GNS connection: {error}"),
            Self::CacheLoss { .. } => f.write_str("GNS NAMECACHE source lost"),
            Self::CacheLocal { reason, .. } => {
                write!(f, "GNS NAMECACHE local termination: {reason:?}")
            }
            Self::CacheOrphan { .. } => f.write_str("GNS NAMECACHE orphan callback"),
            Self::Revocation { .. } => f.write_str("GNS revocation MQ ended"),
            Self::RevocationStatus(raw) => write!(f, "GNS revocation raw status {raw}"),
            Self::DhtLoss { .. } => f.write_str("GNS DHT source retired"),
        }
    }
}
impl std::error::Error for OwnedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) | Self::Clock(error) => Some(error),
            Self::Resolver(error) => Some(error),
            Self::Dns(error) => Some(error),
            Self::Registry(error) => Some(error.as_ref()),
            Self::Ports(error) => Some(error),
            Self::Connect(error) => Some(error),
            Self::CacheLoss { cause, .. } => match cause {
                cache::LossCause::Io(error) => Some(error),
                cache::LossCause::Ports(error) => Some(error),
                cache::LossCause::Protocol(error) | cache::LossCause::Resource(error) => {
                    Some(error)
                }
                _ => None,
            },
            Self::Revocation { cause, .. } => match cause {
                revocation::Cause::Io(error) => Some(error),
                revocation::Cause::Ports(error) => Some(error),
                revocation::Cause::Protocol(error) | revocation::Cause::Clock(error) => Some(error),
                _ => None,
            },
            Self::DhtLoss { cause, .. } => match cause {
                dht::LossCause::Io(error) => Some(error),
                dht::LossCause::Protocol(error) | dht::LossCause::Resource(error) => Some(error),
                _ => None,
            },
            _ => None,
        }
    }
}
/// Actual local operation closure, with authority erased after consumption.
#[derive(Debug)]
pub enum OwnedReport {
    /// Real system subscription outcome; shared Driver wire scope stays explicit.
    System(crate::auxiliary::system::SystemReport),
    /// Real DNS sockets and partial byte observations.
    Dns(crate::auxiliary::dns::DnsReport),
    /// Real files-profile lookup.
    Registry {
        /// Actual prepared protocol/service mapping, or no match.
        mapping: Option<(u16, u16)>,
    },
    /// Actual NAMECACHE operation facts.
    Cache {
        /// Diagnostic serial of the original operation.
        operation: u64,
        /// Original wire correlation value, for diagnostics only.
        request_id: u32,
        /// Actual original operation kind.
        kind: cache::Kind,
        /// Diagnostic serial of the original source, never a reconstructed capability.
        epoch: Option<u64>,
        /// Actual original native submission/exposure state.
        submission: cache::Submission,
        /// Actual raw original status.
        status: Option<i32>,
        /// Whether the actual lookup callback was observed.
        lookup_reply: bool,
        /// Actual local original termination category.
        local: Option<cache::LocalReason>,
        /// Actual original cancellation observation.
        cancellation: Option<cache::Cancellation>,
    },
    /// Actual GET retirement; diagnostic IDs are not source capabilities.
    Remote {
        /// Diagnostic serial of the original GET.
        get: u64,
        /// Diagnostic serial of the original source, never a reconstructed capability.
        epoch: Option<u64>,
        /// Actual original cancellation observation.
        cancellation: Option<dht::Cancel>,
        /// Actual original GET retirement boundary.
        end: Option<OwnedRemoteEnd>,
        /// Actual candidates observed by this GET.
        candidates: u64,
    },
    /// Actual dedicated QUERY MQ.
    Revocation {
        /// Diagnostic serial of the original dedicated request.
        job: Option<u64>,
        /// Diagnostic serial of the original source, never a reconstructed capability.
        epoch: Option<u64>,
        /// Actual original native submission/exposure state.
        submission: Option<revocation::Submission>,
        /// Actual original REVOCATION response, if one arrived.
        response: Option<revocation::ipc::Response>,
        /// True only for the reported owner's actual local retirement scope.
        closed: bool,
        /// Actual original dedicated-MQ termination.
        native_end: Option<OwnedRevocationEnd>,
        /// First original connection failure, without string conversion.
        first_connect_error: Option<io::Error>,
        /// Actual connection-failure count; later causes are explicitly bounded.
        connect_failures: u64,
    },
}
/// Actual terminal reason projected from an already consumed native report.
#[derive(Clone, Copy, Debug)]
pub enum OwnedRemoteEnd {
    /// The original GET was retired before issue.
    BeforeIssue,
    /// The actual original STOP frame was wholly written.
    StopWritten(u64),
    /// The actual original MQ was lost.
    SourceLost(u64),
    /// The original shared provider was physically closed.
    ProviderClosed,
}
/// Same actual administrative close/cancel result and owned cause.
#[derive(Debug)]
pub struct OwnedRevocationEnd {
    /// Diagnostic serial of the original dedicated request.
    pub job: u64,
    /// Diagnostic serial of the original source, never a reconstructed capability.
    pub epoch: Option<u64>,
    /// Actual original native submission/exposure state.
    pub submission: revocation::Submission,
    /// Original owned cause; absence does not imply a remote acknowledgement.
    pub cause: revocation::Cause,
}
impl Report<'_> {
    /// Consume a real report. This method grants no additional terminal fact.
    pub fn into_owned(self) -> OwnedReport {
        match self {
            Self::System(report) => OwnedReport::System(report),
            Self::Dns(report) => OwnedReport::Dns(report),
            Self::Registry { mapping } => OwnedReport::Registry { mapping },
            Self::Cache(report) => OwnedReport::Cache {
                operation: report.operation.diagnostic(),
                request_id: report.request_id,
                kind: report.kind,
                epoch: report.epoch.map(cache::Epoch::diagnostic),
                submission: report.submission,
                status: report.status,
                lookup_reply: report.lookup_reply,
                local: report.local,
                cancellation: report.cancellation,
            },
            Self::Remote(report) => OwnedReport::Remote {
                get: report.get.diagnostic(),
                epoch: report.epoch.map(dht::Epoch::diagnostic),
                cancellation: report.cancellation,
                end: report.end.map(|end| match end {
                    super::RemoteEnd::BeforeIssue => OwnedRemoteEnd::BeforeIssue,
                    super::RemoteEnd::StopWritten(epoch) => {
                        OwnedRemoteEnd::StopWritten(epoch.diagnostic())
                    }
                    super::RemoteEnd::SourceLost(epoch) => {
                        OwnedRemoteEnd::SourceLost(epoch.diagnostic())
                    }
                    super::RemoteEnd::ProviderClosed => OwnedRemoteEnd::ProviderClosed,
                }),
                candidates: report.candidates,
            },
            Self::Revocation(report) => OwnedReport::Revocation {
                job: report.job.map(revocation::Job::diagnostic),
                epoch: report.epoch.map(revocation::Epoch::diagnostic),
                submission: report.submission,
                response: report.response,
                closed: report.closed,
                native_end: report.native_end.map(|end| OwnedRevocationEnd {
                    job: end.job.diagnostic(),
                    epoch: end.epoch.map(revocation::Epoch::diagnostic),
                    submission: end.submission,
                    cause: end.cause,
                }),
                first_connect_error: report.first_connect_error,
                connect_failures: report.connect_failures,
            },
        }
    }
}
/// Shared physical scope only; final broker retirement is separate.
#[derive(Clone, Copy, Debug)]
pub struct OwnedProviderReport {
    /// Original physically closed NAMECACHE source, projected for diagnostics.
    pub cache_epoch: Option<u64>,
    /// Actual operations in that original close report.
    pub cache_operations: Option<usize>,
    /// Actual exposed operations in that original close report.
    pub cache_exposed: Option<usize>,
    /// Original physically closed DHT source, projected for diagnostics.
    pub dht_epoch: Option<u64>,
    /// Actual retained DHT usage at physical close.
    pub dht_snapshot: Option<dht::Snapshot>,
    /// Original NAMECACHE operation report rows still retained.
    pub cache_rows: usize,
    /// Original DHT operation report rows still retained.
    pub dht_rows: usize,
    /// True only for the reported owner's actual local retirement scope.
    pub closed: bool,
}
impl ProviderReport<'_> {
    /// Consume source observations without promoting a lifetime-bound token.
    pub fn into_owned(self) -> OwnedProviderReport {
        OwnedProviderReport {
            cache_epoch: self
                .cache_close
                .and_then(|report| report.epoch)
                .map(cache::Epoch::diagnostic),
            cache_operations: self.cache_close.map(|report| report.operations),
            cache_exposed: self.cache_close.map(|report| report.exposed),
            dht_epoch: self.dht_close.map(|(epoch, _)| epoch.diagnostic()),
            dht_snapshot: self.dht_close.map(|(_, snapshot)| snapshot),
            cache_rows: self.cache_rows,
            dht_rows: self.dht_rows,
            closed: self.closed,
        }
    }
}
