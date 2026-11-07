use super::{cache, dht, revocation};
use crate::NativeFailure;
use gnunet_client_host::ConnectError;
use gnunet_types::Error as Fault;
use std::{fmt, io, sync::Arc};

/// Actual failure, retaining native causes and original-source metadata.
#[derive(Debug)]
pub enum Error<'id> {
    /// Local protocol/resource/closed state.
    Protocol(Fault),
    /// Exact canonical clock refusal.
    Clock(Fault),
    /// Actual shared Resolver query/cleanup failure.
    Resolver(gnunet_resolver_broker::BrokerError),
    /// Actual DNS-only operation failure.
    Dns(crate::auxiliary::dns::Error),
    /// Original unavailable protocol/service files, not a successful no-match.
    Registry(Arc<crate::auxiliary::registry::Error>),
    /// Original endpoint/clock/Resolver/native CLIENT refusal.
    Ports(ConnectError),
    /// An actual preattachment connection attempt failed.
    Connect(io::Error),
    /// Original NAMECACHE source physically ended. Exposed mutations stay unknown.
    CacheLoss {
        /// Actual original NAMECACHE loss report.
        report: cache::Loss<'id>,
        /// Actual original physical source loss cause.
        cause: cache::LossCause,
    },
    /// Original NAMECACHE operation ended without a normal result.
    CacheLocal {
        /// Exact original NAMECACHE operation.
        operation: cache::Operation<'id>,
        /// Original local terminal reason.
        reason: cache::LocalReason,
        /// Actual exposure of this original operation.
        submission: cache::Submission,
    },
    /// Actual terminal NAMECACHE callback without its expected local row.
    /// Keep its original token/outcome instead of discarding the fact.
    CacheOrphan(cache::Completion<'id>),
    /// Original one-shot revocation MQ physically ended.
    Revocation(revocation::End<'id>),
    /// Actual raw query status had no defined revoked/valid interpretation.
    RevocationStatus(u32),
    /// Actual original DHT source retired; read intents may resume under their
    /// same GetId and original budgets, never as an already completed callback.
    DhtLoss {
        /// Original DHT source that retired.
        epoch: dht::Epoch<'id>,
        /// Actual original physical source loss cause.
        cause: dht::LossCause,
        /// Actual logical client state retained after source loss.
        retained: dht::Snapshot,
    },
}
impl fmt::Display for Error<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(f, "GNS dependency: {error}"),
            Self::Clock(error) => write!(f, "GNS dependency clock: {error}"),
            Self::Resolver(error) => write!(f, "GNS shared Resolver: {error}"),
            Self::Dns(error) => write!(f, "GNS DNS-only dependency: {error}"),
            Self::Registry(error) => write!(f, "GNS registry dependency: {error}"),
            Self::Ports(error) => write!(f, "GNS dependency ports: {error}"),
            Self::Connect(error) => write!(f, "GNS dependency connection: {error}"),
            Self::CacheLoss { .. } => f.write_str("GNS NAMECACHE source lost"),
            Self::CacheLocal { reason, .. } => {
                write!(f, "GNS NAMECACHE local termination: {reason:?}")
            }
            Self::CacheOrphan(_) => f.write_str("GNS NAMECACHE callback lost local row"),
            Self::Revocation(_) => f.write_str("GNS revocation source ended"),
            Self::RevocationStatus(raw) => write!(f, "GNS revocation query status {raw}"),
            Self::DhtLoss { .. } => f.write_str("GNS DHT source retired"),
        }
    }
}
impl std::error::Error for Error<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Clock(error) => Some(error),
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
            Self::Revocation(end) => match &end.cause {
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
impl NativeFailure for Error<'_> {
    fn reason(&self) -> Fault {
        match self {
            Self::Protocol(error) | Self::Clock(error) => *error,
            Self::Resolver(gnunet_resolver_broker::BrokerError::Core(error)) => *error,
            Self::Resolver(_) => Fault::Io,
            Self::Dns(error) => error.reason(),
            Self::Registry(error) => match error.as_ref() {
                crate::auxiliary::registry::Error::Protocol(error) => *error,
                crate::auxiliary::registry::Error::Io(_) => Fault::Io,
            },
            Self::Ports(ConnectError::Protocol(error)) => *error,
            Self::Ports(ConnectError::Configuration(_)) => Fault::InvalidInput,
            Self::Ports(ConnectError::Io(_)) | Self::Connect(_) => Fault::Io,
            Self::CacheLocal { reason, .. } => match reason {
                cache::LocalReason::Deadline => Fault::Timeout,
                cache::LocalReason::Cancelled => Fault::Cancelled,
                cache::LocalReason::Closed => Fault::Closed,
                cache::LocalReason::Lost => Fault::Io,
            },
            Self::Revocation(end) => match &end.cause {
                revocation::Cause::Deadline | revocation::Cause::SendDeadline => Fault::Timeout,
                revocation::Cause::Cancelled => Fault::Cancelled,
                revocation::Cause::Closed => Fault::Closed,
                revocation::Cause::Protocol(error) | revocation::Cause::Clock(error) => *error,
                _ => Fault::Io,
            },
            Self::CacheLoss { .. } | Self::DhtLoss { .. } => Fault::Io,
            Self::RevocationStatus(_) => Fault::Malformed,
            Self::CacheOrphan(_) => Fault::Stale,
        }
    }
    fn spent(&self) -> u32 {
        match self {
            Self::Dns(error) => error.spent(),
            _ => 0,
        }
    }
}
impl From<Fault> for Error<'_> {
    fn from(error: Fault) -> Self {
        Self::Protocol(error)
    }
}
impl From<ConnectError> for Error<'_> {
    fn from(error: ConnectError) -> Self {
        Self::Ports(error)
    }
}

/// Original NAMECACHE operation facts, independent of business completion.
#[derive(Debug)]
pub struct CacheReport<'id> {
    /// Original opaque operation.
    pub operation: cache::Operation<'id>,
    /// Actual original official RID.
    pub request_id: u32,
    /// Actual request kind.
    pub kind: cache::Kind,
    /// Source actually associated with this operation, if any.
    pub epoch: Option<cache::Epoch<'id>>,
    /// Observed original byte exposure, not a storage acknowledgement.
    pub submission: cache::Submission,
    /// Raw actual CACHE acknowledgement, including refusal.
    pub status: Option<i32>,
    /// Actual normal LOOKUP reply was consumed, including an explicit miss.
    pub lookup_reply: bool,
    /// Actual local terminal reason, if any.
    pub local: Option<cache::LocalReason>,
    /// Actual callback suppression/drain decision.
    pub cancellation: Option<cache::Cancellation>,
}
/// Original persistent GET retirement, not remote cancellation acknowledgement.
#[derive(Clone, Copy, Debug)]
pub enum RemoteEnd<'id> {
    /// Original intent never had physical wire authority.
    BeforeIssue,
    /// The original official STOP frame actually wrote in full.
    StopWritten(dht::Epoch<'id>),
    /// Original MQ actually ended; canceled intent is not reconstructed.
    SourceLost(dht::Epoch<'id>),
    /// Explicit permanent provider close physically retired original MQ.
    ProviderClosed,
}
/// Original GET facts.
#[derive(Debug)]
pub struct RemoteReport<'id> {
    /// Same original client GET, across any safe read reconnect.
    pub get: dht::GetId<'id>,
    /// Last actual source carrying this GET or callback.
    pub epoch: Option<dht::Epoch<'id>>,
    /// Actual local stop decision.
    pub cancellation: Option<dht::Cancel>,
    /// Real native retirement fact.
    pub end: Option<RemoteEnd<'id>>,
    /// Number of complete candidate payloads actually passed to the resolver.
    pub candidates: u64,
}
/// Original one-shot revocation facts. The actual failure, if any, is separately
/// owned by its Failed/GuardFailed event, not converted into successful status.
#[derive(Debug, Default)]
pub struct RevocationReport<'id> {
    /// Original job, if observed through queue/reply/close.
    pub job: Option<revocation::Job<'id>>,
    /// Actually attached source.
    pub epoch: Option<revocation::Epoch<'id>>,
    /// Actual local exposure.
    pub submission: Option<revocation::Submission>,
    /// Actual raw service response.
    pub response: Option<revocation::ipc::Response>,
    /// Actual dedicated MQ was physically retired.
    pub closed: bool,
    /// Actual administrative close/cancel result when it is not a failure event.
    pub native_end: Option<revocation::End<'id>>,
    /// First actual transient connect error; later attempts are counted.
    pub first_connect_error: Option<io::Error>,
    /// Actual transient connect failures, saturating rather than allocating a log.
    pub connect_failures: u64,
}
/// Actual per-operation retirement. Shared source failures are separate events.
#[derive(Debug)]
pub enum Report<'id> {
    /// Actual shared Resolver callback subscription, not shared wire retirement.
    System(crate::auxiliary::system::SystemReport),
    /// Actual owned DNS socket IO and retirement.
    Dns(crate::auxiliary::dns::DnsReport),
    /// Actual prepared files registry lookup; None preserves literal SBOX.
    Registry {
        /// Actual protocol number and service port, or no matching entry.
        mapping: Option<(u16, u16)>,
    },
    /// Retired original NAMECACHE row.
    Cache(CacheReport<'id>),
    /// Retired original DHT GET.
    Remote(RemoteReport<'id>),
    /// Retired original revocation MQ.
    Revocation(RevocationReport<'id>),
}
