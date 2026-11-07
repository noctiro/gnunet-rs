use crate::{core, identity, namestore};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{fmt, io, net::SocketAddr, sync::Arc};

/// Explicit original endpoint selection and same process clock.
pub struct Ports {
    /// Actual configured IDENTITY endpoint using the caller's shared Resolver.
    pub identity: identity::EndpointSource,
    /// Actual configured NAMESTORE endpoint using that same Resolver.
    pub namestore: namestore::EndpointSource,
    /// Exact same original shared RuntimeClock supplied to both endpoints.
    pub clock: Arc<dyn RuntimeClock>,
}
/// Caller-owned source domains. They outlive every actual borrowed client.
pub struct Instances<'id> {
    /// Original IDENTITY source/operation allocation domain.
    pub identity: &'id identity::Instance,
    /// Original NAMESTORE source/operation/iterator allocation domain.
    pub namestore: &'id namestore::Instance,
}
/// Fixed native limits. Public metadata admission limits/policy live in Core.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual simultaneous raw UDP DNS requests, at most64.
    pub dns_requests: usize,
    /// Concurrent TCP fallbacks, at most16, under the original query bounds.
    pub tcp_requests: usize,
    /// Complete DNS datagram/TCP response length, 12..=65535.
    pub response_bytes: usize,
    /// Actual syscall quantum.
    pub io_bytes: usize,
    /// Existing complete DNS parser arena, including expanded compressed names.
    pub dns_arena_bytes: usize,
    /// Total section-record slots in one complete response.
    pub dns_records: usize,
    /// Actual bounded IDENTITY source policy, with same-owner reconnect by default.
    pub identity: identity::Limits,
    /// Actual bounded NAMESTORE source policy, with same-owner reconnect by default.
    pub namestore: namestore::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            dns_requests: 64,
            tcp_requests: 4,
            response_bytes: 65535,
            io_bytes: 8192,
            dns_arena_bytes: 4 * 1024 * 1024,
            dns_records: 8192,
            identity: identity::Limits {
                operations: 1,
                egos: 4096,
                reconnect: true,
                ..identity::Limits::default()
            },
            namestore: namestore::Limits {
                operations: 32,
                reconnect: true,
                ..namestore::Limits::default()
            },
        }
    }
}
impl Limits {
    pub(crate) fn validate(self) -> Result<(), Fault> {
        if self.dns_requests == 0
            || self.dns_requests > 64
            || self.tcp_requests == 0
            || self.tcp_requests > 16
            || self.tcp_requests > self.dns_requests
            || !(12..=65535).contains(&self.response_bytes)
            || self.io_bytes == 0
            || self.dns_arena_bytes == 0
            || self.dns_arena_bytes > 16 * 1024 * 1024
            || self.dns_records == 0
            || self.dns_records > 8192
        {
            return Err(Fault::InvalidInput);
        }
        Ok(())
    }
}
/// Actual endpoint, parser or native error; never a successful empty DNS answer.
#[derive(Debug)]
pub enum Error {
    /// Only the allocation-free original input IDNA/name-shape check failed.
    /// Allocator, clock, Core capacity and native failures never use this variant.
    InvalidName(Fault),
    /// Original public business/resource classification.
    Core(Fault),
    /// Actual original IDENTITY client cause.
    Identity(identity::Error),
    /// Actual original NAMESTORE client cause.
    Namestore(namestore::Error),
    /// Original raw DNS host/entropy failure.
    Dns(gnunet_dnsstub_host::HostError),
    /// Actual ordinary IO cause.
    Io(io::Error),
    /// An original source/query association still had invalid DNS content.
    Conversion(core::conversion::Failure),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zoneimport: {self:?}")
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Identity(error) | Self::Namestore(error) => Some(error),
            Self::Dns(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Conversion(error) => Some(error),
            Self::Core(_) | Self::InvalidName(_) => None,
        }
    }
}
impl From<Fault> for Error {
    fn from(error: Fault) -> Self {
        Self::Core(error)
    }
}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(error: gnunet_client_host::ConnectError) -> Self {
        Self::Namestore(error)
    }
}
/// Redacted original source retirement metadata. Numeric IDs are diagnostics,
/// not constructors for any future source, job or commit authority.
#[derive(Clone, Copy, Debug)]
pub struct Loss {
    /// Actual source epoch's diagnostic allocation when it had attached.
    pub epoch: Option<u64>,
    /// Actual original operations closed.
    pub operations: usize,
    /// Operations with actual positive native exposure.
    pub exposed: usize,
}
/// A real original source loss cause, held independently from business status.
#[derive(Debug)]
pub enum SourceFailure {
    /// Original IDENTITY monitor/operation source.
    Identity(identity::LossCause),
    /// Original shared NAMESTORE request source.
    Namestore(namestore::LossCause),
    /// Original dedicated iterator source.
    Iterator(namestore::LossCause),
}
/// Real original mutation byte exposure; neither whole write nor zero known
/// bytes grants a service result or a remote rollback receipt.
#[derive(Clone, Copy, Debug)]
pub enum Exposure {
    /// Actual original source confirmed no byte was exposed.
    Unsent,
    /// Positive original immutable prefix.
    Partial {
        /// Actual positive prefix written on this original operation.
        bytes: usize,
        /// Original immutable frame length.
        total: usize,
    },
    /// Actual complete local frame wrote, without a business result claim.
    Whole {
        /// Actual complete frame length written locally.
        bytes: usize,
    },
}
/// Attribution retained when a cleanup bound expires or a terminal Core
/// invariant fails. Diagnostic integers cannot mint a replacement operation.
#[derive(Clone, Copy, Debug)]
pub struct Remaining {
    /// Original Core diagnostic job allocation.
    pub job: u64,
    /// Original operation semantics.
    pub kind: core::Kind,
    /// Original fixed logical and monotonic bounds.
    pub bounds: core::Bounds,
    /// Original attached endpoint epoch, when known.
    pub epoch: Option<u64>,
    /// Actual exposure observed from this same operation.
    pub exposure: Exposure,
    /// A native terminal was consumed but Core could not apply it.
    pub terminal_observed: bool,
}
/// A real native local terminal, independent from a business/source cause.
#[derive(Debug)]
pub enum LocalOutcome {
    /// Original IDENTITY completion with its actual exposure and late status.
    Identity {
        /// Original Core diagnostic allocation, not an authority constructor.
        job: u64,
        /// Actual original local IDENTITY termination reason.
        reason: identity::LocalReason,
        /// Actual original immutable IDENTITY frame exposure.
        submission: identity::Submission,
        /// Actual late ordered service status, when one was received.
        result_code: Option<u32>,
    },
    /// Original NAMESTORE completion; exposure never implies commit/rollback.
    Namestore {
        /// Original Core diagnostic allocation, not an authority constructor.
        job: u64,
        /// Actual original local NAMESTORE termination reason.
        reason: namestore::LocalReason,
        /// Actual original immutable NAMESTORE frame exposure.
        submission: namestore::Submission,
    },
    /// Actual negative signed LOOKUP response, never treated as empty data.
    Lookup {
        /// Original Core diagnostic job.
        job: u64,
        /// Actual signed service result, including a backend failure.
        found: i16,
    },
}
/// Actual finite owner cleanup report. Core stop alone is not native quiescence.
#[derive(Debug, Default)]
pub struct Report {
    /// Original IDENTITY source stop, when that physical owner existed.
    pub identity: Option<Loss>,
    /// Original general NAMESTORE source stop.
    pub namestore: Option<Loss>,
    /// Actual dedicated iterator sources closed.
    pub iterators_closed: usize,
    /// Actual raw DNS requests/socket caches at stop.
    pub dns: Option<gnunet_dnsstub_host::Stopped>,
    /// Actual original TCP fallbacks physically dropped.
    pub tcp_closed: usize,
    /// Actual native terminal observations consumed.
    pub completed: u64,
    /// Prior failed input names plus actual terminal service rejections and
    /// uncertainty observed through retirement. Normal unsent cancellation does
    /// not count as business failure. Zero does not claim all imports stored.
    pub name_failures: core::NameFailures,
    /// Business owner reports all original jobs retired.
    pub core_quiescent: bool,
    /// A real native terminal could not be applied to its original Core job.
    pub invariant_stalled: bool,
    /// Actual owned payload loans released.
    pub payloads_remaining: usize,
    /// Legal inventory names that are not usable DNS-domain candidates.
    pub ignored_identities: u64,
    /// Real recoverable UDP IO errors retained independently of business results.
    pub native_errors: [Option<io::Error>; 4],
    /// Further actual errors beyond the fixed retained diagnostic slots.
    pub additional_native_errors: u64,
    /// Actual original source causes, never replaced by an empty query result.
    pub source_errors: [Option<SourceFailure>; 8],
    /// Further source failures beyond the bounded diagnostic retention.
    pub additional_source_errors: u64,
    /// Original partial NEXT/STOP exposure observed while closing an iterator.
    pub iterator_controls_exposed: usize,
    /// Original unresolved native-to-Core attributions, bounded by Core jobs.
    pub remaining: Vec<Remaining>,
    /// Original local terminal facts, retained separately from source causes.
    pub local_outcomes: [Option<LocalOutcome>; 8],
    /// Explicit count beyond the finite local diagnostic retention slots.
    pub additional_local_outcomes: u64,
}
/// One actual caller-driven turn; Activity never means DNS or STORE success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Real original metadata/IO/callback work progressed.
    Activity,
    /// Initial actual inventory has ended; all configured import work is active.
    Initialized,
    /// All original native sources and original job/payload debts have retired.
    Closed,
}
/// Metadata-only original runtime observations, with no DNS/record/key payload.
#[derive(Clone, Copy, Debug)]
pub enum Event<'a> {
    /// Original actual raw-DNS IO cause; never the full response payload.
    Io {
        /// Original Core allocation when associated with a raw request.
        job: Option<u64>,
        /// Borrowed original native cause, without request payload.
        cause: &'a io::Error,
    },
    /// An unrelated actual inventory name was not a valid DNS-domain candidate.
    IgnoredIdentity,
    /// One original task was actually admitted to the named native port.
    Admitted {
        /// Original Core diagnostic allocation.
        job: u64,
        /// Actual admitted operation kind.
        kind: core::Kind,
    },
    /// Real DNS response metadata was rejected, not an empty set.
    DnsRejected {
        /// Original Core diagnostic allocation, not an authority constructor.
        job: u64,
        /// Actual complete inspector/converter rejection.
        reason: core::conversion::Failure,
    },
    /// Original validated TC initiated same-task TCP fallback.
    TcpFallback {
        /// Original Core query, unchanged across UDP and TCP.
        job: u64,
        /// Actual validated TC datagram's original upstream.
        server: SocketAddr,
    },
    /// An actual original service completion was consumed.
    Result {
        /// Original Core diagnostic allocation, not an authority constructor.
        job: u64,
        /// Original operation semantics.
        kind: core::Kind,
        /// Actual service code when available; absence is not success.
        code: Option<u32>,
    },
    /// A read was really given up after its configured bounded attempts.
    ReadFailed {
        /// Original Core diagnostic allocation.
        job: u64,
        /// Actual attempt failure; exhausted retries are a separate Core fact.
        reason: core::ReadFailure,
    },
    /// Actual finite budget expired; no timeout is a remote result.
    Deadline {
        /// Original Core diagnostic allocation.
        job: u64,
        /// Original bounded operation semantics.
        kind: core::Kind,
    },
}
