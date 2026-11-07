use gnunet_reclaim::business;
use gnunet_service_runtime::{
    accepted::SocketEvent,
    clock::RuntimeClock,
    credentials::UnixAccess,
    service::{PeerAddress, ServiceOptions},
};
use gnunet_types::Error as Fault;
use std::{io, rc::Rc, sync::Arc, time::Duration};
/// Original source/runtime failure, without request/key/record bytes.
#[derive(Debug)]
pub enum Error {
    /// Invalid native/core state or bounded-resource refusal.
    Protocol(Fault),
    /// Actual socket/OS failure.
    Io(io::Error),
    /// Actual process clock failure.
    Clock(Fault),
    /// Actual production CLIENT/provider boundary failure.
    Provider(gnunet_client_host::ConnectError),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "RECLAIM protocol: {e}"),
            Self::Io(e) => e.fmt(f),
            Self::Clock(e) => write!(f, "RECLAIM clock: {e}"),
            Self::Provider(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Provider(e)
    }
}
pub(super) struct Domain {
    pub _private: u8,
}
/// Private generational original accepted-MQ identity; no wire field is added.
#[derive(Clone)]
pub struct Client {
    pub(super) domain: Rc<Domain>,
    pub(super) serial: u64,
}
impl PartialEq for Client {
    fn eq(&self, o: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &o.domain) && self.serial == o.serial
    }
}
impl Eq for Client {}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ReclaimClient").field(&self.serial).finish()
    }
}
impl Client {
    /// Diagnostic value only, not an authority constructor or wire RID.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.serial
    }
}
/// Explicit actual runtime/dependency sources. All three clocks must be the same
/// original Arc; no hidden Resolver or per-request broker is created.
pub struct Ports {
    /// Canonical SERVICE/ACL/shutdown policy.
    pub options: ServiceOptions,
    /// Kernel Unix credential rule.
    pub unix: UnixAccess,
    /// Shared clock.
    pub clock: Arc<dyn RuntimeClock>,
    /// Real configured NAMESTORE CLIENT endpoint.
    pub namestore: gnunet_client_host::EndpointSource,
    /// Real configured GNS CLIENT endpoint.
    pub gns: gnunet_client_host::EndpointSource,
}
/// Native metadata, original FIFO/frame and independent finite lifetime bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Accepted sources.
    pub clients: usize,
    /// Live business jobs including retired-client provider debt.
    pub operations: usize,
    /// Jobs admitted per original app MQ.
    pub per_client: usize,
    /// Complete official frame maximum.
    pub frame_bytes: usize,
    /// One actual syscall quantum.
    pub io_slice_bytes: usize,
    /// First input from accepted native source.
    pub first_input: Duration,
    /// One complete original input, including capacity wait.
    pub input_lifetime: Duration,
    /// Oldest actual queued/prepared output age.
    pub output_lifetime: Duration,
    /// Original entire business operation/iterator TTL.
    pub operation_lifetime: Duration,
    /// Original cancellation/deadline native drain, never renewed.
    pub retirement_grace: Duration,
    /// Explicit GNS service lookup policy bits.
    pub gns_options: u16,
    /// Actual GNS recursion depth.
    pub gns_recursion: u16,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 16,
            operations: 32,
            per_client: 8,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            first_input: Duration::from_secs(30),
            input_lifetime: Duration::from_secs(30),
            output_lifetime: Duration::from_secs(30),
            operation_lifetime: Duration::from_secs(180),
            retirement_grace: Duration::from_secs(5),
            gns_options: 0,
            gns_recursion: 128,
        }
    }
}
/// Actual per-source close cause, never a successful business reply.
#[derive(Debug)]
pub enum CloseCause {
    /// Actual EOF.
    Eof,
    /// Actual native failure.
    Io(io::Error),
    /// Malformed/source/RID violation.
    Protocol(Fault),
    /// Explicit resource refusal prevents same-MQ ordered deadlock.
    Capacity,
    /// Original finite native/logical budget elapsed.
    Deadline,
    /// Original provider failed without an error reply field.
    Provider(business::End),
    /// Service shutdown/physical retirement.
    Shutdown,
}
/// Exact actual native dependency loss cause, preserving the production SDK's
/// original IO/protocol/port or local-retirement classification.
#[derive(Debug)]
pub enum LostCause {
    /// Actual NAMESTORE source cause.
    Namestore(gnunet_namestore_client_host::LossCause),
    /// Actual GNS source cause.
    Gns(gnunet_gns_client_host::LossCause),
}
/// Bounded nonsecret observations. No frame/key/capability/record value is logged.
#[derive(Debug)]
pub enum Event {
    /// Shared canonical accept/EMFILE observation.
    Socket(SocketEvent),
    /// ACL/kernel credential rejection.
    Rejected(PeerAddress),
    /// Actual app MQ accepted.
    Accepted(Client),
    /// Original app MQ physically retired first.
    Closed {
        /// Original source.
        client: Client,
        /// Actual cause.
        cause: CloseCause,
    },
    /// Actual dependency attachment, not an authenticated remote identity.
    Connected {
        /// Provider kind.
        provider: business::Provider,
        /// Original local core source allocation.
        source: u64,
    },
    /// Actual original provider operation admitted.
    Submitted {
        /// Diagnostic original job.
        job: u64,
        /// Actual provider.
        provider: business::Provider,
    },
    /// Actual original provider result/retirement, not publication proof.
    ProviderResult {
        /// Original job.
        job: u64,
        /// Actual current aggregate status, no private payload.
        status: business::Status,
    },
    /// Original bounded result frame queued.
    Queued {
        /// Original app source.
        client: Client,
        /// Official original RID.
        rid: u32,
    },
    /// Original immutable whole response wrote locally.
    Written {
        /// Original app source.
        client: Client,
        /// Original RID.
        rid: u32,
    },
    /// Original actual response exposure retained after physical app-source loss.
    OutputRetired {
        /// Original source.
        client: Client,
        /// Original job diagnostic.
        job: u64,
        /// Original wire RID.
        rid: u32,
        /// Actual original local bytes, not remote consumption.
        exposure: business::Exposure,
    },
    /// Actual selected endpoint unavailable, no fake empty result.
    Unavailable {
        /// Actual selected provider.
        provider: business::Provider,
        /// Original actual endpoint/port cause.
        error: gnunet_client_host::ConnectError,
    },
    /// Actual original dependency source loss, never an empty result.
    BackendLost {
        /// Actual provider kind.
        provider: business::Provider,
        /// Actual original native epoch diagnostic.
        epoch: Option<u64>,
        /// Original actual loss cause.
        cause: LostCause,
    },
    /// Exact local OS/helper failure; no private request data is retained.
    SystemFailed {
        /// Original job diagnostic.
        job: u64,
        /// Original actual provider cause.
        cause: crate::SystemFailure,
    },
    /// Actual original scan owner retired, preserving any NEXT/STOP exposure.
    ScanRetired {
        /// Original job.
        job: u64,
        /// Original native epoch diagnostic only.
        epoch: Option<u64>,
        /// Original control allocation/kind/submission, if any.
        control: Option<(
            u64,
            gnunet_namestore_client_host::ControlKind,
            gnunet_namestore_client_host::Submission,
        )>,
    },
    /// Actual original provider/refusal cause, without private frame bytes.
    ProviderFailed {
        /// Original job.
        job: u64,
        /// Actual provider.
        provider: business::Provider,
        /// Original classified refusal.
        reason: Fault,
    },
    /// Independent cleanup failure.
    Cleanup(Fault),
}
/// One fair caller-driven native step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual bounded work.
    Activity,
    /// Caller observation deadline only.
    WaitDeadline,
    /// Every owned MQ/job is actually retired; commit unknowns remain reported.
    Stopped,
}
/// Actual local owner counters. Remote processing/replication is never inferred.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Accepted app MQs.
    pub accepted: u64,
    /// Actually retired app MQs.
    pub closed: u64,
    /// Accepted original RPCs.
    pub requests: u64,
    /// Actual provider admissions.
    pub submitted: u64,
    /// Actual result/retirement callbacks.
    pub completions: u64,
    /// Actual whole local response writes.
    pub written: u64,
    /// Retired jobs with at least one genuine indeterminate outcome.
    pub unknown: u64,
    /// Forced physical provider owner stops.
    pub forced: u64,
    /// Prepared/queued outputs erased after actual original app-source loss.
    pub dropped_outputs: u64,
}
