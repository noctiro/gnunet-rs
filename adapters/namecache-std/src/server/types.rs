use gnunet_namecache::Stats;
use gnunet_service_runtime::{
    accepted::SocketEvent,
    clock::RuntimeClock,
    credentials::UnixAccess,
    service::{PeerAddress, ServiceOptions},
};
use gnunet_types::Error as Fault;
use std::{io, rc::Rc, sync::Arc, time::Duration};
/// Actual original error. No native failure is replaced with a cache success.
#[derive(Debug)]
pub enum Error {
    /// Core/protocol/resource failure.
    Protocol(Fault),
    /// Original native IO failure.
    Io(io::Error),
    /// Original process clock failure.
    Clock(Fault),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "NAMECACHE protocol: {e}"),
            Self::Io(e) => e.fmt(f),
            Self::Clock(e) => write!(f, "NAMECACHE clock: {e}"),
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
pub(super) struct Domain;
/// Original process-domain source identity. A serial cannot authorize reuse of
/// a retired connection or identify a source in another server instance.
#[derive(Clone)]
pub struct Client {
    pub(super) domain: Rc<Domain>,
    pub(super) serial: u64,
}
impl PartialEq for Client {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &other.domain) && self.serial == other.serial
    }
}
impl Eq for Client {}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("NamecacheClient")
            .field(&self.serial)
            .finish()
    }
}
impl Client {
    /// Diagnostic serial only, not a wire RID or transferable authority.
    pub const fn value(&self) -> u64 {
        self.serial
    }
}
/// Caller-supplied shared service policy and the same process clock/Resolver
/// time domain. Constructing a Server creates no resolver, thread or task.
pub struct Ports {
    /// Canonical listener/address/tolerance/shutdown policy.
    pub options: ServiceOptions,
    /// Actual kernel Unix credentials admission rule.
    pub unix: UnixAccess,
    /// Process-shared canonical logical clock.
    pub clock: Arc<dyn RuntimeClock>,
}
/// Native finite source queues and lifecycle policy, independent of cache bytes.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum simultaneously admitted original MQs.
    pub clients: usize,
    /// Largest whole official input/output frame.
    pub frame_bytes: usize,
    /// Per-source immutable output frames, including partial head.
    pub output_frames: usize,
    /// Per-source retained immutable output bytes.
    pub output_bytes: usize,
    /// Maximum bytes attempted in one actual read/write syscall.
    pub io_slice_bytes: usize,
    /// First complete input bound from actual source admission.
    pub first_input: Duration,
    /// Original input frame lifetime, including output-credit waits.
    pub input_lifetime: Duration,
    /// Oldest retained output lifetime; later frames do not renew it.
    pub output_lifetime: Duration,
    /// Explicit logical cache cleanup interval; clock rollback keeps its target.
    pub maintenance_interval: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 32,
            frame_bytes: 65535,
            output_frames: 4,
            output_bytes: 4 * 65535,
            io_slice_bytes: 65535,
            first_input: Duration::from_secs(30),
            input_lifetime: Duration::from_secs(30),
            output_lifetime: Duration::from_secs(30),
            maintenance_interval: Duration::from_secs(3600),
        }
    }
}
/// Actual original-source retirement cause. Other live sources keep ownership
/// and are not closed by a malformed peer, local source timeout or source IO error.
#[derive(Debug)]
pub enum CloseCause {
    /// Actual EOF.
    Eof,
    /// Original source IO failure.
    Io(io::Error),
    /// Malformed source frame or source-local processing failure.
    Protocol(Fault),
    /// Finite source input/output deadline.
    Deadline,
    /// Service close or finished drain.
    Shutdown,
}
/// Public metadata only; no request frame, encrypted payload or block key dump.
#[derive(Debug)]
pub enum Event {
    /// Actual canonical socket option/accept observation.
    Socket(SocketEvent),
    /// Actual access rule rejection.
    Rejected(PeerAddress),
    /// Original credential-query IO failure; only this unadmitted socket closes.
    AdmissionIo {
        /// Original accepted address.
        address: PeerAddress,
        /// Actual kernel/credential lookup cause.
        error: io::Error,
    },
    /// Source allocation/identity admission failed before any request effect.
    AdmissionFault {
        /// Original accepted address.
        address: PeerAddress,
        /// Actual source admission failure.
        reason: Fault,
    },
    /// Actual admitted original source.
    Accepted(Client),
    /// Physical original source closure.
    Closed {
        /// Original source.
        client: Client,
        /// Original cause.
        cause: CloseCause,
    },
    /// Actual completed memory-backend call, before result queueing. This is not
    /// a disk commit, fsync receipt, client processing or remote publication.
    Result {
        /// Original source.
        client: Client,
        /// Original connection-local RID.
        rid: u32,
        /// True for DELETE; false for CACHE.
        delete: bool,
        /// Actual signed backend result.
        result: i32,
    },
    /// Actual immutable reply admitted to this original source queue.
    Queued {
        /// Original source.
        client: Client,
        /// Original connection-local RID.
        rid: u32,
        /// Non-reused local frame serial.
        write: u64,
    },
    /// Actual complete local frame write; peer processing is not inferred.
    Written {
        /// Original source.
        client: Client,
        /// Original connection-local RID.
        rid: u32,
        /// Original frame serial.
        write: u64,
    },
    /// Actual expired memory rows removed by the explicit clock maintenance.
    Expired {
        /// Actual removed distinct queries.
        count: usize,
    },
}
/// One bounded caller-driven turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual bounded native/domain activity.
    Activity,
    /// Original caller wait bound reached.
    WaitDeadline,
    /// All sources have drained or physically stopped.
    Stopped,
}
/// Actual counters; cache state is volatile and has no hidden store worker.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual source admissions.
    pub accepted: u64,
    /// Actual source closures.
    pub closed: u64,
    /// Actual handled official requests.
    pub handled: u64,
    /// Actual complete local output writes.
    pub written: u64,
    /// Actual queries discarded by expiry maintenance.
    pub expired: u64,
}
/// Final memory-backend/source report, not a durable-storage receipt.
#[derive(Clone, Copy, Debug)]
pub struct Shutdown {
    /// Source counters.
    pub report: Report,
    /// Retained volatile cache allocation summary at stop.
    pub cache: Stats,
}
