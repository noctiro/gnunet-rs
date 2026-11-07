use crate::{backend, worker};
use gnunet_identity::{ChangeKind, Code};
use gnunet_service_runtime::{
    accepted::SocketEvent,
    clock::RuntimeClock,
    credentials::UnixAccess,
    service::{PeerAddress, ServiceOptions},
};
use gnunet_types::Error as Fault;
use std::{io, rc::Rc, sync::Arc, time::Duration};
/// Actual original error, never a fabricated successful RESULT_CODE.
#[derive(Debug)]
pub enum Error {
    /// Pure/core/resource ownership failure.
    Protocol(Fault),
    /// Original socket/reactor failure.
    Io(io::Error),
    /// Original canonical clock read/subscription failure.
    Clock(Fault),
    /// Original native persistence/cleanup cause.
    Storage(Arc<backend::Failure>),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "IDENTITY protocol: {e}"),
            Self::Io(e) => e.fmt(f),
            Self::Clock(e) => write!(f, "IDENTITY clock: {e}"),
            Self::Storage(e) => e.fmt(f),
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
pub(super) struct Domain {
    pub _private: u8,
}
/// Non-forgeable source identity; serial alone cannot name a recycled connection.
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
        f.debug_tuple("IdentityClient").field(&self.serial).finish()
    }
}
impl Client {
    /// Diagnostic serial only; not a wire RID or transferable authority.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.serial
    }
}
/// Explicit shared service ports; constructing Server never starts a Resolver/thread.
pub struct Ports {
    /// Original configured access/tolerance/shutdown policy.
    pub options: ServiceOptions,
    /// Actual kernel Unix admission rule.
    pub unix: UnixAccess,
    /// Process-shared canonical clock.
    pub clock: Arc<dyn RuntimeClock>,
}
/// Independent finite queues, secret storage views and native wait policies.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actual MQ sources.
    pub clients: usize,
    /// Snapshot/result cursor items per source (preallocated at admission).
    pub output_items: usize,
    /// Maximum whole official input/output frame.
    pub frame_bytes: usize,
    /// Per-source original immutable TX queue bounds.
    pub output_frames: usize,
    /// Per-source retained TX bytes.
    pub output_bytes: usize,
    /// One actual syscall quantum.
    pub io_slice_bytes: usize,
    /// Maximum private encoded canonical snapshot body.
    pub snapshot_body_bytes: usize,
    /// Maximum committed snapshot revisions held by live source cursors.
    pub retained_versions: usize,
    /// First complete input bound from actual accepted source admission.
    pub first_input: Duration,
    /// Complete original frame including capacity waits, from its first byte.
    pub input_lifetime: Duration,
    /// Oldest retained output cursor/TX lifetime; later outputs do not renew it.
    pub output_lifetime: Duration,
    /// One original admitted worker wait; expiration closes MQs but never claims
    /// cancellation of the actual disk IO or detaches its writer.
    pub storage_lifetime: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 32,
            output_items: 8,
            frame_bytes: 65535,
            output_frames: 2,
            output_bytes: 131070,
            io_slice_bytes: 65535,
            snapshot_body_bytes: 4 * 1024 * 1024,
            retained_versions: 8,
            first_input: Duration::from_secs(30),
            input_lifetime: Duration::from_secs(30),
            output_lifetime: Duration::from_secs(30),
            storage_lifetime: Duration::from_secs(30),
        }
    }
}
/// Actual per-source local termination, independent of any old storage effect.
#[derive(Debug)]
pub enum CloseCause {
    /// Actual EOF.
    Eof,
    /// Actual native IO error.
    Io(io::Error),
    /// Malformed original request.
    Protocol(Fault),
    /// Local source queue/secret-view bound.
    Capacity,
    /// Original first-input/output lifetime expired.
    Deadline,
    /// Service permanent cleanup.
    Shutdown,
}
/// Public diagnostics never include a request frame, key, secret snapshot or name.
#[derive(Debug)]
pub enum Event {
    /// Actual canonical acceptance observation.
    Socket(SocketEvent),
    /// Actual ACL/kernel-credential rejection.
    Rejected(PeerAddress),
    /// Actual source admitted.
    Accepted(Client),
    /// Physically retired original source.
    Closed {
        /// Original source.
        client: Client,
        /// Actual cause.
        cause: CloseCause,
    },
    /// Immutable original output frame admitted to actual MQ queue.
    Queued {
        /// Original source.
        client: Client,
        /// Original frame serial.
        write: u64,
    },
    /// Actual whole local frame write, not client processing.
    Written {
        /// Original source.
        client: Client,
        /// Original frame serial.
        write: u64,
    },
    /// One official numeric result was placed in its original source FIFO.
    Result {
        /// Original source.
        client: Client,
        /// Actual numeric protocol result.
        code: Code,
    },
    /// Actual original disk command admission.
    StorageQueued {
        /// Original source, which may retire before completion.
        client: Client,
        /// Actual worker job.
        job: worker::Job,
        /// Mutation kind without private data.
        kind: ChangeKind,
    },
    /// Actual durable commit completed, even if its source already disconnected.
    Committed {
        /// Actual original worker job.
        job: worker::Job,
        /// Actual stored generation.
        generation: u64,
        /// Committed mutation kind.
        kind: ChangeKind,
    },
    /// Actual persistence cause, kept independently of source closure.
    StorageFailed(Arc<backend::Failure>),
    /// Independent cleanup error after every possible original source was closed.
    CleanupFailed(Fault),
}
/// One bounded native turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual bounded work.
    Activity,
    /// Caller observation budget ended.
    WaitDeadline,
    /// Original sources and pending storage work have settled.
    Stopped,
}
/// Public metadata only; all secret data stays in zeroizing owners.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual accepted sources.
    pub accepted: u64,
    /// Actual physically retired sources.
    pub closed: u64,
    /// Actual complete local output writes.
    pub written: u64,
    /// Actual committed mutations.
    pub committed: u64,
    /// Actual worker admissions.
    pub submitted: u64,
}
/// Original cleanup result; only an actual join supplies worker report.
#[derive(Debug)]
pub struct Shutdown {
    /// Source/output counters.
    pub report: Report,
    /// Actual original thread termination report.
    pub worker: Option<worker::Stopped>,
    /// Original first error; all cleanup still attempted.
    pub failure: Option<Error>,
}
