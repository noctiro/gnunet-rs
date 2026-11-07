use gnunet_service_runtime::{
    clock::RuntimeClock, credentials::UnixAccess, service::ServiceOptions,
};
use gnunet_types::Error as Fault;
use std::{io, rc::Rc, sync::Arc, time::Duration};
/// Exact original service/runtime failure, without public proof/key data dumps.
#[derive(Debug)]
pub enum Error {
    /// Resource/protocol/core invariant failure.
    Fault(Fault),
    /// Original native I/O cause.
    Io(io::Error),
    /// Original canonical clock fault.
    Clock(Fault),
    /// Original CLIENT/Resolver source cause.
    Native(gnunet_client_host::ConnectError),
    /// Actual independent snapshot failure and its cleanup.
    Storage(Arc<gnunet_snapshot_host::backend::Failure>),
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Fault(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<gnunet_client_host::ConnectError> for Error {
    fn from(e: gnunet_client_host::ConnectError) -> Self {
        Self::Native(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "REVOCATION: {self:?}")
    }
}
impl std::error::Error for Error {}
pub(super) struct Domain;
/// Original accepted MQ identity, unrelated to any future reused row/descriptor.
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
        f.debug_tuple("RevocationClient")
            .field(&self.serial)
            .finish()
    }
}
impl Client {
    /// Diagnostic serial only, not transferable source authority.
    pub const fn value(&self) -> u64 {
        self.serial
    }
}
/// Shared clock and actual SERVICE access policy, with no hidden listener/task.
pub struct Ports {
    /// Actual canonical service policy.
    pub options: ServiceOptions,
    /// Actual kernel Unix credential policy.
    pub unix: UnixAccess,
    /// Original RuntimeClock used by every provider/worker.
    pub clock: Arc<dyn RuntimeClock>,
}
/// Finite IPC, verification, inventory and public dissemination resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Explicit native SETU ABI for the configured local producer.
    pub setu_abi: gnunet_setu_client_host::ipc::Abi,
    /// Actual accepted MQ capacity.
    pub clients: usize,
    /// At most63 remote CORE peer rows plus the local CORE slot.
    pub peers: usize,
    /// Permanent durable fact capacity; no eviction revives keys.
    pub certificates: usize,
    /// Whole snapshot body capacity.
    pub snapshot_bytes: usize,
    /// Maximum unverified public network candidates retained.
    pub network_inputs: usize,
    /// Maximum actual native syscall slice.
    pub io_slice_bytes: usize,
    /// First complete application input bound.
    pub first_input: Duration,
    /// Original input/verification/commit local-interest bound.
    pub operation_lifetime: Duration,
    /// Original output suffix/write bound.
    pub output_lifetime: Duration,
    /// Original cancellation suffix grace, never renewed.
    pub retirement_grace: Duration,
    /// Finite original listener intent, reconstructed explicitly after old close.
    pub listener_lifetime: Duration,
    /// New public knowledge intent retry delay.
    pub retry: Duration,
    /// Periodic new anti-entropy intent interval, not an old RPC replay.
    pub reconciliation_interval: Duration,
    /// Maximum bookkeeping timer interval.
    pub tick: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            setu_abi: gnunet_setu_client_host::ipc::Abi::native(),
            clients: 32,
            peers: 32,
            certificates: 8192,
            snapshot_bytes: 4 * 1024 * 1024,
            network_inputs: 64,
            io_slice_bytes: 65535,
            first_input: Duration::from_secs(30),
            operation_lifetime: Duration::from_secs(30),
            output_lifetime: Duration::from_secs(5),
            retirement_grace: Duration::from_secs(5),
            listener_lifetime: Duration::from_secs(3600),
            retry: Duration::from_secs(1),
            reconciliation_interval: Duration::from_secs(300),
            tick: Duration::from_millis(100),
        }
    }
}
impl Limits {
    pub(super) fn validate(self) -> Result<(), Fault> {
        self.setu_abi.validate()?;
        let needed = self
            .certificates
            .checked_mul(396)
            .and_then(|n| n.checked_add(16))
            .ok_or(Fault::Overflow)?;
        if needed > self.snapshot_bytes {
            return Err(Fault::Capacity);
        }
        if self.clients == 0
            || self.clients > 1024
            || self.peers == 0
            || self.peers > 63
            || self.certificates == 0
            || self.certificates > 131072
            || self.snapshot_bytes < 16
            || self.snapshot_bytes > 64 * 1024 * 1024
            || self.network_inputs == 0
            || self.network_inputs > 4096
            || self.io_slice_bytes == 0
            || self.io_slice_bytes > 65535
        {
            return Err(Fault::Capacity);
        }
        for d in [
            self.first_input,
            self.operation_lifetime,
            self.output_lifetime,
            self.retirement_grace,
            self.listener_lifetime,
            self.retry,
            self.reconciliation_interval,
            self.tick,
        ] {
            if d.is_zero()
                || u64::try_from(d.as_micros()).is_err()
                || std::time::Instant::now().checked_add(d).is_none()
            {
                return Err(Fault::Deadline);
            }
        }
        Ok(())
    }
}
/// Actual original source retirement. No cause implies server-side rollback.
#[derive(Debug)]
pub enum CloseCause {
    /// Actual EOF.
    Eof,
    /// Original native error.
    Io(io::Error),
    /// Original protocol/malformed/invalid certificate.
    Protocol(Fault),
    /// Original native/logic bound.
    Deadline,
    /// Explicit shutdown.
    Shutdown,
    /// Original store outcome is unknown; no false REVOKE1 is sent.
    StorageUnknown,
    /// Clock failed; physical close is independent of clock.
    Clock,
}
/// Original observed input provenance. These diagnostic values cannot admit a
/// request or mint a verification/durability receipt.
#[derive(Clone, Debug)]
pub enum InputSource<'id> {
    /// Original accepted application MQ and private local request ordinal.
    Application(Client, u64),
    /// Actual original CORE MQ and sender identity.
    Core(gnunet_core_client_host::ConnectionEpoch<'id>, [u8; 32]),
    /// Actual original SETU MQ, operation and local observation ordinal.
    Union(
        gnunet_setu_client_host::Epoch<'id>,
        gnunet_setu_client_host::Operation<'id>,
        u64,
    ),
}
/// Actual service observation. Written events prove only local native bytes.
#[derive(Debug)]
pub enum Event<'id> {
    /// Actual immutable input admitted to the original verifier.
    Input(InputSource<'id>),
    /// Actual shared socket admission diagnostics.
    Socket(gnunet_service_runtime::accepted::SocketEvent),
    /// Actual ACL/UID rejection.
    Rejected(gnunet_service_runtime::service::PeerAddress),
    /// Original accepted source.
    Accepted(Client),
    /// Physical original source closed before this event.
    Closed(Client, CloseCause),
    /// Actual original complete reply write.
    Written(Client, u64, gnunet_revocation::ipc::Response),
    /// Actual original verifier admission.
    VerificationQueued(crate::verification::Job),
    /// Actual checked public proof; still not durable acceptance.
    Checked(crate::verification::Job),
    /// Actual original snapshot worker admission.
    StoreQueued(gnunet_snapshot_host::worker::Job),
    /// Actual durable commit and visible inventory generation.
    Committed(u64),
    /// Actual network source/operation observation.
    Network(super::network::NetworkEvent<'id>),
    /// Unadmitted candidate refused by configured resource bounds.
    Capacity,
}
/// Bounded progress; Stopped means native owners have retired, not remote receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One actual action happened.
    Activity,
    /// Only caller observation bound ended.
    WaitDeadline,
    /// No accepted source/original backend work remains active.
    Stopped,
}
/// Official keys in the bounded cumulative metric snapshot. Coordinates0/1
/// are positive/negative contributions to the SAME connected-peer gauge;
/// coordinates2..6 are the four original nonpersistent union counters.
pub const METRIC_NAMES: [&[u8]; 6] = [
    b"# peers connected",
    b"# peers connected",
    b"# unsupported revocations received via set union",
    b"# revocation messages received via set union",
    b"# revocation set unions failed",
    b"# revocation set unions completed",
];
/// Real native callback counters. Separate monotonically accumulated connect
/// and disconnect contributions avoid unsigned negative deltas or guessed ACKs.
/// At u64 saturation these are lower bounds, never wrapped/recycled counts.
#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    values: [u64; 6],
}
impl Metrics {
    /// Original cumulative contributions in METRIC_NAMES order. Coordinate1
    /// must be published as a negative UPDATE; all other coordinates positive.
    pub const fn values(&self) -> &[u64; 6] {
        &self.values
    }
    pub(super) fn add(&mut self, index: usize) {
        self.values[index] = self.values[index].saturating_add(1);
    }
}
/// Actual original source/worker counters, with no public certificate contents.
#[derive(Default, Clone, Copy, Debug)]
pub struct Report {
    /// Actual accepted sources.
    pub accepted: u64,
    /// Actual closed sources.
    pub closed: u64,
    /// Original verifier jobs admitted.
    pub verification_jobs: u64,
    /// Actual completed durable commits.
    pub commits: u64,
    /// Native full reply writes.
    pub replies: u64,
    /// Unadmitted public candidate capacity drops.
    pub network_capacity_drops: u64,
}
/// Original independent shutdown results. A disk syscall may require real OS
/// progress; local socket expiry cannot claim cancellation of a dispatched rename.
#[derive(Debug)]
pub struct Shutdown {
    /// Actual source counters.
    pub report: Report,
    /// Original service failure retained across cleanup.
    pub failure: Option<Error>,
    /// Actual original storage join/result.
    pub storage: Result<gnunet_snapshot_host::worker::Stopped, Fault>,
    /// Actual original verifier join/result.
    pub verification: Result<crate::verification::Stopped, Fault>,
    /// Independent network close failure, if exposed by its port.
    pub network: Result<(), Error>,
}
