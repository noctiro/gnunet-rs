use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_service_runtime::{accepted::SocketEvent, clock::RuntimeClock, service::PeerAddress};
use gnunet_types::Error as Fault;
use std::{fmt, sync::Arc, time::Duration};

/// Actual native/protocol failure, independently retained from authorization.
#[derive(Debug)]
pub enum Error {
    /// Actual accepted client/read/write syscall error.
    Io(std::io::Error),
    /// Original shared CLIENT/clock/configuration/Resolver failure.
    Native(ConnectError),
    /// Actual GNS source retirement cause, not a negative lookup result.
    Gns(gnunet_gns_client_host::LossCause),
    /// Actual NAMESTORE source retirement cause, not an absent label.
    Namestore(gnunet_namestore_client_host::LossCause),
    /// Actual non-success private lookup word, including backend -1 or unknown.
    LookupStatus(i16),
    /// Explicit local resource/protocol/clock/expiry classification.
    Protocol(Fault),
}
impl Error {
    pub(crate) fn classified(&self) -> Fault {
        match self {
            Self::Protocol(e) => *e,
            Self::Native(ConnectError::Protocol(e)) => *e,
            Self::Gns(
                gnunet_gns_client_host::LossCause::Protocol(e)
                | gnunet_gns_client_host::LossCause::Resource(e),
            ) => *e,
            Self::Namestore(
                gnunet_namestore_client_host::LossCause::Protocol(e)
                | gnunet_namestore_client_host::LossCause::Resource(e),
            ) => *e,
            Self::Gns(gnunet_gns_client_host::LossCause::Eof)
            | Self::Namestore(gnunet_namestore_client_host::LossCause::Eof) => Fault::Closed,
            _ => Fault::Io,
        }
    }
}
impl From<Fault> for Error {
    fn from(v: Fault) -> Self {
        Self::Protocol(v)
    }
}
impl From<ConnectError> for Error {
    fn from(v: ConnectError) -> Self {
        Self::Native(v)
    }
}
impl From<std::io::Error> for Error {
    fn from(v: std::io::Error) -> Self {
        Self::Io(v)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LookupStatus(found) => write!(f, "NAMESTORE lookup found={found}"),
            Self::Io(e) => e.fmt(f),
            Self::Native(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Gns(e) => write!(f, "GNS source: {e:?}"),
            Self::Namestore(e) => write!(f, "NAMESTORE source: {e:?}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Native(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Gns(gnunet_gns_client_host::LossCause::Io(e)) => Some(e),
            Self::Gns(
                gnunet_gns_client_host::LossCause::Protocol(e)
                | gnunet_gns_client_host::LossCause::Resource(e),
            ) => Some(e),
            Self::Namestore(gnunet_namestore_client_host::LossCause::Io(e)) => Some(e),
            Self::Namestore(gnunet_namestore_client_host::LossCause::Ports(e)) => Some(e),
            Self::Namestore(
                gnunet_namestore_client_host::LossCause::Protocol(e)
                | gnunet_namestore_client_host::LossCause::Resource(e),
            ) => Some(e),
            _ => None,
        }
    }
}

/// Frozen original service selectors and exactly one shared canonical clock.
/// Selectors do not prove daemon identity across different physical MQs.
pub struct Sources {
    pub(crate) gns: EndpointSource,
    pub(crate) namestore: EndpointSource,
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) fixed_bytes: usize,
}
impl Sources {
    /// Freeze a coherent configuration snapshot without a socket or Resolver task.
    pub fn new(gns: EndpointSource, namestore: EndpointSource) -> Result<Self, Error> {
        let clock = gns.clock();
        if !Arc::ptr_eq(&clock, &namestore.clock()) {
            return Err(Fault::Conflict.into());
        }
        let [gns, namestore] = EndpointSource::snapshot_all([&gns, &namestore])?;
        let gns = gns.fixed_endpoint()?;
        let namestore = namestore.fixed_endpoint()?;
        let fixed_bytes = gns
            .fixed_endpoint_storage_bytes()?
            .ok_or(Fault::Conflict)?
            .checked_add(
                namestore
                    .fixed_endpoint_storage_bytes()?
                    .ok_or(Fault::Conflict)?,
            )
            .ok_or(Fault::Overflow)?;
        Ok(Self {
            gns,
            namestore,
            clock,
            fixed_bytes,
        })
    }
    pub(crate) fn duplicate(&self) -> Result<Self, Error> {
        Ok(Self {
            gns: self.gns.duplicate()?,
            namestore: self.namestore.duplicate()?,
            clock: self.clock.clone(),
            fixed_bytes: self.fixed_bytes,
        })
    }
    /// Original caller-selected shared clock; cloning creates no subscription.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
}

/// Explicit native admission/retained/source bounds. They are deployment
/// resources, not new protocol fields or a claim of measured process RSS.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneous original IPC MQs.
    pub clients: usize,
    /// Simultaneous original queries across all clients, including pending output.
    pub queries: usize,
    /// Per-original-MQ concurrent RID owners, including cleanup/output debt.
    pub queries_per_client: usize,
    /// Conservative allocation reservation per admitted original query.
    pub query_bytes: usize,
    /// Aggregate native/query admission reservation.
    pub total_retained_bytes: usize,
    /// Native IPC complete frame extent through65535.
    pub frame_bytes: usize,
    /// Maximum actual offered socket syscall bytes.
    pub io_slice_bytes: usize,
    /// Finite rule/subject evaluations per fair native turn.
    pub work_units: usize,
    /// First complete original client frame, never renewed by slow progress.
    pub first_input: Duration,
    /// First partial incoming frame target, never renewed by later bytes.
    pub partial_input: Duration,
    /// Original per-query work/source/output lifetime, never renewed.
    pub operation: Duration,
    /// Finite original response queue/write bound, never renewed by partial IO.
    pub output: Duration,
    /// Explicit uncertainty around the selected GNUnet absolute clock sample.
    pub utc_uncertainty: Duration,
    /// Real shared pure delegation core resource/record-layout profile.
    pub core: gnunet_abd::Limits,
    /// Actual original native GNS source frame/record/queue resources.
    pub gns: gnunet_gns_client_host::Limits,
    /// Actual original native private NAMESTORE lookup resources.
    pub namestore: gnunet_namestore_client_host::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        let core = gnunet_abd::Limits {
            name_bytes: gnunet_gns_client_host::MAX_NAME_BYTES,
            ..gnunet_abd::Limits::default()
        };
        Self {
            clients: 32,
            queries: 32,
            queries_per_client: 8,
            query_bytes: 8 << 20,
            total_retained_bytes: 256 << 20,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            work_units: 8,
            first_input: Duration::from_secs(30),
            partial_input: Duration::from_secs(15),
            operation: Duration::from_secs(120),
            output: Duration::from_secs(15),
            utc_uncertainty: Duration::ZERO,
            core,
            gns: gnunet_gns_client_host::Limits::default(),
            namestore: gnunet_namestore_client_host::Limits {
                operations: 1,
                reconnect: false,
                ..gnunet_namestore_client_host::Limits::default()
            },
        }
    }
}
impl Limits {
    /// Early configured profile validation, without source/native/crypto work.
    pub fn validate(self) -> Result<(), Error> {
        self.core.validate()?;
        if self.clients == 0
            || self.queries == 0
            || self.queries_per_client == 0
            || self.query_bytes == 0
            || self.total_retained_bytes < self.query_bytes
            || !(89..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.work_units == 0
            || self.core.name_bytes > gnunet_gns_client_host::MAX_NAME_BYTES
            || self.gns.output.frames == 0
            || self.gns.output.bytes < self.gns.frame_bytes
            || !(20 + 36 + gnunet_gns_client_host::MAX_NAME_BYTES + 1..=65535)
                .contains(&self.gns.frame_bytes)
            || self.gns.records == 0
            || self.gns.io_slice_bytes == 0
            || self.namestore.operations != 1
            || self.namestore.reconnect
            || !(64..=65535).contains(&self.namestore.frame_bytes)
            || self.namestore.source_bytes < 64
            || self.namestore.io_slice_bytes == 0
            || self.namestore.records == 0
            || self.namestore.label_bytes == 0
            || self.namestore.label_bytes > 255
            || self.namestore.hint_bytes > 65534
            || self.namestore.credit == 0
            || self.namestore.retirement_grace.is_zero()
        {
            return Err(Fault::InvalidInput.into());
        }
        let overhead = self
            .frame_bytes
            .max(self.gns.frame_bytes)
            .max(self.namestore.frame_bytes)
            .checked_mul(8)
            .and_then(|n| n.checked_add(256 * 1024))
            .ok_or(Fault::Overflow)?;
        if self
            .core
            .retained_bytes
            .checked_add(overhead)
            .is_none_or(|n| n > self.query_bytes)
        {
            return Err(Fault::Capacity.into());
        }
        self.queries_per_client
            .checked_mul(self.frame_bytes)
            .ok_or(Fault::Overflow)?;
        for d in [
            self.first_input,
            self.partial_input,
            self.operation,
            self.output,
        ] {
            if d.is_zero()
                || std::time::Instant::now().checked_add(d).is_none()
                || d.as_micros() >= u128::from(u64::MAX)
            {
                return Err(Fault::InvalidInput.into());
            }
        }
        u64::try_from(self.utc_uncertainty.as_micros()).map_err(|_| Fault::Overflow)?;
        Ok(())
    }
}

/// Actual aggregate terminal facts for one original IPC client, without private
/// keys/attributes/credential payloads in diagnostics or an unbounded history.
#[derive(Debug, Default)]
pub struct ClientReport {
    /// First original client/query/native failure.
    pub primary: Option<Error>,
    /// First independent physical/source retirement failure.
    pub cleanup: Option<Error>,
    /// Original requests admitted on this MQ.
    pub queries: u64,
    /// Terminal result frames actually wholly written locally.
    pub results_written: u64,
    /// Intermediate frames actually wholly written locally.
    pub intermediates_written: u64,
    /// Original GNS lookups admitted.
    pub lookups: u64,
    /// Original GNS query frames actually wholly written locally.
    pub lookup_writes: u64,
    /// Actual original GNS result callbacks, including empty results.
    pub answers: u64,
    /// Independent invalid/expired signed or malformed GNS records skipped.
    pub ignored_records: u64,
    /// Actual private NAMESTORE lookup whole writes.
    pub collection_writes: u64,
    /// Actual incoming client bytes.
    pub read_bytes: u64,
    /// Actual outgoing client bytes.
    pub written_bytes: u64,
    /// Original client MQ physically retired.
    pub physical_closed: bool,
    /// Original queued output frames retired before their first actual byte.
    pub outputs_retired_unwritten: u64,
    /// Original queued output frames retired after an actual partial write.
    pub outputs_retired_partial: u64,
    /// Original source/future ownership debts not actually retired.
    pub undrained: usize,
}
/// Actual bounded service aggregate, without source/runtime acceptance claims.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual admitted native MQs.
    pub accepted: u64,
    /// Original native MQs physically closed.
    pub closed: u64,
    /// Actual original request admissions.
    pub queries: u64,
    /// Actual whole terminal local response writes.
    pub results_written: u64,
    /// Original clients with a classified failure.
    pub failed: u64,
    /// Original cleanup debts remaining, which prohibit successful shutdown.
    pub undrained: usize,
}
/// Real native observation, with no secret-bearing raw Debug payload.
#[derive(Debug)]
pub enum Event {
    /// Original canonical socket acceptance diagnostic.
    Socket(SocketEvent),
    /// Actual native stream rejected by original access policy.
    Rejected(PeerAddress),
    /// An actual accepted original IPC owner.
    Accepted(u64),
    /// Original unadmitted stream failed/resource-refused and was dropped.
    AdmissionFailed(Error),
    /// Actual native owner terminal, preserving independent original causes.
    Closed {
        /// Original non-reused local client serial.
        client: u64,
        /// Original terminal native/query observations.
        report: ClientReport,
    },
}
/// One fair observation of the same retained native service owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual positive native/core/retirement progress.
    Activity,
    /// Only caller's observation wait ended, without cancelling native work.
    WaitDeadline,
    /// Admission stopped and every original physical/query owner retired.
    Stopped,
}
