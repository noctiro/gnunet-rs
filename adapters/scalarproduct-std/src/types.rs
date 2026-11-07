use gnunet_cadet_host as cadet;
use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_service_runtime::{accepted::SocketEvent, clock::RuntimeClock, service::PeerAddress};
use gnunet_seti_client_host as seti;
use gnunet_types::Error as Fault;
use std::{fmt, sync::Arc, time::Duration};
use tokio::time::Instant;

/// One normal installed endpoint role, independent of the explicit peer profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// scalarproduct-alice ordinary requester IPC.
    Alice,
    /// scalarproduct-bob ordinary responder IPC.
    Bob,
}
/// Original cause, independent of the core's classified terminal observation.
#[derive(Debug)]
pub enum Error {
    /// Original native client socket failure.
    Io(std::io::Error),
    /// Original finite-resource, clock or protocol classification.
    Protocol(Fault),
    /// Original shared CLIENT/CADET endpoint or native cause. Source identity
    /// remains with its original owner; the CADET error is a CLIENT type alias.
    Native(ConnectError),
    /// Original actual SETI source retirement cause.
    Seti(seti::Cause),
    /// Original operating-system entropy failure; partial output was wiped.
    Entropy(getrandom::Error),
    /// Original real Paillier primitive/computation refusal, never a replacement value.
    Paillier(gnunet_scalarproduct_paillier::Error),
}
impl Error {
    pub(crate) fn classified(&self) -> Fault {
        match self {
            Self::Protocol(error) => *error,
            Self::Native(ConnectError::Protocol(error)) => *error,
            Self::Entropy(_) => Fault::EntropyUnavailable,
            Self::Paillier(error) => crate::backend::classify_paillier(*error),
            _ => Fault::Io,
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(out),
            Self::Protocol(e) => e.fmt(out),
            Self::Native(e) => e.fmt(out),
            Self::Seti(e) => write!(out, "SETI source: {e:?}"),
            Self::Entropy(e) => e.fmt(out),
            Self::Paillier(e) => e.fmt(out),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Native(e) => Some(e),
            Self::Paillier(e) => Some(e),
            Self::Seti(seti::Cause::Io(e)) => Some(e),
            Self::Seti(seti::Cause::Ports(e)) => Some(e),
            Self::Seti(seti::Cause::Protocol(e)) => Some(e),
            _ => None,
        }
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ConnectError> for Error {
    fn from(e: ConnectError) -> Self {
        Self::Native(e)
    }
}

/// Frozen selectors from one coherent configuration view and shared clock.
/// No selector proves daemon identity across distinct physical connections.
pub struct Sources {
    pub(crate) cadet: EndpointSource,
    pub(crate) seti: EndpointSource,
    pub(crate) clock: Arc<dyn RuntimeClock>,
}
impl Sources {
    /// Freeze both selectors; start no socket, source or Resolver.
    pub fn new(cadet: EndpointSource, seti: EndpointSource) -> Result<Self, Error> {
        let clock = cadet.clock();
        if !Arc::ptr_eq(&clock, &seti.clock()) {
            return Err(Fault::Conflict.into());
        }
        let [cadet, seti] = EndpointSource::snapshot_all([&cadet, &seti])?;
        let cadet = cadet.fixed_endpoint()?;
        let seti = seti.fixed_endpoint()?;
        Ok(Self { cadet, seti, clock })
    }
    pub(crate) fn retained_bytes(&self) -> Result<usize, Error> {
        let cadet = self
            .cadet
            .fixed_endpoint_storage_bytes()?
            .ok_or(Fault::Conflict)?;
        let seti = self
            .seti
            .fixed_endpoint_storage_bytes()?
            .ok_or(Fault::Conflict)?;
        cadet
            .checked_add(seti)
            .ok_or_else(|| Fault::Overflow.into())
    }
    pub(crate) fn duplicate(&self) -> Result<Self, Error> {
        Ok(Self {
            cadet: self.cadet.duplicate()?,
            seti: self.seti.duplicate()?,
            clock: self.clock.clone(),
        })
    }
    /// Original caller-owned clock; no additional clock is created.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
}

/// Explicit finite source, vector, work and independent lifetime limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Concurrent original IPC/computation owners, including cleanup.
    pub clients: usize,
    /// Original raw vector entries per client, including zero coefficients.
    pub max_rows: usize,
    /// Conservative per-computation owned allocation reservation.
    pub session_bytes: usize,
    /// Aggregate admission reservation, not an RSS measurement.
    pub total_retained_bytes: usize,
    /// Original IPC frame extent, at most 65535.
    pub frame_bytes: usize,
    /// Maximum bytes offered to one client socket syscall.
    pub io_slice_bytes: usize,
    /// Scalar/point/DLOG or Paillier work units per fair native reactor turn.
    pub work_units: usize,
    /// Fixed first-frame bound, never renewed by progress.
    pub first_input: Duration,
    /// Fixed partial-frame bound, never renewed by progress.
    pub partial_input: Duration,
    /// Fixed whole original computation bound, including multipart input.
    pub operation: Duration,
    /// Independent finite physical retirement/control-write grace.
    pub retirement_grace: Duration,
    /// Real ECC core profile; explicit Paillier uses its separate selected policy.
    pub core: gnunet_scalarproduct::Limits,
    /// Explicit native-word hash comparator ABI shared with the remote C role.
    pub hash_order: gnunet_scalarproduct::HashOrder,
    /// Actual original SETI source ABI/framing/resources.
    pub seti: seti::Limits,
    /// Actual original CADET framing and send-credit profile.
    pub cadet: cadet::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        let seti = seti::Limits {
            operations: 1,
            incoming: 1,
            incoming_bytes: 65535,
            output: gnunet_service_runtime::framing::Budget {
                frames: 2,
                bytes: 131070,
            },
            ..seti::Limits::default()
        };
        Self {
            clients: 16,
            max_rows: 65536,
            session_bytes: 16 * 1024 * 1024,
            total_retained_bytes: 256 * 1024 * 1024 + 256 * 1024,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            work_units: 8,
            first_input: Duration::from_secs(30),
            partial_input: Duration::from_secs(15),
            operation: Duration::from_secs(120),
            retirement_grace: Duration::from_secs(5),
            core: gnunet_scalarproduct::Limits {
                max_retained_bytes: 8 * 1024 * 1024,
                ..gnunet_scalarproduct::Limits::default()
            },
            hash_order: gnunet_scalarproduct::HashOrder::native(),
            seti,
            cadet: cadet::Limits::default(),
        }
    }
}
impl Limits {
    /// Validate the complete finite profile before normal SERVICE readiness.
    pub fn validate(self) -> Result<(), Error> {
        self.validate_for(crate::Profile::Ecc)
    }
    pub(crate) fn validate_for(self, profile: crate::Profile) -> Result<(), Error> {
        let core_bytes = profile.core_bytes(self);
        match profile {
            crate::Profile::Ecc => self.core.validate()?,
            crate::Profile::Paillier(policy) => {
                policy.validate().map_err(Error::Paillier)?;
                if self.max_rows > policy.max_rows
                    || self.work_units > usize::from(policy.primitive.units_per_turn)
                    || u64::try_from(self.operation.as_micros()).map_err(|_| Fault::Overflow)?
                        != policy.lifetime_micros
                    || self.cadet.max_payload_bytes < policy.frame_bytes
                {
                    return Err(Fault::InvalidInput.into());
                }
            }
        }
        if !(1..=4096).contains(&self.clients)
            || self.max_rows == 0
            || self.max_rows > 1048576
            || !(184..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.work_units == 0
            || self.work_units > 65536
            || self.session_bytes < core_bytes
            || self.total_retained_bytes < self.session_bytes
        {
            return Err(Fault::InvalidInput.into());
        }
        if self.seti.operations != 1
            || self.seti.incoming != 1
            || self.seti.output.frames == 0
            || self.seti.output.frames > 2
            || self.seti.incoming_bytes < 40
            || !(108..=65535).contains(&self.seti.frame_bytes)
            || self.seti.io_slice_bytes == 0
            || self.seti.retirement_grace_micros == 0
            || self.seti.incoming_lifetime_micros == 0
            || self.seti.output.bytes < self.seti.frame_bytes
            || !(108..=65535).contains(&self.cadet.frame_bytes)
            || self.cadet.io_slice_bytes == 0
            || self.cadet.max_send_credit == 0
            || self.cadet.max_payload_bytes > self.cadet.frame_bytes - 12
            || (matches!(profile, crate::Profile::Ecc)
                && self.cadet.max_payload_bytes
                    < self
                        .core
                        .pairs_per_chunk
                        .checked_mul(64)
                        .and_then(|n| n.checked_add(8))
                        .ok_or(Fault::Overflow)?)
        {
            return Err(Fault::InvalidInput.into());
        }
        let native_allowance = self.native_allowance()?;
        if core_bytes
            .checked_add(native_allowance)
            .is_none_or(|n| n > self.session_bytes)
        {
            return Err(Fault::Capacity.into());
        }
        for duration in [
            self.first_input,
            self.partial_input,
            self.operation,
            self.retirement_grace,
        ] {
            if duration.is_zero()
                || Instant::now().checked_add(duration).is_none()
                || duration.as_micros() >= u128::from(u64::MAX)
            {
                return Err(Fault::InvalidInput.into());
            }
        }
        Ok(())
    }
    pub(crate) fn native_allowance(self) -> Result<usize, Fault> {
        self.frame_bytes
            .max(self.seti.frame_bytes)
            .max(self.cadet.frame_bytes)
            .checked_mul(12)
            .and_then(|n| n.checked_add(256 * 1024))
            .ok_or(Fault::Overflow)
    }
}
/// Real terminal facts from one original native session, including failures.
#[derive(Debug, Default)]
pub struct SessionReport {
    /// Original role if its initial frame was admitted.
    pub role: Option<Role>,
    /// First original native/computation cause.
    pub primary: Option<Error>,
    /// First independent cleanup cause, preserved separately.
    pub cleanup: Option<Error>,
    /// Original CADET retirement retained during held-input drain or local work.
    /// This proves neither complete required data nor a result or peer ACK;
    /// continued computation/output still obey all original operation bounds.
    pub dependency_loss: Option<Error>,
    /// Actual pure computation outcome, not inferred from EOF.
    pub outcome: Option<crate::backend::Outcome>,
    /// Original core effects whose complete native write obligations settled.
    pub written: u64,
    /// Original core effect retired before any exposed byte.
    pub unsent: u64,
    /// Original core effect retired with a partially/exposed unknown outcome.
    pub lost: u64,
    /// Actual positive bytes written to the original client socket.
    pub client_bytes: usize,
    /// Actual positive dependency bytes, not remote processing evidence.
    pub dependency_bytes: usize,
    /// Original native SETI local ends drained after physical retirement.
    pub local_ends: usize,
    /// Actual original SETI local end, including unknown-exposure submission.
    pub seti_end: Option<(seti::Reason, seti::Submission)>,
    /// Original pre-attachment connection retries, never operation replay.
    pub connect_retries: u64,
    /// Last actual transient connection error; terminal causes remain separate.
    pub last_retry: Option<std::io::Error>,
    /// Actual channel count physically retired with the original CADET source.
    pub cadet_channels_retired: usize,
    /// Original CADET pending frame exposure, if that source was lost/closed.
    pub cadet_pending_exposed: Option<bool>,
    /// Diagnostic original pending transmit serial, never authority or a RID.
    pub cadet_pending_serial: Option<u64>,
    /// Diagnostic actual pending MQ epoch, never a replacement source token.
    pub cadet_pending_epoch: Option<u64>,
    /// Non-final inner messages actually processed without an outer ACK.
    pub inner_processed: usize,
    /// Original outer receive_done frames actually written in full.
    pub outer_acks: usize,
    /// Original held outer packets retired by physical source closure.
    pub retired_inputs: usize,
    /// All owned original physical sockets/MQs were explicitly closed.
    pub physical_closed: bool,
    /// Original core/dependency bookkeeping debt after attempted retirement.
    pub undrained: usize,
}
/// Aggregate terminal counts; full original causes remain in Event::Closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual one shared Paillier Alice key generation completed before READY.
    pub key_generated: bool,
    /// Actual pending shared key generation was retired without a key/READY.
    pub key_generation_cancelled: bool,
    /// Actual admitted original IPC owners.
    pub accepted: u64,
    /// Actual terminal original owners and all physical closures observed.
    pub closed: u64,
    /// Sessions whose original client result was fully locally written.
    pub results_written: u64,
    /// Sessions with an actual primary native/core failure.
    pub failed: u64,
    /// Original aggregate core debt not silently treated as success.
    pub undrained: usize,
}
/// Caller-visible real progress, without synthetic protocol acknowledgements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual admission, polling or terminal cleanup progress.
    Activity,
    /// Only the observation wait elapsed.
    WaitDeadline,
    /// Admission stopped and all actual original owners retired.
    Stopped,
}
/// Synchronous observations; no secret vectors, keys or raw payload are logged.
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "original terminal causes and receipts move inline without allocation on failure"
)]
pub enum Event {
    /// Actual socket initialization/accept diagnostic.
    Socket(SocketEvent),
    /// Actual accepted source denied by standard ACL/credentials.
    Rejected(PeerAddress),
    /// Actual admission failed and that source was dropped.
    AdmissionFailed(Error),
    /// Original local session serial, not a wire request ID.
    Accepted(u64),
    /// Original terminal session, preserving native and cleanup causes.
    Closed {
        /// Original local session serial.
        client: u64,
        /// Actual complete terminal observations.
        report: SessionReport,
    },
}
