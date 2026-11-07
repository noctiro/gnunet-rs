use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_service_runtime::{accepted::SocketEvent, clock::RuntimeClock, service::PeerAddress};
use gnunet_types::Error as Fault;
use std::{fmt, sync::Arc, time::Duration};

/// Original provider, protocol, socket or source failure, without private frames.
#[derive(Debug)]
pub enum Error {
    /// Actual native accepted IPC error.
    Io(std::io::Error),
    /// Actual shared CLIENT/configuration/clock/Resolver error.
    Native(ConnectError),
    /// Actual original PILS source loss, not a replacement identity.
    Pils(gnunet_pils_host::client::LossCause),
    /// Actual original CADET MQ loss, independently from a protocol hangup.
    Cadet(gnunet_cadet_host::LossCause),
    /// Actual bounded domain/deadline/protocol refusal.
    Protocol(Fault),
}
impl Error {
    pub(crate) fn classified(&self) -> Fault {
        match self {
            Self::Protocol(e) | Self::Native(ConnectError::Protocol(e)) => *e,
            Self::Pils(
                gnunet_pils_host::client::LossCause::Protocol(e)
                | gnunet_pils_host::client::LossCause::Resource(e),
            ) => *e,
            Self::Pils(gnunet_pils_host::client::LossCause::Setup(ConnectError::Protocol(e))) => *e,
            Self::Cadet(gnunet_cadet_host::LossCause::Protocol(e)) => *e,
            Self::Pils(gnunet_pils_host::client::LossCause::Eof)
            | Self::Cadet(gnunet_cadet_host::LossCause::Eof) => Fault::Closed,
            _ => Fault::Io,
        }
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<ConnectError> for Error {
    fn from(e: ConnectError) -> Self {
        Self::Native(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Native(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Pils(e) => write!(f, "PILS source: {e:?}"),
            Self::Cadet(e) => write!(f, "CADET source: {e:?}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Native(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Pils(gnunet_pils_host::client::LossCause::Io(e))
            | Self::Cadet(gnunet_cadet_host::LossCause::Io(e)) => Some(e),
            Self::Pils(
                gnunet_pils_host::client::LossCause::Protocol(e)
                | gnunet_pils_host::client::LossCause::Resource(e),
            )
            | Self::Cadet(gnunet_cadet_host::LossCause::Protocol(e)) => Some(e),
            Self::Pils(gnunet_pils_host::client::LossCause::Setup(e)) => Some(e),
            _ => None,
        }
    }
}
/// Coherently frozen caller-selected endpoints and one original shared clock.
/// This selects services; it does not prove cross-MQ daemon identity.
pub struct Sources {
    pub(crate) cadet: EndpointSource,
    pub(crate) pils: EndpointSource,
    pub(crate) clock: Arc<dyn RuntimeClock>,
    pub(crate) fixed_bytes: usize,
}
impl Sources {
    /// Snapshot both capabilities together, then freeze actual endpoint storage.
    /// Performs no key access, crypto, DNS or socket operation.
    pub fn new(cadet: EndpointSource, pils: EndpointSource) -> Result<Self, Error> {
        let clock = cadet.clock();
        if !Arc::ptr_eq(&clock, &pils.clock()) {
            return Err(Fault::Conflict.into());
        }
        let [cadet, pils] = EndpointSource::snapshot_all([&cadet, &pils])?;
        let cadet = cadet.fixed_endpoint()?;
        let pils = pils.fixed_endpoint()?;
        let fixed_bytes = cadet
            .fixed_endpoint_storage_bytes()?
            .ok_or(Fault::Conflict)?
            .checked_add(
                pils.fixed_endpoint_storage_bytes()?
                    .ok_or(Fault::Conflict)?,
            )
            .ok_or(Fault::Overflow)?;
        Ok(Self {
            cadet,
            pils,
            clock,
            fixed_bytes,
        })
    }
    pub(crate) fn duplicate(&self) -> Result<Self, Error> {
        Ok(Self {
            cadet: self.cadet.duplicate()?,
            pils: self.pils.duplicate()?,
            clock: self.clock.clone(),
            fixed_bytes: self.fixed_bytes,
        })
    }
    /// Original shared source clock; no new subscription is created.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
}
/// Explicit global, per-Line and original phase limits; no media device policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum original IPC Lines, including cleanup owners.
    pub clients: usize,
    /// Global simultaneous calls, including cleanup and unreported terminals.
    pub calls: usize,
    /// Explicit retained reservation per original native Line.
    pub line_bytes: usize,
    /// Aggregate selected endpoint/owner/Line reservation.
    pub total_retained_bytes: usize,
    /// Complete native IPC extent through65535.
    pub frame_bytes: usize,
    /// Maximum actual offered syscall bytes.
    pub io_slice_bytes: usize,
    /// Finite actor/effect-scan budget per fair turn.
    pub work_units: usize,
    /// Original PILS identity/initial source establishment lifetime.
    pub startup: Duration,
    /// Original first client request lifetime, captured before admission work.
    pub first_input: Duration,
    /// First incomplete client frame lifetime, never renewed by slow bytes.
    pub partial_input: Duration,
    /// Original partial peer input / held outer delivery lifetime.
    pub peer_input: Duration,
    /// Explicit conservative upper UTC uncertainty for real ring sign/verify.
    pub utc_uncertainty: Duration,
    /// Original shared bounded Conversation state/crypto limits per Line.
    pub core: gnunet_conversation::Limits,
    /// Actual CADET source resources; one real MQ per original Line.
    pub cadet: gnunet_cadet_host::Limits,
    /// Actual public identity client resources; no private network key imported.
    pub pils: gnunet_pils_host::client::Limits,
    /// Explicit authenticated public HELLO source shape/resources.
    pub hello: gnunet_pils::HelloLimits,
    /// Exact selected official PILS/HELLO source profile, no downgrade retry.
    pub pils_profile: gnunet_pils::Profile,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 32,
            calls: 256,
            line_bytes: 8 << 20,
            total_retained_bytes: 256 << 20,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            work_units: 8,
            startup: Duration::from_secs(30),
            first_input: Duration::from_secs(30),
            partial_input: Duration::from_secs(15),
            peer_input: Duration::from_secs(15),
            utc_uncertainty: Duration::ZERO,
            core: gnunet_conversation::Limits {
                frame_bytes: 65535,
                ..gnunet_conversation::Limits::default()
            },
            cadet: gnunet_cadet_host::Limits::default(),
            pils: gnunet_pils_host::client::Limits {
                pending_operations: 1,
                frame_bytes: 65535,
                io_slice_bytes: 65535,
            },
            hello: gnunet_pils::HelloLimits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 8192,
                maximum_addresses: 128,
            },
            pils_profile: gnunet_pils::Profile::Reference029,
        }
    }
}
impl Limits {
    /// Validate deployment limits before admitting any native owner.
    pub fn validate(self) -> Result<(), Error> {
        self.core.validate()?;
        if self.clients == 0
            || self.calls == 0
            || self.line_bytes == 0
            || self.total_retained_bytes < self.line_bytes
            || !(140..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.frame_bytes < self.core.frame_bytes
            || !(1..=64).contains(&self.work_units)
            || !(108..=65535).contains(&self.cadet.frame_bytes)
            || self.cadet.io_slice_bytes == 0
            || self.cadet.max_payload_bytes > self.cadet.frame_bytes - 12
            || self.cadet.max_payload_bytes < self.core.frame_bytes.min(64348)
            || self.cadet.max_send_credit == 0
            || self.pils.pending_operations != 1
            || !(176..=65535).contains(&self.pils.frame_bytes)
            || self.pils.io_slice_bytes == 0
            || self.hello.maximum_input_bytes > self.pils.frame_bytes
            || self.hello.maximum_address_bytes == 0
            || self.hello.maximum_addresses == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        let input_buffers = self
            .core
            .calls
            .checked_mul(self.cadet.frame_bytes)
            .ok_or(Fault::Overflow)?;
        let overhead = self
            .frame_bytes
            .max(self.cadet.frame_bytes)
            .max(self.pils.frame_bytes)
            .checked_mul(8)
            .and_then(|v| v.checked_add(self.hello.maximum_address_bytes))
            .and_then(|v| v.checked_add(256 * 1024))
            .and_then(|v| v.checked_add(input_buffers))
            .ok_or(Fault::Overflow)?;
        if self
            .core
            .retained_bytes
            .checked_add(overhead)
            .is_none_or(|v| v > self.line_bytes)
        {
            return Err(Fault::Capacity.into());
        }
        for d in [
            self.startup,
            self.first_input,
            self.partial_input,
            self.peer_input,
        ] {
            if d.is_zero()
                || d.as_micros() >= u128::from(u64::MAX)
                || std::time::Instant::now().checked_add(d).is_none()
            {
                return Err(Fault::InvalidInput.into());
            }
        }
        u64::try_from(self.utc_uncertainty.as_micros()).map_err(|_| Fault::Overflow)?;
        Ok(())
    }
}
/// Bounded public call summary; serial/CID are diagnostics, never capabilities.
#[derive(Clone, Copy, Debug)]
pub struct CallSummary {
    /// Original in-process call serial.
    pub call: u64,
    /// Original opaque local CID echo.
    pub cid: u32,
    /// Actual native peer on the original channel.
    pub peer: [u8; 32],
    /// Original causal call end.
    pub reason: gnunet_conversation::EndReason,
    /// Independent actual source/write failure.
    pub failure: Option<Fault>,
    /// Actual whole local ring write.
    pub ring_written: bool,
    /// Actual remote pickup742.
    pub remote_pickup: bool,
    /// Actual local pickup whole write.
    pub local_pickup_written: bool,
    /// Actual peer hangup741.
    pub remote_hangup: bool,
    /// Actual local hangup whole write.
    pub local_hangup_written: bool,
}
/// Original Line terminal observations. Raw734 key/media frames are never logged.
#[derive(Debug, Default)]
pub struct LineReport {
    /// First original Line/provider/protocol error.
    pub primary: Option<Error>,
    /// First independent physical/core retirement error.
    pub cleanup: Option<Error>,
    /// First actual pre-attachment PILS attempt failure, even if later recovered.
    pub first_pils_retry: Option<std::io::Error>,
    /// First actual pre-attachment CADET attempt failure, even if later recovered.
    pub first_cadet_retry: Option<std::io::Error>,
    /// Actual initial PILS identity/source, not ego caller identity.
    pub identity: Option<([u8; 32], u64)>,
    /// Real call owner admissions.
    pub calls_started: u64,
    /// Calls actually retired with original reports consumed.
    pub calls_closed: u64,
    /// Actual complete local IPC notification/media writes.
    pub client_frames_written: u64,
    /// Actual complete local peer frame writes, not remote receipt.
    pub peer_frames_written: u64,
    /// Original core effects with actual native completion.
    pub effects_written: u64,
    /// Original effects provably not exposed.
    pub effects_unsent: u64,
    /// Original effects retired with actual loss classification.
    pub effects_lost: u64,
    /// Nonfinal inner payloads processed while native outer credit remained held.
    pub processed_inners: u64,
    /// Actual incoming local client bytes.
    pub client_bytes_read: u64,
    /// Actual outgoing local client bytes.
    pub client_bytes_written: u64,
    /// Original IPC physically closed before this report.
    pub physical_closed: bool,
    /// Original CADET physical source permanently closed.
    pub cadet_closed: bool,
    /// Original PILS physical source permanently closed.
    pub pils_closed: bool,
    /// Original cleanup debts remaining; never a successful Stopped result.
    pub undrained: usize,
}
/// Bounded aggregate actual terminal counters, without runtime acceptance claims.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual admitted original IPC Lines.
    pub accepted: u64,
    /// Actual physically closed Lines.
    pub closed: u64,
    /// Actual original call admissions.
    pub calls_started: u64,
    /// Actual reported call retirements.
    pub calls_closed: u64,
    /// Actual complete local IPC output frames.
    pub client_frames_written: u64,
    /// Actual complete local peer output frames.
    pub peer_frames_written: u64,
    /// Failed original Lines.
    pub failed: u64,
    /// Actual undrained owner debts.
    pub undrained: usize,
}
/// Native observations without private key/audio Debug payloads.
#[derive(Debug)]
pub enum Event {
    /// Standard socket acceptance/diagnostic event.
    Socket(SocketEvent),
    /// Actual access-policy rejection.
    Rejected(PeerAddress),
    /// Original admitted Line serial.
    Accepted(u64),
    /// Failed original unadmitted stream.
    AdmissionFailed(Error),
    /// Complete original731 accepted by the local protocol core. The original
    /// input is consumed; this is not a CADET port write or remote-ready ACK.
    RegistrationAccepted {
        /// Original accepted IPC Line. No line-port or private key is logged.
        client: u64,
    },
    /// Actual PILS source context used by the original Line.
    Identity {
        /// Original Line.
        client: u64,
        /// Actual public peer.
        peer: [u8; 32],
        /// Actual source generation.
        epoch: u64,
    },
    /// Actual CADET channel-destroy event, before its later call summary.
    /// This is not a peer HangUp message or a successful call outcome.
    ChannelDestroyed {
        /// Original Line.
        client: u64,
        /// Original call allocation generation.
        call: u64,
        /// Original local IPC call identifier.
        cid: u32,
        /// Original native channel allocation generation.
        channel: u64,
        /// Original CADET MQ epoch.
        epoch: u64,
        /// The SDK still identifies that same MQ as current, with no observed
        /// source retirement. This does not predict its next IO or remote state.
        mq_current: bool,
    },
    /// Actual call terminal after physical close and all original effect debts.
    CallClosed {
        /// Original Line.
        client: u64,
        /// Bounded original call summary.
        report: CallSummary,
    },
    /// Actual Line terminal and independent retirement observations.
    Closed {
        /// Original Line.
        client: u64,
        /// Actual native report.
        report: LineReport,
    },
}
/// Same original owner observation; wait expiration never cancels work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual actor/native/retirement progress.
    Activity,
    /// Only the caller's wait budget expired.
    WaitDeadline,
    /// All original physical/core owners actually retired after stopped admission.
    Stopped,
}
