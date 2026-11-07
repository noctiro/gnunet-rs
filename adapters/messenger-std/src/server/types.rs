use super::*;
/// Original failure only; diagnostics never carry chat or private key bytes.
#[derive(Debug)]
pub enum Error {
    /// Exact pure-state refusal.
    Core(core::Error),
    /// Framing, source or resource refusal.
    Protocol(Fault),
    /// Native IO failure.
    Io(io::Error),
    /// Actual CLIENT boundary failure.
    Provider(gnunet_client_host::ConnectError),
    /// Original PILS physical loss cause.
    PilsLost(pils::LossCause),
    /// Actual original history writer/recovery failure.
    History(crate::history::Error),
    /// Independent final-cut preparation/completion and actual worker join failures.
    HistoryShutdown {
        /// Original Core or history preparation/completion failure.
        original: Box<Error>,
        /// Independent original worker shutdown/drain failure.
        cleanup: crate::history::Error,
    },
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Core(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Provider(e) => e.fmt(f),
            Self::History(e) => e.fmt(f),
            Self::HistoryShutdown { original, cleanup } => write!(
                f,
                "final history: {original}; independent worker shutdown: {cleanup}"
            ),
            Self::PilsLost(e) => write!(f, "PILS original loss: {e:?}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::HistoryShutdown { original, .. } => Some(original.as_ref()),
            Self::Io(error) => Some(error),
            Self::History(error) => Some(error),
            _ => None,
        }
    }
}
impl From<core::Error> for Error {
    fn from(e: core::Error) -> Self {
        Self::Core(e)
    }
}
impl From<crate::history::Error> for Error {
    fn from(e: crate::history::Error) -> Self {
        Self::History(e)
    }
}
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
/// Explicit original dependency/configuration/ACL/clock ports.
pub struct Ports {
    /// SERVICE policy and address ACL.
    pub options: ServiceOptions,
    /// Kernel Unix credential policy.
    pub unix: UnixAccess,
    /// One exact shared clock.
    pub clock: Arc<dyn RuntimeClock>,
    /// One shared CADET CLIENT source.
    pub cadet: EndpointSource,
    /// One shared original public PILS/signing source.
    pub pils: EndpointSource,
}
/// Independent bounded native metadata and real cursor lifetimes.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Accepted app MQs.
    pub clients: usize,
    /// Live shared rooms.
    pub rooms: usize,
    /// Per original app room leases.
    pub client_rooms: usize,
    /// Actual CADET channel metadata entries.
    pub tunnels: usize,
    /// Global small delivery relations; frames remain in bounded Core history.
    pub deliveries: usize,
    /// Actual outstanding purpose12 jobs, at most the PILS Client O.
    pub signatures: usize,
    /// Small queued control notices per app, in addition to one original TX.
    pub controls: usize,
    /// Ordinary frame cap.
    pub frame_bytes: usize,
    /// Real syscall quantum.
    pub io_slice_bytes: usize,
    /// Initial app CREATE/partial frame bound.
    pub input_lifetime: Duration,
    /// Original output/channel/announcement/signing deadline.
    pub operation_lifetime: Duration,
    /// Actual admitted PILS cancellation drain before physical MQ stop.
    pub retirement_grace: Duration,
    /// Exact official PILS/HELLO source semantics, independent of message layout.
    pub pils_profile: gnunet_pils::Profile,
    /// Exact local daemon producer layout.
    pub profile: wire::profile::Profile,
    /// Explicit remote daemon layout; never guessed from data or host OS.
    pub peer_profile: wire::profile::Profile,
    /// Official GROUP_KEYS service setting.
    pub group_keys: bool,
    /// Official peer-advertisement based routing, without hidden DHT discovery.
    pub auto_routing: bool,
    /// Official alternate-entry policy after losing all room routes.
    pub auto_connecting: bool,
    /// Official local history request fanout policy.
    pub local_request: bool,
    /// Desired actual room tunnels; bounded by the caller tunnel pool.
    pub min_routers: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 16,
            rooms: 16,
            client_rooms: 16,
            tunnels: 32,
            deliveries: 512,
            signatures: 16,
            controls: 8,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            input_lifetime: Duration::from_secs(30),
            operation_lifetime: Duration::from_secs(60),
            retirement_grace: Duration::from_secs(5),
            pils_profile: gnunet_pils::Profile::Reference029,
            profile: wire::profile::Profile::NATIVE_255,
            peer_profile: wire::profile::Profile::NATIVE_255,
            group_keys: true,
            auto_routing: true,
            auto_connecting: true,
            local_request: false,
            min_routers: 2,
        }
    }
}
impl Limits {
    pub(super) fn validate(self, operations: usize) -> Result<(), Fault> {
        let destinations = self
            .clients
            .checked_add(self.tunnels)
            .ok_or(Fault::Overflow)?;
        self.profile.validate()?;
        self.peer_profile.validate()?;
        if self.clients == 0
            || self.rooms == 0
            || self.client_rooms == 0
            || self.tunnels == 0
            || self.deliveries < destinations
            || self.signatures == 0
            || self.signatures > operations
            || self.min_routers > self.tunnels
            || self.controls < 2
            || self.frame_bytes < 1024
            || self.frame_bytes > 65535
            || self.io_slice_bytes == 0
        {
            return Err(Fault::Capacity);
        }
        for d in [
            self.input_lifetime,
            self.operation_lifetime,
            self.retirement_grace,
        ] {
            if d.is_zero()
                || Instant::now().checked_add(d).is_none()
                || d.as_micros() > u128::from(u64::MAX - 1)
            {
                return Err(Fault::Deadline);
            }
        }
        Ok(())
    }
    pub(super) fn framing(self) -> FrameLimits {
        FrameLimits {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
}
/// Private original accepted-MQ allocation; numerical diagnostics grant nothing.
#[derive(Clone)]
pub struct Client {
    pub(super) domain: Rc<()>,
    pub(super) serial: u64,
}
impl Client {
    /// Nonsecret diagnostic allocation, never wire authority.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.serial
    }
}
impl PartialEq for Client {
    fn eq(&self, o: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &o.domain) && self.serial == o.serial
    }
}
impl Eq for Client {}
impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MessengerClient")
            .field(&self.serial)
            .finish()
    }
}
/// Exact permanent local source closure reason.
#[derive(Debug)]
pub enum CloseCause {
    /// Actual clean EOF.
    Eof,
    /// Original IO cause.
    Io(io::Error),
    /// Original protocol/state refusal.
    Fault(Fault),
    /// Original pure cryptographic/authorization cause.
    Core(core::Error),
    /// Original finite budget.
    Deadline,
    /// Caller requested physical shutdown.
    Shutdown,
}
/// Nonsecret bounded observations; no callbacks execute during borrowed input.
#[derive(Debug)]
pub enum Event {
    /// Canonical accept/diagnostic event.
    Socket(SocketEvent),
    /// Actual ACL rejection.
    Rejected(PeerAddress),
    /// Actual accepted app source.
    Accepted(Client),
    /// Original app physical owner retired before Core cleanup.
    Closed {
        /// Original accepted client.
        client: Client,
        /// Observed reason for physical closure.
        cause: CloseCause,
    },
    /// One additional room ENTRY failed locally without detaching the active
    /// room. This is an observation, not an invented wire failure acknowledgement.
    EntryFailed {
        /// Original accepted client that submitted this request.
        client: Client,
        /// Original requested room key.
        key: Hash,
        /// Original requested door, never replaced by another room route.
        door: [u8; 32],
        /// Original request refusal; independent output/provider loss stays separate.
        reason: Error,
    },
    /// One additional OPEN failed locally without detaching its room lease.
    /// No wire failure acknowledgement is invented.
    OpenFailed {
        /// Original accepted client that submitted this request.
        client: Client,
        /// Original room requested for hosting.
        key: Hash,
        /// Original local refusal; physical output/provider losses stay separate.
        reason: Error,
    },
    /// Actual public local peer observation.
    Identity,
    /// Original app or CADET output admitted, not delivery.
    Queued {
        /// Original local output sequence.
        sequence: u64,
        /// Whether the output uses CADET rather than an application MQ.
        peer: bool,
    },
    /// Exact complete original local write.
    Written {
        /// Original completely written output sequence.
        sequence: u64,
        /// Whether the output used CADET.
        peer: bool,
    },
    /// Actual bounded input admission; deferred signer validation is explicit.
    Received {
        /// Whether the original source was a CADET peer.
        peer: bool,
        /// Whether the original signed message is already cryptographically authenticated.
        authenticated: bool,
    },
    /// Exact original CADET physical cause and exposure metadata.
    CadetLost {
        /// Original local source diagnostic generation.
        epoch: u64,
        /// Retired channels.
        channels: usize,
        /// Original pending frame identity/exposure, if any.
        pending: Option<(u64, bool)>,
        /// Original SDK/native cause.
        cause: cadet::LossCause,
    },
    /// Invalid original channel data retired without granting receive_done.
    PeerRefused {
        /// Exact original protocol/authentication refusal.
        reason: Error,
    },
    /// Real original PILS job accepted locally, no signature completion yet.
    SignAdmitted {
        /// Original typed SDK operation's diagnostic allocation.
        operation: u64,
    },
    /// Original purpose request actually fully written, no result implied.
    SignWritten {
        /// Original SDK operation diagnostic allocation.
        operation: u64,
    },
    /// Original PILS signature independently checked and committed locally.
    SignApplied {
        /// Original SDK operation diagnostic allocation.
        operation: u64,
    },
    /// Actual original crypto refusal, not a publication acknowledgement.
    SignRejected {
        /// Original SDK operation diagnostic allocation.
        operation: u64,
        /// Exact public SDK refusal classification.
        reason: pc::Failure,
    },
    /// A local purpose draft retired before any actual PILS operation admission.
    SignDraftRetired {
        /// Original Core operation coordinates, not a PILS operation receipt.
        operation: core::HandleObservation,
        /// Actual local refusal of obsolete signing authority.
        reason: Fault,
    },
    /// Exact explicit history worker progress; queued is never durable success.
    History(crate::history::Progress),
    /// Actual provider/source failure; error itself returned separately when fatal.
    DependencyLost {
        /// Whether the original lost dependency was PILS.
        pils: bool,
    },
    /// Original exposed output retired with the physical source, unknown delivery.
    OutputLost {
        /// Original retired output sequence.
        sequence: u64,
        /// None means the original native cursor was unavailable at loss.
        exposed: Option<bool>,
    },
}
/// One fair bounded scheduling step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// One real local state/IO step.
    Activity,
    /// Caller observation deadline only.
    WaitDeadline,
    /// Stop requested and all native owners physically closed.
    Closed,
}
/// Local facts only; physical close is not remote delivery or durable history.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Accepted app MQ count.
    pub accepted: u64,
    /// Physically closed app MQs.
    pub closed: u64,
    /// Original local whole output writes.
    pub written: u64,
    /// Actual authenticated admitted messages.
    pub received: u64,
    /// Original outputs retired with unknown exposed outcome.
    pub unknown: u64,
    /// Provider jobs still pending at forced closure, before actual MQ fencing.
    pub stopped_signatures: usize,
}
/// Explicit caller-owned OS entropy descriptor. Opening is a real runtime action;
/// this library never opens it implicitly or reads private key files.
pub struct SystemEntropy(std::fs::File);
impl SystemEntropy {
    /// Open the OS entropy port at real process startup.
    pub fn open() -> io::Result<Self> {
        Ok(Self(std::fs::File::open("/dev/urandom")?))
    }
}
impl gnunet_crypto::Entropy for SystemEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Fault> {
        use std::io::Read;
        self.0.read_exact(out).map_err(|_| Fault::NotReady)
    }
}
