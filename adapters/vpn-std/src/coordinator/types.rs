use super::*;
/// Explicit source/configuration or original native failure.
#[derive(Debug)]
pub enum Error {
    /// Actual local IPC owner failure.
    Ipc(server::Error),
    /// Actual shared CADET source failure.
    Cadet(cadet::Error),
    /// Actual device/control/readiness/platform error.
    Native(io::Error),
    /// Actual sealed native snapshot/route-query failure.
    Admin(tun::AdminFailure),
    /// Pure engine, policy, deadline or resource classification.
    Protocol(Fault),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ipc(e) => e.fmt(f),
            Self::Cadet(e) => e.fmt(f),
            Self::Native(e) => e.fmt(f),
            Self::Admin(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ipc(e) => Some(e),
            Self::Cadet(e) => Some(e),
            Self::Native(e) => Some(e),
            Self::Admin(e) => Some(e),
            Self::Protocol(e) => Some(e),
        }
    }
}
impl From<tun::AdminFailure> for Error {
    fn from(e: tun::AdminFailure) -> Self {
        Self::Admin(e)
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Native(e)
    }
}
impl From<cadet::Error> for Error {
    fn from(e: cadet::Error) -> Self {
        Self::Cadet(e)
    }
}
impl From<server::Error> for Error {
    fn from(e: server::Error) -> Self {
        Self::Ipc(e)
    }
}
/// Caller-provided actual physical owners. Their pools have independent lifetimes.
pub struct Parts<'id, 'store, 'bytes, 'cadet, 'cstore> {
    /// Original real local SERVICE owner and its borrowed pure engine.
    pub server: server::Server<'id, 'store, 'bytes>,
    /// One exclusive shared native CADET CLIENT, fresh with no channel/port work.
    pub cadet: cadet::Client<'cadet, 'cstore>,
    /// Actual original native TUN or helper packet owner with explicit policy.
    pub device: Device,
}
/// Failed construction returns every original physical owner for explicit cleanup
/// or correction; it does not silently drop an attached MQ or already-open FD.
pub struct BuildFailure<P> {
    /// Actual refusal before configuration/business admission.
    pub error: Error,
    /// All original actual owners, unchanged by the refused build.
    pub parts: P,
}
/// Canonical destination network for an explicitly configured Internet exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Network {
    /// Canonical destination prefix bytes.
    pub address: core::Address,
    /// Network prefix bits through32/128.
    pub bits: u8,
}
impl Network {
    /// Validate canonical prefix/family without guessing an AF platform value.
    pub fn validate(self) -> Result<(), Fault> {
        let width = if self.address.family() == core::Family::V4 {
            32
        } else {
            128
        };
        if usize::from(self.bits) > width {
            return Err(Fault::InvalidInput);
        }
        let h = width - usize::from(self.bits);
        let mask = if h == 128 { 0 } else { u128::MAX << h };
        if number(self.address) & mask != number(self.address) {
            return Err(Fault::InvalidInput);
        }
        Ok(())
    }
    pub(super) fn matches(self, address: core::Address) -> bool {
        if self.address.family() != address.family() {
            return false;
        }
        let width = if address.family() == core::Family::V4 {
            32
        } else {
            128
        };
        let h = width - usize::from(self.bits);
        let mask = if h == 128 { 0 } else { u128::MAX << h };
        number(address) & mask == number(self.address)
    }
}
fn number(a: core::Address) -> u128 {
    match a {
        core::Address::V4(b) => u128::from(u32::from_be_bytes(b)),
        core::Address::V6(b) => u128::from_be_bytes(b),
    }
}
/// An actual caller-authorized fixed exit policy. The separate External mode
/// accepts results from the application's actual REGEX discovery owner.
#[derive(Clone, Copy, Debug)]
pub struct ConfiguredExit {
    /// Optional canonical destination prefix; None matches any.
    pub network: Option<Network>,
    /// Original kernel protocol filter; None matches any.
    pub protocol: Option<u8>,
    /// Inclusive desired destination port range.
    pub ports: (u16, u16),
    /// Actual explicitly configured expected peer.
    pub peer: [u8; 32],
    /// Explicit actual peer endpoint AF profile, not detected from length.
    pub af: core::AfProfile,
}
/// Original discovery port mode. No variant silently starts a Resolver/REGEX job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryMode {
    /// Use only caller-provided fixed policies; no match fails genuinely.
    Configured,
    /// Offer bounded original requests to the caller's real discovery provider.
    External,
}
/// Explicit native coordination budgets, independent of pure packet-pool bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum live flow/channel mappings, including native close debt.
    pub flows: usize,
    /// Actual desired MTU verified/applied before source readiness.
    pub mtu: u32,
    /// Original complete configure+route+DAD operation budget.
    pub control_timeout: Duration,
    /// Original finite received-packet capacity/processing budget.
    pub input_timeout: Duration,
    /// Original raw TUN packet admission-to-whole-write budget.
    pub tun_send_timeout: Duration,
    /// Original CADET frame admission-to-actual-MQ-retirement budget.
    pub cadet_send_timeout: Duration,
    /// Original shutdown through forced physical-source close.
    pub shutdown_grace: Duration,
    /// Actual repeated IPv6 sampling options.
    pub ipv6_watch: tun::Ipv6WatchOptions,
    /// Completed ready-state monitoring query lifetime; each finished sample may
    /// start a distinct query, while unfinished initial DAD never renews its budget.
    pub monitor_timeout: Duration,
    /// Explicit default actual endpoint profile for named services.
    pub service_af: core::AfProfile,
    /// Actual Internet-exit discovery policy mode.
    pub discovery: DiscoveryMode,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            flows: 64,
            mtu: 1280,
            control_timeout: Duration::from_secs(10),
            input_timeout: Duration::from_secs(5),
            tun_send_timeout: Duration::from_secs(5),
            cadet_send_timeout: Duration::from_secs(10),
            shutdown_grace: Duration::from_secs(10),
            ipv6_watch: tun::Ipv6WatchOptions::default(),
            monitor_timeout: Duration::from_secs(3),
            service_af: core::AfProfile::native(),
            discovery: DiscoveryMode::Configured,
        }
    }
}
/// Actual cumulative local observations; none proves downstream IP/peer delivery.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual TUN packets read.
    pub tun_read: u64,
    /// Actual whole packets accepted by a direct native TUN write.
    pub tun_written: u64,
    /// Whole official frames accepted by the helper stdin pipe. This does not
    /// prove that the helper wrote the packet to its kernel TUN descriptor.
    pub helper_submitted: u64,
    /// Consumed input packets explicitly refused/dropped.
    pub dropped: u64,
    /// Actual complete peer application frames written locally.
    pub peer_written: u64,
    /// Actual shared CADET source losses.
    pub cadet_losses: u64,
    /// Actual original raw TUN source losses.
    pub tun_losses: u64,
    /// Original native control successes, not synthetic readiness.
    pub native_applied: u64,
    /// Actual correlated kernel route ACK successes.
    pub route_acks: u64,
    /// Actual explicit configured-exit selections.
    pub configured: u64,
}
/// One fair bounded progress result. Waiting cancellation changes no work owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual IO/control/owner work progressed.
    Activity,
    /// Caller observation deadline only.
    WaitDeadline,
    /// Local shutdown completed or its real hard-close report is ready.
    Stopped,
}
/// Synchronous actual observations; callbacks cannot reenter this borrowed owner.
pub enum Event<'id, 'cadet> {
    /// Actual local IPC fact.
    Ipc(server::Event<'id>),
    /// Actual concrete native configuration receipt.
    Applied(tun::NativeApplied),
    /// Actual read-only source-bound interface snapshot.
    Snapshot(tun::NativeSnapshot),
    /// Actual exact route query; writing its request is never a result.
    RouteQuery(tun::RouteQueryCompletion),
    /// Actual original kernel route transaction result.
    Route(tun::RouteCompletion),
    /// Actual original address-readiness observation.
    Ipv6(tun::Ipv6Observation),
    /// Original watcher physically retired.
    Ipv6Ended(tun::Ipv6Completion),
    /// Actual original native configuration failed/refused.
    ControlFailed(tun::ApplyFailure),
    /// Original exposed route work lacks a proof excluding late kernel effects;
    /// independent source close is attempted while this debt remains Unknown.
    CleanupUncertain {
        /// Actual incomplete-cleanup classification.
        reason: Fault,
    },
    /// Real platform/configuration error not labeled applied.
    NativeError(io::Error),
    /// Actual expected-peer source connected at local service level.
    BackendConnected(cadet::Epoch<'cadet>),
    /// Original shared native MQ physically stopped.
    BackendLost {
        /// Exact original partial/write/source facts.
        report: cadet::Loss<'cadet>,
        /// Original independently retained native cause.
        cause: cadet::LossCause,
    },
    /// Original real backend connection failed; owner chooses retry.
    BackendRetry {
        /// Actual errno.
        error: io::Error,
        /// Actual retry delay.
        retry_after: Duration,
    },
    /// Actual original TUN physically stopped; route cleanup is independent.
    TunLost(tun::Loss),
    /// Original exact core peer retired.
    PeerLost(core::PeerLoss<'id>),
    /// Original exact core TUN retired logically after actual device stop.
    TunCoreLost(core::TunLoss<'id>),
    /// Whole official frame accepted by the original helper stdin pipe. This
    /// is neither a helper TUN-write receipt nor downstream packet processing.
    HelperSubmitted {
        /// Original helper pipe write.
        write: tun::WriteId,
        /// Original pure effect.
        effect: core::Effect<'id>,
        /// Complete raw IP byte count, excluding helper/PI framing.
        bytes: usize,
    },
    /// Whole original queued raw packet wrote; no IP delivery claim.
    TunWritten {
        /// Original write identity.
        write: tun::WriteId,
        /// Exact pure output.
        effect: core::Effect<'id>,
        /// Actual raw packet bytes.
        bytes: usize,
    },
    /// Exact original CADET application frame fully wrote on its MQ.
    PeerWritten {
        /// Original native attempt.
        transmit: cadet::Transmit<'cadet>,
        /// Original pure output.
        effect: core::Effect<'id>,
    },
    /// Original frame continued draining after its logical channel retired.
    RetiredWrite {
        /// Original native attempt.
        transmit: cadet::Transmit<'cadet>,
        /// Original pure effect.
        effect: core::Effect<'id>,
        /// Actual whole frame, otherwise positive prefix.
        complete: bool,
    },
    /// Explicit original bounded input refusal; no successful forwarding claimed.
    Dropped {
        /// Original logical flow if already admitted.
        flow: Option<core::Flow<'id>>,
        /// Actual refusal classification.
        reason: Fault,
    },
    /// Actual bounded external discovery work offered; caller must use original token.
    Discovery(core::DiscoveryRequest<'id>),
}
/// Independently owned original cleanup errors. Taking these transfers each
/// actual error once; no field is a new close attempt or success receipt.
#[derive(Debug, Default)]
pub struct CleanupErrors {
    /// Original coordinator cleanup/protocol/native failure.
    pub failure: Option<Error>,
    /// Independent original local IPC cleanup error.
    pub ipc: Option<server::Error>,
    /// Original errno retained from an earlier physical TUN loss.
    pub prior_tun: Option<io::Error>,
    /// Original native control close errno.
    pub control: Option<io::Error>,
    /// Actual close errno from the final retained original TUN.
    pub tun: Option<io::Error>,
}
impl CleanupErrors {
    /// All original error objects have been transferred or were absent.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.failure.is_none()
            && self.ipc.is_none()
            && self.prior_tun.is_none()
            && self.control.is_none()
            && self.tun.is_none()
    }
}
impl fmt::Display for CleanupErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VPN cleanup coordinator={:?}; IPC={:?}; prior TUN close={:?}; control close={:?}; final TUN close={:?}",
            self.failure, self.ipc, self.prior_tun, self.control, self.tun
        )
    }
}
impl std::error::Error for CleanupErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.failure
            .as_ref()
            .map(|e| e as &dyn std::error::Error)
            .or_else(|| self.ipc.as_ref().map(|e| e as &dyn std::error::Error))
            .or_else(|| self.prior_tun.as_ref().map(|e| e as &dyn std::error::Error))
            .or_else(|| self.control.as_ref().map(|e| e as &dyn std::error::Error))
            .or_else(|| self.tun.as_ref().map(|e| e as &dyn std::error::Error))
    }
}
/// Actual independent forced-close report, without remote-processing claims.
pub struct Close<'cadet> {
    /// Actual local IPC close results.
    pub ipc: server::Shutdown,
    /// Actual original backend MQ stop report, if still attached.
    pub cadet: Option<cadet::Loss<'cadet>>,
    /// Actual original device stop report, if still retained.
    pub tun: Option<tun::Loss>,
    /// Independent close errno from an earlier observed TUN loss. The original
    /// loss was delivered through Event; it never proves kernel route removal.
    pub prior_tun_close_error: Option<io::Error>,
    /// First independent native snapshot/route/query/watcher close errno.
    pub control_close_error: Option<io::Error>,
    /// Actual native control closes whose success remains unconfirmed. Their
    /// original descriptors are never retried after close may have reused them.
    pub unconfirmed_control_closes: u64,
    /// Original unresolved owned OS-route effects.
    pub routes: core::RouteState,
    /// Original core flows retained after physical cleanup.
    pub flows: usize,
    /// Original core packet/outcome rows retained.
    pub buffers: usize,
    /// Actual original discovery jobs still owed to external provider.
    pub discoveries: usize,
    /// First independent failure after attempting all physical sources.
    pub failure: Option<Error>,
    /// Actual local counters.
    pub report: Report,
}

/// Current bounded resource debt; route variants distinguish external borrowing
/// from owned effects. This is not a downstream application-delivery claim.
#[derive(Clone, Copy, Debug)]
pub struct Debt {
    /// Actual native control closes whose success remains unconfirmed.
    pub unconfirmed_control_closes: u64,
    /// Actual logical route provenance/effect state.
    pub routes: core::RouteState,
    /// Original unretired flow rows.
    pub flows: usize,
    /// Original unretired shared buffers.
    pub buffers: usize,
    /// Original admitted external discovery jobs not yet physically retired.
    pub discoveries: usize,
}
