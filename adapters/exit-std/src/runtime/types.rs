use super::*;
/// Actual dependency/native/resource/clock refusal, retaining concrete causes.
#[derive(Debug)]
pub enum Error {
    /// Actual native OS error.
    Io(io::Error),
    /// Actual original sealed kernel observation/query failure.
    Admin(tun::AdminFailure),
    /// Actual entropy provider object retained unchanged during retirement.
    Entropy(getrandom::Error),
    /// Actual CADET CLIENT cause.
    Cadet(cadet::Error),
    /// Actual core/configuration/clock classification.
    Core(Fault),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Admin(e) => e.fmt(f),
            Self::Entropy(e) => write!(f, "actual EXIT entropy provider: {e:?}"),
            Self::Cadet(e) => e.fmt(f),
            Self::Core(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Admin(e) => Some(e),
            Self::Entropy(_) => None,
            Self::Cadet(e) => Some(e),
            Self::Core(e) => Some(e),
        }
    }
}
impl From<tun::AdminFailure> for Error {
    fn from(error: tun::AdminFailure) -> Self {
        Self::Admin(error)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<cadet::Error> for Error {
    fn from(e: cadet::Error) -> Self {
        Self::Cadet(e)
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Core(e)
    }
}
/// Explicit actual endpoint registration; no discovery or remote acceptance.
#[derive(Clone, Copy, Debug)]
pub struct Binding {
    /// Exact official CADET port hash.
    pub hash: [u8; 64],
    /// Exact target selected by that real bound port.
    pub target: Target,
}
impl Binding {
    /// Official Internet-family gateway hash.
    #[must_use]
    pub fn internet(family: gnunet_vpn::Family) -> Self {
        Self {
            hash: gnunet_vpn::gateway_port(family),
            target: Target::Internet(family),
        }
    }
    /// Official DNS exit application port hash, never a DHT advertisement.
    #[must_use]
    pub fn dns() -> Self {
        Self {
            hash: gnunet_crypto::hash512(b"exit-dns"),
            target: Target::Dns,
        }
    }
    /// Exact configured service CADET descriptor/port binding.
    #[must_use]
    pub const fn service(hash: [u8; 64]) -> Self {
        Self {
            hash,
            target: Target::Service(hash),
        }
    }
}
/// Actual local application port state for an explicit external advertiser.
#[derive(Clone, Copy, Debug)]
pub struct BindingStatus {
    /// Original exact configuration.
    pub binding: Binding,
    /// Only actual PORT_OPEN writing on the current MQ, not
    /// published regex/DHT discovery or remote application acceptance.
    pub announced: bool,
}
/// Explicit actual numeric DNS resolver. No ambient/system hostname lookup.
#[derive(Clone, Copy, Debug)]
pub struct Resolver {
    /// Exact configured IP, port, scope.
    pub server: SocketAddr,
    /// Original retries retain the same job/socket/query/id.
    pub retry: Duration,
}
/// Independent bounded native resources. Whole packets and old MQ frames never
/// migrate to a replacement source; all deadlines are original admission targets.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actual listening ports.
    pub ports: usize,
    /// Maximum accepted original channels.
    pub channels: usize,
    /// Maximum nested frames in one original outer DATA.
    pub inner_frames: usize,
    /// Maximum simultaneous actual DNS sockets/jobs.
    pub dns_jobs: usize,
    /// Maximum DNS packet bytes (query and complete response).
    pub dns_bytes: usize,
    /// Maximum question records checked per DNS packet.
    pub dns_questions: usize,
    /// Original partial/control/whole-output native grace.
    pub io_grace: Duration,
    /// Actual first-input lifetime for an idle new channel.
    pub first_input: Duration,
    /// Original held TUN-packet backpressure budget.
    pub tun_input: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            ports: 32,
            channels: 64,
            inner_frames: 64,
            dns_jobs: 32,
            dns_bytes: 4096,
            dns_questions: 16,
            io_grace: Duration::from_secs(5),
            first_input: Duration::from_secs(30),
            tun_input: Duration::from_secs(5),
        }
    }
}
impl Limits {
    pub(super) fn validate(self, core: &Engine<'_>) -> Result<(), Error> {
        if self.ports == 0
            || self.channels == 0
            || self.inner_frames == 0
            || self.dns_jobs == 0
            || !(12..=65535).contains(&self.dns_bytes)
            || self.dns_questions > 128
            || self
                .channels
                .checked_mul(self.inner_frames)
                .is_none_or(|n| n > core.processing_capacity())
        {
            return Err(Fault::Capacity.into());
        }
        for d in [self.io_grace, self.first_input, self.tun_input] {
            if d.is_zero() || Instant::now().checked_add(d).is_none() {
                return Err(Fault::Overflow.into());
            }
        }
        Ok(())
    }
}
/// Explicit OS entropy port. Construction performs no IO; getrandom is called
/// only when the actual core admits a request needing entropy.
#[derive(Default)]
pub struct OsEntropy {
    last: Option<getrandom::Error>,
}
impl Entropy for OsEntropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Fault> {
        getrandom::fill(out).map_err(|e| {
            self.last = Some(e);
            Fault::EntropyUnavailable
        })
    }
}
impl OsEntropy {
    /// Retrieve the original concrete provider failure after a core
    /// entropy classification. No fallback random value is generated.
    pub fn take_failure(&mut self) -> Option<getrandom::Error> {
        self.last.take()
    }
}
/// Original source/protocol observations; none asserts downstream delivery.
#[derive(Debug)]
pub enum Event<'id> {
    /// Actual CADET attachment.
    Connected(cadet::Epoch<'id>),
    /// Actual physical old-MQ loss and exposure facts.
    CadetLost {
        /// Exact original report.
        report: cadet::Loss<'id>,
        /// Actual original cause.
        cause: cadet::LossCause,
    },
    /// Actual endpoint attempt failed; its own retry remains.
    ConnectRetry {
        /// Original actual OS error.
        error: io::Error,
        /// Original selected source delay.
        retry_after: Duration,
    },
    /// Actual channel admission refused, followed by its real close.
    Refused {
        /// Original actual channel.
        channel: cadet::Channel<'id>,
        /// Real local resource/protocol classification.
        error: Fault,
    },
    /// Actual verified TUN source closed, including partial uncertainty.
    TunLost(tun::Loss),
    /// Actual raw IP input was consumed and explicitly dropped.
    TunDropped(Fault),
    /// Actual pure flow became physically quiescent.
    FlowClosed(core::Closed),
    /// Actual literal DNS socket/result/cancel failure.
    DnsFailed {
        /// Exact original job.
        job: core::Dns,
        /// Concrete native/classified cause.
        error: Error,
    },
    /// Actual complete DNS datagram from another endpoint/id/question
    /// was consumed without authorizing a result.
    DnsDiscarded {
        /// Exact job still awaiting its own valid result.
        job: core::Dns,
        /// Actual observed sender endpoint.
        source: SocketAddr,
    },
    /// Original whole data/control/processing transfer progressed.
    Activity,
}
/// One bounded caller-driven observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Real native/domain progress.
    Activity,
    /// Only this caller wait expired, preserving all owned sources.
    WaitDeadline,
    /// All actual native sources and core IO debts are retired.
    Stopped,
}
/// Actual local counters, never a remote application delivery count.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual original accepted channels.
    pub channels: u64,
    /// Complete actual original whole TUN writes.
    pub tun_written: u64,
    /// Whole frames accepted by helper stdin; not kernel injection/delivery.
    pub helper_submitted: u64,
    /// Actual original native DATA writes completed.
    pub peer_written: u64,
    /// Original actual outer receive_done frames completed.
    pub receive_done: u64,
    /// Actual DNS query datagram writes.
    pub dns_written: u64,
    /// Actual valid original DNS responses accepted.
    pub dns_replies: u64,
    /// Actual normalized native TUN packets read.
    pub tun_read: u64,
    /// Complete validated packet frames read from helper stdout; not a native
    /// TUN-read or peer authentication receipt.
    pub helper_received: u64,
}
/// Actual independent source-cleanup result. No clock is required to obtain it.
#[must_use]
pub struct Shutdown {
    /// Final true local counters.
    pub report: Report,
    /// First actual independent cleanup refusal.
    pub failure: Option<Error>,
    /// Core IO-debt state only, after transport close attempts. This never
    /// asserts that a retained helper has been reaped; reap_helper is separate.
    pub quiescent: bool,
}

/// Original actual runtime owners, returned intact on helper-capable refusal.
pub struct Parts<'cfg, 'id, 'slots, E: Entropy> {
    /// Original pure runtime state.
    pub engine: Engine<'cfg>,
    /// Original actual CADET source owner.
    pub cadet: cadet::Client<'id, 'slots>,
    /// Original native descriptor or already-spawned helper.
    pub tun: Option<PacketSource>,
    /// Original entropy port, without invoking it.
    pub entropy: E,
}
/// Constructor refusal does not drop an admitted child and call it completion.
#[must_use]
pub struct BuildFailure<'cfg, 'id, 'slots, E: Entropy> {
    /// Actual original refusal.
    pub error: Error,
    /// Every original linear owner for explicit cleanup/wait.
    pub parts: Parts<'cfg, 'id, 'slots, E>,
}
