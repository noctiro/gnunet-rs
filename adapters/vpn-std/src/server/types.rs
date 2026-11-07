use super::*;
/// Original actual native or protocol/clock failure.
#[derive(Debug)]
pub enum Error {
    /// Concrete native socket error.
    Io(io::Error),
    /// Original core/clock/resource classification.
    Protocol(Fault),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
        }
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
/// Fixed local MQ metadata, native frame and original deadline bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actual admitted local MQs; pure client pool remains independent.
    pub clients: usize,
    /// Maximum retained original request debts per MQ.
    pub requests_per_client: usize,
    /// Complete input frame limit,128..65535. Official requests fit128 bytes.
    pub frame_bytes: usize,
    /// Maximum bytes offered to one native read/write syscall.
    pub io_slice_bytes: usize,
    /// First-byte through complete request admission, including Capacity waits.
    pub input_timeout: Duration,
    /// Oldest current request admission through draining all outstanding replies;
    /// never reset by preparation, partial progress or more pipelined requests.
    pub send_timeout: Duration,
    /// Original soft shutdown through forced actual physical MQ close.
    pub shutdown_grace: Duration,
    /// Maximum idle logical-expiry/source wake interval,1ms..1s.
    pub maintenance_interval: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 32,
            requests_per_client: 32,
            frame_bytes: 128,
            io_slice_bytes: 65535,
            input_timeout: Duration::from_secs(5),
            send_timeout: Duration::from_secs(5),
            shutdown_grace: Duration::from_secs(5),
            maintenance_interval: Duration::from_millis(100),
        }
    }
}
impl Limits {
    pub(super) fn validate(self) -> Result<(), Error> {
        if self.clients == 0
            || self.requests_per_client == 0
            || !(128..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.maintenance_interval < Duration::from_millis(1)
            || self.maintenance_interval > Duration::from_secs(1)
        {
            return Err(Fault::InvalidInput.into());
        }
        for d in [
            self.input_timeout,
            self.send_timeout,
            self.shutdown_grace,
            self.maintenance_interval,
        ] {
            if d.is_zero() || Instant::now().checked_add(d).is_none() {
                return Err(Fault::InvalidInput.into());
            }
        }
        self.clients
            .checked_mul(self.requests_per_client)
            .ok_or(Fault::Overflow)?;
        Ok(())
    }
}
/// Actual original MQ stop cause. Physical close precedes pure loss callbacks.
#[derive(Debug)]
pub enum CloseCause {
    /// Actual clean native EOF between frames.
    Eof,
    /// Original input/send/soft-drain finite deadline.
    Deadline,
    /// Explicit caller shutdown.
    Shutdown,
    /// Actual native/protocol/clock failure.
    Fault(Error),
}
impl CloseCause {
    pub(super) const fn fault(&self) -> Fault {
        match self {
            Self::Deadline => Fault::Deadline,
            Self::Fault(Error::Protocol(e)) => *e,
            Self::Eof | Self::Shutdown | Self::Fault(Error::Io(_)) => Fault::Closed,
        }
    }
}
/// Synchronous actual IPC facts. No event claims route/exit/remote success.
#[derive(Debug)]
pub enum Event<'id> {
    /// Canonical accept/socket option evidence.
    Socket(SocketEvent),
    /// Actual unadmitted MQ refused by ACL/Unix credentials.
    Rejected(PeerAddress),
    /// Actual canonical socket could not be admitted; it was closed.
    AdmissionFailed(Error),
    /// Actual original MQ attached to the pure client pool.
    Accepted(Client<'id>),
    /// Complete original RX retained after actual core/local request Capacity;
    /// existing original TX continues. Emitted once per blocked input episode.
    Backpressured(Client<'id>),
    /// Exact official request admitted; no OS/exit outcome is inferred.
    Input {
        /// Original actual MQ.
        client: Client<'id>,
        /// Original request debt.
        request: Request<'id>,
        /// Original opaque wire RID bytes.
        request_id: [u8; 8],
    },
    /// Immutable original response entered its actual bounded MQ queue.
    Queued {
        /// Original actual MQ.
        client: Client<'id>,
        /// Original response/request authority.
        request: Request<'id>,
        /// Original source-bound immutable effect.
        effect: Effect<'id>,
    },
    /// Positive actual native socket progress, not remote application receipt.
    Write {
        /// Original actual MQ.
        client: Client<'id>,
        /// Original response authority.
        request: Request<'id>,
        /// Actual positive native byte count.
        bytes: usize,
        /// Entire original response physically written to this socket.
        complete: bool,
    },
    /// Original settled response row actually released for reuse. Its logical
    /// allocation lease, if any, remains independent of callback ownership.
    Retired {
        /// Original actual MQ.
        client: Client<'id>,
        /// Exact original request, never rebound from a bare RID.
        request: Request<'id>,
        /// Last actual native response outcome and original lease/RID facts.
        info: RequestInfo<'id>,
    },
    /// Actual original MQ physically stopped before pure loss/request retirement.
    Closed {
        /// Original actual source.
        client: Client<'id>,
        /// Actual stop cause.
        cause: CloseCause,
        /// Actual pure loss summary; None means callback itself failed.
        loss: Option<gnunet_vpn::Loss>,
    },
    /// Independent original cleanup callback failure after physical closure.
    CleanupFailed(Fault),
}
/// One caller-driven bounded scheduling step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual native/domain/expiry progress.
    Activity,
    /// This caller's observation wait ended; original work remains retained.
    WaitDeadline,
    /// Requested local IPC stop physically completed. Other engine ports remain
    /// the coordinator's responsibility and are not claimed quiescent.
    Stopped,
}
/// Actual local IPC counters only.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actual MQ admissions.
    pub accepted: u64,
    /// Actual physical MQ closures.
    pub closed: u64,
    /// Complete original request admissions.
    pub inputs: u64,
    /// Complete original response queue admissions.
    pub queued: u64,
    /// Positive actual response bytes.
    pub written_bytes: u64,
    /// Complete original response writes.
    pub written_frames: u64,
    /// Actual original request metadata retirements.
    pub retired_requests: u64,
}
/// Independent actual IPC shutdown report; does not claim full VPN shutdown.
#[must_use]
pub struct Shutdown {
    /// Actual local native counters after every physical MQ was closed.
    pub report: Report,
    /// First actual independent logical cleanup error, if any.
    pub failure: Option<Error>,
}
