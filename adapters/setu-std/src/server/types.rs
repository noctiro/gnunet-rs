use super::*;
/// Original failure, retaining concrete native/dependency causes.
#[derive(Debug)]
pub enum Error {
    /// Actual local socket error.
    Io(io::Error),
    /// Actual protocol/resource/clock classification.
    Protocol(Fault),
    /// Actual CADET CLIENT endpoint/clock/Resolver/native failure.
    Cadet(cadet::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Protocol(e) => e.fmt(f),
            Self::Cadet(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            Self::Cadet(e) => Some(e),
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
impl From<cadet::Error> for Error {
    fn from(e: cadet::Error) -> Self {
        Self::Cadet(e)
    }
}
/// Explicit independent native resources and original finite deadlines.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actual app MQs (match pure service capacity).
    pub clients: usize,
    /// Maximum original CADET listener/bind owners.
    pub ports: usize,
    /// Maximum original CADET channel/open/first-request owners.
    pub channels: usize,
    /// Complete app IPC frame limit,4..65535.
    pub frame_bytes: usize,
    /// Maximum bytes in one actual app syscall.
    pub io_slice_bytes: usize,
    /// Complete original queued app frames per MQ.
    pub output_frames: usize,
    /// Retained original queued app bytes per MQ, plus one bounded held frame.
    pub output_bytes: usize,
    /// Original whole operation/incoming-first-frame lifetime; never reset.
    pub operation_lifetime: Duration,
    /// Finite original partial/control write and physical-close grace.
    pub retirement_grace: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            clients: 32,
            ports: 32,
            channels: 64,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            output_frames: 4,
            output_bytes: 262140,
            operation_lifetime: Duration::from_secs(300),
            retirement_grace: Duration::from_secs(5),
        }
    }
}
impl Limits {
    pub(super) fn validate(self) -> Result<(), Error> {
        if self.clients == 0
            || self.ports == 0
            || self.channels == 0
            || !(24..=65535).contains(&self.frame_bytes)
            || self.io_slice_bytes == 0
            || self.output_frames == 0
            || self.output_bytes < self.frame_bytes
            || self.operation_lifetime.is_zero()
            || self.retirement_grace.is_zero()
        {
            return Err(Fault::Capacity.into());
        }
        for d in [self.operation_lifetime, self.retirement_grace] {
            let n = u64::try_from(d.as_micros()).map_err(|_| Fault::Overflow)?;
            if n == 0 || n == u64::MAX || Instant::now().checked_add(d).is_none() {
                return Err(Fault::Overflow.into());
            }
        }
        Ok(())
    }
}
/// Actual original app MQ retirement cause.
#[derive(Debug)]
pub enum CloseCause {
    /// Clean original native EOF.
    Eof,
    /// Actual native/protocol admission or processing failure.
    Fault(Error),
    /// Explicit requested service stop.
    Shutdown,
    /// Original finite output drain budget elapsed.
    Deadline,
}
/// Synchronous observations after real bounded owner changes.
#[derive(Debug)]
pub enum Event<'id> {
    /// Shared native socket option/accept diagnostic.
    Socket(SocketEvent),
    /// Actual unadmitted source rejected by ACL/kernel credentials.
    Rejected(PeerAddress),
    /// Actual source admission failure.
    AdmissionFailed(Error),
    /// Actual app MQ attached, granting no peer authority.
    Accepted(CoreClient),
    /// Actual complete official app input was accepted.
    Input(CoreClient),
    /// Actual immutable original app output entered its bounded queue.
    Queued(CoreClient),
    /// Positive actual app socket progress.
    Write {
        /// Original app MQ.
        client: CoreClient,
        /// Positive native byte count.
        bytes: usize,
        /// Complete original frame written.
        complete: bool,
    },
    /// App socket was physically closed before its pure callback.
    Closed {
        /// Original actual app MQ.
        client: CoreClient,
        /// Original cause.
        cause: CloseCause,
    },
    /// Actual original CADET MQ loss, after physical detach.
    CadetLost {
        /// Exact old epoch/prefix report.
        report: cadet::Loss<'id>,
        /// Original native/protocol loss.
        cause: cadet::LossCause,
    },
    /// Actual original endpoint attempt failed; original owner selected retry.
    CadetRetry {
        /// Actual native cause.
        error: io::Error,
        /// Actual source-selected delay.
        retry_after: Duration,
    },
    /// Actual port/operation refusal. Never a synthetic peer or native ACK.
    Refused {
        /// Exact operation when already established.
        operation: Option<Operation>,
        /// Actual local classification.
        error: Fault,
    },
}
/// One bounded scheduler outcome. WaitDeadline only ends observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual IO/domain/control/algorithm progress.
    Activity,
    /// Caller observation deadline elapsed.
    WaitDeadline,
    /// Actual source cleanup completed after requested shutdown.
    Stopped,
}
/// Local actual counters; no field claims remote application receipt.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Actually admitted app sockets.
    pub accepted: u64,
    /// Physically closed app sockets.
    pub closed: u64,
    /// Complete official app inputs accepted.
    pub inputs: u64,
    /// Positive app bytes written.
    pub written_bytes: u64,
    /// Complete app frames written.
    pub written_frames: u64,
    /// Actual CADET payload writes completed.
    pub peer_frames: u64,
    /// Actual outer CADET DATA processing acknowledgments written.
    pub receive_done: u64,
    /// Actual CADET MQ losses/explicit resets.
    pub cadet_losses: u64,
}
/// Explicit physical cleanup facts; unknown native error is retained.
#[must_use]
pub struct Shutdown {
    /// Actual local counters after physical cleanup.
    pub report: Report,
    /// First actual independent cleanup refusal.
    pub failure: Option<Error>,
}
