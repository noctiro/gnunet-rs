//! Native receipt facts and retained failed owners.
use super::BoundedOutput;
use std::{
    error::Error,
    fmt, io,
    sync::atomic::{AtomicU64, Ordering},
};
/// Lower-bound receipts for this output owner. `flushed` is a completed writer
/// flush, not a filesystem durability barrier or downstream reader receipt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Snapshot {
    /// Bytes submitted to original I/O work, including a possibly pending job.
    pub submitted: u64,
    /// Positive native write return counts observed by that original job.
    pub written: u64,
    /// Written prefix followed by a successful actual flush.
    pub flushed: u64,
    /// Admitted bytes still held only in the caller's bounded buffer.
    pub buffered: usize,
    /// Unsubmitted tail explicitly discarded after failure.
    pub discarded: u64,
    /// An original job/outcome remains uncollected, or supervisor failure
    /// prevents proving retirement.
    pub pending: bool,
}
#[derive(Default)]
pub(super) struct Counts {
    submitted: AtomicU64,
    written: AtomicU64,
    flushed: AtomicU64,
}
impl Counts {
    pub(super) fn submit(&self, bytes: u64) {
        let _previous = self
            .submitted
            .try_update(Ordering::Release, Ordering::Relaxed, |old| {
                Some(old.saturating_add(bytes))
            });
    }
    pub(super) fn written(&self, bytes: u64) {
        let _previous = self
            .written
            .try_update(Ordering::Release, Ordering::Relaxed, |old| {
                Some(old.saturating_add(bytes))
            });
    }
    pub(super) fn flushed(&self) {
        self.flushed
            .store(self.written.load(Ordering::Acquire), Ordering::Release);
    }
    pub(super) fn snapshot(&self, buffered: usize, discarded: u64, pending: bool) -> Snapshot {
        let flushed = self.flushed.load(Ordering::Acquire);
        let written = self.written.load(Ordering::Acquire);
        let submitted = self.submitted.load(Ordering::Acquire);
        Snapshot {
            submitted,
            written,
            flushed,
            buffered,
            discarded,
            pending,
        }
    }
}
#[derive(Debug)]
pub(super) enum Cause {
    Native(io::Error),
    Deadline,
    Stop,
    StopSource(io::Error),
    Supervisor,
}
impl Cause {
    pub(super) fn kind(&self) -> io::ErrorKind {
        match self {
            Self::Native(error) | Self::StopSource(error) => error.kind(),
            Self::Deadline => io::ErrorKind::TimedOut,
            Self::Stop => io::ErrorKind::Other,
            Self::Supervisor => io::ErrorKind::BrokenPipe,
        }
    }
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(error) => write!(f, "native output: {error}"),
            Self::Deadline => f.write_str("original output deadline elapsed"),
            Self::Stop => f.write_str("native stop observed while output was pending"),
            Self::StopSource(error) => write!(f, "native output stop source: {error}"),
            Self::Supervisor => f.write_str("original output supervisor ended without a receipt"),
        }
    }
}
impl Error for Cause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Native(error) | Self::StopSource(error) => Some(error),
            _ => None,
        }
    }
}
/// A failed output owner. Keeping this value retains its pending original I/O
/// capability; dropping it detaches any blocking call, without claiming stop.
pub struct Failure {
    pub(super) owner: Box<BoundedOutput>,
}
impl Failure {
    /// Inspect actual receipts without retrying, joining or renewing any work.
    pub fn snapshot(&self) -> Snapshot {
        self.owner.snapshot()
    }
}
impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutputFailure")
            .field("cause", &self.owner.cause)
            .field("receipts", &self.snapshot())
            .finish()
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.owner.cause {
            Some(cause) => write!(f, "{cause}; {:?}", self.snapshot()),
            None => write!(f, "output outcome unavailable; {:?}", self.snapshot()),
        }
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.owner.cause.as_deref().map(|cause| cause as &dyn Error)
    }
}
