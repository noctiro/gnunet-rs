//! Bounded original native IO for both HTTP clients and explicit accepted servers.
use crate::{Error, Fault, SocketDiagnostic, State};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    cell::Cell,
    io,
    pin::Pin,
    rc::Rc,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};
/// Actual original native byte/socket-attempt observations, never remote ACKs.
#[derive(Clone, Copy, Debug, Default)]
pub struct WireReport {
    /// Actual received bytes.
    pub read: usize,
    /// Actual locally written bytes.
    pub written: usize,
    /// Actual socket attempts, never remote processing.
    pub probes: usize,
}
/// Shared exact native-byte counters, also usable by an accepted-server owner.
#[derive(Default)]
pub struct Counters {
    pub(crate) read: AtomicUsize,
    pub(crate) written: AtomicUsize,
    pub(crate) probes: AtomicUsize,
    pub(crate) diagnostics: Mutex<Vec<SocketDiagnostic>>,
    pub(crate) progress: Option<Arc<State>>,
}
impl Counters {
    pub(crate) fn reserved(probes: usize, progress: Arc<State>) -> Result<Self, Error> {
        let mut diagnostics = Vec::new();
        diagnostics
            .try_reserve_exact(probes.checked_mul(2).ok_or(Fault::Overflow)?)
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            diagnostics: Mutex::new(diagnostics),
            progress: Some(progress),
            ..Default::default()
        })
    }
    pub(crate) fn take_diagnostics(&self) -> Result<Vec<SocketDiagnostic>, Error> {
        let mut diagnostics = self.diagnostics.lock().map_err(|_| Fault::Conflict)?;
        Ok(std::mem::take(&mut *diagnostics))
    }
    /// Actual native byte and socket-attempt counters.
    pub fn report(&self) -> WireReport {
        WireReport {
            read: self.read.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            probes: self.probes.load(Ordering::Relaxed),
        }
    }
}

/// Explicit live expiry guard. It never creates an HTTP response receipt.
pub struct IoLease {
    /// Exact caller-owned source clock.
    pub clock: Arc<dyn RuntimeClock>,
    /// Original logical expiry, or a stricter signed-publication expiry.
    pub until: Cell<u64>,
    /// Independent native target, only tightened by the caller.
    pub hard: Cell<Instant>,
    /// Earliest logical sample under which this source was observed.
    pub checked: Cell<u64>,
}
impl IoLease {
    /// Refuse expired, clock-failed or retroactively retagged native IO.
    pub fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.hard.get() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original HTTP native bound",
            ));
        }
        let now = self
            .clock
            .sample()
            .map_err(io::Error::other)?
            .now
            .as_micros();
        if now >= self.until.get() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original HTTP logical bound",
            ));
        }
        if now < self.checked.get() {
            return Err(io::Error::other(Fault::TimeUncertain));
        }
        Ok(())
    }
}
/// Bound each native IO call by the original lease and exact byte allowance.
pub struct Counted<T> {
    /// Actual original IO owner.
    pub inner: T,
    /// Explicit original expiry guard.
    pub lease: Rc<IoLease>,
    /// Shared exact native counts.
    pub counts: Arc<Counters>,
    /// Maximum bytes in each direction for this source.
    pub maximum: usize,
}
impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.lease.check()?;
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let left = this
            .maximum
            .saturating_sub(this.counts.read.load(Ordering::Relaxed));
        if left == 0 {
            return Poll::Ready(Err(io::Error::other(Fault::Capacity)));
        }
        let capacity = buf.remaining().min(left);
        let (result, actual) = {
            let mut bounded = ReadBuf::new(buf.initialize_unfilled_to(capacity));
            let result = Pin::new(&mut this.inner).poll_read(cx, &mut bounded);
            (result, bounded.filled().len())
        };
        // Child initialization was established through the original ReadBuf.
        buf.advance(actual);
        this.counts.read.fetch_add(actual, Ordering::Relaxed);
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.lease.check()?;
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let left = this
            .maximum
            .saturating_sub(this.counts.written.load(Ordering::Relaxed));
        if left == 0 {
            return Poll::Ready(Err(io::Error::other(Fault::Capacity)));
        }
        let result = Pin::new(&mut this.inner).poll_write(cx, &bytes[..bytes.len().min(left)]);
        if let Poll::Ready(Ok(n)) = result {
            this.counts.written.fetch_add(n, Ordering::Relaxed);
            if let Some(progress) = &this.counts.progress
                && progress.dispatch.load(Ordering::Acquire)
            {
                progress.socket.fetch_add(n, Ordering::Release);
            }
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.lease.check()?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
