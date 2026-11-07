//! Actual mature Quinn UDP boundary, with an immutable original native bound.
//! No datagram is assigned to an application packet or claimed peer by guessing.
use quinn::{AsyncUdpSocket, UdpPoller};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::time::Instant;
/// Actual aggregate socket observations, independent of per-message provider IO.
#[derive(Clone, Copy, Debug, Default)]
pub struct Statistics {
    /// Actual UDP payload bytes accepted by socket adapter.
    pub sent: u64,
    /// Actual UDP payload bytes returned by socket adapter.
    pub received: u64,
}
#[derive(Debug)]
pub(crate) struct Gate {
    hard: Instant,
    closed: AtomicBool,
    sent: AtomicU64,
    received: AtomicU64,
    first: Mutex<Option<io::Error>>,
}
impl Gate {
    pub(crate) fn new(hard: Instant) -> Arc<Self> {
        Arc::new(Self {
            hard,
            closed: AtomicBool::new(false),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            first: Mutex::new(None),
        })
    }
    fn check(&self) -> io::Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        }
        if Instant::now() >= self.hard {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        Ok(())
    }
    fn record(&self, error: &io::Error) {
        if error.kind() == io::ErrorKind::WouldBlock {
            return;
        }
        let mut first = match self.first.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if first.is_none() {
            *first = Some(match error.raw_os_error() {
                Some(e) => io::Error::from_raw_os_error(e),
                None => io::Error::new(error.kind(), error.to_string()),
            })
        }
    }
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release)
    }
    pub(crate) fn statistics(&self) -> Statistics {
        Statistics {
            sent: self.sent.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
        }
    }
    pub(crate) fn take_error(&self) -> Option<io::Error> {
        match self.first.lock() {
            Ok(mut g) => g.take(),
            Err(p) => p.into_inner().take(),
        }
    }
}
#[derive(Debug)]
pub(crate) struct Socket {
    inner: Arc<dyn AsyncUdpSocket>,
    gate: Arc<Gate>,
}
impl Socket {
    pub(crate) fn new(inner: Arc<dyn AsyncUdpSocket>, gate: Arc<Gate>) -> Self {
        Self { inner, gate }
    }
}
impl AsyncUdpSocket for Socket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn try_send(&self, packet: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        self.gate.check()?;
        let result = self.inner.try_send(packet);
        match &result {
            Ok(()) => {
                self.gate
                    .sent
                    .fetch_add(packet.contents.len() as u64, Ordering::Relaxed);
            }
            Err(e) => self.gate.record(e),
        }
        result
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = self.gate.check() {
            return Poll::Ready(Err(e));
        }
        // Cap the individual backend receive batch; Quinn's own work limiter
        // and explicit owner round-robin driver polls supply further fairness.
        let n = buffers.len().min(meta.len()).min(8);
        if n == 0 {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::InvalidInput)));
        }
        let result = self.inner.poll_recv(cx, &mut buffers[..n], &mut meta[..n]);
        match &result {
            Poll::Ready(Ok(n)) => {
                let bytes = meta.iter().take(*n).map(|m| m.len as u64).sum::<u64>();
                self.gate.received.fetch_add(bytes, Ordering::Relaxed);
            }
            Poll::Ready(Err(e)) => self.gate.record(e),
            _ => {}
        }
        result
    }
    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
