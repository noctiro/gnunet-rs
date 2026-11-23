//! Actual mature Quinn UDP boundary, with an immutable original native bound.
//! No datagram is assigned to an application packet or claimed peer by guessing.
use quinn::{AsyncUdpSocket, UdpPoller};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::time::Instant;

mod reactor;
#[cfg(test)]
mod tests;

/// Actual aggregate socket observations, independent of per-message provider IO.
#[derive(Clone, Copy, Debug, Default)]
pub struct Statistics {
    /// Actual UDP payload bytes accepted by socket adapter.
    pub sent: u64,
    /// Actual UDP payload bytes returned by socket adapter.
    pub received: u64,
    /// Recoverable send errors treated as loss by the QUIC packet engine.
    pub isolated_sends: u64,
    /// Receive notifications that were isolated without closing the socket.
    pub isolated_receives: u64,
    /// Most recent native error code among isolated receive notifications.
    pub last_isolated_receive_os_error: Option<i32>,
}
#[derive(Debug)]
pub(crate) struct Gate {
    hard: Instant,
    closed: AtomicBool,
    sent: AtomicU64,
    received: AtomicU64,
    isolated_sends: AtomicU64,
    isolated_receives: AtomicU64,
    last_isolated_receive_os_error: AtomicI32,
    first: Mutex<Option<io::Error>>,
}
impl Gate {
    pub(crate) fn new(hard: Instant) -> Arc<Self> {
        Arc::new(Self {
            hard,
            closed: AtomicBool::new(false),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            isolated_sends: AtomicU64::new(0),
            isolated_receives: AtomicU64::new(0),
            last_isolated_receive_os_error: AtomicI32::new(0),
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
    fn record_isolated_receive(&self, error: &io::Error) {
        if let Some(code) = error.raw_os_error() {
            self.last_isolated_receive_os_error
                .store(code, Ordering::Relaxed);
        }
        self.isolated_receives.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release)
    }
    pub(crate) fn statistics(&self) -> Statistics {
        let code = self.last_isolated_receive_os_error.load(Ordering::Relaxed);
        Statistics {
            sent: self.sent.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            isolated_sends: self.isolated_sends.load(Ordering::Relaxed),
            isolated_receives: self.isolated_receives.load(Ordering::Relaxed),
            last_isolated_receive_os_error: (code != 0).then_some(code),
        }
    }
    pub(crate) fn take_error(&self) -> Option<io::Error> {
        match self.first.lock() {
            Ok(mut g) => g.take(),
            Err(p) => p.into_inner().take(),
        }
    }
}

fn isolated_receive_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::ConnectionReset
        || gnunet_native::network::isolated_datagram_receive_error(error)
}

#[derive(Debug)]
pub(crate) struct Socket {
    inner: Arc<dyn AsyncUdpSocket>,
    gate: Arc<Gate>,
}
impl Socket {
    pub(crate) fn from_std(socket: std::net::UdpSocket, gate: Arc<Gate>) -> io::Result<Self> {
        Ok(Self::new(
            Arc::new(reactor::ReactorSocket::new(socket)?),
            gate,
        ))
    }
    fn new(inner: Arc<dyn AsyncUdpSocket>, gate: Arc<Gate>) -> Self {
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
            Err(e) if gnunet_native::network::isolated_datagram_send_error(e) => {
                self.gate.isolated_sends.fetch_add(1, Ordering::Relaxed);
                // Quinn recovers from datagram loss by timeout. Returning a
                // peer-scoped native error here would kill its connection.
                return Ok(());
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
            Poll::Ready(Err(e)) if isolated_receive_error(e) => {
                self.gate.record_isolated_receive(e);
                // Yield after one notification to preserve the caller's driver
                // budget. The next poll rechecks the original deadline.
                cx.waker().wake_by_ref();
                return Poll::Pending;
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
