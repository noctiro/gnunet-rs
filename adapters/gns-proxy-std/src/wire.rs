//! Unique retained socket, native byte observations and clock-free retirement.
use crate::Error;
use gnunet_types::Error as Fault;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    time::Instant,
};
/// Actual original socket observations. TLS plaintext/HTTP body claims are separate.
#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot {
    /// Actual positive native bytes read from this original socket.
    pub read: u64,
    /// Actual positive native bytes written; not remote delivery.
    pub written: u64,
    /// Saturation was explicitly observed rather than wrapping counters.
    pub counter_overflow: bool,
    /// The original non-Clone TLS/HTTP IO lease still exists.
    pub lease_live: bool,
    /// The original TCP shutdown method was actually polled.
    pub shutdown_attempted: bool,
    /// The actual original TCP shutdown method returned success.
    pub shutdown_completed: bool,
    /// The original local owned TCP descriptor was relinquished.
    pub physically_closed: bool,
}
struct State {
    socket: Option<TcpStream>,
    facts: Snapshot,
}
/// The only authority to physically retire this original socket. It cannot clone
/// an IO lease, recreate a peer or substitute a diagnostic descriptor number.
pub(crate) struct Control(Arc<Mutex<State>>);
/// Exactly one non-Clone IO lease retained through TLS/HTTP.
pub(crate) struct Wire(Arc<Mutex<State>>);
impl Control {
    /// Own a real connected/accepted stream once; creates no native work.
    pub(crate) fn new(socket: TcpStream) -> (Self, Wire) {
        let state = Arc::new(Mutex::new(State {
            socket: Some(socket),
            facts: Snapshot {
                lease_live: true,
                ..Snapshot::default()
            },
        }));
        (Self(state.clone()), Wire(state))
    }
    pub(crate) fn snapshot(&self) -> Result<Snapshot, Error> {
        Ok(self.0.lock().map_err(|_| Fault::Unavailable)?.facts)
    }
    /// Called after the original TLS/HTTP lease was relinquished. It attempts
    /// actual TCP shutdown under one caller-captured cleanup hard, then drops
    /// that same physical stream. Timeout is not a successful shutdown receipt.
    pub(crate) async fn close(
        &mut self,
        hard: Instant,
    ) -> (Option<Error>, Result<Snapshot, Error>) {
        let socket = {
            let mut state = match self.0.lock() {
                Ok(state) => state,
                Err(_) => {
                    return (
                        Some(Fault::Unavailable.into()),
                        Err(Fault::Unavailable.into()),
                    );
                }
            };
            if state.facts.lease_live {
                return (Some(Fault::Conflict.into()), Ok(state.facts));
            }
            match state.socket.take() {
                Some(socket) => {
                    state.facts.shutdown_attempted = true;
                    Some(socket)
                }
                None => None,
            }
        };
        let mut error = None;
        if let Some(mut socket) = socket {
            let completed = if Instant::now() >= hard {
                error = Some(Error::Deadline);
                false
            } else {
                let mut timer = Box::pin(tokio::time::sleep_until(hard));
                std::future::poll_fn(|cx| {
                    if Instant::now() >= hard
                        || std::future::Future::poll(timer.as_mut(), cx).is_ready()
                    {
                        return Poll::Ready(Err(Error::Deadline));
                    }
                    Pin::new(&mut socket).poll_shutdown(cx).map_err(Error::Io)
                })
                .await
                .map_or_else(
                    |cause| {
                        error = Some(cause);
                        false
                    },
                    |()| true,
                )
            };
            drop(socket); // same original FD, even on a failed local shutdown
            if let Ok(mut state) = self.0.lock() {
                state.facts.shutdown_completed = completed;
                state.facts.physically_closed = true;
            }
        }
        (error, self.snapshot())
    }
}
impl Drop for Control {
    fn drop(&mut self) {
        // Defensive owner loss only. It is never reported as a completed graceful
        // shutdown. Normal control flow explicitly awaits close above.
        if let Ok(mut state) = self.0.lock()
            && let Some(socket) = state.socket.take()
        {
            drop(socket);
            state.facts.physically_closed = true;
        }
    }
}
fn io_error() -> io::Error {
    io::Error::other("GNS proxy original socket owner unavailable")
}
fn count(total: &mut u64, overflow: &mut bool, n: usize) {
    match u64::try_from(n).ok().and_then(|n| total.checked_add(n)) {
        Some(v) => *total = v,
        None => {
            *total = u64::MAX;
            *overflow = true;
        }
    }
}
impl AsyncRead for Wire {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().map_err(|_| io_error())?;
        let before = buffer.filled().len();
        let socket = state.socket.as_mut().ok_or_else(io_error)?;
        let result = Pin::new(socket).poll_read(cx, buffer);
        if let Poll::Ready(Ok(())) = &result {
            let n = buffer.filled().len().saturating_sub(before);
            let facts = &mut state.facts;
            count(&mut facts.read, &mut facts.counter_overflow, n);
        }
        result
    }
}
impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.lock().map_err(|_| io_error())?;
        let socket = state.socket.as_mut().ok_or_else(io_error)?;
        let result = Pin::new(socket).poll_write(cx, buffer);
        if let Poll::Ready(Ok(n)) = &result {
            let facts = &mut state.facts;
            count(&mut facts.written, &mut facts.counter_overflow, *n);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().map_err(|_| io_error())?;
        Pin::new(state.socket.as_mut().ok_or_else(io_error)?).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.lock().map_err(|_| io_error())?;
        state.facts.shutdown_attempted = true;
        let result = Pin::new(state.socket.as_mut().ok_or_else(io_error)?).poll_shutdown(cx);
        if let Poll::Ready(Ok(())) = &result {
            state.facts.shutdown_completed = true;
        }
        result
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.facts.lease_live = false;
            // No IO lease remains. Relinquish the original FD promptly even
            // when a session retains diagnostic Control metadata. This grants
            // no successful shutdown/remote-EOF fact.
            if let Some(socket) = state.socket.take() {
                drop(socket);
                state.facts.physically_closed = true;
            }
        }
    }
}
/// Only mature TLS/plain TCP implementations can enter HTTP; no raw tunnel is
/// substituted for HTTP or certificate verification.
pub(crate) trait AsyncIo: AsyncRead + AsyncWrite + Unpin {}
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncIo for T {}
pub(crate) type Io = Box<dyn AsyncIo>;
