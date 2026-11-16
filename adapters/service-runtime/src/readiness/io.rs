//! Original nonblocking descriptor I/O and bounded stale-hint retirement.
use super::RegisterError;
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    task::{Context, Poll, ready},
};
use tokio::io::unix::AsyncFd;
/// Exclusive nonblocking descriptor IO with stable reactor registration. This
/// wrapper never exposes mutable ownership or replaces the registered descriptor.
/// Clearing a stale ready hint after an actual WouldBlock schedules one guarded
/// caller turn: cached Ready may not have registered a waker. The next poll
/// registers the empty readiness state or performs one genuinely ready operation.
/// Each method attempts at most one original native IO operation per poll.
#[derive(Debug)]
pub struct RegisteredIo {
    inner: AsyncFd<OwnedFd>,
}
impl RegisteredIo {
    /// Register an already nonblocking descriptor for caller-driven reads/writes.
    /// Refusal retains the original descriptor in [`RegisterError`].
    ///
    /// # Panics
    ///
    /// Tokio requires an entered runtime with its I/O driver enabled.
    #[expect(
        unsafe_code,
        reason = "Exclusive OwnedFd stays unchanged in this opaque registration with no replacement, close or mutable-inner API"
    )]
    pub fn new(descriptor: OwnedFd) -> Result<Self, RegisterError> {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        let flags = match fcntl(&descriptor, FcntlArg::F_GETFL) {
            Ok(flags) => flags,
            Err(error) => {
                return Err(RegisterError {
                    descriptor,
                    error: error.into(),
                });
            }
        };
        if !OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK) {
            return Err(RegisterError {
                descriptor,
                error: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "reactor descriptor must be nonblocking",
                ),
            });
        }
        // SAFETY: the exclusive OwnedFd remains in this private registration;
        // no method closes, exchanges or mutably exposes it while registered.
        unsafe { AsyncFd::register(descriptor) }
            .map(|inner| Self { inner })
            .map_err(|failure| {
                let (descriptor, error) = failure.into_parts();
                RegisterError { descriptor, error }
            })
    }
    /// Poll a caller-defined nonblocking receive using only the original borrowed
    /// descriptor. Return owned observations; no mutable descriptor is exposed.
    /// Actual WouldBlock clears the reactor hint and schedules one caller turn
    /// to recheck its guards and register readiness again. It never retries the
    /// original FnOnce operation inside this poll.
    pub fn poll_read_with<T>(
        &self,
        cx: &mut Context<'_>,
        operation: impl FnOnce(BorrowedFd<'_>) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        let mut guard = ready!(self.inner.poll_read_ready(cx))?;
        match guard.try_io(|io| operation(io.get_ref().as_fd())) {
            Ok(result) => Poll::Ready(result),
            Err(_would_block) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    /// Poll a caller-defined nonblocking send on the same unchanged descriptor.
    /// The caller retains its original datagram/offset across Pending; a native
    /// byte count is never promoted to delivery or persistence acknowledgement.
    pub fn poll_write_with<T>(
        &self,
        cx: &mut Context<'_>,
        operation: impl FnOnce(BorrowedFd<'_>) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        let mut guard = ready!(self.inner.poll_write_ready(cx))?;
        match guard.try_io(|io| operation(io.get_ref().as_fd())) {
            Ok(result) => Poll::Ready(result),
            Err(_would_block) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    /// Poll one nonblocking read, preserving the actual byte count and errno.
    pub fn poll_read(&self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut guard = ready!(self.inner.poll_read_ready(cx))?;
        match guard.try_io(|io| nix::unistd::read(io.get_ref(), bytes).map_err(io::Error::from)) {
            Ok(result) => Poll::Ready(result),
            Err(_would_block) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    /// Poll one nonblocking write, preserving partial native exposure exactly.
    pub fn poll_write(&self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let mut guard = ready!(self.inner.poll_write_ready(cx))?;
        match guard.try_io(|io| nix::unistd::write(io.get_ref(), bytes).map_err(io::Error::from)) {
            Ok(result) => Poll::Ready(result),
            Err(_would_block) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    /// Deregister before transferring the unchanged exclusive descriptor.
    pub fn into_owned(self) -> OwnedFd {
        self.inner.into_inner()
    }
}
