//! Original nonblocking descriptor I/O and bounded stale-hint retirement.
use super::RegisterError;
use gnunet_native::network::StableFd;
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
pub struct RegisteredIo<Descriptor: StableFd = OwnedFd> {
    inner: AsyncFd<Descriptor>,
}
impl RegisteredIo {
    /// Register an already nonblocking descriptor for caller-driven reads/writes.
    /// Refusal retains the original descriptor in [`RegisterError`].
    ///
    /// # Panics
    ///
    /// Tokio requires an entered runtime with its I/O driver enabled.
    pub fn new(descriptor: OwnedFd) -> Result<Self, RegisterError> {
        Self::from_descriptor(descriptor)
            .map_err(|(descriptor, error)| RegisterError { descriptor, error })
    }

    /// Deregister before transferring the unchanged exclusive descriptor.
    pub fn into_owned(self) -> OwnedFd {
        self.inner.into_inner()
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
        self.poll_read_on(cx, |descriptor| operation(descriptor.as_fd()))
    }
    /// Poll a caller-defined nonblocking send on the same unchanged descriptor.
    /// The caller retains its original datagram/offset across Pending; a native
    /// byte count is never promoted to delivery or persistence acknowledgement.
    pub fn poll_write_with<T>(
        &self,
        cx: &mut Context<'_>,
        operation: impl FnOnce(BorrowedFd<'_>) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        self.poll_write_on(cx, |descriptor| operation(descriptor.as_fd()))
    }
    /// Poll one nonblocking read, preserving the actual byte count and errno.
    pub fn poll_read(&self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        self.poll_read_on(cx, |descriptor| {
            nix::unistd::read(descriptor, bytes).map_err(io::Error::from)
        })
    }
    /// Poll one nonblocking write, preserving partial native exposure exactly.
    pub fn poll_write(&self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        self.poll_write_on(cx, |descriptor| {
            nix::unistd::write(descriptor, bytes).map_err(io::Error::from)
        })
    }
}

impl<Descriptor: StableFd> RegisteredIo<Descriptor> {
    /// Register a nonblocking native owner, retaining its concrete I/O contract.
    /// Refusal returns that same owner and the original error.
    ///
    /// # Panics
    ///
    /// Tokio requires an entered runtime with its I/O driver enabled.
    #[expect(
        unsafe_code,
        reason = "Only sealed owning StableFd implementations enter this registration, with no replacement or mutable-inner API"
    )]
    pub fn from_descriptor(descriptor: Descriptor) -> Result<Self, (Descriptor, io::Error)> {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        let flags = match fcntl(&descriptor, FcntlArg::F_GETFL) {
            Ok(flags) => flags,
            Err(error) => return Err((descriptor, error.into())),
        };
        if !OFlag::from_bits_truncate(flags).contains(OFlag::O_NONBLOCK) {
            return Err((
                descriptor,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "reactor descriptor must be nonblocking",
                ),
            ));
        }
        // SAFETY: the sealed owner keeps the original fd open. Shared access
        // cannot replace or mutably expose the registered descriptor.
        unsafe { AsyncFd::register(descriptor) }
            .map(|inner| Self { inner })
            .map_err(tokio::io::unix::AsyncFdRegisterError::into_parts)
    }

    /// Borrow the original registered owner and its typed I/O contract.
    pub fn descriptor(&self) -> &Descriptor {
        self.inner.get_ref()
    }

    /// Poll one nonblocking receive on the original typed descriptor owner.
    pub fn poll_read_on<T>(
        &self,
        cx: &mut Context<'_>,
        operation: impl FnOnce(&Descriptor) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        self.read_on(cx, false, operation)
    }

    /// Poll one nonblocking guard read. A Pending result confirms that the
    /// original descriptor returned WouldBlock in this turn, even when the
    /// reactor has yet to report a newly queued event.
    pub fn poll_guard_read_on<T>(
        &self,
        cx: &mut Context<'_>,
        operation: impl FnOnce(&Descriptor) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        self.read_on(cx, true, operation)
    }

    fn read_on<T>(
        &self,
        cx: &mut Context<'_>,
        check_pending: bool,
        operation: impl FnOnce(&Descriptor) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        let mut guard = match self.inner.poll_read_ready(cx) {
            Poll::Ready(result) => result?,
            Poll::Pending if check_pending => {
                // Poll installed the waker before this original read. Nothing
                // else consumes this exclusive nonblocking descriptor.
                return match operation(self.descriptor()) {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                    result => Poll::Ready(result),
                };
            }
            Poll::Pending => return Poll::Pending,
        };
        match guard.try_io(|io| operation(io.get_ref())) {
            Ok(result) => Poll::Ready(result),
            Err(_would_block) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    /// Poll one nonblocking send on the original typed descriptor owner.
    pub fn poll_write_on<T>(
        &self,
        cx: &mut Context<'_>,
        operation: impl FnOnce(&Descriptor) -> io::Result<T>,
    ) -> Poll<io::Result<T>> {
        let mut guard = ready!(self.inner.poll_write_ready(cx))?;
        match guard.try_io(|io| operation(io.get_ref())) {
            Ok(result) => Poll::Ready(result),
            Err(_would_block) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
