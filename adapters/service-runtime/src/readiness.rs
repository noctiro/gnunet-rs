//! Stable-owned readable registration for shared GNUnet service runtime.
//! No operation consumes listener connections or bytes. The one native constructor
//! establishes AsyncFd's owned-descriptor stability; all other operations are safe.
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    task::{Context, Poll, ready},
};
use tokio::io::{Interest, unix::AsyncFd};
/// Actual level-ready flags, preserved independently rather than inferred from a hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Readiness {
    /// Kernel reports readable data/listener backlog.
    pub readable: bool,
    /// Kernel reports hangup; the caller chooses its source-specific EOF policy.
    pub hangup: bool,
    /// Kernel reports an exceptional socket/pipe error.
    pub error: bool,
}
/// Registration failure returns the still-owned descriptor to its caller.
#[derive(Debug)]
pub struct RegisterError {
    /// Original exclusive ownership, never reconstructed from a raw number.
    pub descriptor: OwnedFd,
    /// Actual reactor error.
    pub error: io::Error,
}
/// Opaque reactor owner. No mutable-inner, replacement or descriptor exchange API.
#[derive(Debug)]
pub struct RegisteredReadiness {
    inner: AsyncFd<OwnedFd>,
}
impl RegisteredReadiness {
    /// Register one exclusive descriptor, retaining it unchanged until deregistration.
    /// Call inside an entered Tokio runtime with its I/O driver enabled.
    ///
    /// # Panics
    ///
    /// Tokio panics when no current I/O reactor exists. Registration OS failures
    /// instead return [`RegisterError`] with the original descriptor still owned.
    #[expect(
        unsafe_code,
        reason = "The opaque wrapper owns the same exclusive OwnedFd throughout registration, exposes no mutable-inner/replacement API, and into_owned deregisters before transfer"
    )]
    pub fn new(descriptor: OwnedFd) -> Result<Self, RegisterError> {
        // SAFETY: descriptor is uniquely owned and remains in this private field;
        // no method replaces/closes it while its registration exists. Moving the
        // wrapper does not change the descriptor value or OS-resource lifetime.
        unsafe { AsyncFd::register_with_interest(descriptor, Interest::READABLE) }
            .map(|inner| Self { inner })
            .map_err(|failure| {
                let (descriptor, error) = failure.into_parts();
                RegisterError { descriptor, error }
            })
    }
    /// Borrow the original still-live descriptor, for safe duplication/inheritance.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.get_ref().as_fd()
    }
    /// Confirm a reactor hint using actual nonconsuming poll0. False cached hints
    /// are cleared by try_io; canceled futures leave this owner and its FD intact.
    pub fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<Readiness>> {
        loop {
            let mut guard = ready!(self.inner.poll_read_ready(cx))?;
            match guard.try_io(|registered| probe(registered.get_ref().as_fd())) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }
    /// Explicit nonconsuming level check, independent from reactor cached state.
    pub fn level(&self) -> io::Result<Readiness> {
        probe(self.as_fd())
    }
    /// Deregister before transferring the unchanged descriptor to another owner.
    pub fn into_owned(self) -> OwnedFd {
        self.inner.into_inner()
    }
}
fn classify(flags: PollFlags) -> io::Result<Readiness> {
    if flags.contains(PollFlags::POLLNVAL) {
        return Err(io::Error::from_raw_os_error(
            nix::errno::Errno::EBADF as i32,
        ));
    }
    let state = Readiness {
        readable: flags.contains(PollFlags::POLLIN),
        hangup: flags.contains(PollFlags::POLLHUP),
        error: flags.contains(PollFlags::POLLERR),
    };
    if !state.readable && !state.hangup && !state.error {
        return Err(io::ErrorKind::WouldBlock.into());
    }
    Ok(state)
}
fn probe(fd: BorrowedFd<'_>) -> io::Result<Readiness> {
    let mut descriptors = [PollFd::new(fd, PollFlags::POLLIN)];
    // A nonblocking confirmation never starts an unowned worker or waits beyond
    // the calling poll. Interrupted errors are explicit and retriable by caller.
    poll(&mut descriptors, PollTimeout::ZERO).map_err(io::Error::from)?;
    classify(descriptors[0].revents().unwrap_or(PollFlags::empty()))
}
#[cfg(test)]
mod tests {
    //! Exact classifier boundaries, independent from OS-specific flag synthesis.
    use super::*;
    #[test]
    fn errors_hangup_invalid_and_empty_are_distinct() {
        assert_eq!(
            classify(PollFlags::POLLNVAL)
                .err()
                .and_then(|e| e.raw_os_error()),
            Some(nix::errno::Errno::EBADF as i32)
        );
        assert!(
            matches!(classify(PollFlags::empty()),Err(e) if e.kind()==io::ErrorKind::WouldBlock)
        );
        assert!(matches!(
            classify(PollFlags::POLLERR),
            Ok(Readiness {
                readable: false,
                hangup: false,
                error: true
            })
        ));
        assert!(matches!(
            classify(PollFlags::POLLHUP | PollFlags::POLLIN),
            Ok(Readiness {
                readable: true,
                hangup: true,
                error: false
            })
        ));
    }
    /// Compile-only here: a real nonblocking pair supplies the cached Ready and
    /// actual EAGAIN, rather than injecting either result into the wrapper.
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert original cached readiness consumption, one cooperative rearm wake and the subsequent idle Pending without executing a second callback"
    )]
    fn cached_readiness_would_block_schedules_next_guarded_turn() -> io::Result<()> {
        use std::{
            future::poll_fn,
            io::Write,
            os::unix::net::UnixStream,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            task::{Wake, Waker},
            time::Duration,
        };
        struct CountWake(AtomicUsize);
        impl Wake for CountWake {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), async {
                for callback in [false, true] {
                    let (reader, mut writer) = UnixStream::pair()?;
                    reader.set_nonblocking(true)?;
                    let io = RegisteredIo::new(reader.into()).map_err(|r| r.error)?;
                    writer.write_all(b"x")?;
                    let mut byte = [0; 1];
                    let count = poll_fn(|cx| io.poll_read(cx, &mut byte)).await?;
                    assert_eq!(count, 1);
                    assert_eq!(byte, [b'x']);
                    let wakes = Arc::new(CountWake(AtomicUsize::new(0)));
                    let waker = Waker::from(wakes.clone());
                    let mut cx = Context::from_waker(&waker);
                    let mut calls = 0;
                    let pending = if callback {
                        io.poll_read_with(&mut cx, |fd| {
                            calls += 1;
                            nix::unistd::read(fd, &mut byte).map_err(io::Error::from)
                        })
                    } else {
                        io.poll_read(&mut cx, &mut byte)
                    };
                    assert!(pending.is_pending());
                    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
                    let next = io.poll_read_with(&mut cx, |fd| {
                        calls += 1;
                        nix::unistd::read(fd, &mut byte).map_err(io::Error::from)
                    });
                    assert!(next.is_pending());
                    assert_eq!(calls, usize::from(callback));
                    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
                }
                Ok::<(), io::Error>(())
            })
            .await
            .map_err(io::Error::other)?
        })
    }
}

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
