//! Stable-owned readable registration for shared GNUnet service runtime.
//! No operation consumes listener connections or bytes. The one native constructor
//! establishes AsyncFd's owned-descriptor stability; all other operations are safe.
use super::Readiness;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    task::{Context, Poll, ready},
};
use tokio::io::{Interest, unix::AsyncFd};
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
        let mut guard = ready!(self.inner.poll_read_ready(cx))?;
        match guard.try_io(|registered| probe(registered.get_ref().as_fd())) {
            Ok(result) => Poll::Ready(result),
            Err(_would_block) => {
                // Cached Ready may not have installed this caller's waker.
                // Bound this poll to one confirmation, then register afresh.
                cx.waker().wake_by_ref();
                Poll::Pending
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
    use crate::readiness::RegisteredIo;
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
