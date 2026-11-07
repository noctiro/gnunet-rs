//! One original interface-route transaction with an actual correlated kernel ACK.
use crate::{Action, ApplyFailure, Effect, EffectId, Info, Timing};
use std::{
    future::{Future, poll_fn},
    io,
    os::fd::{AsRawFd, OwnedFd},
    pin::Pin,
    sync::atomic::{AtomicU32, Ordering},
    task::{Context, Poll},
};
use tokio::{
    io::unix::AsyncFd,
    time::{Instant, Sleep},
};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as native;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as native;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod native {
    use super::*;
    pub(super) fn prepare(_: &Info, _: &Action, _: u32) -> io::Result<Session> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native interface routes require Linux/macOS",
        ))
    }
    pub(super) fn ack(
        _: &[u8],
        _: u32,
        _: u16,
        _: u32,
        _: u32,
        _: &[u8],
    ) -> io::Result<Option<io::Result<()>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native interface route ACKs unavailable",
        ))
    }
}
pub(crate) mod query;
pub use query::{
    RouteQuery, RouteQueryCompletion, RouteQueryEvidence, RouteQueryOutcome, RouteQueryProblem,
    RouteQueryProgress, RouteQuerySubmission, RouteQueryTarget, RouteRecord,
};
// Routing sockets broadcast same-process replies; use a non-recycling process
// sequence even across multiple TUN owners. This is an OS protocol field only.
static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(0);
fn sequence() -> io::Result<u32> {
    NEXT_SEQUENCE
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
            n.checked_add(1).filter(|n| *n <= i32::MAX as u32)
        })
        .map(|n| n + 1)
        .map_err(|_| io::Error::other("route sequence exhausted"))
}
/// Original request exposure, independent of kernel acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteSubmission {
    /// No mutation request was admitted.
    Unsent,
    /// One whole original native request was written.
    Whole {
        /// Complete actual native frame bytes.
        bytes: usize,
    },
    /// Unexpected positive partial write; never resume its suffix.
    Partial {
        /// Actual exposed native bytes.
        bytes: usize,
    },
    /// A native write error may have followed synchronous processing.
    Unknown,
}
/// Actual kernel response or explicit uncertainty/local unsent retirement.
#[derive(Debug)]
pub enum RouteOutcome {
    /// Correlated native ACK: Ok is actual kernel success,
    /// Err preserves the kernel's actual rejection errno.
    KernelAck(io::Result<()>),
    /// No request was written before cancellation/source/deadline.
    Unsent(io::Error),
    /// Request may have changed the kernel; no success/rejection is invented.
    Uncertain(io::Error),
}
/// Terminal original route observation. It contains no reusable Effect authority.
#[derive(Debug)]
pub struct RouteCompletion {
    /// Original device/effect authority.
    pub id: EffectId,
    /// Exact requested action.
    pub action: Action,
    /// Original interface snapshot, never rebound to a replacement.
    pub interface: Info,
    /// Original absolute transaction deadline.
    pub deadline: Instant,
    /// Actual exposure fact.
    pub submission: RouteSubmission,
    /// Real ACK or honest local uncertainty.
    pub outcome: RouteOutcome,
    /// Source/deadline state when observed.
    pub timing: Timing,
    /// Independent native control-socket close error; never retried.
    pub close_error: Option<io::Error>,
    /// Original native write error, retained even if a later ACK/deadline settles it.
    pub write_error: Option<io::Error>,
}
/// One bounded caller-driven native transaction step.
#[derive(Debug)]
pub enum RouteProgress {
    /// Whole original request entered the kernel;
    /// this is not an ACK or proof of route installation.
    Submitted {
        /// Exact original effect.
        id: EffectId,
        /// Actual native bytes written.
        bytes: usize,
    },
    /// Actual native write returned an error; a synchronous kernel may still
    /// emit its correlated reply. The original errno remains on this owner.
    WriteError {
        /// Exact original effect.
        id: EffectId,
    },
    /// One bounded unrelated kernel message was consumed.
    Activity {
        /// Actual native bytes read.
        bytes: usize,
    },
    /// Correlated actual terminal result/local retirement.
    Complete(RouteCompletion),
    /// This caller wait ended; original socket/deadline remain.
    WaitDeadline,
    /// Terminal result was already consumed.
    Finished,
}
struct Session {
    fd: OwnedFd,
    frame: Vec<u8>,
    sequence: u32,
    kind: u16,
    pid: u32,
    index: u32,
}
/// Exactly one original native route socket/request, no background task/retry.
/// Dropping drive futures preserves this owner; cancel closes its original socket
/// and reports uncertainty after exposure. It never sends a rollback/delete.
#[must_use]
pub struct NativeRoute {
    io: Option<AsyncFd<OwnedFd>>,
    effect: Option<Effect>,
    frame: Vec<u8>,
    sequence: u32,
    kind: u16,
    pid: u32,
    index: u32,
    submission: RouteSubmission,
    alarm: Pin<Box<Sleep>>,
    rx: [u8; 4096],
    ignored: usize,
    write_error: Option<io::Error>,
}
impl NativeRoute {
    pub(crate) fn start(effect: Effect) -> Result<Self, ApplyFailure> {
        let prepared = (|| {
            tokio::runtime::Handle::try_current().map_err(|e| io::Error::other(e.to_string()))?;
            if !effect.current() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original route effect expired/source retired",
                ));
            }
            native::prepare(effect.interface(), effect.action(), sequence()?)
        })();
        let session = match prepared {
            Ok(session) => session,
            Err(error) => {
                return Err(ApplyFailure {
                    effect,
                    error,
                    attempted: false,
                });
            }
        };
        #[expect(
            unsafe_code,
            reason = "Private route owner retains exactly this live OwnedFd until deregistration; no mutable FD replacement is exposed"
        )]
        // SAFETY: route socket is uniquely owned and nonblocking. It stays inside
        // this private registration until into_inner deregisters before close.
        let io = match unsafe { AsyncFd::register(session.fd) } {
            Ok(io) => io,
            Err(error) => {
                return Err(ApplyFailure {
                    effect,
                    error: io::Error::from(error),
                    attempted: false,
                });
            }
        };
        let alarm = Box::pin(tokio::time::sleep_until(effect.deadline()));
        Ok(Self {
            io: Some(io),
            effect: Some(effect),
            frame: session.frame,
            sequence: session.sequence,
            kind: session.kind,
            pid: session.pid,
            index: session.index,
            submission: RouteSubmission::Unsent,
            alarm,
            rx: [0; 4096],
            ignored: 0,
            write_error: None,
        })
    }
    /// Original exposure fact; never becomes an ACK merely through waiting.
    #[must_use]
    pub const fn submission(&self) -> RouteSubmission {
        self.submission
    }
    /// Actual original write errno, retained while waiting for a correlated ACK.
    #[must_use]
    pub fn write_error(&self) -> Option<&io::Error> {
        self.write_error.as_ref()
    }
    fn complete(&mut self, outcome: RouteOutcome) -> RouteProgress {
        let close_error = self.io.take().and_then(|io| {
            nix::unistd::close(io.into_inner())
                .err()
                .map(io::Error::from)
        });
        let Some(effect) = self.effect.take() else {
            return RouteProgress::Finished;
        };
        let timing = if !effect.id().epoch().current() {
            Timing::SourceRetired
        } else if Instant::now() >= effect.deadline() {
            Timing::Late
        } else {
            Timing::Timely
        };
        RouteProgress::Complete(RouteCompletion {
            id: effect.id().clone(),
            action: effect.action().clone(),
            interface: effect.interface().clone(),
            deadline: effect.deadline(),
            submission: self.submission,
            outcome,
            timing,
            close_error,
            write_error: self.write_error.take(),
        })
    }
    fn stop(&mut self, error: io::Error) -> RouteProgress {
        let outcome = if self.submission == RouteSubmission::Unsent {
            RouteOutcome::Unsent(error)
        } else {
            RouteOutcome::Uncertain(error)
        };
        self.complete(outcome)
    }
    /// Close the original control socket without claiming to revoke/undo a route.
    pub fn cancel(&mut self) -> RouteProgress {
        self.stop(io::Error::new(
            io::ErrorKind::Interrupted,
            "original route transaction cancelled",
        ))
    }
    /// At most one original native request write or ACK receive per poll. Kernel
    /// state can remain changed after a timeout/close; no automatic replay occurs.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<RouteProgress> {
        let Some(effect) = &self.effect else {
            return Poll::Ready(RouteProgress::Finished);
        };
        if !effect.id().epoch().current() {
            return Poll::Ready(self.stop(io::Error::new(
                io::ErrorKind::NotConnected,
                "original TUN source retired",
            )));
        }
        if Instant::now() >= effect.deadline() || self.alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(self.stop(io::Error::new(
                io::ErrorKind::TimedOut,
                "original route ACK deadline",
            )));
        }
        if self.submission == RouteSubmission::Unsent {
            match crate::platform::index(&effect.interface().name) {
                Ok(index) if index == self.index => {}
                Ok(_) => {
                    return Poll::Ready(self.stop(io::Error::new(
                        io::ErrorKind::NotConnected,
                        "original route interface name/index changed",
                    )));
                }
                Err(error) => return Poll::Ready(self.stop(error)),
            }
            let Some(io) = &self.io else {
                return Poll::Ready(RouteProgress::Finished);
            };
            let result = write_once(io, cx, &self.frame);
            let result = match result {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(value) => value,
            };
            return match result {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Err(error) => {
                    self.submission = RouteSubmission::Unknown;
                    self.write_error = Some(error);
                    Poll::Ready(RouteProgress::WriteError {
                        id: effect.id().clone(),
                    })
                }
                Ok(0) => Poll::Ready(self.stop(io::ErrorKind::WriteZero.into())),
                Ok(n) if n != self.frame.len() => {
                    self.submission = RouteSubmission::Partial { bytes: n };
                    Poll::Ready(
                        self.stop(io::Error::other("short route request; suffix not retried")),
                    )
                }
                Ok(n) => {
                    self.submission = RouteSubmission::Whole { bytes: n };
                    Poll::Ready(RouteProgress::Submitted {
                        id: effect.id().clone(),
                        bytes: n,
                    })
                }
            };
        }
        let Some(io) = &self.io else {
            return Poll::Ready(RouteProgress::Finished);
        };
        let result = read_once(io, cx, &mut self.rx);
        let result = match result {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(value) => value,
        };
        let n = match result {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(error) => return Poll::Ready(self.stop(error)),
            Ok(0) => return Poll::Ready(self.stop(io::ErrorKind::UnexpectedEof.into())),
            Ok(n) => n,
        };
        match native::ack(
            &self.rx[..n],
            self.sequence,
            self.kind,
            self.pid,
            self.index,
            &self.frame,
        ) {
            Err(error) => Poll::Ready(self.stop(error)),
            Ok(Some(result)) => Poll::Ready(self.complete(RouteOutcome::KernelAck(result))),
            Ok(None) => {
                self.ignored += 1;
                if self.ignored > 64 {
                    Poll::Ready(
                        self.stop(io::Error::other("bounded unrelated route message limit")),
                    )
                } else {
                    Poll::Ready(RouteProgress::Activity { bytes: n })
                }
            }
        }
    }
    /// Drive one bounded action; a dropped future preserves the exact request,
    /// original finite deadline and any not-yet-observed kernel ACK.
    pub async fn drive(&mut self, until: Instant) -> RouteProgress {
        let mut wait = Box::pin(tokio::time::sleep_until(until));
        poll_fn(|cx| {
            if wait.as_mut().poll(cx).is_ready() {
                Poll::Ready(RouteProgress::WaitDeadline)
            } else {
                self.poll(cx)
            }
        })
        .await
    }
}
fn write_once(
    io: &AsyncFd<OwnedFd>,
    cx: &mut Context<'_>,
    bytes: &[u8],
) -> Poll<io::Result<usize>> {
    let mut ready = match io.poll_write_ready(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        Poll::Ready(Ok(r)) => r,
    };
    match ready.try_io(|io| nix::unistd::write(io.get_ref(), bytes).map_err(io::Error::from)) {
        Err(_) => {
            // Cached Ready may not have stored a waker before try_io cleared it.
            // Re-poll to register it without repeating the operation here.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        Ok(value) => Poll::Ready(value),
    }
}
fn read_once(
    io: &AsyncFd<OwnedFd>,
    cx: &mut Context<'_>,
    bytes: &mut [u8],
) -> Poll<io::Result<usize>> {
    let mut ready = match io.poll_read_ready(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
        Poll::Ready(Ok(r)) => r,
    };
    match ready.try_io(|io| receive(io.get_ref(), bytes)) {
        Err(_) => {
            // Cached Ready may not have stored a waker before try_io cleared it.
            // Re-poll to register it without repeating the operation here.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        Ok(value) => Poll::Ready(value),
    }
}
fn receive(fd: &OwnedFd, bytes: &mut [u8]) -> io::Result<usize> {
    #[expect(
        unsafe_code,
        reason = "sockaddr_storage and msghdr consist of scalar/pointer storage; zero initialization is valid before recvmsg fills output fields"
    )]
    // SAFETY: both C objects allow all-zero initialization and contain no Rust references.
    let (mut peer, mut message): (libc::sockaddr_storage, libc::msghdr) =
        unsafe { std::mem::zeroed() };
    let mut vector = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    message.msg_name = (&mut peer as *mut libc::sockaddr_storage).cast();
    message.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    #[expect(
        unsafe_code,
        reason = "recvmsg receives one live bounded mutable byte buffer, initialized address storage and exact one-element iovec; no pointer escapes the synchronous syscall"
    )]
    // SAFETY: all capacities agree with the storage above; no concurrent references access it.
    let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &mut message, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if message.msg_flags & libc::MSG_TRUNC != 0 || n as usize > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated original kernel route reply",
        ));
    }
    #[cfg(target_os = "linux")]
    {
        if (message.msg_namelen as usize) < std::mem::size_of::<libc::sockaddr_nl>()
            || peer.ss_family != libc::AF_NETLINK as libc::sa_family_t
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid netlink source",
            ));
        }
        #[expect(
            unsafe_code,
            reason = "The kernel returned a full AF_NETLINK sockaddr in aligned initialized sockaddr_storage; read the documented scalar pid only"
        )]
        // SAFETY: size/family were checked, sockaddr_storage satisfies sockaddr_nl alignment.
        let pid = unsafe { (*(std::ptr::addr_of!(peer).cast::<libc::sockaddr_nl>())).nl_pid };
        if pid != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "route ACK sender is not the kernel",
            ));
        }
    }
    #[cfg(target_os = "macos")]
    {
        if message.msg_namelen < 2 || peer.ss_family != libc::AF_ROUTE as libc::sa_family_t {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid routing-socket source",
            ));
        }
    }
    Ok(n as usize)
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed original route ACK")
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn range<const N: usize>(b: &[u8], at: usize) -> io::Result<[u8; N]> {
    b.get(at..at + N)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn word(b: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(range(b, at)?))
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn short(b: &[u8], at: usize) -> io::Result<u16> {
    Ok(u16::from_ne_bytes(range(b, at)?))
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at + 4].copy_from_slice(&n.to_ne_bytes())
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn put16(b: &mut [u8], at: usize, n: u16) {
    b[at..at + 2].copy_from_slice(&n.to_ne_bytes())
}
fn network(address: std::net::IpAddr, prefix: u8) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let raw = match address {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };
    if usize::from(prefix) > raw.len() * 8 {
        return Err(crate::platform::invalid("route prefix overflow"));
    }
    let mut mask = vec![0; raw.len()];
    for (i, b) in mask.iter_mut().enumerate() {
        let bits = usize::from(prefix).saturating_sub(i * 8).min(8);
        *b = if bits == 0 { 0 } else { 0xff << (8 - bits) }
    }
    if raw.iter().zip(&mask).any(|(a, m)| a & !m != 0) {
        return Err(crate::platform::invalid(
            "route destination has nonzero host bits",
        ));
    }
    Ok((raw, mask))
}
