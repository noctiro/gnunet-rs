//! One original native network-change owner and coalesced rescan hints.
use std::{
    io,
    task::{Context, Poll},
};

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
#[path = "bsd.rs"]
mod socket;
// OpenHarmony standard-system targets use target_os="linux".
#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "linux.rs"]
mod socket;
#[cfg(unix)]
use socket::Source;

#[cfg(windows)]
use gnunet_native::network_change::RouteNotifications as Source;

/// Caller-owned network change subscription. A notification requests a fresh
/// native interface scan and conveys no authoritative address or DNS snapshot.
pub struct RouteMonitor(Option<Source>);

impl RouteMonitor {
    /// Subscribe in the caller's network context. On Unix, enter an I/O-enabled
    /// Tokio runtime. The platform must permit the native subscription.
    ///
    /// # Errors
    /// Returns the original native source or reactor registration error.
    pub fn subscribe() -> io::Result<Self> {
        Source::subscribe().map(|source| Self(Some(source)))
    }

    /// Whether the platform lacks or refuses access to the notification source.
    #[must_use]
    pub fn is_unavailable(error: &io::Error) -> bool {
        if matches!(
            error.kind(),
            io::ErrorKind::PermissionDenied | io::ErrorKind::Unsupported
        ) {
            return true;
        }
        #[cfg(unix)]
        {
            gnunet_native::network::socket_family_unavailable(error)
                || matches!(
                    error.raw_os_error(),
                    Some(libc::EPFNOSUPPORT | libc::ESOCKTNOSUPPORT | libc::ENOSYS),
                )
        }
        #[cfg(windows)]
        {
            false
        }
    }

    /// Observe a coalesced hint. On a native receive failure, retire the
    /// original subscription before opening another one.
    pub fn poll_changed(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(source) = &mut self.0 else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        #[cfg(unix)]
        {
            poll_socket(source, cx)
        }
        #[cfg(windows)]
        {
            source.poll_changed(cx)
        }
    }

    /// Retire this exact subscription. Calling again after success is harmless.
    ///
    /// # Errors
    /// A native callback cancellation error leaves the owner available for retry.
    pub fn close(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        if let Some(source) = &mut self.0 {
            source.close()?;
        }
        self.0 = None;
        Ok(())
    }
}

#[cfg(unix)]
fn poll_socket(source: &mut Source, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    const RECEIVE_QUANTUM: usize = 16;
    let mut changed = false;
    for _ in 0..RECEIVE_QUANTUM {
        match source.poll_receive(cx) {
            Poll::Ready(Ok(hint)) => changed |= hint,
            Poll::Ready(Err(error)) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                changed = true
            }
            Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending if changed => return Poll::Ready(Ok(())),
            Poll::Pending => return Poll::Pending,
        }
    }
    // A busy source gets another bounded turn without withholding its hint.
    cx.waker().wake_by_ref();
    if changed {
        Poll::Ready(Ok(()))
    } else {
        Poll::Pending
    }
}
