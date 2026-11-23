//! Listener ownership without accepting or consuming its queued connections.
use super::Readiness;
use socket2::Socket;
#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(windows)]
use std::os::windows::io::{AsSocket, BorrowedSocket};
use std::{
    io,
    task::{Context, Poll},
};

/// Original listening socket registered only for nonconsuming read observations.
/// Construction transfers ownership; failure drops the supplied socket. Polling
/// never accepts a connection, and canceled waits leave the owner registered.
#[derive(Debug)]
pub struct RegisteredListener {
    #[cfg(unix)]
    inner: super::RegisteredReadiness,
    // A private generic Winsock/Mio carrier; it is never exposed as a TCP stream
    // and performs no TCP protocol operation, address interpretation or I/O.
    #[cfg(windows)]
    inner: tokio::net::TcpStream,
    #[cfg(windows)]
    protection: Option<gnunet_native::local_path::EndpointProtection>,
}
impl RegisteredListener {
    /// Register this owned nonblocking stream socket on the caller's runtime.
    /// Actual local/TCP kind remains with the caller. No wait task is spawned.
    ///
    /// # Panics
    /// Panics if the entered runtime has no enabled I/O driver.
    pub fn new(socket: Socket) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        if socket.r#type()? != socket2::Type::STREAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "stream socket required",
            ));
        }
        #[cfg(unix)]
        let original = socket.as_fd();
        #[cfg(windows)]
        let original = socket.as_socket();
        if !gnunet_native::network::is_listener(original)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "listening socket required",
            ));
        }
        socket.set_nonblocking(true)?;
        #[cfg(unix)]
        {
            super::RegisteredReadiness::new(socket.into())
                .map(|inner| Self { inner })
                .map_err(|failure| failure.error)
        }
        #[cfg(windows)]
        {
            let original: std::net::TcpStream = socket.into();
            tokio::net::TcpStream::from_std(original).map(|inner| Self {
                inner,
                protection: None,
            })
        }
    }

    /// Register this prepared local socket for nonconsuming managed readiness.
    /// Retain pre-listen ACL evidence and return the creator's path owner.
    #[cfg(windows)]
    pub fn from_prepared_local(
        prepared: crate::local_listener::PreparedLocalListener,
    ) -> io::Result<(Self, crate::CreatedPath, Vec<io::Error>)> {
        let (socket, path, warnings, protection) = prepared.into_protected_parts();
        let mut listener = Self::new(socket)?;
        listener.protection = Some(protection);
        Ok((listener, path, warnings))
    }

    /// Register an original activated local listener without adopting its path.
    #[cfg(windows)]
    pub fn from_activated_local(
        socket: crate::activation::ActivatedLocalSocket,
    ) -> io::Result<Self> {
        let (socket, protection) = socket.into_parts();
        let mut listener = Self::new(socket)?;
        listener.protection = protection;
        Ok(listener)
    }

    /// Preserve this original registered listener's pre-listen ACL evidence
    /// when preparing a managed child launch.
    #[cfg(windows)]
    pub fn launch_source(&self) -> gnunet_native::socket_activation::Source<'_> {
        let source = gnunet_native::socket_activation::Source::new(self.as_socket());
        match &self.protection {
            Some(protection) => source.with_protection(protection),
            None => source,
        }
    }

    /// Confirm current readability independently of reactor cached hints.
    /// No current event is `WouldBlock`; exceptional flags remain explicit.
    pub fn level(&self) -> io::Result<Readiness> {
        #[cfg(unix)]
        let original = self.as_fd();
        #[cfg(windows)]
        let original = self.as_socket();
        gnunet_native::network::socket_readiness(original, super::SocketInterest::Readable)?
            .map(|events| Readiness {
                readable: events.readable,
                hangup: events.hangup,
                error: events.error,
            })
            .ok_or_else(|| io::ErrorKind::WouldBlock.into())
    }
    /// Register a wakeup and confirm its hint using native poll0. Cached false
    /// positives are cleared/rearmed through the owning reactor before waiting.
    pub fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<Readiness>> {
        #[cfg(unix)]
        {
            self.inner.poll_ready(cx)
        }
        #[cfg(windows)]
        {
            use std::task::ready;
            use tokio::io::Interest;
            ready!(self.inner.poll_read_ready(cx))?;
            match self.inner.try_io(Interest::READABLE, || self.level()) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    // Clear/rearm through Mio, then take one guarded caller turn
                    // instead of spinning through repeated cached hints.
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                result => Poll::Ready(result),
            }
        }
    }
}
#[cfg(unix)]
impl AsFd for RegisteredListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.as_fd()
    }
}
#[cfg(windows)]
impl AsSocket for RegisteredListener {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.inner.as_socket()
    }
}
