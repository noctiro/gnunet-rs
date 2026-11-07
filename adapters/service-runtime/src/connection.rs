//! Uniquely owned Unix/TCP connections, independent of protocol clients.
use crate::stream::Stream;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
/// An owned dependent resource released before its original service socket.
/// This port has no protocol, DNS or acknowledgement methods.
pub trait ConnectionLease: Send {}
/// Both original owners returned when a connection already retains a lease.
pub type LeaseRejection = gnunet_types::Rejected<(Connection, Box<dyn ConnectionLease>)>;

/// Uniquely owned service stream. Drop closes only this original connection.
/// Reading/writing bytes supplies no protocol or acknowledgement authority.
pub struct Connection {
    // Fields drop in declaration order: release dependent resources while the
    // exact original socket is still open. Neither drop implies protocol success.
    lease: Option<Box<dyn ConnectionLease>>,
    stream: Stream,
}

impl std::os::fd::AsFd for Connection {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        match &self.stream {
            Stream::Unix(stream) => stream.as_fd(),
            Stream::Tcp(stream) => stream.as_fd(),
        }
    }
}

impl Connection {
    /// Whether this original owned stream is Unix. This performs no I/O or
    /// credential lookup and supplies no peer authentication authority.
    #[must_use]
    pub const fn is_unix(&self) -> bool {
        matches!(self.stream, Stream::Unix(_))
    }
    /// Kernel-reported Unix peer UID/GID, or None for TCP. This only observes
    /// the original owned socket; it performs no account lookup or admission.
    pub fn unix_peer_credentials(&self) -> io::Result<Option<(u32, u32)>> {
        match &self.stream {
            Stream::Unix(stream) => {
                #[cfg(target_os = "macos")]
                {
                    // Admission uses only kernel UID/GID. Darwin's independent
                    // peer PID query can fail after disconnect even though the
                    // connect-time credentials remain available on this socket.
                    let (uid, gid) = nix::unistd::getpeereid(stream).map_err(io::Error::from)?;
                    Ok(Some((uid.as_raw(), gid.as_raw())))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let peer = stream.peer_cred()?;
                    Ok(Some((peer.uid(), peer.gid())))
                }
            }
            Stream::Tcp(_) => Ok(None),
        }
    }
    /// Retain an explicit resource lease until this original connection closes.
    /// Rejection returns both original owners unchanged; no lease is replaced.
    pub fn with_lease(mut self, lease: Box<dyn ConnectionLease>) -> Result<Self, LeaseRejection> {
        if self.lease.is_some() {
            return Err(gnunet_types::Rejected {
                reason: gnunet_types::Error::Conflict,
                value: (self, lease),
            });
        }
        self.lease = Some(lease);
        Ok(self)
    }
    /// Whether this connected stream still owns a lifetime lease. The
    /// resource may already be inactive; this supplies no protocol status.
    #[must_use]
    pub fn retains_lease(&self) -> bool {
        self.lease.is_some()
    }

    /// Take an already configured, uniquely owned Unix stream without I/O.
    /// This establishes no protocol, peer authentication or admission authority.
    pub fn from_unix(stream: tokio::net::UnixStream) -> Self {
        Self {
            lease: None,
            stream: Stream::Unix(stream),
        }
    }

    /// Take an already configured, uniquely owned TCP stream without I/O.
    /// The caller retains responsibility for native socket options and policy;
    /// wrapping a stream establishes no protocol or peer authentication.
    pub fn from_tcp(stream: tokio::net::TcpStream) -> Self {
        Self {
            lease: None,
            stream: Stream::Tcp(stream),
        }
    }

    /// Poll physical write readiness. Retain the original write cursor and
    /// re-check readiness after WouldBlock; readiness does not transfer bytes.
    pub fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_write_ready(cx)
    }

    /// Attempt one nonblocking write, reporting the actual transferred count.
    /// WouldBlock/Interrupted transfer no bytes; the caller retains its cursor.
    pub fn try_write(&self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.try_write(bytes)
    }

    /// Attempt one nonblocking vectored write on this original socket. The count
    /// covers only actual transferred bytes in slice order; no protocol outcome
    /// or per-operation completion is inferred.
    pub fn try_write_vectored(&self, slices: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.stream.try_write_vectored(slices)
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Original socket lifetime assertions with fallible setup"
    )]
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };
    struct Lease {
        peer: std::os::unix::net::UnixStream,
        result: Arc<Mutex<Option<bool>>>,
    }
    impl ConnectionLease for Lease {}
    impl Drop for Lease {
        fn drop(&mut self) {
            let ok = self.peer.write_all(b"lease").is_ok();
            if let Ok(mut result) = self.result.lock() {
                *result = Some(ok);
            }
        }
    }
    fn runtime() -> io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }
    #[test]
    fn dependent_lease_drops_while_original_socket_is_still_open() -> io::Result<()> {
        runtime()?.block_on(async {
            let (stream, peer) = std::os::unix::net::UnixStream::pair()?;
            stream.set_nonblocking(true)?;
            let result = Arc::new(Mutex::new(None));
            let connection = Connection::from_unix(tokio::net::UnixStream::from_std(stream)?);
            let connection = connection
                .with_lease(Box::new(Lease {
                    peer,
                    result: result.clone(),
                }))
                .map_err(|r| io::Error::other(r.reason))?;
            assert!(connection.retains_lease());
            drop(connection);
            assert_eq!(
                *result.lock().map_err(|_| io::Error::other("lock"))?,
                Some(true)
            );
            Ok(())
        })
    }
    #[test]
    fn second_lease_refusal_returns_both_original_owners_without_replacement() -> io::Result<()> {
        runtime()?.block_on(async {
            let (stream, peer) = std::os::unix::net::UnixStream::pair()?;
            stream.set_nonblocking(true)?;
            let (other, second_peer) = std::os::unix::net::UnixStream::pair()?;
            let _other = other;
            let first = Arc::new(Mutex::new(None));
            let second = Arc::new(Mutex::new(None));
            let connection = Connection::from_unix(tokio::net::UnixStream::from_std(stream)?)
                .with_lease(Box::new(Lease {
                    peer,
                    result: first.clone(),
                }))
                .map_err(|r| io::Error::other(r.reason))?;
            let rejected = match connection.with_lease(Box::new(Lease {
                peer: second_peer,
                result: second.clone(),
            })) {
                Err(rejected) => rejected,
                Ok(_) => return Err(io::Error::other("lease replaced")),
            };
            assert_eq!(rejected.reason, gnunet_types::Error::Conflict);
            assert_eq!(*first.lock().map_err(|_| io::Error::other("lock"))?, None);
            assert_eq!(*second.lock().map_err(|_| io::Error::other("lock"))?, None);
            let (connection, lease) = rejected.value;
            drop(lease);
            assert_eq!(*first.lock().map_err(|_| io::Error::other("lock"))?, None);
            drop(connection);
            assert_eq!(
                *first.lock().map_err(|_| io::Error::other("lock"))?,
                Some(true)
            );
            Ok(())
        })
    }
}
