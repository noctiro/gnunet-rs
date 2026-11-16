//! AF_UNIX sockets over Tokio/Mio's Windows stream-socket readiness machinery.
//! The private carrier registers the original Winsock handle for generic stream
//! I/O. Native accept, address queries and service tags retain AF_UNIX identity.
use gnunet_native::local_socket::{self, Address};
use socket2::{Domain, SockAddr, SockRef, Socket, Type};
use std::{
    fmt, io,
    os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket},
    path::Path,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, Interest, ReadBuf},
    net::TcpStream,
};

struct Registration(TcpStream);
impl fmt::Debug for Registration {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output
            .debug_struct("LocalRegistration")
            .field("socket", &self.as_socket().as_raw_socket())
            .finish_non_exhaustive()
    }
}
impl Registration {
    fn new(socket: Socket) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        socket.set_nonblocking(true)?;
        // Socket2's safe conversion transfers the original Winsock handle.
        // Both std and Mio use generic socket I/O; the carrier stays private.
        let stream: std::net::TcpStream = socket.into();
        TcpStream::from_std(stream).map(Self)
    }
}
impl AsSocket for Registration {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.0.as_socket()
    }
}
fn check_stream(socket: &Socket) -> io::Result<()> {
    if socket.r#type()? != Type::STREAM {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    Ok(())
}
fn endpoint(path: &Path) -> io::Result<SockAddr> {
    let text = path
        .to_str()
        .filter(|value| !value.is_empty() && !value.as_bytes().contains(&0))
        .ok_or(io::ErrorKind::InvalidInput)?;
    SockAddr::unix(text)
}
/// Original nonblocking Windows AF_UNIX listening socket.
/// The caller separately owns endpoint ACLs and filesystem-node cleanup.
#[derive(Debug)]
pub struct Listener {
    registration: Registration,
}
impl Listener {
    /// Bind one native AF_UNIX stream listener under the entered I/O runtime.
    /// Existing nodes are never removed. The caller owns endpoint ACL policy
    /// and filesystem-node cleanup, including a failure after successful bind.
    pub fn bind(path: impl AsRef<Path>) -> io::Result<Self> {
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.bind(&endpoint(path.as_ref())?)?;
        socket.listen(128)?;
        Self::from_bound_socket(socket)
    }
    /// Take an already bound/listening AF_UNIX stream socket into the reactor.
    /// No path is created, removed or substituted. The original handle is closed
    /// on failure; the caller must retain its filesystem cleanup owner throughout.
    ///
    /// # Errors
    /// Rejects wrong socket roles/families and unavailable runtime, and preserves
    /// native inspection/nonblocking/registration errors.
    ///
    /// # Panics
    /// Like Tokio native registration, panics if the entered runtime disables I/O.
    pub fn from_bound_socket(socket: Socket) -> io::Result<Self> {
        check_stream(&socket)?;
        local_socket::local_address(socket.as_socket())?;
        if !local_socket::is_listener(socket.as_socket())? {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Registration::new(socket).map(|registration| Self { registration })
    }
    /// Native bound name, without a filesystem lookup or peer authority.
    ///
    /// # Errors
    /// Preserves native address errors and refuses malformed native address data.
    pub fn local_addr(&self) -> io::Result<Address> {
        local_socket::local_address(self.as_socket())
    }
    /// Poll one native accept. Pending consumes no connection and creates no
    /// application client. Accept/registration failure closes only its new socket.
    ///
    /// # Panics
    /// Panics when accepting into an entered runtime with I/O disabled.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(Stream, Address)>> {
        loop {
            ready!(self.registration.0.poll_read_ready(cx))?;
            // Tokio delegates try_io to Mio as well as clearing Tokio readiness;
            // this rearms Windows AFD after the raw native accept WouldBlock.
            let accepted = self
                .registration
                .0
                .try_io(Interest::READABLE, || SockRef::from(self).accept());
            match accepted {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => return Poll::Ready(Err(error)),
                Ok((socket, _)) => {
                    return Poll::Ready((|| {
                        let peer = local_socket::peer_address(socket.as_socket())?;
                        Ok((Stream::from_connected_socket(socket)?, peer))
                    })());
                }
            }
        }
    }
    /// Accept one actual local stream; cancellation leaves this listener owned.
    ///
    /// # Errors
    /// Returns original native accept/address/registration errors.
    ///
    /// # Panics
    /// Panics when accepting into an entered runtime with I/O disabled.
    pub async fn accept(&self) -> io::Result<(Stream, Address)> {
        std::future::poll_fn(|cx| self.poll_accept(cx)).await
    }
}
impl AsSocket for Listener {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.registration.as_socket()
    }
}
/// Original Windows AF_UNIX connected stream with cancellation-safe ownership.
/// This supplies bytes and readiness, not an authenticated process or SID.
#[derive(Debug)]
pub struct Stream {
    registration: Registration,
}
impl Stream {
    /// Take an already connected AF_UNIX stream into the reactor without copying
    /// or replacing its native handle. Failure closes that original handle.
    ///
    /// # Errors
    /// Rejects wrong type/family/role, and preserves native/runtime failures.
    ///
    /// # Panics
    /// Panics if the entered runtime disables I/O.
    pub fn from_connected_socket(socket: Socket) -> io::Result<Self> {
        check_stream(&socket)?;
        if local_socket::is_listener(socket.as_socket())? {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        local_socket::peer_address(socket.as_socket())?;
        Registration::new(socket).map(|registration| Self { registration })
    }
    /// Connect to a native Windows UTF-8 filesystem endpoint. Dropping the future
    /// closes its original socket; it cannot retract a peer's earlier acceptance.
    ///
    /// # Errors
    /// Rejects empty/NUL/non-Unicode/oversized AF_UNIX names and preserves native
    /// connect/runtime/readiness errors. Transport selection remains AF_UNIX.
    ///
    /// # Panics
    /// Panics if the entered runtime disables I/O.
    pub async fn connect(path: impl AsRef<Path>) -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let address = endpoint(path.as_ref())?;
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.set_nonblocking(true)?;
        match socket.connect(&address) {
            Ok(()) => return Self::from_connected_socket(socket),
            Err(error) if local_socket::is_connect_pending(&error) => {}
            Err(error) => return Err(error),
        }
        let registration = Registration::new(socket)?;
        loop {
            registration.0.writable().await?;
            match registration.0.try_io(Interest::WRITABLE, || {
                if let Some(error) = SockRef::from(&registration).take_error()? {
                    return Err(error);
                }
                match local_socket::peer_address(registration.as_socket()) {
                    Ok(_) => Ok(()),
                    Err(error) if local_socket::is_not_connected(&error) => {
                        Err(io::ErrorKind::WouldBlock.into())
                    }
                    Err(error) => Err(error),
                }
            }) {
                Ok(()) => return Ok(Self { registration }),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
    }
    /// Native local name; it may be unnamed for an outgoing client.
    ///
    /// # Errors
    /// Preserves native query/length/encoding errors.
    pub fn local_addr(&self) -> io::Result<Address> {
        local_socket::local_address(self.as_socket())
    }
    /// Actual peer name; it supplies no peer-credential authority.
    ///
    /// # Errors
    /// Preserves native query/length/encoding errors.
    pub fn peer_addr(&self) -> io::Result<Address> {
        local_socket::peer_address(self.as_socket())
    }
    /// Await this original socket's read readiness. Readiness is not data,
    /// authentication, peer liveness or a processing receipt.
    pub async fn readable(&self) -> io::Result<()> {
        self.registration.0.readable().await
    }
    /// Await original writable readiness without submitting bytes. Readiness
    /// may be spurious; callers must still handle `WouldBlock` from a write.
    pub async fn writable(&self) -> io::Result<()> {
        self.registration.0.writable().await
    }
    /// Try one nonblocking read on the original socket. Preserves native errors
    /// and actual byte counts; WouldBlock transfers no bytes.
    pub fn try_read(&self, bytes: &mut [u8]) -> io::Result<usize> {
        self.registration.0.try_read(bytes)
    }
    /// Poll original writable readiness without consuming bytes.
    pub fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.registration.0.poll_write_ready(cx)
    }
    /// Attempt one bounded write; WouldBlock consumes no bytes.
    ///
    /// # Errors
    /// Preserves native write errors, including WouldBlock and Interrupted.
    pub fn try_write(&self, bytes: &[u8]) -> io::Result<usize> {
        self.registration.0.try_write(bytes)
    }
    /// Attempt one native scatter write without adding framing.
    ///
    /// # Errors
    /// Preserves native write errors and actual short-write counts.
    pub fn try_write_vectored(&self, slices: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.registration.0.try_write_vectored(slices)
    }
}
impl AsSocket for Stream {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        self.registration.as_socket()
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().registration.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().registration.0).poll_write(cx, bytes)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slices: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().registration.0).poll_write_vectored(cx, slices)
    }
    fn is_write_vectored(&self) -> bool {
        self.registration.0.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().registration.0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().registration.0).poll_shutdown(cx)
    }
}
