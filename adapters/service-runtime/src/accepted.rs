//! Accepted-stream ownership and reactor socket initialization, before domain admission.
use crate::{
    connection::Connection,
    service::{Listener, PeerAddress},
    stream::Stream,
};
use gnunet_native::network::{self, Diagnostics, InitializationError, StreamKind};
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsSocket;
use std::{
    fmt, io,
    task::{Context, Poll},
};

/// Actual native failure before admitting a service client.
#[derive(Debug)]
pub enum AcceptError {
    /// Native/std/mio acceptance or reactor registration failed before this port
    /// obtained an owned stream. Its earlier failure policy is a separate scope.
    Accept(io::Error),
    /// The original accepted socket has already been dropped/closed. Primary
    /// native error and any earlier nonfatal diagnostics remain observable.
    Initialization(InitializationError),
    /// The original connection's configured local admission check failed.
    Credentials(io::Error),
}
impl AcceptError {
    /// Original accept or initialization errno, preserved across socket cleanup.
    pub fn io_error(&self) -> &io::Error {
        match self {
            Self::Accept(error) | Self::Credentials(error) => error,
            Self::Initialization(error) => &error.error,
        }
    }
    /// Actual OS EMFILE condition. Descriptor values have no artificial ceiling.
    #[must_use]
    pub fn is_emfile(&self) -> bool {
        !matches!(self, Self::Credentials(_)) && network::is_descriptor_limit(self.io_error())
    }
}
impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept(e) => e.fmt(f),
            Self::Initialization(e) => e.fmt(f),
            Self::Credentials(e) => write!(f, "local peer admission: {e}"),
        }
    }
}
impl std::error::Error for AcceptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Accept(e) | Self::Credentials(e) => Some(e),
            Self::Initialization(e) => Some(e),
        }
    }
}
/// Synchronous native acceptance diagnostics, in original syscall order.
/// This event creates no service client or application acknowledgement.
#[derive(Debug)]
pub enum SocketEvent {
    /// A nonfatal CLOEXEC or TCP_NODELAY failure; the stream remains usable.
    Diagnostic(network::Diagnostic),
    /// A native accept, initialization or credential failure. Initialization
    /// retains earlier diagnostics in order.
    /// This observation supplies no implicit logging level: service.c suspends
    /// silently on a raw accept EMFILE, whereas other accept errors warn.
    Failed(AcceptError),
}
/// The generic service's EMFILE suspension reason. Shutdown and explicit
/// suspension remain independent gates owned by the enclosing service.
/// `service.c:accept_client/finish_client_drop` suspends every listener on
/// EMFILE and resumes only after dropping a non-persisted admitted client.
#[derive(Debug, Default)]
pub struct AcceptState {
    emfile: bool,
}
impl AcceptState {
    /// Whether the enclosing service may poll its listeners for this reason.
    #[must_use]
    pub const fn ready(&self) -> bool {
        !self.emfile
    }
    /// Observe an actual accept/initialization failure and return its diagnostic
    /// for synchronous delivery. A fatal initialized stream is already closed.
    /// No timer, synthetic retry, client identity or processing result is created.
    pub fn failed(&mut self, failure: AcceptError) -> SocketEvent {
        if failure.is_emfile() {
            self.emfile = true;
        }
        SocketEvent::Failed(failure)
    }
    /// A service client was physically closed. Never call this for an ACL
    /// rejection, an unadmitted stream or a persisted socket still held open.
    pub fn client_closed(&mut self) {
        self.emfile = false;
    }
}
/// One actual accepted, canonically initialized stream and its original peer.
/// Native option diagnostics are bounded, never replaced by invented success.
/// This value grants no application handshake, authentication or core admission.
pub struct AcceptedConnection {
    connection: Connection,
    peer: PeerAddress,
    diagnostics: Diagnostics,
}

/// Initialize an owned reactor TCP stream without replacing its native socket.
///
/// The original stream and bounded nonfatal diagnostics are returned together.
/// This applies equally to accepted and outgoing streams and grants no protocol
/// admission or peer authentication.
///
/// # Errors
///
/// Fatal native initialization closes the original stream before returning its
/// error and any earlier nonfatal diagnostics.
pub fn initialize_tcp_stream(
    stream: tokio::net::TcpStream,
) -> Result<(tokio::net::TcpStream, Diagnostics), InitializationError> {
    initialize_tcp_with(stream, network::initialize_reactor_stream)
}

fn initialize_tcp_with(
    stream: tokio::net::TcpStream,
    initialize: impl FnOnce(
        network::BorrowedStream<'_>,
        StreamKind,
    ) -> Result<Diagnostics, InitializationError>,
) -> Result<(tokio::net::TcpStream, Diagnostics), InitializationError> {
    let diagnostics = initialize(tcp_handle(&stream), StreamKind::Tcp)?;
    Ok((stream, diagnostics))
}

fn tcp_handle(stream: &tokio::net::TcpStream) -> network::BorrowedStream<'_> {
    #[cfg(unix)]
    {
        stream.as_fd()
    }
    #[cfg(windows)]
    {
        stream.as_socket()
    }
}

impl AcceptedConnection {
    /// Borrow this exact original connection without replacing its descriptor.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
    /// Actual address returned by the original accepting operation.
    pub fn peer(&self) -> PeerAddress {
        self.peer
    }
    /// Bounded actual nonfatal native failures, in source order.
    pub fn diagnostics(&self) -> &Diagnostics {
        &self.diagnostics
    }
    /// Transfer the unique stream, original peer and diagnostics exactly once.
    pub fn into_parts(self) -> (Connection, PeerAddress, Diagnostics) {
        (self.connection, self.peer, self.diagnostics)
    }
}
pub(crate) fn canonical(
    stream: Stream,
    peer: PeerAddress,
) -> Result<AcceptedConnection, AcceptError> {
    canonical_with(stream, peer, network::initialize_reactor_stream)
}
fn canonical_with(
    stream: Stream,
    peer: PeerAddress,
    initialize: impl FnOnce(
        network::BorrowedStream<'_>,
        StreamKind,
    ) -> Result<Diagnostics, InitializationError>,
) -> Result<AcceptedConnection, AcceptError> {
    let diagnostics = match &stream {
        #[cfg(unix)]
        Stream::Unix(s) => initialize(s.as_fd(), StreamKind::Unix),
        Stream::Tcp(s) => initialize(tcp_handle(s), StreamKind::Tcp),
        #[cfg(windows)]
        Stream::Unix(s) => initialize(s.as_socket(), StreamKind::Unix),
    };
    match diagnostics {
        Err(error) => {
            drop(stream);
            Err(AcceptError::Initialization(error))
        }
        Ok(diagnostics) => {
            let connection = match stream {
                #[cfg(any(unix, windows))]
                Stream::Unix(s) => Connection::from_unix(s),
                Stream::Tcp(s) => Connection::from_tcp(s),
            };
            Ok(AcceptedConnection {
                connection,
                peer,
                diagnostics,
            })
        }
    }
}
impl Listener<'_> {
    /// Accept one real stream and apply the reactor socket initialization policy.
    /// Nonfatal CLOEXEC/TCP_NODELAY failures return with bounded diagnostics;
    /// fatal fd/nonblocking/Darwin NOSIGPIPE failures close only the accepted
    /// stream and preserve error/earlier diagnostics. No core admission occurs.
    /// Earlier std/mio accept initialization failure policies remain separate.
    pub fn poll_canonical_connection(
        self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<AcceptedConnection, AcceptError>> {
        poll_accept(self, cx).map(|result| match result {
            Ok((stream, peer)) => canonical(stream, peer),
            Err(error) => Err(AcceptError::Accept(error)),
        })
    }

    /// Accept one actual socket into the shared owned transport. The caller
    /// must still apply socket options, peer policy and protocol admission.
    /// Polling Pending does not consume a connection or invent a core client.
    pub fn poll_connection(
        self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(Connection, PeerAddress)>> {
        poll_accept(self, cx).map(|result| {
            result.map(|(stream, peer)| {
                let connection = match stream {
                    #[cfg(any(unix, windows))]
                    Stream::Unix(stream) => Connection::from_unix(stream),
                    Stream::Tcp(stream) => Connection::from_tcp(stream),
                };
                (connection, peer)
            })
        })
    }
}
fn poll_accept(
    listener: Listener<'_>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<(Stream, PeerAddress)>> {
    match listener {
        #[cfg(any(unix, windows))]
        Listener::Unix(listener) => listener
            .poll_accept(cx)
            .map(|r| r.map(|(s, _)| (Stream::Unix(s), PeerAddress::Unix))),
        Listener::Tcp(listener) => listener
            .poll_accept(cx)
            .map(|r| r.map(|(s, peer)| (Stream::Tcp(s), PeerAddress::Tcp(peer)))),
    }
}

#[cfg(test)]
mod tests {
    //! Real owner close/continuation checks with explicitly injected init policy.
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Actual resource invariants use assertions while setup errors propagate"
    )]
    use super::*;
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    #[cfg(windows)]
    use std::os::windows::io::AsRawSocket;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn runtime() -> io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }
    async fn tcp_pair() -> io::Result<(tokio::net::TcpStream, tokio::net::TcpStream)> {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let stream = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
        let (peer, _) = listener.accept().await?;
        Ok((stream, peer))
    }
    #[test]
    fn credential_failure_rejects_one_stream_without_suspending_accept() -> io::Result<()> {
        runtime()?.block_on(async {
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let endpoint = listener.local_addr()?;
            let mut first = tokio::net::TcpStream::connect(endpoint).await?;
            let (stream, _) = listener.accept().await?;
            let connection = Connection::from_tcp(stream);
            let access = crate::credentials::UnixAccess {
                match_uid: true,
                match_gid: false,
            };
            let mut failure = None;
            assert!(!access.admits(&connection, |event| failure = Some(event)));
            let Some(SocketEvent::Failed(AcceptError::Credentials(error))) = failure else {
                return Err(io::Error::other("missing native credential failure"));
            };
            #[cfg(unix)]
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            #[cfg(windows)]
            assert_eq!(error.kind(), io::ErrorKind::Unsupported);
            drop(connection);
            let mut byte = [0];
            assert_eq!(first.read(&mut byte).await?, 0);

            #[cfg(unix)]
            {
                let mut state = AcceptState::default();
                let error = AcceptError::Credentials(io::Error::from_raw_os_error(libc::EMFILE));
                assert!(
                    matches!(state.failed(error), SocketEvent::Failed(error) if !error.is_emfile())
                );
                assert!(state.ready());
            }
            let mut second = tokio::net::TcpStream::connect(endpoint).await?;
            let (mut next, _) = listener.accept().await?;
            second.write_all(b"q").await?;
            next.read_exact(&mut byte).await?;
            assert_eq!(byte, *b"q");
            Ok(())
        })
    }
    #[test]
    fn tcp_initialization_returns_original_usable_socket() -> io::Result<()> {
        runtime()?.block_on(async {
            let (stream, mut peer) = tcp_pair().await?;
            #[cfg(unix)]
            let original = stream.as_raw_fd();
            #[cfg(windows)]
            let original = stream.as_raw_socket();
            let (mut stream, _diagnostics) =
                initialize_tcp_stream(stream).map_err(io::Error::other)?;
            #[cfg(unix)]
            assert_eq!(stream.as_raw_fd(), original);
            #[cfg(windows)]
            assert_eq!(stream.as_raw_socket(), original);
            assert!(stream.nodelay()?);
            peer.write_all(b"q").await?;
            let mut byte = [0];
            stream.read_exact(&mut byte).await?;
            assert_eq!(byte, *b"q");
            Ok(())
        })
    }
    #[test]
    fn tcp_fatal_initialization_closes_original_socket_before_returning_error() -> io::Result<()> {
        runtime()?.block_on(async {
            let (stream, mut peer) = tcp_pair().await?;
            let result = initialize_tcp_with(stream, |_native, kind| {
                assert_eq!(kind, StreamKind::Tcp);
                Err(InitializationError {
                    error: io::Error::new(io::ErrorKind::PermissionDenied, "native initialization"),
                    diagnostics: Diagnostics::default(),
                })
            });
            let error = match result {
                Err(error) => error,
                Ok(_) => {
                    return Err(io::Error::other(
                        "fatal initialization returned a live socket",
                    ));
                }
            };
            assert_eq!(error.error.kind(), io::ErrorKind::PermissionDenied);
            assert_eq!(error.error.to_string(), "native initialization");
            assert!(error.diagnostics.is_empty());
            let mut byte = [0];
            assert_eq!(peer.read(&mut byte).await?, 0);
            Ok(())
        })
    }
    #[cfg(unix)]
    #[test]
    fn injected_fatal_initialization_closes_only_actual_accepted_owner() -> io::Result<()> {
        runtime()?.block_on(async{
        let(stream,mut peer)=tokio::net::UnixStream::pair()?;
        let error=canonical_with(Stream::Unix(stream),PeerAddress::Unix,|_fd,_kind|Err(InitializationError{error:io::Error::from_raw_os_error(nix::errno::Errno::EMFILE as i32),diagnostics:Diagnostics::default()}));
        assert!(matches!(error,Err(AcceptError::Initialization(e))if e.error.raw_os_error()==Some(nix::errno::Errno::EMFILE as i32)));
        let mut byte=[0];assert_eq!(peer.read(&mut byte).await?,0);Ok(())
    })
    }
    #[cfg(unix)]
    #[test]
    fn injected_wrong_kind_actual_nonfatal_setter_error_returns_original_usable_stream()
    -> io::Result<()> {
        runtime()?.block_on(async {
            let (stream, mut peer) = tokio::net::UnixStream::pair()?;
            // The production accepting layer chooses Unix correctly. This finite
            // injected wrong-kind syscall error is component evidence only.
            let accepted = canonical_with(Stream::Unix(stream), PeerAddress::Unix, |fd, _kind| {
                network::initialize_reactor_stream(fd, StreamKind::Tcp)
            })
            .map_err(io::Error::other)?;
            assert!(accepted.diagnostics().tcp_no_delay().is_some());
            let (mut connection, address, diagnostics) = accepted.into_parts();
            assert_eq!(address, PeerAddress::Unix);
            assert_eq!(diagnostics.into_iter().count(), 1);
            peer.write_all(b"q").await?;
            let mut byte = [0];
            connection.read_exact(&mut byte).await?;
            assert_eq!(byte, *b"q");
            Ok(())
        })
    }
}
