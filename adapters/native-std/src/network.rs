//! Borrowed native socket initialization, listen-role and readiness observations.
//! Borrowing never transfers ownership, accepts, closes or substitutes a socket.
use std::{fmt, io};
#[cfg(windows)]
pub(crate) mod adapters;
mod address;
mod datagram;
#[cfg(unix)]
mod descriptor;
mod listener;
mod readiness;
pub use address::{
    SocketAddressHeader, UnixAddressLayout, socket_address_header, unix_address_layout,
};
#[cfg(all(
    feature = "socket-io",
    any(target_os = "linux", target_os = "freebsd", target_os = "macos")
))]
pub use datagram::local::LocalDatagram;
#[cfg(all(windows, feature = "socket-io"))]
pub use datagram::local::LocalDatagramIo;
#[cfg(all(
    feature = "socket-io",
    any(
        windows,
        target_os = "linux",
        target_os = "freebsd",
        target_os = "macos"
    )
))]
pub use datagram::local::LocalReplyPath;
#[cfg(all(windows, feature = "socket-io"))]
pub use datagram::send_windows::send_datagram_from;
#[cfg(feature = "socket-io")]
pub use datagram::source::DatagramSource;
#[cfg(windows)]
pub use datagram::suppress_udp_connection_resets;
pub use datagram::{
    isolated_datagram_receive_error, isolated_datagram_send_error, socket_family_unavailable,
};
#[cfg(unix)]
pub use descriptor::StableFd;
pub use listener::is_listener;
#[cfg(target_os = "macos")]
pub use listener::{DARWIN_SOCKET_INFO_BUFFER_BYTES, DARWIN_SOCKET_OPTIONS_OFFSET};
pub use readiness::{SocketEvents, SocketInterest, socket_readiness};

/// A live borrowed native socket; it never grants ownership.
#[cfg(unix)]
pub type BorrowedStream<'a> = std::os::fd::BorrowedFd<'a>;
/// A live borrowed native socket; it never grants ownership.
#[cfg(windows)]
pub type BorrowedStream<'a> = std::os::windows::io::BorrowedSocket<'a>;

/// Actual transport kind supplied by the accepting layer, not a wire flag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamKind {
    /// Non-Unix TCP stream; attempts TCP_NODELAY after other initialization.
    Tcp,
    /// Unix stream; source skips TCP_NODELAY, retaining other native policy.
    Unix,
}
/// A source-nonfatal diagnostic. No option success is inferred from this value.
#[derive(Debug)]
pub enum Diagnostic {
    /// `socket_set_inheritable` failure: source logs ERROR|BULK and continues.
    CloseOnExec(io::Error),
    /// TCP_NODELAY failure: source logs WARNING and continues.
    TcpNoDelay(io::Error),
}
/// Two fixed diagnostic slots, preserving source order without a growable queue.
#[derive(Debug, Default)]
pub struct Diagnostics {
    close_on_exec: Option<io::Error>,
    tcp_no_delay: Option<io::Error>,
}
impl Diagnostics {
    /// Actual close-on-exec diagnostic, if its native attempt failed.
    pub fn close_on_exec(&self) -> Option<&io::Error> {
        self.close_on_exec.as_ref()
    }
    /// Actual TCP_NODELAY diagnostic, if its native attempt failed.
    pub fn tcp_no_delay(&self) -> Option<&io::Error> {
        self.tcp_no_delay.as_ref()
    }
    /// Whether no native nonfatal failure was observed.
    pub fn is_empty(&self) -> bool {
        self.close_on_exec.is_none() && self.tcp_no_delay.is_none()
    }
}
impl IntoIterator for Diagnostics {
    type Item = Diagnostic;
    type IntoIter = std::iter::Flatten<std::array::IntoIter<Option<Diagnostic>, 2>>;
    fn into_iter(self) -> Self::IntoIter {
        [
            self.close_on_exec.map(Diagnostic::CloseOnExec),
            self.tcp_no_delay.map(Diagnostic::TcpNoDelay),
        ]
        .into_iter()
        .flatten()
    }
}
/// Fatal initialization failure plus earlier nonfatal diagnostics, if any.
/// The borrowed function has not closed the original socket; its owning accept
/// layer must drop/close it before returning this error to a peer consumer.
#[derive(Debug)]
pub struct InitializationError {
    /// Captured primary native error, unaffected by later owner cleanup.
    pub error: io::Error,
    /// Earlier real nonfatal attempts, retained even when a later step failed.
    pub diagnostics: Diagnostics,
}
impl fmt::Display for InitializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl std::error::Error for InitializationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(target_vendor = "apple")]
pub use unix::unix_peer_ids;
#[cfg(unix)]
pub use unix::{initialize_accepted_stream, initialize_reactor_stream};
#[cfg(windows)]
pub use windows::set_exclusive_address_use;
#[cfg(windows)]
pub use windows::{initialize_accepted_stream, initialize_reactor_stream};

/// Whether the original OS error reports native descriptor/socket exhaustion.
pub fn is_descriptor_limit(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::EMFILE)
    }
    #[cfg(windows)]
    {
        error.raw_os_error()
            == Some(windows_sys::Win32::Foundation::ERROR_TOO_MANY_OPEN_FILES as i32)
            || error.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEMFILE)
    }
}

/// Whether a socket-family probe failed because native system resources or
/// access were refused, rather than because that family is unavailable.
pub fn is_fatal_family_probe(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::PermissionDenied || is_descriptor_limit(error) {
        return true;
    }
    #[cfg(unix)]
    {
        error
            .raw_os_error()
            .is_some_and(|code| [libc::ENOBUFS, libc::ENOMEM, libc::ENFILE].contains(&code))
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::{
            Foundation::{ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY},
            Networking::WinSock::WSAENOBUFS,
        };
        error.raw_os_error().is_some_and(|code| {
            [
                WSAENOBUFS,
                ERROR_NOT_ENOUGH_MEMORY as i32,
                ERROR_OUTOFMEMORY as i32,
            ]
            .contains(&code)
        })
    }
}

/// Whether this original nonblocking Internet-stream connect needs completion
/// observation. This neither retries connect nor establishes peer association.
/// Winsock WSAEINPROGRESS describes a separate blocking operation, not this
/// fresh socket's accepted asynchronous connect. See the [Winsock contract](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect).
pub fn connect_in_progress(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::EINPROGRESS)
    }
    #[cfg(windows)]
    {
        error.raw_os_error() == Some(windows_sys::Win32::Networking::WinSock::WSAEWOULDBLOCK)
    }
}
