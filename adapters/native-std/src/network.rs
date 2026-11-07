//! Native initialization of an already accepted uniquely owned socket.
//! Borrowing never transfers ownership, accepts, closes or substitutes a socket.
use std::{fmt, io};

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
