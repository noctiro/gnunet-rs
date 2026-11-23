//! Native socket errors stay separate from peer attribution and send receipts.
use std::io;
#[cfg(all(
    feature = "socket-io",
    any(
        windows,
        target_os = "linux",
        target_os = "freebsd",
        target_os = "macos"
    )
))]
pub(super) mod local;
#[cfg(all(windows, feature = "socket-io"))]
pub(super) mod send_windows;
#[cfg(feature = "socket-io")]
pub(super) mod source;
#[cfg(test)]
mod tests;
/// Whether one failed atomic UDP send can retire its intended endpoint while
/// retaining the shared socket. An asynchronous cause does not authenticate or
/// identify the peer that caused it. Lifecycle, allocation and short-write
/// failures remain terminal to the owner.
pub fn isolated_datagram_send_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NetworkDown
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(libc::EMSGSIZE | libc::EHOSTDOWN | libc::EDESTADDRREQ)
        )
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{WSAEDESTADDRREQ, WSAEHOSTDOWN, WSAEMSGSIZE};
        matches!(
            error.raw_os_error(),
            Some(WSAEMSGSIZE | WSAEHOSTDOWN | WSAEDESTADDRREQ)
        )
    }
}

/// Whether one UDP receive can retire without declaring its shared source lost.
/// An asynchronous error identifies neither a peer nor a successful earlier send.
/// Windows TTL-expiration reports preserve that distinction and their raw code.
pub fn isolated_datagram_receive_error(error: &io::Error) -> bool {
    if matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::Interrupted
    ) {
        return true;
    }
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::EMSGSIZE)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{WSAEMSGSIZE, WSAENETRESET};
        matches!(error.raw_os_error(), Some(WSAEMSGSIZE | WSAENETRESET))
    }
}
/// A genuine unavailable socket family/protocol/option, permitting another family.
pub fn socket_family_unavailable(error: &io::Error) -> bool {
    #[cfg(unix)]
    {
        matches!(
            error.raw_os_error(),
            Some(libc::EAFNOSUPPORT | libc::EPROTONOSUPPORT | libc::ENOPROTOOPT)
        )
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Networking::WinSock::{
            WSAEAFNOSUPPORT, WSAENOPROTOOPT, WSAEPROTONOSUPPORT,
        };
        matches!(
            error.raw_os_error(),
            Some(WSAEAFNOSUPPORT | WSAEPROTONOSUPPORT | WSAENOPROTOOPT)
        )
    }
}
/// Configure this borrowed UDP socket so ICMP port-unreachable messages do not
/// turn unrelated receives into Winsock connection-reset errors. No owner or
/// socket mode is replaced; failure retains the original WSA error code.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "WSAIoctl borrows the live socket and initialized fixed-size BOOL/result storage for one synchronous option call"
)]
pub fn suppress_udp_connection_resets(
    socket: std::os::windows::io::BorrowedSocket<'_>,
) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        SIO_UDP_CONNRESET, SOCKET_ERROR, WSAGetLastError, WSAIoctl,
    };
    let disabled = 0_u32;
    let mut returned = 0_u32;
    // SAFETY: the original socket remains borrowed; all pointer extents match
    // their initialized storage and the call is synchronous, without callbacks.
    if unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_UDP_CONNRESET,
            (&disabled as *const u32).cast(),
            size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    } == SOCKET_ERROR
    {
        // SAFETY: immediate thread-local error capture after the failed call.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}
