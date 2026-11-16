//! Original Windows helper pipe and console resources; no implicit elevation.
mod output;
mod signals;
pub use output::{Output, State};
pub use signals::Signals;

/// Wait on one original Winsock socket. The caller bounds the wait to preserve
/// its own stop, pipe-lifetime and packet deadlines; no event selection changes.
#[expect(
    unsafe_code,
    reason = "WSAPoll borrows one initialized SDK descriptor and captures WSAGetLastError immediately"
)]
pub fn wait_socket(
    socket: std::os::windows::io::BorrowedSocket<'_>,
    interest: crate::network::SocketInterest,
    timeout: std::time::Duration,
) -> std::io::Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        POLLNVAL, POLLRDNORM, POLLWRNORM, SOCKET_ERROR, WSAENOTSOCK, WSAGetLastError, WSAPOLLFD,
        WSAPoll,
    };
    let events = match interest {
        crate::network::SocketInterest::Readable => POLLRDNORM,
        crate::network::SocketInterest::Writable => POLLWRNORM,
        crate::network::SocketInterest::ReadWrite => POLLRDNORM | POLLWRNORM,
    };
    let mut descriptor = WSAPOLLFD {
        fd: socket.as_raw_socket() as usize,
        events,
        revents: 0,
    };
    let millis = i32::try_from(timeout.as_micros().div_ceil(1000).min(500))
        .map_err(std::io::Error::other)?;
    // SAFETY: original socket and one initialized descriptor remain live.
    if unsafe { WSAPoll(&mut descriptor, 1, millis) } == SOCKET_ERROR {
        // SAFETY: immediate thread-local Winsock error query.
        return Err(std::io::Error::from_raw_os_error(unsafe {
            WSAGetLastError()
        }));
    }
    if descriptor.revents & POLLNVAL != 0 {
        return Err(std::io::Error::from_raw_os_error(WSAENOTSOCK));
    }
    Ok(())
}
