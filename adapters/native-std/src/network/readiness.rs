//! Nonconsuming, nonblocking socket observations on the original native handle.
use super::BorrowedStream;
use std::io;

/// Requested ordinary I/O directions; exceptional conditions are always observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SocketInterest {
    /// Readable bytes, EOF or a listening socket's accept backlog.
    Readable,
    /// Ordinary write progress.
    Writable,
    /// Both ordinary directions.
    ReadWrite,
}
/// Actual native level flags. Readiness does not consume data or grant a
/// connection, processing acknowledgement, child identity or lifetime lease.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SocketEvents {
    /// Native ordinary read readiness, including a listener's backlog.
    pub readable: bool,
    /// Native ordinary write readiness.
    pub writable: bool,
    /// Native hangup; callers retain their own EOF policy.
    pub hangup: bool,
    /// Native exceptional socket condition.
    pub error: bool,
}

/// Observe one still-borrowed original socket with a zero-timeout native poll.
/// `None` means no current event. Invalid handles and interrupted system calls
/// remain errors. This never changes socket options, accepts, reads, writes,
/// duplicates, registers a watcher or creates a worker.
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "poll borrows one live original fd and a fully initialized single pollfd for a zero-timeout observation"
)]
pub fn socket_readiness(
    socket: BorrowedStream<'_>,
    interest: SocketInterest,
) -> io::Result<Option<SocketEvents>> {
    use std::os::fd::AsRawFd;
    let events = match interest {
        SocketInterest::Readable => libc::POLLIN,
        SocketInterest::Writable => libc::POLLOUT,
        SocketInterest::ReadWrite => libc::POLLIN | libc::POLLOUT,
    };
    let mut descriptor = libc::pollfd {
        fd: socket.as_raw_fd(),
        events,
        revents: 0,
    };
    // SAFETY: original fd and exact writable record remain live for poll0.
    if unsafe { libc::poll(&mut descriptor, 1, 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let flags = descriptor.revents;
    if flags & libc::POLLNVAL != 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    }
    Ok(observed(SocketEvents {
        readable: flags & libc::POLLIN != 0,
        writable: flags & libc::POLLOUT != 0,
        hangup: flags & libc::POLLHUP != 0,
        error: flags & libc::POLLERR != 0,
    }))
}

/// Observe the original Winsock socket through WSAPoll without consuming its
/// accept queue or modifying shared event-selection/notification state.
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "WSAPoll borrows one live Winsock handle and an initialized single SDK pollfd for a zero-timeout observation; WSAGetLastError is captured immediately on failure"
)]
pub fn socket_readiness(
    socket: BorrowedStream<'_>,
    interest: SocketInterest,
) -> io::Result<Option<SocketEvents>> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{
        POLLERR, POLLHUP, POLLNVAL, POLLRDNORM, POLLWRNORM, SOCKET_ERROR, WSAENOTSOCK,
        WSAGetLastError, WSAPOLLFD, WSAPoll,
    };
    let events = match interest {
        SocketInterest::Readable => POLLRDNORM,
        SocketInterest::Writable => POLLWRNORM,
        SocketInterest::ReadWrite => POLLRDNORM | POLLWRNORM,
    };
    let mut descriptor = WSAPOLLFD {
        fd: socket.as_raw_socket() as usize,
        events,
        revents: 0,
    };
    // SAFETY: original SOCKET and exact initialized SDK record remain live.
    if unsafe { WSAPoll(&mut descriptor, 1, 0) } == SOCKET_ERROR {
        // SAFETY: immediate thread-local scalar error observation only.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let flags = descriptor.revents;
    if flags & POLLNVAL != 0 {
        return Err(io::Error::from_raw_os_error(WSAENOTSOCK));
    }
    Ok(observed(SocketEvents {
        readable: flags & POLLRDNORM != 0,
        writable: flags & POLLWRNORM != 0,
        hangup: flags & POLLHUP != 0,
        error: flags & POLLERR != 0,
    }))
}

fn observed(events: SocketEvents) -> Option<SocketEvents> {
    (events.readable || events.writable || events.hangup || events.error).then_some(events)
}
