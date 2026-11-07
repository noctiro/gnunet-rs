//! Borrowed Winsock initialization; the accepting layer retains socket ownership.
use super::*;
use std::os::windows::io::AsRawSocket;
use windows_sys::Win32::{
    Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation},
    Networking::WinSock::{
        FIONBIO, IPPROTO_TCP, SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, TCP_NODELAY,
        WSAGetLastError, ioctlsocket, setsockopt,
    },
};

#[expect(
    unsafe_code,
    reason = "Winsock returns its thread-local error as a scalar; no pointer or ownership is transferred"
)]
fn socket_error() -> io::Error {
    // SAFETY: WSAGetLastError has no parameters and does not borrow storage.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

/// Reserve a fresh TCP listener's address exclusively before binding it.
/// Windows SO_REUSEADDR can permit another listener to steal traffic, so native
/// service listeners use the Windows ownership option instead of Unix reuse.
#[expect(
    unsafe_code,
    reason = "SO_EXCLUSIVEADDRUSE borrows the live unbound socket and reads exactly one initialized BOOL-sized integer"
)]
pub fn set_exclusive_address_use(socket: BorrowedStream<'_>) -> io::Result<()> {
    let enabled = 1_i32;
    // SAFETY: valid borrowed SOCKET and exact native scalar option storage.
    if unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            std::mem::size_of_val(&enabled) as i32,
        )
    } == SOCKET_ERROR
    {
        Err(socket_error())
    } else {
        Ok(())
    }
}

/// Configure a borrowed native socket without imposing Unix descriptor limits.
/// Windows select limits the number of entries, not the numeric SOCKET value.
/// Nonblocking failure is fatal; inheritance/Nagle failures retain diagnostics.
pub fn initialize_accepted_stream(
    socket: BorrowedStream<'_>,
    kind: StreamKind,
) -> Result<Diagnostics, InitializationError> {
    initialize_reactor_stream(socket, kind)
}

/// Configure the same original Winsock handle for nonblocking reactor I/O.
/// No socket is accepted, closed, duplicated or substituted by this function.
#[expect(
    unsafe_code,
    reason = "Checked Win32/Winsock calls borrow the original live socket and initialized scalar option storage only"
)]
pub fn initialize_reactor_stream(
    socket: BorrowedStream<'_>,
    kind: StreamKind,
) -> Result<Diagnostics, InitializationError> {
    let raw = socket.as_raw_socket() as usize;
    let mut diagnostics = Diagnostics::default();
    // SAFETY: SOCKET is an inheritable kernel handle; this live borrow remains
    // owned by the caller. Only HANDLE_FLAG_INHERIT is changed.
    if unsafe { SetHandleInformation(raw as *mut _, HANDLE_FLAG_INHERIT, 0) } == 0 {
        diagnostics.close_on_exec = Some(io::Error::last_os_error());
    }
    let mut nonblocking = 1_u32;
    // SAFETY: FIONBIO reads the initialized native u_long and retains no pointer.
    if unsafe { ioctlsocket(raw, FIONBIO, &mut nonblocking) } == SOCKET_ERROR {
        return Err(InitializationError {
            error: socket_error(),
            diagnostics,
        });
    }
    if kind == StreamKind::Tcp {
        let enabled = 1_i32;
        // SAFETY: TCP_NODELAY reads exactly one native BOOL-sized integer from
        // live storage. The original socket remains borrowed throughout.
        if unsafe {
            setsockopt(
                raw,
                IPPROTO_TCP,
                TCP_NODELAY,
                (&enabled as *const i32).cast(),
                std::mem::size_of_val(&enabled) as i32,
            )
        } == SOCKET_ERROR
        {
            diagnostics.tcp_no_delay = Some(socket_error());
        }
    }
    Ok(diagnostics)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        net::{TcpListener, TcpStream},
        os::windows::io::AsSocket,
        time::Duration,
    };
    use windows_sys::Win32::Foundation::GetHandleInformation;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert actual Winsock option, mode and handle inheritance results"
    )]
    #[expect(
        unsafe_code,
        reason = "Read flags of the still-owned socket into one initialized DWORD"
    )]
    fn original_socket_is_nonblocking_noninheritable_and_nodelay() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let _peer = TcpStream::connect(listener.local_addr()?)?;
        let (mut socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        let diagnostics = initialize_reactor_stream(socket.as_socket(), StreamKind::Tcp)
            .map_err(io::Error::other)?;
        assert!(diagnostics.is_empty());
        assert!(socket.nodelay()?);
        let mut flags = 0_u32;
        // SAFETY: the socket remains owned and live; flags is writable DWORD storage.
        if unsafe { GetHandleInformation(socket.as_raw_socket() as usize as *mut _, &mut flags) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        assert!(
            socket
                .read(&mut [0; 1])
                .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        );
        Ok(())
    }
}
