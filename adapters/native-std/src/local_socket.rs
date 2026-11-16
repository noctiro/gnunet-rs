//! Windows AF_UNIX observations of the caller's original live socket.
use std::{
    io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawSocket, BorrowedSocket},
    path::{Path, PathBuf},
};
use windows_sys::Win32::Networking::WinSock::{
    AF_UNIX, SO_ACCEPTCONN, SOCKADDR_UN, SOCKET_ERROR, SOL_SOCKET, WSAENOTCONN, WSAGetLastError,
    getpeername, getsockname, getsockopt,
};

/// The filesystem name actually returned by Winsock, or an unnamed local endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Address {
    /// No filesystem name was supplied by the endpoint.
    Unnamed,
    /// Native UTF-8 AF_UNIX name decoded without a lossy substitution.
    Path(PathBuf),
}
impl Address {
    /// Borrow the native pathname of a named AF_UNIX endpoint.
    /// Unnamed endpoints have no filesystem name.
    #[must_use]
    pub fn as_pathname(&self) -> Option<&Path> {
        match self {
            Self::Unnamed => None,
            Self::Path(path) => Some(path),
        }
    }
}
#[derive(Clone, Copy)]
enum End {
    Local,
    Peer,
}
/// Classify an original Winsock connect error as nonblocking progress.
/// This grants no connection-success or protocol authority.
#[must_use]
pub fn is_connect_pending(error: &io::Error) -> bool {
    crate::network::connect_in_progress(error)
}
/// Whether an original Winsock peer-name query reports an unconnected socket.
#[must_use]
pub fn is_not_connected(error: &io::Error) -> bool {
    error.raw_os_error() == Some(WSAENOTCONN)
}
#[expect(
    unsafe_code,
    reason = "Immediately read Winsock's thread-local error after its failed operation"
)]
fn error() -> io::Error {
    // SAFETY: WSAGetLastError has no input and retains no pointers.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}
/// Observe the original bound AF_UNIX address without lookup, duplication or close.
///
/// # Errors
/// Preserves Winsock errors; rejects other families, invalid native lengths and
/// non-UTF-8 names. Windows AF_UNIX paths are UTF-8, unlike general Win32 paths.
pub fn local_address(socket: BorrowedSocket<'_>) -> io::Result<Address> {
    address(socket, End::Local)
}
/// Observe the connected peer's AF_UNIX address; an unnamed peer remains unnamed.
/// This grants no process, SID or peer-credential authority.
///
/// # Errors
/// Preserves Winsock errors, including an unconnected socket, and validates the
/// same native family/length/encoding contract as [`local_address`].
pub fn peer_address(socket: BorrowedSocket<'_>) -> io::Result<Address> {
    address(socket, End::Peer)
}
/// Kernel-reported PID of this original connected AF_UNIX peer. This query does
/// not open a process, authenticate a user, or establish current peer liveness.
/// Preserve the original socket while using the observation; never turn this PID
/// into SID/UID authority by reopening a possibly reused numeric process ID.
#[expect(
    unsafe_code,
    reason = "The synchronous SDK ioctl borrows the original socket and initialized fixed-width output; no caller memory is retained"
)]
pub fn peer_process_id(socket: BorrowedSocket<'_>) -> io::Result<u32> {
    use windows_sys::Win32::Networking::WinSock::{SIO_AF_UNIX_GETPEERPID, WSAIoctl};
    let mut pid = 0u32;
    let mut returned = 0u32;
    // SAFETY: valid borrowed original socket, no input/overlapped/callback, exact
    // ULONG output capacity and exclusive byte-count storage for this call.
    if unsafe {
        WSAIoctl(
            socket.as_raw_socket() as usize,
            SIO_AF_UNIX_GETPEERPID,
            std::ptr::null(),
            0,
            (&mut pid as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut returned,
            std::ptr::null_mut(),
            None,
        )
    } == SOCKET_ERROR
    {
        return Err(error());
    }
    if returned != size_of::<u32>() as u32 || pid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid native AF_UNIX peer PID extent or value",
        ));
    }
    Ok(pid)
}
fn address(socket: BorrowedSocket<'_>, end: End) -> io::Result<Address> {
    let mut value = SOCKADDR_UN::default();
    let mut length = size_of::<SOCKADDR_UN>() as i32;
    #[expect(
        unsafe_code,
        reason = "A live borrowed SOCKET and initialized exact SOCKADDR_UN/length storage remain exclusive through this read-only native address query"
    )]
    // SAFETY: the output capacity is the full native object; no pointer escapes.
    let status = unsafe {
        match end {
            End::Local => getsockname(
                socket.as_raw_socket() as usize,
                (&mut value as *mut SOCKADDR_UN).cast(),
                &mut length,
            ),
            End::Peer => getpeername(
                socket.as_raw_socket() as usize,
                (&mut value as *mut SOCKADDR_UN).cast(),
                &mut length,
            ),
        }
    };
    if status == SOCKET_ERROR {
        return Err(error());
    }
    if value.sun_family != AF_UNIX {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let length = usize::try_from(length).map_err(|_| io::ErrorKind::InvalidData)?;
    let offset = offset_of!(SOCKADDR_UN, sun_path);
    if !(offset..=size_of::<SOCKADDR_UN>()).contains(&length) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut bytes = [0u8; 108];
    let count = length - offset;
    for (out, unit) in bytes[..count].iter_mut().zip(&value.sun_path) {
        *out = *unit as u8;
    }
    let count = bytes[..count]
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(count);
    if count == 0 {
        return Ok(Address::Unnamed);
    }
    let text = std::str::from_utf8(&bytes[..count]).map_err(|_| io::ErrorKind::InvalidData)?;
    Ok(Address::Path(PathBuf::from(text)))
}
/// Read SO_ACCEPTCONN from a live original socket; no descriptor is consumed.
///
/// # Errors
/// Returns the original Winsock error or invalid native option length/value.
pub fn is_listener(socket: BorrowedSocket<'_>) -> io::Result<bool> {
    let mut accepting = 0i32;
    let mut length = size_of::<i32>() as i32;
    #[expect(
        unsafe_code,
        reason = "SO_ACCEPTCONN writes at most one initialized native BOOL-sized integer and its exact length while the original socket remains borrowed"
    )]
    // SAFETY: output pointers remain exclusive and no native ownership transfers.
    if unsafe {
        getsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_ACCEPTCONN,
            (&mut accepting as *mut i32).cast(),
            &mut length,
        )
    } == SOCKET_ERROR
    {
        return Err(error());
    }
    if length != size_of::<i32>() as i32 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(accepting != 0)
}
