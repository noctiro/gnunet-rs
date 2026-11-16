//! Native listen-role observations without accepting or changing socket state.
use super::BorrowedStream;
use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(all(unix, not(target_os = "macos")))]
#[expect(
    unsafe_code,
    reason = "getsockopt SO_ACCEPTCONN writes exactly the provided initialized c_int buffer whose socklen is checked before use"
)]
/// Observe whether this original socket currently has a listen role.
pub fn is_listener(socket: BorrowedStream<'_>) -> io::Result<bool> {
    let fd = socket.as_raw_fd();
    let mut value: libc::c_int = 0;
    let mut length = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: SOL_SOCKET/SO_ACCEPTCONN writes into value with the stated length;
    // length is a valid mutable socklen_t. Invalid/non-socket fds produce errno.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&raw mut value).cast(),
            &raw mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<libc::c_int>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected SO_ACCEPTCONN result size",
        ));
    }
    Ok(value != 0)
}

// macOS defines SO_ACCEPTCONN but does not expose it through getsockopt.
// Public libproc reports the same socket option bits without accepting a queued
// connection or modifying an unlistening socket. Prefix ABI matches the SDK's
// sys/proc_info.h; the subprocess C layout oracle checks its offset and capacity.
#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinProcFileInfo {
    open_flags: u32,
    status: u32,
    offset: libc::off_t,
    kind: i32,
    guard_flags: u32,
}
#[cfg(target_os = "macos")]
#[repr(C)]
struct DarwinSocketPrefix {
    file: DarwinProcFileInfo,
    stat: libc::vinfo_stat,
    socket: u64,
    pcb: u64,
    kind: libc::c_int,
    protocol: libc::c_int,
    family: libc::c_int,
    options: libc::c_short,
}
#[cfg(target_os = "macos")]
/// Byte offset checked against the macOS public SDK by the process fixture.
pub const DARWIN_SOCKET_OPTIONS_OFFSET: usize = std::mem::offset_of!(DarwinSocketPrefix, options);
#[cfg(target_os = "macos")]
/// Native socket-info result capacity checked against the macOS public SDK.
pub const DARWIN_SOCKET_INFO_BUFFER_BYTES: usize = 4096;
#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "Self-process proc_pidfdinfo writes at most the supplied zero-initialized byte buffer; the public SDK prefix offset and result length are checked before reading option bytes"
)]
/// Observe whether this original socket currently has a listen role.
pub fn is_listener(socket: BorrowedStream<'_>) -> io::Result<bool> {
    let fd = socket.as_raw_fd();
    const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
    let mut bytes = [0_u8; DARWIN_SOCKET_INFO_BUFFER_BYTES];
    // SAFETY: the self PID and validated open fd identify our inherited socket;
    // the byte buffer is writable for exactly its advertised length. The kernel
    // API never writes beyond that bound and returns bytes actually copied.
    let written = unsafe {
        libc::proc_pidfdinfo(
            std::process::id() as libc::c_int,
            fd,
            PROC_PIDFDSOCKETINFO,
            bytes.as_mut_ptr().cast(),
            bytes.len() as libc::c_int,
        )
    };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    if (written as usize) < size_of::<DarwinSocketPrefix>() || written as usize > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported native socket-info layout",
        ));
    }
    let start = DARWIN_SOCKET_OPTIONS_OFFSET;
    let options = libc::c_short::from_ne_bytes([bytes[start], bytes[start + 1]]);
    Ok(libc::c_int::from(options) & libc::SO_ACCEPTCONN != 0)
}

/// Observe the original Winsock socket's listen role without consuming backlog.
#[cfg(windows)]
pub fn is_listener(socket: BorrowedStream<'_>) -> io::Result<bool> {
    crate::local_socket::is_listener(socket)
}
