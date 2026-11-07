//! Small checked platform ABI boundary; never runs a command/helper process.
use crate::{Action, Info};
use std::{
    ffi::CString,
    io,
    os::fd::{AsRawFd, OwnedFd},
};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(super) use linux::{apply, open, open_exclusive, verify};
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub(super) use macos::{apply, open, verify};
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn verify(_: &OwnedFd) -> io::Result<Info> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TUN platform unsupported",
    ))
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn apply(_: &Info, _: &Action) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TUN platform configuration unsupported",
    ))
}
pub(super) fn nonblocking(fd: &OwnedFd) -> io::Result<()> {
    use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
    let flags = OFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFL)?);
    let _changed = fcntl(fd, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    let flags = FdFlag::from_bits_retain(fcntl(fd, FcntlArg::F_GETFD)?);
    let _changed = fcntl(fd, FcntlArg::F_SETFD(flags | FdFlag::FD_CLOEXEC))?;
    Ok(())
}
pub(super) fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
pub(super) fn name(name: &str) -> io::Result<CString> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ {
        return Err(invalid("invalid native interface name"));
    }
    CString::new(name).map_err(|_| invalid("NUL interface name"))
}
pub(super) fn index(name: &str) -> io::Result<u32> {
    let n = self::name(name)?;
    #[expect(
        unsafe_code,
        reason = "if_nametoindex reads one live NUL-terminated CString and returns a scalar; no retained pointer"
    )]
    // SAFETY: CString stays valid for this synchronous read-only lookup.
    let result = unsafe { libc::if_nametoindex(n.as_ptr()) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}
pub(super) fn read_name(bytes: &[libc::c_char]) -> io::Result<String> {
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| invalid("unterminated kernel interface name"))?;
    if end == 0 {
        return Err(invalid("empty kernel interface name"));
    }
    let v: Vec<u8> = bytes[..end].iter().map(|b| *b as u8).collect();
    String::from_utf8(v).map_err(|_| invalid("non-UTF8 kernel interface name"))
}
pub(super) fn request(name: &str) -> io::Result<libc::ifreq> {
    #[expect(
        unsafe_code,
        reason = "The C ifreq ABI consists only of integer, byte-array and pointer union storage; all-zero is valid initial storage"
    )]
    // SAFETY: no reference/bool/invalid enum members exist in libc::ifreq.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    let n = self::name(name)?;
    for (a, b) in req.ifr_name.iter_mut().zip(n.as_bytes_with_nul()) {
        *a = *b as libc::c_char
    }
    Ok(req)
}
pub(super) fn control_socket() -> io::Result<socket2::Socket> {
    socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
}
