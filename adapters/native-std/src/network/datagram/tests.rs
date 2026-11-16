//! Pure native error policy; no socket operation or peer attribution.
use super::*;

#[test]
fn send_failures_exclude_owner_resource_and_short_write_faults() {
    for kind in [
        io::ErrorKind::WriteZero,
        io::ErrorKind::OutOfMemory,
        io::ErrorKind::NotConnected,
    ] {
        assert!(!isolated_datagram_send_error(&kind.into()));
    }
    #[cfg(unix)]
    let codes = [libc::EMSGSIZE, libc::EHOSTDOWN, libc::EDESTADDRREQ];
    #[cfg(windows)]
    let codes = {
        use windows_sys::Win32::Networking::WinSock::{WSAEDESTADDRREQ, WSAEHOSTDOWN, WSAEMSGSIZE};
        [WSAEMSGSIZE, WSAEHOSTDOWN, WSAEDESTADDRREQ]
    };
    for code in codes {
        assert!(isolated_datagram_send_error(&io::Error::from_raw_os_error(
            code
        )));
    }
    #[cfg(unix)]
    assert!(!isolated_datagram_send_error(
        &io::Error::from_raw_os_error(libc::EBADF)
    ));
    #[cfg(windows)]
    assert!(!isolated_datagram_send_error(
        &io::Error::from_raw_os_error(windows_sys::Win32::Networking::WinSock::WSAENOTSOCK)
    ));
}
