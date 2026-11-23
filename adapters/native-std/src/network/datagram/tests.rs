//! Pure native error policy; no socket operation or peer attribution.
use super::*;

#[test]
fn receive_reports_preserve_raw_codes_and_keep_source_faults_terminal() {
    #[cfg(unix)]
    let reports = [libc::EMSGSIZE];
    #[cfg(windows)]
    let reports = {
        use windows_sys::Win32::Networking::WinSock::{WSAEMSGSIZE, WSAENETRESET};
        [WSAEMSGSIZE, WSAENETRESET]
    };
    for code in reports {
        let error = io::Error::from_raw_os_error(code);
        assert!(
            isolated_datagram_receive_error(&error),
            "receive code {code}"
        );
        assert_eq!(
            error.raw_os_error(),
            Some(code),
            "original receive code {code}"
        );
    }
    #[cfg(unix)]
    let faults = [libc::EBADF, libc::ENOTSOCK, libc::ENOBUFS, libc::ENOMEM];
    #[cfg(windows)]
    let faults = {
        use windows_sys::Win32::Networking::WinSock::{
            WSAENETDOWN, WSAENOBUFS, WSAENOTSOCK, WSAESHUTDOWN,
        };
        [WSAENOTSOCK, WSAESHUTDOWN, WSAENETDOWN, WSAENOBUFS]
    };
    for code in faults {
        let error = io::Error::from_raw_os_error(code);
        assert!(
            !isolated_datagram_receive_error(&error),
            "source fault {code}"
        );
        assert_eq!(
            error.raw_os_error(),
            Some(code),
            "original source fault {code}"
        );
    }
    for kind in [
        io::ErrorKind::NotConnected,
        io::ErrorKind::OutOfMemory,
        io::ErrorKind::InvalidInput,
    ] {
        assert!(
            !isolated_datagram_receive_error(&kind.into()),
            "source fault {kind:?}"
        );
    }
}

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
