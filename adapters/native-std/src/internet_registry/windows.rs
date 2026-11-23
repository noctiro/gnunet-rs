//! Winsock Internet protocol and service database queries.
use crate::windows::Winsock;
use std::{ffi::CStr, io};
use windows_sys::Win32::Networking::WinSock::{
    WSAGetLastError, WSAHOST_NOT_FOUND, WSANO_DATA, getprotobyname, getservbyname,
};

/// Owns a Winsock startup reference for synchronous registry queries.
/// Each lookup copies the scalar result immediately from native thread-local storage.
pub struct Database {
    _winsock: Winsock,
}

impl Database {
    /// Acquire the native Winsock reference used by this database owner.
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            _winsock: Winsock::start()?,
        })
    }

    /// Look up a named protocol and return its host-order number.
    /// A documented native miss returns `None`. Other lookup errors propagate.
    #[expect(
        unsafe_code,
        reason = "Winsock borrows the live C string and returns a thread-local record read immediately"
    )]
    pub fn protocol(&mut self, name: &CStr) -> io::Result<Option<u16>> {
        // SAFETY: the owner retains an active Winsock reference. The name is
        // a live NUL-terminated string throughout the synchronous call.
        let entry = unsafe { getprotobyname(name.as_ptr().cast()) };
        if entry.is_null() {
            return lookup_error();
        }
        // SAFETY: the successful record still belongs to this thread. Copy
        // only the scalar before making any further call to Winsock.
        let number = unsafe { (*entry).p_proto };
        let number = u16::try_from(number).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "negative Winsock protocol number",
            )
        })?;
        Ok(Some(number))
    }

    /// Look up a named service for the exact protocol name and return its host-order port.
    /// A documented native miss returns `None`. Other lookup errors propagate.
    #[expect(
        unsafe_code,
        reason = "Winsock borrows both live C strings and returns a thread-local record read immediately"
    )]
    pub fn service(&mut self, service: &CStr, protocol: &CStr) -> io::Result<Option<u16>> {
        // SAFETY: the owner retains an active Winsock reference. Both strings
        // are live and NUL-terminated throughout the synchronous call.
        let entry = unsafe { getservbyname(service.as_ptr().cast(), protocol.as_ptr().cast()) };
        if entry.is_null() {
            return lookup_error();
        }
        // SAFETY: the successful record remains live on this thread. Its port
        // stores the full 16-bit network-order representation in a signed short.
        let port = unsafe { (*entry).s_port };
        Ok(Some(u16::from_be_bytes(port.to_ne_bytes())))
    }
}

#[expect(
    unsafe_code,
    reason = "WSAGetLastError reads the scalar error of the immediately preceding failed lookup"
)]
fn lookup_error() -> io::Result<Option<u16>> {
    // SAFETY: the lookup failed on this thread and no intervening native call
    // can replace the documented Winsock error.
    let code = unsafe { WSAGetLastError() };
    match code {
        WSAHOST_NOT_FOUND | WSANO_DATA => Ok(None),
        0 => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Winsock lookup failed without an error code",
        )),
        code => Err(io::Error::from_raw_os_error(code)),
    }
}
