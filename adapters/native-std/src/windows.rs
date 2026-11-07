//! Unicode Winsock hostname and FQDN boundaries with scoped startup ownership.
use crate::NativeError;
use std::{
    ffi::{OsStr, OsString},
    io,
    os::windows::ffi::{OsStrExt, OsStringExt},
    ptr,
};
use windows_sys::Win32::Networking::WinSock::{
    ADDRINFOW, FreeAddrInfoW, GetAddrInfoW, GetHostNameW, SOCKET_ERROR, WSACleanup, WSADATA,
    WSAGetLastError, WSAStartup,
};

struct Winsock;
impl Winsock {
    #[expect(
        unsafe_code,
        reason = "WSAStartup writes one exact output WSADATA; this guard owns exactly its successful reference"
    )]
    fn start() -> io::Result<Self> {
        let mut data = std::mem::MaybeUninit::<WSADATA>::uninit();
        // SAFETY: API receives full writable native WSADATA output storage.
        let code = unsafe { WSAStartup(0x0202, data.as_mut_ptr()) };
        if code == 0 {
            Ok(Self)
        } else {
            Err(io::Error::from_raw_os_error(code))
        }
    }
}
impl Drop for Winsock {
    #[expect(
        unsafe_code,
        reason = "Release exactly this successful WSAStartup reference; no socket or other caller's reference is closed"
    )]
    fn drop(&mut self) {
        // SAFETY: this unique guard follows one successful startup.
        let _released = unsafe { WSACleanup() };
    }
}

/// Maximum native hostname length, excluding the terminating UTF-16 NUL.
#[must_use]
pub const fn hostname_max_length() -> usize {
    255
}

/// Return the real Unicode Winsock hostname without DNS or environment fallback.
#[expect(
    unsafe_code,
    reason = "GetHostNameW writes only the initialized bounded UTF-16 buffer; WSAGetLastError returns a scalar thread-local error"
)]
pub fn hostname() -> io::Result<OsString> {
    let _winsock = Winsock::start()?;
    let mut name = [0_u16; 256];
    // SAFETY: writable 256-WCHAR storage lives through this synchronous call.
    if unsafe { GetHostNameW(name.as_mut_ptr(), name.len() as i32) } == SOCKET_ERROR {
        // SAFETY: read the Winsock error before any cleanup call changes it.
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    let end = name
        .iter()
        .position(|c| *c == 0)
        .filter(|n| *n != 0)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid native hostname length")
        })?;
    Ok(OsString::from_wide(&name[..end]))
}

struct AddressInfo(*mut ADDRINFOW);
impl Drop for AddressInfo {
    #[expect(
        unsafe_code,
        reason = "Free the original successful GetAddrInfoW result exactly once; no pointer is exposed or cloned"
    )]
    fn drop(&mut self) {
        // SAFETY: pointer is non-null, allocated by GetAddrInfoW and uniquely owned.
        unsafe { FreeAddrInfoW(self.0) };
    }
}

#[expect(
    unsafe_code,
    reason = "Synchronous Winsock name resolution borrows NUL-terminated UTF-16 input; the guarded native result owns its documented canonical string"
)]
fn canonical_hostname(name: &OsStr) -> Result<OsString, NativeError> {
    let _winsock = Winsock::start()?;
    let mut input: Vec<u16> = name.encode_wide().collect();
    if input.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "hostname contains NUL").into());
    }
    input.push(0);
    let mut output = ptr::null_mut();
    // SAFETY: native API accepts null service and hints; input lives until return.
    let code = unsafe { GetAddrInfoW(input.as_ptr(), ptr::null(), ptr::null(), &mut output) };
    if code != 0 {
        return Err(NativeError::NameResolution {
            code,
            message: OsString::from(io::Error::from_raw_os_error(code).to_string()),
        });
    }
    if output.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty GetAddrInfoW result").into());
    }
    let result = AddressInfo(output);
    // SAFETY: successful non-null native result initializes its first node.
    let canonical = unsafe { (*result.0).ai_canonname };
    if canonical.is_null() {
        return Ok(name.to_owned());
    }
    let mut end = 0;
    // SAFETY: ai_canonname is a documented NUL-terminated UTF-16 string, kept
    // alive by result. Limit the copied hostname instead of growing unboundedly.
    while end < 65535 && unsafe { *canonical.add(end) } != 0 {
        end += 1;
    }
    if end == 65535 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "canonical hostname exceeds bound",
        )
        .into());
    }
    // SAFETY: the preceding scan established this initialized, live string extent.
    Ok(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(canonical, end)
    }))
}

/// Native FQDN convenience: hostname followed by GetAddrInfoW with null hints.
/// Uses the first canonical name, otherwise the original hostname. This may
/// consult native DNS and is separate from ordinary GNUnet Resolver requests.
pub fn local_fqdn() -> Result<OsString, NativeError> {
    canonical_hostname(&hostname()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert the actual Unicode hostname and native validation error"
    )]
    fn hostname_is_native_and_nul_names_are_rejected() -> io::Result<()> {
        let name = hostname()?;
        let bytes: Vec<_> = name.encode_wide().collect();
        assert!(!bytes.is_empty() && bytes.len() <= hostname_max_length());
        assert!(!bytes.contains(&0));
        assert!(
            matches!(canonical_hostname(OsStr::new("bad\0name")), Err(NativeError::System(error)) if error.kind() == io::ErrorKind::InvalidInput)
        );
        Ok(())
    }
}
