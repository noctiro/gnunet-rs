//! Existing native Unix hostname/FQDN implementation, unchanged by locale support.
use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fmt, io,
    os::unix::ffi::{OsStrExt, OsStringExt},
    ptr,
};

/// Native FQDN lookup failure; no hostname is fabricated on resolution failure.
#[derive(Debug)]
pub enum NativeError {
    /// A system call, allocation or native-result validation failed.
    System(io::Error),
    /// The native `getaddrinfo` error, separate from `errno`.
    NameResolution {
        /// Exact native EAI error code.
        code: i32,
        /// Native diagnostic bytes, retained without a UTF-8 requirement.
        message: OsString,
    },
}
impl fmt::Display for NativeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System(error) => error.fmt(formatter),
            Self::NameResolution { code, message } => {
                write!(
                    formatter,
                    "getaddrinfo ({code}): {}",
                    message.to_string_lossy()
                )
            }
        }
    }
}
impl std::error::Error for NativeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::System(error) => Some(error),
            Self::NameResolution { .. } => None,
        }
    }
}
impl From<io::Error> for NativeError {
    fn from(error: io::Error) -> Self {
        Self::System(error)
    }
}
fn own_bytes(bytes: &[u8]) -> io::Result<OsString> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    owned.extend_from_slice(bytes);
    Ok(OsString::from_vec(owned))
}

/// Native maximum length with the official sysconf/255 fallback.
#[expect(
    unsafe_code,
    reason = "sysconf accepts a valid constant and no pointers"
)]
#[must_use]
pub fn hostname_max_length() -> usize {
    // SAFETY: _SC_HOST_NAME_MAX is a valid sysconf query and takes no pointers.
    let limit = unsafe { libc::sysconf(libc::_SC_HOST_NAME_MAX) };
    usize::try_from(limit)
        .ok()
        .filter(|n| *n != 0)
        .unwrap_or(255)
}

/// Copy the native hostname, without decoding it as UTF-8 or resolving it.
/// Matches the length selection used by `GNUNET_RESOLVER_hostname_resolve`.
#[expect(
    unsafe_code,
    reason = "gethostname writes only the provided owned buffer"
)]
pub fn hostname() -> io::Result<OsString> {
    let limit = hostname_max_length();
    let capacity = limit.checked_add(1).ok_or(io::ErrorKind::OutOfMemory)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    bytes.resize(capacity, 0);
    // SAFETY: bytes owns capacity initialized writable bytes. The syscall is
    // allowed to write limit of them; the extra zero is outside that range.
    let result = unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), limit) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    bytes.truncate(end);
    Ok(OsString::from_vec(bytes))
}

struct AddressInfo(*mut libc::addrinfo);
impl Drop for AddressInfo {
    #[expect(
        unsafe_code,
        reason = "RAII frees exactly the successful native allocation"
    )]
    fn drop(&mut self) {
        // SAFETY: this non-null pointer came from one successful getaddrinfo;
        // this guard is its only owner and is never cloned or exposed.
        unsafe { libc::freeaddrinfo(self.0) };
    }
}

#[expect(
    unsafe_code,
    reason = "Scoped getaddrinfo ownership and native C string contracts"
)]
fn canonical_hostname(name: &OsStr) -> Result<OsString, NativeError> {
    let input = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "hostname contains NUL"))?;
    let mut result = ptr::null_mut();
    // SAFETY: input is a live NUL-terminated string, service/hints are genuinely
    // NULL as in resolver_api.c, and result is a live writable output pointer.
    let code = unsafe { libc::getaddrinfo(input.as_ptr(), ptr::null(), ptr::null(), &mut result) };
    if code != 0 {
        // SAFETY: gai_strerror returns a static C diagnostic for a native code.
        let diagnostic = unsafe { libc::gai_strerror(code) };
        let message = if diagnostic.is_null() {
            OsString::new()
        } else {
            // SAFETY: a non-null gai_strerror result is a static NUL-terminated
            // C string. Copy its bytes before returning from this function.
            own_bytes(unsafe { CStr::from_ptr(diagnostic) }.to_bytes())?
        };
        return Err(NativeError::NameResolution { code, message });
    }
    if result.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty getaddrinfo result").into());
    }
    let result = AddressInfo(result);
    // SAFETY: successful getaddrinfo returned this non-null initialized first
    // addrinfo. The guard keeps the entire list alive until after the copy.
    let canonical = unsafe { (*result.0).ai_canonname };
    if canonical.is_null() {
        return Ok(own_bytes(name.as_bytes())?);
    }
    // SAFETY: a non-null ai_canonname belongs to the guarded native list and is
    // NUL-terminated under getaddrinfo's contract. Its bytes are copied here.
    Ok(own_bytes(unsafe { CStr::from_ptr(canonical) }.to_bytes())?)
}

/// Synchronous official native FQDN convenience for the HAVE_GETADDRINFO profile.
///
/// Calls gethostname then getaddrinfo with NULL service and hints, uses only the
/// first result's ai_canonname when present, and otherwise copies the hostname.
/// This can block and consult native NSS/mDNS/DNS. It must not implement ordinary
/// GNUnet resolver requests, which use the official resolver service instead.
pub fn local_fqdn() -> Result<OsString, NativeError> {
    canonical_hostname(&hostname()?)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Native boundary behavior assertions"
    )]
    use super::*;

    #[test]
    fn hostname_uses_the_native_limit_and_preserves_c_string_bytes() -> io::Result<()> {
        let name = hostname()?;
        assert!(name.len() <= hostname_max_length());
        assert!(!name.as_bytes().contains(&0));
        Ok(())
    }

    #[test]
    fn numeric_native_lookup_uses_null_hints_without_external_name_resolution()
    -> Result<(), NativeError> {
        for name in [OsStr::new("127.0.0.1"), OsStr::new("::1")] {
            match canonical_hostname(name) {
                Ok(value) => assert_eq!(value, name),
                // NULL hints retain the native AI_ADDRCONFIG policy on systems
                // that apply it. An unavailable family is a real EAI failure,
                // never permission to fabricate a successful hostname.
                Err(NativeError::NameResolution { code, .. }) => assert_ne!(code, 0),
                Err(error) => return Err(error),
            }
        }
        assert!(matches!(
            canonical_hostname(OsStr::from_bytes(b"hidden\0suffix")),
            Err(NativeError::System(error)) if error.kind() == io::ErrorKind::InvalidInput
        ));
        Ok(())
    }
}
