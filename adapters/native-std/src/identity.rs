//! Windows identity observations. No impersonation, privilege or ACL mutation.
use std::{
    ffi::OsStr,
    fmt, io,
    mem::{size_of, zeroed},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER,
    Security::{
        CopySid, GetLengthSid, GetTokenInformation, IsValidSid, LookupAccountNameW, PSID,
        SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// Validated native SID bytes. This owns no token or process capability and
/// cannot be constructed from a username or synthetic Unix UID/GID.
#[derive(Clone, Eq, Hash, PartialEq)]
#[repr(C, align(4))]
pub struct Sid {
    bytes: [u8; SECURITY_MAX_SID_SIZE as usize],
    length: u8,
}
impl Sid {
    fn empty() -> Self {
        Self {
            bytes: [0; SECURITY_MAX_SID_SIZE as usize],
            length: 0,
        }
    }
    /// Complete validated SID, excluding unused fixed-capacity storage.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }

    #[expect(
        unsafe_code,
        reason = "Private callers supply a live native SID in bounded initialized API output storage; validation precedes GetLengthSid and CopySid"
    )]
    fn copy_native(source: PSID, available: usize) -> io::Result<Self> {
        if source.is_null() || available < 8 {
            return Err(invalid("missing native SID"));
        }
        // SAFETY: initialized native output includes at least the SID header.
        if unsafe { IsValidSid(source) } == 0 {
            return Err(invalid("invalid native SID"));
        }
        // SAFETY: IsValidSid succeeded before this length query.
        let length = unsafe { GetLengthSid(source) } as usize;
        if length > available || length > SECURITY_MAX_SID_SIZE as usize || length < 8 {
            return Err(invalid("native SID exceeds its output buffer"));
        }
        let mut sid = Self::empty();
        // SAFETY: destination is DWORD-aligned and has SECURITY_MAX_SID_SIZE
        // initialized bytes; the validated source remains live for this copy.
        if unsafe { CopySid(SECURITY_MAX_SID_SIZE, sid.bytes.as_mut_ptr().cast(), source) } == 0 {
            return Err(io::Error::last_os_error());
        }
        sid.length = length as u8;
        Ok(sid)
    }
}
impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.as_bytes();
        let authority = u64::from_be_bytes([0, 0, b[2], b[3], b[4], b[5], b[6], b[7]]);
        write!(f, "S-{}-", b[0])?;
        if authority > u64::from(u32::MAX) {
            write!(f, "0x{authority:012x}")?;
        } else {
            write!(f, "{authority}")?;
        }
        for part in b[8..].as_chunks::<4>().0 {
            write!(
                f,
                "-{}",
                u32::from_le_bytes([part[0], part[1], part[2], part[3]])
            )?;
        }
        Ok(())
    }
}
impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[repr(C)]
struct TokenBuffer {
    user: TOKEN_USER,
    // The native SID is variable length; its maximum is documented by Win32.
    sid: [u32; SECURITY_MAX_SID_SIZE as usize / size_of::<u32>()],
}

/// Observe the current process's primary-token user, not a thread impersonation
/// identity. One TOKEN_QUERY handle is owned and closed exactly once. No group,
/// file access, elevation or peer authentication is inferred from this SID.
#[expect(
    unsafe_code,
    reason = "OpenProcessToken transfers one successful handle into OwnedHandle; GetTokenInformation writes exact aligned initialized TOKEN_USER/SID storage"
)]
pub fn process_user() -> io::Result<Sid> {
    let mut raw = ptr::null_mut();
    // SAFETY: GetCurrentProcess is a borrowed pseudo-handle; raw is output only.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful OpenProcessToken transferred a uniquely owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: TOKEN_USER contains only native scalar/pointer storage; zero is valid.
    let mut output: TokenBuffer = unsafe { zeroed() };
    let mut written = 0;
    // SAFETY: output is aligned and fully writable with its exact byte capacity.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            (&mut output as *mut TokenBuffer).cast(),
            size_of::<TokenBuffer>() as u32,
            &mut written,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if written as usize > size_of::<TokenBuffer>() || (written as usize) < size_of::<TOKEN_USER>() {
        return Err(invalid("invalid TOKEN_USER output extent"));
    }
    let base = &output as *const TokenBuffer as usize;
    let pointer = output.user.User.Sid as usize;
    let offset = pointer
        .checked_sub(base)
        .filter(|n| *n >= size_of::<TOKEN_USER>())
        .ok_or_else(|| invalid("TOKEN_USER SID is outside its original buffer"))?;
    let available = (written as usize)
        .checked_sub(offset)
        .ok_or_else(|| invalid("TOKEN_USER SID exceeds returned extent"))?;
    Sid::copy_native(output.user.User.Sid, available)
}

/// Resolve a native account name through LookupAccountNameW. Unicode is passed
/// unchanged; names are bounded to 32767 UTF-16 units and NUL is refused. Native
/// account lookup may consult the configured domain. Failure retains its Win32
/// error; no environment, UID mapping or alternate account is substituted.
#[expect(
    unsafe_code,
    reason = "Two bounded LookupAccountNameW calls borrow initialized UTF-16 input/output and fixed aligned SID storage; no native pointer is retained"
)]
pub fn account_sid(name: &OsStr) -> io::Result<Sid> {
    let length = name.encode_wide().count();
    if length == 0 || length > 32767 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid account name length",
        ));
    }
    let mut input = Vec::new();
    input
        .try_reserve_exact(length + 1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    input.extend(name.encode_wide());
    if input.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "account name contains NUL",
        ));
    }
    input.push(0);
    let mut sid_size = 0;
    let mut domain_size = 0;
    let mut kind = 0;
    // SAFETY: null output buffers with zero sizes request required capacities.
    let sized = unsafe {
        LookupAccountNameW(
            ptr::null(),
            input.as_ptr(),
            ptr::null_mut(),
            &mut sid_size,
            ptr::null_mut(),
            &mut domain_size,
            &mut kind,
        )
    };
    let error = io::Error::last_os_error();
    if sized != 0 {
        return Err(invalid("account lookup returned no SID storage"));
    }
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if !(8..=SECURITY_MAX_SID_SIZE).contains(&sid_size) || domain_size > 32768 {
        return Err(invalid("account lookup capacity exceeds native bounds"));
    }
    let mut domain = Vec::new();
    domain
        .try_reserve_exact(domain_size.max(1) as usize)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    domain.resize(domain_size.max(1) as usize, 0_u16);
    domain_size = domain.len() as u32;
    let mut sid = Sid::empty();
    sid_size = SECURITY_MAX_SID_SIZE;
    // SAFETY: full initialized capacities and scalar size outputs agree.
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            input.as_ptr(),
            sid.bytes.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut kind,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Sid::copy_native(sid.bytes.as_mut_ptr().cast(), sid_size as usize)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Assertions inspect real process-token SIDs and locally resolved well-known account names"
    )]
    use super::*;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Security::{CreateWellKnownSid, LookupAccountSidW, WinLocalSystemSid};

    #[test]
    fn actual_process_token_produces_a_bounded_owned_sid() -> io::Result<()> {
        let sid = process_user()?;
        let bytes = sid.as_bytes();
        assert_eq!(bytes.len(), 8 + 4 * usize::from(bytes[1]));
        assert!(bytes.len() <= SECURITY_MAX_SID_SIZE as usize);
        assert!(sid.to_string().starts_with("S-1-"));
        assert_eq!(sid, sid.clone());
        Ok(())
    }

    #[test]
    #[expect(
        unsafe_code,
        reason = "Construct and resolve one local well-known SID through exact bounded initialized native buffers"
    )]
    fn native_local_account_name_round_trips_without_a_unix_id() -> io::Result<()> {
        let mut sid = Sid::empty();
        let mut size = SECURITY_MAX_SID_SIZE;
        // SAFETY: native local well-known SID construction receives full storage.
        if unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                ptr::null_mut(),
                sid.bytes.as_mut_ptr().cast(),
                &mut size,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let sid = Sid::copy_native(sid.bytes.as_mut_ptr().cast(), size as usize)?;
        assert_eq!(sid.to_string(), "S-1-5-18");
        let mut account = [0_u16; 256];
        let mut domain = [0_u16; 256];
        let mut account_size = account.len() as u32;
        let mut domain_size = domain.len() as u32;
        let mut kind = 0;
        // SAFETY: validated SID and two exclusive fully initialized name buffers.
        if unsafe {
            LookupAccountSidW(
                ptr::null(),
                sid.bytes.as_ptr().cast_mut().cast(),
                account.as_mut_ptr(),
                &mut account_size,
                domain.as_mut_ptr(),
                &mut domain_size,
                &mut kind,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let end = |v: &[u16]| v.iter().position(|n| *n == 0).unwrap_or(v.len());
        let mut name = std::ffi::OsString::from_wide(&domain[..end(&domain)]);
        name.push("\\");
        name.push(std::ffi::OsString::from_wide(&account[..end(&account)]));
        assert_eq!(account_sid(&name)?, sid);
        assert_eq!(
            account_sid(OsStr::new("bad\0name")).err().map(|e| e.kind()),
            Some(io::ErrorKind::InvalidInput)
        );
        Ok(())
    }
}
