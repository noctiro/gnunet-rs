//! Selected Windows service account authentication and child environment.
use super::{LaunchLimits, environment::wide};
use crate::identity::{self, Sid};
#[cfg(feature = "socket-io")]
use socket2::{Domain, Socket, Type};
use std::{
    ffi::{OsStr, OsString, c_void},
    io,
    os::windows::{
        ffi::OsStringExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    },
    ptr::{self, NonNull},
};
#[cfg(feature = "socket-io")]
use std::{marker::PhantomData, path::Path, time::Duration};
#[cfg(feature = "socket-io")]
use windows_sys::Win32::{
    Foundation::ERROR_NO_TOKEN,
    Security::{ImpersonateLoggedOnUser, RevertToSelf, TOKEN_QUERY},
    System::Threading::{GetCurrentThread, OpenThreadToken},
};
use windows_sys::Win32::{
    Security::{
        Credentials::{
            CRED_MAX_CREDENTIAL_BLOB_SIZE, CRED_MAX_GENERIC_TARGET_NAME_LENGTH, CRED_TYPE_GENERIC,
            CREDENTIALW, CredFree, CredReadW,
        },
        GetTokenInformation, LOGON32_LOGON_BATCH, LOGON32_PROVIDER_DEFAULT, LogonUserW,
        TokenSessionId,
    },
    System::{
        Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
        RemoteDesktop::ProcessIdToSessionId,
        Threading::GetCurrentProcessId,
    },
};
use zeroize::{Zeroize, Zeroizing};

/// An owned batch-logon token whose actual user matches the requested service SID.
pub struct PrimaryToken {
    handle: OwnedHandle,
    user: Sid,
}
impl PrimaryToken {
    /// Sign in using one explicitly selected Generic Credential. Its account
    /// and the resulting token must both resolve to `expected`.
    #[expect(
        unsafe_code,
        reason = "LogonUserW borrows terminated inputs and transfers one token on success"
    )]
    pub fn log_on(target: &OsStr, expected: &Sid) -> io::Result<Self> {
        let credential = Credential::read(target)?;
        let account = credential.account()?;
        if identity::account_sid(&OsString::from_wide(account))? != *expected {
            return Err(account_mismatch());
        }
        let (user, domain) = logon_names(account);
        let password = credential.password()?;
        drop(credential);
        let mut raw = ptr::null_mut();
        // SAFETY: user, domain (if present), and password are terminated and
        // live through the call; raw is an exclusive output.
        let status = unsafe {
            LogonUserW(
                user.as_ptr(),
                domain.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
                password.as_ptr(),
                LOGON32_LOGON_BATCH,
                LOGON32_PROVIDER_DEFAULT,
                &mut raw,
            )
        };
        if status == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the successful batch logon transfers this primary token.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let user = identity::token_user(&handle)?;
        if user != *expected {
            return Err(account_mismatch());
        }
        Ok(Self { handle, user })
    }

    /// The verified SID, suitable for granting access to the child's control endpoint.
    pub fn user(&self) -> &Sid {
        &self.user
    }

    pub(crate) fn primary_group(&self) -> io::Result<Sid> {
        identity::token_primary_group(&self.handle)
    }

    /// Probe a named AF_UNIX endpoint with this token's actual connection access.
    /// Call on a blocking worker. The thread impersonates only while opening,
    /// connecting and closing this probe, and a connection supplies no liveness
    /// authority for any different filesystem object.
    #[cfg(feature = "socket-io")]
    pub fn probe_local(&self, path: &Path, timeout: Duration) -> io::Result<()> {
        let address = crate::local_socket::named_address(path)?;
        let _identity = Impersonation::enter(self)?;
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.connect_timeout(&address, timeout)
    }

    pub(super) fn raw(&self) -> RawHandle {
        self.handle.as_raw_handle()
    }

    pub(crate) fn shares_supervisor_session(&self) -> io::Result<bool> {
        Ok(session(&self.handle)? == current_session()?)
    }

    /// Read the target's native environment within the launch limits.
    pub fn environment(&self, limits: LaunchLimits) -> io::Result<Vec<(OsString, OsString)>> {
        EnvironmentBlock::new(self)?.entries(limits)
    }
}

#[cfg(feature = "socket-io")]
struct Impersonation(PhantomData<*mut ()>);
#[cfg(feature = "socket-io")]
impl Impersonation {
    #[expect(
        unsafe_code,
        reason = "Win32 queries and installs only this thread's identity from the verified owned token"
    )]
    fn enter(token: &PrimaryToken) -> io::Result<Self> {
        let mut existing = ptr::null_mut();
        // SAFETY: the pseudo-handle refers to this thread and the owned handle
        // output is exclusive. Opening as self does not change the thread identity.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut existing) } != 0 {
            // SAFETY: successful OpenThreadToken transfers one unique handle.
            drop(unsafe { OwnedHandle::from_raw_handle(existing) });
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "AF_UNIX account probe requires a worker without thread impersonation",
            ));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
            return Err(error);
        }
        // SAFETY: the verified primary token remains live, and this thread
        // has no earlier impersonation state to restore.
        if unsafe { ImpersonateLoggedOnUser(token.raw()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(PhantomData))
    }
}
#[cfg(feature = "socket-io")]
impl Drop for Impersonation {
    #[expect(
        unsafe_code,
        reason = "Synchronous probe exits on the same thread and must restore its primary identity"
    )]
    fn drop(&mut self) {
        // SAFETY: the guard is private to the synchronous probe and never
        // moves to another thread. Never return control with the wrong identity.
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
    }
}

#[expect(
    unsafe_code,
    reason = "Observe the actual supervisor process session using initialized scalar output"
)]
fn current_session() -> io::Result<u32> {
    let mut session = 0_u32;
    // SAFETY: the publisher is this live process and the exclusive output is one DWORD.
    if unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(session)
}

#[expect(
    unsafe_code,
    reason = "GetTokenInformation writes one DWORD into exact initialized output storage"
)]
fn session(token: &OwnedHandle) -> io::Result<u32> {
    let mut session = 0_u32;
    let mut written = 0;
    // SAFETY: both exclusive outputs have their exact native sizes and the token remains live.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenSessionId,
            ptr::from_mut(&mut session).cast(),
            size_of::<u32>() as u32,
            &mut written,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if written as usize != size_of::<u32>() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(session)
}

fn account_mismatch() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Windows service logon account mismatch",
    )
}

fn logon_names(account: &[u16]) -> (Vec<u16>, Option<Vec<u16>>) {
    let terminated = |value: &[u16]| value.iter().copied().chain([0]).collect();
    if let Some(separator) = account.iter().position(|unit| *unit == u16::from(b'\\')) {
        return (
            terminated(&account[separator + 1..]),
            Some(terminated(&account[..separator])),
        );
    }
    let domain = (!account.contains(&u16::from(b'@'))).then(|| vec![u16::from(b'.'), 0]);
    (terminated(account), domain)
}

struct Credential(NonNull<CREDENTIALW>);
impl Credential {
    #[expect(
        unsafe_code,
        reason = "CredReadW transfers one original credential allocation"
    )]
    fn read(target: &OsStr) -> io::Result<Self> {
        let mut target = wide(target, CRED_MAX_GENERIC_TARGET_NAME_LENGTH as usize)?;
        if target.is_empty() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        target.push(0);
        let mut raw = ptr::null_mut();
        // SAFETY: valid terminated target; raw receives the unique allocation.
        if unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        NonNull::new(raw)
            .map(Self)
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }

    #[expect(
        unsafe_code,
        reason = "The credential owns a native terminated user name for this borrow"
    )]
    fn account(&self) -> io::Result<&[u16]> {
        // SAFETY: the live native credential owns UserName until CredFree.
        let name = unsafe { self.0.as_ref().UserName };
        if !name.is_null() {
            let maximum = windows_sys::Win32::Security::Credentials::CRED_MAX_USERNAME_LENGTH;
            for length in 0..=maximum as usize {
                // SAFETY: the native string is terminated; iteration stops at its first NUL.
                if unsafe { name.add(length).read() } == 0 {
                    if length != 0 {
                        // SAFETY: all units before the observed terminator are initialized.
                        return Ok(unsafe { std::slice::from_raw_parts(name, length) });
                    }
                    break;
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows service credential account",
        ))
    }

    #[expect(
        unsafe_code,
        reason = "The original credential owns the byte blob for its declared extent"
    )]
    fn password(&self) -> io::Result<Zeroizing<Vec<u16>>> {
        // SAFETY: the credential remains live through borrowing and copying its blob.
        let data = unsafe { self.0.as_ref() };
        let size = data.CredentialBlobSize;
        if size == 0
            || size > CRED_MAX_CREDENTIAL_BLOB_SIZE
            || size % 2 != 0
            || data.CredentialBlob.is_null()
        {
            return Err(invalid_password());
        }
        // SAFETY: the credential declares this entire initialized blob.
        let bytes = unsafe { std::slice::from_raw_parts(data.CredentialBlob, size as usize) };
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .copied()
            .map(u16::from_le_bytes);
        let mut secret = Zeroizing::new(Vec::with_capacity(units.len() + 1));
        secret.extend(units);
        if secret.last() == Some(&0) {
            secret.pop();
        }
        if secret.is_empty() || secret.contains(&0) {
            return Err(invalid_password());
        }
        secret.push(0);
        Ok(secret)
    }
}

fn invalid_password() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid Windows service credential format",
    )
}

impl Drop for Credential {
    #[expect(
        unsafe_code,
        reason = "Clear the owned credential blob before releasing the original native allocation"
    )]
    fn drop(&mut self) {
        // SAFETY: the original credential allocation has one owner and no live borrowers.
        unsafe {
            let data = self.0.as_ref();
            if !data.CredentialBlob.is_null()
                && data.CredentialBlobSize <= CRED_MAX_CREDENTIAL_BLOB_SIZE
            {
                std::slice::from_raw_parts_mut(
                    data.CredentialBlob,
                    data.CredentialBlobSize as usize,
                )
                .zeroize();
            }
            CredFree(self.0.as_ptr().cast());
        }
    }
}

struct EnvironmentBlock(NonNull<c_void>);
impl EnvironmentBlock {
    #[expect(
        unsafe_code,
        reason = "CreateEnvironmentBlock borrows a live token and transfers one native block"
    )]
    fn new(token: &PrimaryToken) -> io::Result<Self> {
        let mut raw = ptr::null_mut();
        // SAFETY: raw is exclusive and the verified token lives through the call.
        if unsafe { CreateEnvironmentBlock(&mut raw, token.raw(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        NonNull::new(raw)
            .map(Self)
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }

    #[expect(
        unsafe_code,
        reason = "Read complete entries within the owned native double-NUL-terminated block"
    )]
    fn entries(&self, limits: LaunchLimits) -> io::Result<Vec<(OsString, OsString)>> {
        let block = self.0.cast::<u16>().as_ptr();
        let mut entries = Vec::new();
        let mut start = 0;
        for cursor in 0..limits.environment_units {
            // SAFETY: the native block is terminated; an empty entry ends traversal.
            if unsafe { block.add(cursor).read() } != 0 {
                continue;
            }
            if cursor == start {
                return Ok(entries);
            }
            if entries.len() == limits.environment_entries {
                break;
            }
            // SAFETY: iteration observed the complete, initialized entry before this NUL.
            let entry = unsafe { std::slice::from_raw_parts(block.add(start), cursor - start) };
            let separator = entry
                .iter()
                .skip(1)
                .position(|unit| *unit == u16::from(b'='))
                .ok_or(io::ErrorKind::InvalidData)?
                + 1;
            entries
                .try_reserve(1)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            entries.push((
                OsString::from_wide(&entry[..separator]),
                OsString::from_wide(&entry[separator + 1..]),
            ));
            start = cursor + 1;
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows service account environment exceeds its launch limits",
        ))
    }
}

impl Drop for EnvironmentBlock {
    #[expect(
        unsafe_code,
        reason = "DestroyEnvironmentBlock releases the sole native allocation"
    )]
    fn drop(&mut self) {
        // SAFETY: exactly this original successful native block is released once.
        unsafe { DestroyEnvironmentBlock(self.0.as_ptr()) };
    }
}
