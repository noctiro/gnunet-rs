//! Shared actual-owner/DACL qualification for namespace and private storage.
use super::{SecurityDescriptor, Sid, file_owner, process_user};
use std::{
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::io::AsRawHandle,
    ptr,
};
use windows_sys::Win32::{
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, INHERIT_ONLY_ACE, IsValidAcl,
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinCreatorOwnerSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, READ_CONTROL, SYNCHRONIZE},
};
#[derive(Clone, Copy)]
enum Access {
    Namespace,
    Private,
}
pub(crate) fn validate_parent(file: &File) -> io::Result<()> {
    validate(file, Access::Namespace)
}
pub(crate) fn validate_private(file: &File) -> io::Result<()> {
    validate(file, Access::Private)
}

#[expect(
    unsafe_code,
    reason = "Each Sid owns aligned validated bytes for the complete native SID; IsWellKnownSid does not retain this borrow"
)]
fn trusted(sid: &Sid, user: &Sid) -> bool {
    let raw = sid.as_bytes().as_ptr().cast_mut().cast();
    // SAFETY: Sid's fixed aligned backing store contains the whole validated SID.
    sid == user
        || unsafe {
            IsWellKnownSid(raw, WinLocalSystemSid) != 0
                || IsWellKnownSid(raw, WinBuiltinAdministratorsSid) != 0
        }
}
fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[expect(
    unsafe_code,
    reason = "Native GetSecurityInfo allocation guards its validated ACL; every ACE/SID extent is checked before bounded copying and comparison"
)]
fn validate(file: &File, access: Access) -> io::Result<()> {
    let user = process_user()?;
    let owner = file_owner(file)?;
    if match access {
        Access::Namespace => !trusted(&owner, &user),
        Access::Private => owner != user,
    } {
        return Err(denied("filesystem object has an untrusted owner"));
    }
    let mut raw_descriptor = ptr::null_mut();
    let mut acl = ptr::null_mut();
    // SAFETY: file is live with READ_CONTROL; outputs are independent slots.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut raw_descriptor,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let _descriptor = SecurityDescriptor(raw_descriptor);
    // SAFETY: non-null native ACL is backed by the owned descriptor.
    if acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
        return Err(denied("filesystem object has no valid restrictive DACL"));
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: exact scalar output for the live validated ACL.
    if unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    for index in 0..info.AceCount {
        let mut raw = ptr::null_mut();
        // SAFETY: index is within the validated ACL's reported ACE count.
        if unsafe { GetAce(acl, index, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let offset = (raw as usize)
            .checked_sub(acl as usize)
            .ok_or(io::ErrorKind::InvalidData)?;
        if raw.is_null()
            || offset
                .checked_add(size_of::<ACE_HEADER>())
                .is_none_or(|end| end > info.AclBytesInUse as usize)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // SAFETY: GetAce returns an aligned ACE header within the checked ACL.
        let header = unsafe { &*raw.cast::<ACE_HEADER>() };
        let length = usize::from(header.AceSize);
        if length < size_of::<ACE_HEADER>()
            || offset
                .checked_add(length)
                .is_none_or(|end| end > info.AclBytesInUse as usize)
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // Deny ACEs cannot grant mutation. Other ACE forms are refused rather
        // than interpreting object GUIDs or callback data as standard SID data.
        match header.AceType {
            1 | 6 | 10 | 12 => continue,
            0 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "unsupported filesystem DACL ACE form",
                ));
            }
        }
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if length < sid_offset + 8 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // SAFETY: the ACE extent includes its mask and bounded SID header.
        let mask = unsafe { (*raw.cast::<ACCESS_ALLOWED_ACE>()).Mask };
        let read_only = match access {
            Access::Namespace => {
                FILE_GENERIC_READ
                    | FILE_GENERIC_EXECUTE
                    | windows_sys::Win32::Foundation::GENERIC_READ
                    | windows_sys::Win32::Foundation::GENERIC_EXECUTE
            }
            Access::Private => READ_CONTROL | SYNCHRONIZE,
        };
        if mask & !read_only == 0 {
            continue;
        }
        // SAFETY: byte offset and extent were checked above in the native ACL.
        let sid = Sid::copy_native(
            unsafe { raw.cast::<u8>().add(sid_offset).cast() },
            length - sid_offset,
        )?;
        if trusted(&sid, &user) {
            continue;
        }
        // CREATOR OWNER is resolved to the new object's user on inheritance.
        // It is not accepted as an effective grant on this existing directory.
        if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
            // SAFETY: sid is a complete aligned validated native SID.
            && unsafe {
                IsWellKnownSid(
                    sid.as_bytes().as_ptr().cast_mut().cast(),
                    WinCreatorOwnerSid,
                )
            } != 0
        {
            continue;
        }
        return Err(denied(
            "filesystem object grants refused access to another principal",
        ));
    }
    Ok(())
}
