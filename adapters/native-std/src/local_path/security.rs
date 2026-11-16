//! Native endpoint DACL construction, protected creation and installation.
use super::EndpointAccess;
use crate::identity::{
    SecurityDescriptor, process_primary_group, process_user, security_descriptor,
};
use crate::paths::absolute_wide_path;
use std::{fs::File, io, mem::size_of, os::windows::io::AsRawHandle, path::Path, ptr};
use windows_sys::Win32::Security::{
    Authorization::{SE_FILE_OBJECT, SetSecurityInfo},
    DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

pub(super) enum Object {
    Directory,
    Socket,
}
pub(super) fn descriptor(access: EndpointAccess, object: Object) -> io::Result<SecurityDescriptor> {
    let user = process_user()?;
    let (inherit, rights) = match object {
        Object::Directory => ("OICI", "GRGX"),
        Object::Socket => ("", "GRGWGX"),
    };
    let mut sddl = format!("O:{user}D:P(A;{inherit};FA;;;{user})");
    match access {
        EndpointAccess::Owner => {}
        EndpointAccess::PrimaryGroup => sddl.push_str(&format!(
            "(A;{inherit};{rights};;;{})",
            process_primary_group()?
        )),
        EndpointAccess::Everyone => sddl.push_str(&format!("(A;{inherit};{rights};;;WD)")),
    }
    security_descriptor(&sddl)
}

#[expect(
    unsafe_code,
    reason = "CreateDirectoryW borrows terminated native path and a live owned descriptor; the security attributes disable handle inheritance"
)]
pub(super) fn create_directory(path: &Path, descriptor: &SecurityDescriptor) -> io::Result<()> {
    let wide = absolute_wide_path(path)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: all input storage remains live and correctly terminated for this call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::AlreadyExists && path.is_dir() {
        return Ok(());
    }
    Err(error)
}

#[expect(
    unsafe_code,
    reason = "The owned descriptor backs a valid native DACL, and SetSecurityInfo borrows the original file handle without resolving its path"
)]
pub(super) fn set_access(file: &File, access: EndpointAccess) -> io::Result<()> {
    let descriptor = descriptor(access, Object::Socket)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = ptr::null_mut();
    // SAFETY: the descriptor is live; output slots exactly match the API.
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || acl.is_null() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut owner = ptr::null_mut();
    // SAFETY: the generated descriptor owns the validated process-user SID;
    // the returned pointer borrows that allocation through SetSecurityInfo.
    if unsafe { GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if owner.is_null() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: the original WRITE_DAC/WRITE_OWNER file and descriptor remain live.
    let code = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION
                | OWNER_SECURITY_INFORMATION,
            owner,
            ptr::null_mut(),
            acl,
            ptr::null_mut(),
        )
    };
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
