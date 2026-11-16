//! Original filesystem objects, native security and path identity fixtures.
use super::file::create_new_file;
use super::*;
use std::{
    ffi::OsString,
    fs::{self, File},
    io::{self, Write},
    os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::{Path, PathBuf},
    ptr,
    sync::atomic::{AtomicU64, Ordering},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "gnunet-native-publication-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        drop(fs::remove_dir_all(&self.0));
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Actual native directory creation must preserve Unicode/code units, remain idempotent, refuse files and validate the whole path before creating parents"
)]
fn iterative_directories_preserve_native_names_and_blocking_errors() -> io::Result<()> {
    let directory = Directory::new()?;
    let leaf = OsString::from_wide(&[0x4e2d, 0xd800, 0x61, 0xdc00]);
    let path = directory.0.join("missing").join("nested").join(&leaf);
    create_directory_all(&path)?;
    create_directory_all(&path)?;
    assert!(fs::metadata(&path)?.is_dir());
    assert_eq!(path.file_name(), Some(leaf.as_os_str()));
    let blocked = directory.0.join("blocked");
    fs::write(&blocked, b"keep original file")?;
    let expected = fs::create_dir(&blocked)
        .err()
        .ok_or_else(|| io::Error::other("directory creation replaced a file"))?;
    let error = create_directory_all(&blocked.join("missing").join("leaf"))
        .err()
        .ok_or_else(|| io::Error::other("blocking file was accepted as a directory"))?;
    assert_eq!(error.raw_os_error(), expected.raw_os_error());
    assert_eq!(fs::read(&blocked)?, b"keep original file");
    let parent = directory.0.join("must-not-be-created");
    let invalid = parent.join(OsString::from_wide(&[0x61, 0, 0x62]));
    assert_eq!(
        create_directory_all(&invalid).err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert!(!parent.exists());
    Ok(())
}

struct LocalString(*mut u16);
impl Drop for LocalString {
    #[expect(
        unsafe_code,
        reason = "This unique successful conversion allocation is released once with LocalFree"
    )]
    fn drop(&mut self) {
        // SAFETY: this pointer is the original LocalAlloc output and has one owner.
        let _released = unsafe { windows_sys::Win32::Foundation::LocalFree(self.0.cast()) };
    }
}

#[expect(
    unsafe_code,
    reason = "Native security APIs borrow one live file and return guarded allocations; the reported bounded UTF-16 extent is copied before release"
)]
fn security_snapshot(file: &File) -> io::Result<(u16, String)> {
    use crate::identity::SecurityDescriptor;
    use windows_sys::Win32::Security::{
        Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, OWNER_SECURITY_INFORMATION,
    };
    let mut descriptor = ptr::null_mut();
    // SAFETY: file owns the queried handle and the unique descriptor output is guarded below.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let descriptor = SecurityDescriptor(descriptor);
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: the descriptor is live and both scalar output slots are writable.
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut text = ptr::null_mut();
    let mut count = 0;
    // SAFETY: the live descriptor is converted to one independently owned native string.
    if unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            &mut text,
            &mut count,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let text = LocalString(text);
    if text.0.is_null() || count == 0 || count > 65536 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // Native SID aliases can leave spare WCHARs after the terminator.
    let mut length = 0;
    while length < count as usize {
        // SAFETY: conversion guarantees an initialized NUL-terminated string;
        // stop at its first terminator without reading spare capacity.
        if unsafe { *text.0.add(length) } == 0 {
            break;
        }
        length += 1;
    }
    if length == count as usize {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: the bounded scan read every unit in this initialized prefix.
    let wide = unsafe { std::slice::from_raw_parts(text.0, length) };
    let text = String::from_utf16(wide).map_err(|_| io::ErrorKind::InvalidData)?;
    Ok((control, text))
}

#[expect(
    unsafe_code,
    reason = "A guarded native security descriptor owns a validated single-ACE ACL; its extent is checked before the native SID is compared to the retained process SID"
)]
fn private_access(file: &File) -> io::Result<(u32, bool)> {
    use crate::identity::{SecurityDescriptor, process_user};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, AclSizeInformation,
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation, GetLengthSid, IsValidAcl,
        IsValidSid,
    };
    let mut descriptor = ptr::null_mut();
    let mut acl = ptr::null_mut();
    // SAFETY: exact output slots; file owns the queried native handle.
    let code = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let _descriptor = SecurityDescriptor(descriptor);
    // SAFETY: non-null ACL output is backed by the still-owned descriptor.
    if acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: exact initialized scalar output and validated live ACL.
    if unsafe {
        GetAclInformation(
            acl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of_val(&info) as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if info.AceCount != 1 {
        return Err(io::Error::other(
            "private DACL must contain exactly one ACE",
        ));
    }
    let mut raw = ptr::null_mut();
    // SAFETY: the validated ACL has one ACE; index0 and output are valid.
    if unsafe { GetAce(acl, 0, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if raw.is_null() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: GetAce returns an aligned ACE_HEADER in this valid ACL.
    let header = unsafe { &*raw.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
    if header.AceType != 0
        || header.AceFlags != 0
        || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: the checked ordinary access-allowed ACE has this native layout.
    let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
    let sid = (&ace.SidStart as *const u32).cast_mut().cast();
    // SAFETY: the native valid ACL contains a complete SID in this ACE.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    // SAFETY: SID validity was checked while its descriptor remains owned.
    let length = unsafe { GetLengthSid(sid) } as usize;
    if length + std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart) > usize::from(header.AceSize) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let user = process_user()?;
    // SAFETY: both SIDs are validated, aligned and live through comparison.
    let same = unsafe { EqualSid(sid, user.as_bytes().as_ptr().cast_mut().cast()) } != 0;
    Ok((ace.Mask, same))
}

#[expect(
    unsafe_code,
    reason = "Generated bounded SDDL owns one descriptor through creation of a new private test file with a deliberately restricted initial DACL"
)]
fn create_nonexecutable_file(path: &Path) -> io::Result<File> {
    use crate::identity::{SecurityDescriptor, process_user};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_ALL_ACCESS, FILE_EXECUTE};
    let user = process_user()?;
    let text: Vec<_> = format!(
        "O:{user}D:P(A;;0x{:x};;;{user})",
        FILE_ALL_ACCESS & !FILE_EXECUTE
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let mut raw = ptr::null_mut();
    // SAFETY: generated NUL text contains only native numeric rights/SID.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut raw,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = SecurityDescriptor(raw);
    create_new_file(path, &descriptor)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Inspect real kernel file ACLs and preservation across native replacement"
)]
fn private_creation_and_replacement_retain_native_security() -> io::Result<()> {
    use windows_sys::Win32::Security::SE_DACL_PROTECTED;
    let directory = Directory::new()?;
    let mut long = directory.0.clone();
    for index in 0..4 {
        long.push(format!("{}-{index}", "p".repeat(70)));
    }
    fs::create_dir_all(&long)?;
    let prepared = long.join("prepared-λ.conf");
    let destination = long.join("existing-λ.conf");
    let mut private = create_private_file(&prepared)?;
    assert_eq!(
        crate::identity::file_owner(&private)?,
        crate::identity::process_user()?
    );
    let (control, security) = security_snapshot(&private)?;
    assert_ne!(control & SE_DACL_PROTECTED, 0);
    assert_eq!(security.matches('(').count(), 1);
    assert_eq!(
        private_access(&private)?,
        (
            windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS,
            true
        )
    );
    private.write_all(b"replacement")?;
    private.sync_all()?;
    drop(private);
    let mut original = create_nonexecutable_file(&destination)?;
    original.write_all(b"original")?;
    original.sync_all()?;
    let expected = windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS
        & !windows_sys::Win32::Storage::FileSystem::FILE_EXECUTE;
    assert_eq!(private_access(&original)?, (expected, true));
    assert_ne!(security_snapshot(&original)?.0 & SE_DACL_PROTECTED, 0);
    drop(original);
    let execute = || {
        File::options()
            .access_mode(windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE)
            .open(&destination)
    };
    assert_eq!(
        execute().err().map(|e| e.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    publish_file(&prepared, &destination, Publication::Replace).map_err(|error| {
        io::Error::other(format!("publish over restricted destination: {error}"))
    })?;
    assert_eq!(fs::read(&destination)?, b"replacement");
    assert!(!prepared.exists());
    let replaced = File::open(&destination)?;
    assert_eq!(private_access(&replaced)?, (expected, true));
    assert_ne!(security_snapshot(&replaced)?.0 & SE_DACL_PROTECTED, 0);
    assert_eq!(
        execute().err().map(|e| e.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert real no-replacement publication refuses a raced-in name and retains both files"
)]
fn new_publication_refuses_existing_names_and_keeps_prepared_data() -> io::Result<()> {
    let directory = Directory::new()?;
    let stream = directory.0.join("private.conf:secret");
    assert_eq!(
        create_private_file(&stream).err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidInput)
    );
    assert!(!directory.0.join("private.conf").exists());
    let prepared = directory.0.join("prepared.conf");
    let destination = directory.0.join("destination.conf");
    let mut file = create_private_file(&prepared)?;
    file.write_all(b"prepared")?;
    file.sync_all()?;
    drop(file);
    assert!(create_private_file(&prepared).is_err());
    fs::write(&destination, b"raced-in")?;
    assert!(publish_file(&prepared, &destination, Publication::Create).is_err());
    assert_eq!(fs::read(&destination)?, b"raced-in");
    assert_eq!(fs::read(&prepared)?, b"prepared");
    fs::remove_file(&destination)?;
    publish_file(&prepared, &destination, Publication::Create)?;
    assert_eq!(fs::read(&destination)?, b"prepared");
    assert!(!prepared.exists());
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert actual profile discovery without opening or creating that directory"
)]
fn primary_token_profile_is_a_bounded_absolute_native_path() -> io::Result<()> {
    let path = profile_directory()?;
    assert!(path.is_absolute());
    use std::os::windows::ffi::OsStrExt;
    let wide: Vec<_> = path.as_os_str().encode_wide().collect();
    assert!(!wide.is_empty() && wide.len() < 32768 && !wide.contains(&0));
    Ok(())
}
