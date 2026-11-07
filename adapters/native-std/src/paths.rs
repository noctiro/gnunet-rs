//! Native Unicode paths, directory handles and ACL-preserving file publication.
use crate::identity::{primary_token, private_file_descriptor};
use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
use std::{
    ffi::OsString,
    io,
    os::windows::{ffi::OsStringExt, io::AsRawHandle},
    path::PathBuf,
    ptr,
};
use std::{fs::File, os::windows::fs::OpenOptionsExt, path::Path};
use windows_sys::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER, UI::Shell::GetUserProfileDirectoryW,
};

/// Query the actual primary-token user's profile directory. The token is owned
/// for both native calls and closes once. At most 32768 UTF-16 units, including
/// NUL, are admitted; lookup races retain the second call's original error.
/// No directory is opened, created or authenticated by this observation.
#[expect(
    unsafe_code,
    reason = "GetUserProfileDirectoryW borrows one live query-token handle and bounded initialized UTF-16 output; no native allocation or pointer escapes"
)]
pub fn profile_directory() -> io::Result<PathBuf> {
    let token = primary_token()?;
    let mut count = 0;
    // SAFETY: null output plus zero capacity requests the required WCHAR count.
    let sized =
        unsafe { GetUserProfileDirectoryW(token.as_raw_handle(), ptr::null_mut(), &mut count) };
    let error = io::Error::last_os_error();
    if sized != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "profile query supplied no path storage",
        ));
    }
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if !(2..=32768).contains(&count) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid native profile path capacity",
        ));
    }
    let mut path = Vec::new();
    path.try_reserve_exact(count as usize)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    path.resize(count as usize, 0_u16);
    // SAFETY: count is the full initialized output capacity, in WCHAR units.
    if unsafe { GetUserProfileDirectoryW(token.as_raw_handle(), path.as_mut_ptr(), &mut count) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = count as usize;
    if length < 2 || length > path.len() || path[length - 1] != 0 || path[..length - 1].contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid native profile path extent",
        ));
    }
    let path = PathBuf::from(OsString::from_wide(&path[..length - 1]));
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native profile path is not absolute",
        ));
    }
    Ok(path)
}

/// Open a native directory with traverse access and optional read/list access, following ordinary
/// filesystem reparse resolution. The returned original File owns one handle;
/// metadata is checked on that handle, not on a subsequent pathname lookup.
/// This changes neither permissions nor token privileges.
pub fn open_directory(path: &Path, readable: bool) -> io::Result<File> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    };
    let directory = File::options()
        .access_mode(FILE_GENERIC_EXECUTE | if readable { FILE_GENERIC_READ } else { 0 })
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    if !directory.metadata()?.is_dir() {
        return Err(io::ErrorKind::NotADirectory.into());
    }
    Ok(directory)
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    use std::path::{Component, Prefix};
    const MAX_UNITS: usize = 32767;
    let units = path.as_os_str().encode_wide();
    if units.clone().take(MAX_UNITS + 1).count() > MAX_UNITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native path exceeds UTF-16 bound",
        ));
    }
    if units.clone().any(|unit| unit == 0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in native file path",
        ));
    }
    let absolute = std::path::absolute(path)?;
    let length = absolute
        .as_os_str()
        .encode_wide()
        .take(MAX_UNITS + 1)
        .count();
    // Extend long ordinary drive/UNC paths without rewriting verbatim namespaces.
    let (prefix, skip) = if length >= 260 {
        match absolute.components().next() {
            Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)) => ("\\\\?\\", 0),
            Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::UNC(..)) => {
                ("\\\\?\\UNC\\", 2)
            }
            _ => ("", 0),
        }
    } else {
        ("", 0)
    };
    let length = length + prefix.len() - skip;
    if length > MAX_UNITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "native path exceeds UTF-16 bound",
        ));
    }
    let mut wide = Vec::new();
    wide.try_reserve_exact(length + 1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    wide.extend(prefix.encode_utf16());
    wide.extend(absolute.as_os_str().encode_wide().skip(skip));
    wide.push(0);
    Ok(wide)
}

/// Create one new noninheritable disk file with a protected DACL granting only
/// the current primary-token user full control. Existing names are refused by
/// CREATE_NEW; no data is written and no existing ACL or token privilege changes.
#[expect(
    unsafe_code,
    reason = "CreateFileW borrows live bounded UTF-16 and SECURITY_ATTRIBUTES; a successful unique handle transfers into File and its actual disk type is checked"
)]
pub fn create_private_file(path: &Path) -> io::Result<File> {
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileType,
        },
    };
    if path.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a file leaf",
        ));
    }
    let name = wide_path(path)?;
    let descriptor = private_file_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: attributes and descriptor remain owned through this synchronous call.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateFileW returned an owned non-pseudo handle.
    let file = unsafe { File::from_raw_handle(raw) };
    // SAFETY: file keeps this exact original handle alive for its type query.
    if unsafe { GetFileType(raw) } != FILE_TYPE_DISK {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private output is not a disk file",
        ));
    }
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private output is not a regular file",
        ));
    }
    Ok(file)
}

/// Publication policy selected from the caller's destination observation. A
/// raced-in destination is refused by Create; Replace never falls back to Create.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Publication {
    /// Publish at an absent name without replacing a raced-in destination.
    Create,
    /// Replace an existing file while retaining its native ACL and metadata.
    Replace,
}

/// Publish a prepared same-volume file. Existing targets use ReplaceFileW with
/// ACL merge errors enabled; new targets use a no-replacement native move.
/// On failure the caller must preserve any still-named prepared file and inspect
/// both paths: ReplaceFileW can report a partially completed replacement. No
/// automatic fallback or retry can silently drop destination ACLs.
#[expect(
    unsafe_code,
    reason = "ReplaceFileW/MoveFileExW synchronously borrow bounded native paths only; zero flags retain ACL errors and disallow replacement in the new-target branch"
)]
pub fn publish_file(
    temporary: &Path,
    destination: &Path,
    publication: Publication,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, ReplaceFileW};
    let source = wide_path(temporary)?;
    let target = wide_path(destination)?;
    // SAFETY: paths live through either synchronous native publication call.
    let result = unsafe {
        if publication == Publication::Replace {
            ReplaceFileW(
                target.as_ptr(),
                source.as_ptr(),
                ptr::null(),
                0,
                ptr::null(),
                ptr::null(),
            )
        } else {
            MoveFileExW(source.as_ptr(), target.as_ptr(), 0)
        }
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
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
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo,
                SDDL_REVISION_1, SE_FILE_OBJECT,
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
        // SAFETY: count is the successful native allocation's WCHAR extent, including NUL.
        let wide = unsafe { std::slice::from_raw_parts(text.0, count as usize) };
        if wide.last() != Some(&0) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let text =
            String::from_utf16(&wide[..wide.len() - 1]).map_err(|_| io::ErrorKind::InvalidData)?;
        Ok((control, text))
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
        assert!(security.contains(&format!("(A;;FA;;;{})", crate::identity::process_user()?)));
        private.write_all(b"replacement")?;
        private.sync_all()?;
        drop(private);
        fs::write(&destination, b"original")?;
        let original = security_snapshot(&File::open(&destination)?)?;
        publish_file(&prepared, &destination, Publication::Replace)?;
        assert_eq!(fs::read(&destination)?, b"replacement");
        assert!(!prepared.exists());
        assert_eq!(security_snapshot(&File::open(&destination)?)?, original);
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert real no-replacement publication refuses a raced-in name and retains both files"
    )]
    fn new_publication_refuses_existing_names_and_keeps_prepared_data() -> io::Result<()> {
        let directory = Directory::new()?;
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
}
