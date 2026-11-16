//! Actual granted data-access checks on an original file handle.
use std::{fs::File, io};
/// Require a handle without granted data-write/append access. This checks this
/// original handle's mode, not the file's ACL or immutability. Other processes
/// or existing writable mappings may still modify the file.
pub fn validate_readonly(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        let flags = OFlag::from_bits_truncate(fcntl(file, FcntlArg::F_GETFL)?);
        if flags & OFlag::O_ACCMODE != OFlag::O_RDONLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read-only original handle required",
            ));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        windows(file)
    }
}
#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "NtQueryObject synchronously fills the exact initialized SDK basic information for one borrowed original file handle"
)]
fn windows(file: &File) -> io::Result<()> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows_sys::{
        Wdk::Foundation::{NtQueryObject, ObjectBasicInformation},
        Win32::{
            Storage::FileSystem::{FILE_APPEND_DATA, FILE_WRITE_DATA},
            System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION,
        },
    };
    let mut info = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let mut length = 0;
    // SAFETY: query is an object-manager query, not pending file I/O. The exact
    // initialized SDK output and returned-length scalar stay live throughout.
    let status = unsafe {
        NtQueryObject(
            file.as_raw_handle(),
            ObjectBasicInformation,
            (&mut info as *mut PUBLIC_OBJECT_BASIC_INFORMATION).cast(),
            size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32,
            &mut length,
        )
    };
    crate::paths::relative::status::check("query original file granted access", status)?;
    if length < size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short original handle access observation",
        ));
    }
    if info.GrantedAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "read-only original handle required",
        ));
    }
    Ok(())
}
