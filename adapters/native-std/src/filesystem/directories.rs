//! Original-directory publication and empty-directory retirement.
use super::{Directory, FileIdentity};
use std::{ffi::OsStr, io};

impl Directory {
    /// Compare a named directory with its still-held original. Final symlinks
    /// and name-surrogate reparse points are refused before comparison.
    pub fn same_directory(&self, name: &OsStr, original: &Self) -> io::Result<bool> {
        let named = self.open_directory(name)?;
        Ok(FileIdentity::of(named.as_file())? == FileIdentity::of(original.as_file())?)
    }

    /// Publish an original prepared sibling directory at an absent destination.
    /// No existing entry is replaced and no copy fallback is used. The caller
    /// serializes administrative namespace changes. FreeBSD additionally locks
    /// an independent original parent descriptor across its absence check and
    /// rename; all cooperating publishers must use this boundary. Linux and
    /// macOS request kernel no-replacement; Windows renames a captured handle.
    /// No file or directory synchronization is performed here.
    ///
    /// # Errors
    /// `AlreadyExists` leaves the source unpublished. Any other error can follow
    /// publication, including a failed post-publication identity observation.
    pub fn publish_directory(
        &self,
        source_name: &OsStr,
        original: &Self,
        target_name: &OsStr,
    ) -> io::Result<()> {
        if !self.same_directory(source_name, original)? {
            return Err(io::Error::other(
                "original directory publication source changed",
            ));
        }
        #[cfg(unix)]
        unix::publish(self, source_name, target_name)?;
        #[cfg(windows)]
        crate::paths::relative::publish_directory(
            self.as_file(),
            source_name,
            original.as_file(),
            target_name,
        )?;
        // Never classify a post-publication failure as an unattempted collision.
        match self.same_directory(target_name, original) {
            Ok(true) => Ok(()),
            Ok(false) => Err(io::Error::other("published original directory changed")),
            Err(error) => Err(io::Error::other(error)),
        }
    }

    /// Remove an empty directory still matching its held original. This never
    /// recursively removes contents. Callers exclude administrative namespace
    /// changes; Windows deletes the captured original link handle.
    pub fn remove_directory(&self, name: &OsStr, original: &Self) -> io::Result<()> {
        if !self.same_directory(name, original)? {
            return Err(io::Error::other("original directory removal entry changed"));
        }
        #[cfg(unix)]
        {
            nix::unistd::unlinkat(self.as_file(), name, nix::unistd::UnlinkatFlags::RemoveDir)?;
            Ok(())
        }
        #[cfg(windows)]
        crate::paths::relative::remove_directory(self.as_file(), name, original.as_file())
    }
}

#[cfg(unix)]
mod unix {
    use super::*;
    #[cfg(target_os = "freebsd")]
    use std::fs::File;

    #[cfg(target_os = "linux")]
    #[expect(
        unsafe_code,
        reason = "renameat2 receives two live original-parent fds and validated bounded NUL-terminated leaf names; no ownership is transferred"
    )]
    pub(super) fn publish(parent: &Directory, from: &OsStr, to: &OsStr) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let from = component(from)?;
        let to = component(to)?;
        // SAFETY: stable CString storage and original parent live throughout the
        // synchronous system call; RENAME_NOREPLACE has no overwriting fallback.
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_file().as_raw_fd(),
                from.as_ptr(),
                parent.as_file().as_raw_fd(),
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(target_os = "macos")]
    pub(super) fn publish(parent: &Directory, from: &OsStr, to: &OsStr) -> io::Result<()> {
        use std::os::fd::AsFd;
        crate::directory::publish_noreplace(
            parent.as_file().as_fd(),
            &component(from)?,
            &component(to)?,
        )
    }

    #[cfg(target_os = "freebsd")]
    pub(super) fn publish(parent: &Directory, from: &OsStr, to: &OsStr) -> io::Result<()> {
        use nix::{
            fcntl::{OFlag, openat},
            sys::stat::Mode,
        };
        component(from)?;
        component(to)?;
        // A duplicate shares flock ownership. Open "." through the original
        // parent instead, so concurrent publishers using one Directory serialize.
        let lease = File::from(openat(
            parent.as_file(),
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        lease.lock()?;
        match parent.entry_info(to) {
            Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        nix::fcntl::renameat(parent.as_file(), from, parent.as_file(), to)?;
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    pub(super) fn publish(_: &Directory, _: &OsStr, _: &OsStr) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "exclusive directory publication is unavailable",
        ))
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "freebsd"))]
    fn component(name: &OsStr) -> io::Result<std::ffi::CString> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = name.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 255
            || bytes.contains(&b'/')
            || matches!(bytes, b"." | b"..")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ordinary sibling component required",
            ));
        }
        std::ffi::CString::new(bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
    }
}
