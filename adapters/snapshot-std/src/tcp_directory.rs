//! Publish a synchronized TCP marker directory under the namespace writer contract.
use super::{Failure, os};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

/// Existing entries are qualified by Store::open, never initialized here.
pub(super) fn create(directory: &Path, marker: &str, bytes: &[u8]) -> Result<bool, Failure> {
    match fs::symlink_metadata(directory) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(os("inspect-tcp-directory", error)),
    }
    #[cfg(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "freebsd"
    ))]
    {
        supported::create_missing(directory, marker, bytes)
    }
    #[cfg(not(any(
        all(target_os = "linux", target_env = "gnu"),
        target_os = "macos",
        target_os = "freebsd"
    )))]
    {
        let _ = (marker, bytes);
        Err(super::failure(
            "tcp-directory-publication-platform",
            gnunet_types::Error::Unsupported,
            None,
        ))
    }
}

/// Qualify the final marker first, then finish any interrupted parent sync.
pub(super) fn sync_parent(directory: &Path) -> Result<(), Failure> {
    let parent = directory
        .parent()
        .ok_or_else(|| super::failure("tcp-parent", gnunet_types::Error::InvalidInput, None))?;
    let parent = open_parent(parent).map_err(|error| os("open-tcp-parent", error))?;
    parent
        .sync_all()
        .map_err(|error| os("sync-tcp-parent", error))
}

fn open_parent(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(any(
    all(target_os = "linux", target_env = "gnu"),
    target_os = "macos",
    target_os = "freebsd"
))]
mod supported {
    use super::*;
    use crate::backend::{Exposure, Inode, failure, metadata, path_id};
    use gnunet_types::Error;
    use nix::{
        errno::Errno,
        fcntl::{OFlag, openat},
        sys::stat::{Mode, mkdirat},
        unistd::{UnlinkatFlags, unlinkat},
    };
    use std::{ffi::OsStr, io::Write};

    // A crashed pre-publication sibling is not a store and is never adopted or
    // recursively cleaned. Bounded O_EXCL probing skips such leftovers, including
    // PID reuse; exhaustion reports capacity rather than touching another entry.
    const STAGING_ATTEMPTS: u32 = 1024;

    struct Stage {
        name: String,
        directory: File,
        identity: Inode,
        marker: Option<(File, Inode)>,
    }

    pub(super) fn create_missing(
        directory: &Path,
        marker_name: &str,
        marker_bytes: &[u8],
    ) -> Result<bool, Failure> {
        let final_name = directory
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| failure("tcp-directory-name", Error::InvalidInput, None))?;
        let parent_path = directory
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let original_parent = path_id(parent_path, true, "tcp-parent-policy")?;
        let parent_path =
            fs::canonicalize(parent_path).map_err(|error| os("canonical-tcp-parent", error))?;
        let parent = open_parent(&parent_path).map_err(|error| os("open-tcp-parent", error))?;
        if metadata(&parent, true, "tcp-parent-policy")? != original_parent {
            return Err(failure("tcp-parent-replaced", Error::Conflict, None));
        }
        let mut stage = staging(&parent, final_name)?;
        let mut attempted = false;
        let result = (|| {
            let marker = openat(
                &stage.directory,
                marker_name,
                OFlag::O_RDWR
                    | OFlag::O_CREAT
                    | OFlag::O_EXCL
                    | OFlag::O_NOFOLLOW
                    | OFlag::O_CLOEXEC,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )
            .map(File::from)
            .map_err(|error| os("create-tcp-marker", error.into()))?;
            let marker_id = metadata(&marker, false, "tcp-marker-policy")?;
            stage.marker = Some((marker, marker_id));
            let (marker, _) = stage
                .marker
                .as_mut()
                .ok_or_else(|| failure("tcp-marker-ownership", Error::Conflict, None))?;
            marker
                .write_all(marker_bytes)
                .map_err(|error| os("write-tcp-marker", error))?;
            marker
                .sync_all()
                .map_err(|error| os("sync-tcp-marker", error))?;
            stage
                .directory
                .sync_all()
                .map_err(|error| os("sync-tcp-staging", error))?;
            if metadata(&parent, true, "tcp-parent-policy")? != original_parent
                || path_id(&parent_path, true, "tcp-parent-policy")? != original_parent
                || entry_identity(&parent, OsStr::new(&stage.name), true)? != stage.identity
                || entry_identity(&stage.directory, OsStr::new(marker_name), false)? != marker_id
            {
                return Err(failure("tcp-staging-replaced", Error::Conflict, None));
            }
            attempted = true;
            if let Err(error) = publish(&parent, OsStr::new(&stage.name), final_name) {
                // The qualified APIs guarantee EEXIST made no namespace change.
                // Do not reopen/adopt the racing destination in this invocation.
                if error.kind() == io::ErrorKind::AlreadyExists {
                    attempted = false;
                }
                return Err(os("publish-tcp-directory", error));
            }
            parent
                .sync_all()
                .map_err(|error| os("sync-published-tcp-parent", error))?;
            if entry_identity(&parent, final_name, true)? != stage.identity
                || path_id(&parent_path, true, "tcp-parent-policy")? != original_parent
            {
                return Err(failure(
                    "published-tcp-directory-replaced",
                    Error::Conflict,
                    None,
                ));
            }
            Ok(true)
        })();
        match result {
            Ok(new) => Ok(new),
            Err(mut error) => {
                if attempted {
                    // Never unlink a possibly published final. A later reopen
                    // qualifies the same complete marker with the original Intent.
                    error.exposure = Exposure::Unknown;
                } else if let Err(cleanup) = cleanup(&parent, &stage, marker_name) {
                    error.cleanup = Some(cleanup);
                }
                Err(error)
            }
        }
    }

    fn staging(parent: &File, final_name: &OsStr) -> Result<Stage, Failure> {
        for attempt in 0..STAGING_ATTEMPTS {
            let name = format!(
                ".tcp-replay.initializing-{}-{attempt:04x}",
                std::process::id()
            );
            if OsStr::new(&name) == final_name {
                continue;
            }
            match mkdirat(parent, name.as_str(), Mode::S_IRWXU) {
                Ok(()) => {}
                Err(Errno::EEXIST) => continue,
                Err(error) => return Err(os("create-tcp-staging", error.into())),
            }
            let directory = entry(parent, OsStr::new(&name), true)
                .map_err(|error| os("open-tcp-staging", error))?;
            let identity = metadata(&directory, true, "tcp-staging-policy")?;
            return Ok(Stage {
                name,
                directory,
                identity,
                marker: None,
            });
        }
        Err(failure("tcp-staging-capacity", Error::Capacity, None))
    }

    fn entry(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
        let mut flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
        if directory {
            flags |= OFlag::O_DIRECTORY;
        }
        openat(parent, name, flags, Mode::empty())
            .map(File::from)
            .map_err(io::Error::from)
    }

    fn entry_identity(parent: &File, name: &OsStr, directory: bool) -> Result<Inode, Failure> {
        let file = entry(parent, name, directory).map_err(|error| os("tcp-entry-open", error))?;
        metadata(&file, directory, "tcp-entry-policy")
    }

    fn cleanup(parent: &File, stage: &Stage, marker_name: &str) -> io::Result<()> {
        let verify = || {
            let directory = entry(parent, OsStr::new(&stage.name), true)?;
            if super::super::id(&directory.metadata()?) != stage.identity {
                return Err(io::Error::other("owned TCP staging directory was replaced"));
            }
            Ok(())
        };
        verify()?;
        if let Some((original, identity)) = &stage.marker {
            let current = entry(&stage.directory, OsStr::new(marker_name), false)?;
            if super::super::id(&current.metadata()?) != *identity
                || super::super::id(&original.metadata()?) != *identity
            {
                return Err(io::Error::other("owned TCP staging marker was replaced"));
            }
            unlinkat(&stage.directory, marker_name, UnlinkatFlags::NoRemoveDir)?;
        }
        verify()?;
        // No recursive removal: any foreign/extra entry leaves this directory
        // untouched and produces an independent cleanup error.
        unlinkat(parent, stage.name.as_str(), UnlinkatFlags::RemoveDir)?;
        parent.sync_all()
    }

    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    fn publish(parent: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
        nix::fcntl::renameat2(
            parent,
            from,
            parent,
            to,
            nix::fcntl::RenameFlags::RENAME_NOREPLACE,
        )
        .map_err(io::Error::from)
    }

    // Store::open holds the original parent's exclusive initialization lock
    // across qualification, publication and sync on FreeBSD. All namespaces
    // participate; a hostile same-UID path racer is outside the store contract.
    #[cfg(target_os = "freebsd")]
    fn publish(parent: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
        match nix::sys::stat::fstatat(parent, to, nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(io::Error::from_raw_os_error(libc::EEXIST)),
            Err(Errno::ENOENT) => {}
            Err(error) => return Err(error.into()),
        }
        nix::fcntl::renameat(parent, from, parent, to).map_err(io::Error::from)
    }

    #[cfg(target_os = "macos")]
    fn publish(parent: &File, from: &OsStr, to: &OsStr) -> io::Result<()> {
        use std::{
            ffi::CString,
            os::{fd::AsFd, unix::ffi::OsStrExt},
        };
        let from = CString::new(from.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid staging component")
        })?;
        let to = CString::new(to.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid final component"))?;
        gnunet_native::directory::publish_noreplace(parent.as_fd(), &from, &to)
    }
}
