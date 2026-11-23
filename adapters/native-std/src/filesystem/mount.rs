//! Directory admission anchored to one original Linux mount.
use super::Directory;
use std::{
    io,
    mem::MaybeUninit,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::{Component, Path, PathBuf},
};

/// An open named mount whose Linux mount ID differs from its original parent.
#[derive(Debug)]
pub struct MountPoint {
    root: Directory,
    path: PathBuf,
    id: u64,
}

impl MountPoint {
    /// Open an existing non-root mount without following any symlink.
    ///
    /// # Errors
    /// Returns an error for a nonliteral path, unavailable mount identity,
    /// or a directory that belongs to the same mount as its parent.
    pub fn open(path: &Path) -> io::Result<Self> {
        literal(path)?;
        let name = path.file_name().ok_or_else(invalid_path)?;
        let parent_path = path.parent().ok_or_else(invalid_path)?;
        let mut parent = Directory::open(Path::new("/"))?;
        for part in parent_path.components().skip(1) {
            let Component::Normal(child) = part else {
                return Err(invalid_path());
            };
            parent = parent.open_directory(child)?;
        }
        let root = parent.open_directory(name)?;
        let id = mount_id(&root)?;
        if id == mount_id(&parent)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "required storage path {} is not a mount point",
                    path.display()
                ),
            ));
        }
        Ok(Self {
            root,
            path: path.to_path_buf(),
            id,
        })
    }

    /// Open a strict descendant of the selected path on this original mount.
    ///
    /// # Errors
    /// Rejects paths outside the selected mount, symlinks, nested mounts and
    /// directories whose actual mount identity cannot be read.
    pub fn open_directory(&self, path: &Path) -> io::Result<Directory> {
        literal(path)?;
        let mut parts = path
            .strip_prefix(&self.path)
            .map_err(|_| outside(path, &self.path))?
            .components();
        let Some(Component::Normal(first)) = parts.next() else {
            return Err(outside(path, &self.path));
        };
        let mut directory = self.root.open_directory(first)?;
        for part in parts {
            self.require_original(&directory, path)?;
            let Component::Normal(child) = part else {
                return Err(invalid_path());
            };
            directory = directory.open_directory(child)?;
        }
        self.require_original(&directory, path)?;
        Ok(directory)
    }

    fn require_original(&self, directory: &Directory, path: &Path) -> io::Result<()> {
        if mount_id(directory)? != self.id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("directory {} crosses a different mount", path.display()),
            ));
        }
        Ok(())
    }
}

fn literal(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.components().any(|part| part == Component::ParentDir)
        || path.as_os_str().as_bytes().contains(&0)
    {
        return Err(invalid_path());
    }
    Ok(())
}

fn invalid_path() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "absolute literal directory path required",
    )
}

fn outside(path: &Path, root: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "directory {} must be below mount {}",
            path.display(),
            root.display()
        ),
    )
}

const STATX_MNT_ID: libc::c_uint = 0x1000;

// Linux UAPI include/uapi/linux/stat.h fixes the result extent at 0x100 and
// the mount ID offset at 0x90 independently of the userspace C library.
#[repr(C, align(8))]
struct StatxMount {
    mask: u32,
    _metadata: [u8; 140],
    id: u64,
    _reserved: [u8; 104],
}

#[expect(
    unsafe_code,
    reason = "Linux statx reports the mount ID of the held descriptor without resolving a path"
)]
fn mount_id(directory: &Directory) -> io::Result<u64> {
    let mut info = MaybeUninit::<StatxMount>::uninit();
    // SAFETY: The directory descriptor and empty C string remain live across
    // the syscall. statx writes its result to valid, correctly aligned storage.
    let result = unsafe {
        libc::syscall(
            libc::SYS_statx,
            directory.as_file().as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH,
            STATX_MNT_ID,
            info.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The successful syscall initialized the complete native structure.
    let info = unsafe { info.assume_init() };
    if info.mask & STATX_MNT_ID == 0 || info.id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Linux did not report a directory mount ID",
        ));
    }
    Ok(info.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert descriptor-based admission against Linux procfs"
    )]
    fn opens_only_literal_descendants_of_an_actual_mount() -> io::Result<()> {
        let root = Path::new("/proc");
        let process = root.join(std::process::id().to_string());
        let mount = MountPoint::open(root)?;
        mount.open_directory(&process)?;
        assert!(MountPoint::open(&process).is_err());
        assert!(mount.open_directory(root).is_err());
        assert!(mount.open_directory(Path::new("/proc/../tmp")).is_err());
        assert!(mount.open_directory(Path::new("/proc/self/fd")).is_err());
        Ok(())
    }
}
