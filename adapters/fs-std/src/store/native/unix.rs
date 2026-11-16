//! Descriptor-relative Unix operations and actual directory barriers.
use gnunet_native::DirectorySync;
use nix::{
    errno::Errno,
    fcntl::{AtFlags, OFlag, open, openat},
    sys::stat::{Mode, SFlag, fstat, fstatat, mkdirat},
    unistd::{UnlinkatFlags, linkat, unlinkat},
};
use std::{ffi::OsStr, fs::File, io, path::Path};

const DIRECTORY: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);
#[derive(Debug)]
pub(in crate::store) struct Directory(File);
impl Directory {
    pub(in crate::store) fn open(path: &Path) -> io::Result<Self> {
        if let Some(name) = path.file_name() {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let parent = Self(File::from(open(
                &parent.canonicalize()?,
                DIRECTORY,
                Mode::empty(),
            )?));
            let root = parent.ensure_directory(name)?;
            root.sync()?;
            parent.sync()?;
            Ok(root)
        } else {
            Ok(Self(File::from(open(path, DIRECTORY, Mode::empty())?)))
        }
    }
    #[cfg(feature = "network")]
    pub(in crate::store) fn from_file(file: File) -> io::Result<Self> {
        if !file.metadata()?.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository root must be a directory",
            ));
        }
        Ok(Self(file))
    }
    #[cfg(feature = "network")]
    pub(in crate::store) fn private_child(parent: &File, name: &OsStr) -> io::Result<Self> {
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
        let raw = name.as_bytes();
        if raw.is_empty() || raw.contains(&b'/') || raw.contains(&0) || matches!(raw, b"." | b"..")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "repository child requires one ordinary name",
            ));
        }
        let parent = Self(parent.try_clone()?);
        let root = parent.ensure_directory(name)?;
        let metadata = root.0.metadata()?;
        if metadata.mode() & 0o7777 != 0o700 || metadata.uid() != nix::unistd::geteuid().as_raw() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private repository directory required",
            ));
        }
        root.sync()?;
        parent.sync()?;
        parent.same_object(name, &root.0, SFlag::S_IFDIR)?;
        Ok(root)
    }
    pub(in crate::store) fn ensure_directory(&self, name: &OsStr) -> io::Result<Self> {
        match mkdirat(&self.0, name, Mode::S_IRWXU) {
            Ok(()) | Err(Errno::EEXIST) => {}
            Err(error) => return Err(error.into()),
        }
        self.open_directory(name)
    }
    pub(in crate::store) fn open_directory(&self, name: &OsStr) -> io::Result<Self> {
        Ok(Self(File::from(openat(
            &self.0,
            name,
            DIRECTORY,
            Mode::empty(),
        )?)))
    }
    pub(in crate::store) fn sync(&self) -> io::Result<DirectorySync> {
        self.0.sync_all()?;
        Ok(DirectorySync::Synchronized)
    }
    pub(in crate::store) fn create_file(&self, name: &str) -> io::Result<File> {
        Ok(File::from(openat(
            &self.0,
            name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::S_IRUSR | Mode::S_IWUSR,
        )?))
    }
    pub(in crate::store) fn open_file(&self, name: &str) -> io::Result<File> {
        let file = File::from(openat(
            &self.0,
            name,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?);
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ordinary repository file required",
            ));
        }
        Ok(file)
    }
    pub(in crate::store) fn open_for_sync(&self, name: &str) -> io::Result<File> {
        self.open_file(name)
    }
    fn same_object(&self, name: &OsStr, file: &File, kind: SFlag) -> io::Result<()> {
        let original = fstat(file)?;
        let named = fstatat(&self.0, name, AtFlags::AT_SYMLINK_NOFOLLOW)?;
        if original.st_dev != named.st_dev
            || original.st_ino != named.st_ino
            || SFlag::from_bits_truncate(original.st_mode) != kind
            || SFlag::from_bits_truncate(named.st_mode) != kind
        {
            return Err(io::Error::other(
                "original FS name no longer matches its held object",
            ));
        }
        Ok(())
    }
    pub(in crate::store) fn same_file(&self, name: &str, file: &File) -> io::Result<()> {
        self.same_object(OsStr::new(name), file, SFlag::S_IFREG)
    }
    pub(in crate::store) fn publish(
        &self,
        temporary: &str,
        file: &File,
        name: &str,
    ) -> io::Result<()> {
        self.same_file(temporary, file)?;
        linkat(&self.0, temporary, &self.0, name, AtFlags::empty())?;
        Ok(())
    }
    pub(in crate::store) fn remove(&self, name: &str, file: &File) -> io::Result<()> {
        self.same_file(name, file)?;
        unlinkat(&self.0, name, UnlinkatFlags::NoRemoveDir)?;
        self.sync()?;
        Ok(())
    }
}
