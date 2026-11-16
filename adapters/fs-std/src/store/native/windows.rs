//! Original Windows objects; no synthesized POSIX mode or directory barrier.
use gnunet_native::{DirectorySync, paths};
use std::{ffi::OsStr, fs::File, io, path::Path};
#[derive(Debug)]
pub(in crate::store) struct Directory(paths::Directory);
impl Directory {
    pub(in crate::store) fn open(path: &Path) -> io::Result<Self> {
        let root = if let Some(name) = path.file_name() {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            paths::Directory::open(&parent.canonicalize()?)?.ensure_directory(name)?
        } else {
            paths::Directory::open(path)?
        };
        Ok(Self(root))
    }
    #[cfg(feature = "network")]
    pub(in crate::store) fn from_file(file: File) -> io::Result<Self> {
        Ok(Self(paths::Directory::from_file(&file)?))
    }
    #[cfg(feature = "network")]
    pub(in crate::store) fn private_child(parent: &File, name: &OsStr) -> io::Result<Self> {
        Ok(Self(
            paths::Directory::from_file(parent)?.ensure_private_directory(name)?,
        ))
    }
    pub(in crate::store) fn ensure_directory(&self, name: &OsStr) -> io::Result<Self> {
        Ok(Self(self.0.ensure_directory(name)?))
    }
    pub(in crate::store) fn open_directory(&self, name: &OsStr) -> io::Result<Self> {
        Ok(Self(self.0.open_directory(name)?))
    }
    pub(in crate::store) fn sync(&self) -> io::Result<DirectorySync> {
        Ok(DirectorySync::Unavailable)
    }
    pub(in crate::store) fn create_file(&self, name: &str) -> io::Result<File> {
        self.0.create_private_file(OsStr::new(name))
    }
    pub(in crate::store) fn open_file(&self, name: &str) -> io::Result<File> {
        self.0.open_file(OsStr::new(name))
    }
    pub(in crate::store) fn open_for_sync(&self, name: &str) -> io::Result<File> {
        self.0.open_file_for_update(OsStr::new(name))
    }
    pub(in crate::store) fn same_file(&self, name: &str, file: &File) -> io::Result<()> {
        if self.0.same_file(OsStr::new(name), file)? {
            Ok(())
        } else {
            Err(io::Error::other(
                "original FS name no longer matches its held object",
            ))
        }
    }
    pub(in crate::store) fn publish(
        &self,
        _temporary: &str,
        file: &File,
        name: &str,
    ) -> io::Result<()> {
        self.0.link_file(file, OsStr::new(name))
    }
    pub(in crate::store) fn remove(&self, name: &str, file: &File) -> io::Result<()> {
        self.0.remove_file(OsStr::new(name), file)
    }
}
