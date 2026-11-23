//! Original Windows directories and native publication receipts.
use gnunet_native::{DirectorySync, paths};
use std::{ffi::OsStr, fs::File, io, path::Path};
#[derive(Debug)]
pub(in crate::store) struct Directory {
    directory: paths::Directory,
    parent_sync: Option<DirectorySync>,
}
impl Directory {
    pub(in crate::store) fn open(path: &Path) -> io::Result<Self> {
        if let Some(name) = path.file_name() {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let parent = paths::Directory::open(&parent.canonicalize()?)?;
            let directory = parent.ensure_directory(name)?;
            Self::named(&parent, name, directory)
        } else {
            Ok(Self::held(paths::Directory::open(path)?))
        }
    }
    fn held(directory: paths::Directory) -> Self {
        Self {
            directory,
            parent_sync: None,
        }
    }
    fn named(
        parent: &paths::Directory,
        name: &OsStr,
        directory: paths::Directory,
    ) -> io::Result<Self> {
        let parent_sync = parent.sync()?;
        if !parent.same_directory(name, &directory)? {
            return Err(io::Error::other("original FS directory name changed"));
        }
        Ok(Self {
            directory,
            parent_sync: Some(parent_sync),
        })
    }
    #[cfg(feature = "network")]
    pub(in crate::store) fn from_file(file: File) -> io::Result<Self> {
        Ok(Self::held(paths::Directory::from_file(&file)?))
    }
    #[cfg(feature = "network")]
    pub(in crate::store) fn private_child(parent: &File, name: &OsStr) -> io::Result<Self> {
        let parent = paths::Directory::from_file(parent)?;
        let directory = parent.ensure_private_directory(name)?;
        Self::named(&parent, name, directory)
    }
    pub(in crate::store) fn ensure_directory(&self, name: &OsStr) -> io::Result<Self> {
        Ok(Self::held(self.directory.ensure_directory(name)?))
    }
    pub(in crate::store) fn open_directory(&self, name: &OsStr) -> io::Result<Self> {
        Ok(Self::held(self.directory.open_directory(name)?))
    }
    pub(in crate::store) fn sync(&self) -> io::Result<DirectorySync> {
        let synchronized = self.directory.sync()?;
        Ok(self
            .parent_sync
            .map_or(synchronized, |parent| parent.combine(synchronized)))
    }
    pub(in crate::store) fn create_file(&self, name: &str) -> io::Result<File> {
        self.directory.create_private_file(OsStr::new(name))
    }
    pub(in crate::store) fn open_file(&self, name: &str) -> io::Result<File> {
        self.directory.open_file(OsStr::new(name))
    }
    pub(in crate::store) fn open_for_sync(&self, name: &str) -> io::Result<File> {
        self.directory.open_file_for_update(OsStr::new(name))
    }
    pub(in crate::store) fn same_file(&self, name: &str, file: &File) -> io::Result<()> {
        if self.directory.same_file(OsStr::new(name), file)? {
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
        self.directory.link_file(file, OsStr::new(name))
    }
    pub(in crate::store) fn remove(&self, name: &str, file: &File) -> io::Result<()> {
        self.directory.remove_file(OsStr::new(name), file)
    }
}
