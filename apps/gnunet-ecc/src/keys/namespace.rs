//! Selected original directory, independent of public filename observations.
use crate::Failure;
use gnunet_native::filesystem::{Directory, EntryInfo, FileIdentity, FileInfo, file_info};
use std::{
    ffi::OsString,
    fs::File,
    io,
    path::{Path, PathBuf},
};

pub(super) struct Namespace {
    pub(super) directory: Directory,
    pub(super) name: OsString,
    parent: PathBuf,
    identity: FileIdentity,
}
impl Namespace {
    pub(super) fn select(path: &Path) -> Result<Self, Failure> {
        let name = path
            .file_name()
            .ok_or("ECC requires a native file leaf")?
            .to_owned();
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = Directory::open(parent)?;
        let identity = FileIdentity::of(directory.as_file())?;
        Ok(Self {
            directory,
            name,
            parent: parent.to_owned(),
            identity,
        })
    }
    pub(super) fn verify(&self) -> Result<(), Failure> {
        let current = Directory::open(&self.parent)?;
        if FileIdentity::of(current.as_file())? != self.identity
            || FileIdentity::of(self.directory.as_file())? != self.identity
        {
            return Err("original ECC parent directory changed".into());
        }
        Ok(())
    }
    pub(super) fn path(&self, name: &std::ffi::OsStr) -> PathBuf {
        self.parent.join(name)
    }
}
pub(super) fn observe(file: &File) -> io::Result<FileInfo> {
    match file_info(file)? {
        EntryInfo::File(info) => Ok(info),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ordinary ECC file required",
        )),
    }
}
