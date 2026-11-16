//! Original directory, persistent writer lock and anchored proof publication.
use gnunet_native::{
    DirectorySync,
    filesystem::{Directory, FileIdentity, private_single_file_identity},
};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};
pub(super) struct Namespace {
    directory: Directory,
    path: PathBuf,
    identity: FileIdentity,
    name: OsString,
    guard_name: OsString,
    guard: File,
    guard_identity: FileIdentity,
}
impl Namespace {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        let name = path
            .file_name()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "NSE proof path has no filename",
                )
            })?
            .to_owned();
        gnunet_service_runtime::private_parents(path)?;
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = Directory::open(parent)?;
        directory.validate_namespace()?;
        let identity = FileIdentity::of(directory.as_file())?;
        let path = fs::canonicalize(parent)?;
        let mut guard_name = name.clone();
        guard_name.push(".nse-lock");
        let guard = match directory.open_file_for_update(&guard_name) {
            Ok(file) => file,
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => {
                directory.create_private_file(&guard_name)?
            }
            Err(cause) => return Err(cause),
        };
        let guard_identity = private_single_file_identity(&guard)?;
        guard.try_lock().map_err(io::Error::from)?;
        let namespace = Self {
            directory,
            path,
            identity,
            name,
            guard_name,
            guard,
            guard_identity,
        };
        namespace.verify()?;
        Ok(namespace)
    }
    pub(super) fn verify(&self) -> io::Result<()> {
        self.directory.validate_namespace()?;
        let selected = Directory::open(&self.path)?;
        if FileIdentity::of(selected.as_file())? != self.identity
            || FileIdentity::of(self.directory.as_file())? != self.identity
            || private_single_file_identity(&self.guard)? != self.guard_identity
            || !self.directory.same_file(&self.guard_name, &self.guard)?
        {
            return Err(io::Error::other(
                "original NSE proof namespace or writer fence changed",
            ));
        }
        Ok(())
    }
    pub(super) fn verify_proof(&self, original: &File) -> io::Result<()> {
        self.verify()?;
        if !self.directory.same_file(&self.name, original)? {
            return Err(io::Error::other("original NSE proof name changed"));
        }
        Ok(())
    }
    pub(super) fn sync(&self) -> io::Result<DirectorySync> {
        self.verify()?;
        let barrier = self.directory.sync()?;
        self.verify()?;
        Ok(barrier)
    }
    pub(super) fn open_proof(&self) -> io::Result<File> {
        self.directory.open_file(&self.name)
    }
    pub(super) fn staging(&self) -> io::Result<(OsString, File)> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let mut name = self.name.clone();
        name.push(format!(".new-{:032x}", u128::from_be_bytes(nonce)));
        let file = self.directory.create_private_file(&name)?;
        Ok((name, file))
    }
    pub(super) fn publish(&self, name: &OsStr, original: &File) -> io::Result<()> {
        self.directory.replace_file(name, original, &self.name)
    }
    pub(super) fn discard(&self, name: &OsStr, original: &File) -> io::Result<()> {
        match self.directory.remove_file(name, original) {
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}
