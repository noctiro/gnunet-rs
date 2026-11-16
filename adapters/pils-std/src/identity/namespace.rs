//! Native private directory and persistent cooperating-writer fence.
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
struct Lock {
    file: File,
    name: OsString,
    identity: FileIdentity,
}
pub(super) struct Namespace {
    directory: Directory,
    path: PathBuf,
    identity: FileIdentity,
    key: OsString,
    lock: Option<Lock>,
}
impl Namespace {
    pub(super) fn existing(path: &Path) -> io::Result<Self> {
        let key = path
            .file_name()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "PILS key path has no filename")
            })?
            .to_owned();
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let directory = Directory::open(parent)?;
        directory.validate_namespace()?;
        let identity = FileIdentity::of(directory.as_file())?;
        let path = fs::canonicalize(parent)?;
        let namespace = Self {
            directory,
            path,
            identity,
            key,
            lock: None,
        };
        namespace.verify()?;
        Ok(namespace)
    }
    pub(super) fn writer(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let parent = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        #[cfg(windows)]
        gnunet_native::local_path::prepare_parents(
            path,
            gnunet_native::local_path::EndpointAccess::Owner,
        )?;
        let mut namespace = Self::existing(path)?;
        let mut name = namespace.key.clone();
        name.push(".pils-lock");
        let file = match namespace.directory.open_file_for_update(&name) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                namespace.directory.create_private_file(&name)?
            }
            Err(error) => return Err(error),
        };
        let identity = private_single_file_identity(&file)?;
        file.try_lock().map_err(io::Error::from)?;
        namespace.lock = Some(Lock {
            file,
            name,
            identity,
        });
        namespace.verify()?;
        Ok(namespace)
    }
    pub(super) fn verify(&self) -> io::Result<()> {
        self.directory.validate_namespace()?;
        let selected = Directory::open(&self.path)?;
        if FileIdentity::of(selected.as_file())? != self.identity
            || FileIdentity::of(self.directory.as_file())? != self.identity
        {
            return Err(io::Error::other("PILS original directory changed"));
        }
        if let Some(lock) = &self.lock
            && (private_single_file_identity(&lock.file)? != lock.identity
                || !self.directory.same_file(&lock.name, &lock.file)?)
        {
            return Err(io::Error::other("PILS original writer fence changed"));
        }
        Ok(())
    }
    pub(super) fn verify_key(&self, file: &File) -> io::Result<()> {
        self.verify()?;
        if !self.directory.same_file(&self.key, file)? {
            return Err(io::Error::other("PILS original key name changed"));
        }
        Ok(())
    }
    pub(super) fn open_key(&self, sync: bool) -> io::Result<File> {
        if sync {
            self.directory.open_file_for_sync(&self.key)
        } else {
            self.directory.open_file(&self.key)
        }
    }
    pub(super) fn sync(&self) -> io::Result<DirectorySync> {
        self.directory.sync()
    }
    pub(super) fn staging(&self) -> io::Result<(OsString, File)> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let mut name = self.key.clone();
        name.push(format!(".new-{:032x}", u128::from_be_bytes(nonce)));
        let file = self.directory.create_private_file(&name)?;
        Ok((name, file))
    }
    pub(super) fn publish(&self, name: &OsStr, original: &File) -> io::Result<()> {
        self.verify()?;
        match self.directory.entry_info(&self.key) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "PILS key appeared during creation",
                ));
            }
            Err(error) => return Err(error),
        }
        self.directory.replace_file(name, original, &self.key)
    }
    pub(super) fn discard(&self, name: &OsStr, original: &File) -> io::Result<()> {
        match self.directory.remove_file(name, original) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}
