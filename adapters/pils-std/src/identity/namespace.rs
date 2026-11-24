//! Native private directory and persistent cooperating-writer fence.
use gnunet_native::{
    DirectorySync,
    filesystem::{
        Directory, EntryInfo, FileIdentity, PrivateFileSnapshot, private_single_file_identity,
        publication,
    },
};
use std::{
    ffi::OsString,
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
    pub(super) fn verify_key_name(&self, identity: FileIdentity) -> io::Result<()> {
        self.verify()?;
        let named = self.directory.entry_info(&self.key)?;
        if !matches!(named, EntryInfo::File(info) if info.identity == identity) {
            return Err(io::Error::other("PILS original named key changed"));
        }
        Ok(())
    }
    pub(super) fn verify_key_snapshot(
        &self,
        file: &File,
        snapshot: &PrivateFileSnapshot,
    ) -> io::Result<()> {
        self.verify()?;
        snapshot.verify(&self.directory, &self.key, file)
    }
    pub(super) fn confirm_key_read(
        &self,
        file: &File,
        snapshot: PrivateFileSnapshot,
    ) -> io::Result<PrivateFileSnapshot> {
        self.verify()?;
        snapshot.confirm_read(&self.directory, &self.key, file)
    }
    pub(super) fn open_key(&self) -> io::Result<File> {
        self.directory.open_file(&self.key)
    }
    pub(super) fn sync_key(&self, original: &File) -> io::Result<()> {
        self.verify()?;
        publication::sync_original(&self.directory, &self.key, original)
    }
    pub(super) fn sync(&self) -> io::Result<DirectorySync> {
        self.directory.sync()
    }
    pub(super) fn publish(&self, seed: &[u8; 32]) -> io::Result<(File, DirectorySync)> {
        let published = publication::publish(
            &self.directory,
            &self.key,
            seed,
            publication::Destination::Create,
            || self.verify(),
        )
        .map_err(|failure| io::Error::new(failure.cause.kind(), failure))?;
        Ok(published.into_parts())
    }
}
