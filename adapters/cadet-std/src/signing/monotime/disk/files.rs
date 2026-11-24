//! Native original-object persistence beneath the monotime reservation policy.
mod temporary;
use super::{BYTES, Error, Lease, Outcome, Stage, fail};
use gnunet_native::{
    DirectorySync,
    filesystem::{
        Directory, ExclusiveFile, FileIdentity, FileReader, PrivateFileSnapshot,
        private_data_file_info, private_single_file_identity, publication, validate_readonly,
    },
};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, TryLockError},
    io,
    path::{Path, PathBuf},
    sync::{Arc, atomic::AtomicU64},
};
pub(super) use temporary::Temporary;
pub(super) struct Files {
    parent: PathBuf,
    directory: Directory,
    directory_id: FileIdentity,
    name: OsString,
    guard_name: OsString,
    guard_id: FileIdentity,
    pub(super) lease: Arc<Lease>,
    selected: Option<Image>,
    pending: Option<Image>,
    names: Option<DirectorySync>,
    counter: u64,
}
struct Image {
    file: File,
    reader: FileReader,
}
/// A checked original image tied to both its writer and its staging file.
pub(super) struct Prepared<'writer, 'staging> {
    files: &'writer mut Files,
    temporary: &'staging mut Temporary,
    image: Image,
}
impl Prepared<'_, '_> {
    pub(super) fn publish(self) -> Result<(), Error> {
        let Self {
            files,
            temporary,
            image,
        } = self;
        files.pending = Some(image);
        files.names = None;
        // Native replacement can report failure after applying its effect.
        temporary.published = true;
        files
            .directory
            .replace_file(&temporary.name, &temporary.file, &files.name)
            .map_err(|e| fail(Stage::Rename, Outcome::Unknown, e))
    }
}
impl Image {
    fn new(file: File) -> Result<Self, Error> {
        validate_readonly(&file).map_err(|e| fail(Stage::Read, Outcome::NotCommitted, e))?;
        let info = private_data_file_info(&file)
            .map_err(|e| fail(Stage::Read, Outcome::NotCommitted, e))?;
        if info.bytes != BYTES as u64 {
            return Err(fail(
                Stage::Read,
                Outcome::NotCommitted,
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "monotime requires an exact 80-byte private file",
                ),
            ));
        }
        let reader = FileReader::from_file(&file)
            .map_err(|e| fail(Stage::Read, Outcome::NotCommitted, e))?;
        Ok(Self { file, reader })
    }
    fn read(&self, directory: &Directory, name: &OsStr) -> Result<[u8; BYTES], Error> {
        let before = private_data_file_info(&self.file)
            .map_err(|e| fail(Stage::Read, Outcome::Unknown, e))?;
        if before.bytes != BYTES as u64 {
            return Err(fail(
                Stage::Read,
                Outcome::Unknown,
                io::Error::other("monotime image size changed"),
            ));
        }
        let mut bytes = [0; BYTES];
        self.reader
            .read_exact_at(&mut bytes, 0)
            .map_err(|e| fail(Stage::Read, Outcome::NotCommitted, e))?;
        PrivateFileSnapshot::new(before, &bytes)
            .confirm_read(directory, name, &self.file)
            .map_err(|e| fail(Stage::Read, Outcome::Unknown, e))?;
        Ok(bytes)
    }
}
impl Files {
    pub(super) fn open(path: &Path) -> Result<Self, Error> {
        gnunet_service_runtime::private_parents(path)
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        let name = path
            .file_name()
            .ok_or_else(|| {
                fail(
                    Stage::Fence,
                    Outcome::NotCommitted,
                    io::Error::new(io::ErrorKind::InvalidInput, "monotime path has no filename"),
                )
            })?
            .to_owned();
        let parent = fs::canonicalize(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )
        .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        let directory =
            Directory::open(&parent).map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        directory
            .validate_private()
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        let directory_id = FileIdentity::of(directory.as_file())
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        let mut guard_name = name.clone();
        guard_name.push(".cadet-monotime-lock");
        let guard = match directory.open_file_for_update(&guard_name) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => directory
                .create_private_file(&guard_name)
                .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?,
            Err(e) => return Err(fail(Stage::Fence, Outcome::NotCommitted, e)),
        };
        let guard_id = private_single_file_identity(&guard)
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        let guard = ExclusiveFile::try_lock(guard).map_err(|e| {
            fail(
                Stage::Fence,
                Outcome::NotCommitted,
                match e {
                    TryLockError::WouldBlock => io::ErrorKind::WouldBlock.into(),
                    TryLockError::Error(e) => e,
                },
            )
        })?;
        guard
            .sync_all()
            .map_err(|e| fail(Stage::Fence, Outcome::NotCommitted, e))?;
        let selected = match directory.open_file(&name) {
            Ok(file) => Some(Image::new(file)?),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(fail(Stage::Read, Outcome::NotCommitted, e)),
        };
        let names = Some(
            directory
                .sync()
                .map_err(|e| fail(Stage::DirectorySync, Outcome::Unknown, e))?,
        );
        let files = Self {
            parent,
            directory,
            directory_id,
            name,
            guard_name,
            guard_id,
            lease: Arc::new(Lease {
                guard,
                issued: AtomicU64::new(0),
            }),
            selected,
            pending: None,
            names,
            counter: 0,
        };
        files.fence()?;
        Ok(files)
    }
    pub(super) fn fence(&self) -> Result<(), Error> {
        self.directory
            .validate_private()
            .map_err(|e| fail(Stage::Fence, Outcome::Unknown, e))?;
        let named =
            Directory::open(&self.parent).map_err(|e| fail(Stage::Fence, Outcome::Unknown, e))?;
        if FileIdentity::of(named.as_file()).map_err(|e| fail(Stage::Fence, Outcome::Unknown, e))?
            != self.directory_id
            || private_single_file_identity(self.lease.guard.as_file())
                .map_err(|e| fail(Stage::Fence, Outcome::Unknown, e))?
                != self.guard_id
            || !self
                .directory
                .same_file(&self.guard_name, self.lease.guard.as_file())
                .map_err(|e| fail(Stage::Fence, Outcome::Unknown, e))?
        {
            return Err(fail(
                Stage::Fence,
                Outcome::Unknown,
                io::Error::other("original monotime writer namespace changed"),
            ));
        }
        self.current().map(|_| ())
    }
    fn current(&self) -> Result<Option<&Image>, Error> {
        for image in [self.pending.as_ref(), self.selected.as_ref()]
            .into_iter()
            .flatten()
        {
            match self.directory.same_file(&self.name, &image.file) {
                Ok(true) => return Ok(Some(image)),
                Ok(false) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(fail(Stage::Fence, Outcome::Unknown, e)),
            }
        }
        match self.directory.entry_info(&self.name) {
            Err(e)
                if e.kind() == io::ErrorKind::NotFound
                    && self.pending.is_none()
                    && self.selected.is_none() =>
            {
                Ok(None)
            }
            Err(e) => Err(fail(Stage::Fence, Outcome::Unknown, e)),
            Ok(_) => Err(fail(
                Stage::Fence,
                Outcome::Unknown,
                io::Error::other("monotime name no longer selects an original image"),
            )),
        }
    }
    pub(super) fn read(&self) -> Result<Option<[u8; BYTES]>, Error> {
        self.fence()?;
        let bytes = self
            .current()?
            .map(|image| image.read(&self.directory, &self.name))
            .transpose()?;
        self.fence()?;
        Ok(bytes)
    }
    pub(super) fn prepare<'writer, 'staging>(
        &'writer mut self,
        temporary: &'staging mut Temporary,
    ) -> Result<Prepared<'writer, 'staging>, Error> {
        self.fence()?;
        temporary.verify()?;
        let image = Image::new(
            temporary
                .file
                .try_clone()
                .map_err(|e| fail(Stage::Rename, Outcome::NotCommitted, e))?,
        )?;
        Ok(Prepared {
            files: self,
            temporary,
            image,
        })
    }
    pub(super) fn settle(&mut self) -> Result<(), Error> {
        self.fence()?;
        self.names = None;
        // Keep the selected image read-only. Windows acquires and closes its
        // temporary same-object sync handle before the following readback.
        let image = self.current()?.ok_or_else(|| {
            fail(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("missing monotime image"),
            )
        })?;
        publication::sync_original(&self.directory, &self.name, &image.file)
            .map_err(|e| fail(Stage::Recovery, Outcome::Unknown, e))?;
        self.names = Some(
            self.directory
                .sync()
                .map_err(|e| fail(Stage::Recovery, Outcome::Unknown, e))?,
        );
        self.fence()
    }
    pub(super) fn adopt(&mut self) -> Result<(), Error> {
        self.fence()?;
        let pending = self.pending.as_ref().ok_or_else(|| {
            fail(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("missing original monotime candidate"),
            )
        })?;
        if !self
            .directory
            .same_file(&self.name, &pending.file)
            .map_err(|e| fail(Stage::Recovery, Outcome::Unknown, e))?
        {
            return Err(fail(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original monotime candidate was not selected"),
            ));
        }
        self.selected = self.pending.take();
        Ok(())
    }
    pub(super) fn directory_sync(&self) -> Option<DirectorySync> {
        self.names
    }
}
