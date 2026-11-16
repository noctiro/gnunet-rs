//! Original private file and namespace fences; no image replacement or history.
use super::frame::{self, BYTES, FILE_BYTES, Frame};
use gnunet_native::{
    DirectorySync,
    filesystem::{
        Directory, ExclusiveFile, FileIdentity, private_data_file_info,
        private_single_file_identity,
    },
};
use std::{
    ffi::OsString,
    fs::{self, TryLockError},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
#[derive(Debug)]
pub(super) struct Files {
    parent: PathBuf,
    directory: Directory,
    directory_id: FileIdentity,
    name: OsString,
    file: ExclusiveFile,
    #[cfg(test)]
    pub(super) fail_sync: bool,
}
fn changed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "original TUN checkpoint namespace changed",
    )
}
impl Files {
    pub(super) fn open(path: &Path) -> io::Result<(Self, bool)> {
        let name = path
            .file_name()
            .ok_or(io::ErrorKind::InvalidInput)?
            .to_owned();
        let parent = fs::canonicalize(
            path.parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new(".")),
        )?;
        let directory = Directory::open(&parent)?;
        directory.validate_private()?;
        let directory_id = FileIdentity::of(directory.as_file())?;
        let (file, created) = match directory.open_file_for_update(&name) {
            Ok(file) => (file, false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                (directory.create_private_file(&name)?, true)
            }
            Err(error) => return Err(error),
        };
        private_single_file_identity(&file)?;
        let file = ExclusiveFile::try_lock(file).map_err(|error| match error {
            TryLockError::WouldBlock => io::ErrorKind::WouldBlock.into(),
            TryLockError::Error(error) => error,
        })?;
        let files = Self {
            parent,
            directory,
            directory_id,
            name,
            file,
            #[cfg(test)]
            fail_sync: false,
        };
        files.fence()?;
        Ok((files, created))
    }
    fn fence(&self) -> io::Result<()> {
        self.directory.validate_private()?;
        private_single_file_identity(self.file.as_file())?;
        let named = Directory::open(&self.parent)?;
        if FileIdentity::of(named.as_file())? != self.directory_id
            || !self.directory.same_file(&self.name, self.file.as_file())?
        {
            return Err(changed());
        }
        Ok(())
    }
    pub(super) fn initialize(&mut self, frame: &Frame) -> io::Result<()> {
        self.fence()?;
        if self.file.as_file().metadata()?.len() != 0 {
            return Err(changed());
        }
        self.file.as_file().set_len(FILE_BYTES as u64)?;
        self.write(0, frame)?;

        self.fence()
    }
    pub(super) fn read(&mut self) -> io::Result<(Frame, usize)> {
        self.fence()?;
        let before = private_data_file_info(self.file.as_file())?;
        if before.bytes != FILE_BYTES as u64 {
            return Err(changed());
        }
        let mut bytes = [0; FILE_BYTES];
        // The private original file is never lent or duplicated. All cursor
        // operations are serialized through this unique mutable owner.
        let mut file = self.file.as_file();
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut bytes)?;
        if private_data_file_info(self.file.as_file())? != before {
            return Err(changed());
        }
        self.fence()?;
        frame::select(&bytes)
    }
    pub(super) fn write(&mut self, slot: usize, frame: &Frame) -> io::Result<()> {
        self.fence()?;
        if slot > 1 || self.file.as_file().metadata()?.len() != FILE_BYTES as u64 {
            return Err(changed());
        }
        let mut file = self.file.as_file();
        file.seek(SeekFrom::Start((slot * BYTES) as u64))?;
        file.write_all(&frame.encode())?;
        #[cfg(test)]
        if std::mem::take(&mut self.fail_sync) {
            return Err(io::Error::other(
                "controlled missing checkpoint sync receipt",
            ));
        }
        self.sync()
    }
    pub(super) fn sync_name(&self) -> io::Result<()> {
        self.fence()?;
        if self.directory.sync()? != DirectorySync::Synchronized {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "TUN checkpoint requires a directory naming barrier",
            ));
        }
        self.fence()
    }
    pub(super) fn sync(&self) -> io::Result<()> {
        self.fence()?;
        self.file.sync_all()?;
        self.fence()
    }
}
