//! Original-object snapshot replacement and independent naming-barrier receipts.
use super::{Error, IMAGE, MAX_IMAGE, NEXT, io as failure};
use gnunet_native::{
    DirectorySync,
    filesystem::{Directory, private_data_file_info},
};
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
};

pub(super) struct Image {
    directory: Directory,
    original: Option<Original>,
    naming_sync: Option<DirectorySync>,
}
struct Original {
    file: File,
    info: gnunet_native::filesystem::FileInfo,
}
impl Image {
    pub(super) fn new(directory: &File) -> io::Result<Self> {
        Ok(Self {
            directory: Directory::from_file(directory)?,
            original: None,
            naming_sync: None,
        })
    }
    pub(super) fn read(&mut self) -> Result<Option<Vec<u8>>, Error> {
        let file = match self.directory.open_file(OsStr::new(IMAGE)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let info = private_data_file_info(&file)?;
        if info.bytes > MAX_IMAGE as u64 {
            return Err(Error::Binding("catalog image exceeds bound"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(info.bytes as usize + 1)
            .map_err(|_| Error::Binding("catalog allocation"))?;
        (&file).take(info.bytes + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != info.bytes
            || private_data_file_info(&file)? != info
            || !self.directory.same_file(OsStr::new(IMAGE), &file)?
        {
            return Err(Error::Binding("original catalog image changed"));
        }
        self.original = Some(Original { file, info });
        Ok(Some(bytes))
    }
    fn selected(&self) -> Result<(), Error> {
        match &self.original {
            Some(original) => {
                if private_data_file_info(&original.file)? != original.info
                    || !self
                        .directory
                        .same_file(OsStr::new(IMAGE), &original.file)?
                {
                    return Err(Error::Binding("original catalog image replaced"));
                }
            }
            None => match self.directory.entry_info(OsStr::new(IMAGE)) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(Error::Binding("unexpected catalog image")),
            },
        }
        Ok(())
    }
    pub(super) fn recover_temp(&mut self) -> Result<(), Error> {
        self.selected()?;
        let file = match self.directory.open_file(OsStr::new(NEXT)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        private_data_file_info(&file)?;
        self.naming_sync = None;
        self.directory.remove_file(OsStr::new(NEXT), &file)?;
        self.naming_sync = Some(self.directory.sync()?);
        Ok(())
    }
    pub(super) fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.selected()?;
        let mut file = self.directory.create_private_file(OsStr::new(NEXT))?;
        self.naming_sync = None;
        let mut visible = false;
        let result = (|| -> io::Result<gnunet_native::filesystem::FileInfo> {
            private_data_file_info(&file)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            // Native replacement can have changed names even when it returns
            // an error. Do not clean up or automatically replay that operation.
            visible = true;
            self.directory
                .replace_file(OsStr::new(NEXT), &file, OsStr::new(IMAGE))?;
            self.naming_sync = Some(self.directory.sync()?);
            if !self.directory.same_file(OsStr::new(IMAGE), &file)? {
                return Err(io::Error::other("published catalog image changed"));
            }
            private_data_file_info(&file)
        })();
        let info = match result {
            Ok(info) => info,
            Err(error) => {
                let cleanup = if visible {
                    None
                } else {
                    self.directory.remove_file(OsStr::new(NEXT), &file).err()
                };
                return Err(failure("atomic catalog commit", visible, error, cleanup));
            }
        };
        self.original = Some(Original { file, info });
        Ok(())
    }
    pub(super) fn create_version(&mut self, name: &OsStr) -> Result<(), Error> {
        drop(self.directory.create_private_directory(name)?);
        self.naming_sync = None;
        self.naming_sync = Some(self.directory.sync()?);
        Ok(())
    }
    pub(super) fn directory_sync(&self) -> Option<DirectorySync> {
        self.naming_sync
    }
}
