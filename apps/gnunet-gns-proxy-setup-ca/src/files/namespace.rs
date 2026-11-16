//! Original publication directory, including bounded private ancestor creation.
use crate::{Cause, budget::Budget};
use gnunet_native::filesystem::{Directory, FileIdentity};
use std::{
    ffi::OsString,
    io,
    path::{Path, PathBuf},
};
pub(super) struct Namespace {
    pub directory: Directory,
    pub name: OsString,
    path: PathBuf,
    identity: FileIdentity,
}
impl Namespace {
    pub async fn select(target: &Path, budget: &Budget) -> Result<Self, Cause> {
        let path = if target.is_absolute() {
            target.to_owned()
        } else {
            std::env::current_dir()?.join(target)
        };
        let name = path
            .file_name()
            .ok_or("CA requires an ordinary native file leaf")?
            .to_owned();
        let parent = path
            .parent()
            .ok_or("CA requires a parent directory")?
            .to_owned();
        let mut anchor = parent.as_path();
        let mut missing = Vec::new();
        let mut directory = loop {
            budget.check().await?;
            match Directory::open(anchor) {
                Ok(directory) => break directory,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    if missing.len() == 256 {
                        return Err("CA parent component capacity reached".into());
                    }
                    missing.try_reserve(1)?;
                    missing.push(
                        anchor
                            .file_name()
                            .ok_or("CA parent has no existing anchor")?
                            .to_owned(),
                    );
                    anchor = anchor.parent().ok_or("CA parent has no existing anchor")?;
                }
                Err(error) => return Err(error.into()),
            }
        };
        for name in missing.into_iter().rev() {
            budget.check().await?;
            directory = directory.ensure_directory(&name)?;
        }
        directory.validate_namespace()?;
        let identity = FileIdentity::of(directory.as_file())?;
        let namespace = Self {
            directory,
            name,
            path: parent,
            identity,
        };
        namespace.check()?;
        Ok(namespace)
    }
    pub fn check(&self) -> io::Result<()> {
        self.directory.validate_namespace()?;
        let current = Directory::open(&self.path)?;
        if FileIdentity::of(current.as_file())? != self.identity
            || FileIdentity::of(self.directory.as_file())? != self.identity
        {
            return Err(io::Error::other(
                "original CA publication directory changed",
            ));
        }
        Ok(())
    }
    pub fn absent(&self) -> io::Result<()> {
        match self.directory.entry_info(&self.name) {
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "existing CA destination preserved",
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}
