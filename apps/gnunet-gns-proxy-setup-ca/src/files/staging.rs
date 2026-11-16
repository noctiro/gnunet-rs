//! Private original staging file and independent removal/close observations.
use super::namespace::Namespace;
use crate::{Cause, budget::Budget};
use gnunet_native::filesystem::{self, EntryInfo};
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Write},
};
pub(super) struct Staging {
    pub namespace: Namespace,
    pub name: OsString,
    file: Option<File>,
    present: bool,
    attempted_cleanup: bool,
    length: u64,
}
#[derive(Debug, Default)]
pub(super) struct Cleanup {
    pub retained_name: Option<OsString>,
    pub remove: Option<io::Error>,
    pub close: Option<io::Error>,
}
impl Cleanup {
    pub fn successful(&self) -> bool {
        self.retained_name.is_none() && self.remove.is_none() && self.close.is_none()
    }
}
impl Staging {
    pub async fn create(namespace: Namespace, kind: &str, budget: &Budget) -> Result<Self, Cause> {
        for serial in 0..128u16 {
            budget.check().await?;
            namespace.check()?;
            let name = OsString::from(format!(
                ".gnunet-gns-ca-{kind}-{}-{serial}.tmp",
                std::process::id()
            ));
            match namespace.directory.create_private_file(&name) {
                Ok(file) => {
                    return Ok(Self {
                        namespace,
                        name,
                        file: Some(file),
                        present: true,
                        attempted_cleanup: false,
                        length: 0,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "CA staging-name capacity reached",
        )
        .into())
    }
    pub fn file(&self) -> io::Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::other("CA staging file already retired"))
    }
    pub fn file_mut(&mut self) -> io::Result<&mut File> {
        self.file
            .as_mut()
            .ok_or_else(|| io::Error::other("CA staging file already retired"))
    }
    pub fn check(&self) -> io::Result<()> {
        self.namespace.check()?;
        let file = self.file()?;
        filesystem::validate_private_file(file)?;
        if !matches!(filesystem::file_info(file)?, EntryInfo::File(info) if info.bytes == self.length)
            || self.present && !self.namespace.directory.same_file(&self.name, file)?
        {
            return Err(io::Error::other("original CA staging file changed"));
        }
        Ok(())
    }
    pub async fn write(&mut self, bytes: &[u8], budget: &Budget) -> Result<(), Cause> {
        for chunk in bytes.chunks(4096) {
            let mut at = 0;
            while at < chunk.len() {
                budget.check().await?;
                self.check()?;
                match self.file_mut()?.write(&chunk[at..]) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "zero CA staging write",
                        )
                        .into());
                    }
                    Ok(count) => {
                        at += count;
                        self.length = self
                            .length
                            .checked_add(count as u64)
                            .ok_or("CA staging length overflow")?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error.into()),
                }
            }
        }
        budget.check().await?;
        self.check()?;
        Ok(())
    }
    pub fn remove(&mut self) -> io::Result<()> {
        if self.present {
            self.namespace
                .directory
                .remove_file(&self.name, self.file()?)?;
            self.present = false;
        }
        Ok(())
    }
    pub fn cleanup(&mut self) -> Cleanup {
        self.attempted_cleanup = true;
        let remove = self.remove().err();
        let close = self
            .file
            .take()
            .and_then(|file| filesystem::close(file).err());
        Cleanup {
            retained_name: self.present.then(|| self.name.clone()),
            remove,
            close,
        }
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if !self.attempted_cleanup {
            let _cleanup = self.cleanup();
        }
    }
}
