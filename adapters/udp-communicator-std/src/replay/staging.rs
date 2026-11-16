//! Original private stage with independent, identity-bound cleanup.
use super::{Fence, JournalError, Outcome, Stage, TEMP, native};
use std::{ffi::OsString, fs::File, io, sync::Arc};
pub(super) struct Staging {
    owner: Arc<Fence>,
    name: OsString,
    pub file: Option<File>,
    retired: bool,
}
impl Staging {
    pub fn new(owner: Arc<Fence>) -> Result<Self, JournalError> {
        for _ in 0..16 {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).map_err(|cause| {
                native(
                    Stage::Create,
                    Outcome::NotCommitted,
                    io::Error::other(cause),
                )
            })?;
            let name = OsString::from(format!("{TEMP}{:032x}", u128::from_be_bytes(nonce)));
            match owner.parent.create_private_file(&name) {
                Ok(file) => {
                    return Ok(Self {
                        owner,
                        name,
                        file: Some(file),
                        retired: false,
                    });
                }
                Err(cause) if cause.kind() == io::ErrorKind::AlreadyExists => {}
                Err(cause) => return Err(native(Stage::Create, Outcome::NotCommitted, cause)),
            }
        }
        Err(gnunet_types::Error::Capacity.into())
    }
    pub fn publish(&self, target: &std::ffi::OsStr) -> io::Result<()> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| io::Error::other("UDP original stage was consumed"))?;
        self.owner.parent.replace_file(&self.name, file, target)
    }
    pub fn into_file(mut self) -> Result<File, JournalError> {
        // Publication may have effects even on failure: preserve the original
        // stage name for explicit recovery, never delete the committed target.
        self.retired = true;
        self.file.take().ok_or(gnunet_types::Error::Stale.into())
    }
    pub fn discard(&mut self) -> io::Result<()> {
        self.retired = true;
        let Some(file) = self.file.as_ref() else {
            return Ok(());
        };
        match self.owner.parent.remove_file(&self.name, file) {
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        }
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if !self.retired {
            let _cleanup = self.discard();
        }
    }
}
