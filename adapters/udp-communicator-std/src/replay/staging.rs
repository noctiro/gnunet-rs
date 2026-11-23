//! Original private stage with independent, identity-bound cleanup.
use super::{Fence, JournalError, Outcome, Stage, TEMP, native};
use gnunet_native::filesystem::publication;
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
    pub fn seal(&mut self, expected_bytes: u64) -> Result<publication::Sealed<'_>, JournalError> {
        let file = self.file.take().ok_or(gnunet_types::Error::Stale)?;
        // The native sealing owner now retains exact prepublication cleanup;
        // after replacement is attempted it never removes the original stage.
        self.retired = true;
        publication::seal(&self.owner.parent, &self.name, file, expected_bytes).map_err(|failure| {
            let stage = match failure.stage {
                "file-sync" => Stage::FileSync,
                "writer-close" => Stage::WriterClose,
                _ => Stage::Seal,
            };
            super::publication_failure(stage, failure)
        })
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
