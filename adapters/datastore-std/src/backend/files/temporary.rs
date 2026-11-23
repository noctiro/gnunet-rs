//! Exclusive staging files retained across publication and uncertain errors.
use super::{Error, Files, ProtocolError};
use gnunet_native::filesystem::{Directory, FileIdentity, private_single_file_identity};
use std::{ffi::OsStr, fs::File, io, mem::DropGuard};
pub(in super::super) struct Temporary {
    directory: Directory,
    pub(super) name: String,
    pub(in super::super) file: File,
    pub(super) identity: FileIdentity,
    pub(super) published: bool,
}
impl Files {
    pub(in super::super) fn temporary(&mut self, values: bool) -> Result<Temporary, Error> {
        let directory = if values { &self.values } else { &self.root };
        let directory = directory
            .duplicate()
            .map_err(|e| Error::io("temporary-directory", e))?;
        for _ in 0..1024 {
            let nonce = self.nonce;
            self.nonce = nonce
                .checked_add(1)
                .ok_or_else(|| Error::protocol("temporary-sequence", ProtocolError::Overflow))?;
            let name = format!(".tmp-{}-{nonce}", std::process::id());
            // A failed creation can have consumed a name; retire old receipts.
            self.dirty(values);
            match directory.create_private_file(OsStr::new(&name)) {
                Ok(file) => {
                    let pending = DropGuard::new(file, |file| {
                        let _cleanup = directory.remove_file(OsStr::new(&name), &file);
                    });
                    let identity = private_single_file_identity(&pending)
                        .map_err(|e| Error::io("temporary-metadata", e))?;
                    let file = DropGuard::dismiss(pending);
                    return Ok(Temporary {
                        directory,
                        name,
                        file,
                        identity,
                        published: false,
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(Error::io("temporary-open", e)),
            }
        }
        Err(Error::protocol(
            "temporary-collisions",
            ProtocolError::Capacity,
        ))
    }
}
impl Temporary {
    pub(super) fn verify(&self) -> Result<(), Error> {
        if private_single_file_identity(&self.file).map_err(|e| Error::io("temporary-held", e))?
            != self.identity
            || !self
                .directory
                .same_file(OsStr::new(&self.name), &self.file)
                .map_err(|e| Error::io("temporary-named", e))?
        {
            return Err(Error::protocol(
                "temporary-authority",
                ProtocolError::Conflict,
            ));
        }
        Ok(())
    }
    pub(super) fn remove(&mut self) -> Result<(), Error> {
        self.directory
            .remove_file(OsStr::new(&self.name), &self.file)
            .map_err(|e| Error::io("temporary-cleanup", e))?;
        self.published = true;
        Ok(())
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.published {
            let _cleanup = self
                .directory
                .remove_file(OsStr::new(&self.name), &self.file);
        }
    }
}

pub(super) fn is_temporary(bytes: &[u8]) -> bool {
    let Some(rest) = bytes.strip_prefix(b".tmp-") else {
        return false;
    };
    let Some(split) = rest.iter().position(|b| *b == b'-') else {
        return false;
    };
    split != 0
        && split + 1 < rest.len()
        && rest[..split].iter().all(u8::is_ascii_digit)
        && rest[split + 1..].iter().all(u8::is_ascii_digit)
}
