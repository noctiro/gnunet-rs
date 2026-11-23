//! Exclusive staging and original-object cleanup; no replacement retries.
use super::{BYTES, Directory, Error, File, Files, Outcome, Stage, fail};
use gnunet_native::filesystem::{FileIdentity, private_single_file_identity, publication};
use std::{
    ffi::OsString,
    io::{self, Write},
    mem::DropGuard,
};
pub(in super::super) struct Temporary {
    directory: Directory,
    pub(super) name: OsString,
    pub(super) file: File,
    identity: FileIdentity,
    pub(super) published: bool,
}
impl Temporary {
    pub(in super::super) fn write(&mut self, bytes: &[u8; BYTES]) -> Result<(), Error> {
        self.file
            .write_all(bytes)
            .map_err(|e| fail(Stage::Write, Outcome::NotCommitted, e))?;
        // Finish the only writer before prepare can clone a retained image or
        // positional reader. Failure leaves this original for identity-bound Drop.
        publication::seal_retained(&self.directory, &self.name, &mut self.file, BYTES as u64)
            .map(|_| ())
            .map_err(|failure| {
                fail(
                    Stage::Write,
                    Outcome::NotCommitted,
                    io::Error::new(failure.cause.kind(), failure),
                )
            })
    }
    pub(super) fn verify(&self) -> Result<(), Error> {
        if private_single_file_identity(&self.file)
            .map_err(|e| fail(Stage::Write, Outcome::NotCommitted, e))?
            != self.identity
            || !self
                .directory
                .same_file(&self.name, &self.file)
                .map_err(|e| fail(Stage::Write, Outcome::NotCommitted, e))?
        {
            return Err(fail(
                Stage::Write,
                Outcome::NotCommitted,
                io::Error::other("monotime staging entry changed"),
            ));
        }
        Ok(())
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        if !self.published {
            let _cleanup = self.directory.remove_file(&self.name, &self.file);
        }
    }
}
impl Files {
    pub(in super::super) fn temporary(&mut self) -> Result<Temporary, Error> {
        for _ in 0..64 {
            self.counter = self.counter.checked_add(1).ok_or_else(|| {
                fail(
                    Stage::Write,
                    Outcome::NotCommitted,
                    io::Error::other("monotime temporary counter exhausted"),
                )
            })?;
            let mut name = self.name.clone();
            name.push(format!(
                ".cadet-new-{}-{}",
                std::process::id(),
                self.counter
            ));
            self.names = None;
            match self.directory.create_private_file(&name) {
                Ok(file) => {
                    let pending = DropGuard::new(file, |file| {
                        let _cleanup = self.directory.remove_file(&name, &file);
                    });
                    let identity = private_single_file_identity(&pending)
                        .map_err(|e| fail(Stage::Write, Outcome::NotCommitted, e))?;
                    let directory = self
                        .directory
                        .duplicate()
                        .map_err(|e| fail(Stage::Write, Outcome::NotCommitted, e))?;
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
                Err(e) => return Err(fail(Stage::Write, Outcome::NotCommitted, e)),
            }
        }
        Err(fail(
            Stage::Write,
            Outcome::NotCommitted,
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "bounded monotime temporary namespace occupied",
            ),
        ))
    }
}
