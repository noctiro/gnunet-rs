//! Original private file retained through publication uncertainty.
use super::{Failure, Outcome, Stage, failure, fence::Fence};
use std::{ffi::OsString, fs::File, io, rc::Rc};
pub(super) struct Candidate {
    pub owner: Rc<Fence>,
    pub name: OsString,
    pub file: Option<File>,
    retained: bool,
}
impl Candidate {
    pub fn new(owner: Rc<Fence>) -> Result<Self, Failure> {
        for _ in 0..16 {
            let mut nonce = [0; 16];
            getrandom::fill(&mut nonce).map_err(|cause| {
                failure(Stage::Write, Outcome::NotCommitted, io::Error::other(cause))
            })?;
            let mut bytes = *b".tcp-frontier-00000000000000000000000000000000.tmp";
            const HEX: &[u8; 16] = b"0123456789abcdef";
            for (i, byte) in nonce.into_iter().enumerate() {
                bytes[14 + i * 2] = HEX[usize::from(byte >> 4)];
                bytes[15 + i * 2] = HEX[usize::from(byte & 15)];
            }
            let label = std::str::from_utf8(&bytes).map_err(|cause| {
                failure(Stage::Write, Outcome::NotCommitted, io::Error::other(cause))
            })?;
            let mut name = OsString::new();
            name.try_reserve_exact(bytes.len()).map_err(|cause| {
                failure(Stage::Write, Outcome::NotCommitted, io::Error::other(cause))
            })?;
            name.push(label);
            match owner.parent.create_private_file(&name) {
                Ok(file) => {
                    return Ok(Self {
                        owner,
                        name,
                        file: Some(file),
                        retained: false,
                    });
                }
                Err(cause) if cause.kind() == io::ErrorKind::AlreadyExists => {}
                Err(cause) => return Err(failure(Stage::Write, Outcome::NotCommitted, cause)),
            }
        }
        Err(failure(
            Stage::Write,
            Outcome::NotCommitted,
            io::Error::other("TCP stage namespace exhausted"),
        ))
    }
    pub fn original(&self) -> io::Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::other("original TCP stage consumed"))
    }
    pub fn publish(&mut self) -> io::Result<()> {
        // A returned error can follow the native rename or its identity check.
        self.retained = true;
        self.owner
            .parent
            .replace_file(&self.name, self.original()?, &self.owner.name)
    }
    pub fn discard(&mut self) -> io::Result<()> {
        self.retained = true;
        match self.owner.parent.remove_file(&self.name, self.original()?) {
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
}
impl Drop for Candidate {
    fn drop(&mut self) {
        if !self.retained {
            let _cleanup = self.discard();
        }
    }
}
