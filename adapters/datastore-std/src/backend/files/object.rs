//! Immutable UID objects, bounded reads and original-object cleanup.
use super::{Error, Files, ProtocolError};
use gnunet_crypto::Hash256State;
use gnunet_native::filesystem::{FileIdentity, private_single_file_identity};
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read, Write},
};
impl Files {
    pub(in super::super) fn check_object(&self, uid: u64, length: u64) -> Result<(), Error> {
        self.object(uid, length).map(|_| ())
    }
    pub(in super::super) fn put_object(&mut self, uid: u64, value: &[u8]) -> Result<(), Error> {
        let mut temporary = self.temporary(true)?;
        for chunk in value.chunks(8192) {
            temporary
                .file
                .write_all(chunk)
                .map_err(|e| Error::io("value-write", e))?;
        }
        temporary
            .file
            .sync_all()
            .map_err(|e| Error::io("value-sync", e))?;
        let name = object_name(uid);
        self.values
            .link_file_from(
                &self.values,
                OsStr::new(&temporary.name),
                &temporary.file,
                OsStr::new(name_str(&name)?),
            )
            .map_err(|e| Error::io("value-link", e))?;
        self.sync_names()?;
        self.dirty(true);
        temporary.remove()?;
        self.sync_names()?;
        let installed = self.object(uid, value.len() as u64)?;
        if FileIdentity::of(&installed).map_err(|e| Error::io("installed-value-metadata", e))?
            != temporary.identity
        {
            return Err(Error::protocol(
                "installed-value-authority",
                ProtocolError::Conflict,
            ));
        }
        Ok(())
    }
    pub(in super::super) fn read_object(
        &self,
        uid: u64,
        length: u64,
        digest: &[u8; 32],
        output: &mut [u8],
    ) -> Result<(), Error> {
        if output.len() as u64 != length {
            return Err(Error::protocol("value-output", ProtocolError::Capacity));
        }
        let mut file = self.object(uid, length)?;
        let mut hash = Hash256State::new();
        let result = (|| {
            for chunk in output.chunks_mut(8192) {
                file.read_exact(chunk)
                    .map_err(|error| Error::io("value-read", error))?;
                hash.update(chunk);
            }
            if hash.finish() != *digest {
                return Err(Error::protocol(
                    "value-checksum",
                    ProtocolError::Authentication,
                ));
            }
            Ok(())
        })();
        if result.is_err() {
            output.fill(0);
        }
        result
    }
    pub(in super::super) fn equals_object(
        &self,
        uid: u64,
        value: &[u8],
        digest: &[u8; 32],
    ) -> Result<bool, Error> {
        let mut file = self.object(uid, value.len() as u64)?;
        let mut scratch = [0; 8192];
        let mut hash = Hash256State::new();
        let mut equal = true;
        for chunk in value.chunks(scratch.len()) {
            file.read_exact(&mut scratch[..chunk.len()])
                .map_err(|e| Error::io("value-compare", e))?;
            hash.update(&scratch[..chunk.len()]);
            equal &= scratch[..chunk.len()] == *chunk;
        }
        if hash.finish() != *digest {
            return Err(Error::protocol(
                "value-compare-checksum",
                ProtocolError::Authentication,
            ));
        }
        Ok(equal)
    }
    fn object(&self, uid: u64, length: u64) -> Result<File, Error> {
        let name = object_name(uid);
        let file = self
            .values
            .open_file(OsStr::new(name_str(&name)?))
            .map_err(|e| Error::io("value-open", e))?;
        private_single_file_identity(&file).map_err(|e| Error::io("value-metadata", e))?;
        if file
            .metadata()
            .map_err(|e| Error::io("value-size", e))?
            .len()
            != length
        {
            return Err(Error::protocol("value-shape", ProtocolError::Malformed));
        }
        Ok(file)
    }
    pub(in super::super) fn remove_object(&mut self, uid: u64) -> Result<(), Error> {
        self.remove_unreferenced(uid).map(|_| ())
    }
    pub(super) fn remove_unreferenced(&mut self, uid: u64) -> Result<bool, Error> {
        let name = object_name(uid);
        let name = OsStr::new(name_str(&name)?);
        let file = match self.values.open_file(name) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(Error::io("orphan-open", e)),
        };
        private_single_file_identity(&file).map_err(|e| Error::io("orphan-kind", e))?;
        self.dirty(true);
        self.values
            .remove_file(name, &file)
            .map_err(|e| Error::io("orphan-remove", e))?;
        Ok(true)
    }
    pub(in super::super) fn replace_unreferenced(&mut self, uid: u64) -> Result<(), Error> {
        if self.remove_unreferenced(uid)? {
            self.sync_names()?;
        }
        Ok(())
    }
}
fn name_str(name: &[u8; 16]) -> Result<&str, Error> {
    // object_name emits exactly sixteen lowercase ASCII hexadecimal digits.
    std::str::from_utf8(name).map_err(|_| Error::protocol("uid-name", ProtocolError::Malformed))
}
fn object_name(uid: u64) -> [u8; 16] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = [0; 16];
    for (position, byte) in name.iter_mut().enumerate() {
        *byte = HEX[((uid >> ((15 - position) * 4)) & 15) as usize];
    }
    name
}
pub(super) fn parse_object(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != 16 {
        return None;
    }
    let mut uid = 0_u64;
    for byte in bytes {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return None,
        };
        uid = uid * 16 + u64::from(digit);
    }
    (uid != 0).then_some(uid)
}
