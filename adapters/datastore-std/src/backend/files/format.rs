//! Private format admission before creating the values directory or WAL.
use super::{Directory, Error, LOCK, ProtocolError};
use gnunet_native::filesystem::private_single_file_identity;
use std::{
    ffi::OsStr,
    io::{self, Read, Write},
};
pub(super) fn ensure(root: &Directory) -> Result<(), Error> {
    const NAME: &str = ".format";
    const MAGIC: &[u8; 8] = b"GNDST001";
    match root.open_file(OsStr::new(NAME)) {
        Ok(mut file) => {
            private_single_file_identity(&file).map_err(|e| Error::io("format-metadata", e))?;
            if file
                .metadata()
                .map_err(|e| Error::io("format-size", e))?
                .len()
                != MAGIC.len() as u64
            {
                return Err(Error::protocol("format", ProtocolError::Unsupported));
            }
            let mut actual = [0; 8];
            file.read_exact(&mut actual)
                .map_err(|e| Error::io("format-read", e))?;
            if actual != *MAGIC {
                return Err(Error::protocol("format", ProtocolError::Unsupported));
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            for name in root
                .entries()
                .map_err(|e| Error::io("format-directory", e))?
            {
                if name.map_err(|e| Error::io("format-entry", e))? != OsStr::new(LOCK) {
                    return Err(Error::protocol(
                        "unrecognized-directory",
                        ProtocolError::Unsupported,
                    ));
                }
            }
            let mut file = root
                .create_private_file(OsStr::new(NAME))
                .map_err(|e| Error::io("format-create", e))?;
            file.write_all(MAGIC)
                .map_err(|e| Error::io("format-write", e))?;
            file.sync_all().map_err(|e| Error::io("format-sync", e))?;
            root.sync()
                .map_err(|e| Error::io("format-directory-sync", e))?;
            Ok(())
        }
        Err(e) => Err(Error::io("format-open", e)),
    }
}
