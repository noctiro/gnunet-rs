//! One absolute filename that can be lent as both a native path and IPC bytes.
use super::{Error, ProtocolError};
use std::path::Path;

pub(super) struct Filename {
    #[cfg(unix)]
    path: std::path::PathBuf,
    #[cfg(windows)]
    path: String,
}
impl Filename {
    pub(super) fn new(path: &Path) -> Result<Self, Error> {
        if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
            return Err(ProtocolError::InvalidInput.into());
        }
        #[cfg(unix)]
        {
            Ok(Self {
                path: crate::input::owned_path(path)?,
            })
        }
        #[cfg(windows)]
        {
            // Local UTF-16 code units without Unicode scalar values have no
            // GNUnet filename spelling. Never put local WTF-8 on the wire.
            let text = path.to_str().ok_or(ProtocolError::InvalidInput)?;
            let mut owned = String::new();
            owned
                .try_reserve_exact(text.len())
                .map_err(|_| ProtocolError::Capacity)?;
            owned.push_str(text);
            Ok(Self { path: owned })
        }
    }
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self::new(Path::new(std::ffi::OsStr::from_bytes(bytes)))
        }
        #[cfg(windows)]
        {
            Self::new(Path::new(
                std::str::from_utf8(bytes).map_err(|_| ProtocolError::Malformed)?,
            ))
        }
    }
    pub(super) fn as_path(&self) -> &Path {
        Path::new(&self.path)
    }
    pub(super) fn as_bytes(&self) -> &[u8] {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            self.path.as_os_str().as_bytes()
        }
        #[cfg(windows)]
        {
            self.path.as_bytes()
        }
    }
}
