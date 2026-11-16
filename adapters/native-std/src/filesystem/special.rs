//! Delete a selected special link inside an original caller-owned namespace.
use super::Directory;
#[cfg(unix)]
use super::EntryInfo;
use std::{ffi::OsStr, io};
impl Directory {
    /// Remove a symlink, socket, pipe or other special entry without following
    /// its target or opening its data stream. Ordinary files/directories are
    /// refused. The caller owns this namespace and excludes concurrent entry
    /// replacement; this grants no deletion authority outside this directory.
    pub fn remove_special(&self, name: &OsStr) -> io::Result<()> {
        #[cfg(unix)]
        {
            if self.entry_info(name)? != EntryInfo::Other {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "special entry required",
                ));
            }
            nix::unistd::unlinkat(
                self.as_file(),
                name,
                nix::unistd::UnlinkatFlags::NoRemoveDir,
            )?;
            Ok(())
        }
        #[cfg(windows)]
        {
            crate::paths::relative::remove_special(self.as_file(), name)
        }
    }
}
