use nix::{
    dir::{Dir, OwningIter},
    fcntl::{OFlag, openat},
    sys::stat::Mode,
};
use std::{ffi::OsString, fs::File, io, os::unix::ffi::OsStrExt};
/// Independent original-directory cursor. Entry order is native and may change;
/// callers bound collection and revalidate directory/child observations.
#[derive(Debug)]
pub struct Entries {
    iterator: OwningIter,
}
impl Entries {
    pub(crate) fn open(directory: &File) -> io::Result<Self> {
        let file = openat(
            directory,
            c".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        Ok(Self {
            iterator: Dir::from_fd(file)?.into_iter(),
        })
    }
}
impl Iterator for Entries {
    type Item = io::Result<OsString>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = match self.iterator.next()? {
                Ok(entry) => entry,
                Err(error) => return Some(Err(error.into())),
            };
            let name = entry.file_name().to_bytes();
            if matches!(name, b"." | b"..") {
                continue;
            }
            return Some(Ok(std::ffi::OsStr::from_bytes(name).to_owned()));
        }
    }
}
