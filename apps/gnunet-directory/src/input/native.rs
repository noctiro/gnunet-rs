//! Public file links may resolve; every read still checks the original native object.
use gnunet_native::filesystem::FileInfo;
use std::{fs::File, io, path::Path};

pub(super) fn open(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt};
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
    }
    #[cfg(windows)]
    {
        gnunet_native::paths::open_regular_file(path)
    }
}

pub(super) fn named(path: &Path) -> io::Result<FileInfo> {
    #[cfg(unix)]
    {
        use gnunet_native::filesystem::{FileIdentity, FileTimes};
        let meta = std::fs::metadata(path)?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "regular directory input required",
            ));
        }
        Ok(FileInfo {
            identity: FileIdentity::from_metadata(&meta),
            bytes: meta.len(),
            times: FileTimes::from_metadata(&meta),
        })
    }
    #[cfg(windows)]
    {
        super::observe(&open(path)?)
    }
}
