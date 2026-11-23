//! Ordinary file admission for caller-configured paths.
use std::{fs::File, io, path::Path};

/// Open an ordinary read-only file and qualify the original handle.
///
/// Returns `Ok(None)` when the path or handle is outside the regular file
/// policy. On Unix the open cannot wait for the writer of a named pipe.
/// Ordinary native metadata and reads can still block.
///
/// # Errors
///
/// Preserves operating system errors when the file cannot be opened or inspected.
pub fn open_regular(path: &Path) -> io::Result<Option<File>> {
    #[cfg(unix)]
    {
        use nix::{
            fcntl::{OFlag, open},
            sys::stat::Mode,
        };
        let file = File::from(
            open(
                path,
                OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .map_err(io::Error::from)?,
        );
        Ok(file.metadata()?.is_file().then_some(file))
    }
    #[cfg(windows)]
    {
        match crate::paths::open_regular_file(path) {
            // The Windows path and handle policy uses synthetic InvalidInput;
            // leave any identically classified native error intact.
            Err(error)
                if error.kind() == io::ErrorKind::InvalidInput
                    && error.raw_os_error().is_none() =>
            {
                Ok(None)
            }
            result => result.map(Some),
        }
    }
}
