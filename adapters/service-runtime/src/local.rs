//! Native AF_UNIX stream owners. Byte framing and peer admission remain separate.
#[cfg(unix)]
pub use tokio::net::{UnixListener as Listener, UnixStream as Stream};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use gnunet_native::local_socket::Address;
#[cfg(windows)]
pub use windows::{Listener, Stream};

use gnunet_native::{filesystem::Directory, os_bytes};
use std::{
    io,
    path::{Component, Path},
};

/// Qualify distinct literal endpoints under one existing private IPC directory
/// and retain its original directory handle. The caller keeps the namespace
/// stable until its endpoint owners have retired.
pub fn qualify_private_endpoints<'a>(
    paths: impl Iterator<Item = &'a Path> + Clone,
) -> io::Result<Directory> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected distinct literal endpoints in one absolute private IPC directory",
        )
    };
    let directory = paths
        .clone()
        .next()
        .and_then(Path::parent)
        .ok_or_else(invalid)?;
    if !directory.is_absolute()
        || directory
            .components()
            .any(|part| part == Component::ParentDir)
    {
        return Err(invalid());
    }
    for (index, path) in paths.clone().enumerate() {
        if path.parent() != Some(directory)
            || path.file_name().is_none()
            || paths.clone().take(index).any(|earlier| earlier == path)
            || os_bytes::encode(path.as_os_str())
                .iter()
                .any(|byte| matches!(byte, 0 | b'$'))
            || crate::network::shorten_unixpath(path)? != path
        {
            return Err(invalid());
        }
    }
    let owner = Directory::open(directory)?;
    owner.validate_private()?;
    Ok(owner)
}
