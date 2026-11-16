//! Private native fixture directories.
use std::{io, path::Path};
pub(crate) fn private_directory(path: &Path) -> io::Result<()> {
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    gnunet_native::filesystem::Directory::open(parent)?.create_private_directory(name)?;
    Ok(())
}
