use nix::{
    fcntl::{OFlag, open as native_open},
    sys::stat::Mode,
};
use std::{fs::File, io, path::Path};
pub(crate) fn open(path: &Path) -> io::Result<File> {
    let file = File::from(native_open(
        path,
        OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?);
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FS input must be a regular file",
        ));
    }
    Ok(file)
}
