use std::{fs::File, io, path::Path};
pub(crate) fn open(path: &Path) -> io::Result<File> {
    gnunet_native::paths::open_regular_file(path)
}
