//! Short private fixture roots, shared by native local and TCP test cases.
use std::{ffi::OsStr, fs, io, path::PathBuf};

pub struct Directory(pub PathBuf);
impl Directory {
    pub fn new() -> io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce[..12])?;
        let name = format!("rb-{:024x}", u128::from_le_bytes(nonce));
        let parent = std::env::temp_dir();
        // macOS exposes /tmp through a symlink. Resolve that selected base before
        // opening the original directory; owned fixture descendants stay private.
        #[cfg(unix)]
        let parent = fs::canonicalize(parent)?;
        gnunet_native::filesystem::Directory::open(&parent)?
            .create_private_directory(OsStr::new(&name))?;
        Ok(Self(parent.join(name)))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
