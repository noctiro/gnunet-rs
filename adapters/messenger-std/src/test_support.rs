//! Temporary local namespaces shared by native Messenger component fixtures.
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub(crate) struct Directory(pub(crate) PathBuf);
impl Directory {
    pub(crate) fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "msg-host-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        #[cfg(unix)]
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        #[cfg(windows)]
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
