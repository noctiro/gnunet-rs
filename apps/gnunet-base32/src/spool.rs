//! Private unlinked decoded-data spool. Memory never grows with stdin size.
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
pub(super) struct Spool {
    directory: PathBuf,
    identity: Option<(u64, u64)>,
    file: Option<File>,
    file_identity: Option<(u64, u64)>,
    named: bool,
    removed: bool,
    cleanup_on_drop: bool,
}
impl Spool {
    pub fn create(owner: &mut Option<Self>) -> io::Result<()> {
        if owner.is_some() {
            return Err(io::Error::other("spool already owned"));
        }
        let root = std::env::temp_dir();
        if !root.is_absolute() || !fs::symlink_metadata(&root)?.is_dir() {
            return Err(io::Error::other(
                "temporary parent must be an existing absolute directory",
            ));
        }
        for _ in 0..32 {
            let serial = NEXT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
                .map_err(|_| io::Error::other("spool serial exhausted"))?;
            let directory = root.join(format!("gnunet-base32-{}-{serial}", std::process::id()));
            match DirBuilder::new().mode(0o700).create(&directory) {
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
                Ok(()) => {}
            }
            // Retain successful mkdir before fallible metadata; cleanup cannot
            // remove an unproven/replaced directory merely by its path string.
            *owner = Some(Self {
                directory,
                identity: None,
                file: None,
                file_identity: None,
                named: false,
                removed: false,
                cleanup_on_drop: true,
            });
            let spool = owner
                .as_mut()
                .ok_or_else(|| io::Error::other("spool owner lost"))?;
            let meta = fs::symlink_metadata(&spool.directory)?;
            if !meta.is_dir() || meta.mode() & 0o077 != 0 {
                return Err(io::Error::other("private spool directory changed"));
            }
            spool.identity = Some((meta.dev(), meta.ino()));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(spool.directory.join("data"))?;
            // No other descriptor to the data file is created or exposed.
            spool.file = Some(file);
            spool.named = true;
            let meta = spool
                .file
                .as_ref()
                .ok_or_else(|| io::Error::other("spool file lost"))?
                .metadata()?;
            if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
                return Err(io::Error::other("private spool file changed"));
            }
            spool.file_identity = Some((meta.dev(), meta.ino()));
            spool.check_directory()?;
            let observed = fs::symlink_metadata(spool.directory.join("data"))?;
            if (observed.dev(), observed.ino()) != (meta.dev(), meta.ino()) || !observed.is_file() {
                return Err(io::Error::other("spool pathname replaced"));
            }
            fs::remove_file(spool.directory.join("data"))?;
            spool.named = false;
            spool.check_directory()?;
            fs::remove_dir(&spool.directory)?;
            spool.identity = None;
            spool.removed = true;
            return Ok(());
        }
        Err(io::Error::other("private spool names unavailable"))
    }
    fn check_directory(&self) -> io::Result<()> {
        let identity = self
            .identity
            .ok_or_else(|| io::Error::other("original spool directory identity unconfirmed"))?;
        let meta = fs::symlink_metadata(&self.directory)?;
        if !meta.is_dir() || meta.mode() & 0o077 != 0 || (meta.dev(), meta.ino()) != identity {
            return Err(io::Error::other("original spool directory replaced"));
        }
        Ok(())
    }
    fn file(&mut self) -> io::Result<&mut File> {
        let identity = self
            .file_identity
            .ok_or_else(|| io::Error::other("spool file identity unconfirmed"))?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("spool file closed"))?;
        let meta = file.metadata()?;
        if !meta.is_file()
            || (meta.dev(), meta.ino()) != identity
            || meta.nlink() != u64::from(self.named)
        {
            return Err(io::Error::other("original spool file changed"));
        }
        Ok(file)
    }
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file()?.write(bytes)
    }
    pub fn rewind(&mut self) -> io::Result<()> {
        self.file()?.seek(SeekFrom::Start(0)).map(|_| ())
    }
    pub fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.file()?.read(bytes)
    }
    pub fn path(&self) -> PathBuf {
        self.directory.clone()
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.cleanup_on_drop = false;
        // The anonymous data object is released by its original File, never by
        // an untrusted pathname. Retain any unconfirmed named object on failure.
        self.file = None;
        if self.removed {
            return Ok(());
        }
        self.check_directory()?;
        if self.named {
            let identity = self
                .file_identity
                .ok_or_else(|| io::Error::other("named spool identity unconfirmed"))?;
            let meta = fs::symlink_metadata(self.directory.join("data"))?;
            if !meta.is_file() || meta.nlink() != 1 || (meta.dev(), meta.ino()) != identity {
                return Err(io::Error::other("named spool file replaced"));
            }
            fs::remove_file(self.directory.join("data"))?;
            self.named = false;
        }
        fs::remove_dir(&self.directory)?;
        self.identity = None;
        self.removed = true;
        Ok(())
    }
}
impl Drop for Spool {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _actual = self.close();
        }
    }
}
