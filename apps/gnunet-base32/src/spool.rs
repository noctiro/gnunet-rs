//! One anonymous private decoded-data file, retained through its original handle.
use gnunet_native::filesystem::{self, Directory, FileIdentity};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
const DATA: &str = "data";
pub(super) struct Spool {
    parent: Directory,
    directory: Option<Directory>,
    path: PathBuf,
    name: OsString,
    file: Option<File>,
    identity: Option<FileIdentity>,
    named: bool,
    removed: bool,
    cleanup_on_drop: bool,
}
#[derive(Debug)]
struct Cleanup {
    namespace: Option<io::Error>,
    close: Option<io::Error>,
}

#[derive(Debug)]
struct Operation {
    action: &'static str,
    source: io::Error,
}
impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.action, self.source)
    }
}
impl std::error::Error for Operation {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
fn at<T>(action: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|source| io::Error::new(source.kind(), Operation { action, source }))
}

impl std::fmt::Display for Cleanup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "spool namespace={:?}; original file close={:?}",
            self.namespace, self.close
        )
    }
}
impl std::error::Error for Cleanup {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.namespace
            .as_ref()
            .or(self.close.as_ref())
            .map(|error| error as _)
    }
}
impl Spool {
    pub fn create(owner: &mut Option<Self>) -> io::Result<()> {
        if owner.is_some() {
            return Err(io::Error::other("spool already owned"));
        }
        let root = std::env::temp_dir();
        if !root.is_absolute() {
            return Err(io::Error::other("temporary parent must be absolute"));
        }
        let parent = Directory::open(&root)?;
        for _ in 0..32 {
            let serial = NEXT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
                .map_err(|_| io::Error::other("spool serial exhausted"))?;
            let name = OsString::from(format!("gnunet-base32-{}-{serial}", std::process::id()));
            // Record naming intent before a native create can partially succeed.
            // An unconfirmed object is retained, never deleted by guessed path.
            *owner = Some(Self {
                parent: parent.duplicate()?,
                directory: None,
                path: root.join(&name),
                name,
                file: None,
                identity: None,
                named: false,
                removed: false,
                cleanup_on_drop: true,
            });
            let spool = owner
                .as_mut()
                .ok_or_else(|| io::Error::other("spool owner lost"))?;
            match spool.parent.create_private_directory(&spool.name) {
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    // No ownership was obtained over this existing entry.
                    spool.cleanup_on_drop = false;
                    *owner = None;
                    continue;
                }
                Err(error) => return Err(error),
                Ok(directory) => spool.directory = Some(directory),
            }
            let directory = spool
                .directory
                .as_ref()
                .ok_or_else(|| io::Error::other("spool directory lost"))?;
            at(
                "verify private spool directory",
                directory.validate_private(),
            )?;
            spool.file = Some(at(
                "create spool file",
                directory.create_private_file(OsStr::new(DATA)),
            )?);
            spool.named = true;
            let file = spool
                .file
                .as_ref()
                .ok_or_else(|| io::Error::other("spool file lost"))?;
            spool.identity = Some(at(
                "verify private spool file",
                filesystem::private_single_file_identity(file),
            )?);
            // Windows uses original-link POSIX disposition; Unix uses unlinkat
            // through the held private directory. No file path is reopened.
            at(
                "unlink spool file",
                directory.remove_file(OsStr::new(DATA), file),
            )?;
            spool.named = false;
            at(
                "remove spool directory",
                spool.parent.remove_directory(&spool.name, directory),
            )?;
            spool.removed = true;
            spool.directory = None;
            return Ok(());
        }
        Err(io::Error::other("private spool names unavailable"))
    }
    fn file(&mut self) -> io::Result<&mut File> {
        let identity = self
            .identity
            .ok_or_else(|| io::Error::other("spool file identity unconfirmed"))?;
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("spool file closed"))?;
        if FileIdentity::of(file)? != identity
            || filesystem::file_links(file)? != u64::from(self.named)
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
        self.path.clone()
    }
    fn remove(&mut self) -> io::Result<()> {
        if self.removed {
            return Ok(());
        }
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| io::Error::other("original spool directory unconfirmed"))?;
        at(
            "verify private spool directory",
            directory.validate_private(),
        )?;
        if self.named {
            let file = self
                .file
                .as_ref()
                .ok_or_else(|| io::Error::other("original named spool file lost"))?;
            if Some(FileIdentity::of(file)?) != self.identity {
                return Err(io::Error::other("original named spool file unconfirmed"));
            }
            at(
                "unlink spool file",
                directory.remove_file(OsStr::new(DATA), file),
            )?;
            self.named = false;
        }
        at(
            "remove spool directory",
            self.parent.remove_directory(&self.name, directory),
        )?;
        self.removed = true;
        self.directory = None;
        Ok(())
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.cleanup_on_drop = false;
        let namespace = self.remove().err();
        let close = self
            .file
            .take()
            .and_then(|file| filesystem::close(file).err());
        if namespace.is_some() || close.is_some() {
            Err(io::Error::other(Cleanup { namespace, close }))
        } else {
            Ok(())
        }
    }
}
impl Drop for Spool {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _actual = self.close();
        }
    }
}
