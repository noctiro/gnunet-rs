//! Create-new staging and no-clobber publication; an existing CA is never read.
use crate::{Cause, budget::Budget};
use std::{
    error::Error,
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Seek, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

pub(super) fn absent(path: &Path) -> Result<(), Cause> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "existing CA preserved at {}; explicitly choose a new CA path to rotate it",
                path.display()
            ),
        )
        .into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}
fn temporary(directory: &Path, kind: &str, budget: &Budget) -> Result<(PathBuf, File), Cause> {
    for serial in 0..128u16 {
        budget.check()?;
        let path = directory.join(format!(
            ".gnunet-gns-ca-{kind}-{}-{serial}.tmp",
            std::process::id()
        ));
        match OpenOptions::new()
            .write(true)
            .read(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "CA staging-name capacity reached",
    )
    .into())
}
#[derive(Debug)]
struct PublicationFailure {
    target: PathBuf,
    temporary: PathBuf,
    published: bool,
    original: Option<Cause>,
    cleanup: Option<io::Error>,
}
impl fmt::Display for PublicationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CA publication to {} (published={}, staging={}): original={:?}, cleanup={:?}",
            self.target.display(),
            self.published,
            self.temporary.display(),
            self.original,
            self.cleanup
        )
    }
}
impl Error for PublicationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.cleanup.as_ref().map(|error| error as _))
    }
}
pub(super) fn publish(
    path: &Path,
    certificate: &str,
    key: &str,
    budget: &Budget,
) -> Result<(), Cause> {
    budget.check()?;
    absent(path)?;
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent(path))?;
    budget.check()?;
    let (staging, mut file) = temporary(parent(path), "private", budget)?;
    let mut published = false;
    let result = (|| -> Result<(), Cause> {
        file.write_all(certificate.as_bytes())?;
        budget.check()?;
        file.write_all(key.as_bytes())?;
        budget.check()?;
        file.sync_all()?;
        budget.check()?;
        // Same-directory hard-link publication is atomic and refuses every
        // existing destination, including a symlink. Never replace by rename.
        fs::hard_link(&staging, path)?;
        published = true;
        budget.check()?;
        File::open(parent(path))?.sync_all()?;
        Ok(())
    })();
    drop(file);
    // Cleanup retains its original cause even after a successful publication.
    let cleanup = fs::remove_file(&staging).err();
    match (result, cleanup) {
        (Ok(()), None) => Ok(()),
        (original, cleanup) => Err(Box::new(PublicationFailure {
            target: path.to_owned(),
            temporary: staging,
            published,
            original: original.err(),
            cleanup,
        })),
    }
}

pub(super) struct PublicFile {
    path: Option<PathBuf>,
    file: File,
}
impl PublicFile {
    pub(super) fn new(target: &Path, certificate: &str, budget: &Budget) -> Result<Self, Cause> {
        let (path, mut file) = temporary(parent(target), "public", budget)?;
        let result = (|| -> Result<(), Cause> {
            file.write_all(certificate.as_bytes())?;
            file.flush()?;
            file.rewind()?;
            budget.check()?;
            Ok(())
        })();
        if let Err(error) = result {
            drop(file);
            let cleanup = fs::remove_file(&path).err();
            return Err(Box::new(PublicationFailure {
                target: target.to_owned(),
                temporary: path,
                published: true,
                original: Some(error),
                cleanup,
            }));
        }
        Ok(Self {
            path: Some(path),
            file,
        })
    }
    pub(super) fn input(&mut self) -> io::Result<File> {
        self.file.rewind()?;
        self.file.try_clone()
    }
    pub(super) fn finish(mut self) -> io::Result<()> {
        let path = self
            .path
            .take()
            .ok_or_else(|| io::Error::other("public staging path already retired"))?;
        fs::remove_file(path)
    }
}
impl Drop for PublicFile {
    fn drop(&mut self) {
        // Normal paths use finish() and preserve its result. This fallback
        // releases only this original public staging path after unwinding.
        if let Some(path) = self.path.take() {
            let _cleanup = fs::remove_file(path);
        }
    }
}
