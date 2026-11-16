//! Native private staging and no-clobber publication through original directories.
use crate::{Cause, budget::Budget};
use gnunet_native::DirectorySync;
use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, Seek},
    path::{Path, PathBuf},
};
mod namespace;
mod staging;
use namespace::Namespace;
use staging::{Cleanup, Staging};

pub(super) fn absent(path: &Path) -> Result<(), Cause> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "existing CA destination preserved",
        )
        .into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
#[derive(Debug)]
struct PublicationFailure {
    target: PathBuf,
    attempted: bool,
    published: bool,
    directory_sync: Option<DirectorySync>,
    original: Option<Cause>,
    cleanup: Cleanup,
}
impl fmt::Display for PublicationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CA publication to {}: attempted={}, published={}, directory_sync={:?}, original={:?}, cleanup={:?}",
            self.target.display(),
            self.attempted,
            self.published,
            self.directory_sync,
            self.original,
            self.cleanup
        )
    }
}
impl Error for PublicationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original.as_deref().or_else(|| {
            self.cleanup
                .remove
                .as_ref()
                .or(self.cleanup.close.as_ref())
                .map(|error| error as _)
        })
    }
}
pub(super) async fn publish(
    path: &Path,
    certificate: &str,
    key: &str,
    budget: &Budget,
) -> Result<DirectorySync, Cause> {
    let namespace = Namespace::select(path, budget).await?;
    namespace.absent()?;
    let mut staging = Staging::create(namespace, "private", budget).await?;
    let mut attempted = false;
    let mut published = false;
    let mut directory_sync = None;
    let result = async {
        staging.write(certificate.as_bytes(), budget).await?;
        staging.write(key.as_bytes(), budget).await?;
        budget.check().await?;
        staging.check()?;
        staging.file()?.sync_all()?;
        budget.check().await?;
        staging.check()?;
        staging.namespace.absent()?;
        attempted = true;
        staging.namespace.directory.link_file_from(
            &staging.namespace.directory,
            &staging.name,
            staging.file()?,
            &staging.namespace.name,
        )?;
        published = true;
        budget.check().await?;
        staging.check()?;
        staging.remove()?;
        budget.check().await?;
        staging.namespace.check()?;
        directory_sync = Some(staging.namespace.directory.sync()?);
        budget.check().await?;
        Ok::<(), Cause>(())
    }
    .await;
    let cleanup = staging.cleanup();
    if result.is_err() || !cleanup.successful() {
        return Err(Box::new(PublicationFailure {
            target: path.to_owned(),
            attempted,
            published,
            directory_sync,
            original: result.err(),
            cleanup,
        }));
    }
    directory_sync.ok_or_else(|| "CA publication has no directory barrier observation".into())
}
pub(super) struct PublicFile {
    staging: Staging,
}
impl PublicFile {
    pub(super) async fn new(
        target: &Path,
        certificate: &str,
        budget: &Budget,
    ) -> Result<Self, Cause> {
        let namespace = Namespace::select(target, budget).await?;
        let mut staging = Staging::create(namespace, "public", budget).await?;
        let result = async {
            staging.write(certificate.as_bytes(), budget).await?;
            staging.file_mut()?.rewind()?;
            budget.check().await
        }
        .await;
        if let Err(original) = result {
            let cleanup = staging.cleanup();
            return Err(Box::new(PublicationFailure {
                target: target.to_owned(),
                attempted: false,
                published: false,
                directory_sync: None,
                original: Some(original),
                cleanup,
            }));
        }
        Ok(Self { staging })
    }
    pub(super) fn input(&mut self) -> io::Result<File> {
        self.staging.check()?;
        self.staging.file_mut()?.rewind()?;
        self.staging.file()?.try_clone()
    }
    pub(super) fn finish(mut self) -> Result<(), Cause> {
        let cleanup = self.staging.cleanup();
        if cleanup.successful() {
            return Ok(());
        }
        Err(Box::new(PublicationFailure {
            target: self.staging.namespace.name.clone().into(),
            attempted: false,
            published: false,
            directory_sync: None,
            original: None,
            cleanup,
        }))
    }
}
