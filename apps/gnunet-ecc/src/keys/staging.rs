//! Streaming private key-file publication through the original native directory.
use super::namespace::{Namespace, observe};
use crate::{
    Failure,
    run::{Facts, Guard},
};
use gnunet_native::filesystem::{self, EntryInfo, FileInfo};
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
pub(crate) struct Staging {
    namespace: Namespace,
    name: OsString,
    file: Option<File>,
    original: Option<FileInfo>,
    present: bool,
    cleanup_attempted: bool,
    length: u64,
}
impl Staging {
    pub(super) fn create(target: &Path, owner: &mut Option<Self>) -> Result<(), Failure> {
        if owner.is_some() {
            return Err("ECC staging owner already exists".into());
        }
        let namespace = Namespace::select(target)?;
        namespace.directory.validate_namespace()?;
        let original = match namespace.directory.entry_info(&namespace.name) {
            Ok(EntryInfo::File(info)) if info.bytes % 32 == 0 => Some(info),
            Ok(_) => {
                return Err(
                    "ECC generation target must be absent or an empty/raw32 regular file".into(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        namespace.verify()?;
        for _ in 0..32 {
            let serial = NEXT
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| "ECC staging serial exhausted")?;
            let name = OsString::from(format!(".gnunet-ecc-{}-{serial}.tmp", std::process::id()));
            if name == namespace.name {
                continue;
            }
            match namespace.directory.create_private_file(&name) {
                Ok(file) => {
                    // Retain successful creation before any fallible observation.
                    *owner = Some(Self {
                        namespace,
                        name,
                        file: Some(file),
                        original,
                        present: true,
                        cleanup_attempted: false,
                        length: 0,
                    });
                    owner.as_ref().ok_or("missing ECC staging owner")?.check()?;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("ECC private sibling allocation exhausted".into())
    }
    fn file(&self) -> Result<&File, Failure> {
        self.file
            .as_ref()
            .ok_or_else(|| "ECC staging file retired".into())
    }
    fn check(&self) -> Result<(), Failure> {
        self.namespace.verify()?;
        self.namespace.directory.validate_namespace()?;
        let file = self.file()?;
        filesystem::validate_private_file(file)?;
        if observe(file)?.bytes != self.length
            || self.present && !self.namespace.directory.same_file(&self.name, file)?
        {
            return Err("original ECC staging file changed".into());
        }
        Ok(())
    }
    pub(super) async fn write(
        &mut self,
        seed: &[u8; 32],
        guard: &mut Guard,
        facts: &mut Facts,
    ) -> Result<(), Failure> {
        let mut at = 0;
        while at < seed.len() {
            guard.check().await?;
            self.check()?;
            guard.check().await?;
            match self
                .file
                .as_mut()
                .ok_or("ECC staging file retired")?
                .write(&seed[at..])
            {
                Ok(0) => {
                    return Err(
                        io::Error::new(io::ErrorKind::WriteZero, "zero ECC staging write").into(),
                    );
                }
                Ok(n) => {
                    at += n;
                    self.length = self
                        .length
                        .checked_add(n as u64)
                        .ok_or("ECC staging size overflow")?;
                    facts.staged_bytes = self.length;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
            guard.check().await?;
        }
        Ok(())
    }
    pub(super) async fn publish(
        &mut self,
        guard: &mut Guard,
        facts: &mut Facts,
    ) -> Result<(), Failure> {
        guard.check().await?;
        self.check()?;
        guard.check().await?;
        self.file()?.sync_all()?;
        guard.check().await?;
        self.check()?;
        match (
            self.original,
            self.namespace.directory.entry_info(&self.namespace.name),
        ) {
            (Some(old), Ok(EntryInfo::File(now))) if old == now => {}
            (None, Err(error)) if error.kind() == io::ErrorKind::NotFound => {}
            (_, Err(error)) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
            _ => return Err("ECC target changed before publication".into()),
        }
        guard.check().await?;
        // A native error can follow visible publication, including a failed
        // post-call identity check. Preserve admission before entering the call.
        facts.publication_attempted = true;
        if self.original.is_some() {
            self.namespace.directory.replace_file(
                &self.name,
                self.file()?,
                &self.namespace.name,
            )?;
            self.present = false;
            facts.replaced = true;
        } else {
            self.namespace.directory.link_file_from(
                &self.namespace.directory,
                &self.name,
                self.file()?,
                &self.namespace.name,
            )?;
        }
        facts.published = true;
        guard.check().await?;
        if self.present {
            self.check()?;
            self.namespace
                .directory
                .remove_file(&self.name, self.file()?)?;
            self.present = false;
        }
        guard.check().await?;
        self.namespace.verify()?;
        facts.directory_sync = Some(self.namespace.directory.sync()?);
        guard.check().await
    }
    /// Retire the original sibling and writer independently of cancellation.
    pub(crate) fn cleanup(&mut self) -> Result<(), Failure> {
        self.cleanup_attempted = true;
        let link = if self.present {
            (|| {
                // Cleanup retains the original directory even when its public
                // path moves. Looking up that path cannot select another root.
                self.namespace
                    .directory
                    .remove_file(&self.name, self.file()?)?;
                self.present = false;
                Ok::<_, Failure>(())
            })()
            .err()
        } else {
            None
        };
        let close = self
            .file
            .take()
            .and_then(|file| filesystem::close(file).err());
        if link.is_some() || close.is_some() {
            return Err(Box::new(CleanupFailure { link, close }));
        }
        Ok(())
    }
    pub(crate) fn retained_path(&self) -> Option<PathBuf> {
        self.present.then(|| self.namespace.path(&self.name))
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if !self.cleanup_attempted {
            let _cleanup = self.cleanup();
        }
    }
}
#[derive(Debug)]
struct CleanupFailure {
    link: Option<Failure>,
    close: Option<io::Error>,
}
impl std::fmt::Display for CleanupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ECC staging cleanup: link={:?}; independent writer close={:?}",
            self.link, self.close
        )
    }
}
impl std::error::Error for CleanupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.link
            .as_deref()
            .or_else(|| self.close.as_ref().map(|error| error as _))
    }
}

#[cfg(test)]
mod tests;
