//! Original configuration namespace, writer lease and publication fencing.
use super::worker::{Cause, Cleanup, Committed, Exposure, Failure, Job};
use gnunet_native::filesystem::{Directory, FileIdentity, validate_private_file};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::PathBuf,
    sync::Arc,
};
const LOCK: &str = ".gnunet-rest-configuration.lock";
pub(super) struct Target {
    parent: PathBuf,
    name: OsString,
    directory: Directory,
    lock: File,
    expected: Option<File>,
    pub(super) generation: u64,
    pub(super) blocked: Option<Arc<Failure>>,
}
impl Target {
    pub(super) fn open(path: PathBuf) -> io::Result<Self> {
        if !path.is_absolute()
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let parent = path
            .parent()
            .ok_or(io::ErrorKind::InvalidInput)?
            .to_path_buf();
        let name = path
            .file_name()
            .filter(|n| *n != OsStr::new(LOCK))
            .ok_or(io::ErrorKind::InvalidInput)?
            .to_owned();
        let directory = Directory::open(&parent)?;
        directory.validate_namespace()?;
        let lock = match directory.create_private_file(OsStr::new(LOCK)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                directory.open_file_for_update(OsStr::new(LOCK))?
            }
            Err(error) => return Err(error),
        };
        validate_private_file(&lock)?;
        lock.try_lock().map_err(io::Error::other)?;
        let expected = match directory.open_file(&name) {
            Ok(file) => {
                validate_private_file(&file)?;
                Some(file)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let target = Self {
            parent,
            name,
            directory,
            lock,
            expected,
            generation: 0,
            blocked: None,
        };
        target.fence()?;
        Ok(target)
    }
    fn namespace_fence(&self) -> io::Result<()> {
        let selected = Directory::open(&self.parent)?;
        selected.validate_namespace()?;
        if FileIdentity::of(selected.as_file())? != FileIdentity::of(self.directory.as_file())?
            || !self.directory.same_file(OsStr::new(LOCK), &self.lock)?
        {
            return Err(io::Error::other("original configuration namespace changed"));
        }
        validate_private_file(&self.lock)
    }
    fn fence(&self) -> io::Result<()> {
        self.namespace_fence()?;
        match &self.expected {
            Some(file) if self.directory.same_file(&self.name, file)? => {
                validate_private_file(file)
            }
            Some(_) => Err(io::Error::other("original configuration target changed")),
            None => match self.directory.entry_info(&self.name) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(error) => Err(error),
                Ok(_) => Err(io::Error::other("configuration target appeared")),
            },
        }
    }
    pub(super) fn commit(
        &mut self,
        job: Job,
        expected: u64,
        body: &[u8],
        configuration: &mut gnunet_config::Configuration,
        clock: &dyn gnunet_service_runtime::clock::RuntimeClock,
    ) -> Result<Committed, Arc<Failure>> {
        if let Some(failure) = &self.blocked {
            return Err(failure.clone());
        }
        let known = |stage, cause| {
            Arc::new(Failure {
                stage,
                cause: Cause::Io(cause),
                exposure: Exposure::NotPublished,
                cleanup: Cleanup::NotNeeded,
            })
        };
        if expected != self.generation {
            return Err(known(
                "generation",
                io::Error::other("original configuration generation is stale"),
            ));
        }
        let next = self
            .generation
            .checked_add(1)
            .ok_or_else(|| known("generation", io::ErrorKind::InvalidInput.into()))?;
        if tokio::time::Instant::now() >= job.hard {
            return Err(known("original-deadline", io::ErrorKind::TimedOut.into()));
        }
        let sample = clock.sample().map_err(|cause| {
            Arc::new(Failure {
                stage: "original-clock",
                cause: Cause::Clock(cause),
                exposure: Exposure::NotPublished,
                cleanup: Cleanup::NotNeeded,
            })
        })?;
        if sample.now.as_micros() >= job.until {
            return Err(known(
                "original-logical-deadline",
                io::ErrorKind::TimedOut.into(),
            ));
        }
        self.fence()
            .map_err(|cause| known("original-target-fence", cause))?;
        let result = configuration.write_serialized_in(&self.directory, &self.name, body, || {
            if tokio::time::Instant::now() >= job.hard {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if clock.sample().map_err(io::Error::other)?.now.as_micros() >= job.until {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.fence()
        });
        let published = match result {
            Ok(published) => published,
            Err(failure) => {
                let exposure = if failure.may_have_published {
                    Exposure::Unknown
                } else {
                    Exposure::NotPublished
                };
                let failure = Arc::new(Failure {
                    stage: failure.stage,
                    cause: Cause::Publication(failure),
                    exposure,
                    cleanup: Cleanup::Reported,
                });
                self.blocked = Some(failure.clone());
                return Err(failure);
            }
        };
        let (original, directory_sync) = published.into_parts();
        let finish = self.namespace_fence().and_then(|()| {
            if !self.directory.same_file(&self.name, &original)? {
                return Err(io::Error::other(
                    "original configuration publication changed",
                ));
            }
            Ok(())
        });
        if let Err(cause) = finish {
            let failure = Arc::new(Failure {
                stage: "post-publication-fence",
                cause: Cause::Io(cause),
                exposure: Exposure::Unknown,
                cleanup: Cleanup::Retired,
            });
            self.blocked = Some(failure.clone());
            return Err(failure);
        }
        self.expected = Some(original);
        self.generation = next;
        Ok(Committed {
            job,
            generation: next,
            directory_sync,
        })
    }
}
