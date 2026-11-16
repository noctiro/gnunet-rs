//! Recovery, original-object fences and recognized pending-file retirement.
use super::*;
use std::{ffi::OsStr, io, path::Path};

impl Store {
    /// Create a complete private namespace or reopen its exact marked directory.
    /// Parents must exist; existing unmarked/foreign directories are unchanged.
    pub fn open(
        namespace: Namespace,
        directory: impl AsRef<Path>,
        limits: Limits,
    ) -> Result<(Self, Loaded), Failure> {
        if limits.body_bytes == 0
            || limits.body_bytes > 64 * 1024 * 1024
            || limits.body_bytes.checked_add(HEADER).is_none()
        {
            return Err(failure("limits", Error::Capacity, None));
        }
        let opened = initialize::open(directory.as_ref(), namespace)?;
        let dir_id = FileIdentity::of(opened.directory.as_file())
            .map_err(|error| os("directory-identity", error))?;
        let lock_id = private_single_file_identity(opened.writer.as_file())
            .map_err(|error| os("writer-policy", error))?;
        let directory_sync = opened
            .directory
            .sync()
            .map_err(|error| os("writer-directory-sync", error))?;
        let mut store = Self {
            namespace,
            directory: opened.path,
            dir: opened.directory,
            dir_id,
            marker: opened.marker,
            lock: opened.writer,
            lock_id,
            image: None,
            pending: None,
            generation: 0,
            limits,
            failure: None,
        };
        store.namespace_fence()?;
        let mut recovered = 0;
        for entry in store
            .dir
            .entries()
            .map_err(|error| os("enumerate-store", error))?
        {
            let name = entry.map_err(|error| os("enumerate-store", error))?;
            if [namespace.mark(), namespace.lock(), namespace.image()]
                .iter()
                .any(|known| name == OsStr::new(known))
            {
                continue;
            }
            let recognized = name
                .to_str()
                .and_then(|name| name.strip_prefix(namespace.temporary()))
                .is_some_and(|suffix| {
                    suffix.len() == 16 && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
            if !recognized || recovered != 0 {
                return Err(failure("unknown-store-entry", Error::Storage, None));
            }
            let pending = HeldFile::qualify(
                store
                    .dir
                    .open_file(&name)
                    .map_err(|error| os("open-pending", error))?,
                "pending-policy",
            )?;
            store
                .dir
                .remove_file(&name, &pending.file)
                .map_err(|error| os("retire-pending", error))?;
            store
                .dir
                .sync()
                .map_err(|error| os("sync-retired-pending", error))?;
            recovered += 1;
        }
        let body = match store.dir.open_file_for_sync(OsStr::new(namespace.image())) {
            Ok(file) => {
                let mut held = HeldFile::qualify(file, "image-policy")?;
                let (generation, body) = image::read(&mut held.file, namespace, limits)?;
                held.file
                    .sync_all()
                    .map_err(|error| os("recovery-image-sync", error))?;
                store
                    .dir
                    .sync()
                    .map_err(|error| os("recovery-directory-sync", error))?;
                store.generation = generation;
                store.image = Some(held);
                body
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Zeroizing::new(Vec::new()),
            Err(error) => return Err(os("open-image", error)),
        };
        store.fence()?;
        let loaded = Loaded {
            namespace,
            created_directory: opened.created,
            generation: store.generation,
            body,
            recovered_temporaries: recovered,
            directory_sync,
        };
        Ok((store, loaded))
    }

    pub(super) fn namespace_fence(&self) -> Result<(), Failure> {
        let verify = || {
            namespace::guard(&self.dir, self.namespace)?;
            self.dir
                .validate_private()
                .map_err(|error| os("directory-fence-policy", error))?;
            let selected =
                Directory::open(&self.directory).map_err(|error| os("directory-fence", error))?;
            if FileIdentity::of(self.dir.as_file()).map_err(|error| os("directory-fence", error))?
                != self.dir_id
                || FileIdentity::of(selected.as_file())
                    .map_err(|error| os("directory-fence", error))?
                    != self.dir_id
            {
                return Err(failure("directory-fence-lost", Error::OutcomeUnknown, None));
            }
            self.marker.validate("marker-fence")?;
            if private_single_file_identity(self.lock.as_file())
                .map_err(|error| os("lock-fence", error))?
                != self.lock_id
                || !self
                    .dir
                    .same_file(OsStr::new(self.namespace.mark()), &self.marker.file)
                    .map_err(|error| os("marker-fence", error))?
                || !self
                    .dir
                    .same_file(OsStr::new(self.namespace.lock()), self.lock.as_file())
                    .map_err(|error| os("lock-fence", error))?
            {
                return Err(failure("namespace-fence-lost", Error::OutcomeUnknown, None));
            }
            Ok(())
        };
        verify().map_err(|mut error: Failure| {
            error.exposure = Exposure::Unknown;
            error
        })
    }

    pub(super) fn fence(&self) -> Result<(), Failure> {
        let verify = || {
            self.namespace_fence()?;
            let named = self.dir.entry_info(OsStr::new(self.namespace.image()));
            match (&self.image, named) {
                (None, Err(error)) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                (Some(original), Ok(_)) => {
                    original.validate("image-fence-policy")?;
                    if self
                        .dir
                        .same_file(OsStr::new(self.namespace.image()), &original.file)
                        .map_err(|error| os("image-fence", error))?
                    {
                        Ok(())
                    } else {
                        Err(failure("image-fence-lost", Error::OutcomeUnknown, None))
                    }
                }
                (_, Err(error)) => Err(os("image-fence", error)),
                _ => Err(failure("image-fence-lost", Error::OutcomeUnknown, None)),
            }
        };
        verify().map_err(|mut error: Failure| {
            error.exposure = Exposure::Unknown;
            error
        })
    }
}
