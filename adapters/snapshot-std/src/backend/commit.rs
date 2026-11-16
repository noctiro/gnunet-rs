//! One bounded replacement, exact readback and sticky first-cause ownership.
use super::*;
use std::ffi::OsStr;

impl Store {
    /// Atomically publish the bounded owned core snapshot. Success requires the
    /// original file flush and exact readback; directory barrier availability is
    /// explicit in the receipt. Publication ambiguity permanently fences this
    /// writer. Reopen under a new exclusive lease to recover actual disk bytes.
    pub fn commit(
        &mut self,
        expected: u64,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Committed, Arc<Failure>> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if expected != self.generation || body.len() > self.limits.body_bytes {
            return Err(Arc::new(failure(
                "commit-precondition",
                Error::InvalidInput,
                None,
            )));
        }
        let next = expected
            .checked_add(1)
            .ok_or_else(|| Arc::new(failure("generation", Error::Overflow, None)))?;
        let name = format!("{}{next:016x}", self.namespace.temporary());
        let name = OsStr::new(&name);
        let mut exposed = false;
        let result = (|| {
            self.fence()?;
            let file = self
                .dir
                .create_private_file(name)
                .map_err(|error| os("create-pending", error))?;
            self.pending = Some(HeldFile::qualify(file, "pending-policy")?);
            let pending = self
                .pending
                .as_mut()
                .ok_or_else(|| failure("pending-owner", Error::Storage, None))?;
            image::write(&mut pending.file, self.namespace, next, &body)?;
            pending
                .file
                .sync_all()
                .map_err(|error| os("sync-pending", error))?;
            self.fence()?;
            let pending = self
                .pending
                .as_ref()
                .ok_or_else(|| failure("pending-owner", Error::Storage, None))?;
            pending.validate("pending-before-publish")?;
            if !self
                .dir
                .same_file(name, &pending.file)
                .map_err(|error| os("pending-before-publish", error))?
            {
                return Err(failure("pending-replaced", Error::Conflict, None));
            }
            exposed = true;
            self.dir
                .replace_file(name, &pending.file, OsStr::new(self.namespace.image()))
                .map_err(|error| os("publish-image", error))?;
            self.image = self.pending.take();
            let published = self
                .image
                .as_ref()
                .ok_or_else(|| failure("published-owner", Error::OutcomeUnknown, None))?;
            let directory_sync = self
                .dir
                .sync()
                .map_err(|error| os("sync-published-directory", error))?;
            if directory_sync == DirectorySync::Unavailable {
                // Flush the actual renamed file on Windows. Unix already
                // flushed its data before rename and completed its directory
                // barrier, so a second file fsync would add no required fact.
                published
                    .file
                    .sync_all()
                    .map_err(|error| os("sync-published-file", error))?;
            }
            self.fence()?;
            let mut check = HeldFile::qualify(
                self.dir
                    .open_file(OsStr::new(self.namespace.image()))
                    .map_err(|error| os("readback-open", error))?,
                "readback-policy",
            )?;
            if check.identity != published.identity {
                return Err(failure("readback-replaced", Error::Conflict, None));
            }
            let (generation, check_body) =
                image::read(&mut check.file, self.namespace, self.limits)?;
            if generation != next || check_body.as_slice() != body.as_slice() {
                return Err(failure("readback-mismatch", Error::Storage, None));
            }
            self.fence()?;
            Ok(directory_sync)
        })();
        match result {
            Ok(directory_sync) => {
                self.generation = next;
                Ok(Committed {
                    namespace: self.namespace,
                    generation: next,
                    directory_sync,
                })
            }
            Err(mut error) => {
                if exposed || error.reason == Error::OutcomeUnknown {
                    error.exposure = Exposure::Unknown;
                }
                if !exposed && let Some(pending) = &self.pending {
                    let cleanup = self
                        .dir
                        .remove_file(name, &pending.file)
                        .and_then(|()| self.dir.sync().map(|_| ()));
                    if cleanup.is_ok() {
                        self.pending = None;
                    }
                    error.cleanup = cleanup.err();
                }
                let error = Arc::new(error);
                self.failure = Some(error.clone());
                Err(error)
            }
        }
    }
}
