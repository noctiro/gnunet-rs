//! One bounded replacement, exact readback and sticky first-cause ownership.
use super::*;
use gnunet_native::filesystem::{private_data_file_info, publication};
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
            self.pending = Some(HeldFile::qualify_created(file, "pending-policy", |file| {
                self.dir
                    .remove_file(name, file)
                    .and_then(|()| self.dir.sync().map(|_| ()))
            })?);
            let pending = self
                .pending
                .as_mut()
                .ok_or_else(|| failure("pending-owner", Error::Storage, None))?;
            let header = image::write(&mut pending.file, self.namespace, next, &body)?;
            let image_bytes = (header.len() + body.len()) as u64;
            let prepared =
                publication::seal_retained(&self.dir, name, &mut pending.file, image_bytes)
                    .map_err(|error| {
                        let stage = if error.stage == "file-sync" {
                            "sync-pending"
                        } else {
                            error.stage
                        };
                        os(stage, error.cause)
                    })?;
            self.fence()?;
            let pending = self
                .pending
                .as_ref()
                .ok_or_else(|| failure("pending-owner", Error::Storage, None))?;
            let observed = private_data_file_info(&pending.file)
                .map_err(|error| os("pending-before-publish", error))?;
            if observed != prepared
                || observed.identity != pending.identity
                || !self
                    .dir
                    .same_file(name, &pending.file)
                    .map_err(|error| os("pending-before-publish", error))?
            {
                return Err(failure("pending-replaced", Error::Conflict, None));
            }
            let target = OsStr::new(self.namespace.image());
            exposed = true;
            self.dir
                .replace_file(name, &pending.file, target)
                .map_err(|error| os("publish-image", error))?;
            self.image = self.pending.take();
            let published = self
                .image
                .as_ref()
                .ok_or_else(|| failure("published-owner", Error::OutcomeUnknown, None))?;
            let directory_sync =
                publication::synchronize_published(&self.dir, target, &published.file)
                    .map_err(|error| os(error.stage, error.cause))?;
            self.fence()?;
            let published = self
                .image
                .as_mut()
                .ok_or_else(|| failure("published-owner", Error::OutcomeUnknown, None))?;
            image::verify(&self.dir, target, &mut published.file, &header, &body)?;
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
