//! Snapshot publication across the native Windows directory rename.
use super::*;
use gnunet_native::filesystem::{DirectoryClaim, close};

pub(super) fn claim<'a>(
    parent: &'a Directory,
    name: &OsStr,
    original: &'a Directory,
) -> Result<DirectoryClaim<'a>, Failure> {
    parent.claim_directory(name, original).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            failure("initialization-claim", Error::Conflict, Some(error))
        } else {
            os("initialization-claim", error)
        }
    })
}

impl Stage {
    pub(super) fn publish(
        &mut self,
        parent: &Directory,
        target: &OsStr,
        namespace: Namespace,
        attempted: &mut bool,
    ) -> Result<bool, Failure> {
        // NTFS cannot rename a directory with open descendants. The original
        // directory link admits one initializer until the child lock is held.
        let claim = claim(parent, OsStr::new(&self.name), &self.directory)?;
        let writer = self
            .writer
            .as_ref()
            .ok_or_else(|| failure("writer-owner", Error::Storage, None))?;
        let writer_id = private_single_file_identity(writer.as_file())
            .map_err(|error| os("staging-writer-policy", error))?;
        writer
            .as_file()
            .unlock()
            .map_err(|error| os("staging-writer-unlock", error))?;
        let marker = self
            .marker
            .take()
            .ok_or_else(|| failure("marker-owner", Error::Storage, None))?;
        let marker_id = marker.identity;
        let marker_close = close(marker.file);
        let writer_close = self.writer.take().map_or(Ok(()), ExclusiveFile::close);

        let install = marker_close
            .and(writer_close)
            .map_err(|error| os("close-staged-child", error))
            .and_then(|()| {
                *attempted = true;
                publication_result(claim.publish(target), attempted)
            });

        // Leave uncertain publication for a later opener. After a collision
        // reopen only the original children for retirement of the stage.
        let reopened = if !*attempted || install.is_ok() {
            reopen_children(
                &self.directory,
                namespace,
                marker_id,
                writer_id,
                &mut self.marker,
                &mut self.writer,
            )
        } else {
            Ok(())
        };
        match (install, reopened) {
            (Ok(published), Ok(())) => Ok(published),
            (Ok(_), Err(error)) => Err(error),
            (Err(mut error), reopened) => {
                error.cleanup = reopened.err().map(io::Error::other);
                Err(error)
            }
        }
    }
}

fn reopen_children(
    directory: &Directory,
    namespace: Namespace,
    marker_id: FileIdentity,
    writer_id: FileIdentity,
    marker: &mut Option<HeldFile>,
    writer: &mut Option<ExclusiveFile>,
) -> Result<(), Failure> {
    let actual = HeldFile::qualify(
        directory
            .open_file(OsStr::new(namespace.mark()))
            .map_err(|error| os("reopen-marker", error))?,
        "marker-policy",
    )?;
    if actual.identity != marker_id {
        return Err(failure(
            "staging-marker-replaced",
            Error::OutcomeUnknown,
            None,
        ));
    }
    *marker = Some(actual);
    let file = directory
        .open_file_for_update(OsStr::new(namespace.lock()))
        .map_err(|error| os("reopen-writer", error))?;
    if private_single_file_identity(&file).map_err(|error| os("writer-policy", error))? != writer_id
    {
        return Err(failure(
            "staging-writer-replaced",
            Error::OutcomeUnknown,
            None,
        ));
    }
    *writer = Some(ExclusiveFile::try_lock(file).map_err(writer_lock_error)?);
    Ok(())
}
