//! Native publication and exact original-object reconciliation for one frontier.
use super::{Failure, Outcome, Persisted, Stage, Store, failure, fence::Fence, staging::Candidate};
use gnunet_native::{
    DirectorySync,
    filesystem::{EntryInfo, file_info, private_single_file_identity},
};
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    rc::Rc,
    sync::Arc,
};
pub(super) struct Snapshot {
    pub image: Persisted,
    pub file: File,
}
pub(super) struct Pending {
    image: Persisted,
    candidate: Candidate,
}
pub(super) enum Settlement {
    Idle,
    Published,
    Unpublished,
}
fn invalid(stage: Stage, why: &'static str) -> Failure {
    failure(stage, Outcome::Unknown, io::Error::other(why))
}
fn read_original(owner: &Fence, file: &mut File) -> Result<Persisted, Failure> {
    owner.check()?;
    let map = |cause| failure(Stage::Read, Outcome::Unknown, cause);
    let id = private_single_file_identity(file).map_err(map)?;
    let EntryInfo::File(before) = file_info(file).map_err(map)? else {
        return Err(invalid(Stage::Read, "ordinary TCP frontier required"));
    };
    if id == owner.guard_id
        || before.bytes != 89
        || !owner.parent.same_file(&owner.name, file).map_err(map)?
    {
        return Err(invalid(
            Stage::Read,
            "original exact V2 TCP frontier is not bound",
        ));
    }
    file.seek(SeekFrom::Start(0)).map_err(map)?;
    let mut bytes = [0; 89];
    file.read_exact(&mut bytes).map_err(map)?;
    let mut trailing = [0];
    if file.read(&mut trailing).map_err(map)? != 0
        || file_info(file).map_err(map)? != EntryInfo::File(before)
        || private_single_file_identity(file).map_err(map)? != id
        || !owner.parent.same_file(&owner.name, file).map_err(map)?
    {
        return Err(invalid(
            Stage::Read,
            "original TCP frontier changed during read",
        ));
    }
    owner.check()?;
    Persisted::decode(bytes).map_err(map)
}
impl Store {
    /// Hold the original native writer fence and exact V2 file. Missing state
    /// remains absent; pairing with an existing ledger never initializes it anew.
    pub fn open(path: PathBuf) -> Result<Self, Failure> {
        let owner = Rc::new(Fence::open(&path)?);
        let mut store = Self {
            owner,
            current: None,
            cleanup: None,
            brand: Arc::new(()),
            serial: 0,
            active: None,
            unknown: None,
            catalog: None,
        };
        match store.owner.parent.open_file_for_sync(&store.owner.name) {
            Ok(mut file) => {
                let initial = read_original(&store.owner, &mut file)?;
                file.sync_all()
                    .map_err(|cause| failure(Stage::Read, Outcome::Unknown, cause))?;
                store
                    .owner
                    .sync()
                    .map_err(|cause| failure(Stage::DirectorySync, Outcome::Unknown, cause))?;
                let image = read_original(&store.owner, &mut file)?;
                if image != initial {
                    return Err(invalid(
                        Stage::Read,
                        "TCP frontier changed across startup synchronization",
                    ));
                }
                store.current = Some(Snapshot { image, file });
            }
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => {}
            Err(cause) => return Err(failure(Stage::Read, Outcome::NotCommitted, cause)),
        }
        store.fence()?;
        Ok(store)
    }
    /// Actual last native directory barrier capability. Unavailable is not a
    /// crash-persistence guarantee, a replay floor, or an epoch capability.
    pub fn directory_sync(&self) -> DirectorySync {
        self.owner.barrier.get()
    }
    pub(super) fn committed(&self) -> Option<Persisted> {
        self.current.as_ref().map(|original| original.image)
    }
    pub(super) fn fence(&self) -> Result<(), Failure> {
        self.owner.check()?;
        if self.cleanup.is_some() {
            return Err(failure(
                Stage::Recovery,
                Outcome::NotCommitted,
                io::Error::other("original TCP stage cleanup remains owned"),
            ));
        }
        if self.unknown.is_none()
            && let Some(original) = &self.current
        {
            private_single_file_identity(&original.file)
                .map_err(|cause| failure(Stage::Read, Outcome::Unknown, cause))?;
            if !self
                .owner
                .parent
                .same_file(&self.owner.name, &original.file)
                .map_err(|cause| failure(Stage::Read, Outcome::Unknown, cause))?
            {
                return Err(invalid(
                    Stage::Read,
                    "settled TCP frontier identity changed",
                ));
            }
        }
        Ok(())
    }
    /// Reconcile only this owner's original publication and cleanup debt. This
    /// creates no epoch, replay permit, timestamp or backend-quiescence proof.
    pub fn reconcile(&mut self) -> Result<(), Failure> {
        self.settle().map(|_| ())
    }
    pub(super) fn settle(&mut self) -> Result<Settlement, Failure> {
        self.owner.check()?;
        if let Some(mut original) = self.cleanup.take()
            && let Err(cause) = original.discard()
        {
            self.cleanup = Some(original);
            return Err(failure(Stage::Recovery, Outcome::NotCommitted, cause));
        }
        self.fence()?;
        let Some(mut original) = self.unknown.take() else {
            return Ok(Settlement::Idle);
        };
        let result = (|| {
            let barrier = self
                .owner
                .sync()
                .map_err(|cause| failure(Stage::Recovery, Outcome::Unknown, cause))?;
            let candidate = original
                .candidate
                .original()
                .map_err(|cause| failure(Stage::Recovery, Outcome::Unknown, cause))?;
            let published = match self.owner.parent.same_file(&self.owner.name, candidate) {
                Ok(published) => published,
                Err(cause) if cause.kind() == io::ErrorKind::NotFound => false,
                Err(cause) => return Err(failure(Stage::Recovery, Outcome::Unknown, cause)),
            };
            if published {
                if barrier == DirectorySync::Unavailable {
                    candidate
                        .sync_all()
                        .map_err(|cause| failure(Stage::Recovery, Outcome::Unknown, cause))?;
                }
                let file = original
                    .candidate
                    .file
                    .as_mut()
                    .ok_or_else(|| invalid(Stage::Recovery, "original candidate consumed"))?;
                if read_original(&self.owner, file)? != original.image {
                    return Err(invalid(
                        Stage::Recovery,
                        "original TCP publication differs from its intent",
                    ));
                }
                return Ok(true);
            }
            // Only the still-bound predecessor and still-named original stage
            // can prove no publication. Equal bytes in a replacement cannot.
            let previous = if let Some(current) = self.current.as_mut() {
                read_original(&self.owner, &mut current.file)? == current.image
            } else {
                match self.owner.parent.entry_info(&self.owner.name) {
                    Err(cause) if cause.kind() == io::ErrorKind::NotFound => true,
                    Err(cause) => return Err(failure(Stage::Recovery, Outcome::Unknown, cause)),
                    Ok(_) => false,
                }
            };
            if !previous
                || !self
                    .owner
                    .parent
                    .same_file(
                        &original.candidate.name,
                        original
                            .candidate
                            .original()
                            .map_err(|cause| failure(Stage::Recovery, Outcome::Unknown, cause))?,
                    )
                    .map_err(|cause| failure(Stage::Recovery, Outcome::Unknown, cause))?
            {
                return Err(invalid(
                    Stage::Recovery,
                    "original TCP publication outcome unresolved",
                ));
            }
            original
                .candidate
                .discard()
                .map_err(|cause| failure(Stage::Recovery, Outcome::NotCommitted, cause))?;
            Ok(false)
        })();
        match result {
            Ok(true) => {
                let file = original.candidate.file.take().ok_or_else(|| {
                    invalid(Stage::Recovery, "settled original TCP file consumed")
                })?;
                self.current = Some(Snapshot {
                    image: original.image,
                    file,
                });
                Ok(Settlement::Published)
            }
            Ok(false) => Ok(Settlement::Unpublished),
            Err(error) => {
                self.unknown = Some(original);
                Err(error)
            }
        }
    }
    pub(super) fn update_bound(
        &mut self,
        image: Persisted,
        after: impl FnOnce(),
    ) -> Result<(), Failure> {
        self.fence()?;
        if self.unknown.is_some() {
            return Err(invalid(
                Stage::Recovery,
                "original TCP frontier commit unresolved",
            ));
        }
        let mut candidate = Candidate::new(self.owner.clone())?;
        let prepared = (|| {
            let file = candidate
                .file
                .as_mut()
                .ok_or_else(|| invalid(Stage::Write, "original TCP stage consumed"))?;
            let bytes = image.bytes();
            let mut at = 0;
            while at < bytes.len() {
                let count = file
                    .write(&bytes[at..])
                    .map_err(|cause| failure(Stage::Write, Outcome::NotCommitted, cause))?;
                if count == 0 {
                    return Err(failure(
                        Stage::Write,
                        Outcome::NotCommitted,
                        io::ErrorKind::WriteZero.into(),
                    ));
                }
                at += count;
            }
            file.sync_all()
                .map_err(|cause| failure(Stage::Write, Outcome::NotCommitted, cause))?;
            self.fence()
        })();
        if let Err(mut error) = prepared {
            if let Err(cleanup) = candidate.discard() {
                error.cleanup = Some(cleanup);
                self.cleanup = Some(candidate);
            }
            return Err(error);
        }
        let publication = candidate.publish();
        self.unknown = Some(Pending { image, candidate });
        publication.map_err(|cause| failure(Stage::Write, Outcome::Unknown, cause))?;
        after();
        match self.settle()? {
            Settlement::Published => Ok(()),
            Settlement::Idle | Settlement::Unpublished => Err(failure(
                Stage::Write,
                Outcome::NotCommitted,
                io::Error::other("original TCP frontier was not published"),
            )),
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
