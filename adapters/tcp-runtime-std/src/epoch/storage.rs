//! Native publication and exact original-object reconciliation for one frontier.
use super::{Failure, Outcome, Persisted, Stage, Store, failure, fence::Fence, staging::Candidate};
use gnunet_native::{
    DirectorySync,
    filesystem::{PrivateFileSnapshot, private_data_file_info, publication, validate_readonly},
};
use gnunet_tcp_replay_host::pairing::FRONTIER_BYTES;
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
    snapshot: PrivateFileSnapshot,
}
struct Readback {
    image: Persisted,
    snapshot: PrivateFileSnapshot,
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
fn check_absent(owner: &Fence) -> Result<(), Failure> {
    match owner.parent.entry_info(&owner.name) {
        Err(cause) if cause.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(cause) => Err(failure(Stage::Read, Outcome::Unknown, cause)),
        Ok(_) => Err(invalid(
            Stage::Read,
            "TCP frontier appeared before original initialization",
        )),
    }
}
fn read_original(owner: &Fence, file: &mut File) -> Result<Readback, Failure> {
    owner.check()?;
    let map = |cause| failure(Stage::Read, Outcome::Unknown, cause);
    validate_readonly(file).map_err(map)?;
    let before = private_data_file_info(file).map_err(map)?;
    if before.identity == owner.guard_id || before.bytes != FRONTIER_BYTES as u64 {
        return Err(invalid(
            Stage::Read,
            "original exact V2 TCP frontier is not bound",
        ));
    }
    if !owner.parent.same_file(&owner.name, file).map_err(map)? {
        return Err(invalid(
            Stage::Read,
            "TCP frontier no longer selects the original file",
        ));
    }
    file.seek(SeekFrom::Start(0)).map_err(map)?;
    let mut bytes = [0; FRONTIER_BYTES];
    file.read_exact(&mut bytes).map_err(map)?;
    let mut trailing = [0];
    let trailing_bytes = file.read(&mut trailing).map_err(map)?;
    if trailing_bytes != 0 {
        return Err(map(io::Error::other(format!(
            "original TCP frontier changed during read: unexpected_tail={trailing_bytes}, before={before:?}"
        ))));
    }
    let snapshot = PrivateFileSnapshot::new(before, &bytes)
        .confirm_read(&owner.parent, &owner.name, file)
        .map_err(map)?;
    owner.check()?;
    Ok(Readback {
        image: Persisted::decode(bytes).map_err(map)?,
        snapshot,
    })
}
impl Snapshot {
    fn from_readback(file: File, readback: Readback) -> Self {
        Self {
            image: readback.image,
            file,
            snapshot: readback.snapshot,
        }
    }
    fn check(&self, owner: &Fence) -> Result<(), Failure> {
        let map = |cause| failure(Stage::Read, Outcome::Unknown, cause);
        validate_readonly(&self.file).map_err(map)?;
        self.snapshot
            .verify(&owner.parent, &owner.name, &self.file)
            .map_err(map)
    }
    fn read_expected(&mut self, owner: &Fence) -> Result<PrivateFileSnapshot, Failure> {
        let observed = read_original(owner, &mut self.file)?;
        // The fixed V2 codec interprets every byte. Equal images have equal
        // original bytes, and this read used the pinned file at its own name.
        if observed.snapshot.initial().identity != self.snapshot.initial().identity
            || observed.image != self.image
        {
            return Err(invalid(
                Stage::Recovery,
                "restored TCP frontier differs from the last settled original",
            ));
        }
        Ok(observed.snapshot)
    }
    fn refresh(&mut self, owner: &Fence) -> Result<(), Failure> {
        if self.read_expected(owner)?.initial() != self.snapshot.initial() {
            let map = |cause| failure(Stage::Recovery, Outcome::Unknown, cause);
            publication::sync_original(&owner.parent, &owner.name, &self.file).map_err(map)?;
            owner.sync().map_err(map)?;
            self.snapshot = self.read_expected(owner)?;
        }
        Ok(())
    }
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
        match store.owner.parent.open_file(&store.owner.name) {
            Ok(mut file) => {
                let initial = read_original(&store.owner, &mut file)?;
                publication::sync_original(&store.owner.parent, &store.owner.name, &file)
                    .map_err(|cause| failure(Stage::Read, Outcome::Unknown, cause))?;
                store
                    .owner
                    .sync()
                    .map_err(|cause| failure(Stage::DirectorySync, Outcome::Unknown, cause))?;
                let readback = read_original(&store.owner, &mut file)?;
                if readback.image != initial.image
                    || readback.snapshot.initial().identity != initial.snapshot.initial().identity
                {
                    return Err(invalid(
                        Stage::Read,
                        "TCP frontier changed across startup synchronization",
                    ));
                }
                store.current = Some(Snapshot::from_readback(file, readback));
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
        if self.unknown.is_none() {
            match &self.current {
                Some(original) => original.check(&self.owner),
                None => check_absent(&self.owner),
            }
        } else {
            Ok(())
        }
    }
    /// Reconcile original publication and cleanup debt or refresh the held
    /// settled file after exact original-byte readback and synchronization.
    /// This grants no epoch, replay permit, timestamp or backend quiescence.
    pub fn reconcile(&mut self) -> Result<(), Failure> {
        if self.unknown.is_some() {
            return self.settle().map(|_| ());
        }
        self.retire_cleanup()?;
        match (self.fence(), &mut self.current) {
            (Ok(()), _) => Ok(()),
            (Err(_), Some(current)) => current.refresh(&self.owner),
            (Err(error), None) => Err(error),
        }
    }
    fn retire_cleanup(&mut self) -> Result<(), Failure> {
        self.owner.check()?;
        if let Some(mut original) = self.cleanup.take()
            && let Err(cause) = original.discard()
        {
            self.cleanup = Some(original);
            return Err(failure(Stage::Recovery, Outcome::NotCommitted, cause));
        }
        Ok(())
    }
    pub(super) fn settle(&mut self) -> Result<Settlement, Failure> {
        self.retire_cleanup()?;
        let Some(mut original) = self.unknown.take() else {
            self.fence()?;
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
                    publication::sync_original(&self.owner.parent, &self.owner.name, candidate)
                        .map_err(|cause| failure(Stage::Recovery, Outcome::Unknown, cause))?;
                }
                let file = original
                    .candidate
                    .file
                    .as_mut()
                    .ok_or_else(|| invalid(Stage::Recovery, "original candidate consumed"))?;
                let readback = read_original(&self.owner, file)?;
                if readback.image != original.image {
                    return Err(invalid(
                        Stage::Recovery,
                        "original TCP publication differs from its intent",
                    ));
                }
                return Ok(Some(readback));
            }
            // Only the still-bound predecessor and still-named original stage
            // can prove no publication. Equal bytes in a replacement cannot.
            if !self
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
            match self.current.as_mut() {
                Some(current) => current.refresh(&self.owner)?,
                None => check_absent(&self.owner)?,
            }
            original
                .candidate
                .discard()
                .map_err(|cause| failure(Stage::Recovery, Outcome::NotCommitted, cause))?;
            Ok(None)
        })();
        match result {
            Ok(Some(readback)) => {
                let file = original.candidate.file.take().ok_or_else(|| {
                    invalid(Stage::Recovery, "settled original TCP file consumed")
                })?;
                self.current = Some(Snapshot::from_readback(file, readback));
                Ok(Settlement::Published)
            }
            Ok(None) => Ok(Settlement::Unpublished),
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
            let prepared = publication::seal_retained(
                &candidate.owner.parent,
                &candidate.name,
                file,
                bytes.len() as u64,
            )
            .map_err(|error| {
                failure(
                    Stage::Write,
                    Outcome::NotCommitted,
                    io::Error::new(error.cause.kind(), error),
                )
            })?;
            self.fence()?;
            let observed = private_data_file_info(file)
                .map_err(|cause| failure(Stage::Write, Outcome::NotCommitted, cause))?;
            if observed != prepared {
                return Err(failure(
                    Stage::Write,
                    Outcome::NotCommitted,
                    io::Error::other(format!(
                        "original TCP stage changed before publication: prepared={prepared:?}, observed={observed:?}"
                    )),
                ));
            }
            Ok(())
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
