//! Independent marker-qualified snapshots with one original writer lease.
//! Service codecs, business state and IPC stay outside this adapter.
mod commit;
mod failure;
mod image;
mod initialize;
mod namespace;
mod open;
#[cfg(test)]
mod tests;

pub use failure::{Exposure, Failure};
use failure::{failure, os};
pub use gnunet_native::DirectorySync;
use gnunet_native::filesystem::{
    Directory, ExclusiveFile, FileIdentity, private_single_file_identity,
};
use gnunet_types::Error;
pub use namespace::Namespace;
use std::{fs::File, io, mem::DropGuard, path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

const HEADER: usize = 88;
/// Maximum opaque canonical core snapshot body. No unbounded secret cache exists.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum serialized body, including all names/key bytes and core metadata.
    pub body_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            body_bytes: 4 * 1024 * 1024,
        }
    }
}
/// Only actual recovery creates this value. Its secret body has no Debug/Clone.
pub struct Loaded {
    namespace: Namespace,
    created_directory: bool,
    generation: u64,
    body: Zeroizing<Vec<u8>>,
    recovered_temporaries: usize,
    directory_sync: DirectorySync,
}
impl Loaded {
    /// Combined naming barriers observed for the store and its parent during recovery.
    #[must_use]
    pub const fn directory_sync(&self) -> DirectorySync {
        self.directory_sync
    }

    /// Whether this exact open created the private directory. A marked directory
    /// with no canonical image is not a newly created store.
    #[must_use]
    pub const fn created_directory(&self) -> bool {
        self.created_directory
    }
    /// Actual qualified source namespace; check before interpreting its body.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Actual stored committed generation;0 means no prior canonical image.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Metadata count of safely retired pre-publication owned temporaries.
    #[must_use]
    pub const fn recovered_temporaries(&self) -> usize {
        self.recovered_temporaries
    }
    /// Transfer secret snapshot ownership into the production pure service.
    #[must_use]
    pub fn into_body(self) -> Zeroizing<Vec<u8>> {
        self.body
    }
}
/// Actual successful original snapshot replacement. Constructor is private.
#[derive(Clone, Copy, Debug)]
pub struct Committed {
    namespace: Namespace,
    generation: u64,
    directory_sync: DirectorySync,
}
impl Committed {
    /// Actual native naming-barrier result, separate from file flush and readback.
    #[must_use]
    pub const fn directory_sync(self) -> DirectorySync {
        self.directory_sync
    }

    /// Namespace of the actual original snapshot publication.
    #[must_use]
    pub const fn namespace(self) -> Namespace {
        self.namespace
    }

    /// Generation that reached native replacement, file flush and exact readback.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Held original private single-link file, never an identity-only capability.
struct HeldFile {
    file: File,
    identity: FileIdentity,
}
impl HeldFile {
    fn qualify(file: File, stage: &'static str) -> Result<Self, Failure> {
        let identity = private_single_file_identity(&file).map_err(|error| os(stage, error))?;
        Ok(Self { file, identity })
    }
    fn qualify_created(
        file: File,
        stage: &'static str,
        rollback: impl FnOnce(&File) -> io::Result<()>,
    ) -> Result<Self, Failure> {
        let mut cleanup = None;
        let pending = DropGuard::new(file, |file| cleanup = rollback(&file).err());
        match private_single_file_identity(&pending) {
            Ok(identity) => Ok(Self {
                file: DropGuard::dismiss(pending),
                identity,
            }),
            Err(cause) => {
                drop(pending);
                let mut failure = os(stage, cause);
                failure.cleanup = cleanup;
                Err(failure)
            }
        }
    }
    fn validate(&self, stage: &'static str) -> Result<(), Failure> {
        if private_single_file_identity(&self.file).map_err(|error| os(stage, error))?
            != self.identity
        {
            return Err(failure(stage, Error::OutcomeUnknown, None));
        }
        Ok(())
    }
}
/// Qualified namespace with one native exclusive writer. Original handles fence
/// directory, marker, lock and canonical image. No long-lived secret cache exists.
pub struct Store {
    namespace: Namespace,
    directory: PathBuf,
    dir: Directory,
    dir_id: FileIdentity,
    marker: HeldFile,
    lock: ExclusiveFile,
    lock_id: FileIdentity,
    image: Option<HeldFile>,
    pending: Option<HeldFile>,
    generation: u64,
    limits: Limits,
    failure: Option<Arc<Failure>>,
}
impl Store {
    /// Original selected namespace; immutable for this writer's lifetime.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }
    /// Actual committed generation, never an admitted-write count.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Exact retained first failure, shared with the completion owner.
    #[must_use]
    pub fn failure(&self) -> Option<&Arc<Failure>> {
        self.failure.as_ref()
    }
}
