//! Native raw8 proof persistence, original-object fencing and explicit recovery.
mod namespace;
use gnunet_native::{
    DirectorySync,
    filesystem::{EntryInfo, file_info},
};
use namespace::Namespace;
use std::{
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};
/// Exact native stage; write success alone is not a durability receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Original namespace and writer-lock qualification.
    Fence,
    /// Exact raw8 read.
    Read,
    /// Private staging-file creation.
    Create,
    /// Original staging bytes written.
    Write,
    /// Original staging file synchronized.
    FileSync,
    /// Original publication request.
    Rename,
    /// Naming barrier and original namespace binding.
    DirectorySync,
    /// Reconciliation of an original uncertain publication.
    Recovery,
}
/// Publication certainty, independently of native error classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// No proof publication was attempted.
    NotCommitted,
    /// Publication may have occurred; no new write may replace this obligation.
    Unknown,
}
/// Original native failure with any independent owned-staging cleanup failure.
#[derive(Debug)]
pub struct Error {
    /// Failed native stage.
    pub stage: Stage,
    /// Original publication certainty.
    pub outcome: Outcome,
    /// Original OS failure.
    pub cause: io::Error,
    /// Independent cleanup failure; never replaces the original cause.
    pub cleanup: Option<io::Error>,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NSE proof {:?}/{:?}: {}; staging cleanup={:?}",
            self.stage, self.outcome, self.cause, self.cleanup
        )
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
fn error(stage: Stage, outcome: Outcome, cause: io::Error) -> Error {
    Error {
        stage,
        outcome,
        cause,
        cleanup: None,
    }
}
struct Pending {
    bytes: [u8; 8],
    file: File,
}
/// Actual writer lock, original private namespace and unsettled publication.
/// Callers serialize namespace administration and exclude hostile mutation.
pub struct Store {
    namespace: Namespace,
    unknown: Option<Pending>,
    directory_sync: DirectorySync,
}
impl Store {
    /// Acquire a native writer lock, observe naming-barrier capability and
    /// validate any existing public proof as an exact ordinary raw8 object.
    pub fn open(path: PathBuf) -> Result<Self, Error> {
        let namespace = Namespace::open(&path)
            .map_err(|cause| error(Stage::Fence, Outcome::NotCommitted, cause))?;
        let directory_sync = namespace
            .sync()
            .map_err(|cause| error(Stage::DirectorySync, Outcome::Unknown, cause))?;
        let store = Self {
            namespace,
            unknown: None,
            directory_sync,
        };
        let _saved = store.read()?;
        Ok(store)
    }
    fn fence(&self) -> Result<(), Error> {
        self.namespace
            .verify()
            .map_err(|cause| error(Stage::Fence, Outcome::Unknown, cause))
    }
    fn sync_directory(&mut self) -> io::Result<()> {
        self.directory_sync = self.directory_sync.combine(self.namespace.sync()?);
        Ok(())
    }
    /// Actual native naming-barrier result, separate from successful file sync.
    pub const fn directory_sync(&self) -> DirectorySync {
        self.directory_sync
    }
    fn read(&self) -> Result<Option<[u8; 8]>, Error> {
        self.fence()?;
        let file = match self.namespace.open_proof() {
            Ok(file) => file,
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(cause) => return Err(error(Stage::Read, Outcome::NotCommitted, cause)),
        };
        read_original(&self.namespace, &file)
            .map(Some)
            .map_err(|cause| error(Stage::Read, Outcome::NotCommitted, cause))
    }
    fn read_pending(&self) -> Result<[u8; 8], Error> {
        let pending = self.unknown.as_ref().ok_or_else(|| {
            error(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("missing original proof publication"),
            )
        })?;
        read_original(&self.namespace, &pending.file)
            .map_err(|cause| error(Stage::Read, Outcome::Unknown, cause))
    }
    /// Read a saved raw8 object. Missing is not a durability receipt. No unknown
    /// original publication can be adopted or silently replaced through this API.
    pub fn loaded(&self) -> Result<Option<[u8; 8]>, Error> {
        if self.unknown.is_some() {
            return Err(error(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original proof publication requires recovery"),
            ));
        }
        self.read()
    }
    /// Check original namespace authority and the absence of unsettled effects.
    pub fn quiescent(&self) -> Result<bool, Error> {
        self.fence()?;
        Ok(self.unknown.is_none())
    }
    /// Publish the exact raw8 value. Unknown effects fence subsequent writes;
    /// publication/readback retain the original file rather than reopening it.
    pub fn commit(&mut self, bytes: [u8; 8]) -> Result<(), Error> {
        self.commit_observed(bytes, || {})
    }
    fn commit_observed(
        &mut self,
        bytes: [u8; 8],
        after_rename: impl FnOnce(),
    ) -> Result<(), Error> {
        if self.unknown.is_some() {
            return Err(error(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("unsettled original proof publication"),
            ));
        }
        self.fence()?;
        let (name, mut file) = self
            .namespace
            .staging()
            .map_err(|cause| error(Stage::Create, Outcome::NotCommitted, cause))?;
        let prepared = (|| {
            let mut offset = 0;
            while offset < bytes.len() {
                // Interrupted writes are not replayed: the native prefix may be unknown.
                let count = file
                    .write(&bytes[offset..])
                    .map_err(|cause| error(Stage::Write, Outcome::NotCommitted, cause))?;
                if count == 0 {
                    return Err(error(
                        Stage::Write,
                        Outcome::NotCommitted,
                        io::ErrorKind::WriteZero.into(),
                    ));
                }
                offset += count;
            }
            file.sync_all()
                .map_err(|cause| error(Stage::FileSync, Outcome::NotCommitted, cause))?;
            self.fence()
        })();
        if let Err(mut original) = prepared {
            original.cleanup = self.namespace.discard(&name, &file).err();
            return Err(original);
        }
        // Keep this exact file even on a failed publication request. No later
        // read of a different inode with equal bytes can settle its effects.
        let result = self.namespace.publish(&name, &file);
        self.unknown = Some(Pending { bytes, file });
        result.map_err(|cause| error(Stage::Rename, Outcome::Unknown, cause))?;
        after_rename();
        self.sync_directory()
            .map_err(|cause| error(Stage::DirectorySync, Outcome::Unknown, cause))?;
        if self.read_pending()? != bytes {
            return Err(error(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original proof readback differs"),
            ));
        }
        self.unknown = None;
        Ok(())
    }
    /// Reconcile the same held publication by naming barrier and exact readback.
    /// This never writes a substitute value or accepts a replacement object.
    pub fn recover(&mut self) -> Result<Option<[u8; 8]>, Error> {
        let Some(expected) = self.unknown.as_ref().map(|pending| pending.bytes) else {
            self.fence()?;
            return Ok(None);
        };
        self.fence()?;
        self.sync_directory()
            .map_err(|cause| error(Stage::Recovery, Outcome::Unknown, cause))?;
        if self.read_pending()? != expected {
            return Err(error(
                Stage::Recovery,
                Outcome::Unknown,
                io::Error::other("original proof cannot be reconciled"),
            ));
        }
        self.unknown = None;
        Ok(Some(expected))
    }
}
fn read_original(namespace: &Namespace, mut file: &File) -> io::Result<[u8; 8]> {
    namespace.verify_proof(file)?;
    let before = match file_info(file)? {
        EntryInfo::File(info) if info.bytes == 8 => info,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "NSE proof must be an exact ordinary raw8 file",
            ));
        }
    };
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = [0; 8];
    file.read_exact(&mut bytes)?;
    let mut trailing = [0];
    if file.read(&mut trailing)? != 0 || file_info(file)? != EntryInfo::File(before) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NSE proof changed during read",
        ));
    }
    namespace.verify_proof(file)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
