//! One process fence and full-identity child journals, without history migration.
use super::{DATA, Fence, Journal, JournalError, Outcome, PeerId, Stage, TEMP, invalid, native};
use std::{
    fs, io,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::Path,
    sync::Arc,
};

/// Long-lived normal UDP replay root. Child journals retain this actual process
/// fence too; dropping the facade cannot release authority behind a live child.
pub struct Namespace {
    root: Arc<Fence>,
}
impl Namespace {
    /// Open an existing private root. Unsuffixed snapshots or temporary snapshot
    /// footprints are refused, never migrated, imported or treated as empty.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, JournalError> {
        let original = fs::symlink_metadata(directory.as_ref())
            .map_err(|e| native(Stage::Fence, Outcome::NotCommitted, e))?;
        if !original.is_dir() || original.mode() & 0o077 != 0 {
            return Err(invalid(
                Stage::Fence,
                Outcome::NotCommitted,
                "UDP replay namespace root must be a private real directory",
            ));
        }
        let owner = Self {
            root: Arc::new(Fence::open(directory.as_ref())?),
        };
        owner.check()?;
        owner.reject_unsuffixed_temporary()?;
        Ok(owner)
    }
    pub(super) fn check_root(root: &Fence) -> Result<(), JournalError> {
        root.check()?;
        match fs::symlink_metadata(root.directory.join(DATA)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(native(Stage::Fence, Outcome::Unknown, e)),
            Ok(_) => Err(invalid(
                Stage::Fence,
                Outcome::Unknown,
                "unsuffixed UDP replay history cannot be replaced with empty per-identity state",
            )),
        }
    }
    fn reject_unsuffixed_temporary(&self) -> Result<(), JournalError> {
        // Scan once at root acquisition, never on the packet admission path.
        // The held root writer fence excludes ordinary unsuffixed writers.
        for entry in fs::read_dir(&self.root.directory)
            .map_err(|e| native(Stage::Fence, Outcome::Unknown, e))?
        {
            let entry = entry.map_err(|e| native(Stage::Fence, Outcome::Unknown, e))?;
            let name = entry.file_name();
            if name.as_encoded_bytes().starts_with(TEMP.as_bytes()) {
                return Err(invalid(
                    Stage::Fence,
                    Outcome::Unknown,
                    "unsuffixed UDP replay history cannot be replaced with empty per-identity state",
                ));
            }
        }
        Ok(())
    }
    fn check(&self) -> Result<(), JournalError> {
        Self::check_root(&self.root)
    }
    /// Open this complete local identity's original journal. Each child keeps
    /// its own writer fence, replay floors and outgoing timestamp high-water.
    pub fn journal(&self, local: PeerId, maximum: usize) -> Result<Journal, JournalError> {
        if maximum == 0 || maximum > super::MAX_PEERS {
            return Err(gnunet_types::Error::InvalidInput.into());
        }
        self.check()?;
        let mut name = String::new();
        name.try_reserve_exact(68)
            .map_err(|_| gnunet_types::Error::Capacity)?;
        name.push_str("udp-");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in local {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 15)]));
        }
        let path = self.root.directory.join(name);
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => self
                .root
                .sync()
                .map_err(|e| native(Stage::DirectorySync, Outcome::Unknown, e))?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(native(Stage::Create, Outcome::NotCommitted, e)),
        }
        let metadata =
            fs::symlink_metadata(&path).map_err(|e| native(Stage::Fence, Outcome::Unknown, e))?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err(invalid(
                Stage::Fence,
                Outcome::Unknown,
                "UDP identity journal must be a private real directory",
            ));
        }
        let mut journal = Journal::open(path, local, maximum)?;
        journal.namespace = Some(self.root.clone());
        journal.fence()?;
        Ok(journal)
    }
}

#[cfg(test)]
mod tests;
