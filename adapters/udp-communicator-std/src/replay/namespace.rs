//! One process fence and complete-identity journals on original directories.
use super::{DATA, Fence, Journal, JournalError, Outcome, PeerId, Stage, TEMP, invalid, native};
use std::{ffi::OsStr, io, path::Path, sync::Arc};
const SCAN_LIMIT: usize = 65_536;
/// Normal UDP replay root. Children retain the original process fence until
/// their own physical lifetime ends; retired identity histories are not erased.
pub struct Namespace {
    root: Arc<Fence>,
}
impl Namespace {
    /// Open an existing private root. Unsuffixed snapshots/stages are refused;
    /// no old layout is migrated or silently adopted as an empty identity.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, JournalError> {
        let owner = Self {
            root: Arc::new(Fence::open(directory.as_ref())?),
        };
        owner.check()?;
        let entries = owner
            .root
            .parent
            .entries()
            .map_err(|cause| native(Stage::Fence, Outcome::Unknown, cause))?;
        let mut count = 0;
        for name in entries {
            let name = name.map_err(|cause| native(Stage::Fence, Outcome::Unknown, cause))?;
            count += 1;
            if count > SCAN_LIMIT {
                return Err(gnunet_types::Error::Capacity.into());
            }
            if name.as_encoded_bytes().starts_with(TEMP.as_bytes()) {
                return Err(invalid(
                    Stage::Fence,
                    Outcome::Unknown,
                    "unsuffixed UDP replay stages cannot become empty identity state",
                ));
            }
        }
        Ok(owner)
    }
    pub(super) fn check_root(root: &Fence) -> Result<(), JournalError> {
        root.check()?;
        match root.parent.entry_info(OsStr::new(DATA)) {
            Err(cause) if cause.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(cause) => Err(native(Stage::Fence, Outcome::Unknown, cause)),
            Ok(_) => Err(invalid(
                Stage::Fence,
                Outcome::Unknown,
                "unsuffixed UDP history cannot become empty per-identity state",
            )),
        }
    }
    fn check(&self) -> Result<(), JournalError> {
        Self::check_root(&self.root)
    }
    /// Open this full local identity's original private journal. Directory
    /// creation and publication stay anchored to the held process root.
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
        let directory = match self.root.parent.create_private_directory(OsStr::new(&name)) {
            Ok(directory) => {
                self.root
                    .sync()
                    .map_err(|cause| native(Stage::DirectorySync, Outcome::Unknown, cause))?;
                directory
            }
            Err(cause) if cause.kind() == io::ErrorKind::AlreadyExists => self
                .root
                .parent
                .open_directory(OsStr::new(&name))
                .map_err(|cause| native(Stage::Fence, Outcome::Unknown, cause))?,
            Err(cause) => return Err(native(Stage::Create, Outcome::NotCommitted, cause)),
        };
        let fence = Fence::adopt(directory, &self.root.directory.join(&name))?;
        let mut journal = Journal::from_fence(fence, local, maximum)?;
        journal.namespace = Some(self.root.clone());
        journal.fence()?;
        Ok(journal)
    }
}
#[cfg(test)]
mod tests;
