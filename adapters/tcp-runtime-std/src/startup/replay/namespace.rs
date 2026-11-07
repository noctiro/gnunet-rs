//! One process writer fence and exact per-identity replay/frontier names.
use crate::epoch::Store;
use gnunet_crypto::EddsaPublicKey;
use gnunet_types::Error;
use std::{
    fs, io,
    path::{Path, PathBuf},
};

pub(in crate::startup) struct Namespace {
    directory: PathBuf,
    // Retain the original unsuffixed writer fence as a process-wide fence.
    // No epoch, frontier image or replay authority is created through it.
    fence: Store,
}
impl Namespace {
    pub(in crate::startup) fn open(directory: &Path) -> Result<Self, super::Failure> {
        let fence = Store::open(directory.join("tcp.frontier"))?;
        let owner = Self {
            directory: directory.to_path_buf(),
            fence,
        };
        owner.check()?;
        Ok(owner)
    }
    fn check(&self) -> Result<(), super::Failure> {
        // loaded() checks the actual original descriptor/parent fence too.
        if self.fence.loaded()?.is_some() {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                "unsuffixed TCP frontier is not an identity-qualified namespace; no reset or migration is performed").into());
        }
        match fs::symlink_metadata(self.directory.join("tcp.replay")) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err(io::Error::new(io::ErrorKind::InvalidData,
                "unsuffixed TCP replay footprint cannot be replaced by a fresh per-identity catalog").into()),
        }
    }
    pub(super) fn paths(&self, peer: EddsaPublicKey) -> Result<(PathBuf, PathBuf), super::Failure> {
        self.check()?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::new();
        name.try_reserve_exact(68).map_err(|_| Error::Capacity)?;
        name.push_str("tcp-");
        for byte in peer.as_bytes() {
            name.push(char::from(HEX[usize::from(byte >> 4)]));
            name.push(char::from(HEX[usize::from(byte & 15)]));
        }
        let mut frontier = self.directory.join(&name);
        frontier.set_extension("frontier");
        let mut ledger = self.directory.join(name);
        ledger.set_extension("replay");
        Ok((frontier, ledger))
    }
}

#[cfg(test)]
mod tests;
