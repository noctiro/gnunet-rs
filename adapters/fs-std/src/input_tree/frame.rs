//! Bounded snapshots over the native directory boundary.
use super::{Directory, EntryInfo, File, SourceError, observe};
use crate::FileIdentity;
#[cfg(feature = "network")]
use gnunet_crypto::Hash512State;
use gnunet_native::filesystem::{FileInfo, FileTimes, file_info};
use std::ffi::OsString;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    File,
    Directory,
}
/// Native identity and change observations. Atime is deliberately excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Stamp {
    pub kind: Kind,
    pub identity: FileIdentity,
    pub bytes: u64,
    pub times: FileTimes,
}
impl Stamp {
    fn from_info(info: EntryInfo) -> Result<Self, SourceError> {
        let (
            kind,
            FileInfo {
                identity,
                bytes,
                times,
            },
        ) = match info {
            EntryInfo::File(info) => (Kind::File, info),
            EntryInfo::Directory(info) => (Kind::Directory, info),
            EntryInfo::Other => return Err(SourceError::Unsupported),
        };
        Ok(Self {
            kind,
            identity,
            bytes,
            times,
        })
    }
    /// Private local fingerprint; this is not a GNUnet network format.
    #[cfg(feature = "network")]
    pub fn hash(self, state: &mut Hash512State) {
        state.update(&[match self.kind {
            Kind::File => 1,
            Kind::Directory => 2,
        }]);
        state.update(self.identity.as_bytes());
        state.update(&self.bytes.to_be_bytes());
        state.update(&self.times.modified.to_be_bytes());
        state.update(&self.times.changed.to_be_bytes());
    }
}
pub(crate) fn stamp(file: &File) -> Result<Stamp, SourceError> {
    Stamp::from_info(file_info(file)?)
}
#[derive(Debug)]
pub(crate) struct Name {
    pub native: OsString,
    pub kind: Kind,
    pub stamp: Stamp,
}
fn at_entry(name: OsString, cause: SourceError) -> SourceError {
    SourceError::Entry {
        name,
        cause: Box::new(cause),
    }
}
/// One sorted directory listing, with an independent native enumeration cursor.
/// Only the parent handle stays open; child observations close immediately.
pub(crate) struct FrameSource {
    pub file: File,
    pub stamp: Stamp,
    pub names: Vec<Name>,
    pub names_bytes: usize,
}
impl FrameSource {
    pub fn scan(
        file: File,
        max_children: usize,
        max_name_bytes: usize,
        max_names_bytes: usize,
    ) -> Result<Self, SourceError> {
        let original = stamp(&file)?;
        if original.kind != Kind::Directory {
            return Err(SourceError::Unsupported);
        }
        let parent = Directory::from_file(&file)?;
        let mut names = Vec::new();
        let mut names_bytes = 0_usize;
        for entry in parent.entries()? {
            let name = entry?;
            let bytes = name.as_encoded_bytes().len();
            if names.len() == max_children || bytes > max_name_bytes {
                return Err(SourceError::Limit);
            }
            names_bytes = names_bytes
                .checked_add(bytes)
                .filter(|total| *total <= max_names_bytes)
                .ok_or(SourceError::Limit)?;
            let observed =
                match observe(&parent, &name).and_then(|(_, info)| Stamp::from_info(info)) {
                    Ok(observed) => observed,
                    Err(cause) => return Err(at_entry(name, cause)),
                };
            names.try_reserve(1).map_err(|_| SourceError::Limit)?;
            names.push(Name {
                native: name,
                kind: observed.kind,
                stamp: observed,
            });
        }
        names.sort_unstable_by(|left, right| left.native.cmp(&right.native));
        if names
            .windows(2)
            .any(|pair| pair[0].native == pair[1].native)
            || stamp(&file)? != original
        {
            return Err(SourceError::Changed);
        }
        Ok(Self {
            file,
            stamp: original,
            names,
            names_bytes,
        })
    }
    pub fn verify(&self) -> Result<(), SourceError> {
        if stamp(&self.file)? != self.stamp {
            return Err(SourceError::Changed);
        }
        Ok(())
    }
    pub fn open(&self, index: usize) -> Result<File, SourceError> {
        let name = self
            .names
            .get(index)
            .ok_or(SourceError::Protocol(gnunet_types::Error::InvalidInput))?;
        self.verify()?;
        let (file, info) = observe(&Directory::from_file(&self.file)?, &name.native)?;
        if Stamp::from_info(info)? != name.stamp {
            return Err(SourceError::Changed);
        }
        self.verify()?;
        Ok(file)
    }
}
