//! V2 public frontier format and the actual bootstrap durability barrier. This
//! parses only explicitly selected Rust public state, never any private key.
use gnunet_crypto::EddsaPublicKey;
use gnunet_native::{
    DirectorySync,
    filesystem::{
        Directory, EntryInfo, FileIdentity, PrivateFileSnapshot, file_info, private_data_file_info,
        private_single_file_identity,
    },
};
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Read},
    path::Path,
};
#[cfg(test)]
mod tests;
/// Exact bounded V2 public image, including replay identity and min generation.
/// These fields are format metadata, not a successful persistence receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrontierImage {
    /// Actual process epoch may have unretired remote work.
    pub dirty: bool,
    /// Burned reserved signed time, independent of received replay floors.
    pub reserved: u64,
    /// Public initialized ledger identity.
    pub ledger: [u8; 32],
    /// Fixed actual local peer identity.
    pub local: EddsaPublicKey,
    /// Lowest actual ledger generation authorized before external STORE.
    pub minimum: u64,
}
/// Exact V2 file bound; V1 is intentionally refused rather than migrated.
pub const FRONTIER_BYTES: usize = 89;
impl FrontierImage {
    /// Encode metadata only; writing these bytes does not create authority.
    #[must_use]
    pub fn encode(self) -> [u8; FRONTIER_BYTES] {
        let mut out = [0; FRONTIER_BYTES];
        out[..8].copy_from_slice(b"GNTCPR02");
        out[8] = u8::from(self.dirty);
        out[9..17].copy_from_slice(&self.reserved.to_be_bytes());
        out[17..49].copy_from_slice(&self.ledger);
        out[49..81].copy_from_slice(self.local.as_bytes());
        out[81..89].copy_from_slice(&self.minimum.to_be_bytes());
        out
    }
    /// Decode only exact initialized V2 public metadata, without granting trust.
    pub fn decode(bytes: [u8; FRONTIER_BYTES]) -> io::Result<Self> {
        if &bytes[..8] != b"GNTCPR02" || bytes[8] > 1 {
            return Err(io::Error::other("invalid public TCP V2 frontier"));
        }
        let value = Self {
            dirty: bytes[8] == 1,
            reserved: u64::from_be_bytes(bytes[9..17].try_into().map_err(io::Error::other)?),
            ledger: bytes[17..49].try_into().map_err(io::Error::other)?,
            local: EddsaPublicKey::from_bytes(bytes[49..81].try_into().map_err(io::Error::other)?),
            minimum: u64::from_be_bytes(bytes[81..89].try_into().map_err(io::Error::other)?),
        };
        if value.ledger == [0; 32] || (value.minimum == 0 && (value.dirty || value.reserved != 0)) {
            return Err(io::Error::other("uninitialized TCP frontier binding"));
        }
        Ok(value)
    }
}
pub(crate) struct Inspection {
    pub image: FrontierImage,
    pub directory_sync: DirectorySync,
}
struct Prepared {
    file: File,
    identity: FileIdentity,
    bytes: [u8; FRONTIER_BYTES],
    image: FrontierImage,
    directory_sync: DirectorySync,
}
#[derive(Debug)]
struct PreparationFailure {
    original: io::Error,
    close: io::Error,
}
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; independent original frontier sync-handle close: {}",
            self.original, self.close
        )
    }
}
impl std::error::Error for PreparationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
fn prepare(directory: &Directory, name: &OsStr, mut file: File) -> io::Result<Prepared> {
    let prepared = (|| {
        let identity = private_single_file_identity(&file)?;
        let EntryInfo::File(info) = file_info(&file)? else {
            return Err(io::Error::other("ordinary TCP frontier required"));
        };
        if info.bytes != FRONTIER_BYTES as u64 || !directory.same_file(name, &file)? {
            return Err(io::Error::other("exact original V2 TCP frontier required"));
        }
        let mut bytes = [0; FRONTIER_BYTES];
        file.read_exact(&mut bytes)?;
        let image = FrontierImage::decode(bytes)?;
        file.sync_all()?;
        let directory_sync = directory.sync()?;
        if directory_sync == DirectorySync::Unavailable {
            file.sync_all()?;
        }
        // Select and qualify the reader while the original sync handle still
        // pins its identity. Canonical state is never removed on a refusal.
        let readonly = directory.open_file(name)?;
        let observed = private_single_file_identity(&readonly)?;
        if observed != identity {
            return Err(io::Error::other(format!(
                "original TCP frontier read lease changed: expected={identity:?}, observed={observed:?}"
            )));
        }
        Ok(Prepared {
            file: readonly,
            identity,
            bytes,
            image,
            directory_sync,
        })
    })();
    let closed = gnunet_native::filesystem::close(file);
    match (prepared, closed) {
        (Ok(prepared), Ok(())) => Ok(prepared),
        (Err(original), Ok(())) | (Ok(_), Err(original)) => Err(original),
        (Err(original), Err(close)) => Err(io::Error::new(
            original.kind(),
            PreparationFailure { original, close },
        )),
    }
}
/// Read only the original exact selected object and report its actual native
/// barriers. An equal-byte replacement never supplies this observation.
pub(crate) fn inspect(path: &Path) -> io::Result<Inspection> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.as_os_str().as_encoded_bytes().contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "explicit absolute public frontier path required",
        ));
    }
    let parent = path.parent().ok_or(io::ErrorKind::InvalidInput)?;
    let name = path.file_name().ok_or(io::ErrorKind::InvalidInput)?;
    let directory = Directory::open(parent)?;
    directory.validate_namespace()?;
    let parent_id = FileIdentity::of(directory.as_file())?;
    let Prepared {
        mut file,
        identity: file_id,
        bytes,
        image,
        directory_sync,
    } = prepare(&directory, name, directory.open_file_for_sync(name)?)?;
    // File synchronization and the actual sync-handle close finish before the
    // immutable read fence begins. Full fences still guard the original reader.
    let info = private_data_file_info(&file)?;
    if info.identity != file_id || info.bytes != FRONTIER_BYTES as u64 {
        return Err(io::Error::other(format!(
            "original TCP frontier changed while preparing read lease: original_identity={file_id:?}, after_close={info:?}"
        )));
    }
    let mut actual = [0; FRONTIER_BYTES];
    file.read_exact(&mut actual)?;
    let mut extra = [0];
    let selected = Directory::open(parent)?;
    selected.validate_namespace()?;
    if actual != bytes {
        return Err(io::Error::other(format!(
            "original frontier or directory changed during pairing: content_mismatch=true, before={info:?}"
        )));
    }
    let trailing_bytes = file.read(&mut extra)?;
    if trailing_bytes != 0 {
        return Err(io::Error::other(format!(
            "original frontier or directory changed during pairing: unexpected_tail={trailing_bytes}, before={info:?}"
        )));
    }
    PrivateFileSnapshot::new(info, &actual).verify(&directory, name, &file)?;
    let selected_id = FileIdentity::of(selected.as_file())?;
    if selected_id != parent_id {
        return Err(io::Error::other(format!(
            "original frontier or directory changed during pairing: before_directory={parent_id:?}, named_directory={selected_id:?}"
        )));
    }
    let held_id = FileIdentity::of(directory.as_file())?;
    if held_id != parent_id {
        return Err(io::Error::other(format!(
            "original frontier or directory changed during pairing: before_directory={parent_id:?}, held_directory={held_id:?}"
        )));
    }
    Ok(Inspection {
        image,
        directory_sync,
    })
}
pub(crate) fn barrier(
    path: &Path,
    id: [u8; 32],
    local: EddsaPublicKey,
    generation: u64,
) -> io::Result<DirectorySync> {
    let inspected = inspect(path)?;
    let image = inspected.image;
    if image.dirty
        || image.reserved != 0
        || image.ledger != id
        || image.local != local
        || image.minimum != generation
        || generation != 1
    {
        return Err(io::Error::other(
            "Unbound ledger does not match original initialized frontier",
        ));
    }
    Ok(inspected.directory_sync)
}
