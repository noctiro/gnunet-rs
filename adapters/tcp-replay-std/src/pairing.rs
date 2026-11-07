//! V2 public frontier format and the actual bootstrap durability barrier. This
//! parses only explicitly selected Rust public state, never any private key.
use gnunet_crypto::EddsaPublicKey;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
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
fn inode(meta: &fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
fn check_file(meta: &fs::Metadata) -> io::Result<()> {
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.len() != FRONTIER_BYTES as u64
        || meta.mode() & 0o077 != 0
    {
        return Err(io::Error::other(
            "not an exact private V2 public frontier file",
        ));
    }
    Ok(())
}
pub(crate) fn inspect(path: &Path) -> io::Result<FrontierImage> {
    if !path.is_absolute() || path.file_name().is_none() || path.as_os_str().as_bytes().contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "explicit absolute public frontier path required",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("frontier parent missing"))?;
    let directory = File::open(parent)?;
    let parent_meta = directory.metadata()?;
    if !parent_meta.is_dir() {
        return Err(io::Error::other("frontier parent is not a directory"));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let original = file.metadata()?;
    check_file(&original)?;
    let mut bytes = [0; FRONTIER_BYTES];
    file.read_exact(&mut bytes)?;
    let image = FrontierImage::decode(bytes)?;
    // Actual file and directory barriers precede any Bound snapshot command.
    file.sync_all()?;
    directory.sync_all()?;
    let actual = fs::symlink_metadata(path)?;
    check_file(&actual)?;
    let dir_actual = fs::metadata(parent)?;
    if actual.file_type().is_symlink()
        || inode(&actual) != inode(&original)
        || inode(&file.metadata()?) != inode(&original)
        || !dir_actual.is_dir()
        || inode(&dir_actual) != inode(&parent_meta)
    {
        return Err(io::Error::other(
            "original frontier or directory changed during pairing",
        ));
    }
    Ok(image)
}
pub(crate) fn barrier(
    path: &Path,
    id: [u8; 32],
    local: EddsaPublicKey,
    generation: u64,
) -> io::Result<()> {
    let image = inspect(path)?;
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
    Ok(())
}
