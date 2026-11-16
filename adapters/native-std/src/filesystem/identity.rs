//! Complete native filesystem observations, independently of host protocols.
use std::{fmt, fs::File, io};
#[cfg(unix)]
use std::{fs::Metadata, os::unix::fs::MetadataExt};
/// Noncanonical or unsupported local identity encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidIdentity;
impl fmt::Display for InvalidIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid native file identity")
    }
}
impl std::error::Error for InvalidIdentity {}
/// Native identity fields for reporting. Numbers alone do not authorize actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileIdentityParts {
    /// Full Unix device and inode numbers.
    Unix {
        /// Complete native device number.
        device: u64,
        /// Complete native inode number.
        inode: u64,
    },
    /// Windows volume serial and the complete native 128-bit file ID.
    Windows {
        /// Native volume serial number.
        volume: u64,
        /// Complete native file identifier.
        id: [u8; 16],
    },
}
/// Exact platform-tagged observation. Durable attachment additionally requires
/// its original owner marker; copied IDs alone do not defeat file-ID reuse.
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct FileIdentity([u8; 32]);
impl fmt::Debug for FileIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.parts().fmt(f)
    }
}
impl FileIdentity {
    /// Construct a Unix observation for an explicit persisted/reporting domain.
    /// This grants no live file, namespace or cleanup capability.
    #[must_use]
    pub const fn unix(device: u64, inode: u64) -> Self {
        let device = device.to_be_bytes();
        let inode = inode.to_be_bytes();
        Self([
            1, 0, 0, 0, 0, 0, 0, 0, device[0], device[1], device[2], device[3], device[4],
            device[5], device[6], device[7], inode[0], inode[1], inode[2], inode[3], inode[4],
            inode[5], inode[6], inode[7], 0, 0, 0, 0, 0, 0, 0, 0,
        ])
    }
    /// Fixed local encoding with a platform tag and complete native fields.
    /// This local observation encoding grants no live object authority.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Decode an observation without treating it as original-object authority.
    /// Unknown tags and noncanonical reserved bytes are refused.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, InvalidIdentity> {
        if !matches!(bytes[0], 1 | 2)
            || bytes[1..8] != [0; 7]
            || bytes[0] == 1 && bytes[24..] != [0; 8]
            || bytes[0] == 2 && bytes[16..] == [0; 16]
        {
            return Err(InvalidIdentity);
        }
        Ok(Self(bytes))
    }
    /// Report complete native fields without truncating Windows IDs.
    #[must_use]
    pub fn parts(self) -> FileIdentityParts {
        let mut volume = [0; 8];
        volume.copy_from_slice(&self.0[8..16]);
        let volume = u64::from_be_bytes(volume);
        if self.0[0] == 1 {
            let mut inode = [0; 8];
            inode.copy_from_slice(&self.0[16..24]);
            FileIdentityParts::Unix {
                device: volume,
                inode: u64::from_be_bytes(inode),
            }
        } else {
            let mut id = [0; 16];
            id.copy_from_slice(&self.0[16..]);
            FileIdentityParts::Windows { volume, id }
        }
    }
    /// Whether two observations belong to the same platform and volume/device.
    #[must_use]
    pub fn same_volume(self, other: Self) -> bool {
        self.0[0] == other.0[0] && self.0[8..16] == other.0[8..16]
    }
    /// Observe the held original file object without resolving its pathname.
    /// Native metadata errors remain errors; the observation grants no ownership.
    pub fn of(file: &File) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self::from_metadata(&file.metadata()?))
        }
        #[cfg(windows)]
        {
            let native = crate::paths::FileIdentity::of(file)?;
            let mut bytes = [0; 32];
            bytes[0] = 2;
            bytes[8..16].copy_from_slice(&native.volume().to_be_bytes());
            bytes[16..].copy_from_slice(&native.id());
            Ok(Self(bytes))
        }
    }
    /// Derive Unix identity fields from an already obtained native metadata observation.
    #[cfg(unix)]
    pub fn from_metadata(metadata: &Metadata) -> Self {
        Self::unix(metadata.dev(), metadata.ino())
    }
    #[cfg(unix)]
    #[expect(
        clippy::unnecessary_cast,
        reason = "Normalize platform-sized dev_t/ino_t exactly as Unix MetadataExt does; either field can already be u64"
    )]
    pub(crate) fn from_stat(stat: &nix::sys::stat::FileStat) -> Self {
        Self::unix(stat.st_dev as u64, stat.st_ino as u64)
    }
}
