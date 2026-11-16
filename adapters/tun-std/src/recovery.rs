//! Persistent FreeBSD TUN recovery selectors, never standalone cleanup authority.
//!
//! Save a record durably before using a persistent interface. Recovery must
//! reacquire and qualify the actual exclusive device and current kernel marker.
//! Names, indexes, device IDs and copied records alone cannot grant ownership.
//! Administrators must serialize device/interface mutation across recovery and
//! destruction; FreeBSD has no atomic conditional-destroy ioctl. Only trusted
//! privately retained records from the original administrative scope may drive
//! recovery. Opening a TUN has native side effects even when qualification later
//! fails; this API is not a read-only probe for untrusted input.
#[cfg(target_os = "freebsd")]
pub use crate::platform::recovery::{Cleanup, Failure, Observation};
mod journal;
#[cfg(target_os = "freebsd")]
pub(crate) mod managed;
#[cfg(any(target_os = "freebsd", test))]
pub(crate) mod marker;
use gnunet_native::filesystem::{FileIdentity, FileIdentityParts};
pub use journal::{Intent, Journal, State};
#[cfg(target_os = "freebsd")]
pub use managed::{OpenError, OpenStage};
use std::io;

/// Fixed canonical private record size. This is not a GNUnet wire format.
pub const RECORD_BYTES: usize = 128;
const MAGIC: &[u8; 8] = b"GNTUNR01";
const NAME_BYTES: usize = 16;
/// Correlation data for one original persistent FreeBSD interface. Cloning or
/// decoding it does not acquire a device or authorize destruction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub(crate) name: [u8; NAME_BYTES],
    pub(crate) device: [u8; NAME_BYTES],
    pub(crate) index: u32,
    pub(crate) birth: [u8; 32],
    pub(crate) file: FileIdentity,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid persistent TUN recovery record",
    )
}
pub(crate) fn read_name(bytes: &[u8; NAME_BYTES]) -> io::Result<&str> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(invalid)?;
    if end == 0 || bytes[end..].iter().any(|byte| *byte != 0) {
        return Err(invalid());
    }
    std::str::from_utf8(&bytes[..end]).map_err(|_| invalid())
}
pub(crate) fn canonical_unit(name: &str) -> bool {
    name.strip_prefix("tun").is_some_and(|suffix| {
        !suffix.is_empty()
            && !(suffix.len() > 1 && suffix.starts_with('0'))
            && suffix.bytes().all(|byte| byte.is_ascii_digit())
            && suffix
                .parse::<u32>()
                .is_ok_and(|unit| unit <= i32::MAX as u32)
    })
}
impl Record {
    #[cfg(any(target_os = "freebsd", test))]
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        self.index == other.index
            && self.device == other.device
            && self.birth == other.birth
            && self.file == other.file
    }
    /// Decode a canonical selector without performing any OS operation.
    ///
    /// # Errors
    /// Rejects unknown versions, malformed names/IDs, zero index/marker,
    /// noncanonical device units and nonzero reserved bytes.
    pub fn decode(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != RECORD_BYTES
            || &bytes[..8] != MAGIC
            || bytes[108..].iter().any(|byte| *byte != 0)
        {
            return Err(invalid());
        }
        let record = Self {
            index: u32::from_be_bytes(bytes[8..12].try_into().map_err(|_| invalid())?),
            name: bytes[12..28].try_into().map_err(|_| invalid())?,
            device: bytes[28..44].try_into().map_err(|_| invalid())?,
            birth: bytes[44..76].try_into().map_err(|_| invalid())?,
            file: FileIdentity::from_bytes(bytes[76..108].try_into().map_err(|_| invalid())?)
                .map_err(|_| invalid())?,
        };
        record.interface_name()?;
        if record.index == 0
            || record.birth.iter().all(|byte| *byte == 0)
            || !canonical_unit(record.device_name()?)
            || !matches!(record.file.parts(), FileIdentityParts::Unix { .. })
        {
            return Err(invalid());
        }
        Ok(record)
    }
    /// Encode the selector, including canonical zero padding. The caller owns
    /// private-file publication and durability; encoding is not a checkpoint.
    #[must_use]
    pub fn encode(&self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&self.index.to_be_bytes());
        bytes[12..28].copy_from_slice(&self.name);
        bytes[28..44].copy_from_slice(&self.device);
        bytes[44..76].copy_from_slice(&self.birth);
        bytes[76..108].copy_from_slice(self.file.as_bytes());
        bytes
    }
    /// Original actual interface name, including its successful rename.
    ///
    /// # Errors
    /// Rejects an invalid internal native name rather than guessing a path.
    pub fn interface_name(&self) -> io::Result<&str> {
        read_name(&self.name)
    }
    /// Original canonical devfs unit, unaffected by interface rename.
    ///
    /// # Errors
    /// Rejects an invalid internal native name.
    pub fn device_name(&self) -> io::Result<&str> {
        read_name(&self.device)
    }
    /// Original observed interface index; it is not an immutable birth ID.
    #[must_use]
    pub const fn interface_index(&self) -> u32 {
        self.index
    }
    /// Reacquire and qualify the exclusive native device for explicit cleanup.
    /// A failed lookup/open never creates a substitute or changes its framing.
    ///
    /// # Errors
    /// Retains this selector with the original observation/qualification error.
    #[cfg(target_os = "freebsd")]
    pub fn recover(self) -> Result<Observation, Failure> {
        crate::platform::recovery::recover(self)
    }
}

#[cfg(test)]
mod tests;
