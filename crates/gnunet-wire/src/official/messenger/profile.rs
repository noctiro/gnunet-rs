//! Explicit serialization profile for actual host-order fields. This is not a
//! C ABI/FFI dependency, negotiation message, or fallback compatibility mode.
use gnunet_types::Error;
/// The pinned C member-reset IPC, padding footer and private-record scalar producers use native
/// order. Callers explicitly choose the original producer's order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    /// Normal little-endian Linux/macOS builds.
    Little,
    /// A big-endian producer of the same official fields.
    Big,
}
impl Endian {
    /// Decode one exact producer-order u16.
    pub const fn read_u16(self, b: [u8; 2]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes(b),
            Self::Big => u16::from_be_bytes(b),
        }
    }
    /// Encode one exact producer-order u16.
    pub const fn write_u16(self, n: u16) -> [u8; 2] {
        match self {
            Self::Little => n.to_le_bytes(),
            Self::Big => n.to_be_bytes(),
        }
    }
    /// Decode one exact producer-order u32.
    pub const fn read_u32(self, b: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(b),
            Self::Big => u32::from_be_bytes(b),
        }
    }
    /// Encode one exact producer-order u32.
    pub const fn write_u32(self, n: u32) -> [u8; 4] {
        match self {
            Self::Little => n.to_le_bytes(),
            Self::Big => n.to_be_bytes(),
        }
    }
}
/// File body name length comes from the original C producer's NAME_MAX, not the
/// room-details record's separate fixed256-byte name. All other body integers
/// are explicitly BE; endian affects padding, IPC member reset and private records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    /// Original producer order for member-reset/padding/private-record scalar fields.
    pub endian: Endian,
    /// Exact number of bytes in a FILE body name array.
    pub file_name_bytes: usize,
}
impl Profile {
    /// Current target's producer order with Unix NAME_MAX255. Remote service
    /// callers must explicitly select that service's actual producer profile.
    pub const NATIVE_255: Self = Self {
        endian: if cfg!(target_endian = "little") {
            Endian::Little
        } else {
            Endian::Big
        },
        file_name_bytes: 255,
    };
    /// Normal supported little-endian NAME_MAX255 producer profile.
    pub const LITTLE_255: Self = Self {
        endian: Endian::Little,
        file_name_bytes: 255,
    };
    /// Explicit big-endian NAME_MAX255 producer profile.
    pub const BIG_255: Self = Self {
        endian: Endian::Big,
        file_name_bytes: 255,
    };
    /// Reject a profile whose fixed FILE body cannot fit its u16 length domain.
    pub fn validate(self) -> Result<(), Error> {
        if self.file_name_bytes == 0 || self.file_name_bytes > 65535 - 64 {
            Err(Error::InvalidInput)
        } else {
            Ok(())
        }
    }
}
