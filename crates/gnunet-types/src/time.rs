//! Canonical GNUnet absolute and relative microsecond units and their byte representation.
use crate::{Duration, Error};

/// GNUnet absolute microseconds since the Unix epoch; UINT64_MAX means never.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AbsoluteTime(u64);
impl AbsoluteTime {
    /// The Unix epoch, 1970-01-01T00:00:00Z.
    pub const UNIX_EPOCH: Self = Self(0);
    /// GNUnet's forever/never absolute-time sentinel.
    pub const NEVER: Self = Self(u64::MAX);
    /// Preserve the official microsecond value, including the never sentinel.
    #[must_use]
    pub const fn from_micros(value: u64) -> Self {
        Self(value)
    }
    /// Microseconds in host byte order, without converting to milliseconds.
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }
    /// Add a checked internal microsecond interval without wrapping or saturation.
    /// A caller requiring a finite target must separately reject NEVER.
    pub fn after(self, duration: Duration) -> Result<Self, Error> {
        self.0
            .checked_add(duration.0)
            .map(Self)
            .ok_or(Error::Overflow)
    }
    /// Checked difference between logical absolute observations. This is not
    /// native elapsed time; rollback returns TimeUncertain rather than clamping.
    pub fn duration_since(self, earlier: Self) -> Result<Duration, Error> {
        self.0
            .checked_sub(earlier.0)
            .map(Duration)
            .ok_or(Error::TimeUncertain)
    }
    /// The network byte representation.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
    /// Decode exactly eight bytes; incomplete and trailing encodings are rejected.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        decode_u64(input).map(Self)
    }
    /// Whether this is the official never sentinel.
    #[must_use]
    pub const fn is_never(self) -> bool {
        self.0 == u64::MAX
    }
}

/// GNUnet relative microseconds; UINT64_MAX means forever.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RelativeTime(u64);
impl RelativeTime {
    /// Zero microseconds.
    pub const ZERO: Self = Self(0);
    /// The official unbounded relative-time sentinel.
    pub const FOREVER: Self = Self(u64::MAX);
    /// Preserve the official relative microsecond value.
    #[must_use]
    pub const fn from_micros(value: u64) -> Self {
        Self(value)
    }
    /// Microseconds in host byte order.
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0
    }
    /// The network byte representation.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
    /// Decode exactly eight bytes.
    pub fn decode(input: &[u8]) -> Result<Self, Error> {
        decode_u64(input).map(Self)
    }
    /// Whether this is the official forever sentinel.
    #[must_use]
    pub const fn is_forever(self) -> bool {
        self.0 == u64::MAX
    }
}

fn decode_u64(input: &[u8]) -> Result<u64, Error> {
    if input.len() < 8 {
        return Err(Error::Truncated);
    }
    if input.len() != 8 {
        return Err(Error::InvalidInput);
    }
    Ok(u64::from_be_bytes(
        input.try_into().map_err(|_| Error::Truncated)?,
    ))
}
