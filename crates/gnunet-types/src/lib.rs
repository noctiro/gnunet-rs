//! Checked resource units and errors shared by official GNUnet components.
#![no_std]
#![forbid(unsafe_code)]
use core::fmt;

mod time;
/// Canonical absolute/relative units, distinct from native monotonic coordinates.
pub use time::{AbsoluteTime, RelativeTime};

/// A classified failure; no secrets or attacker-controlled diagnostics are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A finite resource has no available capacity.
    Capacity,
    /// A length, offset or arithmetic result is outside its supported range.
    Overflow,
    /// The supplied bytes or configuration violate the contract.
    InvalidInput,
    /// Malformed external framing or protocol semantics.
    Malformed,
    /// A packet is shorter than its declared framing.
    Truncated,
    /// A critical protocol value or version is unknown.
    Unsupported,
    /// An identifier refers to an old generation or an absent object.
    Stale,
    /// An asynchronous completion targets an obsolete object generation.
    StaleGeneration,
    /// The object is closed and cannot admit new work.
    Closed,
    /// Work cannot complete until a resource or event becomes available.
    WouldBlock,
    /// Authentication or authorization failed.
    Authentication,
    /// An already consumed sequence number or operation was replayed.
    Replay,
    /// A deadline elapsed.
    Timeout,
    /// The trusted UTC interval cannot establish validity.
    TimeUncertain,
    /// The operation was cancelled before its business commit.
    Cancelled,
    /// A storage or device commit could have happened and requires recovery.
    OutcomeUnknown,
    /// The persistence revision has changed.
    Conflict,
    /// The selected role or backend does not provide the capability.
    Unavailable,
    /// The external device or storage failed.
    Io,
    /// Fresh entropy is unavailable.
    Entropy,
    /// The instance entropy port cannot currently provide fresh random bytes.
    EntropyUnavailable,
    /// A requested key, object or route does not exist.
    NotFound,
    /// Required initialization or external progress is incomplete.
    NotReady,
    /// A monotonic admission deadline elapsed.
    Deadline,
    /// The caller lacks a scoped capability for this operation.
    PermissionDenied,
    /// The message exceeds a negotiated size limit.
    TooLarge,
    /// Persistence failed before a durable outcome could be established.
    Storage,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for Error {}

/// Rejected admission returns the value to its original owner without committing it.
#[derive(Debug, Eq, PartialEq)]
#[must_use]
pub struct Rejected<T> {
    /// The original value, still owned by the caller.
    pub value: T,
    /// The admission failure.
    pub reason: Error,
}

/// An internal table slot paired with a non-reused generation; never a wire identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GenerationalId {
    /// Zero-based slot index.
    pub index: u32,
    /// Slot generation; exhaustion retires the slot.
    pub generation: u32,
}
macro_rules! unit {
    ($name:ident,$inner:ty,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub $inner);
        impl $name {
            /// Checked addition in this unit.
            pub fn checked_add(self, rhs: Self) -> Result<Self, Error> {
                self.0.checked_add(rhs.0).map(Self).ok_or(Error::Overflow)
            }
            /// Checked subtraction in this unit.
            pub fn checked_sub(self, rhs: Self) -> Result<Self, Error> {
                self.0.checked_sub(rhs.0).map(Self).ok_or(Error::Overflow)
            }
        }
    };
}
unit!(Bytes, u64, "A separately accounted byte quantity.");
unit!(
    MessageSlots,
    u32,
    "A finite number of message metadata slots."
);
unit!(
    Duration,
    u64,
    "An internal checked microsecond interval, separate from the wire FOREVER sentinel."
);
unit!(
    MonoInstant,
    u64,
    "An internal monotonic microsecond timestamp, separate from wire UTC."
);
impl MonoInstant {
    /// Compute an original deadline without wrapping.
    pub fn after(self, duration: Duration) -> Result<Self, Error> {
        self.0
            .checked_add(duration.0)
            .map(Self)
            .ok_or(Error::Overflow)
    }
    /// Compute elapsed monotonic microseconds, rejecting clock regression.
    pub fn duration_since(self, earlier: Self) -> Result<Duration, Error> {
        self.0
            .checked_sub(earlier.0)
            .map(Duration)
            .ok_or(Error::TimeUncertain)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn units_reject_wrap_and_clock_regression() {
        assert_eq!(Bytes(u64::MAX).checked_add(Bytes(1)), Err(Error::Overflow));
        assert_eq!(
            MessageSlots(0).checked_sub(MessageSlots(1)),
            Err(Error::Overflow)
        );
        assert_eq!(
            MonoInstant(u64::MAX).after(Duration(1)),
            Err(Error::Overflow)
        );
        assert_eq!(
            MonoInstant(1).duration_since(MonoInstant(2)),
            Err(Error::TimeUncertain)
        );
        assert_eq!(
            MonoInstant(3).duration_since(MonoInstant(2)),
            Ok(Duration(1))
        );
    }
}
