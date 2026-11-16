//! Actual data retention, independently of namespace synchronization support.
use gnunet_native::DirectorySync;
/// Where an accepted immutable object is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Retention {
    /// Caller-owned volatile backing; no filesystem synchronization is claimed.
    Volatile,
    /// The data-file synchronization completed, with this directory-barrier result.
    FileSynchronized(DirectorySync),
}
/// Observed immutable object admission, separate from network publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Insert {
    /// A new object was retained at its standard query hash.
    Created(Retention),
    /// Existing exact bytes were checked and their retention refreshed.
    Existing(Retention),
}
impl Insert {
    /// The actual retention observation, independent of new/existing admission.
    #[must_use]
    pub const fn retention(self) -> Retention {
        match self {
            Self::Created(retention) | Self::Existing(retention) => retention,
        }
    }
}
