//! Explicit observations of native directory synchronization support.
/// Whether the backend actually completed a directory synchronization request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectorySync {
    /// The OS accepted the requested directory barrier.
    Synchronized,
    /// This backend has no directory barrier; none is reported as completed.
    Unavailable,
}
impl DirectorySync {
    /// Aggregate all naming barriers without erasing any unavailable result.
    #[must_use]
    pub const fn combine(self, other: Self) -> Self {
        match (self, other) {
            (Self::Synchronized, Self::Synchronized) => Self::Synchronized,
            _ => Self::Unavailable,
        }
    }
}
