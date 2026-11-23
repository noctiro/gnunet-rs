//! Trusted handoff from native checkpoint storage to Messenger recovery.

/// A committed archive loaded from the configured local Messenger store.
///
/// Implement only for an integrity-checked, namespace-qualified checkpoint
/// selected by the original storage owner. Network and IPC bytes do not
/// establish that provenance. Messenger validates the history separately.
pub trait CommittedArchive {
    /// The original nonzero generation selected by native recovery.
    fn generation(&self) -> u64;

    /// The sensitive checkpoint body, without its storage envelope.
    fn expose_committed(&self) -> &[u8];
}
