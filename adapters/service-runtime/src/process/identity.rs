//! Registry-branded original child identities, independent of native PID reuse.
use std::sync::Arc;
#[derive(Debug)]
pub(super) struct RegistryIdentity {
    pub(super) _nonzero: u8,
}
/// Lookup capability for one original admitted child, never numeric-PID authority
/// by itself. Clones share identity only; the registry owns the original native
/// process, wait and control resources.
#[derive(Clone, Debug)]
pub struct OriginalChild {
    pub(super) identity: Arc<RegistryIdentity>,
    pub(super) generation: u64,
    pub(super) pid: u32,
}
impl PartialEq for OriginalChild {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.identity, &other.identity)
            && self.generation == other.generation
            && self.pid == other.pid
    }
}
impl Eq for OriginalChild {}
impl std::hash::Hash for OriginalChild {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::ptr::hash(Arc::as_ptr(&self.identity), state);
        std::hash::Hash::hash(&self.generation, state);
        std::hash::Hash::hash(&self.pid, state);
    }
}
impl OriginalChild {
    /// Diagnostic original PID. Passing this number elsewhere does not transfer
    /// wait/signal authority, and it must never be used after this child's reap.
    pub fn pid(&self) -> u32 {
        self.pid
    }
}
