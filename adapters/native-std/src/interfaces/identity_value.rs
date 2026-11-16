//! Immutable interface facts, independent of native query ownership.
/// An observed Windows interface identity, never authority to own or remove it.
/// Revalidation selects the original LUID and compares index, GUID and thread
/// compartment. It refuses replacement instead of selecting the current index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub(super) compartment: u32,
    pub(super) luid: u64,
    pub(super) index: u32,
    pub(super) guid: [u8; 16],
}
impl Identity {
    /// Original interface index; this number alone is not replacement identity.
    pub const fn index(&self) -> u32 {
        self.index
    }
    /// Original locally unique interface identifier.
    #[cfg(windows)]
    pub const fn luid(&self) -> u64 {
        self.luid
    }
    /// Network compartment in which the identity was observed.
    #[cfg(windows)]
    pub const fn compartment(&self) -> u32 {
        self.compartment
    }
    #[cfg(test)]
    pub(crate) fn fixture(index: u32, device: u8) -> Self {
        Self {
            index,
            compartment: 1,
            luid: u64::from(device),
            guid: [device; 16],
        }
    }
}
