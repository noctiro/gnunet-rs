//! Actual original connection/row inventory; no peer-auth or reachability claim.
/// Public raw-QUIC schema present in the pinned source.
pub const RAW_NAME: &[u8] = b"# peers active";
/// Public HTTP3 schema present in the pinned source.
pub const HTTP3_NAME: &[u8] = b"# connections active";
/// Current owned row inventory, including original rows still retiring.
/// This is independent of the existing native socket byte Statistics API.
#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    active: u64,
    overflowed: bool,
}
impl Metrics {
    pub(crate) fn owned(count: usize) -> Self {
        match u64::try_from(count) {
            Ok(active) => Self {
                active,
                overflowed: false,
            },
            Err(_) => Self {
                active: u64::MAX,
                overflowed: true,
            },
        }
    }
    /// Current actual row owners, not authenticated peers or remote receipt.
    #[must_use]
    pub const fn active(self) -> u64 {
        self.active
    }
    /// Actual inventory cannot be represented exactly in an official u64 value.
    #[must_use]
    pub const fn overflowed(self) -> bool {
        self.overflowed
    }
}
