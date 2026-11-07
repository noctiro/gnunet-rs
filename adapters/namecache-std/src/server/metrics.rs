//! Official handler/callback counters. No preflight or wire-write inference.
use crate::dispatch::{Kind, Observation};
/// Actual nonpersistent NAMECACHE observations, in this order: looked up, found,
/// cached requests, removed requests. Cache memory Stats remain independent.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Metrics {
    values: [u64; 4],
    overflowed: bool,
}
impl Metrics {
    /// Original cumulative values, including backend-negative cache/delete calls
    /// and lookup misses. Found increments only for an actual returned block.
    #[must_use]
    pub const fn values(&self) -> &[u64; 4] {
        &self.values
    }
    /// Diagnostic representation exhausted. Business processing remains valid;
    /// a publisher must fence its own snapshot instead of treating this as success.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }
    pub(super) fn observe(&mut self, event: Observation) {
        let index = match event {
            Observation::Request(Kind::Lookup) => 0,
            Observation::Found => 1,
            Observation::Request(Kind::Cache) => 2,
            Observation::Request(Kind::Delete) => 3,
        };
        if let Some(next) = self.values[index].checked_add(1) {
            self.values[index] = next;
        } else {
            self.overflowed = true;
        }
    }
}
