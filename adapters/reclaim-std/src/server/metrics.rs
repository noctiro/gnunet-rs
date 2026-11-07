//! Official RECLAIM persistent lookup observations; no provider outcome is inferred.
use gnunet_reclaim::business::LookupKind;
/// Exact pinned subsystem counter names, in stable local snapshot order.
pub const METRIC_NAMES: [&[u8]; 4] = [
    b"attribute_lookup_time_total",
    b"attribute_lookups_count",
    b"reclaim_authz_lookup_time_total",
    b"reclaim_authz_lookups_count",
];
/// Bounded cumulative actual callbacks. Private fields prevent forged updates
/// through the native Server API; this snapshot is diagnostic, not authorization.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Metrics {
    values: [u64; 4],
    overflowed: bool,
}
impl Metrics {
    /// Actual elapsed microseconds/counts, never queued-write or result success.
    #[must_use]
    pub const fn values(&self) -> &[u64; 4] {
        &self.values
    }
    /// A checked observation exceeded its finite representation. The publisher
    /// must fence diagnostics rather than silently publish an understated value.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }
    pub(super) fn callback(&mut self, kind: LookupKind, elapsed: u128) {
        let index = match kind {
            LookupKind::Attribute => 0,
            LookupKind::Authorization => 2,
        };
        let next = u64::try_from(elapsed)
            .ok()
            .and_then(|elapsed| self.values[index].checked_add(elapsed))
            .zip(self.values[index + 1].checked_add(1));
        if let Some((elapsed, count)) = next {
            self.values[index] = elapsed;
            self.values[index + 1] = count;
        } else {
            self.overflowed = true;
        }
    }
}
