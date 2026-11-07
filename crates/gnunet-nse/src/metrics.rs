//! Actual bounded NSE domain observations, without a statistics socket or task.
use gnunet_types::Error;
/// Exact normal upstream nonpersistent subsystem `nse` keys. Histogram-only
/// `extra messages` and `cross messages` are not ordinary production metrics.
pub const METRIC_NAMES: [&[u8]; 10] = [
    b"# nodes in the network (estimate)",
    b"# flood messages not generated (no proof yet)",
    b"# flood messages not generated (lack of history)",
    b"# flood messages started",
    b"# flood messages transmitted",
    b"# flood messages received",
    b"# flood messages discarded (clock skew too large)",
    b"# flood messages ignored (had closer already)",
    b"# estimated network diameter",
    b"# peers connected",
];
/// Copy snapshot of seven cumulative counters and three actual derived/live
/// gauges, in METRIC_NAMES order. Stored once on the unique Service owner;
/// original marker instances and peer/token auto traits do not change.
#[derive(Clone, Copy, Debug)]
pub struct Metrics {
    values: [u64; 10],
    overflowed: bool,
}
impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}
impl Metrics {
    pub(crate) const fn new() -> Self {
        // The existing zero-history summary has the defined one-node floor.
        Self {
            values: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            overflowed: false,
        }
    }
    /// Immutable actual source coordinates; no native SET/UPDATE is implied.
    #[must_use]
    pub const fn values(&self) -> &[u64; 10] {
        &self.values
    }
    /// Permanent source observation overflow/projection diagnostic. It never
    /// grants a false estimate, successful native publication or cryptographic fact.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }
    /// Exact metric names paired with the actual current domain values.
    pub fn entries(self) -> impl ExactSizeIterator<Item = (&'static [u8], u64)> {
        METRIC_NAMES.into_iter().zip(self.values)
    }
    pub(crate) fn increment(&mut self, index: usize) {
        match self.values[index].checked_add(1) {
            Some(value) => self.values[index] = value,
            None => {
                self.values[index] = u64::MAX;
                self.overflowed = true;
            }
        }
    }
    pub(crate) fn reset_diameter(&mut self) {
        self.values[8] = 0;
    }
    pub(crate) fn gauges(&mut self, estimate: Result<u64, Error>, diameter: u32, peers: usize) {
        match estimate {
            Ok(value) => self.values[0] = value,
            // Preserve the last representable observation, with an explicit
            // permanent diagnostic; never reproduce a C float-to-u64 overflow.
            Err(_) => self.overflowed = true,
        }
        self.values[8] = self.values[8].max(u64::from(diameter));
        match u64::try_from(peers) {
            Ok(value) => self.values[9] = value,
            Err(_) => self.overflowed = true,
        }
    }
}
