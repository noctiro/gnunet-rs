//! Official diagnostic names and saturating counters. No counter is a receipt.
//!
//! Values are cumulative for this original Core allocation, nonpersistent, and
//! never reset on client reconnect/refresh. Saturation is a lower bound, not a
//! business error. The host alone writes these observations to its real
//! STATISTICS source; this pure module emits no wire traffic or native work.

/// Official nonpersistent STATISTICS keys, under subsystem `regex`.
/// Order matches [`Metrics::values`] and [`Metrics::entries`].
pub const METRIC_NAMES: [&[u8]; 9] = [
    b"# regex accepting blocks stored",
    b"# regex accepting block bytes stored",
    b"# regex blocks stored",
    b"# regex block bytes stored",
    b"# regex accepting blocks found",
    b"# regex accepting block bytes found",
    b"# regex cadet blocks iterated",
    b"# regex edges iterated",
    b"# regex nodes traversed",
];

/// Readonly cumulative snapshot. Official “stored” names count actual local
/// provider PUT admission, never remote replication, durable storage or an ACK.
/// `cadet blocks iterated` remains zero while this implementation performs no
/// C-style cached raw-state replay. No cache work is invented for that metric.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Metrics {
    values: [u64; 9],
}
impl Metrics {
    /// Fixed-order counters, with no allocation or mutable access.
    #[must_use]
    pub fn values(&self) -> &[u64; 9] {
        &self.values
    }
    /// Exact official names and cumulative values; no STATISTICS write/ACK is
    /// implied. A native owner must retain its own source and whole-write cursor.
    pub fn entries(self) -> impl ExactSizeIterator<Item = (&'static [u8], u64)> {
        METRIC_NAMES.into_iter().zip(self.values)
    }
}
#[cfg(feature = "alloc")]
impl Metrics {
    fn add(&mut self, index: usize, value: u64) {
        self.values[index] = self.values[index].saturating_add(value);
    }
    pub(crate) fn put_admitted(&mut self, kind: u32, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        match kind {
            23 => {
                self.add(0, 1);
                self.add(1, bytes);
            }
            22 => {
                self.add(2, 1);
                self.add(3, bytes);
            }
            _ => {}
        }
    }
    pub(crate) fn accepting_found(&mut self, bytes: usize) {
        self.add(4, 1);
        self.add(5, u64::try_from(bytes).unwrap_or(u64::MAX));
    }
    pub(crate) fn edges_inspected(&mut self, count: usize) {
        self.add(7, u64::try_from(count).unwrap_or(u64::MAX));
    }
    pub(crate) fn node_admitted(&mut self) {
        self.add(8, 1);
    }
}
