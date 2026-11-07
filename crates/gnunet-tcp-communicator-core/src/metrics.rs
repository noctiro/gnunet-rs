//! Read-only official communicator-tcp observations, without IPC or a publisher.
//! Plain owned counters preserve the original Session/owner Send and Sync traits.
use crate::wire;
/// Exact ordinary nonpersistent names from the pinned TCP communicator.
pub const METRIC_NAMES: [&[u8]; 6] = [
    b"# queues active",
    b"# messages lost in communicator API towards CORE",
    b"# bytes lost due to CORE not running",
    b"# bytes decrypted with BOX",
    b"# messages decrypted with BOX",
    b"# rekeying successful",
];
/// Actual source coordinates, not a STATISTICS write, crypto capability or ACK.
/// Index zero is a current local queue gauge; the other five are lifetime totals.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Metrics {
    values: [u64; 6],
    overflowed: bool,
}
impl Metrics {
    /// Fixed source coordinates in METRIC_NAMES order.
    #[must_use]
    pub const fn values(&self) -> &[u64; 6] {
        &self.values
    }
    /// Permanent observation overflow. Business processing is unaffected.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }
    /// Pair actual coordinates with exact public names, with no allocation.
    pub fn entries(self) -> impl ExactSizeIterator<Item = (&'static [u8], u64)> {
        METRIC_NAMES.into_iter().zip(self.values)
    }
    fn add(&mut self, index: usize, value: u64) {
        match self.values[index].checked_add(value) {
            Some(total) => self.values[index] = total,
            None => {
                self.values[index] = u64::MAX;
                self.overflowed = true;
            }
        }
    }
    fn bytes(&mut self, index: usize, bytes: usize) {
        match u64::try_from(bytes) {
            Ok(bytes) => self.add(index, bytes),
            Err(_) => self.overflowed = true,
        }
    }
    pub(crate) fn queue(&mut self, live: bool) {
        self.values[0] = u64::from(live);
    }
    pub(crate) fn box_decrypted(&mut self, payload: usize) {
        match payload.checked_add(wire::BOX_PREFIX) {
            Some(bytes) => self.bytes(3, bytes),
            None => self.overflowed = true,
        }
        self.add(4, 1);
    }
    pub(crate) fn receive_failed(&mut self) {
        self.add(1, 1);
    }
    pub(crate) fn core_unavailable(&mut self, payload: usize) {
        self.bytes(2, payload);
    }
    pub(crate) fn rekey_applied(&mut self) {
        self.add(5, 1);
    }
    /// Aggregate exactly one currently owned Session snapshot. The owner must
    /// start from its retained-retired baseline, not repeatedly add a live row.
    pub fn add_active(&mut self, source: Self) {
        for (index, value) in source.values.into_iter().enumerate() {
            self.add(index, value);
        }
        self.overflowed |= source.overflowed;
    }
    /// Retain one original Session's counters when its actual owner is removed.
    /// Its former live gauge is deliberately not retained. Call once at retirement.
    pub fn add_retired(&mut self, source: Self) {
        for (index, value) in source.values.into_iter().enumerate().skip(1) {
            self.add(index, value);
        }
        self.overflowed |= source.overflowed;
    }
}
