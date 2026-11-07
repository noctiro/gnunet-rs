//! Exact official zonemaster nonpersistent statistics. Gauges describe local
//! actual source/job/API facts; the historical DHT name proves no remote store.
/// Actual source names, indexed by Counter.
pub const NAMES: [&[u8]; 16] = [
    b"Namecache updates skipped (NC disabled)",
    b"Namecache updates pushed",
    "Minimum relative record expiration (in μs)".as_bytes(),
    "Zone publication time window (in μs)".as_bytes(),
    "Target zone iteration velocity (μs)".as_bytes(),
    "Current zone iteration velocity (μs/record)".as_bytes(),
    b"# dispatched jobs",
    b"% speed increase needed for target velocity",
    b"# records processed in current iteration",
    "Current artificial NAMESTORE delay (μs/record)".as_bytes(),
    b"DHT put operations initiated",
    b"Number of public records in DHT",
    b"Full zone iterations launched",
    b"Namestore monitor events received",
    b"Namestore monitor errors encountered",
    b"Workers running",
];
/// Which official values are relative event counters (others are absolute gauges).
pub const RELATIVE: [bool; 16] = [
    true, true, false, false, false, false, false, false, false, false, true, false, true, true,
    true, false,
];
/// Public fixed local metric indexes, never wire identifiers.
#[derive(Clone, Copy)]
pub enum Counter {
    /// Actual skipped cache intent.
    CacheSkipped = 0,
    /// Actual cache admission.
    CachePushed = 1,
    /// Original relative minimum.
    Minimum = 2,
    /// Actual current publication window.
    Window = 3,
    /// Desired bounded pace.
    Target = 4,
    /// Coherent-clock local input pace.
    Velocity = 5,
    /// Actual retained jobs.
    Jobs = 6,
    /// Local observed versus target pace.
    Speed = 7,
    /// Actual current inventory nonempty sets.
    Processed = 8,
    /// Actual scheduled background NEXT pause per set.
    Delay = 9,
    /// Actual original public PUT admission.
    Puts = 10,
    /// Last actual complete inventory set count (legacy official name).
    Public = 11,
    /// Actual full START admission.
    Iterations = 12,
    /// Actual monitor records.
    Monitor = 13,
    /// Actual monitor-source loss/error.
    MonitorErrors = 14,
    /// Actual currently owned CPU worker threads.
    Workers = 15,
}
/// Fixed local snapshot. No wire processing or durability receipt is fabricated.
#[derive(Clone, Copy, Default)]
pub struct Metrics {
    values: [u64; 16],
}
impl Metrics {
    pub(crate) fn bump(&mut self, c: Counter) {
        self.values[c as usize] = self.values[c as usize].saturating_add(1)
    }
    pub(crate) fn set(&mut self, c: Counter, n: u64) {
        self.values[c as usize] = n
    }
    /// Actual local values; publication names do not strengthen their API boundary.
    pub const fn values(self) -> [u64; 16] {
        self.values
    }
}
