//! Actual bounded diagnostic observations; they never settle business work.
use std::time::Instant;
/// Number of actual official nonpersistent coordinates.
pub const COUNT: usize = 17;
/// Fixed public names used by the pinned `zoneimport` STATISTICS owner.
pub const NAMES: [&[u8]; COUNT] = [
    b"# expired records obtained from DNS",
    "# average NAMESTORE PUT latency (μs)".as_bytes(),
    b"# Regular processing completed without NAMESTORE",
    b"# Regular processing completed with NAMESTORE PUT",
    "# average request processing latency (μs)".as_bytes(),
    "# total time spent idle (μs)".as_bytes(),
    b"# Unsuccessful DNS lookups",
    b"# DNS requests given up on",
    b"# DNS ID mismatches",
    b"# DNS parser errors",
    b"# requests given up on",
    "# average DNS lookup latency (μs)".as_bytes(),
    b"# empty DNS replies (usually NXDOMAIN)",
    b"# NAMESTORE records requested from cache",
    b"# Domain names without cached reply",
    b"# zones iterated",
    b"# domain names provided",
];
/// True selects official absolute SET, including cumulative per-run totals.
pub const GAUGES: [bool; COUNT] = [
    false, true, true, true, true, true, false, false, false, false, false, true, false, true,
    true, false, true,
];
/// Public diagnostic snapshot, not a transport or persistence receipt.
#[derive(Clone, Copy, Debug)]
pub struct Metrics {
    /// Exact fixed coordinate order from NAMES.
    pub values: [u64; COUNT],
    /// At least one original observation could not be represented exactly.
    pub overflowed: bool,
}
/// Internal accumulation is saturating and cannot fail or replay business work.
pub(crate) struct Tracker {
    values: [u64; COUNT],
    overflowed: bool,
    dns_sum: u64,
    dns_count: u64,
    store_sum: u64,
    store_count: u64,
    started: Instant,
    idle: Option<Instant>,
    idle_micros: u64,
}
impl Tracker {
    pub fn new() -> Self {
        Self {
            values: [0; COUNT],
            overflowed: false,
            dns_sum: 0,
            dns_count: 0,
            store_sum: 0,
            store_count: 0,
            started: Instant::now(),
            idle: None,
            idle_micros: 0,
        }
    }
    fn sum(slot: &mut u64, value: u64, overflowed: &mut bool) {
        match slot.checked_add(value) {
            Some(total) => *slot = total,
            None => {
                *slot = u64::MAX;
                *overflowed = true;
            }
        }
    }
    pub fn add(&mut self, index: usize, value: u64) {
        if let Some(slot) = self.values.get_mut(index) {
            Self::sum(slot, value, &mut self.overflowed);
        } else {
            self.overflowed = true;
        }
    }
    pub fn set(&mut self, index: usize, value: usize) {
        match (self.values.get_mut(index), u64::try_from(value)) {
            (Some(slot), Ok(value)) => *slot = value,
            _ => self.overflowed = true,
        }
    }
    fn micros(&mut self, start: Instant) -> u64 {
        match u64::try_from(start.elapsed().as_micros()) {
            Ok(value) => value,
            Err(_) => {
                self.overflowed = true;
                u64::MAX
            }
        }
    }
    pub fn dns(&mut self, start: Instant) {
        let elapsed = self.micros(start);
        Self::sum(&mut self.dns_sum, elapsed, &mut self.overflowed);
        Self::sum(&mut self.dns_count, 1, &mut self.overflowed);
        self.values[11] = self.dns_sum / self.dns_count.max(1);
    }
    pub fn stored(&mut self, start: Instant) {
        let elapsed = self.micros(start);
        Self::sum(&mut self.store_sum, elapsed, &mut self.overflowed);
        Self::sum(&mut self.store_count, 1, &mut self.overflowed);
        self.values[1] = self.store_sum / self.store_count.max(1);
        self.add(3, 1);
    }
    pub fn idle(&mut self, idle: bool) {
        match (self.idle, idle) {
            (None, true) => self.idle = Some(Instant::now()),
            (Some(start), false) => {
                let elapsed = self.micros(start);
                Self::sum(&mut self.idle_micros, elapsed, &mut self.overflowed);
                self.idle = None;
            }
            _ => {}
        }
    }
    pub fn snapshot(&self) -> Metrics {
        let mut values = self.values;
        let mut overflowed = self.overflowed;
        let mut micros = |start: Instant| match u64::try_from(start.elapsed().as_micros()) {
            Ok(value) => value,
            Err(_) => {
                overflowed = true;
                u64::MAX
            }
        };
        let active_idle = self.idle.map(&mut micros).unwrap_or(0);
        let elapsed = micros(self.started);
        let idle = match self.idle_micros.checked_add(active_idle) {
            Some(value) => value,
            None => {
                overflowed = true;
                u64::MAX
            }
        };
        values[5] = idle;
        let completed = match values[2].checked_add(values[3]) {
            Some(value) => value,
            None => {
                overflowed = true;
                u64::MAX
            }
        };
        values[4] = elapsed.saturating_sub(idle) / completed.max(1);
        Metrics { values, overflowed }
    }
}
