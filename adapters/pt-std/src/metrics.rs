//! Fixed nonpersistent official PT counters, incremented only by real events.
/// Exact upstream statistic names, with creating subsystem `pt`.
pub const NAMES: [&[u8]; 9] = [
    b"# DNS requests mapped to VPN",
    b"# DNS records modified",
    b"# DNS replies intercepted",
    b"# DNS requests dropped (timeout)",
    b"# DNS requests intercepted",
    b"# DNS requests dropped (DNS cadet channel down)",
    b"# DNS requests dropped (malformed)",
    b"# DNS replies received",
    b"# DNS replies dropped (too late?)",
];
/// Numeric indexes are local metadata and never protocol fields.
#[derive(Clone, Copy, Debug)]
pub enum Counter {
    /// Actual post transformation/Answer admission.
    Mapped = 0,
    /// Actual matching VPN allocation consumed for one record.
    Modified = 1,
    /// Actual POST callback.
    RepliesIntercepted = 2,
    /// Actual original PRE callback timeout.
    Timeout = 3,
    /// Actual PRE callback.
    RequestsIntercepted = 4,
    /// PRE dropped with no actual admitted channel.
    ChannelDown = 5,
    /// Structurally malformed PRE packet rejected.
    Malformed = 6,
    /// Matching original whole-written query got a valid answer.
    Received = 7,
    /// Actual valid reply had no live original query on its channel.
    Late = 8,
}
/// Fixed-size local event totals. These are not remote STATISTICS receipts.
#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    counts: [u64; 9],
}
impl Metrics {
    pub(crate) fn bump(&mut self, c: Counter) {
        self.counts[c as usize] = self.counts[c as usize].saturating_add(1)
    }
    /// Snapshot exact local totals; a publisher retains its own admitted cursor.
    pub const fn counts(self) -> [u64; 9] {
        self.counts
    }
}
