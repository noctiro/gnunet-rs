//! Bounded observations of real CADET events, without network-success authority.
//! Stores belong to original owners or already-single-thread caller domains;
//! recycling channel/tunnel rows
//! does not lose cumulative observations. No global state, allocation or clock.
use core::cell::Cell;
/// Number of supported official non-DHT observations. C-only queued duplicate
/// eviction, fresh-candidate replacement and the absent dual-KX state have no
/// false zero registration.
pub const COUNT: usize = 32;
/// Exact official metric names in snapshot order.
pub const NAMES: [&[u8]; COUNT] = [
    b"# clients",
    b"# payload received from clients",
    b"# channels",
    b"# duplicate CREATE_ACKs",
    b"# duplicate DATA (ancient or future)",
    b"# duplicate DATA",
    b"# messages dropped due to slow client",
    b"# duplicate DATA_ACKs",
    b"# keepalives sent",
    b"# latencies observed",
    b"# buffer use",
    b"# messages dropped due to full buffer",
    b"# messages dropped due to route destruction",
    b"# routes",
    b"# KX transmitted",
    b"# KX_AUTH transmitted",
    b"# Ratchet key already known",
    b"# Root key already known",
    b"# Useless KX",
    b"# KX received",
    b"# Duplicate KX received",
    b"# Duplicate unverified KX received",
    b"# Fresh KX setup",
    b"# redundant KX_AUTH received",
    b"# KX_AUTH not using our last KX received (auth failure)",
    b"# KX_AUTH received",
    b"# keepalives received",
    b"# received encrypted without any KX",
    b"# received encrypted without KX",
    b"# unable to decrypt",
    b"# decrypted bytes",
    b"# encrypted bytes",
];
/// True for actual current-resource observations, false for cumulative events.
pub const GAUGES: [bool; COUNT] = [
    true, false, false, false, false, false, false, false, false, false, true, false, false, true,
    false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false,
];
#[derive(Clone, Copy)]
pub(crate) enum Metric {
    Clients,
    Payload,
    Channels,
    DuplicateCreateAck,
    DuplicateDataWindow,
    DuplicateData,
    SlowClient,
    DuplicateDataAck,
    KeepaliveSent,
    Latencies,
    BufferUse,
    FullBuffer,
    RouteDestroyed,
    Routes,
    KxSent,
    AuthSent,
    RatchetKnown,
    RootKnown,
    UselessKx,
    KxReceived,
    DuplicateKx,
    DuplicateUnverifiedKx,
    FreshKx,
    RedundantAuth,
    AuthFailure,
    AuthReceived,
    KeepaliveReceived,
    EncryptedWithoutAnyKx,
    EncryptedWithoutKx,
    UnableDecrypt,
    DecryptedBytes,
    EncryptedBytes,
}
/// Diagnostic-only aggregate. Checked overflow fences publication; it does
/// not change protocol or manufacture a successful operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot {
    values: [u64; COUNT],
    overflowed: bool,
}
impl Snapshot {
    /// Empty initial observation, not an assertion that any peer exists.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            values: [0; COUNT],
            overflowed: false,
        }
    }
    /// Values in NAMES order. Gauges are current; other entries are cumulative.
    #[must_use]
    pub const fn values(&self) -> &[u64; COUNT] {
        &self.values
    }
    /// At least one actual count could not fit. Never silently wrap/reset it.
    #[must_use]
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }
    /// Supply the actual native owner's current MQ inventory. A physical close
    /// can precede a refused pure detach; this overrides only the diagnostic
    /// client gauge, never changes accepted source or cleanup authority.
    #[must_use]
    pub fn with_native_clients(mut self, clients: usize) -> Self {
        self.set(Metric::Clients, clients);
        self
    }
    /// Add disjoint original domains. The caller must not merge the same domain
    /// twice; this snapshot conveys no proof or operation authority.
    pub fn merge(&mut self, other: &Self) {
        self.overflowed |= other.overflowed;
        for (total, value) in self.values.iter_mut().zip(&other.values) {
            if let Some(next) = total.checked_add(*value) {
                *total = next;
            } else {
                self.overflowed = true;
            }
        }
    }
    /// Preserve a retired disjoint domain's cumulative events while discarding
    /// resource gauges which no longer describe a live generation.
    #[must_use]
    pub fn into_history(mut self) -> Self {
        for (value, gauge) in self.values.iter_mut().zip(GAUGES) {
            if gauge {
                *value = 0;
            }
        }
        self
    }
    pub(crate) fn set(&mut self, metric: Metric, value: usize) {
        if let Ok(value) = u64::try_from(value) {
            self.values[metric as usize] = value;
        } else {
            self.overflowed = true;
        }
    }
}
impl Default for Snapshot {
    fn default() -> Self {
        Self::new()
    }
}
pub(crate) struct Store {
    values: [Cell<u64>; COUNT],
    overflowed: Cell<bool>,
}
impl Store {
    pub(crate) const fn new() -> Self {
        Self {
            values: [const { Cell::new(0) }; COUNT],
            overflowed: Cell::new(false),
        }
    }
    pub(crate) fn add(&self, metric: Metric, amount: u64) {
        let slot = &self.values[metric as usize];
        if let Some(next) = slot.get().checked_add(amount) {
            slot.set(next)
        } else {
            self.overflowed.set(true)
        }
    }
    pub(crate) fn bytes(&self, metric: Metric, amount: usize) {
        if let Ok(amount) = u64::try_from(amount) {
            self.add(metric, amount)
        } else {
            self.overflowed.set(true)
        }
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            values: core::array::from_fn(|i| self.values[i].get()),
            overflowed: self.overflowed.get(),
        }
    }
}
impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

// Service/Book retain exclusive mutable ownership and marker-only domains.
// Diagnostics must not change their original Send/Sync token/owner boundary.
pub(crate) struct OwnedStore {
    values: [u64; COUNT],
    overflowed: bool,
}
impl OwnedStore {
    pub(crate) const fn new() -> Self {
        Self {
            values: [0; COUNT],
            overflowed: false,
        }
    }
    pub(crate) fn add(&mut self, metric: Metric, amount: u64) {
        let slot = &mut self.values[metric as usize];
        if let Some(next) = slot.checked_add(amount) {
            *slot = next
        } else {
            self.overflowed = true
        }
    }
    pub(crate) fn bytes(&mut self, metric: Metric, amount: usize) {
        if let Ok(amount) = u64::try_from(amount) {
            self.add(metric, amount)
        } else {
            self.overflowed = true
        }
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot {
            values: self.values,
            overflowed: self.overflowed,
        }
    }
}
