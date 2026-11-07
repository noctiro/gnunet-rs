//! Persisted monotime reservations are explicit disk work, separate from native
//! signing/CORE polling. A Range is a non-Clone, checked in-memory reservation;
//! creating it requires its entire high-water to be durably committed first.
#[cfg(unix)]
mod disk;
#[cfg(unix)]
pub use disk::{Error, Outcome, Stage, Store};
use gnunet_types::Error as ProtocolError;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
/// Explicit per-open reservation domain. All remaining ranges retain the actual
/// writer fence and share an in-memory issued frontier; this is never global.
pub(super) struct Lease {
    #[cfg(unix)]
    pub(super) guard: std::fs::File,
    pub(super) issued: AtomicU64,
}

/// One already durable node-local reservation. Consuming values performs no
/// filesystem persistence, clock sampling, allocation or native crypto operation.
/// Dropped/unused values are permanently burned by the persisted high-water.
pub struct Range {
    local: [u8; 32],
    next: u64,
    left: u64,
    lease: Option<Arc<Lease>>,
}
impl Range {
    /// Exact local public peer whose durable state reserved this range.
    #[must_use]
    pub const fn local(&self) -> [u8; 32] {
        self.local
    }
    /// Still-unused reserved values, independent of source clock changes.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.left
    }
    /// Consume exactly one already persisted value. Empty returns NotReady so
    /// the caller can request explicit out-of-poll reservation work; no clock
    /// fallback or automatic refill is performed.
    pub fn take_next(&mut self) -> Result<u64, ProtocolError> {
        if self.left == 0 {
            return Err(ProtocolError::NotReady);
        }
        let value = self.next;
        let following = if self.left > 1 {
            self.next.checked_add(1).ok_or(ProtocolError::Overflow)?
        } else {
            value
        };
        let lease = self.lease.as_ref().ok_or(ProtocolError::StaleGeneration)?;
        if lease
            .issued
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |previous| {
                (value > previous).then_some(value)
            })
            .is_err()
        {
            // A newer reserved range already issued a value. Burn this older
            // remainder instead of returning a descending signed monotime.
            self.left = 0;
            self.lease = None;
            return Err(ProtocolError::StaleGeneration);
        }
        self.next = following;
        self.left -= 1;
        if self.left == 0 {
            self.lease = None;
        }
        Ok(value)
    }
}

impl std::fmt::Debug for Range {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Range")
            .field("local", &self.local)
            .field("remaining", &self.left)
            .finish()
    }
}
