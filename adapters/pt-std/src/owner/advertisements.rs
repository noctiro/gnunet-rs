//! Signed exit advertisements, original leases and DHT query retirement.
use super::{Event, Failure, Failures, Fault, Owner, reserve};
use crate::discovery;
use std::time::Duration;
use tokio::time::Instant;

#[cfg(test)]
mod tests;

pub(super) struct Lease {
    pub(super) peer: [u8; 32],
    pub(super) expires: u64,
    pub(super) hard: Instant,
}

// Signed absolute expirations form one ordered namespace. Once an admitted
// lease expires on its canonical or original native target, no candidate at or
// below that boundary can regain authority. This one floor replaces per-peer
// history; the table retains only leases above it, within the configured quota.
pub(super) struct Leases {
    rows: Vec<Lease>,
    limit: usize,
    expired_through: u64,
}
impl Leases {
    pub(super) fn new(limit: usize) -> Result<Self, Fault> {
        Ok(Self {
            rows: reserve(limit)?,
            limit,
            expired_through: 0,
        })
    }
    pub(super) fn iter(&self) -> impl ExactSizeIterator<Item = &Lease> {
        self.rows.iter()
    }
    fn admission(&self, peer: [u8; 32], expires: u64) -> Result<(), Fault> {
        if expires <= self.expired_through {
            return Err(Fault::Deadline);
        }
        if self.rows.len() >= self.limit && !self.rows.iter().any(|row| row.peer == peer) {
            return Err(Fault::Capacity);
        }
        Ok(())
    }
    fn insert(&mut self, lease: Lease) -> Result<(), Fault> {
        self.admission(lease.peer, lease.expires)?;
        if let Some(row) = self.rows.iter_mut().find(|row| row.peer == lease.peer) {
            // An equal/older signed expiration cannot replace the original hard
            // bound, even when another observation followed a clock rollback.
            if lease.expires > row.expires {
                *row = lease;
            }
        } else {
            self.rows.push(lease);
        }
        Ok(())
    }
    pub(super) fn expire_native(
        &mut self,
        now: Instant,
        withdraw: impl FnMut([u8; 32]) -> Result<(), Fault>,
    ) -> Result<bool, Fault> {
        let through = self
            .rows
            .iter()
            .filter(|row| now >= row.hard)
            .map(|row| row.expires)
            .max()
            .unwrap_or(self.expired_through);
        self.retire_through(through, withdraw)
    }
    pub(super) fn expire_canonical(
        &mut self,
        now: u64,
        withdraw: impl FnMut([u8; 32]) -> Result<(), Fault>,
    ) -> Result<bool, Fault> {
        // Record only actual admitted expirations, rather than unrelated clock
        // observations which could reject fresh candidates after a rollback.
        let through = self
            .rows
            .iter()
            .filter(|row| row.expires <= now)
            .map(|row| row.expires)
            .max()
            .unwrap_or(self.expired_through);
        self.retire_through(through, withdraw)
    }
    fn retire_through(
        &mut self,
        through: u64,
        mut withdraw: impl FnMut([u8; 32]) -> Result<(), Fault>,
    ) -> Result<bool, Fault> {
        self.expired_through = self.expired_through.max(through);
        let mut retired = false;
        let mut i = 0;
        while i < self.rows.len() {
            if self.rows[i].expires <= self.expired_through {
                // Fence authority before reusing the slot. A failed withdrawal
                // retains this row for the original owner's explicit cleanup.
                withdraw(self.rows[i].peer)?;
                self.rows.swap_remove(i);
                retired = true;
            } else {
                i += 1;
            }
        }
        Ok(retired)
    }
}

impl<'a, 'slots> Owner<'a, 'slots> {
    pub(super) fn on_discovery(
        &mut self,
        p: discovery::Event<'a>,
        now: u64,
    ) -> Result<Event, Failure> {
        match p {
            discovery::Event::Result {
                original,
                query,
                block_type,
                block,
            } => {
                let Some((current, bounds)) = self.discovery else {
                    return Ok(Event::Activity);
                };
                if current != original || !bounds.live(now) {
                    return Ok(Event::Activity);
                }
                let bytes = block.bytes();
                if bytes.len() != 112 {
                    return Ok(Event::CleanupFailure(Fault::Malformed.into()));
                }
                let expires =
                    u64::from_be_bytes(bytes[72..80].try_into().map_err(|_| Fault::Truncated)?);
                let peer: [u8; 32] = bytes[80..112].try_into().map_err(|_| Fault::Truncated)?;
                let Some(delta) = expires.checked_sub(now) else {
                    return Ok(Event::Activity);
                };
                let lifetime = Duration::from_micros(delta);
                if lifetime.is_zero() || lifetime > self.limits.advertisement_lifetime {
                    return Ok(Event::Activity);
                }
                match self.leases.admission(peer, expires) {
                    Ok(()) => {}
                    Err(Fault::Deadline) => return Ok(Event::Activity),
                    Err(Fault::Capacity) => return Ok(Event::Backpressure),
                    Err(error) => return Err(error.into()),
                }
                let hard = Instant::now()
                    .checked_add(lifetime)
                    .ok_or(Fault::Overflow)?;
                if let Err(e) = self
                    .core
                    .advertisement(original, &query, block_type, bytes, now)
                {
                    return Ok(Event::CleanupFailure(e.into()));
                }
                self.leases.insert(Lease {
                    peer,
                    expires,
                    hard,
                })?;
                Ok(Event::Advertisement)
            }
            discovery::Event::SourceFailure { original: _, error } => {
                Ok(Event::CleanupFailure(error))
            }
            discovery::Event::Ended { original, error } => {
                if self.discovery.is_some_and(|(d, _)| d == original) {
                    self.discovery = None;
                    if let Err(cause) = self.core.discovery_stopped(original) {
                        return Err(Box::new(Failures {
                            original: error,
                            cleanup: vec![cause.into()],
                        }));
                    }
                    self.discovery_retry = Some(
                        Instant::now()
                            .checked_add(self.limits.retry)
                            .ok_or(Fault::Overflow)?,
                    )
                }
                if let Some(e) = error {
                    self.failed_cleanup(e)
                }
                Ok(Event::Activity)
            }
        }
    }
    pub(super) fn stop_discovery(&mut self) -> Result<(), Failure> {
        if let Some((d, _)) = self.discovery.take() {
            let result = self.dht.as_mut().ok_or(Fault::Unavailable)?.stop(d);
            let stopped = self.core.discovery_stopped(d).map_err(Failure::from);
            match (result, stopped) {
                (Ok(()), Ok(())) => {}
                (Err(error), Ok(())) | (Ok(()), Err(error)) => return Err(error),
                (Err(original), Err(cleanup)) => {
                    return Err(Box::new(Failures {
                        original: Some(original),
                        cleanup: vec![cleanup],
                    }));
                }
            }
        }
        Ok(())
    }
}
