//! Bounded local immutable leases over externally owned bytes.
use core::cell::Cell;
use gnunet_types::Error;

/// External local lease registry. Sharing consumes a finite reference slot and uses no atomics.
pub struct LeaseSource<'a> {
    bytes: &'a [u8],
    active: Cell<u32>,
    limit: u32,
}

impl<'a> LeaseSource<'a> {
    /// Register immutable bytes with a maximum number of concurrent leases.
    #[must_use]
    pub const fn new(bytes: &'a [u8], limit: u32) -> Self {
        Self {
            bytes,
            active: Cell::new(0),
            limit,
        }
    }

    /// Acquire one immutable lease. Exhaustion does not mutate the counter.
    pub fn lease(&self) -> Result<FrameLease<'_, 'a>, Error> {
        let next = self.active.get().checked_add(1).ok_or(Error::Capacity)?;
        if next > self.limit {
            return Err(Error::Capacity);
        }
        self.active.set(next);
        Ok(FrameLease { source: self })
    }

    /// Number of slots currently consumed, including deliberately forgotten leases.
    #[must_use]
    pub fn active(&self) -> u32 {
        self.active.get()
    }
}

/// A finite immutable local lease. Forgetting it leaks capacity but cannot free its backing bytes.
#[must_use]
pub struct FrameLease<'registry, 'bytes> {
    source: &'registry LeaseSource<'bytes>,
}

impl<'registry, 'bytes> FrameLease<'registry, 'bytes> {
    /// Share immutable bytes only when a real reference slot is available.
    pub fn try_share(&self) -> Result<Self, Error> {
        self.source.lease()
    }
}

impl AsRef<[u8]> for FrameLease<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        self.source.bytes
    }
}

impl Drop for FrameLease<'_, '_> {
    fn drop(&mut self) {
        self.source
            .active
            .set(self.source.active.get().saturating_sub(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sharing_has_real_capacity() -> Result<(), Error> {
        let source = LeaseSource::new(b"record", 1);
        let lease = source.lease()?;
        if lease.try_share().is_ok() {
            return Err(Error::InvalidInput);
        }
        drop(lease);
        let replacement = source.lease()?;
        if replacement.as_ref() != b"record" {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
