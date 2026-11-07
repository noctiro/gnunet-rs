//! Fixed material-epoch provenance. This is independent of every packet and
//! route budget, and has no cache-hit renewal or authentication authority.
use super::*;

#[derive(Clone, Copy, Debug)]
pub(crate) struct MaterialLease {
    pub(crate) until: u64,
    hard: Instant,
}
impl MaterialLease {
    pub(crate) fn capture(
        now: u64,
        native: Instant,
        source_until: u64,
        identity_until: u64,
        source_hard: Instant,
        lifetime: std::time::Duration,
    ) -> Result<Self, Protocol> {
        let micros = u64::try_from(lifetime.as_micros()).map_err(|_| Protocol::Overflow)?;
        if micros == 0 {
            return Err(Protocol::InvalidInput);
        }
        let lease = Self {
            until: now
                .checked_add(micros)
                .ok_or(Protocol::Overflow)?
                .min(source_until)
                .min(identity_until),
            hard: native
                .checked_add(lifetime)
                .ok_or(Protocol::Overflow)?
                .min(source_hard),
        };
        lease.check_at(now, native)?;
        Ok(lease)
    }
    pub(crate) fn check(self, now: u64) -> Result<(), Protocol> {
        self.check_at(now, Instant::now())
    }
    fn check_at(self, now: u64, native: Instant) -> Result<(), Protocol> {
        if now >= self.until || native >= self.hard {
            Err(Protocol::Deadline)
        } else {
            Ok(())
        }
    }
}

/// Both independent authorities must still be live immediately before cache
/// installation. A material Task cannot extend its producer packet operation.
pub(crate) fn check_install(
    bounds: &Bound,
    lease: MaterialLease,
    now: u64,
) -> Result<(), Protocol> {
    bounds.check(now)?;
    lease.check(now)
}

/// Match the exact typed epoch, never an old lifetime for a reused slot. The
/// returned lease is copied without changing its original captured targets.
fn retained_lease<I: Copy + Eq>(
    slots: &[Option<(I, MaterialLease)>],
    id: I,
) -> Option<MaterialLease> {
    slots
        .iter()
        .flatten()
        .find_map(|(known, lease)| (*known == id).then_some(*lease))
}

/// A lookup hint, not a material-use receipt. Actual sealing checks the same
/// epoch and lease again before consuming the packet task or a nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SendHit<'id> {
    id: cache::SendId<'id>,
    stamp: u64,
}
impl SendHit<'_> {
    pub(crate) fn stamp(self) -> u64 {
        self.stamp
    }
}

/// One owner for the pure send cache, exact lease provenance and replacement
/// cursor. No caller can install a key separately from its native lease.
pub(crate) struct SendMaterials<'slots, 'source, 'id> {
    cache: cache::SendCache<'slots, 'source, 'id>,
    leases: Vec<Option<(cache::SendId<'id>, MaterialLease)>>,
    next: usize,
}
impl<'slots, 'source, 'id> SendMaterials<'slots, 'source, 'id> {
    pub(crate) fn new(
        slots: &'slots mut [cache::SendSlot<'source, 'id>],
    ) -> Result<Self, Protocol> {
        let count = slots.len();
        let cache = cache::SendCache::new(slots)?;
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(count)
            .map_err(|_| Protocol::Capacity)?;
        leases.resize(count, None);
        Ok(Self {
            cache,
            leases,
            next: 0,
        })
    }
    fn live(&mut self, id: cache::SendId<'id>, now: u64) -> Result<bool, Protocol> {
        if self.cache.material(id).is_err() {
            return Ok(false);
        }
        if retained_lease(&self.leases, id).is_some_and(|lease| lease.check(now).is_ok()) {
            return Ok(true);
        }
        self.cache.revoke(id)?;
        Ok(false)
    }
    pub(crate) fn find(
        &mut self,
        source: &Source<'id>,
        target: PeerId,
        now: u64,
    ) -> Result<Option<SendHit<'id>>, Protocol> {
        let Some(id) = self.cache.find(source, target, now) else {
            return Ok(None);
        };
        if !self.live(id, now)? {
            return Ok(None);
        }
        Ok(Some(SendHit {
            id,
            stamp: self.cache.material(id)?.stamp(),
        }))
    }
    pub(crate) fn install(
        &mut self,
        material: cache::SendMaterial<'source, 'id>,
        lease: MaterialLease,
        packet: &Bound,
        now: u64,
    ) -> Result<SendHit<'id>, Protocol> {
        check_install(packet, lease, now)?;
        if material.until() != lease.until {
            return Err(Protocol::InvalidInput);
        }
        let stamp = material.stamp();
        let id = self.cache.insert(self.next, material, now)?;
        self.leases[self.next] = Some((id, lease));
        self.next = (self.next + 1) % self.leases.len();
        Ok(SendHit { id, stamp })
    }
    /// A stale/expired hint is a real miss, with no nonce consumed. The caller
    /// can start a new material job under that SAME packet's original budget.
    pub(crate) fn seal(
        &mut self,
        hit: SendHit<'id>,
        task: Task<'source, 'id>,
        now: u64,
        packet: cache::Packet<'_>,
        scratch: &mut [u8],
        output: &mut [u8],
    ) -> Result<Option<gnunet_transport_dv_crypto::Sealed<'id>>, Protocol> {
        if !self.live(hit.id, now)? {
            scratch.zeroize();
            return Ok(None);
        }
        self.cache
            .seal(hit.id, task, now, packet, scratch, output)
            .map(Some)
    }
    pub(crate) fn close(&mut self) {
        self.cache.clear();
        self.leases.fill(None);
    }
}

/// Actual cache use always returns ownership of the complete plaintext loan.
/// A miss grants no authentication and leaves packet/source/replay ownership
/// with the original input row.
pub(crate) enum ReceiveUse<'source, 'id, 'out> {
    Opened(gnunet_transport_dv_crypto::Opened<'source, 'id, 'out>),
    Miss(&'out mut [u8]),
    Failed {
        error: Protocol,
        buffer: &'out mut [u8],
    },
}

/// One owner for recipient material, exact lease provenance and replacement.
pub(crate) struct ReceiveMaterials<'slots, 'source, 'id> {
    cache: cache::ReceiveCache<'slots, 'source, 'id>,
    leases: Vec<Option<(cache::ReceiveId<'id>, MaterialLease)>>,
    next: usize,
}
impl<'slots, 'source, 'id> ReceiveMaterials<'slots, 'source, 'id> {
    pub(crate) fn new(
        slots: &'slots mut [cache::ReceiveSlot<'source, 'id>],
    ) -> Result<Self, Protocol> {
        let count = slots.len();
        let cache = cache::ReceiveCache::new(slots)?;
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(count)
            .map_err(|_| Protocol::Capacity)?;
        leases.resize(count, None);
        Ok(Self {
            cache,
            leases,
            next: 0,
        })
    }
    fn live_at(
        &mut self,
        id: cache::ReceiveId<'id>,
        now: u64,
        native: Instant,
    ) -> Result<bool, Protocol> {
        // A different epoch may occupy this slot. Never revoke that replacement.
        if self.cache.material(id).is_err() {
            return Ok(false);
        }
        if retained_lease(&self.leases, id).is_some_and(|lease| lease.check_at(now, native).is_ok())
        {
            return Ok(true);
        }
        self.cache.revoke(id)?;
        Ok(false)
    }
    pub(crate) fn live(&mut self, id: cache::ReceiveId<'id>, now: u64) -> Result<bool, Protocol> {
        self.live_at(id, now, Instant::now())
    }
    pub(crate) fn find(
        &mut self,
        source: &Source<'id>,
        encapsulation: &[u8; 32],
        now: u64,
    ) -> Result<Option<cache::ReceiveId<'id>>, Protocol> {
        let Some(id) = self.cache.find(source, encapsulation, now) else {
            return Ok(None);
        };
        Ok(self.live(id, now)?.then_some(id))
    }
    pub(crate) fn install(
        &mut self,
        material: cache::ReceiveMaterial<'source, 'id>,
        lease: MaterialLease,
        packet: &Bound,
        now: u64,
    ) -> Result<cache::ReceiveId<'id>, Protocol> {
        check_install(packet, lease, now)?;
        if material.until() != lease.until {
            return Err(Protocol::InvalidInput);
        }
        let id = self.cache.insert(self.next, material, now)?;
        self.leases[self.next] = Some((id, lease));
        self.next = (self.next + 1) % self.leases.len();
        Ok(id)
    }
    pub(crate) fn open<'packet, 'out>(
        &mut self,
        id: cache::ReceiveId<'id>,
        request: gnunet_transport_dv_crypto::OpenRequest<'source, 'id, 'packet>,
        now: u64,
        scratch: &mut [u8],
        output: &'out mut [u8],
    ) -> ReceiveUse<'source, 'id, 'out> {
        match self.live(id, now) {
            Ok(true) => match self.cache.open_recover(id, request, now, scratch, output) {
                Ok(opened) => ReceiveUse::Opened(opened),
                Err(failed) => ReceiveUse::Failed {
                    error: failed.error(),
                    buffer: failed.recycle(),
                },
            },
            Ok(false) => {
                scratch.zeroize();
                output.zeroize();
                ReceiveUse::Miss(output)
            }
            Err(error) => {
                scratch.zeroize();
                output.zeroize();
                ReceiveUse::Failed {
                    error,
                    buffer: output,
                }
            }
        }
    }
    pub(crate) fn close(&mut self) {
        self.cache.clear();
        self.leases.fill(None);
    }
}

#[cfg(test)]
mod tests;
