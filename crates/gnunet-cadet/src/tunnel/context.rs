//! Stable caller-owned domain and bounded reusable context leases.
//! No capability borrows a dynamic Controller/Session or enters the wire.
use super::{LocalKeys, Role};
use core::{cell::Cell, cmp::Ordering, fmt, ptr};
use gnunet_types::Error;
use gnunet_wire::official::cadet_peer::{KX_FORCE_REPLY, PeerMessage};

/// Stable node domain. Allocation IDs never repeat within this domain, even
/// when a registry row is reused. This single-thread owner contains no secrets.
#[derive(Default)]
pub struct Instance {
    next: Cell<u64>,
    statistics: crate::statistics::Store,
}
impl Instance {
    /// Cumulative tunnel observations for this entire original domain.
    #[must_use]
    pub fn statistics(&self) -> crate::statistics::Snapshot {
        self.statistics.snapshot()
    }
    /// Empty explicit domain; no global counter or allocation is used.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: Cell::new(0),
            statistics: crate::statistics::Store::new(),
        }
    }
}
#[derive(Clone, Copy)]
struct Live {
    allocation: u64,
    admission: u64,
}
/// One fixed live-registry row. Reusing this row cannot recreate an old scope.
pub struct Slot {
    live: Cell<Live>,
}
impl Slot {
    /// Free fixed registry storage, independent of per-peer crypto buffers.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            live: Cell::new(Live {
                allocation: 0,
                admission: 0,
            }),
        }
    }
}
impl Default for Slot {
    fn default() -> Self {
        Self::new()
    }
}
/// Caller-owned fixed registry, movable independently of every live lease.
/// Only the stable external domain/rows are borrowed by scope capabilities.
pub struct Registry<'node> {
    instance: &'node Instance,
    slots: &'node [Slot],
}
impl<'node> Registry<'node> {
    /// Bind empty caller rows to one stable node domain. Cell mutation is only
    /// single-thread local metadata; it grants no network or crypto authority.
    pub fn new(instance: &'node Instance, slots: &'node mut [Slot]) -> Result<Self, Error> {
        if slots.is_empty() {
            return Err(Error::Capacity);
        }
        if slots.iter().any(|s| s.live.get().allocation != 0) {
            return Err(Error::Conflict);
        }
        Ok(Self { instance, slots })
    }
    /// Allocate distinct public peer facts and a unique owned lease. Refusal
    /// does not consume a row or ID; checked ID exhaustion never wraps.
    pub fn allocate(&mut self, local: [u8; 32], peer: [u8; 32]) -> Result<Context<'node>, Error> {
        let role = match local.cmp(&peer) {
            Ordering::Less => Role::Alice,
            Ordering::Greater => Role::Betty,
            Ordering::Equal => return Err(Error::InvalidInput),
        };
        let slots: &'node [Slot] = self.slots;
        let slot = slots
            .iter()
            .find(|slot| slot.live.get().allocation == 0)
            .ok_or(Error::Capacity)?;
        let allocation = self
            .instance
            .next
            .get()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.instance.next.set(allocation);
        slot.live.set(Live {
            allocation,
            admission: 0,
        });
        Ok(Context {
            binding: Scope {
                instance: self.instance,
                slot,
                allocation,
                local,
                peer,
                role,
            },
            owned: true,
        })
    }
    /// Observe the shared original domain once, including retired contexts.
    #[must_use]
    pub fn statistics(&self) -> crate::statistics::Snapshot {
        self.instance.statistics()
    }
    /// Currently free logical rows. External original IO may still be retiring
    /// after a lease closes; this count does not claim physical quiescence.
    #[must_use]
    pub fn available(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.live.get().allocation == 0)
            .count()
    }
}

/// One owned non-Copy, non-Clone context lease. Closing or dropping it revokes
/// future admission immediately; original admitted outputs still must retire.
pub struct Context<'node> {
    pub(super) binding: Scope<'node>,
    owned: bool,
}
impl<'node> Context<'node> {
    /// Original ordered local role, independent of a reusable row's contents.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.binding.role
    }
    /// Original end-to-end remote peer metadata, never raw-CID authentication.
    #[must_use]
    pub const fn peer(&self) -> [u8; 32] {
        self.binding.peer
    }
    /// Original local public peer metadata.
    #[must_use]
    pub const fn local(&self) -> [u8; 32] {
        self.binding.local
    }
    /// Original capability, borrowing only stable caller domain/registry rows.
    #[must_use]
    pub const fn scope(&self) -> Scope<'node> {
        self.binding
    }
    /// Revoke new logical operations. This does not stop or settle backend IO;
    /// previously admitted jobs keep their exact stored original retirement.
    pub fn close(&mut self) {
        if self.owned {
            self.binding.revoke();
            self.owned = false;
        }
    }
    // Transfer the one revocation obligation to a standalone Session without
    // retaining a second full copy of the immutable scope facts.
    pub(super) fn into_scope(mut self) -> Scope<'node> {
        self.owned = false;
        self.binding
    }
    /// Encode initial Alice KX from actual fresh original local keys.
    pub fn initial_key_exchange(
        &self,
        local: &LocalKeys,
        connection: [u8; 32],
    ) -> Result<PeerMessage<'static>, Error> {
        self.binding.authorize()?;
        if self.role() != Role::Alice {
            return Err(Error::InvalidInput);
        }
        let exchange = local.exchange();
        Ok(PeerMessage::KeyExchange {
            flags: KX_FORCE_REPLY,
            connection,
            ephemeral_key: exchange.ephemeral_key,
            ratchet_key: exchange.ratchet_key,
        })
    }
}
impl Drop for Context<'_> {
    fn drop(&mut self) {
        self.close();
    }
}

/// Copyable original context capability. Stable-domain references never pin
/// dynamic peer Context/Controller/Session values or their reusable slots.
#[derive(Clone, Copy)]
pub struct Scope<'node> {
    instance: &'node Instance,
    slot: &'node Slot,
    allocation: u64,
    pub(super) local: [u8; 32],
    pub(super) peer: [u8; 32],
    pub(super) role: Role,
}
impl<'node> Scope<'node> {
    pub(crate) fn statistics(self) -> &'node crate::statistics::Store {
        &self.instance.statistics
    }
    /// Original peer metadata; a stale scope never observes replacement facts.
    #[must_use]
    pub const fn peer(self) -> [u8; 32] {
        self.peer
    }
    /// Original local public peer metadata.
    #[must_use]
    pub const fn local(self) -> [u8; 32] {
        self.local
    }
    /// Diagnostic unique local allocation, never a wire field or authority alone.
    #[must_use]
    pub const fn allocation(self) -> u64 {
        self.allocation
    }
    /// Whether this original logical lease still admits operations.
    #[must_use]
    pub fn is_live(self) -> bool {
        self.slot.live.get().allocation == self.allocation
    }
    pub(super) fn authorize(self) -> Result<(), Error> {
        if self.is_live() {
            Ok(())
        } else {
            Err(Error::StaleGeneration)
        }
    }
    pub(super) fn authorize_admission(self, generation: u64) -> Result<(), Error> {
        let live = self.slot.live.get();
        if live.allocation == self.allocation && live.admission == generation && generation != 0 {
            Ok(())
        } else {
            Err(Error::StaleGeneration)
        }
    }
    pub(super) fn admission(self, generation: u64) {
        if self.is_live() {
            self.slot.live.set(Live {
                allocation: self.allocation,
                admission: generation,
            });
        }
    }
    pub(super) fn revoke(self) {
        if self.is_live() {
            self.slot.live.set(Live {
                allocation: 0,
                admission: 0,
            });
        }
    }
}
impl PartialEq for Scope<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.instance, other.instance)
            && self.allocation == other.allocation
            && ptr::eq(self.slot, other.slot)
    }
}
impl Eq for Scope<'_> {}
impl fmt::Debug for Scope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunnelScope")
            .field("allocation", &self.allocation)
            .field("local", &self.local)
            .field("peer", &self.peer)
            .finish()
    }
}

#[cfg(test)]
mod tests;
