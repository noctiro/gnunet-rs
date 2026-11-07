//! Trusted asynchronous identity-DH backend boundary, separate from public peer
//! metadata. Only an actual backend can supply its completed 64-byte DH hash.
//! No completion constructor labels arbitrary public bytes as verified PILS.
use super::{Exchange, Role, controller::Generation};
use core::{fmt, ptr};
use gnunet_types::{Error, MonoInstant};
/// Stable explicit source domain. Checked local bind IDs never repeat, even
/// when a fixed row is reused for another actual original MQ.
#[derive(Default)]
pub struct Instance {
    next: core::cell::Cell<u64>,
}
impl Instance {
    /// Empty local source domain, without allocation or implicit global IDs.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            next: core::cell::Cell::new(0),
        }
    }
}
/// Fixed live source-registry storage, separate from native jobs/results.
pub struct Slot {
    binding: core::cell::Cell<u64>,
}
impl Slot {
    /// An empty source row, reused only under a new unique bind ID.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            binding: core::cell::Cell::new(0),
        }
    }
}
impl Default for Slot {
    fn default() -> Self {
        Self::new()
    }
}
/// Movable caller-owned registry. Sources borrow stable domain/rows, never a
/// dynamic native Port, client, source Binding or per-peer Context.
pub struct Registry<'id> {
    instance: &'id Instance,
    slots: &'id [Slot],
}
impl<'id> Registry<'id> {
    /// Bind fixed empty caller storage to one stable source domain.
    pub fn new(instance: &'id Instance, slots: &'id mut [Slot]) -> Result<Self, Error> {
        if slots.is_empty() {
            return Err(Error::Capacity);
        }
        if slots.iter().any(|slot| slot.binding.get() != 0) {
            return Err(Error::Conflict);
        }
        Ok(Self { instance, slots })
    }
    /// Own an actual observed local-peer/original-MQ binding. Native providers
    /// invoke this only after verifying their real client identity/typed epoch.
    /// A custom pure caller remains an explicit trusted source boundary.
    pub fn bind(&mut self, local: [u8; 32], epoch: u64) -> Result<Binding<'id>, Error> {
        if epoch == 0 {
            return Err(Error::InvalidInput);
        }
        let slots: &'id [Slot] = self.slots;
        let slot = slots
            .iter()
            .find(|s| s.binding.get() == 0)
            .ok_or(Error::Capacity)?;
        let allocation = self
            .instance
            .next
            .get()
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        self.instance.next.set(allocation);
        slot.binding.set(allocation);
        Ok(Binding {
            source: Source {
                instance: self.instance,
                slot,
                allocation,
                local,
                epoch,
            },
        })
    }
    /// Free logical source rows, without claiming old physical jobs settled.
    #[must_use]
    pub fn available(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.binding.get() == 0)
            .count()
    }
}
/// Owned original source lease. Drop/close revokes admission but cannot by
/// itself settle any original native operation. There is no Clone/Copy.
pub struct Binding<'id> {
    source: Source<'id>,
}
impl<'id> Binding<'id> {
    /// Original public source capability, never a private key/result proof.
    #[must_use]
    pub const fn source(&self) -> Source<'id> {
        self.source
    }
    /// Revoke this original logical binding. The native owner independently
    /// stops IO and drains its original jobs; stale tokens cannot rebind it.
    pub fn close(&mut self) {
        if self.source.is_live() {
            self.source.slot.binding.set(0);
        }
    }
}
impl Drop for Binding<'_> {
    fn drop(&mut self) {
        self.close();
    }
}
/// Original trusted backend identity/MQ metadata, not private-key authority.
#[derive(Clone, Copy)]
pub struct Source<'id> {
    instance: &'id Instance,
    slot: &'id Slot,
    allocation: u64,
    local: [u8; 32],
    epoch: u64,
}
impl Source<'_> {
    /// Actual original public peer; this grants no DH completion by itself.
    #[must_use]
    pub const fn local(self) -> [u8; 32] {
        self.local
    }
    /// Original diagnostic MQ generation, never standalone authority/wire ID.
    #[must_use]
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
    /// Unique checked local bind ID, independent of reused native epoch values.
    #[must_use]
    pub const fn allocation(self) -> u64 {
        self.allocation
    }
    /// Whether this exact original source still admits new jobs.
    #[must_use]
    pub fn is_live(self) -> bool {
        self.slot.binding.get() == self.allocation
    }
}
impl PartialEq for Source<'_> {
    fn eq(&self, other: &Self) -> bool {
        ptr::eq(self.instance, other.instance)
            && ptr::eq(self.slot, other.slot)
            && self.allocation == other.allocation
    }
}
impl Eq for Source<'_> {}
impl fmt::Debug for Source<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityDhSource")
            .field("allocation", &self.allocation)
            .field("local", &self.local)
            .field("epoch", &self.epoch)
            .finish()
    }
}
/// One original candidate's single identity×remote-ephemeral hash operation.
/// Every field is private and minted only by the actual controller state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Request<'id> {
    pub(super) source: Source<'id>,
    pub(super) generation: Generation<'id>,
    pub(super) local: Exchange,
    pub(super) remote: Exchange,
    pub(super) role: Role,
    pub(super) expires: MonoInstant,
}
impl<'id> Request<'id> {
    /// Check the still-live original source/context/candidate before actual
    /// backend admission. Revoked unsubmitted copies cannot create a job, even
    /// after registry/high-water rows are reused. Retirement uses stored jobs.
    pub fn admission(self) -> Result<(), Error> {
        if !self.source.is_live() {
            return Err(Error::StaleGeneration);
        }
        self.generation.admission()
    }
    /// Original exact trusted backend/source allocation.
    #[must_use]
    pub const fn source(self) -> Source<'id> {
        self.source
    }
    /// Original candidate/context generation, never a wire RID.
    #[must_use]
    pub const fn generation(self) -> Generation<'id> {
        self.generation
    }
    /// Original local ephemeral and ratchet public coordinates.
    #[must_use]
    pub const fn local_exchange(self) -> Exchange {
        self.local
    }
    /// Original remote ephemeral and ratchet public coordinates.
    #[must_use]
    pub const fn remote_exchange(self) -> Exchange {
        self.remote
    }
    /// Exact original role determined by actual public peer ordering.
    #[must_use]
    pub const fn role(self) -> Role {
        self.role
    }
    /// Absolute original candidate lifetime; retries/awaiting do not extend it.
    #[must_use]
    pub const fn expires(self) -> MonoInstant {
        self.expires
    }
}
/// Backend result consumption status. No variant exposes reusable DH bytes.
pub enum Completion<T> {
    /// The original actual operation remains pending; no callback was invoked.
    Pending,
    /// Its original result and physical request ownership have settled. Callback
    /// output or an actual backend failure can now retire this operation once.
    Finished(Result<T, Error>),
}
/// Explicit trusted identity-DH source, analogous to Entropy/native source ports.
/// An implementation is responsible for real backend/source verification; this
/// trait is not a claim that arbitrary user-provided implementations are PILS.
/// Native ports own/poll their actual PILS client and keep its original secret,
/// OperationId and exact Identity/MQ internally. There is no raw-result accept API.
pub trait Port<'id> {
    /// Original immutable source binding, retained even during source retirement.
    fn source(&self) -> Source<'id>;
    /// Check Request::admission before admitting this exact request at most once.
    /// A revoked lease/candidate cannot start IO even if never previously submitted.
    /// Err means it was not
    /// admitted and no hidden backend operation will later claim completion.
    fn submit(&mut self, request: Request<'id>) -> Result<(), Error>;
    /// Invoke accept at most once with the original actual SHA512 DH result,
    /// only after original source/identity/operation and physical request checks.
    /// The borrowed secret cannot escape unless a trusted callback explicitly
    /// copies it. Native providers erase it on every completion/drop/refusal.
    /// Outer Err does not assert retirement; Finished does assert original actual
    /// result/request ownership settled, even when the backend/callback failed.
    fn finish<T>(
        &mut self,
        request: Request<'id>,
        accept: impl FnOnce(&[u8; 64]) -> Result<T, Error>,
    ) -> Result<Completion<T>, Error>;
    /// Stop/drain only this original admitted job after candidate cancellation,
    /// expiry or controller close. true requires actual original retirement;
    /// false retains its ownership. No synthetic completion or replacement job.
    fn retire(&mut self, request: Request<'id>) -> Result<bool, Error>;
}
