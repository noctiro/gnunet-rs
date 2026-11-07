//! Bounded original address-validation signing effects; no private wire fields.
use crate::{ClientId, PeerId, p2p::Validation};
use alloc::{collections::VecDeque, sync::Arc};
use gnunet_types::Error;

/// How a signer authorizes an original purpose35 snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationMode {
    /// Sign synchronously while the caller holds the current identity capability.
    Immediate,
    /// Retain an original effect for an asynchronous identity service.
    Deferred,
}
/// Instance-branded original effect identity; never an official request number.
#[derive(Clone, Debug)]
pub struct ValidationId {
    instance: Arc<()>,
    serial: u64,
}
impl PartialEq for ValidationId {
    fn eq(&self, other: &Self) -> bool {
        self.serial == other.serial && Arc::ptr_eq(&self.instance, &other.instance)
    }
}
impl Eq for ValidationId {}
/// Immutable original signature intent. Cloning copies fixed metadata and retains
/// the original branded owner; it does not grant authority to a replacement MQ.
#[derive(Clone, Debug)]
pub struct ValidationRequest {
    pub(crate) id: ValidationId,
    pub(crate) owner: ClientId,
    pub(crate) peer: PeerId,
    pub(crate) route: u64,
    signer: PeerId,
    region: [u8; 48],
    origin: u64,
    expires: u64,
}
impl ValidationRequest {
    /// Original instance/operation token, not a wire ID.
    #[must_use]
    pub fn id(&self) -> &ValidationId {
        &self.id
    }
    /// Original physical communicator IPC owner.
    #[must_use]
    pub fn client(&self) -> &ClientId {
        &self.owner
    }
    /// Original remote destination.
    #[must_use]
    pub const fn peer(&self) -> PeerId {
        self.peer
    }
    /// Exact local identity required by this engine epoch.
    #[must_use]
    pub const fn signer(&self) -> PeerId {
        self.signer
    }
    /// Complete original purpose35 region, including size and purpose headers.
    #[must_use]
    pub const fn region(&self) -> &[u8; 48] {
        &self.region
    }
    pub(crate) const fn expired(&self, now: u64) -> bool {
        self.expires <= now
    }
    pub(crate) fn response(&self, signature: [u8; 64]) -> [u8; 120] {
        let mut nonce = [0; 32];
        nonce.copy_from_slice(&self.region[16..48]);
        let mut validity = [0; 8];
        validity.copy_from_slice(&self.region[8..16]);
        Validation {
            signature,
            nonce,
            origin: self.origin,
            validity: u64::from_be_bytes(validity),
        }
        .encode()
    }
}
pub(crate) struct Context {
    pub owner: ClientId,
    pub peer: PeerId,
    pub route: u64,
    pub signer: PeerId,
    pub nonce: [u8; 32],
    pub origin: u64,
    pub lifetime: u64,
    pub now: u64,
}
struct Entry {
    request: ValidationRequest,
    claimed: bool,
}
pub(crate) struct Requests {
    instance: Arc<()>,
    serial: u64,
    maximum: usize,
    entries: VecDeque<Entry>,
}
impl Requests {
    pub fn new(instance: Arc<()>, messages: usize, bytes: usize) -> Result<Self, Error> {
        let maximum = messages.min(bytes / 48);
        let mut entries = VecDeque::new();
        entries
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            instance,
            serial: 0,
            maximum,
            entries,
        })
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn stage(&mut self, context: Context) -> Result<bool, Error> {
        if self.entries.len() == self.maximum {
            return Ok(false);
        }
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        // This is a finite local retention policy, not an official wire timeout.
        let expires = context.now.saturating_add(60_000_000);
        let request = ValidationRequest {
            id: ValidationId {
                instance: self.instance.clone(),
                serial,
            },
            owner: context.owner,
            peer: context.peer,
            route: context.route,
            signer: context.signer,
            region: Validation::signed_region(&context.nonce, context.lifetime),
            origin: context.origin,
            expires,
        };
        self.entries.push_back(Entry {
            request,
            claimed: false,
        });
        self.serial = serial;
        Ok(true)
    }
    pub fn next(&self) -> Option<&ValidationRequest> {
        self.entries.iter().find(|e| !e.claimed).map(|e| &e.request)
    }
    pub fn get(&self, id: &ValidationId) -> Option<&ValidationRequest> {
        self.entries
            .iter()
            .find(|e| e.request.id == *id)
            .map(|e| &e.request)
    }
    pub fn claim(&mut self, id: &ValidationId) -> Result<(), Error> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.request.id == *id)
            .ok_or(Error::Stale)?;
        if entry.claimed {
            return Err(Error::Stale);
        }
        entry.claimed = true;
        Ok(())
    }
    pub fn remove(&mut self, id: &ValidationId) -> Result<(), Error> {
        let index = self
            .entries
            .iter()
            .position(|e| e.request.id == *id)
            .ok_or(Error::Stale)?;
        self.entries.remove(index);
        Ok(())
    }
    pub fn retire(&mut self, live: impl Fn(&ClientId, u64) -> bool, now: u64) {
        self.entries
            .retain(|e| e.request.expires > now && live(&e.request.owner, e.request.route));
    }
}
