//! Immutable element bodies shared by independent mutation/operation views.
use crate::allocation::Growth;
use crate::wire::{Abi, Element};
use alloc::{rc::Rc, vec::Vec};
use core::{cell::Cell, mem::size_of};
use gnunet_types::Error;
/// Explicit local membership and allocation bounds, independent of wire fields.
#[derive(Clone, Copy, Debug)]
pub struct ContentLimits {
    /// Maximum distinct typed elements in one set or original snapshot.
    pub elements: usize,
    /// Maximum sum of payload capacities retained by one logical view.
    pub body_bytes: usize,
    /// Maximum single opaque payload accepted by the standard element frame.
    pub element_bytes: usize,
}
impl Default for ContentLimits {
    fn default() -> Self {
        Self {
            elements: 8192,
            body_bytes: 8 * 1024 * 1024,
            element_bytes: 65527,
        }
    }
}
impl ContentLimits {
    pub(crate) fn validate(self) -> Result<(), Error> {
        if self.elements == 0 || u32::try_from(self.elements).is_err() || self.element_bytes > 65527
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}
/// One accounting domain owns no bodies. Each actual Body allocation holds one
/// lease, so arbitrary snapshot/result/drop order needs no pointer side table.
pub(crate) struct BodyLedger {
    allocated: Cell<usize>,
}
impl BodyLedger {
    pub(crate) fn new() -> Rc<Self> {
        Rc::new(Self {
            allocated: Cell::new(0),
        })
    }
    pub(crate) fn allocation_bytes() -> usize {
        size_of::<Self>() + 2 * size_of::<usize>()
    }
    pub(crate) fn charged_bytes(&self) -> Result<usize, Error> {
        self.allocated
            .get()
            .checked_add(Self::allocation_bytes())
            .ok_or(Error::Overflow)
    }
    pub(crate) fn share(ledger: &Rc<Self>) -> Result<Rc<Self>, Error> {
        if Rc::strong_count(ledger) >= usize::MAX / 2 {
            return Err(Error::Overflow);
        }
        Ok(ledger.clone())
    }
}
struct BodyAllocation {
    ledger: Rc<BodyLedger>,
    bytes: usize,
}
impl Drop for BodyAllocation {
    #[expect(
        clippy::expect_used,
        reason = "A private non-Clone lease is created once per charged Body and refunded only by its final drop; underflow is an internal accounting defect, never an admissible input"
    )]
    fn drop(&mut self) {
        // Only a newly created Body owns a lease; cloning its Rc never creates
        // another one. Its last drop is the sole refund, including on failure.
        self.ledger.allocated.set(
            self.ledger
                .allocated
                .get()
                .checked_sub(self.bytes)
                .expect("original body allocation lease"),
        );
    }
}
pub(crate) struct Body {
    pub(crate) kind: u16,
    pub(crate) data: Vec<u8>,
    pub(crate) hash: [u8; 64],
    // Last field: payload drops before the lease refunds its actual capacity.
    _allocation: BodyAllocation,
}
impl Body {
    pub(crate) fn allocation_overhead() -> usize {
        size_of::<Self>() + 2 * size_of::<usize>()
    }
    /// The caller must preclaim payload capacity and this Rc allocation in its
    /// original Growth turn before allocating or transferring either buffer.
    pub(crate) fn new(
        kind: u16,
        data: Vec<u8>,
        hash: [u8; 64],
        ledger: &Rc<BodyLedger>,
    ) -> Result<Rc<Self>, Error> {
        let bytes = data
            .capacity()
            .checked_add(Self::allocation_overhead())
            .ok_or(Error::Overflow)?;
        let allocated = ledger
            .allocated
            .get()
            .checked_add(bytes)
            .ok_or(Error::Overflow)?;
        let ledger = BodyLedger::share(ledger)?;
        ledger.allocated.set(allocated);
        Ok(Rc::new(Self {
            kind,
            data,
            hash,
            _allocation: BodyAllocation { ledger, bytes },
        }))
    }
    pub(crate) fn element(&self) -> Element<'_> {
        Element {
            element_type: self.kind,
            data: &self.data,
        }
    }
}
pub(crate) fn hash(element: Element<'_>, abi: Abi) -> Result<[u8; 64], Error> {
    abi.validate()?;
    let prefix = element.fingerprint_prefix(abi.order)?;
    Ok(gnunet_crypto::hash512_parts(&[&prefix, element.data]))
}
fn copy_members(source: &[Rc<Body>]) -> Result<Vec<Rc<Body>>, Error> {
    // Preflight refcount increments before allocation/any ownership changes.
    if source.iter().any(|b| Rc::strong_count(b) >= usize::MAX / 2) {
        return Err(Error::Overflow);
    }
    let mut members = Vec::new();
    members
        .try_reserve_exact(source.len())
        .map_err(|_| Error::Capacity)?;
    members.extend(source.iter().cloned());
    Ok(members)
}
fn reference_charge(len: usize, capacity: usize, body_bytes: usize) -> Result<usize, Error> {
    capacity
        .checked_mul(size_of::<Rc<Body>>())
        .and_then(|n| {
            len.checked_mul(Body::allocation_overhead())
                .and_then(|v| n.checked_add(v))
        })
        .and_then(|n| n.checked_add(body_bytes))
        .and_then(|n| n.checked_add(BodyLedger::allocation_bytes()))
        .ok_or(Error::Overflow)
}
/// One local typed set. Mutations never modify a prior snapshot or lazy copy.
/// Body payloads are allocated only when a new distinct element is accepted.
pub struct Content {
    members: Vec<Rc<Body>>,
    body_bytes: usize,
    limits: ContentLimits,
    abi: Abi,
    pub(crate) generation: u64,
    ledger: Rc<BodyLedger>,
}
impl Content {
    /// Create bounded empty membership without reserving the maximum element count.
    pub fn new(limits: ContentLimits, abi: Abi) -> Result<Self, Error> {
        limits.validate()?;
        abi.validate()?;
        Self::with_ledger(limits, abi, BodyLedger::new())
    }
    pub(crate) fn with_ledger(
        limits: ContentLimits,
        abi: Abi,
        ledger: Rc<BodyLedger>,
    ) -> Result<Self, Error> {
        limits.validate()?;
        abi.validate()?;
        Ok(Self {
            members: Vec::new(),
            body_bytes: 0,
            limits,
            abi,
            generation: 0,
            ledger,
        })
    }
    /// Add one distinct original typed element. Duplicate content performs no
    /// payload allocation and does not advance membership generation.
    pub fn add(&mut self, element: Element<'_>) -> Result<bool, Error> {
        self.add_with_allowance(element, usize::MAX)
    }
    pub(crate) fn add_with_allowance(
        &mut self,
        element: Element<'_>,
        additional: usize,
    ) -> Result<bool, Error> {
        if element.data.len() > self.limits.element_bytes {
            return Err(Error::TooLarge);
        }
        let fingerprint = hash(element, self.abi)?;
        match self.members.binary_search_by_key(&fingerprint, |e| e.hash) {
            Ok(i) => {
                let original = self.members[i].element();
                if original.element_type != element.element_type || original.data != element.data {
                    return Err(Error::Authentication);
                }
                Ok(false)
            }
            Err(i) => {
                if self.members.len() == self.limits.elements {
                    return Err(Error::Capacity);
                }
                let generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
                if element.data.len() > self.limits.body_bytes.saturating_sub(self.body_bytes) {
                    return Err(Error::Capacity);
                }
                let mut growth = Growth::new(additional);
                growth.claim(Body::allocation_overhead())?;
                let mut data = growth.vector(element.data.len())?;
                let bytes = self
                    .body_bytes
                    .checked_add(data.capacity())
                    .ok_or(Error::Overflow)?;
                if bytes > self.limits.body_bytes {
                    return Err(Error::Capacity);
                }
                // Prepare only actual geometric growth; no mutation or full
                // per-add membership clone precedes the final quota decision.
                let mut replacement = None;
                let capacity = self.members.capacity();
                if self.members.len() == capacity {
                    let target = capacity
                        .max(4)
                        .checked_mul(2)
                        .ok_or(Error::Overflow)?
                        .min(self.limits.elements)
                        .max(self.members.len() + 1);
                    let prepared = growth.vector(target)?;
                    if prepared.capacity() > self.limits.elements {
                        return Err(Error::Capacity);
                    }
                    replacement = Some(prepared);
                }
                data.extend_from_slice(element.data);
                let body = Body::new(element.element_type, data, fingerprint, &self.ledger)?;
                if let Some(mut prepared) = replacement {
                    prepared.append(&mut self.members);
                    self.members = prepared;
                }
                self.members.insert(i, body);
                self.body_bytes = bytes;
                self.generation = generation;
                Ok(true)
            }
        }
    }
    /// Remove one exact typed element without changing older copied memberships.
    pub fn remove(&mut self, element: Element<'_>) -> Result<bool, Error> {
        let fingerprint = hash(element, self.abi)?;
        let Ok(i) = self.members.binary_search_by_key(&fingerprint, |e| e.hash) else {
            return Ok(false);
        };
        let original = self.members[i].element();
        if original.element_type != element.element_type || original.data != element.data {
            return Err(Error::Authentication);
        }
        let generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        let removed = self.members.remove(i);
        self.body_bytes -= removed.data.capacity();
        self.generation = generation;
        Ok(true)
    }
    /// Freeze exact current membership while sharing original immutable bodies.
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        let ledger = BodyLedger::share(&self.ledger)?;
        Ok(Snapshot {
            members: copy_members(&self.members)?,
            abi: self.abi,
            generation: self.generation,
            body_bytes: self.body_bytes,
            ledger,
        })
    }
    /// Copy the source's membership at actual lazy-connect time. Subsequent
    /// changes to either set are independent; no C generation layout is copied.
    pub fn fork(&self) -> Result<Self, Error> {
        let ledger = BodyLedger::share(&self.ledger)?;
        Ok(Self {
            members: copy_members(&self.members)?,
            body_bytes: self.body_bytes,
            limits: self.limits,
            abi: self.abi,
            generation: self.generation,
            ledger,
        })
    }
    /// Current unique typed member count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }
    /// Whether the original membership is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
    /// Conservative reference footprint, counting each shared payload once per
    /// view, including its accounting-domain allocation. Summing view charges
    /// is an upper bound, not unique heap usage. Service uses its shared ledger
    /// once and each view's membership metadata separately.
    pub fn charged_bytes(&self) -> Result<usize, Error> {
        reference_charge(self.members.len(), self.members.capacity(), self.body_bytes)
    }
    pub(crate) fn metadata_bytes(&self) -> Result<usize, Error> {
        self.members
            .capacity()
            .checked_mul(size_of::<Rc<Body>>())
            .ok_or(Error::Overflow)
    }
}
/// Immutable original operation/iteration membership. It cannot expose mutable
/// payloads or adopt elements added to the original set after snapshot admission.
pub struct Snapshot {
    pub(crate) members: Vec<Rc<Body>>,
    abi: Abi,
    generation: u64,
    body_bytes: usize,
    pub(crate) ledger: Rc<BodyLedger>,
}
impl Snapshot {
    /// Independently retain this exact original membership, sharing payloads.
    pub fn try_clone(&self) -> Result<Self, Error> {
        let ledger = BodyLedger::share(&self.ledger)?;
        Ok(Self {
            members: copy_members(&self.members)?,
            abi: self.abi,
            generation: self.generation,
            body_bytes: self.body_bytes,
            ledger,
        })
    }
    /// Original unique element count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }
    /// Whether this original membership was empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
    /// Original diagnostic generation, not an operation/source capability.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    /// Original native element-hash and peer ABI selection.
    #[must_use]
    pub const fn abi(&self) -> Abi {
        self.abi
    }
    /// Borrow one exact original typed element by its stable snapshot index.
    #[must_use]
    pub fn element(&self, index: usize) -> Option<Element<'_>> {
        self.members.get(index).map(|b| b.element())
    }
    /// Borrow the standard original native16-prefixed SHA512 fingerprint.
    #[must_use]
    pub fn hash(&self, index: usize) -> Option<&[u8; 64]> {
        self.members.get(index).map(|b| &b.hash)
    }
    /// Find an original fingerprint without treating collisions as new authority.
    #[must_use]
    pub fn find_hash(&self, hash: &[u8; 64]) -> Option<usize> {
        self.members.binary_search_by_key(hash, |b| b.hash).ok()
    }
    /// Iterate only exact original typed members without allocation or encoding.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = Element<'_>> {
        self.members.iter().map(|b| b.element())
    }
    /// Conservative complete view footprint, including shared body allocations
    /// and its ledger allocation. This is independent of other live views.
    pub fn charged_bytes(&self) -> Result<usize, Error> {
        reference_charge(self.members.len(), self.members.capacity(), self.body_bytes)
    }
    pub(crate) fn metadata_bytes(&self) -> Result<usize, Error> {
        self.members
            .capacity()
            .checked_mul(size_of::<Rc<Body>>())
            .ok_or(Error::Overflow)
    }
}
