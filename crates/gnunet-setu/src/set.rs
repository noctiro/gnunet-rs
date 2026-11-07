//! Actual immutable typed elements and inexpensive stable operation snapshots.
use crate::{
    ibf::{Key, Order},
    wire::{Abi, Element as Borrowed},
};
use alloc::{rc::Rc, vec::Vec};
use gnunet_crypto::hash512_parts;
use gnunet_types::Error;
/// One owned, immutable source element; no operation can mutate a prior snapshot.
#[derive(Debug)]
pub struct Element {
    kind: u16,
    data: Vec<u8>,
    hash: [u8; 64],
    key: Key,
}
impl Element {
    /// Copy one bounded element and compute the source's actual native16
    /// size/type + data SHA512, then the official HKDF-derived IBF key.
    pub fn new(element: Borrowed<'_>, abi: Abi) -> Result<Self, Error> {
        abi.validate()?;
        let size = u16::try_from(element.data.len()).map_err(|_| Error::TooLarge)?;
        if element.data.len() > 65527 {
            return Err(Error::TooLarge);
        }
        let size = abi.order.u16(size);
        let ty = abi.order.u16(element.kind);
        let hash = hash512_parts(&[&size, &ty, element.data]);
        let order = match abi.order {
            crate::wire::Order::Little => Order::Little,
            crate::wire::Order::Big => Order::Big,
        };
        let key = Key::from_element_hash(&hash, order)?;
        let mut data = Vec::new();
        data.try_reserve_exact(element.data.len())
            .map_err(|_| Error::Capacity)?;
        data.extend_from_slice(element.data);
        Ok(Self {
            kind: element.kind,
            data,
            hash,
            key,
        })
    }
    /// Exact official borrowed typed data.
    #[must_use]
    pub fn borrowed(&self) -> Borrowed<'_> {
        Borrowed {
            kind: self.kind,
            data: &self.data,
        }
    }
    /// Actual source-compatible SHA512 element fingerprint, not peer authority.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 64] {
        &self.hash
    }
    /// Actual unsalted64-bit IBF key, not an element uniqueness guarantee.
    #[must_use]
    pub const fn key(&self) -> Key {
        self.key
    }
}
/// Explicit per-set/operation content resources.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum unique elements retained in a set or union snapshot.
    pub elements: usize,
    /// Maximum actual owned element bytes.
    pub bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            elements: 4096,
            bytes: 16 * 1024 * 1024,
        }
    }
}
/// Mutable local set. A later add/remove never changes a live snapshot.
pub struct Set {
    pub(crate) elements: Vec<Rc<Element>>,
    bytes: usize,
    limits: Limits,
    abi: Abi,
    generation: u64,
}
impl Set {
    /// Reserve bounded metadata; allocate no maximum-sized per-element payload.
    pub fn new(limits: Limits, abi: Abi) -> Result<Self, Error> {
        abi.validate()?;
        if limits.elements == 0 {
            return Err(Error::Capacity);
        }
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(limits.elements)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            elements,
            bytes: 0,
            limits,
            abi,
            generation: 0,
        })
    }
    /// Add a typed element once; duplicate identical elements are harmless.
    pub fn add(&mut self, element: Borrowed<'_>) -> Result<bool, Error> {
        let owned = Element::new(element, self.abi)?;
        match self
            .elements
            .binary_search_by_key(owned.hash(), |element| *element.hash())
        {
            Ok(index) => {
                if self.elements[index].borrowed() != element {
                    return Err(Error::Authentication);
                }
                Ok(false)
            }
            Err(index) => {
                let bytes = self
                    .bytes
                    .checked_add(element.data.len())
                    .ok_or(Error::Capacity)?;
                if self.elements.len() == self.limits.elements || bytes > self.limits.bytes {
                    return Err(Error::Capacity);
                }
                let next = self.generation.checked_add(1).ok_or(Error::Overflow)?;
                self.elements.insert(index, Rc::new(owned));
                self.bytes = bytes;
                self.generation = next;
                Ok(true)
            }
        }
    }
    /// Internal Rust mutation preserving existing snapshots. Active SETU has no
    /// REMOVE IPC; a host must not invent a new wire command for this method.
    pub fn remove(&mut self, element: Borrowed<'_>) -> Result<bool, Error> {
        let owned = Element::new(element, self.abi)?;
        let Ok(index) = self
            .elements
            .binary_search_by_key(owned.hash(), |element| *element.hash())
        else {
            return Ok(false);
        };
        if self.elements[index].borrowed() != element {
            return Err(Error::Authentication);
        }
        let next = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        let removed = self.elements.remove(index);
        self.bytes -= removed.data.len();
        self.generation = next;
        Ok(true)
    }
    /// Freeze exact element membership using shared immutable element owners.
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        let mut elements = Vec::new();
        elements
            .try_reserve_exact(self.elements.len())
            .map_err(|_| Error::Capacity)?;
        elements.extend(self.elements.iter().cloned());
        Ok(Snapshot {
            elements,
            bytes: self.bytes,
            generation: self.generation,
            abi: self.abi,
        })
    }
    /// Current distinct element count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.elements.len()
    }
    /// Whether this set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
}
/// Original immutable membership and source generation for one operation.
pub struct Snapshot {
    pub(crate) elements: Vec<Rc<Element>>,
    pub(crate) bytes: usize,
    pub(crate) generation: u64,
    pub(crate) abi: Abi,
}
impl Snapshot {
    /// Original element count, independent of later local mutations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.elements.len()
    }
    /// Whether the original snapshot is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }
    /// Original local membership generation, not a peer/wire sequence number.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}
