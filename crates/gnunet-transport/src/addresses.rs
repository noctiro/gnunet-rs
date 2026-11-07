//! Bounded original communicator address ownership and local publication leases.
//! A publication's full write is not a PILS application acknowledgement.
use crate::ClientId;
use alloc::{sync::Arc, vec::Vec};
use gnunet_types::Error;
/// One admitted physical ADD, including a duplicate of the same wire id/bytes.
/// This private engine brand is never serialized or recovered from a cache.
#[derive(Clone, Debug)]
pub struct AddressLease {
    scope: Arc<()>,
    serial: u64,
}
impl PartialEq for AddressLease {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.scope, &other.scope) && self.serial == other.serial
    }
}
impl Eq for AddressLease {}
/// One engine-branded original aggregate revision; never a wire identifier.
#[derive(Clone, Debug)]
pub struct PublicationId {
    scope: Arc<()>,
    revision: u64,
}
impl PartialEq for PublicationId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.scope, &other.scope) && self.revision == other.revision
    }
}
impl Eq for PublicationId {}
struct Entry {
    lease: AddressLease,
    owner: ClientId,
    id: u32,
    native: Vec<u8>,
    uri: Vec<u8>,
    network: u32,
    validity: u64,
}
/// Original still-owned local address, including its unchanged lifetime hint.
#[non_exhaustive]
pub struct LocalAddress<'a> {
    original: &'a Entry,
    /// Original admitted ADD, distinct even when all its wire fields repeat.
    pub lease: &'a AddressLease,
    /// Original physical communicator.
    pub owner: &'a ClientId,
    /// Official local address identifier.
    pub id: u32,
    /// Original native human-readable bytes.
    pub address: &'a [u8],
    /// Checked corresponding HELLO URI.
    pub uri: &'a [u8],
    /// Original network hint.
    pub network: u32,
    /// Original relative expected lifetime; ownership ends on delete/EOF.
    pub validity: u64,
}
impl LocalAddress<'_> {
    pub(crate) fn is_original(&self) -> bool {
        self.original.lease == *self.lease
            && self.original.owner == *self.owner
            && self.original.id == self.id
            && self.original.native.as_slice() == self.address
            && self.original.uri.as_slice() == self.uri
            && self.original.network == self.network
            && self.original.validity == self.validity
    }
}
/// Borrowed current aggregate. Admission must copy its original bytes before claim.
pub struct Publication<'a> {
    id: PublicationId,
    entries: &'a [Entry],
}
impl Publication<'_> {
    /// Original revision, distinct from a future replacement.
    pub fn id(&self) -> &PublicationId {
        &self.id
    }
    /// All currently owned original records. Duplicate wire IDs are legal on their
    /// original MQ; the normal reference library currently transmits aid0 on add.
    pub fn records(&self) -> impl Iterator<Item = LocalAddress<'_>> {
        records(self.entries)
    }
    /// Unique current URIs; withdrawing one owner cannot erase another's address.
    pub fn uris(&self) -> impl Iterator<Item = &[u8]> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(i, e)| !self.entries[..*i].iter().any(|p| p.uri == e.uri))
            .map(|(_, e)| e.uri.as_slice())
    }
}
/// One original complete ADD consumed with a visible local resource refusal.
/// No wire acknowledgement or remote delivery is implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressRejection {
    /// Original physical communicator owner, never a replacement.
    pub client: ClientId,
    /// Original communicator address id, including valid duplicate zero ids.
    pub address_id: u32,
    /// Local quota/allocation refusal; the accepted set is unchanged.
    pub reason: Error,
}

/// Safe serialized URI-byte bound, including each NUL, for the owned book.
/// A native address has n>=2 bytes (`a-` is the shortest valid form), its URI
/// has n+2, so the book charges2n+2 and serialization usesn+3. For k records,
/// k<=min(maximum_records,maximum_owned_bytes/6) and bytes<=floor(budget/2)+2k.
/// Deduplication can only reduce this bound; no live address is truncated.
pub fn maximum_serialized_bytes(
    maximum_records: usize,
    maximum_owned_bytes: usize,
) -> Result<usize, Error> {
    let records = maximum_records.min(maximum_owned_bytes / 6);
    if records == 0 {
        return Ok(0);
    }
    (maximum_owned_bytes / 2)
        .checked_add(records.checked_mul(2).ok_or(Error::Capacity)?)
        .ok_or(Error::Capacity)
}

pub(crate) struct Book {
    scope: Arc<()>,
    entries: Vec<Entry>,
    maximum: usize,
    bytes: usize,
    maximum_bytes: usize,
    revision: u64,
    settled: u64,
    inflight: Option<u64>,
    poisoned: bool,
    last_lease: u64,
}
impl Book {
    pub(crate) fn new(scope: Arc<()>, maximum: usize, maximum_bytes: usize) -> Result<Self, Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            scope,
            entries,
            maximum,
            bytes: 0,
            maximum_bytes,
            revision: 0,
            settled: 0,
            inflight: None,
            poisoned: false,
            last_lease: 0,
        })
    }
    pub(crate) fn add(
        &mut self,
        owner: &ClientId,
        id: u32,
        native: &[u8],
        network: u32,
        validity: u64,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Capacity);
        }
        if native.contains(&0) {
            return Err(Error::Malformed);
        }
        let prefix = gnunet_hello::address_to_prefix(native).ok_or(Error::Malformed)?;
        let body = &native[prefix.len() + 1..];
        let uri_len = native.len().checked_add(2).ok_or(Error::Overflow)?;
        let charge = native.len().checked_add(uri_len).ok_or(Error::Overflow)?;
        let bytes = self.bytes.checked_add(charge).ok_or(Error::Capacity)?;
        if self.entries.len() == self.maximum || bytes > self.maximum_bytes {
            return Err(Error::Capacity);
        }
        let mut uri = Vec::new();
        uri.try_reserve_exact(uri_len)
            .map_err(|_| Error::Capacity)?;
        uri.extend_from_slice(prefix);
        uri.extend_from_slice(b"://");
        uri.extend_from_slice(body);
        gnunet_hello::Address::from_uri(&uri)?;
        let changed = !self.entries.iter().any(|e| e.uri == uri);
        let revision = if changed {
            self.revision.checked_add(1).ok_or(Error::Capacity)?
        } else {
            self.revision
        };
        let mut original = Vec::new();
        original
            .try_reserve_exact(native.len())
            .map_err(|_| Error::Capacity)?;
        original.extend_from_slice(native);
        let serial = self.last_lease.checked_add(1).ok_or(Error::Capacity)?;
        self.entries.push(Entry {
            lease: AddressLease {
                scope: self.scope.clone(),
                serial,
            },
            owner: owner.clone(),
            id,
            native: original,
            uri,
            network,
            validity,
        });
        self.bytes = bytes;
        self.revision = revision;
        self.last_lease = serial;
        Ok(())
    }
    pub(crate) fn records(&self) -> impl Iterator<Item = LocalAddress<'_>> {
        records(&self.entries)
    }
    pub(crate) fn snapshot(&self) -> Result<Publication<'_>, Error> {
        if self.poisoned {
            return Err(Error::Capacity);
        }
        Ok(Publication {
            id: PublicationId {
                scope: self.scope.clone(),
                revision: self.revision,
            },
            entries: &self.entries,
        })
    }
    pub(crate) fn contains(&self, lease: &AddressLease) -> bool {
        self.entries.iter().any(|entry| entry.lease == *lease)
    }
    pub(crate) fn remove(&mut self, owner: &ClientId, id: u32) {
        // The source server's head-first matching removes the newest duplicate ID.
        let Some(i) = self
            .entries
            .iter()
            .rposition(|e| e.owner == *owner && e.id == id)
        else {
            return;
        };
        let changed = !self
            .entries
            .iter()
            .enumerate()
            .any(|(j, e)| j != i && e.uri == self.entries[i].uri);
        let e = self.entries.remove(i);
        self.bytes -= e.native.len() + e.uri.len();
        if changed {
            self.changed();
        }
    }
    pub(crate) fn close(&mut self, owner: &ClientId) {
        let changed = self.entries.iter().filter(|e| e.owner == *owner).any(|e| {
            !self
                .entries
                .iter()
                .any(|p| p.owner != *owner && p.uri == e.uri)
        });
        self.entries.retain(|e| {
            if e.owner == *owner {
                self.bytes -= e.native.len() + e.uri.len();
                false
            } else {
                true
            }
        });
        if changed {
            self.changed();
        }
    }
    fn changed(&mut self) {
        match self.revision.checked_add(1) {
            Some(r) => self.revision = r,
            None => self.poisoned = true,
        }
    }
    pub(crate) fn matches(&self, hello: gnunet_hello::Hello<'_>) -> bool {
        hello
            .addresses()
            .all(|a| self.entries.iter().any(|e| e.uri == a.as_bytes()))
            && self
                .entries
                .iter()
                .all(|e| hello.addresses().any(|a| a.as_bytes() == e.uri))
    }
    pub(crate) fn refresh(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Capacity);
        }
        self.revision = self.revision.checked_add(1).ok_or(Error::Capacity)?;
        Ok(())
    }
    pub(crate) fn publication(&self) -> Result<Option<Publication<'_>>, Error> {
        if self.poisoned {
            return Err(Error::Capacity);
        }
        Ok(
            (self.inflight.is_none() && self.revision != self.settled).then(|| Publication {
                id: PublicationId {
                    scope: self.scope.clone(),
                    revision: self.revision,
                },
                entries: &self.entries,
            }),
        )
    }
    pub(crate) fn claim(&mut self, id: &PublicationId) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::Capacity);
        }
        if !Arc::ptr_eq(&id.scope, &self.scope)
            || id.revision != self.revision
            || self.inflight.is_some()
            || self.revision == self.settled
        {
            return Err(Error::Stale);
        }
        self.inflight = Some(id.revision);
        Ok(())
    }
    pub(crate) fn written(&mut self, id: &PublicationId) -> Result<(), Error> {
        if !Arc::ptr_eq(&id.scope, &self.scope) || self.inflight != Some(id.revision) {
            return Err(Error::Stale);
        }
        self.inflight = None;
        self.settled = id.revision;
        Ok(())
    }
}
fn records(entries: &[Entry]) -> impl Iterator<Item = LocalAddress<'_>> {
    entries.iter().map(|e| LocalAddress {
        original: e,
        lease: &e.lease,
        owner: &e.owner,
        id: e.id,
        address: &e.native,
        uri: &e.uri,
        network: e.network,
        validity: e.validity,
    })
}
