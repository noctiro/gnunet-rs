//! Optional explicit aggregate quota for a single immutable zeroizing allocation
//! per owned object/list/frame. No implicit clone, key cache, or background task.
use crate::{
    Attribute, AttributeList, Credential, CredentialList, ListLimits, Presentation,
    PresentationList, Ticket, Uri,
    ipc::{Request, Response},
};
use alloc::{rc::Rc, vec::Vec};
use core::{cell::Cell, fmt, mem::size_of};
use gnunet_types::Error;
use zeroize::Zeroizing;

/// Aggregate immutable-storage quota shared by one Pool and its original owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum simultaneously owned allocations.
    pub objects: usize,
    /// Maximum charged Vec CAPACITY plus per-owner metadata. The fixed shared
    /// budget block is charged too; caller stack and allocator headers are excluded.
    pub bytes: usize,
    /// Maximum actual payload capacity of any one allocation.
    pub object_bytes: usize,
}
/// Current accounting, including original owners that outlive their Pool.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Usage {
    /// Number of immutable original owners.
    pub objects: usize,
    /// Actual payload capacity and fixed Rust metadata charged to these owners.
    pub bytes: usize,
}
struct State {
    limits: Limits,
    usage: Cell<Usage>,
}
/// Explicit non-threaded allocation domain. Dropping it never invalidates borrowed
/// data held by an existing Owned value; that value retains its original quota.
pub struct Pool {
    state: Rc<State>,
}
impl Pool {
    /// Create one fixed budget block. The global Rust allocator may abort on OOM
    /// for this fixed Rc metadata; variable payload allocation is fallible.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        let fixed = size_of::<State>()
            .checked_add(2 * size_of::<usize>())
            .ok_or(Error::Overflow)?;
        if limits.objects == 0 || limits.object_bytes == 0 || limits.bytes < fixed {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            state: Rc::new(State {
                limits,
                usage: Cell::new(Usage {
                    objects: 0,
                    bytes: fixed,
                }),
            }),
        })
    }
    /// Exact currently charged payload capacity/metadata, including live owners.
    pub fn usage(&self) -> Usage {
        self.state.usage.get()
    }
    /// Original immutable limits.
    pub fn limits(&self) -> Limits {
        self.state.limits
    }
    /// Serialize one attribute once into zeroizing immutable storage.
    pub fn attribute(&self, value: Attribute<'_>) -> Result<Owned, Error> {
        self.allocate(Kind::Attribute, value.encoded_len()?, |o| value.encode(o))
    }
    /// Serialize one credential once; no JWT/PABC validation is implied.
    pub fn credential(&self, value: Credential<'_>) -> Result<Owned, Error> {
        self.allocate(Kind::Credential, value.encoded_len()?, |o| value.encode(o))
    }
    /// Serialize one presentation once, without verifying its proof.
    pub fn presentation(&self, value: Presentation<'_>) -> Result<Owned, Error> {
        self.allocate(Kind::Presentation, value.encoded_len()?, |o| {
            value.encode(o)
        })
    }
    /// Serialize one sensitive capability, including its NUL terminator.
    pub fn ticket(&self, value: Ticket<'_>) -> Result<Owned, Error> {
        self.allocate(Kind::Ticket, value.encoded_len(), |o| value.encode(o))
    }
    /// Serialize one complete original request, keeping every private byte redacted.
    pub fn request(&self, value: Request<'_>) -> Result<Owned, Error> {
        self.allocate(Kind::Request, value.encoded_len()?, |o| value.encode(o))
    }
    /// Serialize one complete response without inventing a result or receipt.
    pub fn response(&self, value: Response<'_>) -> Result<Owned, Error> {
        self.allocate(Kind::Response, value.encoded_len()?, |o| value.encode(o))
    }
    /// Validate then copy one existing exact serialization once. Failure does not
    /// change quota or the original source and creates no partially owned value.
    pub fn copy(&self, kind: Kind, input: &[u8]) -> Result<Owned, Error> {
        validate(kind, input)?;
        self.allocate(kind, input.len(), |out| {
            out.copy_from_slice(input);
            Ok(input.len())
        })
    }
    fn allocate(
        &self,
        kind: Kind,
        len: usize,
        encode: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
    ) -> Result<Owned, Error> {
        let usage = self.state.usage.get();
        let limits = self.state.limits;
        let minimum = len.checked_add(size_of::<Owned>()).ok_or(Error::Overflow)?;
        let minimum_total = usage.bytes.checked_add(minimum).ok_or(Error::Overflow)?;
        if usage.objects >= limits.objects
            || len > limits.object_bytes
            || minimum_total > limits.bytes
        {
            return Err(Error::Capacity);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(len).map_err(|_| Error::Capacity)?;
        let charge = bytes
            .capacity()
            .checked_add(size_of::<Owned>())
            .ok_or(Error::Overflow)?;
        let total = usage.bytes.checked_add(charge).ok_or(Error::Overflow)?;
        if bytes.capacity() > limits.object_bytes || total > limits.bytes {
            return Err(Error::Capacity);
        }
        bytes.resize(len, 0);
        if encode(&mut bytes)? != len {
            return Err(Error::Malformed);
        }
        let objects = usage.objects.checked_add(1).ok_or(Error::Overflow)?;
        self.state.usage.set(Usage {
            objects,
            bytes: total,
        });
        Ok(Owned {
            bytes,
            kind,
            state: Rc::clone(&self.state),
            charge,
        })
    }
}
impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool")
            .field("usage", &self.usage())
            .field("limits", &self.limits())
            .finish()
    }
}
/// Which validated serialization is retained by an immutable Owned value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// One attribute.
    Attribute,
    /// One credential.
    Credential,
    /// One presentation.
    Presentation,
    /// A complete concatenated attribute list.
    Attributes,
    /// A complete concatenated credential list.
    Credentials,
    /// A complete concatenated presentation list.
    Presentations,
    /// A ticket capability, including its final wire NUL.
    Ticket,
    /// An RP URI, including its final wire NUL.
    Uri,
    /// One original complete IPC request.
    Request,
    /// One original complete IPC response.
    Response,
}
/// One validated immutable original allocation. No Clone/Hash/secret Debug or
/// extraction of unzeroized ownership is provided. Typed views borrow this owner.
pub struct Owned {
    bytes: Zeroizing<Vec<u8>>,
    kind: Kind,
    state: Rc<State>,
    charge: usize,
}
impl Owned {
    /// Exact retained serialization kind.
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    /// Logical serialized length, without exposing data in diagnostics.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    /// Whether this is an empty serialized list.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// Explicit sensitive borrow; it cannot outlive or mutate this owner.
    pub fn expose_serialized(&self) -> &[u8] {
        &self.bytes
    }
    /// Attribute view, rejecting a mismatched retained kind.
    pub fn attribute(&self) -> Result<Attribute<'_>, Error> {
        self.require(Kind::Attribute)?;
        Attribute::decode(&self.bytes)
    }
    /// Credential view; not a verification result.
    pub fn credential(&self) -> Result<Credential<'_>, Error> {
        self.require(Kind::Credential)?;
        Credential::decode(&self.bytes)
    }
    /// Presentation view; not a cryptographic proof result.
    pub fn presentation(&self) -> Result<Presentation<'_>, Error> {
        self.require(Kind::Presentation)?;
        Presentation::decode(&self.bytes)
    }
    /// Attribute-list view without copying its items.
    pub fn attributes(&self) -> Result<AttributeList<'_>, Error> {
        self.require(Kind::Attributes)?;
        AttributeList::new(&self.bytes, ListLimits::IPC)
    }
    /// Credential-list view without C's linked-list allocation overhead.
    pub fn credentials(&self) -> Result<CredentialList<'_>, Error> {
        self.require(Kind::Credentials)?;
        CredentialList::new(&self.bytes, ListLimits::IPC)
    }
    /// Presentation-list view without copying credential proofs.
    pub fn presentations(&self) -> Result<PresentationList<'_>, Error> {
        self.require(Kind::Presentations)?;
        PresentationList::new(&self.bytes, ListLimits::IPC)
    }
    /// Ticket capability view.
    pub fn ticket(&self) -> Result<Ticket<'_>, Error> {
        self.require(Kind::Ticket)?;
        Ticket::decode(&self.bytes)
    }
    /// RP URI view.
    pub fn uri(&self) -> Result<Uri<'_>, Error> {
        self.require(Kind::Uri)?;
        Uri::decode(&self.bytes)
    }
    /// Original complete request view, including redacted borrowed key fields.
    pub fn request(&self) -> Result<Request<'_>, Error> {
        self.require(Kind::Request)?;
        Request::decode(&self.bytes)
    }
    /// Original complete response view; raw status words are preserved.
    pub fn response(&self) -> Result<Response<'_>, Error> {
        self.require(Kind::Response)?;
        Response::decode(&self.bytes)
    }
    fn require(&self, kind: Kind) -> Result<(), Error> {
        if self.kind == kind {
            Ok(())
        } else {
            Err(Error::InvalidInput)
        }
    }
}
impl Drop for Owned {
    fn drop(&mut self) {
        let old = self.state.usage.get();
        // Only allocate constructs an owner, exactly once after admission; there
        // is no Clone or public quota mutator. Original quota is returned once.
        self.state.usage.set(Usage {
            objects: old.objects - 1,
            bytes: old.bytes - self.charge,
        });
        // Zeroizing<Vec> then erases initialized bytes and spare capacity before
        // allocator release; immutable views cannot outlive this Drop in safe Rust.
    }
}
impl fmt::Debug for Owned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Owned")
            .field("kind", &self.kind)
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
fn validate(kind: Kind, input: &[u8]) -> Result<(), Error> {
    match kind {
        Kind::Attribute => {
            Attribute::decode(input)?;
        }
        Kind::Credential => {
            Credential::decode(input)?;
        }
        Kind::Presentation => {
            Presentation::decode(input)?;
        }
        Kind::Attributes => {
            AttributeList::new(input, ListLimits::IPC)?;
        }
        Kind::Credentials => {
            CredentialList::new(input, ListLimits::IPC)?;
        }
        Kind::Presentations => {
            PresentationList::new(input, ListLimits::IPC)?;
        }
        Kind::Ticket => {
            Ticket::decode(input)?;
        }
        Kind::Uri => {
            Uri::decode(input)?;
        }
        Kind::Request => {
            Request::decode(input)?;
        }
        Kind::Response => {
            Response::decode(input)?;
        }
    }
    Ok(())
}
