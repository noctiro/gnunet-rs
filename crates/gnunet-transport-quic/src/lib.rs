//! Distinct official raw QUIC and HTTP/3 communicator application profiles.
//! No QUIC, TLS, HTTP/3/QPACK engine, IO, entropy or authenticated peer factory.
//! A public peer proposal is a claim, not a signature or certificate binding.
#![no_std]
#![forbid(unsafe_code)]
use core::cell::Cell;
use gnunet_types::{Error, MonoInstant};
pub mod address;
pub mod frame;
pub mod h3;
pub mod raw;
pub mod tx;
/// Stable caller-owned allocation domain; no global or atomics are required.
#[derive(Default)]
pub struct Instance {
    next: Cell<u64>,
}
impl Instance {
    /// New independent original allocation domain.
    pub const fn new() -> Self {
        Self { next: Cell::new(0) }
    }
    fn allocate(&self) -> Result<u64, Error> {
        let next = self.next.get().checked_add(1).ok_or(Error::Overflow)?;
        self.next.set(next);
        Ok(next)
    }
}
/// Original local source identity, not a wire field or peer authentication.
#[derive(Clone, Copy)]
pub struct Epoch<'id> {
    instance: &'id Instance,
    serial: u64,
}
impl core::fmt::Debug for Epoch<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("QuicEpoch").field(&self.serial).finish()
    }
}
impl PartialEq for Epoch<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.instance, other.instance) && self.serial == other.serial
    }
}
impl Eq for Epoch<'_> {}
/// Original finite application source bound. Native deadline is additionally
/// owned/enforced by the future IO adapter; a bare MonoInstant is never Unix time.
pub(crate) struct Scope<'id> {
    epoch: Epoch<'id>,
    until: MonoInstant,
    closed: bool,
    last: Cell<u64>,
}
impl<'id> Scope<'id> {
    fn new(instance: &'id Instance, until: MonoInstant, now: MonoInstant) -> Result<Self, Error> {
        if until.0 == u64::MAX || now.0 >= until.0 {
            return Err(Error::Deadline);
        }
        Ok(Self {
            epoch: Epoch {
                instance,
                serial: instance.allocate()?,
            },
            until,
            closed: false,
            last: Cell::new(now.0),
        })
    }
    fn live(&self, now: MonoInstant) -> Result<(), Error> {
        if self.closed {
            return Err(Error::Closed);
        }
        if now.0 < self.last.get() {
            return Err(Error::TimeUncertain);
        }
        // Record every non-rollback observation, including expiry. Otherwise a
        // later lower timestamp could revive this already-expired source.
        self.last.set(now.0);
        if now.0 >= self.until.0 {
            return Err(Error::Deadline);
        }
        Ok(())
    }
}
/// Opaque original local stream lease, never a raw stream-id callback alias.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stream<'id> {
    epoch: Epoch<'id>,
    serial: u64,
    id: u64,
}
impl<'id> Stream<'id> {
    /// Actual QUIC stream id; the local generation is retained separately.
    pub const fn id(self) -> u64 {
        self.id
    }
    /// Exact original application source.
    pub const fn epoch(self) -> Epoch<'id> {
        self.epoch
    }
}
/// Caller-observed role, independent of TLS certificate authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// The original queue request already supplied this expected peer identity.
    Initiator {
        /// Original requested public peer; no remote proof implied.
        expected: [u8; 32],
    },
    /// The remote initiator must submit its raw32 public peer proposal.
    Acceptor,
}
/// Public unverified remote peer metadata. Never authorizes a CORE identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimedPeer(pub [u8; 32]);
/// Canonical client-initiated bidirectional QUIC id, bounded to QUIC varint62.
pub(crate) fn request_stream(id: u64) -> Result<(), Error> {
    if id > ((1u64 << 62) - 1) || id & 3 != 0 {
        Err(Error::InvalidInput)
    } else {
        Ok(())
    }
}
