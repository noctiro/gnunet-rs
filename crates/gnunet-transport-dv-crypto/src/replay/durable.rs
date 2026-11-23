//! Synchronous durable admission for one original DV destination.

use super::{Denied, FRESH, LIVE, LOST, id, same};
use crate::{Opened, Source, Token};
use gnunet_transport::PeerId;
use gnunet_types::{Error, Rejected};

/// Authenticated metadata from one actual AEAD and signature result.
#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    target: PeerId,
    sender: PeerId,
    stamp: u64,
    encapsulation: &'a [u8; 32],
    nonce: &'a [u8; 24],
}

impl<'a> Packet<'a> {
    /// Original local destination.
    #[must_use]
    pub const fn target(self) -> PeerId {
        self.target
    }

    /// Signature-verified sender.
    #[must_use]
    pub const fn sender(self) -> PeerId {
        self.sender
    }

    /// Sender's authenticated monotonic floor.
    #[must_use]
    pub const fn stamp(self) -> u64 {
        self.stamp
    }

    /// Exact original public encapsulation.
    #[must_use]
    pub const fn encapsulation(self) -> &'a [u8; 32] {
        self.encapsulation
    }

    /// Exact original authenticated packet nonce.
    #[must_use]
    pub const fn nonce(self) -> &'a [u8; 24] {
        self.nonce
    }
}

/// Original backend result when durable publication did not succeed.
#[derive(Debug, Eq, PartialEq)]
pub enum CommitFailure<E> {
    /// Known rejection, including duplicate input or exhausted capacity.
    Rejected(E),
    /// The writer cannot establish whether this operation was published.
    OutcomeUnknown(E),
}

/// Exclusive local durable replay authority for the provisioned destination.
pub trait Store {
    /// Original diagnostic from the supplied implementation.
    type Error;

    /// Check and commit the authentic packet in one durable transaction.
    ///
    /// The destination rejects older sender stamps and a previously admitted
    /// exact encapsulation and nonce, across senders and stamp changes. Equal
    /// stamps with distinct tuples remain eligible. Success is permitted only
    /// after both replay invariants survive reopen. A known rejection leaves
    /// authority unchanged.
    fn commit(&mut self, packet: Packet<'_>) -> Result<(), CommitFailure<Self::Error>>;
}

/// The exact source or storage reason an authenticated packet was refused.
#[derive(Debug, Eq, PartialEq)]
pub enum Refusal<E> {
    /// The original source is closed, expired or foreign.
    Source(Error),
    /// The original store did not confirm a durable admission.
    Store(CommitFailure<E>),
}

/// One published original, or the unchanged authenticated owner on refusal.
pub type Admission<'source, 'id, 'out, E> =
    Result<Granted<'source, 'id, 'out>, Denied<Opened<'source, 'id, 'out>, Refusal<E>>>;

/// Replay owner fixed to the original live destination and its store.
///
/// An uncertain write retires the source. To continue, the embedding must
/// recover the durable authority and establish a fresh source.
pub struct Destination<'source, 'id, B> {
    source: &'source Source<'id>,
    store: B,
}

impl<'source, 'id, B: Store> Destination<'source, 'id, B> {
    /// Bind the original store for the lifetime of this replay owner.
    ///
    /// # Errors
    /// Refuses a closed source or a source with any previous replay owner.
    pub fn new(source: &'source Source<'id>, store: B) -> Result<Self, Rejected<B>> {
        if !source.active.get() {
            return Err(Rejected {
                value: store,
                reason: Error::Closed,
            });
        }
        if source.replay_claim.get() != FRESH {
            return Err(Rejected {
                value: store,
                reason: Error::Conflict,
            });
        }
        source.replay_claim.set(LIVE);
        Ok(Self { source, store })
    }

    /// Publish replay protection before returning the original plaintext grant.
    #[expect(
        clippy::result_large_err,
        reason = "Refusal returns the original zeroizing owner for bounded caller storage reuse"
    )]
    pub fn admit<'out>(
        &mut self,
        opened: Opened<'source, 'id, 'out>,
        now: u64,
    ) -> Admission<'source, 'id, 'out, B::Error> {
        let provenance = opened.task.check(now).and_then(|()| {
            if same(id(self.source), id(opened.task.source)) && opened.target() == self.source.local
            {
                Ok(())
            } else {
                Err(Error::Stale)
            }
        });
        if let Err(reason) = provenance {
            return Err(Denied {
                reason: Refusal::Source(reason),
                value: opened,
            });
        }

        let packet = Packet {
            target: opened.target(),
            sender: opened.sender(),
            stamp: opened.stamp(),
            encapsulation: opened.encapsulation(),
            nonce: opened.nonce(),
        };
        if let Err(failure) = self.store.commit(packet) {
            if matches!(&failure, CommitFailure::OutcomeUnknown(_)) {
                self.source.retire();
            }
            return Err(Denied {
                reason: Refusal::Store(failure),
                value: opened,
            });
        }
        Ok(Granted { opened })
    }
}

impl<B> Drop for Destination<'_, '_, B> {
    fn drop(&mut self) {
        if self.source.replay_claim.get() == LIVE {
            self.source.replay_claim.set(LOST);
        }
    }
}

/// The original authenticated payload with confirmed durable replay protection.
pub struct Granted<'source, 'id, 'out> {
    opened: Opened<'source, 'id, 'out>,
}

impl<'id, 'out> Granted<'_, 'id, 'out> {
    /// Original cryptographic operation identity.
    #[must_use]
    pub fn token(&self) -> Token<'id> {
        self.opened.token()
    }

    /// Borrow the authenticated payload while the original source is live.
    ///
    /// # Errors
    /// Refuses the borrow on source retirement or at its original task expiry.
    pub fn message(&self, now: u64) -> Result<&[u8], Error> {
        self.opened.message(now)
    }

    /// Consume the grant and erase the complete original caller buffer.
    #[must_use]
    pub fn recycle(self) -> &'out mut [u8] {
        self.opened.recycle()
    }
}
