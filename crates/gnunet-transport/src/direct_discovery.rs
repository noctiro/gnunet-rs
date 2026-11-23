//! Allocation-free address discovery for one provisioned peer.
//!
//! HELLO carries a signed expiration but no signed generation. A strictly
//! later expiration supersedes the previous address set. The ordinary
//! GNUnet signature covers metadata only, so an address from that profile
//! requires direct attribution to its authenticated CORE sender.

use gnunet_crypto::EddsaPublicKey;
use gnunet_hello::{Address, Hello, SignatureCoverage, VerifiedHello};
use gnunet_types::{AbsoluteTime, Error};
use gnunet_wire::official::{Frame, message_type as mt};

pub use gnunet_hello::{Limits, SignatureProfile};

/// Recognize one complete official HELLO_URI frame before choosing its parser.
#[must_use]
pub fn is_hello_uri(bytes: &[u8]) -> bool {
    Frame::decode(bytes).is_ok_and(|frame| frame.header().message_type() == mt::HELLO_URI)
}

/// An official HELLO representation received outside its subject's CORE session.
#[derive(Clone, Copy, Debug)]
pub enum Input<'a> {
    /// Public HELLO block.
    Block(&'a [u8]),
    /// HELLO_URI or DHT_P2P_HELLO for this book's provisioned peer.
    Message(&'a [u8]),
    /// A `gnunet://hello/` URL.
    Url(&'a [u8]),
}

/// Evidence that the selected complete address set belongs to its subject.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressProof {
    /// The official purpose-7 signature also covers the canonical URI bytes.
    Signature,
    /// The peer sent its own metadata-signed HELLO through its authenticated CORE session.
    AuthenticatedCore,
}

/// Effect of accepting an authenticated HELLO.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Update {
    /// The book now holds the newer nonempty set.
    Published,
    /// The newer empty set withdrew all previous addresses.
    Withdrawn,
    /// The exact set and expiration already exist. Provenance can become stronger.
    Unchanged,
}

/// The live authenticated snapshot borrowed from the original address book.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Snapshot<'a> {
    peer: EddsaPublicKey,
    expiration: AbsoluteTime,
    addresses: &'a [u8],
    proof: AddressProof,
}

impl<'a> Snapshot<'a> {
    /// Subject authenticated for this set.
    #[must_use]
    pub const fn peer(self) -> EddsaPublicKey {
        self.peer
    }

    /// Exact signed wire expiration.
    #[must_use]
    pub const fn expiration(self) -> AbsoluteTime {
        self.expiration
    }

    /// Canonical descending NUL-delimited set of official URIs.
    #[must_use]
    pub const fn address_bytes(self) -> &'a [u8] {
        self.addresses
    }

    /// How the set itself was authenticated.
    #[must_use]
    pub const fn proof(self) -> AddressProof {
        self.proof
    }
}

/// One original URI selected from a live authenticated set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Selection<'a> {
    peer: EddsaPublicKey,
    address: Address<'a>,
    expiration: AbsoluteTime,
    proof: AddressProof,
}

impl<'a> Selection<'a> {
    /// Expected identity for the new connection's authentication.
    #[must_use]
    pub const fn peer(self) -> EddsaPublicKey {
        self.peer
    }

    /// Exact official address bytes in the original HELLO.
    #[must_use]
    pub const fn address(self) -> Address<'a> {
        self.address
    }

    /// Time at which this candidate stops being eligible for selection.
    #[must_use]
    pub const fn expiration(self) -> AbsoluteTime {
        self.expiration
    }

    /// How the address, in addition to its peer metadata, was authenticated.
    #[must_use]
    pub const fn proof(self) -> AddressProof {
        self.proof
    }
}

#[derive(Clone, Copy)]
struct Record {
    expiration: AbsoluteTime,
    used: usize,
    proof: AddressProof,
}

/// One canonical address set in exclusive caller-supplied storage.
///
/// Parsing uses separate caller scratch. Invalid input leaves the accepted
/// record unchanged. Expiry hides the record while retaining its freshness
/// floor for this owner's lifetime. Selection still requires authenticating
/// the expected peer on the newly opened native connection.
pub struct Book<'storage> {
    peer: EddsaPublicKey,
    storage: &'storage mut [u8],
    limits: Limits,
    record: Option<Record>,
    observed: Option<AbsoluteTime>,
}

impl<'storage> Book<'storage> {
    /// Reserve the maximum retained bytes for one provisioned peer's HELLOs.
    ///
    /// # Errors
    /// Rejects an invalid peer key or backing storage smaller than the configured limit.
    pub fn new(
        peer: EddsaPublicKey,
        storage: &'storage mut [u8],
        limits: Limits,
    ) -> Result<Self, Error> {
        peer.validate_peer()?;
        let storage = storage
            .get_mut(..limits.maximum_address_bytes)
            .ok_or(Error::Capacity)?;
        Ok(Self {
            peer,
            storage,
            limits,
            record: None,
            observed: None,
        })
    }

    /// Import official HELLO bytes whose purpose-7 signature binds their addresses.
    ///
    /// # Errors
    /// Rejects bad framing or signature, a different subject, an expired or
    /// unbounded record, a regressing UTC sample or a stale/conflicting set.
    pub fn import_signed(
        &mut self,
        input: Input<'_>,
        now: AbsoluteTime,
        scratch: &mut [u8],
    ) -> Result<Update, Error> {
        self.advance(now)?;
        let hello = match input {
            Input::Block(bytes) => Hello::parse_block(bytes, scratch, self.limits),
            Input::Message(bytes) => {
                Hello::parse_message(bytes, Some(self.peer), scratch, self.limits)
            }
            Input::Url(bytes) => Hello::parse_url(bytes, scratch, self.limits),
        }?;
        let verified = hello.verify_at(SignatureProfile::DeterministicPidDerivation, now)?;
        self.install(verified, AddressProof::Signature)
    }

    /// Receive a peer's own HELLO_URI through its original authenticated CORE DATA.
    ///
    /// `sender` is the authenticated sender supplied by the CORE receive owner.
    /// It must match the book's peer and the message subject. The caller selects
    /// the peer's official signature profile before processing the message.
    ///
    /// # Errors
    /// Rejects a different sender or subject, other message types and invalid,
    /// expired, unbounded, stale or conflicting HELLOs.
    pub fn receive_authenticated(
        &mut self,
        sender: EddsaPublicKey,
        message: &[u8],
        profile: SignatureProfile,
        now: AbsoluteTime,
        scratch: &mut [u8],
    ) -> Result<Update, Error> {
        self.advance(now)?;
        if sender != self.peer {
            return Err(Error::Authentication);
        }
        if message.len() > self.limits.maximum_input_bytes {
            return Err(Error::Capacity);
        }
        if Frame::decode(message)?.header().message_type() != mt::HELLO_URI {
            return Err(Error::Unsupported);
        }
        let hello = Hello::parse_message(message, None, scratch, self.limits)?;
        let verified = hello.verify_at(profile, now)?;
        let proof = match verified.coverage() {
            SignatureCoverage::MetadataAndAddresses => AddressProof::Signature,
            SignatureCoverage::MetadataOnly => AddressProof::AuthenticatedCore,
        };
        self.install(verified, proof)
    }

    fn advance(&mut self, now: AbsoluteTime) -> Result<(), Error> {
        if now.is_never() || self.observed.is_some_and(|previous| now < previous) {
            return Err(Error::TimeUncertain);
        }
        self.observed = Some(now);
        Ok(())
    }

    /// Next pending nonempty set retirement. Drive [`Self::expire`] when due.
    #[must_use]
    pub fn next_expiration(&self) -> Option<AbsoluteTime> {
        self.record
            .filter(|record| record.used != 0)
            .map(|record| record.expiration)
    }

    /// Latest accepted signed expiration, including a withdrawn or expired set.
    #[must_use]
    pub fn freshness_floor(&self) -> Option<AbsoluteTime> {
        self.record.map(|record| record.expiration)
    }

    /// Borrow the original authenticated set if it is still live at `now`.
    ///
    /// # Errors
    /// Refuses an invalid UTC observation.
    pub fn current(&mut self, now: AbsoluteTime) -> Result<Option<Snapshot<'_>>, Error> {
        self.advance(now)?;
        Ok(self.live(now).map(|record| Snapshot {
            peer: self.peer,
            expiration: record.expiration,
            addresses: &self.storage[..record.used],
            proof: record.proof,
        }))
    }

    /// Retire an expired nonempty set and report that transition exactly once.
    /// The original signed expiration remains the replacement freshness floor.
    ///
    /// # Errors
    /// Refuses an invalid UTC observation.
    pub fn expire(&mut self, now: AbsoluteTime) -> Result<bool, Error> {
        self.advance(now)?;
        let Some(record) = &mut self.record else {
            return Ok(false);
        };
        if now < record.expiration || record.used == 0 {
            return Ok(false);
        }
        self.storage[..record.used].fill(0);
        record.used = 0;
        Ok(true)
    }

    /// Select the highest eligible address rank. Equal ranks preserve the
    /// official canonical descending byte order. `None` rejects an address.
    ///
    /// # Errors
    /// Refuses an invalid UTC observation. Successful selection borrows the
    /// book so its exact address bytes cannot be replaced during the borrow.
    pub fn select(
        &mut self,
        now: AbsoluteTime,
        mut rank: impl FnMut(Address<'_>) -> Option<u16>,
    ) -> Result<Option<Selection<'_>>, Error> {
        self.advance(now)?;
        let Some(record) = self.live(now) else {
            return Ok(None);
        };
        let mut best = None;
        for bytes in self.storage[..record.used].split(|byte| *byte == 0) {
            if bytes.is_empty() {
                continue;
            }
            let address = Address::from_uri(bytes)?;
            if let Some(score) = rank(address)
                && best.is_none_or(|(previous, _)| score > previous)
            {
                best = Some((score, address));
            }
        }
        Ok(best.map(|(_, address)| Selection {
            peer: self.peer,
            address,
            expiration: record.expiration,
            proof: record.proof,
        }))
    }

    fn live(&self, now: AbsoluteTime) -> Option<Record> {
        self.record
            .filter(|record| record.used != 0 && now < record.expiration)
    }

    fn install(
        &mut self,
        verified: VerifiedHello<'_>,
        proof: AddressProof,
    ) -> Result<Update, Error> {
        let hello = verified.hello();
        let expiration = hello.expiration();
        if hello.peer() != self.peer {
            return Err(Error::Authentication);
        }
        if expiration.is_never() {
            return Err(Error::InvalidInput);
        }
        if expiration <= verified.checked_at() {
            return Err(Error::Timeout);
        }
        let bytes = hello.address_bytes();
        if let Some(original) = &mut self.record {
            if expiration < original.expiration {
                return Err(Error::Replay);
            }
            if expiration == original.expiration {
                if bytes != &self.storage[..original.used] {
                    return Err(Error::Conflict);
                }
                if proof == AddressProof::Signature {
                    original.proof = proof;
                }
                return Ok(Update::Unchanged);
            }
            if bytes.len() < original.used {
                self.storage[bytes.len()..original.used].fill(0);
            }
        }
        self.storage[..bytes.len()].copy_from_slice(bytes);
        self.record = Some(Record {
            expiration,
            used: bytes.len(),
            proof,
        });
        Ok(if bytes.is_empty() {
            Update::Withdrawn
        } else {
            Update::Published
        })
    }
}

#[cfg(test)]
mod tests;
