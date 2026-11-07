//! Immutable aggregate purpose7 candidate and ordinary binary HELLO projection.
//! Reuses the HELLO codec and explicit Reference029 metadata-only profile.
use crate::{
    addresses::{Publication, PublicationId},
    own::{Authority, CommitOutcome, HELLO_TTL, PublicationBounds, REFRESH_CAP},
};
use alloc::{sync::Arc, vec::Vec};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_hello::{AbsoluteTime, HelloBuilder, Limits, SignatureProfile};
use gnunet_types::Error;

/// An original aggregate generation, distinct from another refresh of the same
/// URI set. It is not a wire id and cannot be reconstructed from a disk cache.
#[derive(Clone, Debug)]
pub struct HelloOfferId {
    scope: Arc<()>,
    set: PublicationId,
    authority: Authority,
}
impl PartialEq for HelloOfferId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.scope, &other.scope)
    }
}
impl Eq for HelloOfferId {}
impl HelloOfferId {
    /// Original physical authority retained by this exact aggregate offer.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Offered,
    Issued,
    Verified,
    Writing,
    Unknown,
    Committed,
    Refused,
}
/// One staged aggregate, bounded by the original book/output quotas. The host
/// keeps at most its configured count; preparing one never signs or writes.
pub struct HelloCandidate {
    id: HelloOfferId,
    region: [u8; 80],
    expiry: AbsoluteTime,
    uris: Vec<u8>,
    message: Vec<u8>,
    limits: Limits,
    phase: Phase,
    live: bool,
}
impl HelloCandidate {
    /// Fallibly reserve all retained bytes before a PILS operation is admitted.
    /// An empty set is a managed-record withdrawal, not a future-TTL empty public
    /// HELLO: official `message_expiration` reports zero for an empty112B message.
    pub fn prepare(
        set: Publication<'_>,
        authority: Authority,
        now: u64,
        bounds: PublicationBounds,
        maximum_records: usize,
    ) -> Result<Self, Error> {
        let expiry = AbsoluteTime::from_micros(
            now.checked_add(HELLO_TTL)
                .filter(|end| *end != u64::MAX)
                .ok_or(Error::Overflow)?,
        );
        let limits = Limits {
            maximum_input_bytes: u16::MAX as usize,
            maximum_address_bytes: bounds.address_bytes,
            maximum_addresses: maximum_records,
        };
        let mut uris = Vec::new();
        uris.try_reserve_exact(bounds.address_bytes)
            .map_err(|_| Error::Capacity)?;
        uris.resize(bounds.address_bytes, 0);
        let (region, used) = {
            let mut builder = HelloBuilder::new(&mut uris, limits);
            for uri in set.uris() {
                builder.add_address(uri)?;
            }
            let placeholder = builder.with_signature(
                authority.peer(),
                EddsaSignature::from_bytes([0; 64]),
                expiry,
            );
            (
                placeholder.signed_payload(SignatureProfile::Gnunet029)?,
                builder.address_bytes().len(),
            )
        };
        uris.truncate(used);
        let length = gnunet_hello::MESSAGE_FIXED_LEN
            .checked_add(used)
            .ok_or(Error::Capacity)?;
        // Public PS record is HELLO bytes plus60+10+25, not PILS's72B prefix.
        let record_length = length.checked_add(95).ok_or(Error::Capacity)?;
        if record_length > bounds.hello_record_bytes || record_length > u16::MAX as usize {
            return Err(Error::Capacity);
        }
        let mut message = Vec::new();
        if used != 0 {
            message
                .try_reserve_exact(length)
                .map_err(|_| Error::Capacity)?;
            message.resize(length, 0);
        }
        Ok(Self {
            id: HelloOfferId {
                scope: Arc::new(()),
                set: set.id().clone(),
                authority,
            },
            region,
            expiry,
            uris,
            message,
            limits,
            phase: if used == 0 {
                Phase::Verified
            } else {
                Phase::Offered
            },
            live: true,
        })
    }
    /// Exact original offer, preserving both its set and physical authority.
    pub fn id(&self) -> &HelloOfferId {
        &self.id
    }
    /// Whether this immutable candidate still describes the desired URI set.
    pub fn matches(&self, set: &Publication<'_>, authority: &Authority) -> bool {
        self.live && self.id.set == *set.id() && self.id.authority == *authority
    }
    /// Exact original80B purpose7 bytes for verification/correlation only.
    /// Actual native admission uses `with_builder` and the existing sign_hello.
    pub fn signed_region(&self) -> &[u8; 80] {
        &self.region
    }
    /// Expected original signer.
    pub fn peer(&self) -> EddsaPublicKey {
        self.id.authority.peer()
    }
    /// Original pure brand mapped by the runtime to one physical PILS authority.
    pub fn authority(&self) -> &Authority {
        &self.id.authority
    }
    /// Original signed expiration, separate from a local finite refresh deadline.
    pub fn expiry(&self) -> AbsoluteTime {
        self.expiry
    }
    /// Only a nonempty original candidate needs a signature before publication.
    pub fn needs_signature(&self) -> bool {
        self.live && self.phase == Phase::Offered
    }
    /// Rebuild the original immutable set in caller-owned common scratch. Failure
    /// never consumes a signing offer or modifies its retained canonical bytes.
    pub fn with_builder<T>(
        &self,
        scratch: &mut [u8],
        f: impl FnOnce(&HelloBuilder<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !self.needs_signature() {
            return Err(Error::Stale);
        }
        if scratch.len() < self.uris.len() {
            return Err(Error::Capacity);
        }
        let mut builder = HelloBuilder::new(scratch, self.limits);
        for uri in self
            .uris
            .split(|byte| *byte == 0)
            .filter(|uri| !uri.is_empty())
        {
            builder.add_address(uri)?;
        }
        f(&builder)
    }
    /// Note actual original native signing admission exactly once.
    pub fn signing_admitted(&mut self, id: &HelloOfferId) -> Result<(), Error> {
        if self.id != *id || !self.needs_signature() {
            return Err(Error::Stale);
        }
        self.phase = Phase::Issued;
        Ok(())
    }
    /// Attach the actual verified signature with the common HELLO encoder. An
    /// insufficient scratch buffer leaves this original issued offer retryable.
    pub fn signed(
        &mut self,
        id: &HelloOfferId,
        peer: EddsaPublicKey,
        signature: EddsaSignature,
        scratch: &mut [u8],
    ) -> Result<bool, Error> {
        if self.id != *id || self.phase != Phase::Issued {
            return Err(Error::Stale);
        }
        if peer != self.peer() {
            return Err(Error::Authentication);
        }
        peer.verify(7, &self.region, &signature)?;
        if !self.live {
            self.phase = Phase::Refused;
            return Ok(false);
        }
        if scratch.len() < self.uris.len() {
            return Err(Error::Capacity);
        }
        let mut builder = HelloBuilder::new(scratch, self.limits);
        for uri in self.uris.split(|b| *b == 0).filter(|uri| !uri.is_empty()) {
            builder.add_address(uri)?;
        }
        builder
            .with_signature(peer, signature, self.expiry)
            .encode_message(&mut self.message)?;
        self.phase = Phase::Verified;
        Ok(true)
    }
    /// Verified ordinary binary HELLO value, or a managed withdrawal for an empty
    /// original set. None outside Verified; no store/ACK has happened here.
    pub fn projection(&self) -> Option<Option<&[u8]>> {
        (self.live && self.phase == Phase::Verified)
            .then(|| (!self.uris.is_empty()).then_some(self.message.as_slice()))
    }
    /// Original backend admission, independent of actual durable completion.
    pub fn commit_started(&mut self, id: &HelloOfferId) -> Result<(), Error> {
        if self.id != *id || self.phase != Phase::Verified || !self.live {
            return Err(Error::Stale);
        }
        self.phase = Phase::Writing;
        Ok(())
    }
    /// Return the actual original transaction outcome. Unknown cannot be cleared
    /// by preparing another snapshot or by retirement/physical identity loss.
    pub fn commit_finished(
        &mut self,
        id: &HelloOfferId,
        outcome: CommitOutcome,
    ) -> Result<(), Error> {
        self.finish(id, outcome, Phase::Writing)
    }
    /// Resolve the exact original Unknown; a later same-set offer cannot match it.
    pub fn recovered(&mut self, id: &HelloOfferId, outcome: CommitOutcome) -> Result<(), Error> {
        self.finish(id, outcome, Phase::Unknown)
    }
    fn finish(
        &mut self,
        id: &HelloOfferId,
        outcome: CommitOutcome,
        expected: Phase,
    ) -> Result<(), Error> {
        if self.id != *id || self.phase != expected {
            return Err(Error::Stale);
        }
        self.phase = match outcome {
            CommitOutcome::Committed => Phase::Committed,
            CommitOutcome::NotCommitted(_) => Phase::Refused,
            CommitOutcome::Unknown(_) => Phase::Unknown,
        };
        Ok(())
    }
    /// Finite renewal deadline for a known live nonempty managed HELLO. It is
    /// anchored to this candidate's original preparation time and independent
    /// of communicator FOREVER hints. Empty managed withdrawal has no periodic
    /// record to renew. Writing/Unknown never authorize a replacement effect.
    pub fn refresh_deadline(&self) -> Option<u64> {
        (self.live && self.phase == Phase::Committed && !self.uris.is_empty())
            .then(|| self.expiry.as_micros() - HELLO_TTL + REFRESH_CAP)
    }
    /// Retire original intent, keeping any admitted sign/store outcome owned.
    pub fn retire(&mut self) {
        self.live = false;
        if matches!(self.phase, Phase::Offered | Phase::Verified) {
            self.phase = Phase::Refused;
        }
    }
    /// Original sign cancellation requires native cursor drain/retirement first.
    pub fn signing_retired(&mut self, id: &HelloOfferId) -> Result<(), Error> {
        if self.id != *id || self.phase != Phase::Issued {
            return Err(Error::Stale);
        }
        self.phase = Phase::Refused;
        Ok(())
    }
    /// No original admitted operation remains. This says nothing about a still
    /// live prior managed public record or actual remote announcement/delivery.
    pub fn effects_quiescent(&self) -> bool {
        matches!(
            self.phase,
            Phase::Offered | Phase::Verified | Phase::Committed | Phase::Refused
        )
    }
}
