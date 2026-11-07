//! Explicit original PILS/Journal port context for the own-address publisher.
//! No resolver/backend task, private wire protocol or hidden key-file access.
use gnunet_pils::client as pc;
use gnunet_transport::{
    addresses::Publication,
    own_hello::{HelloCandidate, HelloOfferId},
};
use gnunet_transport::{
    own::{Authority, Certificate, CommitOutcome, OfferId, RecordProvenance},
    own_wire,
};
use gnunet_types::Error;

/// Actual native-client epoch paired once with its corresponding pure authority.
/// Same peer32 on another client/MQ cannot manufacture a compatible brand.
pub struct ObservedAuthority<'a> {
    pure: Authority,
    original: pc::Identity<'a>,
}
impl<'a> ObservedAuthority<'a> {
    /// Bind an actual verified native PILS announcement, never cached peer bytes.
    pub fn new(original: pc::Identity<'a>) -> Self {
        Self {
            pure: Authority::from_verified_peer(original.peer()),
            original,
        }
    }
    /// Borrow this original native-to-pure authority mapping for resource slots.
    pub fn pure(&self) -> &Authority {
        &self.pure
    }
    /// Accept metadata changes only on this original native instance/MQ and key.
    pub fn compatible(&self, current: pc::Identity<'a>) -> bool {
        current.epoch() == self.original.epoch() && current.peer() == self.original.peer()
    }
}

/// A signing plan prepared before native admission. Its original branded offer
/// selects the certificate's immutable80B region; the physical epoch remains
/// separate from later same-key metadata revisions on that same native client.
pub struct SignaturePlan<'a> {
    offer: OfferId,
    epoch: pc::Epoch<'a>,
}
impl<'a> SignaturePlan<'a> {
    /// Prepare on this client's actual identity, preserving same-key metadata
    /// revisions without treating another physical MQ as the same authority.
    pub fn prepare(
        certificate: &Certificate,
        authority: &ObservedAuthority<'a>,
        identity: pc::Identity<'a>,
    ) -> Result<Self, Error> {
        let offer = certificate.signature_offer().ok_or(Error::NotReady)?;
        if certificate.authority() != authority.pure() || !authority.compatible(identity) {
            return Err(Error::Stale);
        }
        if offer.peer != identity.peer() {
            return Err(Error::Authentication);
        }
        Ok(Self {
            offer: offer.id.clone(),
            epoch: identity.epoch(),
        })
    }
    /// Admit through the actual native client using this exact original target.
    /// The client checks its own identity brand/revision before creating an
    /// operation. No caller-supplied operation from another client can be adopted.
    /// The exact still-offered certificate is claimed in the same synchronous
    /// step before any I/O can run. Repeated/stale plans cannot queue another
    /// request. If the later pure claim unexpectedly refuses, the error retains
    /// the admitted operation so its native owner can cancel/drain it.
    pub fn admit<const O: usize>(
        self,
        certificate: &mut Certificate,
        client: &mut gnunet_pils_host::client::Client<'a, O>,
    ) -> SignatureAdmission<'a> {
        let Some(offer) = certificate.signature_offer().filter(|offer| {
            *offer.id == self.offer && certificate.authority() == self.offer.authority()
        }) else {
            return SignatureAdmission::Refused {
                original: self,
                cause: Error::Stale.into(),
            };
        };
        let Some(identity) = client.identity().filter(|identity| {
            identity.epoch() == self.epoch && identity.peer() == self.offer.authority().peer()
        }) else {
            return SignatureAdmission::Refused {
                original: self,
                cause: Error::Stale.into(),
            };
        };
        let operation = match client.sign(offer.region, pc::KeyTarget::Exact(identity)) {
            Ok(operation) => operation,
            Err(cause) => {
                return SignatureAdmission::Refused {
                    original: self,
                    cause,
                };
            }
        };
        let original = OriginalSignature {
            plan: self,
            operation,
        };
        match certificate.signing_admitted(&original.plan.offer) {
            Ok(()) => SignatureAdmission::Queued(original),
            Err(cause) => SignatureAdmission::Retire { original, cause },
        }
    }
}
/// Native admission has three ownership outcomes. A refused plan owns no native
/// operation; an operation needing retirement has already been admitted. Neither
/// can be erased by interpreting all refusal paths as the same generic failure.
#[must_use = "Retain the original plan or operation until its explicit disposition."]
pub enum SignatureAdmission<'a> {
    /// Actual native request and pure original offer were admitted together.
    /// The native owner still needs polling; no signature or durable ACK exists.
    Queued(OriginalSignature<'a>),
    /// No native operation exists and no signing result was fabricated.
    Refused {
        /// Exact original target and80B region, unchanged by refusal.
        original: SignaturePlan<'a>,
        /// Actual native/client refusal, retaining its protocol or I/O cause.
        cause: gnunet_pils_host::client::Error,
    },
    /// Native admission happened; preserve this owner until cancel/drain ends.
    Retire {
        /// The actual original operation; never silently lost on a pure error.
        original: OriginalSignature<'a>,
        /// The actual post-admission pure-state refusal.
        cause: Error,
    },
}
/// An admitted operation whose actual physical/native owner remains the PILS
/// client. Keep this context until its terminal completion or explicit cancel.
pub struct OriginalSignature<'a> {
    plan: SignaturePlan<'a>,
    operation: pc::OperationId<'a>,
}
/// Terminal original signature disposition; unrelated completions are borrowed
/// and refused before changing any certificate or consuming their owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureResult {
    /// Verified original public value is staged; no durable write happened.
    Verified,
    /// Original resource/context was retired; no replacement adopted its result.
    Retired,
    /// Actual original PILS refusal, with an independent paced retry deadline.
    Failed {
        /// Original actual service result cause.
        reason: pc::Failure,
        /// Finite next attempt deadline or the actual range error.
        retry: Result<u64, Error>,
    },
}
/// Cancellation and the original copied frame have separate completion points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureRetirement {
    /// The original native client still owns logical or copied work.
    Pending,
    /// Original work is quiescent and its pure signing phase was retired.
    Retired {
        /// Finite retry deadline, or the actual clock range refusal.
        retry: Result<u64, Error>,
    },
}
impl<'a> OriginalSignature<'a> {
    /// Actual original client operation, never its reusable u32 wire RID.
    pub fn operation(&self) -> pc::OperationId<'a> {
        self.operation
    }
    /// Original pure offer; foreign/new resource generations cannot match it.
    pub fn offer(&self) -> &OfferId {
        &self.plan.offer
    }
    /// Same-key metadata revision is compatible only on the original physical MQ.
    pub fn context_is_current(&self, current: Option<pc::Identity<'a>>) -> bool {
        current.is_some_and(|id| {
            id.epoch() == self.plan.epoch && id.peer() == self.plan.offer.authority().peer()
        })
    }
    /// Request logical cancellation without treating copied bytes as retired.
    /// The original owner remains required on both success and actual refusal.
    pub fn request_cancel<const O: usize>(
        &self,
        certificate: &mut Certificate,
        client: &mut gnunet_pils_host::client::Client<'a, O>,
    ) -> Result<(), gnunet_pils_host::client::Error> {
        if certificate.pending_id() != Some(&self.plan.offer)
            || certificate.authority() != self.plan.offer.authority()
        {
            return Err(Error::Stale.into());
        }
        certificate.retire();
        client.cancel(self.operation)
    }
    /// Retire the exact pure signing phase only after actual native quiescence.
    pub fn finish_retirement<const O: usize>(
        &self,
        certificate: &mut Certificate,
        client: &gnunet_pils_host::client::Client<'a, O>,
        now: u64,
    ) -> Result<SignatureRetirement, gnunet_pils_host::client::Error> {
        if certificate.cancellation_required() != Some(&self.plan.offer)
            || certificate.authority() != self.plan.offer.authority()
        {
            return Err(Error::Stale.into());
        }
        if !client.operation_quiescent(self.operation)? {
            return Ok(SignatureRetirement::Pending);
        }
        Ok(SignatureRetirement::Retired {
            retry: certificate.signing_retired(&self.plan.offer, now)?,
        })
    }
    /// Borrow the actual completion, keeping its original event in caller hands.
    /// On a context loss, retire the resource intent before accepting that old
    /// result. The caller must separately retain/return the physical loss event.
    pub fn apply(
        &self,
        certificate: &mut Certificate,
        completion: &pc::Completion<'a>,
        current: Option<pc::Identity<'a>>,
        now: u64,
    ) -> Result<SignatureResult, Error> {
        if completion.operation() != self.operation
            || certificate.pending_id() != Some(&self.plan.offer)
            || certificate.authority() != self.plan.offer.authority()
        {
            return Err(Error::Stale);
        }
        if !self.context_is_current(current) {
            certificate.retire();
        }
        match completion {
            pc::Completion::Signature {
                peer, signature, ..
            } => {
                if *peer != self.plan.offer.authority().peer() {
                    return Err(Error::Authentication);
                }
                // The native client verified its retained request. The pure
                // certificate rechecks its original immutable region below.
                if certificate.signed(&self.plan.offer, *peer, *signature)? {
                    Ok(SignatureResult::Verified)
                } else {
                    Ok(SignatureResult::Retired)
                }
            }
            pc::Completion::Failed {
                kind: pc::OperationKind::Sign,
                reason,
                ..
            } => {
                let retry = certificate.signing_retired(&self.plan.offer, now)?;
                Ok(SignatureResult::Failed {
                    reason: *reason,
                    retry,
                })
            }
            _ => Err(Error::Malformed),
        }
    }
}

/// Owned ordinary record draft. Preparation is fallible before an original
/// signature completion is released. Payload is public, not private key material.
pub struct OwnRecord {
    /// Exact admitted ADD/certificate/authority generation.
    offer: OfferId,
    /// Expected original signer.
    peer: [u8; 32],
    /// Complete canonical ordinary public value including NUL.
    value: Vec<u8>,
    /// Original unsigned cache lifetime endpoint.
    expiry: u64,
    provenance: RecordProvenance,
}
impl OwnRecord {
    /// Fallibly own and independently verify the exact staged value. The backend
    /// adds private origin metadata; it does not change the official value.
    pub fn copy_from(
        certificate: &Certificate,
        maximum_value_bytes: usize,
        now: u64,
    ) -> Result<Self, Error> {
        let draft = certificate.publication_record(now)?;
        let authority = certificate.authority();
        if draft.peer != authority.peer() {
            return Err(Error::Authentication);
        }
        if draft.value.len() > maximum_value_bytes {
            return Err(Error::Capacity);
        }
        own_wire::AddressRecord::parse(draft.value)?.verify(draft.peer)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(draft.value.len())
            .map_err(|_| Error::Capacity)?;
        value.extend_from_slice(draft.value);
        Ok(Self {
            offer: draft.id.clone(),
            peer: *draft.peer.as_bytes(),
            value,
            expiry: draft.expiry,
            provenance: draft.provenance,
        })
    }
    /// Exact original certificate generation.
    pub fn offer(&self) -> &OfferId {
        &self.offer
    }
    /// Original authority mapped to its actual native instance/MQ.
    pub fn authority(&self) -> &Authority {
        self.offer.authority()
    }
    /// Expected original record issuer.
    pub fn peer(&self) -> &[u8; 32] {
        &self.peer
    }
    /// Immutable exact official record bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    /// Unsigned original cache lifetime endpoint.
    pub fn expiry(&self) -> u64 {
        self.expiry
    }
    /// Only Staged records need their pure original commit transition. A current
    /// record keeps its already committed original offer and is not re-signed.
    pub fn provenance(&self) -> RecordProvenance {
        self.provenance
    }
}
/// Retained values allowed in one immutable managed projection. Complete public
/// framing, origin metadata and disk snapshot limits are checked by its backend.
#[derive(Clone, Copy, Debug)]
pub struct ProjectionLimits {
    /// Maximum address records; the separate HELLO is not counted here.
    pub records: usize,
    /// Maximum ordinary value bytes per address record.
    pub value_bytes: usize,
    /// Maximum combined address and binary HELLO value bytes.
    pub total_value_bytes: usize,
}
/// One immutable managed projection. The backend replaces only its own origin
/// partition, preserving public/foreign records and replay/highwater domains.
/// An empty HELLO value means remove the managed HELLO, not store an empty112B
/// record with a claimed future expiry (the official helper reports zero).
pub struct OwnedProjection {
    hello_offer: HelloOfferId,
    records: Vec<OwnRecord>,
    hello: Option<Vec<u8>>,
}
impl OwnedProjection {
    /// Own an exact still-current set after all original signatures complete.
    /// No member from a removed/replaced ADD or another authority is adopted.
    /// `limits.total_value_bytes` bounds retained public value bytes; the native
    /// backend additionally checks complete framing, origin metadata and its
    /// total disk snapshot quota before it admits a transaction.
    pub fn copy_from(
        set: Publication<'_>,
        authority: &ObservedAuthority<'_>,
        certificates: &[&Certificate],
        hello: &HelloCandidate,
        limits: ProjectionLimits,
        now: u64,
    ) -> Result<Self, Error> {
        if certificates.len() > limits.records {
            return Err(Error::Capacity);
        }
        if !hello.matches(&set, authority.pure()) || set.records().count() != certificates.len() {
            return Err(Error::Stale);
        }
        let hello_value = hello.projection().ok_or(Error::NotReady)?;
        let mut records = Vec::new();
        records
            .try_reserve_exact(certificates.len())
            .map_err(|_| Error::Capacity)?;
        let mut bytes = hello_value.map_or(0, <[u8]>::len);
        if bytes > limits.total_value_bytes {
            return Err(Error::Capacity);
        }
        for (index, certificate) in certificates.iter().enumerate() {
            if certificate.authority() != authority.pure()
                || !set
                    .records()
                    .any(|resource| resource.lease == certificate.lease())
                || certificates[..index]
                    .iter()
                    .any(|old| old.lease() == certificate.lease())
            {
                return Err(Error::Stale);
            }
            let record = OwnRecord::copy_from(certificate, limits.value_bytes, now)?;
            bytes = bytes
                .checked_add(record.value.len())
                .ok_or(Error::Capacity)?;
            if bytes > limits.total_value_bytes {
                return Err(Error::Capacity);
            }
            records.push(record);
        }
        let owned_hello = match hello_value {
            Some(value) => {
                let mut owned = Vec::new();
                owned
                    .try_reserve_exact(value.len())
                    .map_err(|_| Error::Capacity)?;
                owned.extend_from_slice(value);
                Some(owned)
            }
            None => None,
        };
        Ok(Self {
            hello_offer: hello.id().clone(),
            records,
            hello: owned_hello,
        })
    }
    /// Original aggregate candidate; no later same-set refresh can replace it.
    pub fn hello_offer(&self) -> &HelloOfferId {
        &self.hello_offer
    }
    /// Original physical authority brand for this entire atomic candidate.
    pub fn authority(&self) -> &Authority {
        self.hello_offer.authority()
    }
    /// Canonical ordinary purpose29 records of all actual original ADDs.
    pub fn records(&self) -> &[OwnRecord] {
        &self.records
    }
    /// Complete binary HELLO or an explicit managed-record withdrawal.
    pub fn hello(&self) -> Option<&[u8]> {
        self.hello.as_deref()
    }
    /// Derive the actual expiry from the retained common binary HELLO codec.
    /// A managed withdrawal has no HELLO record or claimed future expiry.
    pub fn hello_expiry(&self) -> Result<Option<u64>, Error> {
        self.hello
            .as_deref()
            .map(gnunet_hello::message_expiration)
            .transpose()
            .map(|expiry| expiry.map(|expiry| expiry.as_micros()))
    }
}
/// Rejected preparation always returns the original whole projection owner.
pub struct RejectedProjection {
    /// Original unchanged draft; no replayed signing operation is necessary.
    pub original: OwnedProjection,
    /// Actual local preparation refusal.
    pub cause: Error,
}
/// Fenced own-record backend contract, implemented by
/// [`crate::own_store::JournalBackend`]. A trait call is not a complete-Node claim.
/// One transaction
/// retains the original mutation, exact candidate/predecessor and physical fence.
pub trait OwnRecordBackend {
    /// Non-replayed original transaction owner, retained across Unknown recovery.
    type Transaction;
    /// Stage one bounded immutable original; no durable acknowledgement yet.
    fn prepare_own(
        &mut self,
        original: OwnedProjection,
    ) -> Result<Self::Transaction, RejectedProjection>;
    /// Attempt actual publication. Return Committed only after the real file,
    /// rename, directory sync, readback and retained-authority barrier succeeds.
    fn commit_own(&mut self, original: &mut Self::Transaction) -> CommitOutcome;
    /// Resolve that exact Unknown under the original fence, without a fresh sign
    /// or blind STORE replay. After-rename read errors remain Unknown.
    fn recover_own(&mut self, original: &mut Self::Transaction) -> CommitOutcome;
    /// No detached syscall/worker can still publish from this original owner.
    /// This alone does not mean a previously Unknown outcome has been resolved.
    fn own_io_quiescent(&self, original: &Self::Transaction) -> bool;
}
