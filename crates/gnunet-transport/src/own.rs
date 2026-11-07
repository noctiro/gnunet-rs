//! Pure local certificate lifecycle. Host ports supply actual current authority,
//! durably reserved timestamps and original signing/storage terminal results.
//! No cached record can create an ADD lease or perform a side effect here.
use crate::{
    addresses::{AddressLease, LocalAddress},
    own_wire,
};
use alloc::{sync::Arc, vec::Vec};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_types::Error;

/// Default public HELLO signature lifetime, two days in microseconds.
pub const HELLO_TTL: u64 = 172_800_000_000;
/// Paced local retry/renewal floor, independent of a cache lifetime hint.
pub const REFRESH_FLOOR: u64 = 30_000_000;
/// Finite renewal cap, including for a FOREVER communicator forecast.
pub const REFRESH_CAP: u64 = HELLO_TTL / 4;
// Ordinary public PEERSTORE record: fixed60B plus subsystem/key wire NULs.
const OWN_RECORD_PREFIX_BYTES: usize = 60 + own_wire::SUBSYSTEM.len() + 1 + own_wire::KEY.len() + 1;

/// Complete output bounds for the new own-record publisher. Existing public
/// STORE and iterator wrappers are equally60B; the extra31B is relative to PILS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicationBounds {
    /// Unique serialized URI bytes including NULs, conservatively bounded.
    pub address_bytes: usize,
    /// Complete actual PILS announcement envelope.
    pub pils_bytes: usize,
    /// Complete public binary HELLO PEERSTORE record.
    pub hello_record_bytes: usize,
    /// Maximum public purpose29 record, or zero when no ADD can be admitted.
    pub own_record_bytes: usize,
}
impl PublicationBounds {
    /// Refuse inconsistent output budgets before any owner/port is activated.
    pub fn checked(
        records: usize,
        owned_bytes: usize,
        pils_frame: usize,
        store_frame: usize,
    ) -> Result<Self, Error> {
        let address_bytes = crate::addresses::maximum_serialized_bytes(records, owned_bytes)?;
        let pils_bytes = address_bytes.checked_add(176).ok_or(Error::Capacity)?;
        let hello_record_bytes = address_bytes.checked_add(207).ok_or(Error::Capacity)?;
        let own_record_bytes = if records == 0 || owned_bytes < 6 {
            0
        } else {
            // One native n and URI n+2 charge2n+2 in the original book.
            ((owned_bytes - 2) / 2)
                .checked_add(213)
                .ok_or(Error::Capacity)?
        };
        if pils_bytes > pils_frame
            || hello_record_bytes > store_frame
            || own_record_bytes > store_frame
            || pils_bytes > u16::MAX as usize
            || hello_record_bytes > u16::MAX as usize
            || own_record_bytes > u16::MAX as usize
        {
            return Err(Error::Capacity);
        }
        Ok(Self {
            address_bytes,
            pils_bytes,
            hello_record_bytes,
            own_record_bytes,
        })
    }
}

/// A host-created brand for one actual verified physical identity authority.
/// Clone it for offers on that same original authority; never recreate it from
/// a peer32 or a different native client's numeric epoch.
#[derive(Clone, Debug)]
pub struct Authority {
    brand: Arc<()>,
    peer: EddsaPublicKey,
}
impl Authority {
    /// Bind a newly verified original physical authority. This constructor does
    /// not verify a cached public key or authorize access to private material.
    pub fn from_verified_peer(peer: EddsaPublicKey) -> Self {
        Self {
            brand: Arc::new(()),
            peer,
        }
    }
    /// Expected original signer; no later identity may sign an offered snapshot.
    pub fn peer(&self) -> EddsaPublicKey {
        self.peer
    }
}
impl PartialEq for Authority {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.brand, &other.brand)
    }
}
impl Eq for Authority {}

/// Immutable original signing/commit generation. Private fields prevent a wire
/// address id or a later identical ADD from impersonating an earlier effect.
#[derive(Clone, Debug)]
pub struct OfferId {
    scope: Arc<()>,
    lease: AddressLease,
    authority: Authority,
    generation: u64,
}
impl PartialEq for OfferId {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.scope, &other.scope)
            && self.lease == other.lease
            && self.authority == other.authority
            && self.generation == other.generation
    }
}
impl Eq for OfferId {}
impl OfferId {
    /// Original physical signing authority retained by this immutable offer.
    /// Reusing its public peer bytes cannot recreate the private authority brand.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }
}
/// Original signing bytes, offered before a native operation is admitted.
pub struct SignatureOffer<'a> {
    /// Claim exactly this original before accepting a completion.
    pub id: &'a OfferId,
    /// Expected signer on the retained physical authority.
    pub peer: EddsaPublicKey,
    /// Complete80B purpose29 region, immutable until terminal retirement.
    pub region: &'a [u8; own_wire::REGION_BYTES],
}
/// Origin of the exact retained value used in a managed projection.
/// This is local ownership metadata and is never serialized on the public wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordProvenance {
    /// This original offer has a verified signature awaiting its first commit.
    Staged,
    /// This exact original offer already has a known committed durable value.
    Committed,
}
/// Verified ordinary PEERSTORE value with its original operation provenance.
#[non_exhaustive]
pub struct RecordDraft<'a> {
    /// Original operation generation.
    pub id: &'a OfferId,
    /// Original issuer, never replaced by a later identity.
    pub peer: EddsaPublicKey,
    /// Ordinary canonical purpose29 record value including NUL.
    pub value: &'a [u8],
    /// Unsigned cache expiry computed from the original forecast.
    pub expiry: u64,
    /// Distinguishes a new pending commit from reuse of an earlier known value.
    pub provenance: RecordProvenance,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Offered,
    Issued,
    Verified,
    Writing,
    Unknown,
}
struct Pending {
    id: OfferId,
    region: [u8; own_wire::REGION_BYTES],
    expiry: u64,
    refresh: u64,
    value: Vec<u8>,
    phase: Phase,
}
struct Current {
    id: OfferId,
    value: Vec<u8>,
    expiry: u64,
}
/// Actual backend certainty for the original retained transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// Original candidate passed the backend's durable publication barrier.
    Committed,
    /// Backend proved the original candidate was never published.
    NotCommitted(Error),
    /// Publication may have happened. Keep original bytes/fence and recover.
    Unknown(Error),
}
/// Pure result after an original backend terminal observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitResult {
    /// Durable bytes exist; retired entries additionally require withdrawal.
    Committed {
        /// Whether the original resource was retired while committing.
        retired: bool,
        /// A newly representable finite deadline, or the actual clock-range error.
        refresh: Result<u64, Error>,
    },
    /// No publication; the next attempt must be a fresh paced effect.
    NotCommitted {
        /// Original backend cause, unchanged.
        cause: Error,
        /// Fresh paced retry deadline, or the actual clock-range error.
        retry: Result<u64, Error>,
    },
    /// New writes/authority activation remain blocked for this original.
    Unknown(Error),
}
/// One bounded original resource's certificate owner. A host bounds the number
/// of these slots by its original book quota; one slot retains at most a pending
/// and a committed public value. It never signs, writes or spawns a task itself.
pub struct Certificate {
    scope: Arc<()>,
    lease: AddressLease,
    authority: Authority,
    native: Vec<u8>,
    network: u32,
    forecast: u64,
    maximum_value_bytes: usize,
    last_generation: u64,
    last_issued: Option<u64>,
    next_refresh: Option<u64>,
    live: bool,
    pending: Option<Pending>,
    current: Option<Current>,
}
impl Certificate {
    /// Fallibly retain the original resource before admitting any effect.
    pub fn new(
        local: LocalAddress<'_>,
        authority: Authority,
        maximum_value_bytes: usize,
    ) -> Result<Self, Error> {
        if !local.is_original() {
            return Err(Error::Stale);
        }
        let value_bound = own_wire::maximum_value_bytes(local.address.len())?;
        if value_bound > maximum_value_bytes
            || value_bound
                .checked_add(OWN_RECORD_PREFIX_BYTES)
                .is_none_or(|bytes| bytes > u16::MAX as usize)
        {
            return Err(Error::Capacity);
        }
        own_wire::signed_region(local.address, 0)?;
        let mut native = Vec::new();
        native
            .try_reserve_exact(local.address.len())
            .map_err(|_| Error::Capacity)?;
        native.extend_from_slice(local.address);
        Ok(Self {
            scope: Arc::new(()),
            lease: local.lease.clone(),
            authority,
            native,
            network: local.network,
            forecast: local.validity,
            maximum_value_bytes,
            last_generation: 0,
            last_issued: None,
            next_refresh: Some(0),
            live: true,
            pending: None,
            current: None,
        })
    }
    /// Exact original ADD; the driver checks it against the still-live engine.
    pub fn lease(&self) -> &AddressLease {
        &self.lease
    }
    /// Original verified physical authority.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }
    /// Original pending generation, including an unknown store outcome.
    pub fn pending_id(&self) -> Option<&OfferId> {
        self.pending.as_ref().map(|p| &p.id)
    }
    /// Prepare one immutable snapshot using an already durably reserved stamp.
    /// No state changes on clock, allocation, busy or stale rejection.
    pub fn prepare(&mut self, now: u64, reserved_stamp: u64) -> Result<&OfferId, Error> {
        if !self.live {
            return Err(Error::Stale);
        }
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        if now < self.next_refresh.ok_or(Error::Overflow)? {
            return Err(Error::NotReady);
        }
        if self.last_issued.is_some_and(|old| reserved_stamp <= old) {
            return Err(Error::Replay);
        }
        let refresh = finite_deadline(now, refresh_interval(self.forecast))?;
        let generation = self.last_generation.checked_add(1).ok_or(Error::Capacity)?;
        let region = own_wire::signed_region(&self.native, reserved_stamp)?;
        let mut value = Vec::new();
        value
            .try_reserve_exact(
                own_wire::maximum_value_bytes(self.native.len())?.min(self.maximum_value_bytes),
            )
            .map_err(|_| Error::Capacity)?;
        let pending = Pending {
            id: OfferId {
                scope: self.scope.clone(),
                lease: self.lease.clone(),
                authority: self.authority.clone(),
                generation,
            },
            region,
            expiry: now.saturating_add(self.forecast),
            refresh,
            value,
            phase: Phase::Offered,
        };
        self.pending = Some(pending);
        self.last_generation = generation;
        Ok(&self.pending.as_ref().ok_or(Error::NotReady)?.id)
    }
    /// Borrow original bytes so the native port can reserve traffic first.
    pub fn signature_offer(&self) -> Option<SignatureOffer<'_>> {
        let p = self.pending.as_ref()?;
        (p.phase == Phase::Offered).then_some(SignatureOffer {
            id: &p.id,
            peer: self.authority.peer,
            region: &p.region,
        })
    }
    /// Record actual native admission exactly once. The host retains its own
    /// original OperationId and physical epoch beside this same OfferId.
    pub fn signing_admitted(&mut self, id: &OfferId) -> Result<(), Error> {
        let p = self.pending.as_mut().ok_or(Error::Stale)?;
        if p.id != *id || p.phase != Phase::Offered || !self.live {
            return Err(Error::Stale);
        }
        p.phase = Phase::Issued;
        self.last_issued = Some(u64::from_be_bytes(
            p.region[8..16].try_into().map_err(|_| Error::Malformed)?,
        ));
        Ok(())
    }
    /// Accept only the original verified signer/bytes. Output allocation was
    /// reserved before admission, so a complete result never causes a second sign.
    pub fn signed(
        &mut self,
        id: &OfferId,
        peer: EddsaPublicKey,
        signature: EddsaSignature,
    ) -> Result<bool, Error> {
        let p = self.pending.as_mut().ok_or(Error::Stale)?;
        if p.id != *id || p.phase != Phase::Issued {
            return Err(Error::Stale);
        }
        if peer != self.authority.peer {
            return Err(Error::Authentication);
        }
        peer.verify(own_wire::PURPOSE, &p.region, &signature)?;
        if !self.live {
            self.pending = None;
            return Ok(false);
        }
        let generated =
            u64::from_be_bytes(p.region[8..16].try_into().map_err(|_| Error::Malformed)?);
        let record = own_wire::AddressRecord {
            signature,
            generated,
            network: self.network,
            native: &self.native,
        };
        let len = record.encoded_len()?;
        if len > p.value.capacity() {
            return Err(Error::Capacity);
        }
        p.value.resize(len, 0);
        record.encode(&mut p.value)?;
        p.phase = Phase::Verified;
        Ok(true)
    }
    /// Original result ready for one explicit bounded native store transaction.
    pub fn record_draft(&self) -> Option<RecordDraft<'_>> {
        let p = self.pending.as_ref()?;
        (p.phase == Phase::Verified && self.live).then_some(RecordDraft {
            id: &p.id,
            peer: self.authority.peer,
            value: &p.value,
            expiry: p.expiry,
            provenance: RecordProvenance::Staged,
        })
    }
    /// Read the existing original verified offer's cache expiry and internal
    /// refresh target, in the same explicit UTC-microsecond coordinate supplied
    /// to prepare(). Exact offer ID/live/Verified checks are required. This
    /// reveals policy only; it grants no signature, commit, durable publication
    /// or native service receipt, and does not weaken commit_finished().
    pub fn offer_deadlines(&self, id: &OfferId) -> Result<(u64, u64), Error> {
        let pending = self.pending.as_ref().ok_or(Error::Stale)?;
        if pending.id != *id || pending.phase != Phase::Verified || !self.live {
            return Err(Error::Stale);
        }
        Ok((pending.expiry, pending.refresh))
    }
    /// Select a value for a complete current managed projection. A known current
    /// may be reused only while this original resource is live and its cache
    /// expiry is strictly future. Any pending non-Verified effect blocks reuse;
    /// a possible replacement write must never fall back to the old current.
    /// The caller separately proves this lease is in its actual desired set.
    pub fn publication_record(&self, now: u64) -> Result<RecordDraft<'_>, Error> {
        if !self.live {
            return Err(Error::Stale);
        }
        let record = match self.pending.as_ref() {
            Some(pending) => match pending.phase {
                Phase::Verified => RecordDraft {
                    id: &pending.id,
                    peer: self.authority.peer,
                    value: &pending.value,
                    expiry: pending.expiry,
                    provenance: RecordProvenance::Staged,
                },
                Phase::Offered | Phase::Issued => return Err(Error::NotReady),
                Phase::Writing => return Err(Error::Conflict),
                Phase::Unknown => return Err(Error::OutcomeUnknown),
            },
            None => {
                let current = self.current.as_ref().ok_or(Error::NotReady)?;
                if current.expiry <= now {
                    return Err(Error::Stale);
                }
                RecordDraft {
                    id: &current.id,
                    peer: self.authority.peer,
                    value: &current.value,
                    expiry: current.expiry,
                    provenance: RecordProvenance::Committed,
                }
            }
        };
        if record.id.lease != self.lease || record.id.authority != self.authority {
            return Err(Error::Stale);
        }
        Ok(record)
    }
    /// Record native transaction admission; this is not durable completion.
    pub fn commit_started(&mut self, id: &OfferId) -> Result<(), Error> {
        let p = self.pending.as_mut().ok_or(Error::Stale)?;
        if p.id != *id || p.phase != Phase::Verified || !self.live {
            return Err(Error::Stale);
        }
        p.phase = Phase::Writing;
        Ok(())
    }
    /// Return the original store outcome. Unknown retains its snapshot and blocks
    /// all fresh effects until explicit recovery returns a known outcome.
    pub fn commit_finished(
        &mut self,
        id: &OfferId,
        outcome: CommitOutcome,
        now: u64,
    ) -> Result<CommitResult, Error> {
        self.finish(id, outcome, now, Phase::Writing)
    }
    /// Resolve the exact original unknown candidate under its retained fence.
    pub fn recovered(
        &mut self,
        id: &OfferId,
        outcome: CommitOutcome,
        now: u64,
    ) -> Result<CommitResult, Error> {
        self.finish(id, outcome, now, Phase::Unknown)
    }
    fn finish(
        &mut self,
        id: &OfferId,
        outcome: CommitOutcome,
        now: u64,
        expected: Phase,
    ) -> Result<CommitResult, Error> {
        let p = self.pending.as_ref().ok_or(Error::Stale)?;
        if p.id != *id || p.phase != expected {
            return Err(Error::Stale);
        }
        if let CommitOutcome::Unknown(cause) = outcome {
            self.pending.as_mut().ok_or(Error::Stale)?.phase = Phase::Unknown;
            return Ok(CommitResult::Unknown(cause));
        }
        // Consume a known durable result even if a later timer is unrepresentable.
        // Return that actual range error separately; never submit a MAX timer.
        let retry = finite_deadline(now, REFRESH_FLOOR);
        let p = self.pending.take().ok_or(Error::Stale)?;
        match outcome {
            CommitOutcome::Committed => {
                let refresh = retry.map(|retry| p.refresh.max(retry));
                self.next_refresh = refresh.ok();
                self.current = Some(Current {
                    id: p.id,
                    value: p.value,
                    expiry: p.expiry,
                });
                Ok(CommitResult::Committed {
                    retired: !self.live,
                    refresh,
                })
            }
            CommitOutcome::NotCommitted(cause) => {
                self.next_refresh = retry.ok();
                Ok(CommitResult::NotCommitted { cause, retry })
            }
            CommitOutcome::Unknown(_) => Err(Error::NotReady),
        }
    }
    /// Last known durable record, including after retirement until a managed
    /// withdrawal really commits. Its existence grants no current resource lease.
    pub fn current(&self) -> Option<RecordDraft<'_>> {
        self.current.as_ref().map(|c| RecordDraft {
            id: &c.id,
            peer: self.authority.peer,
            value: &c.value,
            expiry: c.expiry,
            provenance: RecordProvenance::Committed,
        })
    }
    /// Retire original resource intent without erasing admitted side effects.
    pub fn retire(&mut self) {
        self.live = false;
        if self
            .pending
            .as_ref()
            .is_some_and(|p| matches!(p.phase, Phase::Offered | Phase::Verified))
        {
            self.pending = None;
        }
    }
    /// Original issued signing operation must be canceled/drained by its native
    /// owner before this slot can be physically released or replaced.
    pub fn cancellation_required(&self) -> Option<&OfferId> {
        self.pending
            .as_ref()
            .filter(|p| !self.live && p.phase == Phase::Issued)
            .map(|p| &p.id)
    }
    /// Original native sign/cancel has become terminal. Never applies to a store.
    pub fn signing_retired(&mut self, id: &OfferId, now: u64) -> Result<Result<u64, Error>, Error> {
        let p = self.pending.as_ref().ok_or(Error::Stale)?;
        if p.id != *id || p.phase != Phase::Issued {
            return Err(Error::Stale);
        }
        let retry = finite_deadline(now, REFRESH_FLOOR);
        self.pending = None;
        self.next_refresh = retry.ok();
        Ok(retry)
    }
    /// Whether no original sign/store outcome remains owned. A durable managed
    /// record may still require a separate known withdrawal before Node cleanup.
    pub fn effects_quiescent(&self) -> bool {
        self.pending.is_none()
    }
    /// A finite canonical refresh deadline, or none when retired/blocked/full.
    pub fn refresh_deadline(&self) -> Option<u64> {
        if self.live && self.pending.is_none() {
            self.next_refresh
        } else {
            None
        }
    }
}
/// Finite paced renewal independent of whether cache expiry is FOREVER.
pub fn refresh_interval(forecast: u64) -> u64 {
    if forecast == u64::MAX {
        REFRESH_CAP
    } else {
        (forecast / 4).clamp(REFRESH_FLOOR, REFRESH_CAP)
    }
}
fn finite_deadline(now: u64, delay: u64) -> Result<u64, Error> {
    now.checked_add(delay)
        .filter(|end| *end != u64::MAX)
        .ok_or(Error::Overflow)
}
