//! One bounded own-address pipeline over original PILS and Journal owners.
use crate::{
    Error,
    own::{
        ObservedAuthority, OriginalSignature, OwnRecordBackend, OwnedProjection, ProjectionLimits,
        SignatureAdmission, SignaturePlan, SignatureResult,
    },
    own_aggregate::{
        HelloSignatureAdmission, HelloSignaturePlan, HelloSignatureResult, OriginalHelloSignature,
    },
    own_store::{JournalBackend, ManagedTransaction},
};
use gnunet_pils::client as pc;
use gnunet_pils_host::client::{Client as NativeClient, Error as NativeError};
use gnunet_transport::{
    PeerId,
    addresses::PublicationId,
    own::{
        Certificate, CommitOutcome, CommitResult, PublicationBounds, REFRESH_FLOOR,
        RecordProvenance,
    },
    own_hello::HelloCandidate,
};
use gnunet_transport_host::{
    Server,
    peerstore::{Journal, JournalTransaction},
};
use gnunet_types::Error as ProtocolError;

struct Slot {
    certificate: Certificate,
    desired: bool,
}
struct Aggregate {
    candidate: HelloCandidate,
    set: PublicationId,
}
struct Receipt {
    set: PublicationId,
    refresh: Option<u64>,
}
#[derive(Clone, Copy)]
enum SignState {
    Waiting,
    Done,
    Failed,
    Retiring { attempted: bool },
}
enum Native<'a> {
    Address {
        slot: usize,
        original: OriginalSignature<'a>,
        state: SignState,
    },
    Hello {
        original: OriginalHelloSignature<'a>,
        state: SignState,
    },
}
impl<'a> Native<'a> {
    fn operation(&self) -> pc::OperationId<'a> {
        match self {
            Self::Address { original, .. } => original.operation(),
            Self::Hello { original, .. } => original.operation(),
        }
    }
    fn retire(&mut self) {
        let state = match self {
            Self::Address { state, .. } | Self::Hello { state, .. } => state,
        };
        if matches!(state, SignState::Waiting) {
            *state = SignState::Retiring { attempted: false };
        }
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum ClaimState {
    Unstarted,
    Writing,
    Unknown,
    Settled,
}
struct Claim {
    slot: usize,
    record: usize,
    state: ClaimState,
}
struct Managed {
    original: ManagedTransaction,
    abort: bool,
    hello: ClaimState,
}
enum Store {
    Managed(Managed),
    Withdrawal(JournalTransaction),
}
impl Store {
    fn outcome(&self) -> Option<CommitOutcome> {
        match self {
            Self::Managed(store) => store.original.outcome(),
            Self::Withdrawal(original) => original.outcome(),
        }
    }
}

/// One actual signing authority. No cache record creates an original ADD lease.
/// Slot indices remain fixed while an operation or transaction refers to them.
pub(crate) struct Publisher<'a> {
    authority: ObservedAuthority<'a>,
    maximum: usize,
    bounds: PublicationBounds,
    projection_limits: ProjectionLimits,
    slots: Vec<Slot>,
    claims: Vec<Claim>,
    scratch: Vec<u8>,
    native: Option<Native<'a>>,
    hello: Option<Aggregate>,
    receipt: Option<Receipt>,
    store: Option<Store>,
    desired_set: Option<PublicationId>,
    desired_count: usize,
    dirty: bool,
    retiring: bool,
    withdrawn: bool,
    retry_at: Option<u64>,
    last_now: u64,
    notice: Option<Error>,
}
impl<'a> Publisher<'a> {
    pub(crate) fn new(
        identity: pc::Identity<'a>,
        maximum_records: usize,
        bounds: PublicationBounds,
    ) -> Result<Self, Error> {
        let capacity = maximum_records
            .checked_add(1)
            .ok_or(ProtocolError::Capacity)?;
        let total_value_bytes = maximum_records
            .checked_mul(bounds.own_record_bytes)
            .and_then(|n| n.checked_add(bounds.hello_record_bytes))
            .ok_or(ProtocolError::Capacity)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| ProtocolError::Capacity)?;
        let mut claims = Vec::new();
        claims
            .try_reserve_exact(maximum_records)
            .map_err(|_| ProtocolError::Capacity)?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(bounds.address_bytes)
            .map_err(|_| ProtocolError::Capacity)?;
        scratch.resize(bounds.address_bytes, 0);
        Ok(Self {
            authority: ObservedAuthority::new(identity),
            maximum: maximum_records,
            bounds,
            projection_limits: ProjectionLimits {
                records: maximum_records,
                value_bytes: bounds.own_record_bytes,
                total_value_bytes,
            },
            slots,
            claims,
            scratch,
            native: None,
            hello: None,
            receipt: None,
            store: None,
            desired_set: None,
            desired_count: 0,
            dirty: true,
            retiring: false,
            withdrawn: false,
            retry_at: None,
            last_now: 0,
            notice: None,
        })
    }
    /// A paced resource refusal retains its actual native cause for the runtime.
    pub(crate) fn take_error(&mut self) -> Option<Error> {
        self.notice.take()
    }
    pub(crate) fn has_error(&self) -> bool {
        self.notice.is_some()
    }
    pub(crate) fn storage_failure(
        &self,
    ) -> Option<&gnunet_transport_host::peerstore::JournalFailure> {
        match self.store.as_ref()? {
            Store::Managed(store) => store.original.failure(),
            Store::Withdrawal(original) => original.failure(),
        }
    }
    pub(crate) fn storage_pending(&self) -> bool {
        self.store.is_some()
    }
    pub(crate) fn retired(&self) -> bool {
        self.retiring
            && self.withdrawn
            && self.native.is_none()
            && self.store.is_none()
            && self.hello.is_none()
            && self.slots.is_empty()
    }
    pub(crate) fn begin_retirement(&mut self) {
        if !self.retiring {
            self.retry_at = None;
        }
        self.retiring = true;
        self.desired_set = None;
        self.desired_count = 0;
        for slot in &mut self.slots {
            slot.desired = false;
            slot.certificate.retire();
        }
        if let Some(hello) = &mut self.hello {
            hello.candidate.retire();
        }
        if let Some(native) = &mut self.native {
            native.retire();
        }
        if let Some(Store::Managed(store)) = &mut self.store {
            store.abort = true;
        }
    }
    fn pace(&mut self, now: u64) -> Result<(), Error> {
        self.retry_at = Some(
            now.checked_add(REFRESH_FLOOR)
                .filter(|end| *end != u64::MAX)
                .ok_or(ProtocolError::Overflow)?,
        );
        Ok(())
    }
    fn record_notice(&mut self, cause: Error) -> Result<(), Error> {
        if self.notice.is_some() {
            return Err(cause);
        }
        self.notice = Some(cause);
        Ok(())
    }
    fn refuse_native(&mut self, cause: NativeError, now: u64) -> Result<bool, Error> {
        if matches!(
            &cause,
            NativeError::Protocol(ProtocolError::Capacity | ProtocolError::WouldBlock)
        ) {
            // These are bounded queue refusals, not successful admissions. Real
            // native I/O errors below move unchanged to the caller immediately.
            self.record_notice(cause.into())?;
            self.pace(now)?;
            Ok(true)
        } else {
            Err(cause.into())
        }
    }
    fn reconcile(
        &mut self,
        server: Option<&Server>,
        client: &NativeClient<'a>,
    ) -> Result<bool, Error> {
        let mut changed = false;
        if !self.retiring
            && (server.is_none()
                || !client
                    .identity()
                    .is_some_and(|current| self.authority.compatible(current)))
        {
            self.begin_retirement();
            changed = true;
        }
        if self.retiring {
            return Ok(changed);
        }
        let server = server.ok_or(ProtocolError::NotReady)?;
        let set = server.address_snapshot()?;
        let count = set.records().count();
        if count > self.maximum {
            return Err(ProtocolError::Capacity.into());
        }
        if self.desired_set.as_ref() != Some(set.id()) {
            self.desired_set = Some(set.id().clone());
            self.desired_count = count;
            self.dirty = true;
            changed = true;
        }
        for slot in &mut self.slots {
            if slot.desired && !server.owns_local_address(slot.certificate.lease()) {
                slot.desired = false;
                slot.certificate.retire();
                changed = true;
            }
        }
        if let Some(Native::Address { slot, state, .. }) = &mut self.native
            && !self.slots.get(*slot).ok_or(ProtocolError::Stale)?.desired
            && matches!(state, SignState::Waiting)
        {
            *state = SignState::Retiring { attempted: false };
        }
        if let Some(hello) = &mut self.hello
            && (!hello.candidate.matches(&set, self.authority.pure())
                || hello.candidate.expiry().as_micros() <= self.last_now)
        {
            hello.candidate.retire();
            if let Some(Native::Hello { state, .. }) = &mut self.native
                && matches!(state, SignState::Waiting)
            {
                *state = SignState::Retiring { attempted: false };
            }
            if let Some(Store::Managed(store)) = &mut self.store {
                store.abort = true;
            }
        }
        Ok(changed)
    }
    /// Reconcile and suppress retired logical work before the native client may
    /// reconnect/write. This performs no Journal or fresh signing admission.
    pub(crate) fn preflight(
        &mut self,
        server: Option<&Server>,
        client: &mut NativeClient<'a>,
        now: u64,
    ) -> Result<bool, Error> {
        self.last_now = now;
        let changed = self.reconcile(server, client)?;
        let retiring = self.native.as_ref().is_some_and(|native| match native {
            Native::Address { state, .. } | Native::Hello { state, .. } => {
                matches!(state, SignState::Retiring { .. })
            }
        });
        if retiring {
            self.advance_native(client, now).map(|step| step || changed)
        } else {
            Ok(changed)
        }
    }
    pub(crate) fn observe(
        &mut self,
        completion: &pc::Completion<'a>,
        client: &NativeClient<'a>,
        now: u64,
    ) -> Result<bool, Error> {
        self.last_now = now;
        if self
            .native
            .as_ref()
            .is_none_or(|native| native.operation() != completion.operation())
        {
            return Ok(false);
        }
        if !client
            .identity()
            .is_some_and(|current| self.authority.compatible(current))
        {
            self.begin_retirement();
        }
        match self.native.as_mut().ok_or(ProtocolError::Stale)? {
            Native::Address {
                slot,
                original,
                state,
            } => {
                if !matches!(state, SignState::Waiting | SignState::Retiring { .. }) {
                    return Ok(false);
                }
                let certificate = &mut self
                    .slots
                    .get_mut(*slot)
                    .ok_or(ProtocolError::Stale)?
                    .certificate;
                if matches!(
                    completion,
                    pc::Completion::Failed {
                        kind: pc::OperationKind::Sign,
                        ..
                    }
                ) && !client.operation_quiescent(original.operation())?
                {
                    *state = SignState::Failed;
                    return Ok(true);
                }
                let result = original.apply(certificate, completion, client.identity(), now)?;
                *state = SignState::Done;
                match result {
                    SignatureResult::Verified => self.dirty = true,
                    SignatureResult::Retired => {}
                    SignatureResult::Failed { retry, .. } => {
                        retry?;
                    }
                }
            }
            Native::Hello { original, state } => {
                if !matches!(state, SignState::Waiting | SignState::Retiring { .. }) {
                    return Ok(false);
                }
                let hello = &mut self.hello.as_mut().ok_or(ProtocolError::Stale)?.candidate;
                match original.apply(hello, completion, client, &mut self.scratch)? {
                    HelloSignatureResult::Verified => *state = SignState::Done,
                    HelloSignatureResult::Retired => *state = SignState::Done,
                    HelloSignatureResult::Failed { .. } => {
                        *state = SignState::Done;
                        if !self.retiring {
                            self.pace(now)?;
                        }
                    }
                    HelloSignatureResult::RetirementPending { .. } => {
                        *state = SignState::Retiring { attempted: true };
                    }
                }
            }
        }
        Ok(true)
    }
    fn advance_native(&mut self, client: &mut NativeClient<'a>, now: u64) -> Result<bool, Error> {
        let Some(native) = self.native.as_mut() else {
            return Ok(false);
        };
        match native {
            Native::Address {
                slot,
                original,
                state,
            } => {
                let certificate = &mut self
                    .slots
                    .get_mut(*slot)
                    .ok_or(ProtocolError::Stale)?
                    .certificate;
                match *state {
                    SignState::Waiting => return Ok(false),
                    SignState::Done => {
                        if !client.operation_quiescent(original.operation())? {
                            return Ok(false);
                        }
                    }
                    SignState::Failed => {
                        if !client.operation_quiescent(original.operation())? {
                            return Ok(false);
                        }
                        let retry = certificate.signing_retired(original.offer(), now)?;
                        self.native = None;
                        retry?;
                        return Ok(true);
                    }
                    SignState::Retiring { attempted } => {
                        certificate.retire();
                        if client.operation_quiescent(original.operation())? {
                            let result = original.finish_retirement(certificate, client, now)?;
                            let crate::own::SignatureRetirement::Retired { retry } = result else {
                                return Ok(false);
                            };
                            self.native = None;
                            retry?;
                            return Ok(true);
                        }
                        if !attempted {
                            *state = SignState::Retiring { attempted: true };
                            original.request_cancel(certificate, client)?;
                            return Ok(true);
                        }
                        return Ok(false);
                    }
                }
            }
            Native::Hello { original, state } => {
                let hello = &mut self.hello.as_mut().ok_or(ProtocolError::Stale)?.candidate;
                match *state {
                    SignState::Waiting => return Ok(false),
                    SignState::Done => {
                        if !original.operation_quiescent(client)? {
                            return Ok(false);
                        }
                    }
                    SignState::Failed => return Err(ProtocolError::Stale.into()),
                    SignState::Retiring { attempted } => {
                        if original.operation_quiescent(client)? {
                            if !original.finish_retirement(hello, client)? {
                                return Ok(false);
                            }
                            let failed = original.service_failure().is_some();
                            self.native = None;
                            self.hello = None;
                            if failed && !self.retiring {
                                self.pace(now)?;
                            }
                            return Ok(true);
                        }
                        if !attempted {
                            *state = SignState::Retiring { attempted: true };
                            original.request_cancel(hello, client)?;
                            return Ok(true);
                        }
                        return Ok(false);
                    }
                }
            }
        }
        self.native = None;
        if self
            .hello
            .as_ref()
            .is_some_and(|hello| hello.candidate.projection().is_none())
        {
            self.hello = None;
        }
        Ok(true)
    }
    fn all_ready(&self, now: u64) -> bool {
        self.slots.iter().filter(|slot| slot.desired).count() == self.desired_count
            && self
                .slots
                .iter()
                .filter(|slot| slot.desired)
                .all(|slot| slot.certificate.publication_record(now).is_ok())
    }
    fn prepare_store(
        &mut self,
        server: &Server,
        journal: &mut Journal,
        now: u64,
    ) -> Result<bool, Error> {
        let mut references = Vec::new();
        references
            .try_reserve_exact(self.desired_count)
            .map_err(|_| ProtocolError::Capacity)?;
        for slot in self.slots.iter().filter(|slot| slot.desired) {
            references.push(&slot.certificate);
        }
        let aggregate = self.hello.as_ref().ok_or(ProtocolError::NotReady)?;
        let projection = OwnedProjection::copy_from(
            server.address_snapshot()?,
            &self.authority,
            &references,
            &aggregate.candidate,
            self.projection_limits,
            now,
        )?;
        drop(references);
        self.claims.clear();
        for ((record, row), (slot, entry)) in projection.records().iter().enumerate().zip(
            self.slots
                .iter()
                .enumerate()
                .filter(|(_, entry)| entry.desired),
        ) {
            if row.provenance() == RecordProvenance::Staged {
                if entry.certificate.pending_id() != Some(row.offer()) {
                    return Err(ProtocolError::Stale.into());
                }
                self.claims.push(Claim {
                    slot,
                    record,
                    state: ClaimState::Unstarted,
                });
            }
        }
        let original = match JournalBackend::at(journal, now).prepare_own(projection) {
            Ok(original) => original,
            Err(refused) if refused.cause == ProtocolError::WouldBlock => {
                self.record_notice(refused.cause.into())?;
                self.pace(now)?;
                return Ok(true);
            }
            Err(refused) => return Err(refused.cause.into()),
        };
        // Retain the prepared original before any pure claim. If an invariant
        // refuses midway, the next step aborts that exact prepared transaction.
        self.store = Some(Store::Managed(Managed {
            original,
            abort: true,
            hello: ClaimState::Unstarted,
        }));
        let Some(Store::Managed(store)) = &mut self.store else {
            return Err(ProtocolError::Stale.into());
        };
        for claim in &mut self.claims {
            let offer = store.original.projection().records()[claim.record].offer();
            self.slots[claim.slot].certificate.commit_started(offer)?;
            claim.state = ClaimState::Writing;
        }
        self.hello
            .as_mut()
            .ok_or(ProtocolError::Stale)?
            .candidate
            .commit_started(store.original.projection().hello_offer())?;
        store.hello = ClaimState::Writing;
        store.abort = false;
        Ok(true)
    }
    fn settle_managed(&mut self, outcome: CommitOutcome, now: u64) -> Result<bool, Error> {
        let Some(Store::Managed(store)) = &mut self.store else {
            return Err(ProtocolError::Stale.into());
        };
        let mut error = None;
        for claim in &mut self.claims {
            if matches!(claim.state, ClaimState::Unstarted | ClaimState::Settled) {
                continue;
            }
            let offer = store.original.projection().records()[claim.record].offer();
            let certificate = &mut self.slots[claim.slot].certificate;
            let result = if claim.state == ClaimState::Unknown {
                certificate.recovered(offer, outcome, now)
            } else {
                certificate.commit_finished(offer, outcome, now)
            };
            match result {
                Ok(result) => {
                    claim.state = if matches!(outcome, CommitOutcome::Unknown(_)) {
                        ClaimState::Unknown
                    } else {
                        ClaimState::Settled
                    };
                    let clock = match result {
                        CommitResult::Committed { refresh, .. } => refresh,
                        CommitResult::NotCommitted { retry, .. } => retry,
                        CommitResult::Unknown(_) => Ok(0),
                    };
                    if let Err(cause) = clock {
                        error.get_or_insert(cause);
                    }
                }
                Err(cause) => {
                    error.get_or_insert(cause);
                }
            }
        }
        if !matches!(store.hello, ClaimState::Unstarted | ClaimState::Settled) {
            let aggregate = &mut self.hello.as_mut().ok_or(ProtocolError::Stale)?.candidate;
            let result = if store.hello == ClaimState::Unknown {
                aggregate.recovered(store.original.projection().hello_offer(), outcome)
            } else {
                aggregate.commit_finished(store.original.projection().hello_offer(), outcome)
            };
            match result {
                Ok(()) => {
                    store.hello = if matches!(outcome, CommitOutcome::Unknown(_)) {
                        ClaimState::Unknown
                    } else {
                        ClaimState::Settled
                    }
                }
                Err(cause) => {
                    error.get_or_insert(cause);
                }
            }
        }
        if matches!(outcome, CommitOutcome::Unknown(_)) {
            self.pace(now)?;
            return error.map_or(Ok(true), |cause| Err(cause.into()));
        }
        let settled = self
            .claims
            .iter()
            .all(|claim| matches!(claim.state, ClaimState::Unstarted | ClaimState::Settled))
            && matches!(store.hello, ClaimState::Unstarted | ClaimState::Settled);
        if !settled {
            return Err(error.unwrap_or(ProtocolError::Stale).into());
        }
        let aborted = store.abort;
        let failure = store.original.take_failure();
        if outcome == CommitOutcome::Committed {
            self.withdrawn = store.original.projection().records().is_empty()
                && store.original.projection().hello().is_none();
            if let Some(hello) = &self.hello {
                let refresh = match hello.candidate.refresh_deadline() {
                    Some(end) => match now
                        .checked_add(REFRESH_FLOOR)
                        .filter(|floor| *floor != u64::MAX)
                    {
                        Some(floor) => Some(end.max(floor)),
                        None => {
                            error.get_or_insert(ProtocolError::Overflow);
                            None
                        }
                    },
                    None => None,
                };
                self.receipt = Some(Receipt {
                    set: hello.set.clone(),
                    refresh,
                });
                self.dirty = self.retiring || self.desired_set.as_ref() != Some(&hello.set);
            }
        } else {
            self.dirty = true;
        }
        self.store = None;
        self.claims.clear();
        self.hello = None;
        // Preserve the actual original cause before a later timer calculation
        // can fail. Known pure results and disk certainty were already consumed.
        if !(aborted && outcome == CommitOutcome::NotCommitted(ProtocolError::Cancelled)) {
            if let Some(failure) = failure {
                self.record_notice(Error::Store(failure))?;
            } else if let CommitOutcome::NotCommitted(cause) = outcome {
                self.record_notice(cause.into())?;
            }
        }
        if outcome != CommitOutcome::Committed && !aborted && !self.retiring {
            self.pace(now)?;
        } else {
            self.retry_at = None;
        }
        error.map_or(Ok(true), |cause| Err(cause.into()))
    }
    fn advance_store(&mut self, journal: &mut Journal, now: u64) -> Result<bool, Error> {
        let store = self.store.as_mut().ok_or(ProtocolError::Stale)?;
        if matches!(store.outcome(), Some(CommitOutcome::Unknown(_)))
            && self.retry_at.is_some_and(|end| now < end)
        {
            return Ok(false);
        }
        match store {
            Store::Managed(store) => {
                let mut backend = JournalBackend::at(journal, now);
                let outcome = match store.original.outcome() {
                    Some(CommitOutcome::Unknown(_)) => backend.recover_own(&mut store.original),
                    Some(known) => known,
                    None if store.abort => backend.abort_own(&mut store.original)?,
                    None => backend.commit_own(&mut store.original),
                };
                self.settle_managed(outcome, now)
            }
            Store::Withdrawal(original) => {
                let outcome = match original.outcome() {
                    Some(CommitOutcome::Unknown(_)) => journal.recover(original),
                    Some(known) => known,
                    None => journal.commit(original),
                };
                match outcome {
                    CommitOutcome::Unknown(_) => {
                        self.pace(now)?;
                    }
                    CommitOutcome::Committed => {
                        let failure = original.take_failure();
                        self.store = None;
                        self.withdrawn = true;
                        self.receipt = None;
                        self.retry_at = None;
                        if let Some(failure) = failure {
                            self.record_notice(Error::Store(failure))?;
                        }
                    }
                    CommitOutcome::NotCommitted(cause) => {
                        let failure = original.take_failure();
                        self.store = None;
                        self.record_notice(failure.map_or_else(|| cause.into(), Error::Store))?;
                        self.pace(now)?;
                    }
                }
                Ok(true)
            }
        }
    }
    /// Perform at most one bounded admission, preparation, original transaction
    /// completion/recovery, or cleanup step. None never starts a new P29 effect.
    pub(crate) fn advance(
        &mut self,
        server: Option<&Server>,
        client: &mut NativeClient<'a>,
        journal: &mut Journal,
        now: u64,
        reserved_stamp: Option<u64>,
    ) -> Result<bool, Error> {
        self.last_now = now;
        let changed = self.reconcile(server, client)?;
        if self.store.is_some() {
            return self.advance_store(journal, now).map(|step| step || changed);
        }
        if self.native.is_some() {
            return self.advance_native(client, now).map(|step| step || changed);
        }
        if let Some(index) = self
            .slots
            .iter()
            .position(|slot| !slot.desired && slot.certificate.effects_quiescent())
        {
            self.slots.remove(index);
            return Ok(true);
        }
        if self.retiring {
            if self.hello.is_some() {
                self.hello = None;
                return Ok(true);
            }
            if self.withdrawn {
                return Ok(changed);
            }
            if self.retry_at.is_some_and(|end| now < end) {
                return Ok(changed);
            }
            match journal.prepare_managed(
                PeerId(*self.authority.pure().peer().as_bytes()),
                &[],
                None,
                now,
            ) {
                Ok(original) => {
                    self.store = Some(Store::Withdrawal(original));
                    return Ok(true);
                }
                Err(ProtocolError::WouldBlock) => return Ok(changed),
                Err(cause) => return Err(cause.into()),
            }
        }
        if changed {
            return Ok(true);
        }
        if self.notice.is_some()
            || self.retry_at.is_some_and(|end| now < end)
            || reserved_stamp.is_none()
        {
            return Ok(false);
        }
        let server = server.ok_or(ProtocolError::NotReady)?;
        if let Some(local) = server.local_addresses().find(|local| {
            !self
                .slots
                .iter()
                .any(|slot| slot.desired && slot.certificate.lease() == local.lease)
        }) {
            if self.slots.len() >= self.maximum {
                return Err(ProtocolError::Capacity.into());
            }
            let certificate = Certificate::new(
                local,
                self.authority.pure().clone(),
                self.bounds.own_record_bytes,
            )?;
            self.slots.push(Slot {
                certificate,
                desired: true,
            });
            self.dirty = true;
            return Ok(true);
        }
        for index in 0..self.slots.len() {
            let certificate = &mut self.slots[index].certificate;
            if certificate.signature_offer().is_some() {
                let identity = client.identity().ok_or(ProtocolError::NotReady)?;
                let plan = SignaturePlan::prepare(certificate, &self.authority, identity)?;
                return match plan.admit(certificate, client) {
                    SignatureAdmission::Queued(original) => {
                        self.native = Some(Native::Address {
                            slot: index,
                            original,
                            state: SignState::Waiting,
                        });
                        Ok(true)
                    }
                    SignatureAdmission::Refused { cause, .. } => self.refuse_native(cause, now),
                    SignatureAdmission::Retire { original, cause } => {
                        self.slots[index].desired = false;
                        self.slots[index].certificate.retire();
                        self.native = Some(Native::Address {
                            slot: index,
                            original,
                            state: SignState::Retiring { attempted: false },
                        });
                        Err(cause.into())
                    }
                };
            }
            if certificate.refresh_deadline().is_some_and(|end| now >= end) {
                certificate.prepare(now, reserved_stamp.ok_or(ProtocolError::NotReady)?)?;
                return Ok(true);
            }
        }
        if !self.all_ready(now) {
            if self.hello.is_some() {
                self.hello = None;
                return Ok(true);
            }
            return Ok(false);
        }
        if self.hello.is_none() {
            let set = server.address_snapshot()?;
            let needed = self.dirty
                || self.receipt.as_ref().is_none_or(|receipt| {
                    receipt.set != *set.id() || receipt.refresh.is_some_and(|end| now >= end)
                });
            if !needed {
                return Ok(false);
            }
            let candidate = HelloCandidate::prepare(
                set,
                self.authority.pure().clone(),
                now,
                self.bounds,
                self.maximum,
            )?;
            let set = server.address_snapshot()?.id().clone();
            self.hello = Some(Aggregate { candidate, set });
            return Ok(true);
        }
        let hello = &mut self.hello.as_mut().ok_or(ProtocolError::Stale)?.candidate;
        if hello.needs_signature() {
            let plan = HelloSignaturePlan::prepare(
                hello,
                &self.authority,
                client.identity().ok_or(ProtocolError::NotReady)?,
            )?;
            return match plan.admit(hello, client, &mut self.scratch) {
                HelloSignatureAdmission::Queued(original) => {
                    self.native = Some(Native::Hello {
                        original,
                        state: SignState::Waiting,
                    });
                    Ok(true)
                }
                HelloSignatureAdmission::RefusedPlan { cause, .. } => {
                    self.refuse_native(cause, now)
                }
                HelloSignatureAdmission::RetireAdmitted { original, cause } => {
                    self.native = Some(Native::Hello {
                        original,
                        state: SignState::Retiring { attempted: false },
                    });
                    Err(cause.into())
                }
            };
        }
        if hello.projection().is_some() {
            return self.prepare_store(server, journal, now);
        }
        self.hello = None;
        Ok(true)
    }
    pub(crate) fn next_deadline(&self) -> Option<u64> {
        if self.retired() {
            return None;
        }
        if let Some(store) = &self.store {
            return if matches!(store.outcome(), Some(CommitOutcome::Unknown(_))) {
                self.retry_at
            } else {
                Some(0)
            };
        }
        if self.native.is_some() || self.notice.is_some() {
            return None;
        }
        let floor = self.retry_at.unwrap_or(0);
        if self.retiring {
            return Some(floor);
        }
        let mut next = self
            .slots
            .iter()
            .filter(|slot| slot.desired)
            .filter_map(|slot| slot.certificate.refresh_deadline())
            .map(|end| end.max(floor))
            .min();
        if self.hello.is_some()
            || self
                .slots
                .iter()
                .any(|slot| slot.certificate.signature_offer().is_some())
            || self.slots.iter().filter(|slot| slot.desired).count() < self.desired_count
            || (self.dirty && self.all_ready(self.last_now))
        {
            next = Some(next.map_or(floor, |old| old.min(floor)));
        }
        if self.all_ready(self.last_now)
            && let Some(end) = self.receipt.as_ref().and_then(|receipt| receipt.refresh)
        {
            let end = end.max(floor);
            next = Some(next.map_or(end, |old| old.min(end)));
        }
        next
    }
}
