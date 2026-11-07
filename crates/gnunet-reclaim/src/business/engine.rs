use super::{
    memory::{Lease, Quota, Table},
    records::Row,
    types::{Domain, SourceData, request_key},
    *,
};
use crate::{
    Identifier,
    ipc::{Iteration, Request},
};
use alloc::rc::Rc;
use core::{cell::Cell, mem};
use gnunet_gnsrecord::ZoneKey;
use gnunet_types::Error;
use gnunet_wire::official::namestore::Records;
/// Caller-owned shared bounded business allocation/source domain. Construction
/// opens no identity, resolver, store, provider, key file or background worker.
pub struct Factory {
    pub(super) quota: Rc<Quota>,
}
impl Factory {
    /// Configure the aggregate RAM/operation limits.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let fixed = super::memory::rc_cost::<Quota>()?;
        if fixed > limits.bytes {
            return Err(Error::Capacity);
        }
        Ok(Self {
            quota: Rc::new(Quota {
                limits,
                used: Cell::new(fixed),
                jobs: Cell::new(0),
                sources: Cell::new(0),
                serial: Cell::new(0),
            }),
        })
    }
    /// Current charged retained bytes, including original jobs/sources outliving
    /// this Factory. Allocator headers and caller/native buffers are separate.
    #[must_use]
    pub fn retained_bytes(&self) -> usize {
        self.quota.used.get()
    }
    /// Bind only an actually live native/provider source. This is a trusted port
    /// admission fact, never a convenience constructor for a fake successful MQ.
    pub fn bind(&self, provider: Provider) -> Result<Source, Error> {
        if self.quota.sources.get() == self.quota.limits.sources {
            return Err(Error::Capacity);
        }
        let lease = self
            .quota
            .reserve(super::memory::rc_cost::<SourceData>()?)?;
        let serial = self.quota.next()?;
        self.quota.sources.set(
            self.quota
                .sources
                .get()
                .checked_add(1)
                .ok_or(Error::Overflow)?,
        );
        Ok(Source(Rc::new(SourceData {
            quota: self.quota.clone(),
            provider,
            serial,
            live: Cell::new(true),
            _lease: lease,
        })))
    }
    /// Retain one original complete active request and original finite deadline.
    /// NEXT/STOP must target the existing Job through next/cancel; they never
    /// allocate a new iterator generation. No request is automatically replayed.
    pub fn start(&self, request: Request<'_>, now: u64, deadline: u64) -> Result<Job, Error> {
        if deadline <= now || deadline == u64::MAX {
            return Err(Error::Deadline);
        }
        let mode = match request {
            Request::StoreAttribute { .. } => Mode::StoreAttribute,
            Request::StoreCredential { .. } => Mode::StoreCredential,
            Request::DeleteAttribute { .. } => Mode::DeleteAttribute,
            Request::DeleteCredential { .. } => Mode::DeleteCredential,
            Request::IssueTicket { attributes, .. } => {
                if attributes.len() > self.quota.limits.items {
                    return Err(Error::Capacity);
                }
                Mode::Issue
            }
            Request::RevokeTicket { .. } => Mode::Revoke,
            Request::ConsumeTicket { ticket, .. } => {
                // The C consumer reads the issuer key before inspecting status.
                // Refuse a capability without that original public authority
                // before a job can manufacture a keyless failure response.
                super::records::capability(ticket)?;
                Mode::Consume
            }
            Request::IterateStart { kind, .. } => Mode::Iterate(kind),
            _ => return Err(Error::InvalidInput),
        };
        if self.quota.jobs.get() == self.quota.limits.jobs {
            return Err(Error::Capacity);
        }
        let original = Blob::encode(&self.quota, request.encoded_len()?, |o| request.encode(o))?;
        let lease = self.quota.reserve(
            mem::size_of::<Job>()
                .checked_add(super::memory::rc_cost::<Domain>()?)
                .ok_or(Error::Overflow)?,
        )?;
        let rows = Table::new(&self.quota, self.quota.limits.rows)?;
        let maximum = self
            .quota
            .limits
            .rows
            .checked_mul(2)
            .and_then(|n| {
                self.quota
                    .limits
                    .items
                    .checked_mul(2)
                    .and_then(|x| n.checked_add(x))
            })
            .and_then(|n| n.checked_add(1))
            .ok_or(Error::Overflow)?;
        let changes = Table::new(&self.quota, maximum)?;
        let attributes = Table::new(&self.quota, self.quota.limits.items)?;
        let presentations = Table::new(&self.quota, self.quota.limits.items)?;
        let references = Table::new(&self.quota, self.quota.limits.items)?;
        let rotations = Table::new(&self.quota, self.quota.limits.items)?;
        let removed = Table::new(&self.quota, self.quota.limits.items)?;
        let mut job = Job {
            quota: self.quota.clone(),
            _lease: lease,
            domain: Rc::new(Domain { _private: 0 }),
            original,
            mode,
            phase: Phase::Idle,
            deadline,
            serial: 0,
            pending: None,
            attempt: None,
            output: None,
            end: None,
            committed: 0,
            rows,
            changes,
            attributes,
            presentations,
            references,
            rotations,
            removed,
            snapshot: None,
            issuer: None,
            ticket: None,
            last_exposure: Exposure::Unsent,
            last_code: None,
            unknown: false,
            observed_now: now,
            work_left: Cell::new(self.quota.limits.work_units),
            credit: 1,
            cursor: (0, 0),
        };
        self.quota.jobs.set(
            self.quota
                .jobs
                .get()
                .checked_add(1)
                .ok_or(Error::Overflow)?,
        );
        if let Err(error) = job.initialize() {
            job.fail(error)?;
        }
        Ok(job)
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Mode {
    StoreAttribute,
    StoreCredential,
    DeleteAttribute,
    DeleteCredential,
    Issue,
    Consume,
    Revoke,
    Iterate(Iteration),
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Phase {
    Idle,
    Public,
    Scan,
    GenerateStore,
    GenerateTicket,
    GenerateRotation(usize),
    Present(usize),
    ConsumeAuth,
    ConsumeRef(usize),
    Writing(usize),
}
pub(super) struct Attempt {
    pub token: Effect,
    pub source: Source,
    pub exposure: Exposure,
    // Only a retained GNS read can wait for another actual connection. Old
    // source callbacks remain fenced while the native QueryId is still owned.
    pub parked: bool,
}
pub(super) struct OwnedId(zeroize::Zeroizing<[u8; 32]>);
impl OwnedId {
    pub fn new(id: Identifier) -> Self {
        Self(zeroize::Zeroizing::new(*id.bytes()))
    }
    pub fn value(&self) -> Identifier {
        Identifier::new(*self.0)
    }
}
pub(super) struct Rotation {
    pub old: OwnedId,
    pub new: Option<OwnedId>,
    pub moves_credential: bool,
}
pub(super) struct PendingOutput {
    pub token: Output,
    pub bytes: Blob,
    pub stage: u8,
    pub exposed: usize,
    pub final_item: bool,
}
/// One original actual business operation. Keep its owner until native provider
/// and output debts actually retire. Drop never pretends to cancel external IO.
pub struct Job {
    pub(super) quota: Rc<Quota>,
    _lease: Lease,
    pub(super) domain: Rc<Domain>,
    pub(super) original: Blob,
    pub(super) mode: Mode,
    pub(super) phase: Phase,
    pub(super) deadline: u64,
    pub(super) serial: u64,
    pub(super) pending: Option<Effect>,
    pub(super) attempt: Option<Attempt>,
    pub(super) output: Option<PendingOutput>,
    pub(super) end: Option<End>,
    pub(super) committed: usize,
    pub(super) rows: Table<Row>,
    pub(super) changes: Table<Row>,
    pub(super) attributes: Table<Blob>,
    pub(super) presentations: Table<Blob>,
    pub(super) references: Table<OwnedId>,
    pub(super) rotations: Table<Rotation>,
    pub(super) removed: Table<OwnedId>,
    pub(super) snapshot: Option<super::snapshot::Snapshot>,
    pub(super) issuer: Option<ZoneKey>,
    pub(super) ticket: Option<Blob>,
    pub(super) last_exposure: Exposure,
    pub(super) last_code: Option<u32>,
    pub(super) unknown: bool,
    pub(super) observed_now: u64,
    pub(super) work_left: Cell<usize>,
    pub(super) credit: u64,
    pub(super) cursor: (usize, usize),
}
impl Drop for Job {
    fn drop(&mut self) {
        self.quota.jobs.set(self.quota.jobs.get().saturating_sub(1));
    }
}
impl Job {
    pub(super) fn work(&self, units: usize) -> Result<(), Error> {
        consume_work(&self.work_left, units)
    }
    pub(super) fn request(&self) -> Result<Request<'_>, Error> {
        Request::decode(self.original.expose())
    }
    pub(super) fn key(&self) -> Result<gnunet_wire::official::identity::SecretKeyView<'_>, Error> {
        request_key(self.request()?).ok_or(Error::InvalidInput)
    }
    pub(super) fn transition(&mut self, phase: Phase) -> Result<(), Error> {
        if self.attempt.is_some() {
            return Err(Error::WouldBlock);
        }
        self.phase = phase;
        self.pending = if phase == Phase::Idle {
            None
        } else {
            self.serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
            Some(Effect {
                domain: self.domain.clone(),
                serial: self.serial,
            })
        };
        Ok(())
    }
    pub(super) fn provider(&self) -> Result<Provider, Error> {
        Ok(match self.phase {
            Phase::Public => Provider::Identity,
            Phase::GenerateStore | Phase::GenerateTicket | Phase::GenerateRotation(_) => {
                Provider::Entropy
            }
            Phase::Scan | Phase::Writing(_) => Provider::Namestore,
            Phase::Present(_) => Provider::Credential,
            Phase::ConsumeAuth | Phase::ConsumeRef(_) => Provider::Gns,
            Phase::Idle => return Err(Error::NotReady),
        })
    }
    fn exact(&self, effect: &Effect, source: &Source) -> Result<(), Error> {
        let attempt = self.attempt.as_ref().ok_or(Error::StaleGeneration)?;
        if attempt.token != *effect || !Rc::ptr_eq(&attempt.source.0, &source.0) {
            return Err(Error::StaleGeneration);
        }
        Ok(())
    }
    fn active(&self, effect: &Effect, source: &Source) -> Result<(), Error> {
        self.exact(effect, source)?;
        if self.attempt.as_ref().ok_or(Error::Stale)?.parked {
            return Err(Error::StaleGeneration);
        }
        Ok(())
    }
    fn remember_exposure(&mut self, exposure: Exposure) {
        // One GNS lookup may use several physically retired MQs. Keep a
        // bounded historical fact if a later retry/close was less exposed;
        // this never satisfies the new source's independent Written gate.
        self.last_exposure = if matches!(self.phase, Phase::ConsumeAuth | Phase::ConsumeRef(_)) {
            match (self.last_exposure, exposure) {
                (old @ Exposure::Written { .. }, _) => old,
                (_, written @ Exposure::Written { .. }) => written,
                (Exposure::Partial { bytes: a }, Exposure::Partial { bytes: b }) => {
                    Exposure::Partial { bytes: a.max(b) }
                }
                (old @ Exposure::Partial { .. }, Exposure::Unsent) => old,
                (_, current) => current,
            }
        } else {
            exposure
        };
    }
    /// Original request id only; no private effect metadata enters wire.
    pub fn request_id(&self) -> Result<u32, Error> {
        Ok(self.request()?.request_id())
    }
    /// Original deadline, never extended by a retry, completion or late poll.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }
    /// Current exact business/debt accounting, with no secret diagnostics.
    #[must_use]
    pub fn status(&self) -> Status {
        Status {
            end: self.end,
            committed_stores: self.committed,
            provider_debt: self.attempt.is_some(),
            output_debt: self.output.is_some(),
            exposure: self
                .attempt
                .as_ref()
                .map_or(self.last_exposure, |a| a.exposure),
            provider_code: self.last_code,
            outcome_unknown: self.unknown,
        }
    }
    /// True only when no actual admitted provider/output fact is still owed.
    #[must_use]
    pub fn quiescent(&self) -> bool {
        self.end.is_some() && self.attempt.is_none() && self.output.is_none()
    }
    /// Borrow the original immutable action; repeatedly reading does not admit
    /// a second native attempt. An admitted action is not offered again.
    pub fn prepared(&self) -> Result<Option<Prepared<'_>>, Error> {
        if self.end.is_some() || self.attempt.is_some() {
            return Ok(None);
        }
        let Some(effect) = self.pending.as_ref() else {
            return Ok(None);
        };
        Ok(Some(Prepared {
            effect,
            deadline: self.deadline,
            action: self.action()?,
        }))
    }
    /// Read the real purpose of this exact currently prepared original effect.
    /// This does not admit work, change phase, inspect a key or grant a result.
    pub fn lookup_kind(&self, effect: &Effect) -> Result<Option<super::LookupKind>, Error> {
        if self.pending.as_ref() != Some(effect) || self.end.is_some() || self.attempt.is_some() {
            return Err(Error::StaleGeneration);
        }
        Ok(match self.phase {
            Phase::ConsumeAuth => Some(super::LookupKind::Authorization),
            Phase::ConsumeRef(_) => Some(super::LookupKind::Attribute),
            _ => None,
        })
    }
    /// Record actual admission by the matching live original provider source.
    /// Queueing alone does not permit a remote result or count as STORE success.
    pub fn admitted(&mut self, effect: &Effect, source: &Source, now: u64) -> Result<(), Error> {
        self.expire(now);
        if self.end.is_some() {
            return Err(Error::Closed);
        }
        if self.attempt.is_some() {
            return Err(Error::Replay);
        }
        if self.pending.as_ref() != Some(effect)
            || !Rc::ptr_eq(&source.0.quota, &self.quota)
            || source.provider() != self.provider()?
            || !source.is_live()
        {
            return Err(Error::StaleGeneration);
        }
        if source.provider() == Provider::Gns {
            // New logical read, unlike rebind_lookup of this same effect.
            self.last_exposure = Exposure::Unsent;
        }
        self.attempt = Some(Attempt {
            token: effect.clone(),
            source: source.clone(),
            exposure: Exposure::Unsent,
            parked: false,
        });
        Ok(())
    }
    /// Park this exact read only after its original GNS MQ has really retired
    /// and its native owner still retains the same logical query for retry.
    /// Call before marking the old Source lost; no clock or new action is used.
    /// This cannot park NAMESTORE mutations, credential work or ended requests.
    pub fn park_lookup(&mut self, effect: &Effect, source: &Source) -> Result<(), Error> {
        self.exact(effect, source)?;
        if self.end.is_some() || self.unknown {
            return Err(Error::Closed);
        }
        if !matches!(self.phase, Phase::ConsumeAuth | Phase::ConsumeRef(_))
            || source.provider() != Provider::Gns
        {
            return Err(Error::Conflict);
        }
        let attempt = self.attempt.as_mut().ok_or(Error::Stale)?;
        if attempt.parked {
            return Err(Error::Replay);
        }
        let exposure = attempt.exposure;
        attempt.parked = true;
        self.remember_exposure(exposure);
        Ok(())
    }
    /// Rebind a parked original GNS read only after an actual new connection.
    /// The caller must retain the same native QueryId and original native hard.
    /// A new live Source from this Factory replaces the permanently lost one;
    /// neither the effect nor the original request/deadline is reconstructed.
    pub fn rebind_lookup(
        &mut self,
        effect: &Effect,
        old: &Source,
        new: &Source,
        now: u64,
    ) -> Result<(), Error> {
        self.expire(now);
        self.exact(effect, old)?;
        if self.end.is_some() || self.unknown {
            return Err(Error::Closed);
        }
        if !matches!(self.phase, Phase::ConsumeAuth | Phase::ConsumeRef(_))
            || old.provider() != Provider::Gns
            || old.is_live()
            || new.provider() != Provider::Gns
            || !new.is_live()
            || !Rc::ptr_eq(&new.0.quota, &self.quota)
            || Rc::ptr_eq(&old.0, &new.0)
        {
            return Err(Error::StaleGeneration);
        }
        let attempt = self.attempt.as_mut().ok_or(Error::Stale)?;
        if !attempt.parked {
            return Err(Error::NotReady);
        }
        attempt.source = new.clone();
        // This describes the newly attached source only. Previous real write
        // exposure is retained in last_exposure, not rewritten as never sent.
        attempt.exposure = Exposure::Unsent;
        attempt.parked = false;
        Ok(())
    }
    /// Original positive native request write. Local credential/entropy/key
    /// providers need no fabricated socket exposure callbacks.
    pub fn exposed(&mut self, effect: &Effect, source: &Source, bytes: usize) -> Result<(), Error> {
        self.active(effect, source)?;
        if bytes == 0 {
            return Err(Error::InvalidInput);
        }
        let attempt = self.attempt.as_mut().ok_or(Error::Stale)?;
        let before = match attempt.exposure {
            Exposure::Unsent => 0,
            Exposure::Partial { bytes } => bytes,
            Exposure::Written { .. } => return Err(Error::Replay),
        };
        attempt.exposure = Exposure::Partial {
            bytes: before.checked_add(bytes).ok_or(Error::Overflow)?,
        };
        Ok(())
    }
    /// Record actual original whole native write, after its positive bytes have
    /// been reported. Still not a service reply, durability or GNS publication.
    pub fn written(&mut self, effect: &Effect, source: &Source, total: usize) -> Result<(), Error> {
        self.active(effect, source)?;
        let attempt = self.attempt.as_mut().ok_or(Error::Stale)?;
        if attempt.exposure != (Exposure::Partial { bytes: total }) || total == 0 {
            return Err(Error::Conflict);
        }
        attempt.exposure = Exposure::Written { bytes: total };
        Ok(())
    }
    fn remote_ready(&self, effect: &Effect, source: &Source) -> Result<(), Error> {
        self.active(effect, source)?;
        if !source.is_live() {
            return Err(Error::StaleGeneration);
        }
        if !matches!(
            self.attempt.as_ref().ok_or(Error::Stale)?.exposure,
            Exposure::Written { .. }
        ) {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    /// Feed one actual original NAMESTORE iterator row. The exact original key
    /// must match, including key type. Capacity returns without consuming this
    /// row; retain the original native frame or explicitly stop the source.
    pub fn row(
        &mut self,
        effect: &Effect,
        source: &Source,
        key: gnunet_wire::official::identity::SecretKeyView<'_>,
        label: &[u8],
        records: Records<'_>,
        now: u64,
    ) -> Result<(), Error> {
        self.expire(now);
        self.remote_ready(effect, source)?;
        if self.end.is_some() {
            return Ok(());
        }
        if self.phase != Phase::Scan {
            return Err(Error::Conflict);
        }
        let expected = self.key()?.expose_serialized();
        let actual = key.expose_serialized();
        if expected
            .iter()
            .zip(actual)
            .fold(0u8, |n, (a, b)| n | (*a ^ *b))
            != 0
        {
            return Err(Error::Authentication);
        }
        self.work(
            self.rows
                .len()
                .checked_add(usize::from(records.count()))
                .ok_or(Error::Overflow)?,
        )?;
        if self.rows.iter().any(|r| r.label.expose() == label) {
            return Err(Error::Conflict);
        }
        let row = Row::copy(&self.quota, label, records)?;
        self.rows.push(row)
    }
    /// Consume one actual fully retired native/provider result. Wrong/late
    /// sources cannot advance a replacement. A valid completion is consumed
    /// once, including a subsequent business Capacity failure; do not replay it.
    pub fn complete(
        &mut self,
        effect: &Effect,
        source: &Source,
        result: Completion<'_>,
        now: u64,
    ) -> Result<(), Error> {
        self.expire(now);
        self.active(effect, source)?;
        if !self.result_matches(&result) {
            return Err(Error::Conflict);
        }
        if matches!(source.provider(), Provider::Namestore | Provider::Gns)
            && !matches!(result, Completion::Failed(_) | Completion::Unknown)
            && !matches!(
                self.attempt.as_ref().ok_or(Error::Stale)?.exposure,
                Exposure::Written { .. }
            )
        {
            return Err(Error::NotReady);
        }
        if matches!(
            result,
            Completion::Unknown | Completion::Failed(Error::OutcomeUnknown)
        ) {
            self.unknown = true;
            if self.end.is_none() {
                self.end = Some(End::Unknown);
            }
        }
        if !source.is_live() && self.end.is_none() {
            self.end = Some(End::SourceLost);
        }
        self.remember_exposure(self.attempt.as_ref().ok_or(Error::Stale)?.exposure);
        if let Completion::Stored(code) = &result {
            self.last_code = Some(*code);
        }
        self.attempt = None;
        self.pending = None;
        if self.end.is_some() {
            if matches!(result, Completion::Stored(0)) {
                self.committed = self.committed.checked_add(1).ok_or(Error::Overflow)?;
            }
            self.phase = Phase::Idle;
            return Ok(());
        }
        let step = match result {
            Completion::Failed(e) => Err(e),
            Completion::Unknown => {
                self.end = Some(End::Unknown);
                self.phase = Phase::Idle;
                return Ok(());
            }
            r => self.apply(r),
        };
        if let Err(error) = step {
            self.fail(error)?;
        }
        Ok(())
    }
    /// Actual cancellation/physical stop retirement of the ORIGINAL admitted
    /// native operation. Revocation/deadline alone is insufficient to call this.
    /// It remains legal for an already revoked Source so cleanup cannot deadlock.
    pub fn retired(&mut self, effect: &Effect, source: &Source) -> Result<(), Error> {
        self.exact(effect, source)?;
        self.remember_exposure(self.attempt.as_ref().ok_or(Error::Stale)?.exposure);
        self.attempt = None;
        self.pending = None;
        self.phase = Phase::Idle;
        if self.end.is_none() {
            self.end = Some(End::SourceLost)
        }
        Ok(())
    }
    /// Local callback cancellation. It admits no later effect and claims no
    /// rollback; the exact original provider/output debt must still retire.
    pub fn cancel(&mut self) {
        if self.end.is_none() {
            self.end = Some(End::Cancelled)
        }
        self.pending = None;
        if self.attempt.is_none() {
            self.phase = Phase::Idle
        }
        if self.output.as_ref().is_some_and(|o| o.stage == 0) {
            self.output = None;
        }
    }
    /// Check the caller's original absolute clock. Source revocation stops new
    /// state immediately, while actual old IO receipts remain independently due.
    pub fn expire(&mut self, now: u64) {
        if self.end.is_none() {
            if now < self.observed_now {
                self.end = Some(End::Failed(Error::TimeUncertain));
            } else if now >= self.deadline {
                self.end = Some(End::Deadline);
            } else if self
                .attempt
                .as_ref()
                .is_some_and(|a| !a.parked && !a.source.is_live())
            {
                self.end = Some(End::SourceLost);
            }
        }
        self.observed_now = self.observed_now.max(now);
        if matches!(
            self.end,
            Some(End::Cancelled | End::Deadline | End::SourceLost | End::Unknown)
        ) {
            self.pending = None;
            if self.output.as_ref().is_some_and(|o| o.stage == 0) {
                self.output = None;
            }
        }
    }
    /// Actual official NEXT from the original app source, one credit per request.
    /// No output completion/local write is silently counted as client NEXT.
    pub fn grant_next(&mut self) -> Result<(), Error> {
        if !matches!(self.mode, Mode::Iterate(_)) {
            return Err(Error::Unsupported);
        }
        if self.end.is_some() {
            return Err(Error::Closed);
        }
        self.credit = self
            .credit
            .checked_add(1)
            .filter(|n| *n <= self.quota.limits.items as u64)
            .ok_or(Error::Capacity)?;
        if self.phase == Phase::Idle && self.output.is_none() {
            self.iteration_output()?;
        }
        Ok(())
    }
    /// Borrow the one exact immutable response, prepared only once. Its bytes
    /// carry the original official RID and omit all private effect/source IDs.
    #[must_use]
    pub fn response(&self) -> Option<ResponseView<'_>> {
        self.output.as_ref().map(|o| ResponseView {
            output: &o.token,
            bytes: &o.bytes,
        })
    }
    /// Actual immutable app-MQ admission, distinct from business provider success.
    pub fn output_queued(&mut self, token: &Output) -> Result<(), Error> {
        let o = self.output.as_mut().ok_or(Error::Stale)?;
        if o.token != *token || o.stage != 0 {
            return Err(Error::Replay);
        }
        o.stage = 1;
        Ok(())
    }
    /// Actual positive original response write exposure.
    pub fn output_exposed(&mut self, token: &Output, bytes: usize) -> Result<(), Error> {
        let o = self.output.as_mut().ok_or(Error::Stale)?;
        if o.token != *token || o.stage == 0 || bytes == 0 {
            return Err(Error::Stale);
        }
        o.exposed = o
            .exposed
            .checked_add(bytes)
            .filter(|n| *n <= o.bytes.len())
            .ok_or(Error::Overflow)?;
        o.stage = 2;
        Ok(())
    }
    /// Whole original response actually wrote. This grants no remote consumption
    /// or extra iterator credit. Natural END finishes only after this receipt.
    pub fn output_written(&mut self, token: &Output) -> Result<(), Error> {
        let o = self.output.as_ref().ok_or(Error::Stale)?;
        if o.token != *token || o.exposed != o.bytes.len() {
            return Err(Error::Conflict);
        }
        let final_item = o.final_item;
        self.output = None;
        if final_item {
            if self.end.is_none() {
                self.end = Some(End::Complete)
            }
        } else if self.end.is_none() && self.phase == Phase::Idle {
            self.iteration_output()?;
        }
        Ok(())
    }
    /// Actual original app-MQ physical loss; it erases undelivered output but
    /// never retires a still-live independent NAMESTORE/GNS provider operation.
    pub fn output_lost(&mut self) {
        self.output = None;
        self.cancel();
    }
}

pub(super) fn consume_work(left: &Cell<usize>, units: usize) -> Result<(), Error> {
    left.set(left.get().checked_sub(units).ok_or(Error::Capacity)?);
    Ok(())
}
