//! Caller-driven original snapshot cursors and monitor credit/backpressure.
//! These pure receipt methods must be called only by the actual native owner;
//! queue/write completion grants no remote processing or persistence authority.
use crate::inventory::{Budget, Lease, ReadPolicy};
use crate::{Change, Core, Filter, Query, SecretKeyView, Snapshot, Zone};
use alloc::{collections::VecDeque, rc::Rc};
use core::{fmt, mem};
use gnunet_types::Error;
/// Explicit source metadata and bounded scanning quantum.
#[derive(Clone, Copy, Debug)]
pub struct StreamLimits {
    /// Maximum committed batches retained behind one slow monitor.
    pub changes: usize,
    /// Maximum inspected/skipped rows in one prepare call.
    pub scan_rows: usize,
}
impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            changes: 8,
            scan_rows: 16,
        }
    }
}
impl StreamLimits {
    fn validate(self) -> Result<(), Error> {
        if self.changes == 0 || self.changes > 4096 || self.scan_rows == 0 || self.scan_rows > 65535
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
struct Domain {
    _private: u8,
}
/// Non-forgeable original local output identity. It never enters protocol bytes.
#[derive(Clone)]
pub struct Write {
    domain: Rc<Domain>,
    serial: u64,
}
impl PartialEq for Write {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &other.domain) && self.serial == other.serial
    }
}
impl Eq for Write {}
impl fmt::Debug for Write {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NamestoreWrite").field(&self.serial).finish()
    }
}
/// One immutable original output, borrowed while its exact cursor owns it.
#[derive(Debug)]
pub enum Item<'a> {
    /// Actual normalized data. A zero-count change represents a filtered deletion.
    Record {
        /// Original iterator RID, or monitor convention0.
        request: u32,
        /// Sensitive immutable original payload.
        query: &'a Query,
    },
    /// Natural iterator end. STOP receives no fabricated end/ack.
    End {
        /// Original iterator RID.
        request: u32,
    },
    /// Monitor initialization barrier; it consumes no result credit.
    Sync,
}
/// A prepared original output. Native callers encode into their erased frame,
/// preflight actual queue capacity, then queued/write the same token and bytes.
#[derive(Debug)]
pub struct Prepared<'a> {
    /// Exact original output authority.
    pub write: &'a Write,
    /// Immutable actual output.
    pub item: Item<'a>,
}
/// One bounded pure controller step; no native work or ACK is inferred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamProgress {
    /// A new immutable original is available from prepared().
    Prepared,
    /// Bounded scanning advanced without an output; call again cooperatively.
    Advanced,
    /// No result credit; only actual NEXT admission may increase it.
    WaitCredit,
    /// No pending change; monitor remains live.
    Idle,
    /// Original queued/exposed output must drain or its source actually close.
    Draining,
    /// Locally stopped, no queued/exposed output remains.
    Stopped,
    /// Natural iterator End was actually wholly locally written.
    Finished,
}
/// Local source debt at actual physical retirement, never a remote outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamLoss {
    /// An unadmitted prepared payload was erased locally.
    pub prepared: bool,
    /// One actual original frame was admitted but had no observed positive write.
    pub queued: bool,
    /// Positive original write exposure; remote processing is unknown.
    pub exposed: bool,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Stage {
    Prepared,
    Queued,
    Exposed,
}
enum Payload {
    Record(Query),
    End,
    Sync,
}
#[derive(Clone, Copy)]
enum Advance {
    Initial(usize),
    Change { revision: u64, next: usize },
    End,
    Sync,
}
struct Pending {
    write: Write,
    payload: Payload,
    stage: Stage,
    advance: Advance,
}
struct Batch {
    change: Change,
    index: usize,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    Iterator,
    Monitor,
}
struct Driver {
    source: Rc<Budget>,
    initial: Option<Snapshot>,
    initial_revision: u64,
    zone: Option<Zone>,
    filter: Filter,
    request: u32,
    mode: Mode,
    limits: StreamLimits,
    index: usize,
    synced: bool,
    credit: u64,
    last_offered: u64,
    queued_revision: u64,
    changes: VecDeque<Batch>,
    domain: Rc<Domain>,
    next_write: u64,
    pending: Option<Pending>,
    stopped: bool,
    finished: bool,
    _lease: Lease,
}
impl Driver {
    fn new(
        core: &Core,
        key: Option<SecretKeyView<'_>>,
        filter: Filter,
        request: u32,
        mode: Mode,
        iterate_first: bool,
        limits: StreamLimits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let metadata = mem::size_of::<Self>()
            .checked_add(2 * mem::size_of::<usize>() + 36)
            .and_then(|n| {
                if mode == Mode::Monitor {
                    limits
                        .changes
                        .checked_mul(mem::size_of::<Batch>())
                        .and_then(|m| n.checked_add(m))
                } else {
                    Some(n)
                }
            })
            .ok_or(Error::Overflow)?;
        let lease = core.stream_lease(metadata)?;
        let initial = core.snapshot()?;
        let revision = initial.revision();
        let index = if iterate_first {
            0
        } else {
            initial.rows().len()
        };
        let zone = key.map(|k| core.zone(k)).transpose()?;
        let mut changes = VecDeque::new();
        if mode == Mode::Monitor {
            changes
                .try_reserve_exact(limits.changes)
                .map_err(|_| Error::Capacity)?;
        }
        Ok(Self {
            source: initial.domain(),
            initial: Some(initial),
            initial_revision: revision,
            zone,
            filter,
            request,
            mode,
            limits,
            index,
            synced: false,
            credit: 1,
            last_offered: revision,
            queued_revision: revision,
            changes,
            domain: Rc::new(Domain { _private: 0 }),
            next_write: 0,
            pending: None,
            stopped: false,
            finished: false,
            _lease: lease,
        })
    }
    fn matches(&self, zone: &Zone) -> bool {
        self.zone.as_ref().is_none_or(|z| z.same(zone))
    }
    fn grant(&mut self, amount: u64) -> Result<(), Error> {
        if !self.source.live.get() {
            return Err(Error::OutcomeUnknown);
        }
        if self.stopped || self.finished {
            return Err(Error::Closed);
        }
        self.credit = self.credit.checked_add(amount).ok_or(Error::Overflow)?;
        Ok(())
    }
    fn set(&mut self, payload: Payload, advance: Advance) -> Result<StreamProgress, Error> {
        let serial = self.next_write.checked_add(1).ok_or(Error::Overflow)?;
        self.pending = Some(Pending {
            write: Write {
                domain: self.domain.clone(),
                serial,
            },
            payload,
            stage: Stage::Prepared,
            advance,
        });
        self.next_write = serial;
        Ok(StreamProgress::Prepared)
    }
    fn prepared(&self) -> Option<Prepared<'_>> {
        if !self.source.live.get() {
            return None;
        }
        let p = self
            .pending
            .as_ref()
            .filter(|p| p.stage == Stage::Prepared)?;
        Some(Prepared {
            write: &p.write,
            item: match &p.payload {
                Payload::Record(query) => Item::Record {
                    request: self.request,
                    query,
                },
                Payload::End => Item::End {
                    request: self.request,
                },
                Payload::Sync => Item::Sync,
            },
        })
    }
    fn checked(&self, w: &Write) -> Result<&Pending, Error> {
        self.pending
            .as_ref()
            .filter(|p| p.write == *w)
            .ok_or(Error::StaleGeneration)
    }
    fn reject(&mut self, w: &Write) -> Result<(), Error> {
        if self.checked(w)?.stage != Stage::Prepared {
            return Err(Error::NotReady);
        }
        drop(self.pending.take());
        Ok(())
    }
    fn can_queue(&self, w: &Write) -> Result<(), Error> {
        if !self.source.live.get() {
            return Err(Error::OutcomeUnknown);
        }
        if self.stopped {
            return Err(Error::Closed);
        }
        let p = self.checked(w)?;
        if p.stage != Stage::Prepared {
            return Err(Error::Replay);
        }
        if matches!(&p.payload, Payload::Record(_)) && self.credit == 0 {
            return Err(Error::NotReady);
        }
        Ok(())
    }
    fn queued(&mut self, w: &Write) -> Result<(), Error> {
        self.can_queue(w)?;
        let p = self.checked(w)?;
        if p.stage != Stage::Prepared {
            return Err(Error::Replay);
        }
        let debit = matches!(&p.payload, Payload::Record(_));
        let advance = p.advance;
        if debit && self.credit == 0 {
            return Err(Error::NotReady);
        }
        match advance {
            Advance::Initial(next) => self.index = next,
            Advance::Change { revision, next } => {
                let batch = self.changes.front_mut().ok_or(Error::StaleGeneration)?;
                if batch.change.after().revision() != revision {
                    return Err(Error::StaleGeneration);
                }
                batch.index = next;
                if next >= batch.change.len() {
                    self.queued_revision = revision;
                    drop(self.changes.pop_front());
                }
            }
            Advance::End => {}
            Advance::Sync => {
                self.synced = true;
                self.queued_revision = self.initial_revision;
                self.initial = None;
            }
        }
        if debit {
            self.credit -= 1;
        }
        self.pending.as_mut().ok_or(Error::StaleGeneration)?.stage = Stage::Queued;
        Ok(())
    }
    fn exposed(&mut self, w: &Write) -> Result<(), Error> {
        let p = self.checked(w)?;
        if p.stage != Stage::Queued && p.stage != Stage::Exposed {
            return Err(Error::NotReady);
        }
        self.pending.as_mut().ok_or(Error::StaleGeneration)?.stage = Stage::Exposed;
        Ok(())
    }
    fn written(&mut self, w: &Write) -> Result<(), Error> {
        if self.checked(w)?.stage != Stage::Exposed {
            return Err(Error::NotReady);
        }
        let p = self.pending.take().ok_or(Error::StaleGeneration)?;
        if matches!(p.payload, Payload::End) {
            self.finished = true;
            self.initial = None;
            self.zone = None;
        }
        Ok(())
    }
    fn stop(&mut self) {
        self.stopped = true;
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.stage == Stage::Prepared)
        {
            drop(self.pending.take());
        }
        self.changes.clear();
        self.initial = None;
        self.zone = None;
    }
    fn lost(&mut self) -> StreamLoss {
        let pending = self.pending.take();
        let loss = StreamLoss {
            prepared: pending.as_ref().is_some_and(|p| p.stage == Stage::Prepared),
            queued: pending.as_ref().is_some_and(|p| p.stage == Stage::Queued),
            exposed: pending.as_ref().is_some_and(|p| p.stage == Stage::Exposed),
        };
        drop(pending);
        self.stop();
        loss
    }
    fn prepare(&mut self, core: &Core, now: u64) -> Result<StreamProgress, Error> {
        if (!self.stopped || self.pending.is_some()) && !self.source.live.get() {
            return Err(Error::OutcomeUnknown);
        }
        if let Some(p) = &self.pending {
            return Ok(if p.stage == Stage::Prepared {
                StreamProgress::Prepared
            } else {
                StreamProgress::Draining
            });
        }
        if self.finished {
            return Ok(StreamProgress::Finished);
        }
        if self.stopped {
            return Ok(StreamProgress::Stopped);
        }
        core.source_domain(&self.source)?;
        let mut work = 0;
        if !self.synced {
            let snapshot = self.initial.as_ref().ok_or(Error::Closed)?;
            while self.index < snapshot.rows().len() && work < self.limits.scan_rows {
                let row = &snapshot.rows()[self.index];
                if !self.matches(row.zone()) {
                    self.index += 1;
                    work += 1;
                    continue;
                }
                if self.credit == 0 {
                    return Ok(StreamProgress::WaitCredit);
                }
                let query = core.query(
                    snapshot,
                    row.zone().clone(),
                    row.label(),
                    Some(row),
                    ReadPolicy {
                        filter: self.filter,
                        now,
                        nickname: true,
                    },
                )?;
                if query.records()?.count() == 0 {
                    self.index += 1;
                    work += 1;
                    continue;
                }
                return self.set(Payload::Record(query), Advance::Initial(self.index + 1));
            }
            if self.index < snapshot.rows().len() {
                return Ok(StreamProgress::Advanced);
            }
            return if self.mode == Mode::Iterator {
                self.set(Payload::End, Advance::End)
            } else {
                self.set(Payload::Sync, Advance::Sync)
            };
        }
        while work < self.limits.scan_rows {
            let Some(batch) = self.changes.front() else {
                return Ok(StreamProgress::Idle);
            };
            let change = batch.change.clone();
            let at = batch.index;
            let revision = change.after().revision();
            if at >= change.len() {
                self.queued_revision = revision;
                drop(self.changes.pop_front());
                work += 1;
                continue;
            }
            let changed = change.changed(at)?;
            if !self.matches(changed.zone) {
                self.changes
                    .front_mut()
                    .ok_or(Error::StaleGeneration)?
                    .index += 1;
                work += 1;
                continue;
            }
            let query = core.query(
                change.after(),
                changed.zone.clone(),
                changed.label,
                changed.after,
                ReadPolicy {
                    filter: self.filter,
                    now,
                    nickname: true,
                },
            )?;
            if query.records()?.count() == 0 {
                let before = core.query(
                    change.before(),
                    changed.zone.clone(),
                    changed.label,
                    changed.before,
                    ReadPolicy {
                        filter: self.filter,
                        now,
                        nickname: true,
                    },
                )?;
                if before.records()?.count() == 0 {
                    self.changes
                        .front_mut()
                        .ok_or(Error::StaleGeneration)?
                        .index += 1;
                    work += 1;
                    continue;
                }
            }
            if self.credit == 0 {
                return Ok(StreamProgress::WaitCredit);
            }
            return self.set(
                Payload::Record(query),
                Advance::Change {
                    revision,
                    next: at + 1,
                },
            );
        }
        Ok(StreamProgress::Advanced)
    }
    fn offer(&mut self, change: Change) -> Result<(), (Error, Change)> {
        if !self.source.live.get() {
            return Err((Error::OutcomeUnknown, change));
        }
        if self.stopped || self.finished {
            return Err((Error::Closed, change));
        }
        if !Rc::ptr_eq(&self.source, &change.after().domain())
            || change.before().revision() != self.last_offered
        {
            return Err((Error::StaleGeneration, change));
        }
        if self.changes.len() >= self.limits.changes {
            return Err((Error::Capacity, change));
        }
        self.last_offered = change.after().revision();
        self.changes.push_back(Batch { change, index: 0 });
        Ok(())
    }
}
/// One finite immutable original snapshot iterator. Initially one result credit;
/// NEXT grants explicit additional result count, End needs no result credit.
pub struct ZoneIterator(Driver);
impl ZoneIterator {
    /// Bind a new original cursor to this actual committed Core/scope and RID.
    pub fn new(
        core: &Core,
        request: u32,
        zone: Option<SecretKeyView<'_>>,
        filter: Filter,
        limits: StreamLimits,
    ) -> Result<Self, Error> {
        Driver::new(core, zone, filter, request, Mode::Iterator, true, limits).map(Self)
    }
    /// Grant only after actual original NEXT input admission, checking overflow.
    pub fn grant(&mut self, amount: u64) -> Result<(), Error> {
        self.0.grant(amount)
    }
    /// Inspect/prepare at most the declared scanning quantum using explicit time.
    pub fn prepare(&mut self, core: &Core, now: u64) -> Result<StreamProgress, Error> {
        self.0.prepare(core, now)
    }
    /// Borrow the immutable actual output; no implicit MQ or provider is touched.
    #[must_use]
    pub fn prepared(&self) -> Option<Prepared<'_>> {
        self.0.prepared()
    }
    /// Actual native queue refusal: release only the unadmitted prepared copy.
    pub fn reject_prepared(&mut self, write: &Write) -> Result<(), Error> {
        self.0.reject(write)
    }
    /// Preflight this exact original immediately before actual MQ admission.
    pub fn can_queue(&self, write: &Write) -> Result<(), Error> {
        self.0.can_queue(write)
    }
    /// Record actual admission of this original immutable output frame.
    pub fn queued(&mut self, write: &Write) -> Result<(), Error> {
        self.0.queued(write)
    }
    /// Record actual positive original local write, never a service ACK.
    pub fn exposed(&mut self, write: &Write) -> Result<(), Error> {
        self.0.exposed(write)
    }
    /// Record actual whole original local frame completion and release its lease.
    pub fn written(&mut self, write: &Write) -> Result<(), Error> {
        self.0.written(write)
    }
    /// Stop only this original cursor. Queued/exposed output remains a debt;
    /// the native owner must drain its suffix or actually close that original MQ.
    pub fn stop(&mut self) {
        self.0.stop();
    }
    /// Call only after the actual original physical source was independently
    /// closed. Erase its pending output/views and return exact local exposure.
    pub fn source_lost(&mut self) -> StreamLoss {
        self.0.lost()
    }
}
/// One bounded monitor: immutable initial snapshot/SYNC followed by every
/// original committed revision in order. Record results consume credit; SYNC
/// and invisible/empty revisions do not. No hidden subscriber/task exists.
pub struct Monitor(Driver);
impl Monitor {
    /// Bind this original source's monitor. Initially one result credit; no
    /// original snapshot/key can be rebound to a different recovered Core.
    pub fn new(
        core: &Core,
        zone: Option<SecretKeyView<'_>>,
        iterate_first: bool,
        filter: Filter,
        limits: StreamLimits,
    ) -> Result<Self, Error> {
        Driver::new(core, zone, filter, 0, Mode::Monitor, iterate_first, limits).map(Self)
    }
    /// Offer each actual committed revision exactly once. Capacity returns the
    /// unchanged original Change so its owner retains the notification debt.
    /// Record-producing store replies must remain withheld until queued_revision
    /// covers that original commit, or the monitor's source actually retires.
    pub fn offer(&mut self, change: Change) -> Result<(), (Error, Change)> {
        self.0.offer(change)
    }
    /// Last revision whose complete selected notification batch entered actual
    /// native queues (or contained no selected record effects). This does not
    /// prove the monitor processed it. Check synchronized() for initial barrier.
    #[must_use]
    pub const fn queued_revision(&self) -> u64 {
        self.0.queued_revision
    }
    /// Initial SYNC actually entered its original native output queue.
    #[must_use]
    pub const fn synchronized(&self) -> bool {
        self.0.synced
    }
    /// Grant only the actual admitted original monitor NEXT credit.
    pub fn grant(&mut self, amount: u64) -> Result<(), Error> {
        self.0.grant(amount)
    }
    /// One declared bounded scan/preparation, preserving pending originals.
    pub fn prepare(&mut self, core: &Core, now: u64) -> Result<StreamProgress, Error> {
        self.0.prepare(core, now)
    }
    /// Borrow the immutable original result/SYNC frame description.
    #[must_use]
    pub fn prepared(&self) -> Option<Prepared<'_>> {
        self.0.prepared()
    }
    /// Reject the unadmitted original without consuming cursor/credit.
    pub fn reject_prepared(&mut self, write: &Write) -> Result<(), Error> {
        self.0.reject(write)
    }
    /// Preflight the original source/token immediately before actual MQ admission.
    pub fn can_queue(&self, write: &Write) -> Result<(), Error> {
        self.0.can_queue(write)
    }
    /// Record actual original native queue admission and consume record credit.
    pub fn queued(&mut self, write: &Write) -> Result<(), Error> {
        self.0.queued(write)
    }
    /// Record actual positive original local exposure.
    pub fn exposed(&mut self, write: &Write) -> Result<(), Error> {
        self.0.exposed(write)
    }
    /// Record actual whole local completion, not monitor processing.
    pub fn written(&mut self, write: &Write) -> Result<(), Error> {
        self.0.written(write)
    }
    /// Stop preparation, preserving any original queued/exposed payload debt.
    pub fn stop(&mut self) {
        self.0.stop();
    }
    /// Actual original physical MQ closure must precede this loss receipt.
    pub fn source_lost(&mut self) -> StreamLoss {
        self.0.lost()
    }
}
