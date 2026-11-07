use crate::{
    Cancellation, Completion, Control, ControlKind, ControlLoss, Epoch, Error, Instance, Kind,
    Limits, LocalReason, Loss, LossCause, Operation, Outcome, Progress, SecretKey, Stored,
    Submission, ZoneKey, ipc, scope::Scope,
};
use gnunet_client_host::{EndpointSource, channel::Channel};
use gnunet_service_runtime::{
    clock::{Deadline, RuntimeClock},
    framing::OwnedFrame,
};
use gnunet_types::Error as Fault;
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::time::{Instant, Sleep};
use zeroize::Zeroizing;
mod control;
mod io;
#[derive(Clone, Copy, Eq, PartialEq)]
enum Mode {
    General,
    Iterator,
    Monitor,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Origin<'id> {
    Request {
        epoch: Epoch<'id>,
        operation: Operation<'id>,
        rid: u32,
    },
    Control {
        epoch: Epoch<'id>,
        control: Control<'id>,
    },
}
struct StreamMeta<'id> {
    operation: Operation<'id>,
    credit: u64,
    synced: bool,
    stopping: bool,
}
struct ControlState<'id> {
    id: Control<'id>,
    kind: ControlKind,
    source: Option<OwnedFrame>,
    len: usize,
    sent: usize,
    queued: bool,
    epoch: Option<Epoch<'id>>,
    expires: u64,
    hard: Instant,
}
impl ControlState<'_> {
    fn submission(&self) -> Submission {
        if self.sent == self.len {
            Submission::Written { bytes: self.len }
        } else if self.sent > 0 {
            Submission::Partial {
                bytes: self.sent,
                total: self.len,
            }
        } else {
            Submission::Unsent
        }
    }
}
struct State<'id> {
    operation: Operation<'id>,
    rid: u32,
    kind: Kind,
    zone: Option<SecretKey>,
    source: Option<OwnedFrame>,
    len: usize,
    expires: u64,
    hard: Instant,
    retirement: Option<Instant>,
    epoch: Option<Epoch<'id>>,
    queued: bool,
    sent: usize,
    written: bool,
    reason: Option<LocalReason>,
    outcome: Option<Outcome>,
}
impl State<'_> {
    fn submission(&self) -> Submission {
        if self.written {
            Submission::Written { bytes: self.len }
        } else if self.sent > 0 {
            Submission::Partial {
                bytes: self.sent,
                total: self.len,
            }
        } else {
            Submission::Unsent
        }
    }
}
/// One original NAMESTORE general MQ. All private key/record frame buffers
/// erase on release; native writes and actual service results stay distinct.
/// Dedicated iterator/monitor wrappers reuse this driver with bounded credit.
pub struct Client<'id> {
    scope: Scope<'id>,
    channel: Channel<Origin<'id>>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    mode: Mode,
    stream: Option<StreamMeta<'id>>,
    control: Option<ControlState<'id>>,
    slots: Vec<Option<State<'id>>>,
    bytes: usize,
    admission_loss: Option<(Loss<'id>, Fault)>,
    control_close: Option<Loss<'id>>,
    next_rid: u64,
    epoch: Option<Epoch<'id>>,
    retry: bool,
    blocked: bool,
    paused: bool,
    closed: bool,
    yield_due: bool,
    read_first: bool,
    alarm: Option<Pin<Box<Deadline>>>,
    alarm_at: Option<u64>,
    native_alarm: Option<Pin<Box<Sleep>>>,
    native_at: Option<Instant>,
}
impl<'id> Client<'id> {
    /// Reserve finite operation metadata and subscribe to the explicit source's
    /// shared canonical clock. Opens no socket and creates no Resolver/task.
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let scope = Scope::new(instance)?;
        let clock = source.clock();
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.operations)
            .map_err(|_| Fault::Capacity)?;
        slots.resize_with(limits.operations, || None);
        Ok(Self {
            scope,
            channel: Channel::new(source, limits.framing())?,
            clock,
            limits,
            mode: Mode::General,
            stream: None,
            control: None,
            slots,
            bytes: 0,
            admission_loss: None,
            control_close: None,
            next_rid: 0,
            epoch: None,
            retry: false,
            blocked: false,
            paused: false,
            closed: false,
            yield_due: false,
            read_first: false,
            alarm: None,
            alarm_at: None,
            native_alarm: None,
            native_at: None,
        })
    }
    /// Original canonical clock; cloning starts no listener or network action.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Exact actual source, absent before attachment or after physical loss.
    #[must_use]
    pub const fn epoch(&self) -> Option<Epoch<'id>> {
        self.epoch
    }
    /// Current request, partial-drain, and undelivered result rows.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.slots.iter().flatten().count()
    }
    /// Exact official RID for a live original token; no foreign/stale fallback.
    pub fn request_id(&self, operation: Operation<'id>) -> Result<Option<u32>, Error> {
        let s = self.slots[self.index(operation)?]
            .as_ref()
            .ok_or(Fault::StaleGeneration)?;
        Ok(if s.kind == Kind::Monitor {
            None
        } else {
            Some(s.rid)
        })
    }
    fn index(&self, operation: Operation<'id>) -> Result<usize, Error> {
        if !self.scope.same(operation.scope) {
            return Err(Fault::StaleGeneration.into());
        }
        self.slots
            .iter()
            .position(|s| s.as_ref().is_some_and(|s| s.operation == operation))
            .ok_or_else(|| Fault::StaleGeneration.into())
    }
    fn admission_now(&mut self) -> Result<u64, Error> {
        match self.clock.sample() {
            Ok(sample) => Ok(sample.now.as_micros()),
            Err(error) => {
                // Public admission methods are also source boundaries: do not
                // leave attached/partial IO alive until a later drive call.
                self.blocked = true;
                self.channel.detach();
                let report = self.invalidate(LocalReason::Lost);
                self.retry = false;
                self.paused = true;
                self.admission_loss = Some((report, error));
                Err(error.into())
            }
        }
    }
    fn rid(&self) -> Result<u32, Fault> {
        u32::try_from(self.next_rid).map_err(|_| Fault::Overflow)
    }
    fn append(
        &mut self,
        request: ipc::Request<'_>,
        kind: Kind,
        zone: Option<SecretKey>,
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.blocked || self.paused || self.admission_loss.is_some() {
            return Err(Fault::NotReady.into());
        }
        let now = self.admission_now()?;
        if until <= now || until == u64::MAX {
            return Err(Fault::Deadline.into());
        }
        let hard = Instant::now()
            .checked_add(Duration::from_micros(until - now))
            .ok_or(Fault::Overflow)?;
        let row = self
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let len = request.encoded_len()?;
        let total = self.bytes.checked_add(len).ok_or(Fault::Overflow)?;
        if len > self.limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        if total > self.limits.source_bytes {
            return Err(Fault::Capacity.into());
        }
        let rid = self.rid()?;
        if request.request_id().is_some_and(|r| r != rid) {
            return Err(Fault::Conflict.into());
        }
        let mut encoded = Zeroizing::new(Vec::new());
        encoded
            .try_reserve_exact(len)
            .map_err(|_| Fault::Capacity)?;
        encoded.resize(len, 0);
        request.encode(&mut encoded)?;
        let operation = self.scope.operation()?;
        let next = self.next_rid.checked_add(1).ok_or(Fault::Overflow)?;
        self.slots[row] = Some(State {
            operation,
            rid,
            kind,
            zone,
            source: Some(OwnedFrame::new(std::mem::take(&mut *encoded))),
            len,
            expires: until,
            hard,
            retirement: None,
            epoch: None,
            queued: false,
            sent: 0,
            written: false,
            reason: None,
            outcome: None,
        });
        self.bytes = total;
        self.next_rid = next;
        self.alarm = None;
        self.alarm_at = None;
        Ok(operation)
    }
    fn label<'a>(&self, bytes: &'a [u8], nonempty: bool) -> Result<ipc::CString<'a>, Error> {
        if bytes.len() > self.limits.label_bytes {
            return Err(Fault::TooLarge.into());
        }
        if nonempty && bytes.is_empty() {
            return Err(Fault::InvalidInput.into());
        }
        Ok(ipc::CString::new(bytes)?)
    }
    fn hint<'a>(&self, bytes: &'a [u8]) -> Result<ipc::CString<'a>, Error> {
        if bytes.len() > self.limits.hint_bytes {
            return Err(Fault::TooLarge.into());
        }
        Ok(ipc::CString::new(bytes)?)
    }
    /// Submit complete STORE sets in one official frame. single_tx applies only
    /// to this frame; no standalone/cross-frame transaction control is invented.
    pub fn store(
        &mut self,
        zone: &SecretKey,
        sets: ipc::RecordSets<'_>,
        single_tx: bool,
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        if usize::from(sets.count()) > self.limits.record_sets {
            return Err(Fault::TooLarge.into());
        }
        for set in sets.iter() {
            let set = set?;
            self.label(set.label.wire_bytes(), false)?;
            if usize::from(set.records.count()) > self.limits.records {
                return Err(Fault::TooLarge.into());
            }
        }
        let rid = self.rid()?;
        self.append(
            ipc::Request::Store {
                rid,
                zone: zone.view()?,
                single_tx: u16::from(single_tx),
                reserved: 0,
                sets,
            },
            Kind::Store,
            Some(zone.try_clone_secret()),
            until,
        )
    }
    /// Encode the largest complete-set prefix that fits this one frame/resource
    /// budget and return its exact count. No partial label or record is emitted.
    /// The caller explicitly submits any remainder with its own operation.
    pub fn store_batch(
        &mut self,
        zone: &SecretKey,
        sets: &[ipc::StoreSet<'_>],
        single_tx: bool,
        until: u64,
    ) -> Result<Stored<'id>, Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.blocked || self.paused || self.admission_loss.is_some() {
            return Err(Fault::NotReady.into());
        }
        let now = self.admission_now()?;
        if until <= now || until == u64::MAX {
            return Err(Fault::Deadline.into());
        }
        if self.pending() == self.limits.operations {
            return Err(Fault::Capacity.into());
        }
        let prefix = ipc::STORE_PREFIX
            .checked_add(gnunet_identity::KEY_LEN)
            .ok_or(Fault::Overflow)?;
        let capacity = self
            .limits
            .frame_bytes
            .min(self.limits.source_bytes.saturating_sub(self.bytes))
            .saturating_sub(prefix);
        let (mut count, mut len) = (0usize, 0usize);
        for set in sets
            .iter()
            .take(self.limits.record_sets.min(usize::from(u16::MAX)))
        {
            self.label(set.label.wire_bytes(), false)?;
            if usize::from(set.records.count()) > self.limits.records {
                return Err(Fault::TooLarge.into());
            }
            let next = len.checked_add(set.encoded_len()?).ok_or(Fault::Overflow)?;
            if next > capacity {
                break;
            }
            len = next;
            count += 1;
        }
        if count == 0 && !sets.is_empty() {
            return Err(Fault::Capacity.into());
        }
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.try_reserve_exact(len).map_err(|_| Fault::Capacity)?;
        bytes.resize(len, 0);
        ipc::encode_sets(&sets[..count], &mut bytes)?;
        let sent = u16::try_from(count).map_err(|_| Fault::Overflow)?;
        let batch = ipc::RecordSets::new(&bytes, sent)?;
        let operation = self.store(zone, batch, single_tx, until)?;
        Ok(Stored {
            operation,
            sets_sent: sent,
        })
    }
    /// Actual filtered label lookup. It returns the service's found1/0/-1 and
    /// opaque record set without conflating loss/error with an absent label.
    pub fn lookup(
        &mut self,
        zone: &SecretKey,
        label: &[u8],
        filter: u16,
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        let label = self.label(label, true)?;
        let rid = self.rid()?;
        self.append(
            ipc::Request::Lookup {
                rid,
                zone: zone.view()?,
                label,
                filter,
                unused: 0,
            },
            Kind::Lookup,
            Some(zone.try_clone_secret()),
            until,
        )
    }
    /// Actual reverse delegation search for a public target in this private zone.
    /// Header-only no-results errors are retained; no missing key is fabricated.
    pub fn zone_to_name(
        &mut self,
        zone: &SecretKey,
        target: ZoneKey,
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        let rid = self.rid()?;
        self.append(
            ipc::Request::ZoneToName {
                rid,
                zone: zone.view()?,
                target,
            },
            Kind::ZoneToName,
            Some(zone.try_clone_secret()),
            until,
        )
    }
    /// Actual editor-hint/advisory lock acquisition/replacement and record read.
    /// This does not grant an exclusive lock or a private transaction channel.
    pub fn edit_begin(
        &mut self,
        zone: &SecretKey,
        label: &[u8],
        hint: &[u8],
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        let label = self.label(label, true)?;
        let hint = self.hint(hint)?;
        let rid = self.rid()?;
        self.append(
            ipc::Request::EditBegin {
                rid,
                zone: zone.view()?,
                label,
                hint,
                reserved: 0,
            },
            Kind::EditBegin,
            Some(zone.try_clone_secret()),
            until,
        )
    }
    /// Actual conditional editor-hint replacement. This is a new state-changing
    /// official RPC, independent of locally canceling an EditBegin callback.
    pub fn edit_cancel(
        &mut self,
        zone: &SecretKey,
        label: &[u8],
        hint: &[u8],
        replacement: &[u8],
        until: u64,
    ) -> Result<Operation<'id>, Error> {
        let label = self.label(label, true)?;
        let hint = self.hint(hint)?;
        let replacement = self.hint(replacement)?;
        let rid = self.rid()?;
        self.append(
            ipc::Request::EditCancel {
                rid,
                zone: zone.view()?,
                label,
                hint,
                replacement,
            },
            Kind::EditCancel,
            Some(zone.try_clone_secret()),
            until,
        )
    }
    fn local(state: &mut State<'id>, reason: LocalReason) {
        state.outcome = Some(Outcome::Local {
            reason,
            submission: state.submission(),
        });
        state.source = None;
        state.zone = None;
    }
    fn retire_request(&mut self, row: usize, reason: LocalReason) -> Result<Cancellation, Error> {
        let state = self.slots[row].as_mut().ok_or(Fault::StaleGeneration)?;
        if state.outcome.is_some() {
            return Ok(Cancellation::Completed);
        }
        if state.reason.is_some() {
            return Ok(Cancellation::Draining);
        }
        state.reason = Some(reason);
        if !state.queued {
            self.bytes = self.bytes.checked_sub(state.len).ok_or(Fault::Conflict)?;
            Self::local(state, reason);
            return Ok(Cancellation::Unsent);
        }
        if state.sent == 0 {
            let operation = state.operation;
            let count = self
                .channel
                .framing_mut()
                .ok_or(Fault::StaleGeneration)?
                .remove_unwritten(
                    |origin, _| matches!(origin,Origin::Request{operation:op,..}if op==operation),
                    |_, _| {},
                );
            if count != 1 {
                return Err(Fault::Conflict.into());
            }
            self.bytes = self.bytes.checked_sub(state.len).ok_or(Fault::Conflict)?;
            state.queued = false;
            Self::local(state, reason);
            return Ok(Cancellation::Unsent);
        }
        // RID-addressed replies need no FIFO tombstone after a full write. IDs
        // are never reused; the eventual old reply is safely ignored.
        if state.written {
            Self::local(state, reason);
            return Ok(Cancellation::Unknown);
        }
        state.retirement = Some(
            Instant::now()
                .min(state.hard)
                .checked_add(self.limits.retirement_grace)
                .ok_or(Fault::Overflow)?,
        );
        Ok(Cancellation::Draining)
    }
    /// Suppress this original callback. No wire CANCEL exists. Partial originals
    /// retain their exact suffix until whole local write or physical MQ stop.
    pub fn cancel(&mut self, operation: Operation<'id>) -> Result<Cancellation, Error> {
        let row = self.index(operation)?;
        self.retire_request(row, LocalReason::Cancelled)
    }
    fn complete(&mut self) -> Option<Completion<'id>> {
        let row = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(row, s)| {
                s.as_ref()
                    .filter(|s| s.outcome.is_some())
                    .map(|s| (row, s.operation.serial))
            })
            .min_by_key(|(_, serial)| *serial)
            .map(|(row, _)| row)?;
        let mut state = self.slots[row].take()?;
        Some(Completion {
            operation: state.operation,
            epoch: state.epoch,
            request_id: if state.kind == Kind::Monitor {
                None
            } else {
                Some(state.rid)
            },
            kind: state.kind,
            outcome: state.outcome.take()?,
        })
    }
    fn invalidate(&mut self, reason: LocalReason) -> Loss<'id> {
        let epoch = self.epoch.take();
        let (mut operations, mut exposed) = (0, 0);
        for state in self.slots.iter_mut().flatten() {
            if state.outcome.is_some() {
                continue;
            }
            operations += 1;
            if state.sent > 0 {
                exposed += 1;
            }
            let local = state.reason.unwrap_or(reason);
            Self::local(state, local);
        }
        let control = self.control.take().map(|c| ControlLoss {
            control: c.id,
            kind: c.kind,
            submission: c.submission(),
        });
        if let Some(stream) = self.stream.as_mut() {
            stream.credit = 0;
            stream.synced = false;
        }
        self.bytes = 0;
        self.alarm = None;
        self.alarm_at = None;
        self.native_alarm = None;
        self.native_at = None;
        Loss {
            epoch,
            operations,
            exposed,
            control,
        }
    }
    fn lost(&mut self, cause: LossCause) -> Progress<'id> {
        self.channel.detach();
        let report = self.invalidate(LocalReason::Lost);
        self.retry = self.limits.reconnect && !self.closed && !self.blocked;
        self.paused = !self.retry;
        Progress::Lost { report, cause }
    }
    /// Physically retire the original source, preserve original local outcomes,
    /// and permit a fresh source. No old operation or encoded frame is replayed.
    pub fn reconnect(&mut self) -> Result<Progress<'id>, Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.mode != Mode::General {
            return Err(Fault::Unsupported.into());
        }
        let event = self.lost(LossCause::Requested);
        self.retry = true;
        self.paused = false;
        Ok(event)
    }
    /// Explicitly recover original canonical clock/Resolver refusal. No actual
    /// attachment or server result is implied by recovery.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if !self.blocked {
            return Err(Fault::NotReady.into());
        }
        match self.channel.recover_ports() {
            Ok(()) | Err(Error::Protocol(Fault::NotReady)) => {}
            Err(error) => return Err(error),
        }
        self.blocked = false;
        self.paused = false;
        self.retry = true;
        Ok(())
    }
    /// Stop the physical owner first without reading a clock; then retire local
    /// originals. Queued completions remain drainable. This is no wire CANCEL,
    /// database/advisory rollback, fsync acknowledgement, or close errno.
    pub fn close(&mut self) -> Option<Loss<'id>> {
        if self.closed {
            return None;
        }
        self.channel.close();
        self.closed = true;
        self.retry = false;
        Some(self.invalidate(LocalReason::Closed))
    }
}
impl Drop for Client<'_> {
    fn drop(&mut self) {
        self.channel.close();
    }
}
