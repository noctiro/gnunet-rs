use crate::{
    AbsoluteTime, Cancellation, Completion, Epoch, Error, Instance, Kind, Limits, LocalReason,
    Loss, LossCause, Operation, Outcome, Progress, Submission, ipc, scope::Scope,
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
mod io;
#[derive(Clone, Copy, Eq, PartialEq)]
struct Origin<'id> {
    epoch: Epoch<'id>,
    operation: Operation<'id>,
    rid: u32,
}
struct State<'id> {
    operation: Operation<'id>,
    rid: u32,
    kind: Kind,
    query: Option<[u8; 64]>,
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
/// One original NAMECACHE MQ and bounded request/response storage. No private
/// Init, Resolver, thread, worker, decryption, or default success is introduced.
/// All original protocol IDs are BE32 and never reused within this owner.
pub struct Client<'id> {
    scope: Scope<'id>,
    channel: Channel<Origin<'id>>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    slots: Vec<Option<State<'id>>>,
    bytes: usize,
    admission_loss: Option<(Loss<'id>, Fault)>,
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
            slots,
            bytes: 0,
            admission_loss: None,
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
    pub fn request_id(&self, operation: Operation<'id>) -> Result<u32, Error> {
        Ok(self.slots[self.index(operation)?]
            .as_ref()
            .ok_or(Fault::StaleGeneration)?
            .rid)
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
        query: Option<[u8; 64]>,
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
        if request.request_id() != rid {
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
            query,
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
    /// Submit an official lookup for an exact derived public-key hash. A result
    /// is exposed only after real signature/query/inner-outer-expiry validation.
    /// Expiration filtering and zone/name authentication belong to the caller.
    pub fn lookup(&mut self, query: &[u8; 64], until: u64) -> Result<Operation<'id>, Error> {
        let rid = self.rid()?;
        self.append(
            ipc::Request::Lookup { rid, query },
            Kind::Lookup,
            Some(*query),
            until,
        )
    }
    /// Validate the carried-key signature on the complete encrypted block and
    /// submit actual CACHE. No plaintext/zone secret is accepted or decrypted.
    /// Outer expiration0 matches the official producer; inner expiry is signed.
    pub fn cache(&mut self, block: &[u8], until: u64) -> Result<Operation<'id>, Error> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.blocked || self.paused || self.admission_loss.is_some() {
            return Err(Fault::NotReady.into());
        }
        if self.pending() == self.limits.operations {
            return Err(Fault::Capacity.into());
        }
        let now = self.admission_now()?;
        if until <= now || until == u64::MAX {
            return Err(Fault::Deadline.into());
        }
        if block.len() > self.limits.block_bytes {
            return Err(Fault::TooLarge.into());
        }
        let len = ipc::BLOCK_PREFIX
            .checked_add(block.len())
            .ok_or(Fault::Overflow)?;
        if len > self.limits.frame_bytes {
            return Err(Fault::TooLarge.into());
        }
        if self.bytes.checked_add(len).ok_or(Fault::Overflow)? > self.limits.source_bytes {
            return Err(Fault::Capacity.into());
        }
        self.rid()?;
        gnunet_namecache::Block::decode(block)?.verify_signature()?;
        let rid = self.rid()?;
        self.append(
            ipc::Request::Cache {
                rid,
                expiration: AbsoluteTime::UNIX_EPOCH,
                block,
            },
            Kind::Cache,
            None,
            until,
        )
    }
    /// Actual BLOCK_DELETE request. Raw response distinguishes success, missing,
    /// and failure; closing/canceling the MQ never implies cache deletion.
    pub fn delete(&mut self, query: &[u8; 64], until: u64) -> Result<Operation<'id>, Error> {
        let rid = self.rid()?;
        self.append(
            ipc::Request::Delete { rid, query },
            Kind::Delete,
            None,
            until,
        )
    }
    fn local(state: &mut State<'id>, reason: LocalReason) {
        state.outcome = Some(Outcome::Local {
            reason,
            submission: state.submission(),
        });
        state.source = None;
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
                .remove_unwritten(|origin, _| origin.operation == operation, |_, _| {});
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
            request_id: state.rid,
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
        self.bytes = 0;
        self.alarm = None;
        self.alarm_at = None;
        self.native_alarm = None;
        self.native_at = None;
        Loss {
            epoch,
            operations,
            exposed,
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
    /// cache rollback, disk fsync acknowledgement, or independent close errno.
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
