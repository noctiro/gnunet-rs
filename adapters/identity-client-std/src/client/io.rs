//! Original source cursors, ordered replies, and explicitly bounded directory.
use super::{Cache, Client, Mode, Origin, Record};
use crate::{
    Change, Ego, Epoch, Error, Identity, InventoryProgress, LocalReason, LossCause, Outcome,
    Progress, SecretKey, ipc,
};
use gnunet_client_host::channel::ConnectionStep;
use gnunet_service_runtime::{
    clock::Deadline,
    framing::{Class, ReadPoll, ReadStep},
};
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    future::{Future, poll_fn},
    task::{Context, Poll},
};
use tokio::time::Instant;

// An input is owned before its zeroizing retained RX is released. This enum
// deliberately implements no Debug/Clone/Serialize for sensitive UPDATE data.
enum Incoming {
    Result(u32),
    Update {
        name: Option<Vec<u8>>,
        key: SecretKey,
    },
    End,
}
impl<'id> Client<'id> {
    fn retired_ego(&mut self) -> Option<Ego<'id>> {
        let row = self
            .egos
            .iter()
            .position(|s| matches!(s, Some(Cache::Retired(_))))?;
        match self.egos[row].take() {
            Some(Cache::Retired(ego)) => Some(ego),
            _ => None,
        }
    }
    fn pending_event(&mut self) -> Option<Progress<'id>> {
        if let Some((report, error)) = self.pending_loss.take() {
            return Some(Progress::Lost {
                report,
                cause: LossCause::Ports(error.into()),
            });
        }
        if let Some(completion) = self.complete() {
            return Some(Progress::Completed(completion));
        }
        self.retired_ego().map(Progress::EgoRetired)
    }
    fn head(&self) -> Result<usize, Fault> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(row, s)| {
                s.as_ref()
                    .filter(|s| s.queued && s.outcome.is_none())
                    .map(|s| (row, s.operation.serial))
            })
            .min_by_key(|(_, serial)| *serial)
            .map(|(row, _)| row)
            .ok_or(Fault::Malformed)
    }
    fn incoming(&mut self) -> Result<Incoming, Error> {
        let input = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(Fault::NotReady)?;
        let value = match ipc::Response::decode(input)? {
            ipc::Response::ResultCode { code } => Incoming::Result(code),
            ipc::Response::EndOfList => Incoming::End,
            ipc::Response::Update { name, key } => {
                if self.mode == Mode::Operations {
                    return Err(Fault::Malformed.into());
                }
                let name = match name {
                    Some(name) => {
                        self.name(name)?;
                        let mut copy = Vec::new();
                        copy.try_reserve_exact(name.len())
                            .map_err(|_| Fault::Capacity)?;
                        copy.extend_from_slice(name);
                        Some(copy)
                    }
                    None => None,
                };
                Incoming::Update {
                    name,
                    key: SecretKey::from_serialized(key.expose_serialized())?,
                }
            }
        };
        self.channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .release_frame();
        Ok(value)
    }
    fn result(&mut self, epoch: Epoch<'id>, code: u32) -> Result<Progress<'id>, Error> {
        let row = self.head()?;
        let state = self.slots[row].as_mut().ok_or(Fault::StaleGeneration)?;
        if !state.written || state.epoch != Some(epoch) {
            return Err(Fault::Malformed.into());
        }
        if let Some(reason) = state.reason {
            Self::local(state, reason, Some(code));
        } else {
            state.outcome = Some(Outcome::Result {
                code,
                created: if code == 0 {
                    state.key.take()
                } else {
                    state.key = None;
                    None
                },
            });
        }
        let completion = self.complete().ok_or(Fault::Conflict)?;
        Ok(Progress::Completed(completion))
    }
    fn lookup_found(
        &mut self,
        epoch: Epoch<'id>,
        name: Option<Vec<u8>>,
        key: SecretKey,
    ) -> Result<Progress<'id>, Error> {
        let name = name.ok_or(Fault::Malformed)?;
        let row = self.head()?;
        let state = self.slots[row].as_mut().ok_or(Fault::StaleGeneration)?;
        if !state.written || state.epoch != Some(epoch) {
            return Err(Fault::Malformed.into());
        }
        if let Some(reason) = state.reason {
            Self::local(state, reason, None);
        } else {
            state.outcome = Some(Outcome::Found(Identity { name, key }));
        }
        Ok(Progress::Completed(self.complete().ok_or(Fault::Conflict)?))
    }
    fn update(
        &mut self,
        epoch: Epoch<'id>,
        name: Option<Vec<u8>>,
        key: SecretKey,
    ) -> Result<Progress<'id>, Error> {
        if self.mode == Mode::Lookup {
            return self.lookup_found(epoch, name, key);
        }
        if self.mode != Mode::Monitor || !self.start_written {
            return Err(Fault::Malformed.into());
        }
        // Bound scan, no private-key hash/identifier exposure and no key cloning
        // on rename. The supplied UPDATE key erases after comparison.
        let row = self.egos.iter().position(
            |slot| matches!(slot,Some(Cache::Live(r))if r.identity.key.constant_time_eq(&key)),
        );
        match (row, name) {
            (Some(row), Some(name)) => {
                let Some(Cache::Live(record)) = self.egos[row].as_mut() else {
                    return Err(Fault::Conflict.into());
                };
                record.identity.name = name;
                Ok(Progress::Ego {
                    ego: record.ego,
                    change: Change::Renamed,
                    initial: !self.initialized,
                })
            }
            (None, Some(name)) => {
                let row = self
                    .egos
                    .iter()
                    .position(Option::is_none)
                    .ok_or(Fault::Capacity)?;
                let ego = self.scope.ego(epoch)?;
                self.egos[row] = Some(Cache::Live(Record {
                    ego,
                    identity: Identity { name, key },
                }));
                Ok(Progress::Ego {
                    ego,
                    change: Change::Added,
                    initial: !self.initialized,
                })
            }
            (Some(row), None) => {
                let Some(Cache::Live(record)) = self.egos[row].take() else {
                    return Err(Fault::Conflict.into());
                };
                Ok(Progress::Deleted {
                    ego: record.ego,
                    identity: record.identity,
                })
            }
            (None, None) => Err(Fault::Malformed.into()),
        }
    }
    fn dispatch(&mut self, epoch: Epoch<'id>) -> Result<Progress<'id>, Error> {
        match self.incoming()? {
            Incoming::Result(code) => self.result(epoch, code),
            Incoming::Update { name, key } => self.update(epoch, name, key),
            Incoming::End => {
                if self.mode != Mode::Monitor || !self.start_written || self.initialized {
                    return Err(Fault::Malformed.into());
                }
                self.initialized = true;
                self.initial_hard = None;
                Ok(Progress::Initialized(epoch))
            }
        }
    }
    fn prepare(&mut self, epoch: Epoch<'id>) -> Result<Option<Progress<'id>>, Error> {
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        if framed.queued_frames() != 0 {
            return Ok(None);
        }
        if self.mode == Mode::Monitor && !self.start_queued {
            let mut bytes = [0u8; 4];
            ipc::Request::Start.encode(&mut bytes)?;
            framed.enqueue_copy(&bytes, Origin::Start(epoch), Class::Ordinary)?;
            self.start_queued = true;
            return Ok(Some(Progress::StartQueued(epoch)));
        }
        if self.mode == Mode::Monitor && !self.start_written {
            return Ok(None);
        }
        let row = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(row, s)| {
                s.as_ref()
                    .filter(|s| !s.queued && s.reason.is_none() && s.outcome.is_none())
                    .map(|s| (row, s.operation.serial))
            })
            .min_by_key(|(_, serial)| *serial)
            .map(|(row, _)| row);
        let Some(row) = row else {
            return Ok(None);
        };
        let state = self.slots[row].as_mut().ok_or(Fault::StaleGeneration)?;
        match framed.reserve(state.len, Class::Ordinary) {
            Ok(()) => {}
            Err(Fault::WouldBlock) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let frame = state.source.take().ok_or(Fault::Conflict)?;
        let operation = state.operation;
        if let Err(rejected) = framed.enqueue_owned(
            frame,
            Origin::Operation { epoch, operation },
            Class::Ordinary,
        ) {
            state.source = Some(rejected.value.0);
            return Err(rejected.reason.into());
        }
        state.epoch = Some(epoch);
        state.queued = true;
        Ok(Some(Progress::Queued { epoch, operation }))
    }
    fn write(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'id>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        let progress = match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_write(cx)
        {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Ok(self.lost(LossCause::Io(error)))),
            Poll::Ready(Ok(progress)) => progress,
        };
        self.read_first = true;
        match progress.origin {
            Origin::Start(original) => {
                if original != epoch || self.start_written {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                if progress.complete {
                    self.start_written = true;
                    return Poll::Ready(Ok(Progress::StartWritten(epoch)));
                }
            }
            Origin::Operation {
                epoch: original,
                operation,
            } => {
                if original != epoch {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                let row = self.index(operation)?;
                let state = self.slots[row].as_mut().ok_or(Fault::StaleGeneration)?;
                if state.epoch != Some(epoch)
                    || !state.queued
                    || state.written
                    || state.outcome.is_some()
                {
                    return Poll::Ready(Err(Fault::StaleGeneration.into()));
                }
                state.sent = state
                    .sent
                    .checked_add(progress.bytes)
                    .ok_or(Fault::Overflow)?;
                if state.sent > state.len {
                    return Poll::Ready(Err(Fault::Conflict.into()));
                }
                if progress.complete {
                    if state.sent != state.len {
                        return Poll::Ready(Err(Fault::Conflict.into()));
                    }
                    state.written = true;
                    self.bytes = self.bytes.checked_sub(state.len).ok_or(Fault::Conflict)?;
                    return Poll::Ready(Ok(Progress::Written { epoch, operation }));
                }
            }
        }
        Poll::Ready(Ok(Progress::Activity {
            read_bytes: 0,
            written_bytes: progress.bytes,
        }))
    }
    fn read(
        &mut self,
        cx: &mut Context<'_>,
        epoch: Epoch<'id>,
        native_pending: &mut bool,
    ) -> Poll<Result<Progress<'id>, Error>> {
        let observed = self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_read_observed(cx);
        let step = match observed {
            ReadPoll::NativePending => {
                *native_pending = true;
                Poll::Pending
            }
            ReadPoll::Deferred => Poll::Pending,
            ReadPoll::Ready(result) => Poll::Ready(result),
        };
        match step {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Ok(self.lost(LossCause::Io(error)))),
            Poll::Ready(Ok(ReadStep::Eof)) => Poll::Ready(Ok(self.lost(LossCause::Eof))),
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.read_first = false;
                if complete {
                    Poll::Ready(self.dispatch(epoch))
                } else {
                    Poll::Ready(Ok(Progress::Activity {
                        read_bytes: bytes,
                        written_bytes: 0,
                    }))
                }
            }
        }
    }
    // None checks only original native bounds. Canonical source time is used
    // only after the actual shared clock is ready and sampled successfully.
    fn expire(&mut self, now: Option<u64>) -> Result<Option<Progress<'id>>, Error> {
        let native = Instant::now();
        if self.initial_hard.is_some_and(|until| native >= until) {
            return Ok(Some(self.lost(LossCause::Resource(Fault::Deadline))));
        }
        if self
            .slots
            .iter()
            .flatten()
            .any(|s| s.outcome.is_none() && s.retirement.is_some_and(|until| native >= until))
        {
            return Ok(Some(self.lost(LossCause::RetirementDeadline)));
        }
        for row in 0..self.slots.len() {
            if self.slots[row].as_ref().is_some_and(|s| {
                s.outcome.is_none()
                    && s.reason.is_none()
                    && (now.is_some_and(|now| s.expires != u64::MAX && now >= s.expires)
                        || s.hard.is_some_and(|hard| native >= hard))
            }) {
                self.retire_request(row, LocalReason::Deadline)?;
            }
        }
        // A late first poll can create a retirement already in the past. Close
        // on this turn before any subsequent native I/O is attempted.
        let retirement_now = Instant::now();
        if self.slots.iter().flatten().any(|s| {
            s.outcome.is_none() && s.retirement.is_some_and(|until| retirement_now >= until)
        }) {
            return Ok(Some(self.lost(LossCause::RetirementDeadline)));
        }
        Ok(self.pending_event())
    }
    /// Earliest original logical request deadline. A callback/caller wait never
    /// renews it; native hard retirement independently survives clock rollback.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .filter(|s| s.outcome.is_none() && s.reason.is_none() && s.expires != u64::MAX)
            .map(|s| s.expires)
            .min()
    }
    // Register the existing native target before any canonical-clock wait.
    // This sleep is only a wake source: it never changes hard/retirement bounds.
    fn poll_native_alarm(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Result<(), Fault> {
        let native = self
            .slots
            .iter()
            .flatten()
            .filter(|s| s.outcome.is_none())
            .filter_map(|s| s.retirement.or(s.hard))
            .chain(self.initial_hard)
            .chain(until)
            .min();
        if let Some(target) = native {
            if self.native_at != Some(target) {
                self.native_alarm = Some(Box::pin(tokio::time::sleep_until(target)));
                self.native_at = Some(target);
            }
            if self
                .native_alarm
                .as_mut()
                .ok_or(Fault::NotReady)?
                .as_mut()
                .poll(cx)
                .is_ready()
            {
                cx.waker().wake_by_ref();
            }
        } else {
            self.native_alarm = None;
            self.native_at = None;
        }
        Ok(())
    }
    fn poll_alarm(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<(), Fault>> {
        self.poll_native_alarm(cx, until)?;
        if let Some(target) = self.next_deadline() {
            if self.alarm_at != Some(target) {
                self.alarm = Some(Box::pin(Deadline::at(
                    self.clock.clone(),
                    AbsoluteTime::from_micros(target),
                )?));
                self.alarm_at = Some(target);
            }
            match self
                .alarm
                .as_mut()
                .ok_or(Fault::NotReady)?
                .as_mut()
                .poll(cx)
            {
                Poll::Ready(result) => {
                    self.alarm = None;
                    self.alarm_at = None;
                    result?;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Pending => {}
            }
        } else {
            self.alarm = None;
            self.alarm_at = None;
        }
        Poll::Pending
    }
    fn port_loss(&mut self, error: Error) -> Progress<'id> {
        self.blocked = true;
        self.lost(LossCause::Ports(error))
    }
    fn classified_loss(&mut self, error: Error) -> Progress<'id> {
        let cause = match error {
            Error::Protocol(error)
                if matches!(error, Fault::Capacity | Fault::Overflow | Fault::TooLarge) =>
            {
                LossCause::Resource(error)
            }
            Error::Protocol(error) => LossCause::Protocol(error),
            other => {
                self.blocked = true;
                LossCause::Ports(other)
            }
        };
        self.lost(cause)
    }
    /// Check/arm the original native operation, initialization and retirement
    /// bounds before an enclosing owner waits on another source. No socket IO,
    /// canonical-clock sampling or deadline renewal occurs here. Actual local
    /// outcomes and source loss preserve the same original exposure and cause.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Progress<'id>> {
        if let Some(event) = self.pending_event() {
            return Some(event);
        }
        if self.closed || self.blocked || self.paused {
            return None;
        }
        match self.expire(None) {
            Ok(Some(event)) => return Some(event),
            Ok(None) => {}
            Err(error) => return Some(self.classified_loss(error)),
        }
        if let Err(error) = self.poll_native_alarm(cx, None) {
            return Some(self.port_loss(error.into()));
        }
        None
    }
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
        inventory_idle: &mut bool,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if let Some(event) = self.pending_event() {
            return Poll::Ready(Ok(event));
        }
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        if self.blocked || self.paused {
            if until.is_some_and(|target| Instant::now() >= target) {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
            return self
                .channel
                .poll_wait(cx, until)
                .map_ok(|()| Progress::WaitDeadline);
        }
        // A continuously racing clock revision may keep poll_clock pending.
        // Native hard/initial/control/drain bounds must still retire the original
        // source, and their wake must be registered before that independent wait.
        if let Some(event) = self.expire(None)? {
            return Poll::Ready(Ok(event));
        }
        if until.is_some_and(|target| Instant::now() >= target) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if let Err(error) = self.poll_native_alarm(cx, until) {
            return Poll::Ready(Ok(self.port_loss(error.into())));
        }
        match self.channel.poll_clock(cx) {
            Poll::Pending => {
                return self
                    .channel
                    .poll_wait(cx, until)
                    .map_ok(|()| Progress::WaitDeadline);
            }
            Poll::Ready(Err(error)) => return Poll::Ready(Ok(self.port_loss(error))),
            Poll::Ready(Ok(())) => {}
        }
        let now = match self.clock.sample() {
            Ok(s) => s.now.as_micros(),
            Err(error) => return Poll::Ready(Ok(self.port_loss(error.into()))),
        };
        if let Some(event) = self.expire(Some(now))? {
            return Poll::Ready(Ok(event));
        }
        if until.is_some_and(|target| Instant::now() >= target) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
        }
        if let Poll::Ready(Err(error)) = self.poll_alarm(cx, until) {
            return Poll::Ready(Ok(self.port_loss(error.into())));
        }
        if self.retry {
            self.channel.schedule_retry()?;
            self.retry = false;
        }
        if self.channel.framing().is_none() {
            return match self.channel.poll_connect(cx) {
                Poll::Pending => self
                    .channel
                    .poll_wait(cx, until)
                    .map_ok(|()| Progress::WaitDeadline),
                Poll::Ready(Err(error)) => Poll::Ready(Ok(self.port_loss(error))),
                Poll::Ready(Ok(ConnectionStep::Attached)) => {
                    let epoch = self.scope.epoch()?;
                    self.epoch = Some(epoch);
                    if self.mode == Mode::Monitor {
                        self.initial_hard = Some(
                            Instant::now()
                                .checked_add(self.limits.initialization_timeout)
                                .ok_or(Fault::Overflow)?,
                        );
                    }
                    Poll::Ready(Ok(Progress::Connected(epoch)))
                }
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after })) => {
                    Poll::Ready(Ok(Progress::ConnectRetry { error, retry_after }))
                }
                Poll::Ready(Ok(ConnectionStep::Unavailable(error))) => {
                    Poll::Ready(Ok(Progress::Unavailable(error)))
                }
            };
        }
        let epoch = self.epoch.ok_or(Fault::StaleGeneration)?;
        // Retained input is consumed before admitting more operations; updates
        // and FIFO results cannot be attributed to a replacement native source.
        if self.channel.framing().is_some_and(|f| f.frame().is_some()) {
            return Poll::Ready(self.dispatch(epoch));
        }
        if let Some(event) = self.prepare(epoch)? {
            return Poll::Ready(Ok(event));
        }
        let mut native_read_pending = false;
        if self.read_first {
            if let Poll::Ready(event) = self.read(cx, epoch, &mut native_read_pending) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.write(cx, epoch) {
                return Poll::Ready(event);
            }
        } else {
            if let Poll::Ready(event) = self.write(cx, epoch) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.read(cx, epoch, &mut native_read_pending) {
                return Poll::Ready(event);
            }
        }
        // Both actual read/write attempts above returned Pending. A cooperative
        // yield or a clock wait never reaches this point. Partial retained RX
        // still blocks a coordinating writer even when the socket needs input.
        *inventory_idle = native_read_pending
            && self.mode == Mode::Monitor
            && self.initialized
            && self.epoch == Some(epoch)
            && self.slots.iter().all(Option::is_none)
            && self.channel.framing().is_some_and(|framed| {
                framed.read_progress_bytes() == 0
                    && framed.frame().is_none()
                    && framed.queued_frames() == 0
            });
        self.channel
            .poll_wait(cx, until)
            .map_ok(|()| Progress::WaitDeadline)
    }
    /// Poll one bounded actual MQ step. Canceling the containing future retains
    /// all original read/write cursors. `until` is observation-only. Operations
    /// use their original finite deadlines and a separate finite native drain.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        self.poll_observed(cx, until, &mut false)
    }
    /// Coordinate against this initialized monitor without treating the ordinary
    /// driver's cooperative Pending as receive idleness. Every call preserves
    /// the original clock, native bounds, source errors and partial cursors.
    /// Source events must be handled before the caller advances another source.
    pub fn poll_inventory(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<InventoryProgress<'id>, Error>> {
        if self.mode != Mode::Monitor {
            return Poll::Ready(Err(Fault::InvalidInput.into()));
        }
        let mut idle = false;
        match self.poll_observed(cx, until, &mut idle) {
            Poll::Ready(result) => Poll::Ready(result.map(InventoryProgress::Source)),
            Poll::Pending if idle => Poll::Ready(Ok(InventoryProgress::Idle(
                self.epoch.ok_or(Fault::StaleGeneration)?,
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_observed(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
        inventory_idle: &mut bool,
    ) -> Poll<Result<Progress<'id>, Error>> {
        *inventory_idle = false;
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let step = match self.poll_step(cx, until, inventory_idle) {
            Poll::Ready(Err(error)) if !self.closed => Poll::Ready(Ok(self.classified_loss(error))),
            other => other,
        };
        if matches!(&step,Poll::Ready(Ok(event))if !matches!(event,Progress::Closed|Progress::WaitDeadline))
        {
            self.yield_due = true;
        }
        step
    }
    /// Caller-driven wrapper; starts no thread/task and retains original native
    /// cursors if this future is canceled between polls.
    pub async fn drive(&mut self, until: Option<Instant>) -> Result<Progress<'id>, Error> {
        poll_fn(|cx| self.poll(cx, until)).await
    }
}

#[cfg(test)]
mod late_poll_tests {
    use super::*;
    use crate::{Instance, Limits};
    use gnunet_client_host::EndpointSource;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert the expired partial-cursor state transition; no socket is opened"
    )]
    fn newly_due_retirement_closes_in_first_late_turn() -> Result<(), Box<dyn std::error::Error>> {
        let instance = Instance::new();
        let source = EndpointSource::unix("/unused-public-model-socket".into());
        let now = source.clock().sample()?.now.as_micros();
        let mut client = Client::new(
            &instance,
            source,
            Limits {
                retirement_grace: std::time::Duration::from_secs(1),
                ..Limits::default()
            },
        )?;
        client.rename(b"old", b"new", now + 1_000_000)?;
        // This pure cursor fixture creates no transport or write receipt.
        let state = client
            .slots
            .iter_mut()
            .flatten()
            .next()
            .ok_or(Fault::NotReady)?;
        state.source = None;
        state.queued = true;
        state.sent = 1;
        state.hard = Some(
            Instant::now()
                .checked_sub(std::time::Duration::from_secs(2))
                .ok_or(Fault::Overflow)?,
        );
        assert!(matches!(
            client.expire(None)?,
            Some(Progress::Lost {
                cause: LossCause::RetirementDeadline,
                ..
            })
        ));
        Ok(())
    }
}
