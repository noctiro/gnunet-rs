//! Actual original source cursors, addressed responses, and public verification.
use super::{Client, Origin};
use crate::{
    AbsoluteTime, Block, Epoch, Error, Kind, LocalReason, LossCause, Outcome, Progress, ipc,
};
use gnunet_client_host::channel::ConnectionStep;
use gnunet_service_runtime::{
    clock::Deadline,
    framing::{Class, ReadStep},
};
use gnunet_types::Error as Fault;
use std::{
    future::{Future, poll_fn},
    task::{Context, Poll},
};
use tokio::time::Instant;
impl<'id> Client<'id> {
    fn dispatch(&mut self, epoch: Epoch<'id>) -> Result<Progress<'id>, Error> {
        let input = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(Fault::NotReady)?;
        let response = ipc::Response::decode(input)?;
        let request_id = response.request_id();
        let row = self.slots.iter().position(|slot| {
            slot.as_ref()
                .is_some_and(|state| state.rid == request_id && state.outcome.is_none())
        });
        let Some(row) = row else {
            self.channel
                .framing_mut()
                .ok_or(Fault::NotReady)?
                .release_frame();
            return Ok(Progress::Ignored { epoch, request_id });
        };
        let state = self.slots[row].as_ref().ok_or(Fault::StaleGeneration)?;
        if !state.queued || !state.written || state.epoch != Some(epoch) {
            return Err(Fault::Malformed.into());
        }
        let outcome = match response {
            ipc::Response::Lookup {
                expiration, block, ..
            } if state.kind == Kind::Lookup => {
                if expiration != AbsoluteTime::UNIX_EPOCH && block.len() > self.limits.block_bytes {
                    return Err(Fault::TooLarge.into());
                }
                let query = state.query.as_ref().ok_or(Fault::Conflict)?;
                let verified = gnunet_namecache::verify_lookup(query, expiration, block)?;
                let owned = if verified.is_some() {
                    let mut bytes = Vec::new();
                    bytes
                        .try_reserve_exact(block.len())
                        .map_err(|_| Fault::Capacity)?;
                    bytes.extend_from_slice(block);
                    Some(Block {
                        bytes,
                        query: *query,
                        expiration,
                    })
                } else {
                    None
                };
                Outcome::Lookup(owned)
            }
            ipc::Response::Cache { result, .. } if state.kind == Kind::Cache => {
                Outcome::Cache(result)
            }
            ipc::Response::Delete { result, .. } if state.kind == Kind::Delete => {
                Outcome::Delete(result)
            }
            _ => return Err(Fault::Malformed.into()),
        };
        self.channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .release_frame();
        self.slots[row]
            .as_mut()
            .ok_or(Fault::StaleGeneration)?
            .outcome = Some(outcome);
        Ok(Progress::Completed(self.complete().ok_or(Fault::Conflict)?))
    }
    fn prepare(&mut self, epoch: Epoch<'id>) -> Result<Option<Progress<'id>>, Error> {
        let framed = self.channel.framing_mut().ok_or(Fault::NotReady)?;
        if framed.queued_frames() != 0 {
            return Ok(None);
        }
        let row = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(row, slot)| {
                slot.as_ref()
                    .filter(|state| {
                        !state.queued && state.reason.is_none() && state.outcome.is_none()
                    })
                    .map(|state| (row, state.operation.serial))
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
        let request_id = state.rid;
        let origin = Origin {
            epoch,
            operation,
            rid: request_id,
        };
        if let Err(rejected) = framed.enqueue_owned(frame, origin, Class::Ordinary) {
            state.source = Some(rejected.value.0);
            return Err(rejected.reason.into());
        }
        state.queued = true;
        state.epoch = Some(epoch);
        Ok(Some(Progress::Queued {
            epoch,
            operation,
            request_id,
        }))
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
        let origin = progress.origin;
        if origin.epoch != epoch {
            return Poll::Ready(Err(Fault::StaleGeneration.into()));
        }
        let row = self.index(origin.operation)?;
        let state = self.slots[row].as_mut().ok_or(Fault::StaleGeneration)?;
        if state.rid != origin.rid
            || state.epoch != Some(epoch)
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
        self.read_first = true;
        if progress.complete {
            if state.sent != state.len {
                return Poll::Ready(Err(Fault::Conflict.into()));
            }
            state.written = true;
            self.bytes = self.bytes.checked_sub(state.len).ok_or(Fault::Conflict)?;
            if let Some(reason) = state.reason {
                Self::local(state, reason);
            }
            return Poll::Ready(Ok(Progress::Written {
                epoch,
                operation: origin.operation,
                request_id: origin.rid,
            }));
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
    ) -> Poll<Result<Progress<'id>, Error>> {
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_read(cx)
        {
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
        if self.slots.iter().flatten().any(|state| {
            state.outcome.is_none() && state.retirement.is_some_and(|until| native >= until)
        }) {
            return Ok(Some(self.lost(LossCause::RetirementDeadline)));
        }
        for row in 0..self.slots.len() {
            if self.slots[row].as_ref().is_some_and(|state| {
                state.outcome.is_none()
                    && state.reason.is_none()
                    && (now.is_some_and(|now| now >= state.expires) || native >= state.hard)
            }) {
                self.retire_request(row, LocalReason::Deadline)?;
            }
        }
        // Newly created retirement may already be due after a late first poll;
        // it cannot authorize one more native I/O turn.
        let retirement_now = Instant::now();
        if self.slots.iter().flatten().any(|s| {
            s.outcome.is_none() && s.retirement.is_some_and(|until| retirement_now >= until)
        }) {
            return Ok(Some(self.lost(LossCause::RetirementDeadline)));
        }
        Ok(self.complete().map(Progress::Completed))
    }
    /// Earliest original logical deadline. Never renewed by observation waits,
    /// retries or cancellation; native-time bounds independently prevent drift.
    #[must_use]
    pub fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .filter(|state| state.outcome.is_none() && state.reason.is_none())
            .map(|state| state.expires)
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
            .filter(|state| state.outcome.is_none())
            .map(|state| state.retirement.unwrap_or(state.hard))
            .chain(until)
            .min();
        if let Some(target) = native {
            if self.native_at != Some(target) {
                let alarm = self
                    .native_alarm
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
                alarm.as_mut().reset(target);
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
                    gnunet_types::AbsoluteTime::from_micros(target),
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
                Poll::Pending => {}
                Poll::Ready(result) => {
                    self.alarm = None;
                    self.alarm_at = None;
                    result?;
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
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
    /// Check and arm original native operation/drain deadlines before an outer
    /// owner's canonical-clock wait. Performs no socket IO, logical-clock sample,
    /// decoding or cryptographic verification. Returns at most one actual prior
    /// admission loss, settled completion or native-deadline observation.
    /// Physical source retirement precedes any returned loss; local completion
    /// retains its actual Unsent/Unknown exposure rather than a service result.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Progress<'id>> {
        self.native_guard(cx, None)
    }
    fn native_guard(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Option<Progress<'id>> {
        if let Some((report, cause)) = self.admission_loss.take() {
            return Some(Progress::Lost {
                report,
                cause: LossCause::Ports(cause.into()),
            });
        }
        if let Some(done) = self.complete() {
            return Some(Progress::Completed(done));
        }
        if self.closed || self.blocked || self.paused {
            return None;
        }
        match self.expire(None) {
            Ok(Some(event)) => return Some(event),
            Ok(None) => {}
            Err(error) => return Some(self.classified_loss(error)),
        }
        if let Err(error) = self.poll_native_alarm(cx, until) {
            return Some(self.port_loss(error.into()));
        }
        None
    }
    fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if let Some(event) = self.native_guard(cx, until) {
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
        if until.is_some_and(|target| Instant::now() >= target) {
            return Poll::Ready(Ok(Progress::WaitDeadline));
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
            Ok(sample) => sample.now.as_micros(),
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
        if self
            .channel
            .framing()
            .is_some_and(|framed| framed.frame().is_some())
        {
            return Poll::Ready(self.dispatch(epoch));
        }
        if let Some(event) = self.prepare(epoch)? {
            return Poll::Ready(Ok(event));
        }
        if self.read_first {
            if let Poll::Ready(event) = self.read(cx, epoch) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.write(cx, epoch) {
                return Poll::Ready(event);
            }
        } else {
            if let Poll::Ready(event) = self.write(cx, epoch) {
                return Poll::Ready(event);
            }
            if let Poll::Ready(event) = self.read(cx, epoch) {
                return Poll::Ready(event);
            }
        }
        self.channel
            .poll_wait(cx, until)
            .map_ok(|()| Progress::WaitDeadline)
    }
    /// Poll one bounded original native step. Canceling the containing future
    /// preserves original partial cursors. The optional wait is observation-only.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        until: Option<Instant>,
    ) -> Poll<Result<Progress<'id>, Error>> {
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let event = match self.poll_step(cx, until) {
            Poll::Ready(Err(error)) if !self.closed => Poll::Ready(Ok(self.classified_loss(error))),
            other => other,
        };
        if matches!(&event,Poll::Ready(Ok(progress))if !matches!(progress,Progress::Closed|Progress::WaitDeadline))
        {
            self.yield_due = true;
        }
        event
    }
    /// Caller-driven wrapper. No task/thread is started, and cancellation of the
    /// wait does not remove/replace an actual original MQ or request suffix.
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
        client.lookup(&[0; 64], now + 1_000_000)?;
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
        state.hard = Instant::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .ok_or(Fault::Overflow)?;
        assert!(matches!(
            client.expire(None)?,
            Some(Progress::Lost {
                cause: LossCause::RetirementDeadline,
                ..
            })
        ));
        Ok(())
    }

    // A legal revision change between each sample/registration prevents a
    // coherent canonical turn indefinitely. No transport/crypto/key is used.
    #[derive(Clone)]
    struct RacingClock(std::sync::Arc<std::sync::atomic::AtomicU64>);
    impl gnunet_service_runtime::clock::RuntimeClock for RacingClock {
        fn sample(&self) -> Result<gnunet_service_runtime::clock::ClockSample, Fault> {
            Ok(gnunet_service_runtime::clock::ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(1_000_000),
                revision: self.0.load(std::sync::atomic::Ordering::SeqCst),
            })
        }
        fn subscribe(
            &self,
        ) -> Result<Box<dyn gnunet_service_runtime::clock::ClockSubscription>, Fault> {
            Ok(Box::new(self.clone()))
        }
    }
    impl gnunet_service_runtime::clock::ClockSubscription for RacingClock {
        fn poll_changed(
            &mut self,
            _cx: &mut Context<'_>,
            _observed_revision: u64,
        ) -> Poll<Result<gnunet_service_runtime::clock::ClockSample, Fault>> {
            let revision = self
                .0
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .wrapping_add(1);
            Poll::Ready(Ok(gnunet_service_runtime::clock::ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(1_000_000),
                revision,
            }))
        }
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert independent native wake and same-turn expiry in a pure cursor model"
    )]
    fn native_alarm_and_late_retirement_survive_pending_canonical_clock()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let _entered = runtime.enter();
        let revisions = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clock = std::sync::Arc::new(RacingClock(revisions.clone()));
        let source = EndpointSource::unix_with_clock("/unused-public-model-socket".into(), clock);
        let instance = Instance::new();
        let mut client = Client::new(
            &instance,
            source,
            Limits {
                retirement_grace: std::time::Duration::from_secs(1),
                ..Limits::default()
            },
        )?;
        client.lookup(&[0; 64], 2_000_000)?;
        let hard = Instant::now()
            .checked_add(std::time::Duration::from_secs(60))
            .ok_or(Fault::Overflow)?;
        client
            .slots
            .iter_mut()
            .flatten()
            .next()
            .ok_or(Fault::NotReady)?
            .hard = hard;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        // poll_clock repeatedly observes a revision race. Its Pending branch
        // must already have registered the original native timer; no connect
        // call or syscall is reached by this model.
        assert!(client.poll_step(&mut cx, None).is_pending());
        assert!(revisions.load(std::sync::atomic::Ordering::SeqCst) > 0);
        assert_eq!(client.native_at, Some(hard));
        assert!(client.native_alarm.is_some());
        let before = revisions.load(std::sync::atomic::Ordering::SeqCst);
        let state = client
            .slots
            .iter_mut()
            .flatten()
            .next()
            .ok_or(Fault::NotReady)?;
        // Public fabricated partial-cursor state, not an actual write receipt.
        // Its original hard+grace is already past at the first later poll.
        state.source = None;
        state.queued = true;
        state.sent = 1;
        state.hard = Instant::now()
            .checked_sub(std::time::Duration::from_secs(2))
            .ok_or(Fault::Overflow)?;
        assert!(matches!(
            client.poll_step(&mut cx, None),
            Poll::Ready(Ok(Progress::Lost {
                cause: LossCause::RetirementDeadline,
                report: crate::Loss {
                    operations: 1,
                    exposed: 1,
                    ..
                },
            }))
        ));
        // Native retirement won before any further canonical subscription poll.
        assert_eq!(revisions.load(std::sync::atomic::Ordering::SeqCst), before);
        assert!(client.channel.framing().is_none());
        assert!(matches!(
            client.complete().ok_or(Fault::NotReady)?.outcome,
            Outcome::Local {
                reason: LocalReason::Deadline,
                submission: crate::Submission::Partial { bytes: 1, .. },
            }
        ));
        Ok(())
    }
}
