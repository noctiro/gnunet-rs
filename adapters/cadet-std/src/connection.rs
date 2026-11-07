//! Actual caller-driven CORE MQ to pure CADET connection ownership.
//! No discovery, PILS signing, KX/session selection or application coordinator.
mod types;
use crate::{
    EndpointSource, Error,
    time::{Sample, Timebase},
};
use gnunet_cadet::connection::{Book, Neighbor, ResetAuthority};
use gnunet_core_client_host::{
    self as core, Client, ConnectionEpoch, Inbound, Message, OwnedTraffic, PayloadState, Peer,
    Progress, SendId, SendOutcome,
};
use gnunet_service_runtime::clock::{ClockSubscription, RuntimeClock};
use gnunet_types::{Error as ProtocolError, MonoInstant};
use gnunet_wire::official::{
    cadet_peer::PeerMessage,
    core::{Direction, SEND_PREFIX},
};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
pub use types::{
    Binding, DropReason, Expiration, Limits, MAX_PEER_FRAME, MESSAGE_TYPES, Observer, PeerSlot,
    Report, SendBudget, SendSlot, Source, Step,
};
use types::{BudgetState, PeerRecord, Phase, SendRecord};
/// Actual native CORE driver with bounded per-generation source/send records.
/// The Book stays separately owned so coordinator/session/service layers remain
/// distinct. Only this bridge drives this native client and CORE-neighbor facts.
pub struct Bridge<'core, 'book, 'slots, const C: usize = 64, const S: usize = 32> {
    native: Client<'core, C, S>,
    authority: ResetAuthority<'book>,
    timebase: Timebase,
    peers: &'slots mut [PeerSlot<'core, 'book>],
    sends: &'slots mut [SendSlot<'core, 'book>],
    epoch: Option<ConnectionEpoch<'core>>,
    local: Option<Peer<'core>>,
    identity_ok: bool,
    fault: Option<ProtocolError>,
    pending_retirement: Option<Progress<'core>>,
    offer: bool,
    offered_frame: Option<gnunet_cadet::connection::Frame<'book>>,
    last_now: MonoInstant,
    limits: Limits,
    report: Report,
    budget_subscription: Option<Box<dyn ClockSubscription>>,
    budget_revision: u64,
    budget_timer: Option<Pin<Box<Sleep>>>,
    cleanup_error: Option<Error>,
    native_failed: bool,
}
impl<'core, 'book, 'slots, const C: usize, const S: usize> Bridge<'core, 'book, 'slots, C, S> {
    /// Bind the original Book, empty caller records and one real CORE client.
    /// Peer storage covers current peers plus original sends' retiring peers.
    /// The Book must have been initialized from this same Timebase's native
    /// sample; its elapsed coordinates are never logical absolute timestamps.
    pub fn new<const P: usize>(
        instance: &'core mut core::Instance,
        source: EndpointSource,
        book: &Book<'book, '_, '_, P>,
        peers: &'slots mut [PeerSlot<'core, 'book>],
        sends: &'slots mut [SendSlot<'core, 'book>],
        limits: Limits,
        timebase: Timebase,
    ) -> Result<Self, Error> {
        let needed = C
            .checked_add(limits.core.sends)
            .ok_or(ProtocolError::Capacity)?;
        if peers.len() < needed
            || sends.len() < limits.core.sends
            || peers.iter().any(|p| p.record.is_some())
            || sends.iter().any(|s| s.record.is_some())
        {
            return Err(ProtocolError::Capacity.into());
        }
        if limits.send_budget.is_some_and(|budget| {
            budget.lifetime_micros == 0
                || budget.lifetime_micros == u64::MAX
                || budget.retirement_grace_micros == 0
                || budget.retirement_grace_micros == u64::MAX
        }) {
            return Err(ProtocolError::InvalidInput.into());
        }
        let clock = timebase.source();
        if !Arc::ptr_eq(&clock, &source.clock()) {
            return Err(ProtocolError::InvalidInput.into());
        }
        let sample = timebase.sample()?;
        let native = Client::new(
            instance,
            source,
            limits.class_order,
            0,
            &MESSAGE_TYPES,
            limits.core,
        )?;
        // One explicit independently polled budget owner, not a listener/task
        // per send. Default None retains the existing single native listener.
        let budget_subscription = if limits.send_budget.is_some() {
            Some(clock.subscribe()?)
        } else {
            None
        };
        Ok(Self {
            native,
            authority: book.reset_authority(),
            timebase,
            peers,
            sends,
            epoch: None,
            local: None,
            identity_ok: false,
            fault: None,
            pending_retirement: None,
            offer: true,
            offered_frame: None,
            last_now: sample.monotonic,
            limits,
            report: Report::default(),
            budget_subscription,
            budget_revision: sample.revision,
            budget_timer: None,
            cleanup_error: None,
            native_failed: false,
        })
    }
    /// Original source clock; cloning creates no independent listener.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.timebase.source()
    }
    /// Shared native elapsed epoch used by this bridge and its original Book.
    /// Cloning never creates a new anchor or changes a live budget's deadline.
    #[must_use]
    pub fn timebase(&self) -> &Timebase {
        &self.timebase
    }
    /// Bounded public counters; no remote delivery is inferred.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
    /// Exact current CORE peer to original Neighbor map, for outgoing lookup only.
    #[must_use]
    pub fn neighbor(&self, peer: Peer<'core>) -> Option<Neighbor<'book>> {
        if !self.identity_ok
            || self.pending_retirement.is_some()
            || self.native.peer(peer.identity()) != Some(peer)
        {
            return None;
        }
        self.peers
            .iter()
            .filter_map(|p| p.record)
            .find(|p| p.peer == peer && p.phase == Phase::Live)
            .and_then(|p| p.neighbor)
    }
    fn check<const P: usize>(&self, book: &Book<'book, '_, '_, P>) -> Result<(), Error> {
        if book.reset_authority() != self.authority {
            return Err(ProtocolError::StaleGeneration.into());
        }
        Ok(())
    }
    /// Bounded public operation context from the actual native CORE poll error.
    /// This is an observation of the original driver, not a send/source permit.
    #[must_use]
    pub fn native_failure_context(&self) -> Option<core::OperationContext> {
        self.native_failed
            .then(|| self.native.failure_context())
            .flatten()
    }
    /// Original finite budget target. No new native/Book effect is admitted by
    /// observing it, and canceled waiting futures do not reset its ownership.
    /// This is native elapsed time in timebase(), not a wire absolute deadline.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonoInstant> {
        if !self.identity_ok || self.pending_retirement.is_some() {
            return None;
        }
        self.sends
            .iter()
            .filter_map(|slot| slot.record.and_then(|record| record.budget))
            .map(|budget| {
                if budget.expired {
                    budget.hard_stop
                } else {
                    budget.expires
                }
            })
            .min()
    }
    /// Independent actual physical cleanup refusal encountered after an original
    /// clock error. Taking it never restores/reconnects that stopped source.
    pub fn take_cleanup_error(&mut self) -> Option<Error> {
        self.cleanup_error.take()
    }
    fn clock_failure(&mut self) {
        // Stop physical IO before returning the real clock error. Preserve its
        // actual retirement until the same provider supplies a coherent sample.
        match self.native.close() {
            Ok(Some(actual)) if self.pending_retirement.is_none() => {
                self.pending_retirement = Some(actual)
            }
            Ok(_) => {}
            Err(error) if self.cleanup_error.is_none() => self.cleanup_error = Some(error),
            Err(_) => {}
        }
        self.identity_ok = false;
        self.budget_timer = None;
    }
    fn time_sample(&mut self) -> Result<Sample, Error> {
        let sample = match self.timebase.sample() {
            Ok(sample) => sample,
            Err(reason) => {
                self.clock_failure();
                return Err(reason.into());
            }
        };
        if sample.monotonic < self.last_now {
            self.clock_failure();
            return Err(ProtocolError::TimeUncertain.into());
        }
        self.last_now = sample.monotonic;
        Ok(sample)
    }
    fn time(&mut self) -> Result<MonoInstant, Error> {
        Ok(self.time_sample()?.monotonic)
    }
    fn poll_time(&mut self, cx: &mut Context<'_>) -> Poll<Result<MonoInstant, Error>> {
        if self.limits.send_budget.is_none() {
            return Poll::Ready(self.time());
        }
        let observed = self.budget_revision;
        let changed = self
            .budget_subscription
            .as_mut()
            .ok_or(ProtocolError::Closed)?
            .poll_changed(cx, observed);
        match changed {
            Poll::Ready(Err(reason)) => {
                self.clock_failure();
                return Poll::Ready(Err(reason.into()));
            }
            Poll::Ready(Ok(sample)) => self.budget_revision = sample.revision,
            Poll::Pending => {}
        }
        let sample = self.time_sample()?;
        let raced = self
            .budget_subscription
            .as_mut()
            .ok_or(ProtocolError::Closed)?
            .poll_changed(cx, sample.revision);
        match raced {
            Poll::Ready(Err(reason)) => {
                self.clock_failure();
                Poll::Ready(Err(reason.into()))
            }
            Poll::Ready(Ok(changed)) => {
                self.budget_revision = changed.revision;
                cx.waker().wake_by_ref();
                // A legitimate logical adjustment cannot postpone an original
                // native expiry. The sample's elapsed observation remains real;
                // admission samples absolute time independently before send.
                Poll::Ready(Ok(sample.monotonic))
            }
            Poll::Pending => {
                self.budget_revision = sample.revision;
                Poll::Ready(Ok(sample.monotonic))
            }
        }
    }
    fn poll_budget_timer(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        let Some(target) = self.next_deadline() else {
            self.budget_timer = None;
            return Ok(());
        };
        let target = self.timebase.native_bound(target)?;
        let timer = self
            .budget_timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(target)));
        timer.as_mut().reset(target);
        if timer.as_mut().poll(cx).is_ready() {
            // Readiness only wakes this owner; the next coherent sample checks
            // the fixed original native target and actual logical-source state.
            self.budget_timer = None;
            cx.waker().wake_by_ref();
        }
        Ok(())
    }
    fn peer_index(&self, epoch: ConnectionEpoch<'core>, peer: Peer<'core>) -> Option<usize> {
        self.peers
            .iter()
            .position(|p| p.record.is_some_and(|p| p.epoch == epoch && p.peer == peer))
    }
    fn send_index(&self, send: SendId<'core>) -> Option<usize> {
        self.sends
            .iter()
            .position(|s| s.record.is_some_and(|s| s.send == send))
    }
    fn active(&self, peer: Peer<'core>) -> bool {
        self.sends
            .iter()
            .any(|s| s.record.is_some_and(|s| s.source.peer == peer))
    }
    fn admit_peer<const P: usize>(
        &mut self,
        index: usize,
        book: &mut Book<'book, '_, '_, P>,
    ) -> Result<Source<'core, 'book>, ProtocolError> {
        let p = self.peers[index]
            .record
            .ok_or(ProtocolError::StaleGeneration)?;
        if !self.identity_ok
            || self.pending_retirement.is_some()
            || self.epoch != Some(p.epoch)
            || self.native.peer(p.peer.identity()) != Some(p.peer)
        {
            return Err(ProtocolError::NotReady);
        }
        if self.peers.iter().enumerate().any(|(i, s)| {
            i != index
                && s.record
                    .is_some_and(|r| r.peer.identity() == p.peer.identity() && r.neighbor.is_some())
        }) {
            return Err(ProtocolError::WouldBlock);
        }
        let neighbor = book.neighbor_up(p.peer.identity().0)?;
        self.peers[index].record = Some(PeerRecord {
            neighbor: Some(neighbor),
            phase: Phase::Live,
            ..p
        });
        Ok(Source {
            epoch: p.epoch,
            peer: p.peer,
            neighbor,
        })
    }
    /// Retry only already retained actual peer announcements after caller frees
    /// Book resources. No raw identity or synthetic Connected input is accepted.
    pub fn retry_neighbors<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
    ) -> Result<usize, Error> {
        self.check(book)?;
        let now = self.time()?;
        let mut admitted = 0;
        for i in 0..self.peers.len() {
            if self.peers[i]
                .record
                .is_some_and(|p| p.phase == Phase::Waiting)
            {
                match self.admit_peer(i, book) {
                    Ok(source) => {
                        observer.neighbor(source, book, now);
                        admitted += 1;
                    }
                    Err(ProtocolError::Capacity | ProtocolError::WouldBlock) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(admitted)
    }
    fn availability<const P: usize>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
    ) -> Result<bool, Error> {
        let mut became_ready = false;
        for p in self.peers.iter().filter_map(|p| p.record) {
            if let Some(neighbor) = p.neighbor {
                let available = if self.identity_ok
                    && p.phase == Phase::Live
                    && !self.active(p.peer)
                {
                    match self.native.request_available(p.peer, 4, 4) {
                        Ok(available) => available,
                        // Native has already stopped/admission is unavailable;
                        // only actual later Lost/peer notices authorize retirement.
                        Err(Error::Protocol(
                            ProtocolError::Closed | ProtocolError::NotReady | ProtocolError::Stale,
                        )) => false,
                        Err(error) => return Err(error),
                    }
                } else {
                    false
                };
                let was_ready = book.neighbor_is_ready(neighbor)?;
                book.neighbor_ready(neighbor, available)?;
                became_ready |= available && !was_ready;
            }
        }
        Ok(became_ready)
    }
    fn retire_peer<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        index: usize,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
        now: MonoInstant,
    ) -> Result<usize, Error> {
        let p = self.peers[index]
            .record
            .ok_or(ProtocolError::StaleGeneration)?;
        if self.active(p.peer) {
            return Err(ProtocolError::WouldBlock.into());
        }
        let routes = match p.neighbor {
            Some(n) => book.neighbor_lost(n, now)?,
            None => 0,
        };
        self.peers[index].record = None;
        if let Some(neighbor) = p.neighbor {
            observer.retired(
                Source {
                    epoch: p.epoch,
                    peer: p.peer,
                    neighbor,
                },
                routes,
                book,
                now,
            );
        }
        // A new actual same-PID generation was retained while this old native
        // payload drained; it may now mint its own distinct Neighbor allocation.
        for i in 0..self.peers.len() {
            if self.peers[i].record.is_some_and(|r| {
                r.phase == Phase::Waiting && r.peer.identity() == p.peer.identity()
            }) {
                match self.admit_peer(i, book) {
                    Ok(source) => observer.neighbor(source, book, now),
                    Err(ProtocolError::Capacity | ProtocolError::WouldBlock) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok(routes)
    }
    fn book_completion<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
        now: MonoInstant,
    ) -> Result<Option<Step<'core, 'book>>, Error> {
        let Some(done) = book.completion() else {
            return Ok(None);
        };
        if self
            .sends
            .iter()
            .any(|s| s.record.is_some_and(|s| s.frame == done.frame))
        {
            return Ok(None);
        }
        observer.completed(done, None, None, book, now);
        self.report.completed = self.report.completed.saturating_add(1);
        book.release_frame(done.frame)?;
        Ok(Some(Step::BookCompleted(done)))
    }
    fn transmit<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        cx: &mut Context<'_>,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
    ) -> Result<Option<Step<'core, 'book>>, Error> {
        if !self.identity_ok {
            return Ok(None);
        }
        if self.availability(book)? {
            // The containing Node may already have tried to prepare a channel
            // ACK/DATA before this bridge restored local CORE availability.
            // Its next pure step is now enabled even if no Book frame exists
            // yet and native CORE has no IO event. Wake this same owner once
            // for the actual false-to-true transition; repeated ready samples
            // do not spin and imply no wire permit or peer acknowledgement.
            cx.waker().wake_by_ref();
        }
        let Some(queued) = book.next_frame() else {
            return Ok(None);
        };
        let Some(peer) = self
            .peers
            .iter()
            .filter_map(|p| p.record)
            .find(|p| p.phase == Phase::Live && p.neighbor == Some(queued.neighbor))
        else {
            return Err(ProtocolError::StaleGeneration.into());
        };
        let Some(slot) = self.sends.iter().position(|s| s.record.is_none()) else {
            return Ok(None);
        };
        let frame = queued.frame;
        let source = Source {
            epoch: peer.epoch,
            peer: peer.peer,
            neighbor: queued.neighbor,
        };
        let message = Message::copy_from(queued.bytes)?;
        if queued.bytes.len() > MAX_PEER_FRAME {
            return Ok(Some(Step::SendRefused {
                frame,
                reason: ProtocolError::TooLarge,
                source: message,
            }));
        }
        let total = SEND_PREFIX
            .checked_add(queued.bytes.len())
            .ok_or(ProtocolError::Capacity)?;
        // One coherent admission sample freezes independent native scheduling
        // targets and the public absolute CORE deadline. A later UTC adjustment
        // can change neither this send's age nor the deadline already on wire.
        let sample = self.time_sample()?;
        let now = sample.monotonic;
        let budget = self
            .limits
            .send_budget
            .map(|policy| -> Result<BudgetState, ProtocolError> {
                let expires = MonoInstant(
                    now.0
                        .checked_add(policy.lifetime_micros)
                        .filter(|v| *v != u64::MAX)
                        .ok_or(ProtocolError::Overflow)?,
                );
                let hard_stop = MonoInstant(
                    expires
                        .0
                        .checked_add(policy.retirement_grace_micros)
                        .filter(|v| *v != u64::MAX)
                        .ok_or(ProtocolError::Overflow)?,
                );
                self.timebase.native_bound(hard_stop)?;
                let wire_deadline = sample
                    .absolute
                    .as_micros()
                    .checked_add(policy.lifetime_micros)
                    .filter(|value| *value != u64::MAX)
                    .ok_or(ProtocolError::Overflow)?;
                Ok(BudgetState {
                    expires,
                    hard_stop,
                    wire_deadline,
                    expired: false,
                })
            })
            .transpose()?;
        let deadline = budget.map_or(self.limits.send_deadline, |budget| budget.wire_deadline);
        let send = match self
            .native
            .send(peer.peer, self.limits.priority, deadline, message)
        {
            Ok(send) => send,
            Err(rejected) => {
                return Ok(Some(Step::SendRefused {
                    frame,
                    reason: rejected.reason,
                    source: rejected.value,
                }));
            }
        };
        self.sends[slot].record = Some(SendRecord {
            source,
            send,
            frame,
            attempt: None,
            written: 0,
            total,
            aborting: None,
            budget,
        });
        match book.start(frame) {
            Ok(attempt) => {
                self.sends[slot]
                    .record
                    .as_mut()
                    .ok_or(ProtocolError::StaleGeneration)?
                    .attempt = Some(attempt);
                let binding = Binding {
                    source,
                    send,
                    attempt,
                };
                observer.started(binding, book, now);
                self.report.started = self.report.started.saturating_add(1);
                Ok(Some(Step::Started(binding)))
            }
            Err(reason) => {
                self.sends[slot]
                    .record
                    .as_mut()
                    .ok_or(ProtocolError::StaleGeneration)?
                    .aborting = Some(reason);
                book.neighbor_ready(source.neighbor, false)?;
                let (cancelled, cancellation_error) = match self.native.cancel(send) {
                    Ok(cancelled) => (cancelled, None),
                    Err(error) => (None, Some(error)),
                };
                if cancelled.is_some() {
                    self.sends[slot].record = None;
                }
                Ok(Some(Step::StartRefused {
                    send,
                    frame,
                    reason,
                    cancelled,
                    cancellation_error,
                }))
            }
        }
    }
    fn cancelled<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        index: usize,
        completion: &core::SendCompletion<Message>,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
        now: MonoInstant,
    ) -> Result<(), Error> {
        let original = self.sends[index]
            .record
            .ok_or(ProtocolError::StaleGeneration)?;
        if original.written != 0
            || completion.outcome != SendOutcome::CancelledBeforePayload
            || book.frame_bytes(original.frame)? != completion.source.as_ref()
        {
            return Err(ProtocolError::Authentication.into());
        }
        if let Some(binding) = original.binding() {
            let done = book.settle(binding.attempt, false, now)?;
            // No synthetic private PayloadState: actual synchronous SDK cancel
            // itself proves zero payload. Preserve that distinction to observers.
            observer.completed(done, Some(binding), None, book, now);
            self.report.completed = self.report.completed.saturating_add(1);
            book.release_frame(original.frame)?;
        }
        self.sends[index].record = None;
        if let Some(index) = self.peer_index(original.source.epoch, original.source.peer)
            && self.peers[index]
                .record
                .is_some_and(|p| p.phase == Phase::Disconnected)
            && !self.active(original.source.peer)
        {
            self.retire_peer(index, book, observer, now)?;
        }
        Ok(())
    }
    fn expire<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
        now: MonoInstant,
    ) -> Result<Option<Step<'core, 'book>>, Error> {
        if !self.identity_ok || self.pending_retirement.is_some() {
            return Ok(None);
        }
        for index in 0..self.sends.len() {
            let Some(original) = self.sends[index].record else {
                continue;
            };
            let Some(budget) = original.budget else {
                continue;
            };
            if budget.expired && now >= budget.hard_stop {
                // Native may already be physically draining an earlier real
                // loss before its receipt reached us. Let that actual receipt
                // drain; never manufacture a second reconnect or Book outcome.
                if matches!(
                    self.native.request_available(original.source.peer, 4, 4),
                    Err(Error::Protocol(ProtocolError::Closed))
                ) {
                    self.identity_ok = false;
                    self.budget_timer = None;
                    return Ok(None);
                }
                let actual = self.native.reconnect()?;
                self.report.forced_reconnects = self.report.forced_reconnects.saturating_add(1);
                self.budget_timer = None;
                return self.progress(actual, book, observer, now).map(Some);
            }
            if budget.expired || now < budget.expires {
                continue;
            }
            self.sends[index]
                .record
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?
                .budget
                .as_mut()
                .ok_or(ProtocolError::StaleGeneration)?
                .expired = true;
            self.report.expired_sends = self.report.expired_sends.saturating_add(1);
            let outcome = match self.native.cancel(original.send) {
                Ok(Some(completion)) => {
                    self.cancelled(index, &completion, book, observer, now)?;
                    Expiration::Cancelled(completion)
                }
                Ok(None) => Expiration::Draining,
                Err(error) => {
                    self.report.cancellation_errors =
                        self.report.cancellation_errors.saturating_add(1);
                    Expiration::Refused(error)
                }
            };
            self.offer = true;
            return Ok(Some(Step::SendExpired {
                binding: original.binding(),
                send: original.send,
                expires: budget.expires,
                hard_stop: budget.hard_stop,
                outcome,
            }));
        }
        Ok(None)
    }
    fn expose<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        index: usize,
        state: PayloadState<'core>,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
        now: MonoInstant,
    ) -> Result<Binding<'core, 'book>, Error> {
        let r = self.sends[index]
            .record
            .ok_or(ProtocolError::StaleGeneration)?;
        if state.epoch() != r.source.epoch
            || state.peer() != r.source.peer
            || state.send() != r.send
            || state.frame_bytes() != r.total
            || state.written() < r.written
        {
            return Err(ProtocolError::Authentication.into());
        }
        let binding = r.binding().ok_or(ProtocolError::StaleGeneration)?;
        if r.written == 0 && state.exposed() {
            book.exposed(binding.attempt)?;
            observer.exposed(binding, state, book, now);
            self.report.exposed = self.report.exposed.saturating_add(1);
        }
        self.sends[index]
            .record
            .as_mut()
            .ok_or(ProtocolError::StaleGeneration)?
            .written = state.written();
        Ok(binding)
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "Original native tuple/source, independent Book effects and native scheduling time are retained together"
    )]
    fn finish<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        epoch: ConnectionEpoch<'core>,
        peer: Peer<'core>,
        send: SendId<'core>,
        state: PayloadState<'core>,
        completion: core::SendCompletion<Message>,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
        now: MonoInstant,
    ) -> Result<Step<'core, 'book>, Error> {
        let index = self
            .send_index(send)
            .ok_or(ProtocolError::StaleGeneration)?;
        let r = self.sends[index]
            .record
            .ok_or(ProtocolError::StaleGeneration)?;
        if epoch != r.source.epoch
            || peer != r.source.peer
            || state.epoch() != epoch
            || state.peer() != peer
            || state.send() != send
            || state.frame_bytes() != r.total
            || state.written() < r.written
            || book.frame_bytes(r.frame)? != completion.source.as_ref()
        {
            return Err(ProtocolError::Authentication.into());
        }
        if completion.outcome == SendOutcome::Written && !state.complete() {
            return Err(ProtocolError::InvalidInput.into());
        }
        if r.attempt.is_none() && r.aborting.is_none() {
            return Err(ProtocolError::StaleGeneration.into());
        }
        let binding = r.binding();
        if let Some(original) = binding {
            self.expose(index, state, book, observer, now)?;
            let done = book.settle(original.attempt, state.complete(), now)?;
            observer.completed(done, binding, Some(state), book, now);
            self.report.completed = self.report.completed.saturating_add(1);
            book.release_frame(r.frame)?;
        } else if state.exposed() {
            return Err(ProtocolError::Conflict.into());
        }
        self.sends[index].record = None;
        if let Some(i) = self.peer_index(epoch, peer)
            && self.peers[i]
                .record
                .is_some_and(|p| p.phase == Phase::Disconnected)
            && !self.active(peer)
        {
            self.retire_peer(i, book, observer, now)?;
        }
        Ok(Step::Finished {
            binding,
            state,
            completion,
        })
    }
    fn dropped(
        &mut self,
        epoch: ConnectionEpoch<'core>,
        peer: core::PeerId,
        connection: Option<Peer<'core>>,
        traffic: OwnedTraffic,
        reason: DropReason,
    ) -> Step<'core, 'book> {
        self.report.dropped = self.report.dropped.saturating_add(1);
        if reason == DropReason::Protocol(ProtocolError::Capacity) {
            self.report.capacity_drops = self.report.capacity_drops.saturating_add(1);
        }
        Step::Dropped {
            epoch,
            peer,
            connection,
            traffic,
            reason,
        }
    }
    fn inbound<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        epoch: ConnectionEpoch<'core>,
        event: Inbound<'core>,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
        now: MonoInstant,
    ) -> Result<Step<'core, 'book>, Error> {
        match event {
            Inbound::Ready { local, .. } => {
                if self.epoch != Some(epoch) || local.identity().0 != self.authority.local() {
                    self.fault = Some(ProtocolError::Authentication);
                    self.identity_ok = false;
                    return Ok(Step::IdentityMismatch {
                        epoch,
                        actual: local,
                        expected: self.authority.local(),
                    });
                }
                self.local = Some(local);
                self.identity_ok = true;
                Ok(Step::Identity(local))
            }
            Inbound::Connected(peer) => {
                if !self.identity_ok || self.epoch != Some(epoch) || Some(peer) == self.local {
                    return Err(ProtocolError::Authentication.into());
                }
                let index = self
                    .peers
                    .iter()
                    .position(|p| p.record.is_none())
                    .ok_or(ProtocolError::Capacity)?;
                self.peers[index].record = Some(PeerRecord {
                    epoch,
                    peer,
                    neighbor: None,
                    phase: Phase::Waiting,
                });
                match self.admit_peer(index, book) {
                    Ok(source) => {
                        observer.neighbor(source, book, now);
                        Ok(Step::Neighbor(source))
                    }
                    Err(reason @ (ProtocolError::Capacity | ProtocolError::WouldBlock)) => {
                        Ok(Step::Waiting {
                            epoch,
                            peer,
                            reason: Some(reason),
                        })
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Inbound::Disconnected(peer) => {
                let index = self
                    .peer_index(epoch, peer)
                    .ok_or(ProtocolError::StaleGeneration)?;
                if let Some(p) = self.peers[index].record.as_mut() {
                    p.phase = Phase::Disconnected;
                    if let Some(n) = p.neighbor {
                        book.neighbor_ready(n, false)?;
                    }
                }
                if !self.active(peer) {
                    let routes = self.retire_peer(index, book, observer, now)?;
                    Ok(Step::Retired { peer, routes })
                } else {
                    Ok(Step::Waiting {
                        epoch,
                        peer,
                        reason: None,
                    })
                }
            }
            Inbound::SendReady { send, capacity } => {
                let index = self
                    .send_index(send)
                    .ok_or(ProtocolError::StaleGeneration)?;
                Ok(Step::Permit {
                    binding: self.sends[index].record.and_then(SendRecord::binding),
                    capacity,
                })
            }
            Inbound::Traffic {
                peer,
                connection,
                direction,
                traffic,
            } => {
                if self.local.is_some_and(|p| p.identity() == peer) {
                    return Ok(self.dropped(
                        epoch,
                        peer,
                        connection,
                        traffic,
                        DropReason::Loopback,
                    ));
                }
                if !self.identity_ok
                    || self.epoch != Some(epoch)
                    || direction != Direction::Inbound
                    || !matches!(traffic, OwnedTraffic::Full(_))
                {
                    return Ok(self.dropped(
                        epoch,
                        peer,
                        connection,
                        traffic,
                        DropReason::Observation,
                    ));
                }
                let Some(record) = connection
                    .and_then(|p| self.peer_index(epoch, p))
                    .and_then(|i| self.peers[i].record)
                    .filter(|p| p.phase == Phase::Live && p.peer.identity() == peer)
                else {
                    return Ok(self.dropped(epoch, peer, connection, traffic, DropReason::Source));
                };
                let source = Source {
                    epoch,
                    peer: record.peer,
                    neighbor: record.neighbor.ok_or(ProtocolError::StaleGeneration)?,
                };
                let OwnedTraffic::Full(message) = &traffic else {
                    return Err(ProtocolError::InvalidInput.into());
                };
                let bytes = message.as_ref();
                let result =
                    PeerMessage::decode(bytes).and_then(|m| book.receive(source.neighbor, m, now));
                match result {
                    Ok(event) => {
                        let length = bytes.len();
                        observer.input(source, event, bytes, book, now);
                        self.report.inputs = self.report.inputs.saturating_add(1);
                        Ok(Step::Input {
                            source,
                            bytes: length,
                        })
                    }
                    Err(reason) => {
                        if reason == ProtocolError::Capacity {
                            // This original input is actually consumed below;
                            // never count a local enqueue retry as a dropped packet.
                            if let Ok(message) = PeerMessage::decode(bytes) {
                                book.discarded_full_buffer(source.neighbor, message);
                            }
                        }
                        Ok(self.dropped(
                            epoch,
                            peer,
                            connection,
                            traffic,
                            DropReason::Protocol(reason),
                        ))
                    }
                }
            }
            other => Ok(Step::Core(Progress::Inbound {
                epoch,
                event: other,
            })),
        }
    }
    fn progress<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        progress: Progress<'core>,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
        now: MonoInstant,
    ) -> Result<Step<'core, 'book>, Error> {
        match progress {
            Progress::Connected(epoch) => {
                self.epoch = Some(epoch);
                self.local = None;
                self.identity_ok = false;
                Ok(Step::Connected(epoch))
            }
            Progress::Inbound { epoch, event } => self.inbound(epoch, event, book, observer, now),
            Progress::Activity {
                epoch,
                payload: Some(receipt),
                ..
            } => {
                let state = receipt.state();
                if epoch != state.epoch() {
                    return Err(ProtocolError::Authentication.into());
                }
                let index = self
                    .send_index(state.send())
                    .ok_or(ProtocolError::StaleGeneration)?;
                let previous = self.sends[index]
                    .record
                    .ok_or(ProtocolError::StaleGeneration)?
                    .written;
                if receipt.previous() != previous {
                    return Err(ProtocolError::InvalidInput.into());
                }
                let binding = self.expose(index, state, book, observer, now)?;
                Ok(Step::Writing { binding, receipt })
            }
            Progress::Finished {
                epoch,
                peer,
                send,
                payload,
                completion,
            } => self.finish(epoch, peer, send, payload, completion, book, observer, now),
            Progress::Lost { epoch, cause } => {
                self.identity_ok = false;
                for p in self
                    .peers
                    .iter_mut()
                    .filter_map(|slot| slot.record.as_mut())
                    .filter(|p| p.epoch == epoch)
                {
                    // An older disconnected generation may not be in CORE's
                    // current PeerLost list after same-PID reuse. Its own
                    // terminal sends must still retire it.
                    if p.phase != Phase::Disconnected {
                        p.phase = Phase::MqLost;
                    }
                    if let Some(n) = p.neighbor {
                        book.neighbor_ready(n, false)?;
                    }
                }
                Ok(Step::Lost { epoch, cause })
            }
            Progress::PeerLost { epoch, peer } => {
                if let Some(index) = self.peer_index(epoch, peer) {
                    let routes = self.retire_peer(index, book, observer, now)?;
                    Ok(Step::Retired { peer, routes })
                } else {
                    Ok(Step::Core(Progress::PeerLost { epoch, peer }))
                }
            }
            other => Ok(Step::Core(other)),
        }
    }
    /// Poll one actual native or Book action. Transactional input errors are
    /// explicit packet drops returning original OwnedTraffic, never fake ACKs.
    pub fn poll<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        cx: &mut Context<'_>,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
        deadline: Option<Instant>,
    ) -> Poll<Result<Step<'core, 'book>, Error>> {
        self.native_failed = false;
        self.check(book)?;
        if let Some(error) = self.fault {
            return Poll::Ready(Err(error.into()));
        }
        let now = match self.poll_time(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result?,
        };
        if let Some(actual) = self.pending_retirement.take() {
            return Poll::Ready(self.progress(actual, book, observer, now));
        }
        if let Some(step) = self.expire(book, observer, now)? {
            return Poll::Ready(Ok(step));
        }
        self.poll_budget_timer(cx)?;
        if let Some(step) = self.book_completion(book, observer, now)? {
            return Poll::Ready(Ok(step));
        }
        // Higher layers can queue a fresh immutable frame after independent
        // PILS/application progress while CORE itself remains quiet. Retry a
        // newly eligible frame without repeatedly copying the same refused one.
        let queued = book.next_frame().map(|frame| frame.frame);
        if self.offer || queued != self.offered_frame {
            self.offer = false;
            let submitted = self.transmit(cx, book, observer)?;
            self.offered_frame = book.next_frame().map(|frame| frame.frame);
            if let Some(step) = submitted {
                return Poll::Ready(Ok(step));
            }
        }
        match self.native.poll(cx, deadline) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.native_failed = true;
                Poll::Ready(Err(e))
            }
            Poll::Ready(Ok(p)) => {
                self.offer = true;
                let step = self.progress(p, book, observer, now);
                if let Err(Error::Protocol(reason)) = &step {
                    self.fault = Some(*reason);
                }
                Poll::Ready(step)
            }
        }
    }
    /// Wait for one actual action; canceled waits retain all original mappings,
    /// native cursors/sources and Book frames. No background task is spawned.
    pub async fn drive<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
        deadline: Option<Instant>,
    ) -> Result<Step<'core, 'book>, Error> {
        poll_fn(|cx| self.poll(cx, book, observer, deadline)).await
    }
    /// Explicitly retire the actual MQ, preserving original source/result drain.
    pub fn reconnect<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
    ) -> Result<Step<'core, 'book>, Error> {
        self.check(book)?;
        let actual = self.native.reconnect()?;
        self.fault = None;
        self.pending_retirement = Some(actual);
        let now = self.time()?;
        let actual = self
            .pending_retirement
            .take()
            .ok_or(ProtocolError::StaleGeneration)?;
        self.progress(actual, book, observer, now)
    }
    /// Close actual native work, then keep polling to drain original results and
    /// peer losses. It does not synthesize terminal Book/channel success.
    pub fn close<const P: usize, O: Observer<'core, 'book, P>>(
        &mut self,
        book: &mut Book<'book, '_, '_, P>,
        observer: &mut O,
    ) -> Result<Option<Step<'core, 'book>>, Error> {
        self.check(book)?;
        let actual = self.native.close()?;
        self.fault = None;
        if let Some(actual) = actual {
            self.pending_retirement = Some(actual);
        }
        // Stopping the original MQ never depends on a healthy clock. If its
        // logical provider refuses, retain its actual retirement receipt until
        // that source recovers; do not invent a successful coherent sample.
        let now = self.time()?;
        self.pending_retirement
            .take()
            .map(|p| self.progress(p, book, observer, now))
            .transpose()
    }
    /// Retry only the real native client's refused source-domain ports.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        self.native.recover_ports()
    }
}
