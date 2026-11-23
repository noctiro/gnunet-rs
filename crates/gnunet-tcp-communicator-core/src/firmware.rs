//! Caller-driven TCP link for firmware with synchronous durable effects.

use crate::{
    replay_store::{Backend, ReplayError, ReplayStore},
    session::{
        Buffers, Effect, FINISH_US, Handshake, Identity, Phase, Policy, ResultKind, Role, Scope,
        Session, Time,
    },
    stream::{self, Pump, Ready, Scratch, Stream, WaitStream},
};
use core::num::NonZeroU64;
use gnunet_crypto::{EddsaPublicKey, Entropy};
use gnunet_types::{AbsoluteTime, Duration, Error, MonoInstant, Rejected, monotime::Window};

#[cfg(test)]
mod tests;

/// Concurrent replay operations supported by the bounded firmware owner.
pub const REPLAY_OPERATIONS: usize = 3;

/// One sample of the board's distinct protocol and deadline clocks.
#[derive(Clone, Copy, Debug)]
pub struct Sample {
    /// Qualified GNUnet absolute microseconds. This clock can be corrected.
    pub absolute: AbsoluteTime,
    /// Native elapsed microseconds. A decrease fences this connection.
    pub elapsed: MonoInstant,
}

/// Original board time, entropy and durable timestamp namespace.
pub trait Clock: Entropy {
    /// Observe both clock domains and verify the original timestamp namespace
    /// is still live even when the owner can issue from an existing range.
    fn sample(&mut self) -> Result<Sample, Error>;
    /// Read the authoritative durable upper bound under exclusive ownership.
    fn signed_high_water(&mut self) -> Result<u64, Error>;
    /// Commit an inclusive range in that same namespace before returning.
    fn reserve_signed(&mut self, first: NonZeroU64) -> Result<(u64, u64), Error>;

    /// Issue one durable signed stamp for this device identity. Concurrent
    /// carriers on one store use a common issuer. The default uses the
    /// original per-driver window for an exclusive store.
    fn issue_signed(
        &mut self,
        observed: AbsoluteTime,
        local: &mut Window,
    ) -> Result<NonZeroU64, Error> {
        local
            .issue(observed, |first| self.reserve_signed(first))
            .map_err(|error| match error {
                gnunet_types::monotime::IssueError::Reserve(error)
                | gnunet_types::monotime::IssueError::Sequence(error) => error,
            })
    }
}

/// The completed result of passing one authenticated BOX to local TRANSPORT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Delivery {
    /// The original message was consumed within the call.
    Consumed,
    /// The local engine discarded this message.
    Dropped,
    /// The local engine has no receiving owner.
    Unavailable,
}

/// One actual sample and durable stamp used to drive the local queue owner.
pub struct TransportContext<'a, E> {
    /// Qualified absolute time and monotonic elapsed time from the board.
    pub sample: Sample,
    /// Original durable signed stamp for this turn.
    pub signed: NonZeroU64,
    /// Original entropy source, borrowed only while driving this turn.
    pub entropy: &'a mut E,
}

/// Upcoming protocol work in the scheduling domain of its owner.
#[derive(Clone, Copy, Debug, Default)]
pub struct TransportDeadlines {
    /// Deadline in GNUnet absolute microseconds.
    pub absolute: Option<AbsoluteTime>,
    /// Deadline in native elapsed microseconds.
    pub elapsed: Option<MonoInstant>,
}

impl TransportDeadlines {
    /// Combine the earliest deadlines independently in each clock domain.
    pub fn earliest(self, other: Self) -> Self {
        Self {
            absolute: [self.absolute, other.absolute].into_iter().flatten().min(),
            elapsed: [self.elapsed, other.elapsed].into_iter().flatten().min(),
        }
    }

    fn due(self, sample: Sample) -> bool {
        self.absolute.is_some_and(|until| sample.absolute >= until)
            || self.elapsed.is_some_and(|until| sample.elapsed >= until)
    }
}

/// One original synchronous send offered by the local TRANSPORT owner.
#[derive(Clone, Copy, Debug)]
pub enum Outgoing<'a> {
    /// Ordinary BOX with the ordered-ciphertext completion only.
    Buffered(&'a [u8]),
    /// BOX also requiring an observation of physical socket acceptance.
    ObserveNative {
        /// Complete original GNUnet frame.
        message: &'a [u8],
        /// Identifier owned by the local queue until `outgoing_written`.
        id: NonZeroU64,
    },
}

/// Synchronous owner of the original reliable queue in the local TRANSPORT
/// engine. The transport implementation owns TNG validation, flow and routing.
pub trait Transport {
    /// Register the authenticated carrier before accepting data for it.
    fn add_queue(
        &mut self,
        local: EddsaPublicKey,
        peer: EddsaPublicKey,
        role: Role,
    ) -> Result<(), Error>;
    /// Retire only the queue created by `add_queue`.
    fn remove_queue(&mut self);
    /// Handle one complete, MAC-verified transport message during this call.
    fn receive(
        &mut self,
        peer: EddsaPublicKey,
        message: &[u8],
        context: &mut TransportContext<'_, impl Entropy>,
    ) -> Result<Delivery, Error>;
    /// Advance local timers and offer at most one complete frame through the
    /// original queue. Only successful `admit` commits to the cipher stream.
    /// An unaccepted frame can remain owned by its original producer.
    /// A second observed send waits for the first native outcome, while an
    /// ordinary send can use the queue as soon as SendContinue releases it.
    fn poll_send(
        &mut self,
        context: &mut TransportContext<'_, impl Entropy>,
        admit: impl FnOnce(Outgoing<'_>) -> Result<(), Error>,
    ) -> Result<(), Error>;
    /// Observe the original SendContinue. Success acknowledges the ordered
    /// ciphertext buffer only.
    fn outgoing_complete(&mut self, result: Result<(), Error>);
    /// Settle one admitted native observation. Success means the socket
    /// accepted every byte through the original BOX. `elapsed` is the native
    /// clock sample for the write turn or its retirement. The observation is
    /// independent of the SendContinue effect and grants no remote delivery.
    fn outgoing_written(
        &mut self,
        _id: NonZeroU64,
        _result: Result<(), Error>,
        _elapsed: MonoInstant,
    ) {
    }
    /// Timers that can make progress when the original queue is idle.
    fn deadlines(&self) -> Result<TransportDeadlines, Error>;
    /// Timers that can change authorization while an original send is pending.
    fn maintenance_deadlines(&self) -> TransportDeadlines {
        TransportDeadlines::default()
    }
    /// Advance local authorization when the maintenance timer elapses.
    /// This does not grant another send or settle its original receipt.
    fn maintain(&mut self, _sample: Sample) -> Result<(), Error> {
        Ok(())
    }
    /// Revalidate the original authorization before a ready native write.
    /// A failure retires the carrier without advancing its ciphertext stream.
    fn before_write(&mut self, _sample: Sample) -> Result<(), Error> {
        Ok(())
    }
}

/// Storage, identity and peer role for one original connection.
pub struct Connection<'a> {
    /// Unique caller-owned ticket scope.
    pub scope: &'a mut Scope,
    /// Original local peer identity.
    pub identity: Identity<'a>,
    /// Initial key exchange, including the expected remote identity when provisioned.
    pub handshake: Handshake,
    /// Persistent protocol buffers and completion slots.
    pub buffers: Buffers<'a>,
    /// Persistent read scratch for the original stream.
    pub scratch: Scratch<'a>,
    /// Explicit session resource limits.
    pub policy: Policy,
}

/// Exclusive ports required for the original connected or accepted stream.
pub struct Ports<S, B, C, T> {
    /// Owns the original nonblocking socket.
    pub stream: S,
    /// Original durable received-replay store.
    pub replay: B,
    /// Original signing clock and entropy source.
    pub clock: C,
    /// Local TRANSPORT queue owner.
    pub transport: T,
}

/// One bounded turn or original connection retirement.
#[derive(Debug)]
pub enum Turn {
    /// A native or buffered stream transition took place.
    Stream(stream::Turn),
    /// One original replay or queue effect ran, or one outgoing frame was admitted.
    Service,
    /// The original socket and queue have retired.
    Closed,
}

/// Failure from an exact owner. Continue driving to finish bounded cleanup.
#[derive(Debug)]
pub enum Fault<I, B> {
    /// Initial key exchange failed authentication before any replay operation.
    PeerRejected,
    /// Clock, session, or local TRANSPORT failure.
    Session(Error),
    /// Original synchronous replay operation failed.
    Replay(ReplayError<B>),
    /// Physical socket or its exact session transition failed.
    Stream(stream::PumpError<I>),
}

enum Mode {
    Running,
    Finishing(MonoInstant),
    Aborting,
}

#[derive(Clone, Copy)]
enum Queue {
    Absent,
    Registered,
    Sending { bytes: usize },
}

/// Read-only state of the original authenticated physical queue.
pub struct QueueObservation<'a, T> {
    /// The paired clock sample used in its latest transport turn.
    pub sample: Sample,
    /// Whole payload length of the one accepted send awaiting settlement.
    pub pending_bytes: usize,
    /// Owner of the corresponding link protocol state.
    pub transport: &'a T,
}

/// One firmware TCP owner. Every turn settles an original replay or queue
/// effect before scheduling another stream operation. The caller owns the
/// task, the wakeup source and the hardware provisioning for these ports.
pub struct Driver<'a, S, B, C, T: Transport> {
    pump: Pump<'a, 'a, S>,
    replay: ReplayStore<'a, B, REPLAY_OPERATIONS>,
    clock: C,
    transport: T,
    signed: Window,
    local: EddsaPublicKey,
    last_time: Time,
    last_elapsed: MonoInstant,
    queue_sample: Sample,
    mode: Mode,
    queue: Queue,
    native_write_id: Option<NonZeroU64>,
}

impl<'a, S: Stream, B: Backend, C: Clock, T: Transport> Driver<'a, S, B, C, T> {
    /// Admit a stream already connected or accepted by the board.
    ///
    /// # Errors
    /// Returns the original stream on rejection so its owner can report close
    /// errors. A durable timestamp reserved during setup remains spent.
    pub fn new(connection: Connection<'a>, ports: Ports<S, B, C, T>) -> Result<Self, Rejected<S>> {
        let Ports {
            stream,
            replay,
            mut clock,
            transport,
        } = ports;
        let local = connection.identity.public();
        let prepared = (|| {
            if connection.policy.max_replay_operations != REPLAY_OPERATIONS {
                return Err(Error::InvalidInput);
            }
            let mut signed = Window::resume(clock.signed_high_water()?)?;
            let sample = finite_sample(clock.sample()?)?;
            let time = issue(&mut signed, &mut clock, sample.absolute)?;
            let session = Session::with_handshake(
                connection.scope,
                connection.identity,
                connection.handshake,
                connection.buffers,
                connection.policy,
                time,
                &mut clock,
            )?;
            Ok((signed, sample, time, session))
        })();
        let (signed, sample, time, session) = match prepared {
            Ok(prepared) => prepared,
            Err(reason) => {
                return Err(Rejected {
                    value: stream,
                    reason,
                });
            }
        };
        Ok(Self {
            pump: Pump::new(session, stream, connection.scratch),
            replay: ReplayStore::new(replay),
            clock,
            transport,
            signed,
            local,
            last_time: time,
            last_elapsed: sample.elapsed,
            queue_sample: sample,
            mode: Mode::Running,
            queue: Queue::Absent,
            native_write_id: None,
        })
    }

    /// Original socket interest and logical protocol deadline.
    #[must_use]
    pub fn interest(&self) -> stream::Interest {
        self.pump.interest()
    }

    /// Borrow the real registered queue, including an accepted pending send.
    #[must_use]
    pub fn queue_observation(&self) -> Option<QueueObservation<'_, T>> {
        let pending_bytes = match self.queue {
            Queue::Absent => return None,
            Queue::Registered => 0,
            Queue::Sending { bytes } => bytes,
        };
        Some(QueueObservation {
            sample: self.queue_sample,
            pending_bytes,
            transport: &self.transport,
        })
    }

    /// Whether the original session settled its close effect. Inspect the
    /// original turn result to distinguish a confirmed close from a failure.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.pump.session().phase() == Phase::Closed
    }

    /// Whether only local retirement effects remain. No new readiness or
    /// clock observation is needed to drive these effects.
    #[must_use]
    pub fn is_retiring(&self) -> bool {
        matches!(
            self.pump.session().phase(),
            Phase::Closing | Phase::Detached | Phase::Closed
        )
    }

    /// Deadlines of the local TRANSPORT/CORE owner driving the queue.
    pub fn transport_deadlines(&self) -> Result<TransportDeadlines, Error> {
        if !matches!(self.mode, Mode::Running) {
            return Ok(TransportDeadlines::default());
        }
        match self.queue {
            Queue::Absent => Ok(TransportDeadlines::default()),
            Queue::Registered => Ok(self
                .transport
                .deadlines()?
                .earliest(self.transport.maintenance_deadlines())),
            Queue::Sending { .. } => Ok(self.transport.maintenance_deadlines()),
        }
    }

    /// Wait on the original physical owner. Call after draining local work and
    /// cap the wait by all original protocol, retirement and application timers.
    ///
    /// # Errors
    /// Propagates the original scheduler or native readiness observation.
    pub fn wait_ready(&mut self, timeout_ms: u32) -> Result<S::Events, stream::PumpError<S::Error>>
    where
        S: WaitStream,
    {
        self.pump.wait_ready(timeout_ms)
    }

    /// Native deadline for a requested FINISH, independent of absolute time.
    #[must_use]
    pub fn stop_deadline(&self) -> Option<MonoInstant> {
        match self.mode {
            Mode::Finishing(deadline) => Some(deadline),
            Mode::Running | Mode::Aborting => None,
        }
    }

    /// Begin sending the final FINISH and fence new local sends. Repeated stop
    /// requests keep the first native deadline.
    ///
    /// # Errors
    /// A clock or session failure begins immediate retirement.
    pub fn stop(&mut self) -> Result<(), Error> {
        if matches!(self.mode, Mode::Running)
            && let Err(error) = self.begin_stop()
        {
            self.abort();
            return Err(error);
        }
        Ok(())
    }

    fn begin_stop(&mut self) -> Result<(), Error> {
        let sample = self.observe_time()?;
        self.mode = Mode::Finishing(sample.elapsed.after(Duration(FINISH_US))?);
        self.last_time.now = sample.absolute.as_micros();
        self.pump.session_mut().finish(self.last_time)
    }

    /// Fence this connection immediately. `turn` still retires its original
    /// queue, socket and any synchronous operation receipts.
    pub fn abort(&mut self) {
        self.mode = Mode::Aborting;
        self.pump.session_mut().native_lost();
        self.settle_native_write();
    }

    /// Process at most one original effect or one bounded stream transition.
    /// After any failure, continue turns without native readiness until closed.
    ///
    /// # Errors
    /// Errors retain the original owner and begin terminal cleanup.
    pub fn turn(&mut self, ready: Ready) -> Result<Turn, Fault<S::Error, B::Error>> {
        let result = self.advance(ready);
        if result.is_err() {
            self.abort();
        } else {
            self.settle_native_write();
        }
        result
    }

    fn advance(&mut self, ready: Ready) -> Result<Turn, Fault<S::Error, B::Error>> {
        let phase = self.pump.session().phase();
        if phase == Phase::Closed {
            return Ok(Turn::Closed);
        }
        if matches!(phase, Phase::Closing | Phase::Detached) {
            self.mode = Mode::Aborting;
        }
        let time = self.time().map_err(Fault::Session)?;
        let sample = Sample {
            absolute: AbsoluteTime::from_micros(time.now),
            elapsed: self.last_elapsed,
        };
        self.queue_sample = sample;
        if matches!(self.mode, Mode::Running)
            && !matches!(self.queue, Queue::Absent)
            && self.transport.maintenance_deadlines().due(sample)
        {
            self.transport.maintain(sample).map_err(Fault::Session)?;
        }
        let session = self.pump.session_mut();
        if let Some(ticket) = session.next_effect_replay_first().map_err(Fault::Session)? {
            if self
                .replay
                .drive(session, ticket, time, &mut self.clock)
                .map_err(Fault::Replay)?
            {
                return Ok(Turn::Service);
            }
            if matches!(
                session.effect(ticket).map_err(Fault::Session)?,
                Effect::Close
            ) {
                self.pump
                    .close(ticket, time, &mut self.clock)
                    .map_err(Fault::Stream)?;
                return Ok(Turn::Closed);
            }
            let outcome = transport_effect(
                &mut self.queue,
                &mut self.transport,
                self.local,
                session.effect(ticket).map_err(Fault::Session)?,
                &mut context(time, self.last_elapsed, &mut self.clock).map_err(Fault::Session)?,
            );
            let verdict = outcome.as_ref().copied().unwrap_or(ResultKind::Failed);
            session
                .acknowledge(ticket, verdict, time, &mut self.clock)
                .map_err(Fault::Session)?;
            outcome.map_err(Fault::Session)?;
            return Ok(Turn::Service);
        }
        if self.replay.has_pending() {
            return Err(Fault::Session(Error::Conflict));
        }
        if matches!(self.mode, Mode::Running)
            && matches!(self.queue, Queue::Registered)
            && session.phase() == Phase::Established
        {
            let mut admitted = None;
            let outcome = self.transport.poll_send(
                &mut context(time, self.last_elapsed, &mut self.clock).map_err(Fault::Session)?,
                |outgoing| {
                    let length = match outgoing {
                        Outgoing::Buffered(message) => {
                            session.send(message)?;
                            message.len()
                        }
                        Outgoing::ObserveNative { message, id } => {
                            session.send_observed(message)?;
                            self.native_write_id = Some(id);
                            message.len()
                        }
                    };
                    admitted = Some(length);
                    Ok(())
                },
            );
            if let Some(bytes) = admitted {
                self.queue = Queue::Sending { bytes };
                outcome.map_err(Fault::Session)?;
                return Ok(Turn::Service);
            }
            if outcome != Err(Error::WouldBlock) {
                outcome.map_err(Fault::Session)?;
            }
        }
        if !matches!(self.mode, Mode::Aborting)
            && !matches!(self.queue, Queue::Absent)
            && ready.writable
            && self.pump.interest().writable
        {
            self.transport
                .before_write(sample)
                .map_err(Fault::Session)?;
        }
        self.pump
            .turn(ready, time, &mut self.clock)
            .map(Turn::Stream)
            .map_err(|error| match error {
                stream::PumpError::Session(Error::Authentication) if phase == Phase::Initial => {
                    Fault::PeerRejected
                }
                error => Fault::Stream(error),
            })
    }

    fn settle_native_write(&mut self) {
        if let Some(outcome) = self.pump.session_mut().take_native_write()
            && let Some(id) = self.native_write_id.take()
        {
            self.transport
                .outgoing_written(id, outcome, self.last_elapsed);
        }
    }

    /// Observe the original board clock to schedule the next task wait.
    ///
    /// # Errors
    /// Refuses an unavailable clock, a non-finite reading or elapsed clock
    /// regression. The caller must retire the connection on failure.
    pub fn observe_time(&mut self) -> Result<Sample, Error> {
        let sample = finite_sample(self.clock.sample()?)?;
        sample.elapsed.duration_since(self.last_elapsed)?;
        self.last_elapsed = sample.elapsed;
        Ok(sample)
    }

    fn time(&mut self) -> Result<Time, Error> {
        if matches!(self.mode, Mode::Aborting) {
            return Ok(self.last_time);
        }
        let sample = self.observe_time()?;
        if matches!(self.mode, Mode::Running) && self.pump.session().phase() == Phase::Finishing {
            self.mode = Mode::Finishing(sample.elapsed.after(Duration(FINISH_US))?);
        }
        if matches!(self.mode, Mode::Finishing(until) if sample.elapsed >= until) {
            return Err(Error::Timeout);
        }
        self.last_time = issue(&mut self.signed, &mut self.clock, sample.absolute)?;
        Ok(self.last_time)
    }
}

fn finite_sample(sample: Sample) -> Result<Sample, Error> {
    if sample.absolute.is_never() || sample.elapsed.0 == u64::MAX {
        return Err(Error::TimeUncertain);
    }
    Ok(sample)
}

fn context<E>(
    time: Time,
    elapsed: MonoInstant,
    entropy: &mut E,
) -> Result<TransportContext<'_, E>, Error> {
    Ok(TransportContext {
        sample: Sample {
            absolute: AbsoluteTime::from_micros(time.now),
            elapsed,
        },
        signed: NonZeroU64::new(time.signed).ok_or(Error::Conflict)?,
        entropy,
    })
}

impl<S, B, C, T: Transport> Drop for Driver<'_, S, B, C, T> {
    fn drop(&mut self) {
        if let Some(id) = self.native_write_id.take() {
            self.transport
                .outgoing_written(id, Err(Error::Closed), self.last_elapsed);
        }
        retire_queue(&mut self.queue, &mut self.transport);
    }
}

fn issue(signed: &mut Window, clock: &mut impl Clock, now: AbsoluteTime) -> Result<Time, Error> {
    let stamp = clock.issue_signed(now, signed)?;
    Ok(Time {
        now: now.as_micros(),
        signed: stamp.get(),
    })
}

fn transport_effect(
    queue: &mut Queue,
    transport: &mut impl Transport,
    local: EddsaPublicKey,
    effect: Effect<'_, '_>,
    context: &mut TransportContext<'_, impl Entropy>,
) -> Result<ResultKind, Error> {
    match effect {
        Effect::QueueAdd(peer, role) if matches!(queue, Queue::Absent) => {
            transport.add_queue(local, peer, role)?;
            *queue = Queue::Registered;
        }
        Effect::QueueDelete if !matches!(queue, Queue::Absent) => {
            retire_queue(queue, transport);
        }
        Effect::SendContinue if matches!(queue, Queue::Sending { .. }) => {
            transport.outgoing_complete(Ok(()));
            *queue = Queue::Registered;
        }
        Effect::Receive { peer, message, .. } => {
            return Ok(if matches!(queue, Queue::Absent) {
                ResultKind::Unavailable
            } else {
                match transport.receive(peer, message, context)? {
                    Delivery::Consumed => ResultKind::Consumed,
                    Delivery::Dropped => ResultKind::Dropped,
                    Delivery::Unavailable => ResultKind::Unavailable,
                }
            });
        }
        _ => return Err(Error::Conflict),
    }
    Ok(ResultKind::Success)
}

fn retire_queue(queue: &mut Queue, transport: &mut impl Transport) {
    if matches!(queue, Queue::Sending { .. }) {
        transport.outgoing_complete(Err(Error::Closed));
    }
    if !matches!(queue, Queue::Absent) {
        transport.remove_queue();
        *queue = Queue::Absent;
    }
}
