//! One actual shared DHT MQ, bounded original PUTs and clock-free retirement.
use super::{Event, Factory, Inputs, Port, Put};
use crate::{
    Failure,
    core::{material::PublicPublication, schedule::Job},
};
use gnunet_dht_client_host as dht;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use gnunet_wire::official::AbsoluteTime;
use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

/// Original local reason; none is a remote DHT storage acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reason {
    /// Original canonical/block/native target elapsed.
    Deadline,
    /// The original job's caller canceled its interest.
    Cancelled,
    /// Another original job required retirement of the same physical MQ.
    SharedRetirement,
    /// Actual DHT/native source failed.
    Source,
    /// Original native one-shot outcome was not a live full write.
    Terminal,
}
/// Bounded original outcome metadata with a shared actual source cause.
/// A canceled whole write remains visible here and is never remote success.
#[derive(Debug)]
pub struct NativeFailure {
    /// Exact original unforgeable job coordinate.
    pub job: Job,
    /// Actual local reason.
    pub reason: Reason,
    /// Actual original one-shot notice; absent for no native admission or a
    /// positively observed BeforeIssue removal.
    pub outcome: Option<dht::Outcome>,
    /// Actual original cancellation disposition, if cancellation was requested.
    pub cancellation: Option<dht::Cancel>,
    cause: Option<Rc<dyn Error>>,
}
impl fmt::Display for NativeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original ZONEMASTER DHT {:?}: {:?}; outcome={:?}; cancellation={:?}",
            self.job, self.reason, self.outcome, self.cancellation
        )?;
        if let Some(cause) = &self.cause {
            write!(f, "; source: {cause}")?;
        }
        Ok(())
    }
}
impl Error for NativeFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause.as_deref()
    }
}
/// Production factory owns the original brand; the opened producer borrows it
/// for the complete foreground run. It contains no self-reference or scheduler.
pub struct DhtFactory {
    instance: dht::Instance,
}
impl DhtFactory {
    /// Create metadata only; no endpoint, socket, key or worker is started.
    pub fn new() -> Self {
        Self {
            instance: dht::Instance::new(),
        }
    }
}
impl Default for DhtFactory {
    fn default() -> Self {
        Self::new()
    }
}
impl Factory for DhtFactory {
    fn open<'a>(&'a mut self, input: Inputs) -> Result<Box<dyn Port + 'a>, Failure> {
        if input.parallel == 0 || !Arc::ptr_eq(&input.source.clock(), &input.clock) {
            return Err(Fault::InvalidInput.into());
        }
        let bytes = input.parallel.checked_mul(65535).ok_or(Fault::Overflow)?;
        let mut limits = dht::Limits::default();
        limits.protocol.gets = 0;
        limits.protocol.monitors = 0;
        limits.protocol.hellos = 0;
        limits.protocol.known_per_get = 0;
        limits.protocol.operations = input.parallel;
        // One physical FIFO frame at a time avoids a second full parallel set
        // of encoded payloads, while logical original PUTs remain bounded.
        limits.protocol.attempts = 1;
        limits.protocol.source_bytes = bytes;
        limits.output.frames = 1;
        limits.output.bytes = 65535;
        let client = dht::Client::new(&mut self.instance, input.source, limits)?;
        let mut flights = Vec::new();
        flights
            .try_reserve_exact(input.parallel)
            .map_err(|_| Fault::Capacity)?;
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(input.parallel)
            .map_err(|_| Fault::Capacity)?;
        Ok(Box::new(Native {
            client,
            clock: input.clock,
            limit: input.parallel,
            flights,
            events,
            alarm: None,
            alarm_at: None,
            retry: None,
            closed: false,
        }))
    }
}
struct Flight<'a> {
    job: Job,
    until: u64,
    block_until: u64,
    hard: Instant,
    public: Option<PublicPublication>,
    operation: Option<dht::OperationId<'a>>,
    epoch: Option<dht::Epoch<'a>>,
    cancellation: Option<dht::Cancel>,
    reason: Option<Reason>,
    cause: Option<Rc<dyn Error>>,
}
struct Native<'a> {
    client: dht::Client<'a>,
    clock: Arc<dyn RuntimeClock>,
    limit: usize,
    flights: Vec<Flight<'a>>,
    events: VecDeque<Event>,
    alarm: Option<Pin<Box<Sleep>>>,
    alarm_at: Option<Instant>,
    retry: Option<Rc<dyn Error>>,
    closed: bool,
}
impl<'a> Native<'a> {
    fn next_hard(&self) -> Option<Instant> {
        self.flights.iter().map(|f| f.hard).min()
    }
    fn contains(&self, job: Job) -> bool {
        self.flights.iter().any(|f| f.job == job)
            || self.events.iter().any(|e| match e {
                Event::Submitted { job: original } | Event::Lost { job: original, .. } => {
                    *original == job
                }
            })
    }
    fn finish(&mut self, index: usize, outcome: Option<dht::Outcome>) {
        let flight = self.flights.remove(index);
        let event = if outcome == Some(dht::Outcome::Written) {
            Event::Submitted { job: flight.job }
        } else {
            Event::Lost {
                job: flight.job,
                error: Some(Box::new(NativeFailure {
                    job: flight.job,
                    reason: flight.reason.unwrap_or(Reason::Terminal),
                    outcome,
                    cancellation: flight.cancellation,
                    cause: flight.cause,
                })),
            }
        };
        // flights + queued notices never exceeds the pre-reserved limit.
        self.events.push_back(event);
    }
    fn completion(&mut self, completion: dht::Completion<'a>) -> Result<(), Failure> {
        let index = self
            .flights
            .iter()
            .position(|f| f.operation == Some(completion.operation))
            .ok_or(Fault::Stale)?;
        self.finish(index, Some(completion.outcome));
        Ok(())
    }
    fn loss(&mut self, epoch: dht::Epoch<'a>, cause: dht::LossCause) {
        let cause: Rc<dyn Error> = Rc::new(Lost(cause));
        for flight in &mut self.flights {
            if flight.epoch == Some(epoch) {
                flight.cause.get_or_insert_with(|| cause.clone());
            }
        }
    }
    fn drain(&mut self) -> Result<(), Failure> {
        let mut first = None;
        while let Some(completion) = self.client.take_completion() {
            if let Err(error) = self.completion(completion)
                && first.is_none()
            {
                first = Some(error);
            }
        }
        first.map_or(Ok(()), Err)
    }
    fn arm(&mut self, cx: &mut Context<'_>) {
        let target = self.next_hard();
        if target != self.alarm_at {
            self.alarm_at = target;
            if let Some(target) = target {
                if let Some(alarm) = &mut self.alarm {
                    alarm.as_mut().reset(target);
                } else {
                    self.alarm = Some(Box::pin(tokio::time::sleep_until(target)));
                }
            } else {
                self.alarm = None;
            }
        }
        if let Some(alarm) = &mut self.alarm {
            let _ready = alarm.as_mut().poll(cx);
        }
    }
    fn retire_selected(
        &mut self,
        selected: impl Fn(&Flight<'a>) -> bool,
        reason: Reason,
        cause: Option<Rc<dyn Error>>,
    ) -> Result<(), Failure> {
        // Real already-completed writes/losses precede cancellation. They are
        // queued as their actual original fact even if a logical job expired.
        if let Err(error) = self.drain() {
            let _actual = self.client.close();
            self.closed = true;
            return Err(error);
        }
        if !self.flights.iter().any(&selected) {
            return Ok(());
        }
        for f in &mut self.flights {
            if selected(f) {
                f.reason = Some(reason);
                f.cause = cause.clone().or_else(|| self.retry.clone());
            } else if f.operation.is_some() {
                f.reason.get_or_insert(Reason::SharedRetirement);
            }
        }
        let mut cancel_error = None;
        let mut index = 0;
        while index < self.flights.len() {
            if !selected(&self.flights[index]) {
                index += 1;
                continue;
            }
            let cancellation = match self.flights[index]
                .operation
                .map(|op| self.client.cancel(op))
                .transpose()
            {
                Ok(cancellation) => cancellation,
                Err(error) => {
                    let error: Rc<dyn Error> = Rc::new(error);
                    self.flights[index].cause = Some(error.clone());
                    if cancel_error.is_none() {
                        cancel_error = Some(error);
                    }
                    index += 1;
                    continue;
                }
            };
            self.flights[index].cancellation = cancellation;
            if cancellation.is_none() || cancellation == Some(dht::Cancel::BeforeIssue) {
                self.finish(index, None);
            } else {
                index += 1;
            }
        }
        // Shared MQ retirement settles all affected issued operations; only
        // never-admitted waiting public values can survive for their original
        // first PUT on a later MQ. No issued one-shot is ever reconstructed.
        match self.client.retire_io() {
            Ok(actual) => {
                if let Some(dht::Progress::Lost { epoch, cause, .. }) = actual {
                    self.loss(epoch, cause);
                }
                self.drain()?;
                if let Some(error) = cancel_error {
                    Err(Box::new(Shared(error)))
                } else {
                    Ok(())
                }
            }
            Err(error) => {
                let _actual = self.client.close();
                self.closed = true;
                self.drain()?;
                while !self.flights.is_empty() {
                    self.flights[0].reason.get_or_insert(Reason::Source);
                    self.finish(0, None);
                }
                Err(error.into())
            }
        }
    }
    fn fail(&mut self, error: Failure) -> Result<(), Failure> {
        let cause: Rc<dyn Error> = Rc::from(error);
        self.retire_selected(|_| true, Reason::Source, Some(cause))
    }
    fn guard(&mut self, cx: &mut Context<'_>) -> Result<Option<Event>, Failure> {
        self.drain()?;
        let now = Instant::now();
        if self.flights.iter().any(|f| now >= f.hard) {
            self.retire_selected(|f| now >= f.hard, Reason::Deadline, None)?;
        }
        self.arm(cx);
        Ok(self.events.pop_front())
    }
}
impl<'a> Port for Native<'a> {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    fn put(&mut self, input: Put) -> Result<(), Failure> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if Instant::now() >= input.hard {
            return Err(Fault::Deadline.into());
        }
        let now = self.clock.sample()?.now.as_micros();
        if Instant::now() >= input.hard || now >= input.expires || now >= input.public.expires() {
            return Err(Fault::Deadline.into());
        }
        if input.block_type != 11
            || input.replication != 5
            || input.options != 1
            || input.public.bytes().is_empty()
        {
            return Err(Fault::InvalidInput.into());
        }
        if self.contains(input.job) {
            return Err(Fault::Replay.into());
        }
        if self
            .flights
            .len()
            .checked_add(self.events.len())
            .ok_or(Fault::Overflow)?
            >= self.limit
        {
            return Err(Fault::Capacity.into());
        }
        let frame = dht::ipc::Put {
            block_type: input.block_type,
            options: input.options,
            replication: input.replication,
            expiration: AbsoluteTime::from_micros(input.public.expires()),
            key: input.public.query(),
            payload: input.public.bytes(),
        };
        if frame.encoded_len()? > 65535 {
            return Err(Fault::TooLarge.into());
        }
        self.flights.push(Flight {
            job: input.job,
            until: input.expires,
            block_until: input.public.expires(),
            hard: input.hard,
            public: Some(input.public),
            operation: None,
            epoch: None,
            cancellation: None,
            reason: None,
            cause: None,
        });
        Ok(())
    }
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Result<Event, Failure>> {
        match self.guard(cx) {
            Ok(event) => event.map(Ok),
            Err(original) => {
                let cleanup = self.close();
                Some(Err(match cleanup {
                    Ok(()) => original,
                    Err(cleanup) => Box::new(CloseFailure { original, cleanup }) as Failure,
                }))
            }
        }
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event, Failure>> {
        if let Some(event) = self.poll_native_guard(cx) {
            return Poll::Ready(event);
        }
        if self.flights.is_empty() {
            return Poll::Pending;
        }
        let now = match self.clock.sample() {
            Ok(sample) => sample.now.as_micros(),
            Err(error) => {
                self.fail(error.into())?;
                return self
                    .events
                    .pop_front()
                    .map_or(Poll::Pending, |event| Poll::Ready(Ok(event)));
            }
        };
        if self
            .flights
            .iter()
            .any(|f| now >= f.until || now >= f.block_until)
        {
            self.retire_selected(
                |f| now >= f.until || now >= f.block_until,
                Reason::Deadline,
                None,
            )?;
            self.arm(cx);
            return self
                .events
                .pop_front()
                .map_or(Poll::Pending, |event| Poll::Ready(Ok(event)));
        }
        if let Some(epoch) = self.client.epoch()
            && let Some(index) = self.flights.iter().position(|f| f.operation.is_none())
        {
            let f = &self.flights[index];
            let public = f.public.as_ref().ok_or(Fault::Stale)?;
            let admitted = self.client.put(dht::ipc::Put {
                block_type: 11,
                options: 1,
                replication: 5,
                expiration: AbsoluteTime::from_micros(public.expires()),
                key: public.query(),
                payload: public.bytes(),
            });
            match admitted {
                Ok(operation) => {
                    self.flights[index].operation = Some(operation);
                    self.flights[index].epoch = Some(epoch);
                    self.flights[index].public = None;
                }
                Err(error) => {
                    self.flights[index].reason = Some(Reason::Source);
                    self.flights[index].cause = Some(Rc::new(error));
                    self.finish(index, None);
                    cx.waker().wake_by_ref();
                    return self
                        .events
                        .pop_front()
                        .map_or(Poll::Pending, |event| Poll::Ready(Ok(event)));
                }
            }
        }
        // The copy/admission above spends the same original hard budget. Retire
        // before any native IO if that budget elapsed during preparation.
        if let Some(event) = self.poll_native_guard(cx) {
            return Poll::Ready(event);
        }
        let hard = self.next_hard();
        match self.client.poll_with_input(cx, hard, true) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.fail(error.into())?;
                self.events
                    .pop_front()
                    .map_or(Poll::Pending, |event| Poll::Ready(Ok(event)))
            }
            Poll::Ready(Ok(progress)) => {
                match progress {
                    dht::Progress::Completed(completion) => self.completion(completion)?,
                    dht::Progress::Lost { epoch, cause, .. } => {
                        for flight in &mut self.flights {
                            if flight.epoch == Some(epoch) {
                                flight.reason = Some(Reason::Source);
                            }
                        }
                        self.loss(epoch, cause);
                    }
                    dht::Progress::Connected(_) => self.retry = None,
                    dht::Progress::ConnectRetry { error, .. } => self.retry = Some(Rc::new(error)),
                    dht::Progress::Unavailable(error) => self.fail(error.into())?,
                    dht::Progress::Capacity(_) => self.fail(Fault::Capacity.into())?,
                    dht::Progress::Closed => {
                        self.closed = true;
                        self.fail(Fault::Closed.into())?;
                    }
                    _ => {}
                }
                self.drain()?;
                self.arm(cx);
                if let Some(event) = self.events.pop_front() {
                    Poll::Ready(Ok(event))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
    fn stop(&mut self, job: Job) -> Result<(), Failure> {
        self.retire_selected(|f| f.job == job, Reason::Cancelled, None)
    }
    fn take_settled(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
    fn close(&mut self) -> Result<(), Failure> {
        // Consume actual already-retained terminal notices before physical
        // close; shutdown never rewrites a completed original write as loss.
        let original = self.drain();
        for flight in &mut self.flights {
            flight.reason.get_or_insert(Reason::Cancelled);
        }
        if let Some(dht::Progress::Lost { epoch, cause, .. }) = self.client.close() {
            self.loss(epoch, cause);
        }
        self.closed = true;
        let completion = self.drain();
        while !self.flights.is_empty() {
            self.finish(0, None);
        }
        self.alarm = None;
        self.alarm_at = None;
        match (original, completion) {
            (Ok(()), result) | (result, Ok(())) => result,
            (Err(original), Err(cleanup)) => Err(Box::new(CloseFailure { original, cleanup })),
        }
    }
}
#[derive(Debug)]
struct Lost(dht::LossCause);
impl fmt::Display for Lost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "original DHT MQ loss: {:?}", self.0)
    }
}
impl Error for Lost {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.0 {
            dht::LossCause::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct Shared(Rc<dyn Error>);
impl fmt::Display for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl Error for Shared {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
#[derive(Debug)]
struct CloseFailure {
    original: Failure,
    cleanup: Failure,
}
impl fmt::Display for CloseFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "original DHT notice: {}; independent close notice: {}",
            self.original, self.cleanup
        )
    }
}
impl Error for CloseFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}
