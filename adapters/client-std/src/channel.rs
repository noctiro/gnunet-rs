//! Caller-driven physical CLIENT lifetime without a domain protocol dependency.
//! The enclosing domain creates its own epoch only after an actual connection
//! attaches, owns all original frame tags and reports full writes before reads.
use crate::{
    ConnectError as Error, ConnectGuard, ConnectionAttempt, Endpoint, EndpointSource,
    resolution::{PortError, ResolutionTimer},
};
use gnunet_service_runtime::{
    clock::{ClockSubscription, RuntimeClock},
    framing::{Framed, Limits},
};
use gnunet_types::Error as ProtocolError;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// One actual CLIENT connection-selection observation; no domain readiness.
pub enum ConnectionStep {
    /// The original native connection now owns retained framing storage.
    Attached,
    /// The original syscall failed; the source-domain retry remains pending.
    Retry {
        /// Actual socket/DNS attempt failure.
        error: io::Error,
        /// Delay selected after the failure, not an application deadline.
        retry_after: Duration,
    },
    /// Current configuration could not select an endpoint; not service absence.
    Unavailable(Error),
}
/// Generic physical CLIENT and retained framed cursors, with opaque domain tags.
/// No background task, Resolver broker, domain ID or protocol reply is created.
pub struct Channel<Origin: Copy> {
    attempt: Option<ConnectionAttempt>,
    framed: Option<Framed<Origin>>,
    source: EndpointSource,
    endpoint: Option<Endpoint>,
    clock: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    timer: Option<ResolutionTimer>,
    delay: Option<Duration>,
    backoff: u64,
    round: u64,
    port_error: Option<PortError>,
    clock_refused: bool,
    wait: Option<Pin<Box<Sleep>>>,
    limits: Limits,
    connect_guard: Option<ConnectGuard>,
    closed: bool,
}
fn clock_error(error: ProtocolError) -> Error {
    Error::Io(PortError::mark(io::Error::other(error)))
}
impl<Origin: Copy> Channel<Origin> {
    /// Reserve one independent clock subscription; create no socket or task.
    pub fn new(source: EndpointSource, limits: Limits) -> Result<Self, Error> {
        Self::new_inner(source, limits, None)
    }
    /// Same original connection owner with a retained native connect gate.
    /// The caller owns cancellation/source state; no new identity is inferred.
    pub fn new_guarded(
        source: EndpointSource,
        limits: Limits,
        guard: ConnectGuard,
    ) -> Result<Self, Error> {
        Self::new_inner(source, limits, Some(guard))
    }
    fn new_inner(
        source: EndpointSource,
        limits: Limits,
        connect_guard: Option<ConnectGuard>,
    ) -> Result<Self, Error> {
        limits.validate()?;
        let clock = source.clock();
        let subscription = clock.subscribe().map_err(clock_error)?;
        Ok(Self {
            attempt: None,
            framed: None,
            source,
            endpoint: None,
            clock,
            subscription: Some(subscription),
            revision: 0,
            timer: None,
            delay: None,
            backoff: 0,
            round: 0,
            port_error: None,
            clock_refused: false,
            wait: None,
            limits,
            connect_guard,
            closed: false,
        })
    }
    /// Borrow only the current physical framing owner.
    #[must_use]
    pub fn framing(&self) -> Option<&Framed<Origin>> {
        self.framed.as_ref()
    }
    /// Drive retained cursors after checking the canonical clock on this turn.
    pub fn framing_mut(&mut self) -> Option<&mut Framed<Origin>> {
        self.framed.as_mut()
    }
    /// Close the original native attempt/MQ before the domain retires its epoch.
    /// Clock-port refusal remains explicit and is not silently cleared.
    pub fn detach(&mut self) {
        drop(self.attempt.take());
        self.timer = None;
        if let Some(mut framed) = self.framed.take() {
            framed.retire();
        }
        self.endpoint = None;
        self.round = 0;
        self.wait = None;
    }
    /// Select a bounded retry after an actual domain/native loss. It creates
    /// no timer until the next explicit connection poll.
    pub fn schedule_retry(&mut self) -> Result<Duration, Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        let delay = Duration::from_micros(self.backoff);
        self.backoff = if self.backoff == 0 {
            1000
        } else {
            self.backoff.saturating_mul(2).min(900_000_000)
        };
        self.delay = Some(delay);
        Ok(delay)
    }
    /// Reset only the exponent used for a future reconnect after an actual
    /// source-matching successful observation. Existing retry delay/timer,
    /// original source, frame cursors and deadlines remain unchanged.
    pub fn reset_backoff(&mut self) {
        self.backoff = 0;
    }
    /// Validate this turn's actual clock and revision before native IO.
    /// Refused source/timer/Resolver ports require explicit recovery.
    pub fn poll_clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.closed {
            return Poll::Ready(Err(ProtocolError::Closed.into()));
        }
        if let Some(error) = &self.port_error {
            return Poll::Ready(Err(Error::Io(error.to_io())));
        }
        let result = self.clock_step(cx);
        if let Poll::Ready(Err(Error::Io(error))) = &result {
            self.port_error = PortError::from_io(error).cloned();
            self.clock_refused = true;
        }
        result
    }
    fn clock_step(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let subscription = self.subscription.as_mut().ok_or(ProtocolError::Closed)?;
        match subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(clock_error(error))),
            Poll::Ready(Ok(sample)) => self.revision = sample.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample().map_err(clock_error)?;
        match subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(clock_error(error))),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => {
                self.revision = sample.revision;
                Poll::Ready(Ok(()))
            }
        }
    }
    /// Poll one retained original connection attempt, including its source timer.
    /// Calling while already attached does not replace that physical owner.
    pub fn poll_connect(&mut self, cx: &mut Context<'_>) -> Poll<Result<ConnectionStep, Error>> {
        if self.closed {
            return Poll::Ready(Err(ProtocolError::Closed.into()));
        }
        if self.framed.is_some() {
            return Poll::Ready(Err(ProtocolError::NotReady.into()));
        }
        if let Some(error) = &self.port_error {
            return Poll::Ready(Err(Error::Io(error.to_io())));
        }
        if let Some(delay) = self.delay
            && self.timer.is_none()
        {
            match self.source.timer(delay) {
                Ok(timer) => self.timer = Some(timer),
                Err(error) => return self.refuse(error),
            }
        }
        if let Some(timer) = &mut self.timer {
            match timer.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return self.refuse(error),
                Poll::Ready(Ok(())) => {
                    self.timer = None;
                    self.delay = None;
                }
            }
        }
        if self.endpoint.is_none() {
            match self.source.resolve() {
                Ok(endpoint) => self.endpoint = Some(endpoint),
                Err(error) => {
                    self.schedule_retry()?;
                    return Poll::Ready(Ok(ConnectionStep::Unavailable(error)));
                }
            }
        }
        if self.attempt.is_none() {
            let next = self.round.checked_add(1).ok_or(ProtocolError::Overflow)?;
            let endpoint = self.endpoint.as_ref().ok_or(ProtocolError::NotReady)?;
            self.attempt = Some(match &self.connect_guard {
                Some(guard) => endpoint.attempt_guarded(self.round, guard.clone()),
                None => endpoint.attempt(self.round),
            });
            self.round = next;
        }
        match Pin::new(self.attempt.as_mut().ok_or(ProtocolError::NotReady)?).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                if PortError::from_io(&error).is_some() {
                    return self.refuse(error);
                }
                drop(self.attempt.take());
                let retry_after = self.schedule_retry()?;
                Poll::Ready(Ok(ConnectionStep::Retry { error, retry_after }))
            }
            Poll::Ready(Ok(connection)) => {
                self.attempt = None;
                self.framed = Some(Framed::new(connection, self.limits)?);
                Poll::Ready(Ok(ConnectionStep::Attached))
            }
        }
    }
    fn refuse<T>(&mut self, error: io::Error) -> Poll<Result<T, Error>> {
        let error = PortError::mark(error);
        self.port_error = PortError::from_io(&error).cloned();
        Poll::Ready(Err(Error::Io(error)))
    }
    /// Recover the original explicit port refusal without replaying native IO.
    /// Permanent close cannot register another clock subscription or connection.
    pub fn recover_ports(&mut self) -> Result<(), Error> {
        if self.closed {
            return Err(ProtocolError::Closed.into());
        }
        if self.port_error.is_none() {
            return Err(ProtocolError::NotReady.into());
        }
        if self.clock_refused {
            self.subscription = None;
            match self.clock.subscribe() {
                Ok(subscription) => self.subscription = Some(subscription),
                Err(error) => {
                    let error = clock_error(error);
                    if let Error::Io(cause) = &error {
                        self.port_error = PortError::from_io(cause).cloned();
                    }
                    return Err(error);
                }
            }
            self.clock_refused = false;
        } else {
            drop(self.attempt.take());
            self.timer = None;
        }
        self.port_error = None;
        Ok(())
    }
    /// Wait only for the caller's real-time observation budget. This does not
    /// cancel a domain lookup or replace its canonical logical clock.
    pub fn poll_wait(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<(), Error>> {
        if self.closed {
            return Poll::Ready(Err(ProtocolError::Closed.into()));
        }
        let Some(deadline) = deadline else {
            return Poll::Pending;
        };
        let timer = self
            .wait
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        timer.as_mut().reset(deadline);
        timer.as_mut().poll(cx).map(Ok)
    }
    /// Permanently close original IO and release this owner's clock subscription.
    pub fn close(&mut self) {
        self.detach();
        self.subscription = None;
        self.delay = None;
        self.closed = true;
    }
}
impl<Origin: Copy> Drop for Channel<Origin> {
    fn drop(&mut self) {
        self.close();
    }
}
