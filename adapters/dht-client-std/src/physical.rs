use super::*;
// Native CLIENT lifecycle only; the pure DHT client owns protocol/epoch authority.
pub(super) struct Physical<'a> {
    pub(super) attempt: Option<ConnectionAttempt>,
    pub(super) framed: Option<Framed<Attempt<'a>>>,
    pub(super) source: EndpointSource,
    pub(super) endpoint: Option<Endpoint>,
    pub(super) clock: Arc<dyn RuntimeClock>,
    pub(super) subscription: Option<Box<dyn ClockSubscription>>,
    pub(super) revision: u64,
    pub(super) timer: Option<ResolutionTimer>,
    pub(super) delay: Option<Duration>,
    pub(super) backoff: u64,
    pub(super) round: u64,
    pub(super) port_error: Option<PortError>,
    pub(super) clock_refused: bool,
    pub(super) wait: Option<Pin<Box<Sleep>>>,
    pub(super) limits: Limits,
}
pub(super) enum ConnectionStep {
    Attached,
    Retry(io::Error, Duration),
    Unavailable(Error),
}
fn clock_error(error: ProtocolError) -> Error {
    Error::Io(PortError::mark(io::Error::other(error)))
}
impl<'a> Physical<'a> {
    pub(super) fn new(source: EndpointSource, limits: Limits) -> Result<Self, Error> {
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
        })
    }
    pub(super) fn stop(&mut self) {
        drop(self.attempt.take());
        self.timer = None;
        if let Some(mut framed) = self.framed.take() {
            framed.retire();
        }
        self.endpoint = None;
        self.round = 0;
        self.wait = None;
    }
    pub(super) fn schedule(&mut self) -> Duration {
        let delay = Duration::from_micros(self.backoff);
        self.backoff = if self.backoff == 0 {
            1000
        } else {
            self.backoff.saturating_mul(2).min(900_000_000)
        };
        self.delay = Some(delay);
        delay
    }
    pub(super) fn clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if let Some(error) = &self.port_error {
            return Poll::Ready(Err(Error::Io(error.to_io())));
        }
        let result = self.poll_clock(cx);
        if let Poll::Ready(Err(error)) = &result
            && let Error::Io(error) = error
        {
            self.port_error = PortError::from_io(error).cloned();
            self.clock_refused = true;
        }
        result
    }
    fn poll_clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
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
    pub(super) fn poll_connect(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ConnectionStep, Error>> {
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
                    self.schedule();
                    return Poll::Ready(Ok(ConnectionStep::Unavailable(error)));
                }
            }
        }
        if self.attempt.is_none() {
            let round = self.round.checked_add(1).ok_or(ProtocolError::Capacity)?;
            self.attempt = Some(
                self.endpoint
                    .as_ref()
                    .ok_or(ProtocolError::NotReady)?
                    .attempt(self.round),
            );
            self.round = round;
        }
        let result = Pin::new(self.attempt.as_mut().ok_or(ProtocolError::NotReady)?).poll(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                if PortError::from_io(&error).is_some() {
                    return self.refuse(error);
                }
                drop(self.attempt.take());
                let delay = self.schedule();
                Poll::Ready(Ok(ConnectionStep::Retry(error, delay)))
            }
            Poll::Ready(Ok(connection)) => {
                self.attempt = None;
                self.framed = Some(Framed::new(connection, self.limits.framing())?);
                Poll::Ready(Ok(ConnectionStep::Attached))
            }
        }
    }
    fn refuse<T>(&mut self, error: io::Error) -> Poll<Result<T, Error>> {
        let error = PortError::mark(error);
        self.port_error = PortError::from_io(&error).cloned();
        Poll::Ready(Err(Error::Io(error)))
    }
    pub(super) fn recover_ports(&mut self) -> Result<(), Error> {
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
    pub(super) fn poll_wait(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
    ) -> Poll<Result<(), Error>> {
        let Some(deadline) = deadline else {
            return Poll::Pending;
        };
        let timer = self
            .wait
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        timer.as_mut().reset(deadline);
        timer.as_mut().poll(cx).map(Ok)
    }
}
impl Drop for Physical<'_> {
    fn drop(&mut self) {
        self.stop();
        self.subscription = None;
    }
}
