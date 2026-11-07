//! One retained actual CLIENT socket/Resolver attempt; no protocol request replay.
use gnunet_client_host::{
    ConnectError, ConnectionAttempt, Endpoint, EndpointSource, resolution::ResolutionTimer,
};
use gnunet_service_runtime::connection::Connection;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
/// Original socket failure and the canonical retry budget actually installed.
#[derive(Debug)]
pub struct Retry {
    /// Original native failure.
    pub error: io::Error,
    /// Actual next CLIENT retry delay.
    pub after: Duration,
}
/// Actual setup/port failure, preserving an earlier failed native attempt too.
#[derive(Debug)]
pub struct Failure {
    /// Original attempt cause if retry-port admission also failed.
    pub original: Option<io::Error>,
    /// Actual configuration/port cause.
    pub cause: ConnectError,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.original, self.cause)
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
/// One original logical service MQ before any domain frame exists. Dropped wait
/// futures preserve attempts/timers/notices. Disposing this owner cancels only
/// those native acquisition resources; it has no crypto/store side effect.
pub struct Dial {
    source: EndpointSource,
    endpoint: Option<Endpoint>,
    attempt: Option<ConnectionAttempt>,
    timer: Option<ResolutionTimer>,
    round: u64,
    delay: u64,
    failed: Option<io::Error>,
    notice: Option<Retry>,
    closed: bool,
}
impl Dial {
    /// Retain the caller's explicit process CLIENT/Resolver/clock context.
    #[must_use]
    pub fn new(source: EndpointSource) -> Self {
        Self {
            source,
            endpoint: None,
            attempt: None,
            timer: None,
            round: 0,
            delay: 1_000,
            failed: None,
            notice: None,
            closed: false,
        }
    }
    /// Begin a new physical acquisition only after the preceding real success.
    /// This keeps the original selector/Resolver/clock and discards its old
    /// endpoint cache; no protocol request or prior failed attempt is replayed.
    pub fn restart(&mut self) -> Result<(), gnunet_types::Error> {
        if !self.closed
            || self.attempt.is_some()
            || self.timer.is_some()
            || self.failed.is_some()
            || self.notice.is_some()
        {
            return Err(gnunet_types::Error::Conflict);
        }
        self.endpoint = None;
        self.round = 0;
        self.delay = 1_000;
        self.closed = false;
        Ok(())
    }
    /// Cancel only the original native acquisition and return every unobserved
    /// retry/failure. No domain frame has been submitted by this owner.
    pub fn close(&mut self) -> (Option<Retry>, Option<io::Error>) {
        self.attempt = None;
        self.endpoint = None;
        self.timer = None;
        self.closed = true;
        (self.notice.take(), self.failed.take())
    }
    /// Drain the original actual retry notification before another may overwrite it.
    pub fn take_retry(&mut self) -> Option<Retry> {
        self.notice.take()
    }
    /// Drain an original failure on enclosing shutdown/port refusal.
    pub fn take_unreported(&mut self) -> Option<io::Error> {
        self.failed.take()
    }
    /// Poll the same actual retained attempt. A pending original notice must be
    /// consumed before retry advances. Success transfers the original connection.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Connection, Failure>> {
        if self.closed {
            return Poll::Ready(Err(Failure {
                original: self.failed.take(),
                cause: gnunet_types::Error::Closed.into(),
            }));
        }
        if self.notice.is_some() {
            return Poll::Pending;
        }
        if self.failed.is_some() {
            let duration = Duration::from_micros(self.delay);
            match self.source.timer(duration) {
                Ok(timer) => {
                    self.timer = Some(timer);
                    if let Some(error) = self.failed.take() {
                        self.notice = Some(Retry {
                            error,
                            after: duration,
                        });
                    }
                    self.delay = self.delay.saturating_mul(2).min(60_000_000);
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(error) => {
                    self.closed = true;
                    return Poll::Ready(Err(Failure {
                        original: self.failed.take(),
                        cause: ConnectError::Io(error),
                    }));
                }
            }
        }
        if let Some(timer) = &mut self.timer {
            match timer.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => self.timer = None,
                Poll::Ready(Err(error)) => {
                    self.closed = true;
                    return Poll::Ready(Err(Failure {
                        original: None,
                        cause: ConnectError::Io(error),
                    }));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.endpoint.is_none() {
            match self.source.resolve() {
                Ok(endpoint) => self.endpoint = Some(endpoint),
                Err(cause) => {
                    self.closed = true;
                    return Poll::Ready(Err(Failure {
                        original: None,
                        cause,
                    }));
                }
            }
        }
        if self.attempt.is_none()
            && let Some(endpoint) = &self.endpoint
        {
            self.attempt = Some(endpoint.attempt(self.round));
        }
        let Some(attempt) = &mut self.attempt else {
            return Poll::Ready(Err(Failure {
                original: None,
                cause: gnunet_types::Error::NotReady.into(),
            }));
        };
        match Pin::new(attempt).poll(cx) {
            Poll::Ready(Ok(connection)) => {
                self.attempt = None;
                self.closed = true;
                Poll::Ready(Ok(connection))
            }
            Poll::Ready(Err(error)) => {
                self.attempt = None;
                self.failed = Some(error);
                let Some(round) = self.round.checked_add(1) else {
                    self.closed = true;
                    return Poll::Ready(Err(Failure {
                        original: self.failed.take(),
                        cause: gnunet_types::Error::Overflow.into(),
                    }));
                };
                self.round = round;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
