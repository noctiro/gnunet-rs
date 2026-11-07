//! One bounded retained stdout result, with actual cursor and flush failure.
//! Inherited descriptor flags are unchanged. Synchronous calls are not preemptible.
use crate::run::Failure;
use gnunet_scalarproduct_client_host::Bounds;
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    future::Future,
    io::{self, Write},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::time::Sleep;
#[derive(Debug)]
struct OutputFailure {
    original: Failure,
    accepted: usize,
    total: usize,
    phase: &'static str,
}
impl std::fmt::Display for OutputFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SCALARPRODUCT stdout {} failed after {}/{} bytes accepted: {}",
            self.phase, self.accepted, self.total, self.original
        )
    }
}
impl std::error::Error for OutputFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}
pub(super) struct Output {
    stdout: io::Stdout,
    bytes: Vec<u8>,
    at: usize,
    hard: Option<Instant>,
    wait: Option<Pin<Box<Sleep>>>,
    timeout: Duration,
    max: usize,
    original: Bounds,
    clock: Arc<dyn RuntimeClock>,
}
impl Output {
    pub(super) fn new(
        timeout: Duration,
        max: usize,
        original: Bounds,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, Failure> {
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            return Err("invalid SCALARPRODUCT output timeout".into());
        }
        Ok(Self {
            stdout: io::stdout(),
            bytes: Vec::new(),
            at: 0,
            hard: None,
            wait: None,
            timeout,
            max,
            original,
            clock,
        })
    }
    pub(super) fn pending(&self) -> bool {
        self.hard.is_some()
    }
    fn check(&self) -> Result<(), Failure> {
        if Instant::now() >= self.original.hard || self.hard.is_some_and(|h| Instant::now() >= h) {
            return Err("SCALARPRODUCT original stdout/native deadline expired".into());
        }
        let now = self.clock.sample()?.now.as_micros();
        if Instant::now() >= self.original.hard
            || now >= self.original.expires
            || self.hard.is_some_and(|h| Instant::now() >= h)
        {
            return Err("SCALARPRODUCT original stdout/canonical deadline expired".into());
        }
        Ok(())
    }
    pub(super) fn admit(&mut self, bytes: Vec<u8>) -> Result<(), Failure> {
        if self.pending() {
            return Err("original SCALARPRODUCT stdout is still pending".into());
        }
        self.check()?;
        if bytes.len() > self.max || bytes.capacity() > self.max {
            return Err("SCALARPRODUCT stdout exceeds its retained byte budget".into());
        }
        self.bytes = bytes;
        self.at = 0;
        self.hard = Some(
            Instant::now()
                .checked_add(self.timeout)
                .ok_or("SCALARPRODUCT stdout deadline overflow")?
                .min(self.original.hard),
        );
        Ok(())
    }
    fn failure(&self, original: Failure, phase: &'static str) -> Failure {
        Box::new(OutputFailure {
            original,
            accepted: self.at,
            total: self.bytes.len(),
            phase,
        })
    }
    fn delay(&mut self) {
        let hard = self.hard.unwrap_or(self.original.hard);
        let until = Instant::now()
            .checked_add(Duration::from_millis(10))
            .unwrap_or(hard)
            .min(hard);
        self.wait = Some(Box::pin(tokio::time::sleep_until(until.into())));
    }
    /// One bounded synchronous write/flush attempt. Actual late return becomes
    /// failure even when bytes escaped; no deadline is claimed to preempt stdio.
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Failure>> {
        if !self.pending() {
            return Poll::Pending;
        }
        if let Err(e) = self.check() {
            return Poll::Ready(Err(self.failure(e, "guard")));
        }
        if let Some(wait) = &mut self.wait {
            if wait.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.wait = None;
        }
        if self.at < self.bytes.len() {
            let until = self.at.saturating_add(512).min(self.bytes.len());
            match self.stdout.write(&self.bytes[self.at..until]) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    self.delay();
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => return Poll::Ready(Ok(false)),
                Err(e) => return Poll::Ready(Err(self.failure(Box::new(e), "write"))),
                Ok(0) => {
                    return Poll::Ready(Err(
                        self.failure(Box::new(io::Error::from(io::ErrorKind::WriteZero)), "write")
                    ));
                }
                Ok(n) => {
                    self.at = match self.at.checked_add(n).filter(|n| *n <= until) {
                        Some(n) => n,
                        None => {
                            return Poll::Ready(Err(
                                self.failure("invalid actual stdout byte count".into(), "write")
                            ));
                        }
                    };
                    if let Err(e) = self.check() {
                        return Poll::Ready(Err(self.failure(e, "post-write guard")));
                    }
                }
            }
        }
        if self.at < self.bytes.len() {
            return Poll::Ready(Ok(false));
        }
        match self.stdout.flush() {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.delay();
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => return Poll::Ready(Ok(false)),
            Err(e) => return Poll::Ready(Err(self.failure(Box::new(e), "flush"))),
            Ok(()) => {}
        }
        if let Err(e) = self.check() {
            return Poll::Ready(Err(self.failure(e, "post-flush guard")));
        }
        self.hard = None;
        self.wait = None;
        self.bytes.clear();
        self.at = 0;
        Poll::Ready(Ok(true))
    }
    /// Preserve an unfinished original result on any other failure, without
    /// writing or flushing more bytes after that source/cancellation decision.
    pub(super) fn abandoned(&self) -> Option<Failure> {
        self.pending().then(|| {
            self.failure(
                "original output abandoned without extra IO".into(),
                "retirement",
            )
        })
    }
}
