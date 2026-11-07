//! One HTTP/TLS IO value, one non-Clone Hyper lease, retained cleanup authority.
use crate::{Error, budget::Budget, wire::Io};
use gnunet_types::Error as Fault;
use std::{
    cell::RefCell,
    io,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};

/// Facts about the original already-connected HTTP/TLS stream. The surrounding
/// session separately owns and reports actual underlying TCP FD retirement.
#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot {
    /// Bytes actually read from this plaintext/TLS-stream API.
    pub read: u64,
    /// Bytes accepted by this plaintext/TLS-stream API, not remote delivery.
    pub accepted_write: u64,
    /// A diagnostic counter exceeded u64.
    pub counter_overflow: bool,
    /// The one non-Clone Hyper lease still exists.
    pub lease_live: bool,
    /// The actual stream shutdown method was polled.
    pub shutdown_attempted: bool,
    /// The actual stream shutdown returned success.
    pub shutdown_completed: bool,
    /// Actual shutdown returned an IO error, independently retained by Observer.
    pub shutdown_failed: bool,
    /// The first caller-supplied cleanup hard expired before shutdown completed.
    pub shutdown_timed_out: bool,
    /// The same original HTTP/TLS IO value was relinquished. This is not proof
    /// that a parent-owned TCP FD closed or a close_notify reached the peer.
    pub io_released: bool,
}
struct State {
    io: Option<Io>,
    facts: Snapshot,
    cleanup_hard: Option<Instant>,
    alarm: Option<Pin<Box<Sleep>>>,
}
#[derive(Clone)]
pub(super) struct Control(Rc<RefCell<State>>);
pub(super) struct Lease(Rc<RefCell<State>>);
impl Control {
    pub(super) fn new(io: Io) -> (Self, Lease) {
        let shared = Rc::new(RefCell::new(State {
            io: Some(io),
            facts: Snapshot {
                lease_live: true,
                ..Snapshot::default()
            },
            cleanup_hard: None,
            alarm: None,
        }));
        (Self(shared.clone()), Lease(shared))
    }
    pub(super) fn snapshot(&self) -> Result<Snapshot, Error> {
        Ok(self.0.try_borrow().map_err(|_| Fault::Conflict)?.facts)
    }
    fn finish(state: &mut State, cx: &mut Context<'_>) -> Poll<Result<Snapshot, Error>> {
        if state.facts.lease_live {
            return Poll::Ready(Err(Fault::Conflict.into()));
        }
        if state.io.is_none() {
            return Poll::Ready(Ok(state.facts));
        }
        if state.facts.shutdown_completed {
            drop(state.io.take());
            state.facts.io_released = true;
            return Poll::Ready(Ok(state.facts));
        }
        state.facts.shutdown_attempted = true;
        let result = Pin::new(state.io.as_mut().ok_or(Fault::Closed)?.as_mut()).poll_shutdown(cx);
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                state.facts.shutdown_completed = result.is_ok();
                state.facts.shutdown_failed = result.is_err();
                drop(state.io.take());
                state.facts.io_released = true;
                Poll::Ready(result.map(|()| state.facts).map_err(Error::Io))
            }
        }
    }
    pub(super) fn poll_normal(
        &self,
        cx: &mut Context<'_>,
        budget: &Budget,
    ) -> Poll<Result<Snapshot, Error>> {
        budget.check()?;
        let mut state = self.0.try_borrow_mut().map_err(|_| Fault::Conflict)?;
        Self::finish(&mut state, cx)
    }
    /// Closing only: no source-clock sample or business admission. The first
    /// cleanup target is captured once; a later call can only shorten it.
    pub(super) fn poll_retire(
        &self,
        cx: &mut Context<'_>,
        hard: Instant,
    ) -> Poll<Result<Snapshot, Error>> {
        let mut state = self.0.try_borrow_mut().map_err(|_| Fault::Conflict)?;
        if state.io.is_none() {
            return Poll::Ready(Ok(state.facts));
        }
        let target = state.cleanup_hard.map_or(hard, |old| old.min(hard));
        if state.cleanup_hard != Some(target) {
            state.cleanup_hard = Some(target);
            state.alarm = Some(Box::pin(tokio::time::sleep_until(target)));
        }
        if state.facts.lease_live {
            return Poll::Ready(Err(Fault::Conflict.into()));
        }
        if state.io.is_none() {
            return Poll::Ready(Ok(state.facts));
        }
        if state.facts.shutdown_completed {
            drop(state.io.take());
            state.facts.io_released = true;
            return Poll::Ready(Ok(state.facts));
        }
        if Instant::now() >= target
            || state
                .alarm
                .as_mut()
                .is_some_and(|timer| std::future::Future::poll(timer.as_mut(), cx).is_ready())
        {
            state.facts.shutdown_timed_out = !state.facts.shutdown_completed;
            drop(state.io.take());
            state.facts.io_released = true;
            return Poll::Ready(Err(Error::Deadline));
        }
        Self::finish(&mut state, cx)
    }
}
fn unavailable() -> io::Error {
    io::Error::other("GNS proxy original HTTP stream unavailable")
}
fn count(value: &mut u64, overflow: &mut bool, bytes: usize) {
    match u64::try_from(bytes).ok().and_then(|n| value.checked_add(n)) {
        Some(next) => *value = next,
        None => {
            *value = u64::MAX;
            *overflow = true;
        }
    }
}
impl AsyncRead for Lease {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut state = self.0.try_borrow_mut().map_err(|_| unavailable())?;
        let before = buffer.filled().len();
        let result =
            Pin::new(state.io.as_mut().ok_or_else(unavailable)?.as_mut()).poll_read(cx, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) {
            let facts = &mut state.facts;
            count(
                &mut facts.read,
                &mut facts.counter_overflow,
                buffer.filled().len().saturating_sub(before),
            );
        }
        result
    }
}
impl AsyncWrite for Lease {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.0.try_borrow_mut().map_err(|_| unavailable())?;
        let result =
            Pin::new(state.io.as_mut().ok_or_else(unavailable)?.as_mut()).poll_write(cx, bytes);
        if let Poll::Ready(Ok(n)) = &result {
            let facts = &mut state.facts;
            count(&mut facts.accepted_write, &mut facts.counter_overflow, *n);
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.try_borrow_mut().map_err(|_| unavailable())?;
        Pin::new(state.io.as_mut().ok_or_else(unavailable)?.as_mut()).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.0.try_borrow_mut().map_err(|_| unavailable())?;
        state.facts.shutdown_attempted = true;
        let result =
            Pin::new(state.io.as_mut().ok_or_else(unavailable)?.as_mut()).poll_shutdown(cx);
        if let Poll::Ready(result) = &result {
            state.facts.shutdown_completed = result.is_ok();
            state.facts.shutdown_failed = result.is_err();
        }
        result
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.try_borrow_mut() {
            state.facts.lease_live = false;
        }
    }
}
