//! One logical target and immutable native allowance for an original transfer.
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
#[cfg(feature = "network")]
use std::future::poll_fn;
use std::{
    future::Future,
    marker::PhantomData,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

pub(crate) trait Failure: From<ProtocolError> {
    fn expired() -> Self;
}
impl Failure for ProtocolError {
    fn expired() -> Self {
        Self::Deadline
    }
}

pub(crate) struct TimeLimit<E> {
    clock: Arc<dyn RuntimeClock>,
    timer: Deadline,
    pub(crate) now: AbsoluteTime,
    target: AbsoluteTime,
    native: Option<(Instant, Option<Pin<Box<Sleep>>>)>,
    error: PhantomData<fn() -> E>,
}
impl<E: Failure> TimeLimit<E> {
    /// Copy the original native stop target without creating a new allowance.
    pub(crate) fn native_deadline(&self) -> Option<Instant> {
        self.native.as_ref().map(|(hard, _)| *hard)
    }
    pub(crate) fn new(
        clock: Arc<dyn RuntimeClock>,
        target: AbsoluteTime,
        outer: Option<Instant>,
    ) -> Result<Self, E> {
        Self::admit(clock, target, Instant::now(), outer)
    }
    pub(crate) fn admit(
        clock: Arc<dyn RuntimeClock>,
        target: AbsoluteTime,
        origin: Instant,
        outer: Option<Instant>,
    ) -> Result<Self, E> {
        if outer.is_some_and(|hard| origin >= hard) {
            return Err(E::expired());
        }
        let now = clock.sample()?.now;
        if target <= now {
            return Err(E::expired());
        }
        // A finite source-clock target also captures one native allowance.
        // Neither a stalled source nor block/MQ/sink progress can renew it.
        // FOREVER remains a caller-selected unlimited logical lifetime unless
        // an explicit outer native target was supplied.
        let hard = if target.is_never() {
            outer
        } else {
            let nominal = origin
                .checked_add(Duration::from_micros(target.as_micros() - now.as_micros()))
                .ok_or(ProtocolError::Overflow)?;
            Some(outer.map_or(nominal, |outer| nominal.min(outer)))
        };
        if hard.is_some_and(|hard| Instant::now() >= hard) {
            return Err(E::expired());
        }
        let timer = Deadline::at(clock.clone(), target)?;
        if hard.is_some_and(|hard| Instant::now() >= hard) {
            return Err(E::expired());
        }
        Ok(Self {
            clock,
            timer,
            now,
            target,
            native: hard.map(|hard| (hard, None)),
            error: PhantomData,
        })
    }
    pub(crate) fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<(), E> {
        if let Some((hard, timer)) = self.native.as_mut() {
            if Instant::now() >= *hard {
                return Err(E::expired());
            }
            let timer = timer.get_or_insert_with(|| Box::pin(tokio::time::sleep_until(*hard)));
            if timer.as_mut().poll(cx).is_ready() {
                return Err(E::expired());
            }
        }
        Ok(())
    }
    /// Check synchronous boundaries without creating a native timer or polling IO.
    pub(crate) fn check(&mut self) -> Result<(), E> {
        let elapsed = |native: &Option<(Instant, Option<Pin<Box<Sleep>>>)>| {
            native
                .as_ref()
                .is_some_and(|(hard, _)| Instant::now() >= *hard)
        };
        if elapsed(&self.native) {
            return Err(E::expired());
        }
        let now = self.clock.sample()?.now;
        if elapsed(&self.native) {
            return Err(E::expired());
        }
        if now < self.now {
            return Err(ProtocolError::TimeUncertain.into());
        }
        self.now = now;
        if now >= self.target {
            return Err(E::expired());
        }
        Ok(())
    }
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), E>> {
        self.native_guard(cx)?;
        self.check()?;
        match Pin::new(&mut self.timer).poll(cx) {
            Poll::Pending => Poll::Ready(self.native_guard(cx)),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(())) => Poll::Ready(Err(E::expired())),
        }
    }
    #[cfg(feature = "network")]
    pub(crate) async fn during<F: Future>(&mut self, future: F) -> Result<F::Output, E> {
        let mut future = std::pin::pin!(future);
        poll_fn(|cx| {
            match self.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result?,
            }
            future.as_mut().poll(cx).map(Ok)
        })
        .await
    }
    #[cfg(feature = "network")]
    pub(crate) fn remaining(&self) -> gnunet_types::Duration {
        gnunet_types::Duration(self.target.as_micros().saturating_sub(self.now.as_micros()))
    }
}

#[cfg(all(test, feature = "network"))]
mod tests;
