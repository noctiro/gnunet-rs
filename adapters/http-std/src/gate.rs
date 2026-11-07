//! One original canonical/native lease; no I/O requires successful future clocks.
use crate::{Error, Fault};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub(crate) struct Gate {
    pub until: u64,
    pub hard: Instant,
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    alarm: Option<Pin<Box<Sleep>>>,
}
impl Gate {
    pub fn new(clock: Arc<dyn RuntimeClock>, until: u64) -> Result<Self, Error> {
        let native_start = Instant::now();
        let subscription = clock.subscribe().map_err(Error::Clock)?;
        let sample = clock.sample().map_err(Error::Clock)?;
        if until == u64::MAX || sample.now.as_micros() >= until {
            return Err(Fault::Deadline.into());
        }
        let hard = native_start
            .checked_add(Duration::from_micros(until - sample.now.as_micros()))
            .ok_or(Fault::Overflow)?;
        Ok(Self {
            until,
            hard,
            clock,
            subscription,
            revision: sample.revision,
            alarm: None,
        })
    }
    fn alarm(&mut self, cx: &mut Context<'_>, target: Instant) {
        if let Some(alarm) = &mut self.alarm {
            alarm.as_mut().reset(target)
        } else {
            self.alarm = Some(Box::pin(tokio::time::sleep_until(target)))
        }
        if let Some(alarm) = &mut self.alarm
            && alarm.as_mut().poll(cx).is_ready()
        {
            cx.waker().wake_by_ref()
        }
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<ClockSample, Error>> {
        if Instant::now() >= self.hard {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        // Register original native hard before a revision race can defer sampling.
        self.alarm(cx, self.hard);
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = match self.clock.sample() {
            Ok(s) => s,
            Err(e) => return Poll::Ready(Err(Error::Clock(e))),
        };
        self.revision = sample.revision;
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(Error::Clock(e))),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        if sample.now.as_micros() >= self.until {
            return Poll::Ready(Err(Fault::Deadline.into()));
        }
        let target = Instant::now()
            .checked_add(Duration::from_micros(self.until - sample.now.as_micros()))
            .ok_or(Fault::Overflow)?
            .min(self.hard);
        self.alarm(cx, target);
        Poll::Ready(Ok(sample))
    }
}

/// A single foreground yield; pending futures remain in their original owner.
pub(crate) async fn cooperate() {
    let mut yielded = false;
    std::future::poll_fn(move |cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await
}
