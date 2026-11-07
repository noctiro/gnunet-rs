use crate::Failure;
use gnunet_service_runtime::clock::{ClockSubscription, RuntimeClock};
use gnunet_types::AbsoluteTime;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
#[derive(Clone, Copy)]
pub(super) struct Due {
    pub logical: AbsoluteTime,
    pub native: Instant,
    pub name: &'static str,
}
impl Due {
    pub fn after(
        clock: &dyn RuntimeClock,
        duration: Duration,
        name: &'static str,
    ) -> Result<Self, Failure> {
        // Capture native origin before any caller clock port, never after it.
        let origin = Instant::now();
        let now = clock.sample()?.now;
        let logical = now
            .as_micros()
            .checked_add(u64::try_from(duration.as_micros())?)
            .filter(|n| *n < u64::MAX)
            .ok_or("CORE CLI logical target overflow")?;
        Ok(Self {
            logical: AbsoluteTime::from_micros(logical),
            native: origin
                .checked_add(duration)
                .ok_or("CORE CLI native target overflow")?,
            name,
        })
    }
    pub fn within(self, parent: Self) -> Self {
        Self {
            logical: self.logical.min(parent.logical),
            native: self.native.min(parent.native),
            ..self
        }
    }
}
pub(super) struct Guard {
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    alarm: Option<Pin<Box<Sleep>>>,
}
pub(super) enum Check {
    Current,
    Expired(&'static str),
}
impl Guard {
    pub fn new(clock: Arc<dyn RuntimeClock>) -> Result<Self, Failure> {
        let subscription = clock.subscribe()?;
        Ok(Self {
            clock,
            subscription,
            revision: 0,
            alarm: None,
        })
    }
    pub fn poll(&mut self, cx: &mut Context<'_>, due: &[Due]) -> Poll<Result<Check, Failure>> {
        let current = Instant::now();
        let mut hard = None;
        for d in due {
            if current >= d.native {
                return Poll::Ready(Ok(Check::Expired(d.name)));
            }
            hard = Some(hard.map_or(d.native, |old: Instant| old.min(d.native)));
        }
        let hard = hard.ok_or("CORE CLI missing original target")?;
        // Register independent original hard before clock subscription races.
        if let Some(alarm) = &mut self.alarm {
            alarm.as_mut().reset(hard)
        } else {
            self.alarm = Some(Box::pin(tokio::time::sleep_until(hard)))
        }
        if let Some(alarm) = &mut self.alarm {
            let _ready = alarm.as_mut().poll(cx);
        }
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample()?;
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Pending => {}
        }
        self.revision = sample.revision;
        let current = Instant::now();
        for d in due {
            if current >= d.native {
                return Poll::Ready(Ok(Check::Expired(d.name)));
            }
        }
        let mut next = hard;
        for d in due {
            if sample.now >= d.logical {
                return Poll::Ready(Ok(Check::Expired(d.name)));
            }
            let wake = Instant::now()
                .checked_add(Duration::from_micros(
                    d.logical.as_micros() - sample.now.as_micros(),
                ))
                .ok_or("CORE CLI alarm overflow")?;
            next = next.min(wake);
        }
        if let Some(alarm) = &mut self.alarm {
            alarm.as_mut().reset(next);
            if alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        }
        Poll::Ready(Ok(Check::Current))
    }
}
