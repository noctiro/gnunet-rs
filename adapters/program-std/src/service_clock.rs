//! Shared logical clock adaptation for native services, independent of Resolver.
//! Every driver retains its own bounded subscription to the original clock.
use crate::shared_clock::{SharedClock, Subscription};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
use gnunet_types::Error;
use std::task::{Context, Poll};

impl RuntimeClock for SharedClock {
    fn sample(&self) -> Result<ClockSample, Error> {
        let sample = SharedClock::sample(self)?;
        Ok(ClockSample {
            now: sample.now,
            revision: sample.revision,
        })
    }

    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        Ok(Box::new(SharedClock::subscribe(self)?))
    }
}

impl ClockSubscription for Subscription {
    fn poll_changed(
        &mut self,
        cx: &mut Context<'_>,
        observed: u64,
    ) -> Poll<Result<ClockSample, Error>> {
        Subscription::poll_changed(self, cx, observed).map(|result| {
            result.map(|sample| ClockSample {
                now: sample.now,
                revision: sample.revision,
            })
        })
    }
}
