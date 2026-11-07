//! One pure scheduling model. No key construction, derivation/hash/signature,
//! native/socket/store/service/Resolver/crypto operation is executed here.
use crate::{
    clock::{DriverClock, Span},
    io::original_write_head,
};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
use gnunet_types::Error;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
#[derive(Default)]
struct Churn(Arc<AtomicU64>);
struct Changes(Arc<AtomicU64>);
impl RuntimeClock for Churn {
    fn sample(&self) -> Result<ClockSample, Error> {
        Ok(ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(1),
            revision: self.0.fetch_add(1, Ordering::Relaxed),
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        Ok(Box::new(Changes(self.0.clone())))
    }
}
impl ClockSubscription for Changes {
    fn poll_changed(&mut self, _: &mut Context<'_>, _: u64) -> Poll<Result<ClockSample, Error>> {
        Poll::Ready(Ok(ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(1),
            revision: self.0.fetch_add(1, Ordering::Relaxed),
        }))
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Public scheduling assertions with fallible timer setup"
)]
fn original_fifo_and_clock_race() -> Result<(), Box<dyn std::error::Error>> {
    // Original higher job order differs from actual native admission order.
    let rows = [(0, Some(2), true), (1, Some(1), true), (2, None, false)];
    assert_eq!(original_write_head(rows.into_iter()), Some(1));
    let drained = [(0, Some(2), true), (1, Some(1), false)];
    assert_eq!(original_write_head(drained.into_iter()), Some(0));
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?
        .block_on(async {
            let mut clock = DriverClock::new(Arc::new(Churn::default()))?;
            let span = Span::new(1, Duration::from_millis(1))?;
            {
                let mut cx = Context::from_waker(Waker::noop());
                let _registered = clock.poll_native(&mut cx, Some(span.hard));
                assert!(clock.poll_now(&mut cx).is_pending());
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
            {
                let mut cx = Context::from_waker(Waker::noop());
                assert!(clock.poll_native(&mut cx, Some(span.hard)));
                assert!(span.expired(None));
                assert!(clock.poll_now(&mut cx).is_pending());
            }
            Ok::<_, Error>(())
        })?;
    Ok(())
}
