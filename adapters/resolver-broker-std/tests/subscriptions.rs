//! Distinct canonical waiter ownership in the integrated Broker/CLIENT graph.
#[path = "../../ipc-unix/tests/support/clock_source.rs"]
pub mod clock_source;
#[cfg(test)]
mod tests {
    use super::clock_source::Adjustable as SharedClock;
    use gnunet_config::Configuration;
    use gnunet_resolver_broker::{BrokerError, FamilyProfile, Limits, LiveConfiguration, broker};
    use gnunet_types::Error;
    use std::{
        future::Future,
        io,
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
        time::Duration,
    };
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn waker() -> (Arc<Count>, Waker) {
        let c = Arc::new(Count(AtomicUsize::new(0)));
        let w = Waker::from(c.clone());
        (c, w)
    }
    fn runtime() -> io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
    }
    fn clock(n: usize) -> Result<SharedClock, Error> {
        SharedClock::frozen(100_000_000, n)
    }
    fn broker_for(
        clock: &SharedClock,
    ) -> Result<
        (
            gnunet_resolver_broker::Context<2, 64>,
            gnunet_resolver_broker::Driver<2, 64>,
        ),
        BrokerError,
    > {
        broker::<2, 64>(
            LiveConfiguration::new(Configuration::default()),
            Limits::default(),
            FamilyProfile::new(2, 30)?,
            Arc::new(clock.clone()),
        )
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Actual public owner independent waker assertions"
    )]
    fn actual_driver_and_two_provider_timers_all_wake_across_both_poll_orders()
    -> Result<(), Box<dyn std::error::Error>> {
        let rt = runtime()?;
        let _entered = rt.enter();
        let clock = clock(3)?;
        let (ctx, mut driver) = broker_for(&clock)?;
        let resolution = ctx.resolution_context();
        let mut first = resolution.timer(Duration::from_secs(30))?;
        let mut second = resolution.timer(Duration::from_secs(30))?;
        let (a, wa) = waker();
        let (b, wb) = waker();
        let (c, wc) = waker();
        let mut ca = Context::from_waker(&wa);
        let mut cb = Context::from_waker(&wb);
        let mut cc = Context::from_waker(&wc);
        let mut wait = pin!(driver.drive_waiting(None, |_| {}));
        assert!(wait.as_mut().poll(&mut ca).is_pending());
        assert!(first.as_mut().poll(&mut cb).is_pending());
        assert!(second.as_mut().poll(&mut cc).is_pending());
        clock.set_offset(1)?;
        assert_eq!(
            [
                a.0.load(Ordering::SeqCst),
                b.0.load(Ordering::SeqCst),
                c.0.load(Ordering::SeqCst)
            ],
            [1, 1, 1]
        );
        assert!(second.as_mut().poll(&mut cc).is_pending());
        assert!(first.as_mut().poll(&mut cb).is_pending());
        assert!(wait.as_mut().poll(&mut ca).is_pending());
        clock.set_offset(-1)?;
        assert_eq!(
            [
                a.0.load(Ordering::SeqCst),
                b.0.load(Ordering::SeqCst),
                c.0.load(Ordering::SeqCst)
            ],
            [2, 2, 2]
        );
        assert_eq!(clock.listeners()?, 3);
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Fallible bounded timer admission and exact credit release assertions"
    )]
    fn timer_capacity_fails_atomically_then_drop_and_completion_each_return_only_their_credit()
    -> Result<(), Box<dyn std::error::Error>> {
        let rt = runtime()?;
        let _entered = rt.enter();
        let clock = clock(2)?;
        let (ctx, driver) = broker_for(&clock)?;
        let resolution = ctx.resolution_context();
        let timer = resolution.timer(Duration::from_secs(30))?;
        assert_eq!(clock.listeners()?, 2);
        let error = match resolution.timer(Duration::ZERO) {
            Err(e) => e,
            Ok(_) => return Err("capacity was silently ignored".into()),
        };
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
        assert_eq!(clock.listeners()?, 2);
        assert_eq!(ctx.pending_requests()?, 0);
        drop(timer);
        assert_eq!(clock.listeners()?, 1);
        let mut done = resolution.timer(Duration::ZERO)?;
        let (_, w) = waker();
        assert!(matches!(
            done.as_mut().poll(&mut Context::from_waker(&w)),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(clock.listeners()?, 1);
        // A completed Future retained by its caller does not retain listener credit.
        let replacement = resolution.timer(Duration::MAX)?;
        assert_eq!(clock.listeners()?, 2);
        drop(done);
        assert_eq!(clock.listeners()?, 2);
        drop(driver);
        assert_eq!(clock.listeners()?, 1);
        drop(replacement);
        assert_eq!(clock.listeners()?, 0);
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Failed constructor must not create a partially observable broker owner"
    )]
    fn broker_requires_its_own_subscription_before_returning_any_owner() -> Result<(), Error> {
        let clock = clock(0)?;
        assert!(matches!(
            broker_for(&clock),
            Err(BrokerError::Core(Error::Capacity))
        ));
        assert_eq!(clock.listeners()?, 0);
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Retirement and slot reuse cannot wake a retired owner"
    )]
    fn dropping_driver_drops_its_stored_waker_while_retained_context_and_timer_keep_same_source()
    -> Result<(), Box<dyn std::error::Error>> {
        let rt = runtime()?;
        let _entered = rt.enter();
        let clock = clock(2)?;
        let (ctx, mut driver) = broker_for(&clock)?;
        let resolution = ctx.resolution_context();
        let mut timer = resolution.timer(Duration::from_secs(30))?;
        let (a, wa) = waker();
        let (b, wb) = waker();
        {
            let mut wait = pin!(driver.drive_waiting(None, |_| {}));
            assert!(
                wait.as_mut()
                    .poll(&mut Context::from_waker(&wa))
                    .is_pending()
            );
        }
        assert!(
            timer
                .as_mut()
                .poll(&mut Context::from_waker(&wb))
                .is_pending()
        );
        drop(wa);
        drop(driver);
        assert_eq!(Arc::strong_count(&a), 1);
        assert_eq!(clock.listeners()?, 1);
        let mut replacement = resolution.timer(Duration::from_secs(30))?;
        let (c, wc) = waker();
        assert!(
            replacement
                .as_mut()
                .poll(&mut Context::from_waker(&wc))
                .is_pending()
        );
        clock.set_offset(5)?;
        assert_eq!(
            [
                a.0.load(Ordering::SeqCst),
                b.0.load(Ordering::SeqCst),
                c.0.load(Ordering::SeqCst)
            ],
            [0, 1, 1]
        );
        drop(ctx);
        drop(timer);
        drop(replacement);
        assert_eq!(clock.listeners()?, 0);
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Canceling one drive Future must retain the driver's one listener and replace its own waker"
    )]
    fn canceled_drive_future_preserves_original_driver_subscription_and_new_wait_replaces_only_its_waker()
    -> Result<(), Box<dyn std::error::Error>> {
        let rt = runtime()?;
        let _entered = rt.enter();
        let clock = clock(1)?;
        let (_ctx, mut driver) = broker_for(&clock)?;
        let (a, wa) = waker();
        let (b, wb) = waker();
        {
            let mut old = pin!(driver.drive_waiting(None, |_| {}));
            assert!(
                old.as_mut()
                    .poll(&mut Context::from_waker(&wa))
                    .is_pending()
            );
        }
        assert_eq!(clock.listeners()?, 1);
        {
            let mut new = pin!(driver.drive_waiting(None, |_| {}));
            assert!(
                new.as_mut()
                    .poll(&mut Context::from_waker(&wb))
                    .is_pending()
            );
            clock.set_offset(1)?;
            assert_eq!(
                [a.0.load(Ordering::SeqCst), b.0.load(Ordering::SeqCst)],
                [0, 1]
            );
        }
        drop(driver);
        assert_eq!(clock.listeners()?, 0);
        Ok(())
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "An actual Provider timer source error must return its waiter credit without timeout success"
)]
fn provider_timer_poll_source_error_releases_only_original_waiter_even_if_future_is_retained()
-> Result<(), Box<dyn std::error::Error>> {
    use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
    use gnunet_types::Error;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::Context,
    };
    struct Source {
        clock: clock_source::Adjustable,
        failed: AtomicBool,
    }
    impl RuntimeClock for Source {
        fn sample(&self) -> Result<ClockSample, Error> {
            if self.failed.load(Ordering::SeqCst) {
                Err(Error::Io)
            } else {
                self.clock.sample()
            }
        }
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
            self.clock.subscribe()
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let _entered = runtime.enter();
    let source = Arc::new(Source {
        clock: clock_source::Adjustable::frozen(1_000_000, 2)?,
        failed: AtomicBool::new(false),
    });
    let (context, driver) = gnunet_resolver_broker::broker::<2, 64>(
        gnunet_resolver_broker::LiveConfiguration::new(gnunet_config::Configuration::default()),
        Default::default(),
        gnunet_resolver_broker::FamilyProfile::new(2, 30)?,
        source.clone(),
    )?;
    let mut timer = context
        .resolution_context()
        .timer(std::time::Duration::from_secs(30))?;
    assert_eq!(source.clock.listeners()?, 2);
    source.failed.store(true, Ordering::SeqCst);
    let wake = std::task::Waker::noop();
    assert!(matches!(
        timer.as_mut().poll(&mut Context::from_waker(wake)),
        std::task::Poll::Ready(Err(_))
    ));
    assert_eq!(source.clock.listeners()?, 1);
    source.failed.store(false, Ordering::SeqCst);
    let replacement = context
        .resolution_context()
        .timer(std::time::Duration::MAX)?;
    assert_eq!(source.clock.listeners()?, 2);
    drop(timer);
    assert_eq!(source.clock.listeners()?, 2);
    drop(driver);
    assert_eq!(source.clock.listeners()?, 1);
    drop(replacement);
    assert_eq!(source.clock.listeners()?, 0);
    Ok(())
}
