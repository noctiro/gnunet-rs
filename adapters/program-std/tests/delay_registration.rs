//! Actual public PROGRAM registration semantics, no C execution or network.
#![cfg(feature = "runtime")]
#[cfg(test)]
mod tests {
    use gnunet_program_host::{
        runtime::{Delay, Scope, run_tasks_fallible},
        shared_clock::{SharedClock, WallClock},
    };
    use gnunet_types::{AbsoluteTime, Error, RelativeTime};
    use std::{
        future::Future,
        pin::pin,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicU64, Ordering},
        },
        task::{Context, Poll, Waker},
    };
    struct Wall(AtomicU64, AtomicBool);
    impl WallClock for Wall {
        fn wall_us(&self) -> Result<u64, Error> {
            if self.1.load(Ordering::SeqCst) {
                Err(Error::Io)
            } else {
                Ok(self.0.load(Ordering::SeqCst))
            }
        }
    }
    fn runtime() -> Result<tokio::runtime::Runtime, Error> {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|_| Error::Io)
    }
    fn escape(
        clock: SharedClock,
        make: impl FnOnce(Scope<'_>) -> Result<Delay, Error>,
    ) -> Result<Delay, Error> {
        let mut delay = None;
        let mut outcome = None;
        {
            let mut run = pin!(run_tasks_fallible::<Error>(clock, 0, |scope| {
                delay = Some(make(scope)?);
                Ok(())
            }));
            let mut cx = Context::from_waker(Waker::noop());
            if let Poll::Ready(result) = run.as_mut().poll(&mut cx) {
                outcome = Some(result);
            }
        }
        outcome.ok_or(Error::WouldBlock)??;
        delay.ok_or(Error::NotReady)
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Due-at-registration ready admission must survive a rollback before first poll"
    )]
    fn exact_and_past_absolute_registered_ready_tasks_remain_ready_after_rollback()
    -> Result<(), Error> {
        let rt = runtime()?;
        let _entered = rt.enter();
        for target in [999, 1000] {
            let clock = SharedClock::new(
                2,
                Arc::new(Wall(AtomicU64::new(1000), AtomicBool::new(false))),
            )?;
            let delay = escape(clock.clone(), |s| {
                s.delay_until(AbsoluteTime::from_micros(target))
            })?;
            clock.set_offset(-500)?;
            let mut delay = pin!(delay);
            assert_eq!(
                delay.as_mut().poll(&mut Context::from_waker(Waker::noop())),
                Poll::Ready(Ok(()))
            );
            assert_eq!(clock.listeners()?, 0);
        }
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Relative zero is queued ready when registered, without changing the original absolute target"
    )]
    fn relative_zero_registration_is_ready_across_backwards_adjustment() -> Result<(), Error> {
        let rt = runtime()?;
        let _entered = rt.enter();
        let clock = SharedClock::new(
            2,
            Arc::new(Wall(AtomicU64::new(1000), AtomicBool::new(false))),
        )?;
        let delay = escape(clock.clone(), |s| s.delay(RelativeTime::ZERO))?;
        clock.set_offset(-500)?;
        assert_eq!(
            pin!(delay)
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        );
        Ok(())
    }
    #[test]
    fn relative_zero_uses_one_coherent_registration_sample() -> Result<(), Error> {
        struct RegressingWall(AtomicU64);
        impl WallClock for RegressingWall {
            fn wall_us(&self) -> Result<u64, Error> {
                Ok(if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    1000
                } else {
                    500
                })
            }
        }
        let rt = runtime()?;
        let _entered = rt.enter();
        let wall = Arc::new(RegressingWall(AtomicU64::new(0)));
        let clock = SharedClock::new(2, wall.clone())?;
        let delay = escape(clock.clone(), |scope| {
            wall.0.store(0, Ordering::SeqCst);
            let delay = scope.delay(RelativeTime::ZERO)?;
            if wall.0.load(Ordering::SeqCst) != 1 {
                return Err(Error::InvalidInput);
            }
            Ok(delay)
        })?;
        if clock.sample()?.now != AbsoluteTime::from_micros(500) {
            return Err(Error::InvalidInput);
        }
        let mut delay = pin!(delay);
        if delay.as_mut().poll(&mut Context::from_waker(Waker::noop())) != Poll::Ready(Ok(())) {
            return Err(Error::InvalidInput);
        }
        if clock.listeners()? != 0 {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "A future deadline not ready at registration must retain its original logical target"
    )]
    fn not_yet_due_at_registration_is_not_promoted_to_ready_by_rollback() -> Result<(), Error> {
        let rt = runtime()?;
        let _entered = rt.enter();
        let clock = SharedClock::new(
            2,
            Arc::new(Wall(AtomicU64::new(1000), AtomicBool::new(false))),
        )?;
        let delay = escape(clock.clone(), |s| {
            s.delay_until(AbsoluteTime::from_micros(1500))
        })?;
        clock.set_offset(-500)?;
        let mut delay = pin!(delay);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(delay.as_mut().poll(&mut cx).is_pending());
        clock.set_offset(499)?;
        assert!(delay.as_mut().poll(&mut cx).is_pending());
        clock.set_offset(500)?;
        assert_eq!(delay.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Explicit never target remains pending when sampled logical now equals MAX"
    )]
    fn never_is_not_queued_ready_at_max_and_finite_max_minus_one_can_be_ready() -> Result<(), Error>
    {
        let rt = runtime()?;
        let _entered = rt.enter();
        let wall = Arc::new(Wall(AtomicU64::new(u64::MAX), AtomicBool::new(false)));
        let clock = SharedClock::new(2, wall)?;
        let delay = escape(clock.clone(), |s| s.delay_until(AbsoluteTime::NEVER))?;
        assert!(
            pin!(delay)
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        let finite = escape(clock, |s| {
            s.delay_until(AbsoluteTime::from_micros(u64::MAX - 1))
        })?;
        assert_eq!(
            pin!(finite)
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        );
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Failed registration clock sample atomically drops the just-reserved timer slot"
    )]
    fn finite_registration_sample_failure_returns_exact_error_without_listener_leak()
    -> Result<(), Error> {
        let rt = runtime()?;
        let _entered = rt.enter();
        let wall = Arc::new(Wall(AtomicU64::new(1000), AtomicBool::new(false)));
        let clock = SharedClock::new(2, wall.clone())?;
        let result = escape(clock.clone(), |s| {
            wall.1.store(true, Ordering::SeqCst);
            s.delay_until(AbsoluteTime::from_micros(1500))
        });
        assert!(matches!(result, Err(Error::Io)));
        assert_eq!(clock.listeners()?, 0);
        Ok(())
    }
}
