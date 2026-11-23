//! Scripted write observations exercise real target retirement without socket IO.
use super::*;
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, SystemClock};
use std::{
    error::Error as StdError,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

struct Clock {
    now: AtomicU64,
    refused: AtomicBool,
}
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Fault> {
        if self.refused.load(Ordering::Acquire) {
            return Err(Fault::Deadline);
        }
        Ok(ClockSample {
            now: gnunet_types::AbsoluteTime::from_micros(self.now.load(Ordering::Acquire)),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        SystemClock.subscribe()
    }
}

#[test]
fn whole_write_checks_its_original_target_before_retiring_it() -> Result<(), Box<dyn StdError>> {
    for case in 0..5 {
        let clock = Arc::new(Clock {
            now: AtomicU64::new(1_000_000),
            refused: AtomicBool::new(false),
        });
        let original = Bounds::new(clock.as_ref(), Duration::from_secs(30))?;
        let mut session: Session<u8> = Session::new(
            EndpointSource::unix_with_clock("unused-set-write-observation".into(), clock.clone()),
            crate::encode(gnunet_wire::official::set::ClientRequest::Create { operation: 2 })?,
            Limits::default(),
            original,
        )?;
        session.epoch = Some(Epoch::new());
        session.initialized = true;
        session.initial = None;
        let bound = Bounds {
            expires: 2_000_000,
            hard: if case == 2 {
                Instant::now() - Duration::from_secs(1)
            } else {
                Instant::now() + Duration::from_secs(10)
            },
        };
        let tag = if case == 3 {
            session.initialized = false;
            session.initial = Some(bound);
            None
        } else {
            session.writes.push(Write { tag: 7, bound });
            Some(7)
        };
        match case {
            1 | 3 => clock.now.store(bound.expires, Ordering::Release),
            // Native expiry must not sample a refused Clock to recover its cause.
            2 | 4 => clock.refused.store(true, Ordering::Release),
            _ => {}
        }
        let Step::Written {
            tag: observed,
            bytes,
            complete,
            failure,
            ..
        } = session.written(framing::WriteProgress {
            origin: Origin { tag },
            bytes: 8,
            complete: true,
        })?
        else {
            return Err("write observation was replaced by another event".into());
        };
        if observed != tag || bytes != 8 || !complete || !session.writes.is_empty() {
            return Err("original complete write facts were lost".into());
        }
        if case == 0 {
            if failure.is_some() {
                return Err("timely original write failed".into());
            }
            // Caller delay cannot turn an already timely whole write into a
            // new timeout after that write's phase actually ended.
            clock.now.store(bound.expires, Ordering::Release);
            session.check()?;
        } else if case == 4 {
            if !matches!(failure, Some(Error::Clock(_))) {
                return Err("post-write Clock refusal lost its original port".into());
            }
        } else {
            let context = failure
                .as_ref()
                .and_then(Error::deadline_context)
                .ok_or("late original write lost its deadline context")?;
            let expected = if case == 3 {
                DeadlineScope::Initial
            } else {
                DeadlineScope::Write(DeadlineWrite::Operation { request_id: 7 })
            };
            if context.scope != expected
                || context.hard != bound.hard
                || context.expires != Some(bound.expires)
                || context.observed_canonical != (case != 2).then_some(bound.expires)
            {
                return Err("post-write check replaced the original target".into());
            }
        }
        if case == 3 && (!session.initialized || session.initial_bytes != 8) {
            return Err("late initializer lost its actual whole extent".into());
        }
    }
    Ok(())
}
