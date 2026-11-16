//! Original deadlines remain authoritative across source callbacks and wake races.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Regression assertions distinguish native expiry, source failure and original wake ownership"
)]
use super::*;
use gnunet_types::Error as Fault;
use std::{
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    task::Wake,
};

const SOURCE_DELAY: Duration = Duration::from_millis(100);
const HARD_LIFETIME: Duration = Duration::from_millis(50);

#[derive(Default)]
struct State {
    canonical: AtomicU64,
    revision: AtomicU64,
    samples: AtomicUsize,
    polls: AtomicUsize,
    active: AtomicUsize,
    slow_sample: AtomicBool,
    slow_subscribe: AtomicBool,
    slow_poll: AtomicUsize,
    failed_poll: AtomicUsize,
    changed_poll: AtomicUsize,
}
struct Clock(Arc<State>);
impl Clock {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(State::default())))
    }
    fn sample_now(&self) -> ClockSample {
        ClockSample {
            now: AbsoluteTime::from_micros(self.0.canonical.load(Ordering::SeqCst)),
            revision: self.0.revision.load(Ordering::SeqCst),
        }
    }
}
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Fault> {
        self.0.samples.fetch_add(1, Ordering::SeqCst);
        if self.0.slow_sample.load(Ordering::SeqCst) {
            std::thread::sleep(SOURCE_DELAY);
        }
        Ok(self.sample_now())
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        if self.0.slow_subscribe.load(Ordering::SeqCst) {
            std::thread::sleep(SOURCE_DELAY);
        }
        self.0.active.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Subscription(self.0.clone())))
    }
}
struct Subscription(Arc<State>);
impl Drop for Subscription {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}
impl ClockSubscription for Subscription {
    fn poll_changed(
        &mut self,
        _: &mut Context<'_>,
        observed: u64,
    ) -> Poll<Result<ClockSample, Fault>> {
        let turn = self.0.polls.fetch_add(1, Ordering::SeqCst) + 1;
        if turn == self.0.slow_poll.load(Ordering::SeqCst) {
            std::thread::sleep(SOURCE_DELAY);
        }
        if turn == self.0.failed_poll.load(Ordering::SeqCst) {
            return Poll::Ready(Err(Fault::TimeUncertain));
        }
        if turn == self.0.changed_poll.load(Ordering::SeqCst) {
            self.0.revision.fetch_add(1, Ordering::SeqCst);
        }
        let revision = self.0.revision.load(Ordering::SeqCst);
        if revision != observed {
            Poll::Ready(Ok(ClockSample {
                now: AbsoluteTime::from_micros(self.0.canonical.load(Ordering::SeqCst)),
                revision,
            }))
        } else {
            Poll::Pending
        }
    }
}
#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_expiry_is_rechecked_after_each_source_callback() -> Result<(), BoundsError> {
    for boundary in 0..3 {
        let clock = Clock::new();
        let bounds = Bounds::from_targets(
            AbsoluteTime::from_micros(1_000_000),
            Instant::now() + HARD_LIFETIME,
        )?;
        let mut guard = DeadlineGuard::new(clock.clone(), bounds)?;
        if boundary == 0 {
            clock.0.slow_sample.store(true, Ordering::SeqCst);
        } else {
            clock.0.slow_poll.store(boundary, Ordering::SeqCst);
        }
        let result = guard.poll(&mut Context::from_waker(Waker::noop()));
        assert!(
            matches!(result, Poll::Ready(Err(BoundsError::Deadline))),
            "callback boundary {boundary} granted an expired turn: {result:?}"
        );
        assert_eq!(
            clock.0.samples.load(Ordering::SeqCst),
            if boundary == 1 { 1 } else { 2 },
            "an expired native bound must prevent the next source call"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn subscription_failure_remains_the_cause_when_its_callback_crosses_expiry()
-> Result<(), BoundsError> {
    let clock = Clock::new();
    let bounds = Bounds::from_targets(
        AbsoluteTime::from_micros(1_000_000),
        Instant::now() + HARD_LIFETIME,
    )?;
    let mut guard = DeadlineGuard::new(clock.clone(), bounds)?;
    clock.0.slow_poll.store(2, Ordering::SeqCst);
    clock.0.failed_poll.store(2, Ordering::SeqCst);
    assert!(
        matches!(
            guard.poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(BoundsError::Clock(Fault::TimeUncertain)))
        ),
        "the post-sample subscription's source failure must not become expiry"
    );
    assert!(Instant::now() >= bounds.hard());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn revision_race_retains_a_registered_native_alarm() -> Result<(), BoundsError> {
    let clock = Clock::new();
    let hard = Instant::now() + HARD_LIFETIME;
    let bounds = Bounds::from_targets(AbsoluteTime::from_micros(1_000_000), hard)?;
    let mut guard = DeadlineGuard::new(clock.clone(), bounds)?;
    clock.0.changed_poll.store(2, Ordering::SeqCst);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    assert!(guard.poll(&mut Context::from_waker(&waker)).is_pending());
    assert!(
        guard.alarm.is_some(),
        "a source revision race needs its native alarm first"
    );
    wakes.0.store(0, Ordering::SeqCst);
    tokio::time::sleep_until(hard + Duration::from_millis(5)).await;
    assert!(
        wakes.0.load(Ordering::SeqCst) > 0,
        "the original native alarm must wake even while source revisions defer progress"
    );
    assert!(matches!(
        guard.poll(&mut Context::from_waker(&waker)),
        Poll::Ready(Err(BoundsError::Deadline))
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn tightening_wakes_only_the_current_owner_and_preserves_earlier_alarm()
-> Result<(), BoundsError> {
    let clock = Clock::new();
    let hard = Instant::now() + Duration::from_secs(10);
    let until = 1_000_000;
    let bounds = Bounds::from_targets(AbsoluteTime::from_micros(until), hard)?;
    let mut guard = DeadlineGuard::new(clock.clone(), bounds)?;
    clock.0.canonical.store(until - 500_000, Ordering::SeqCst);
    let old = Arc::new(Wakes::default());
    let old_waker = Waker::from(old.clone());
    assert!(matches!(
        guard.poll(&mut Context::from_waker(&old_waker)),
        Poll::Ready(Ok(_))
    ));
    let current = Arc::new(Wakes::default());
    let current_waker = Waker::from(current.clone());
    assert!(matches!(
        guard.poll(&mut Context::from_waker(&current_waker)),
        Poll::Ready(Ok(_))
    ));
    let original_alarm = guard.alarm.as_ref().map(|alarm| alarm.deadline());
    guard.tighten(until - 1, hard);
    assert_eq!(
        current.0.load(Ordering::SeqCst),
        1,
        "canonical-only tightening must wake"
    );
    assert_eq!(
        old.0.load(Ordering::SeqCst),
        0,
        "a replaced waker must not be retained"
    );
    assert_eq!(
        guard.alarm.as_ref().map(|alarm| alarm.deadline()),
        original_alarm,
        "tightening cannot postpone an earlier canonical alarm"
    );
    current.0.store(0, Ordering::SeqCst);
    guard.tighten(u64::MAX, hard + Duration::from_secs(1));
    assert_eq!(
        current.0.load(Ordering::SeqCst),
        0,
        "a widening request changes no limit"
    );
    assert_eq!(guard.bounds().expires(), until - 1);
    let tighter_hard = Instant::now() + Duration::from_millis(100);
    guard.tighten(u64::MAX, tighter_hard);
    assert_eq!(
        guard.alarm.as_ref().map(|alarm| alarm.deadline()),
        Some(tighter_hard)
    );
    assert_eq!(
        current.0.load(Ordering::SeqCst),
        1,
        "native tightening must wake"
    );
    drop(guard);
    assert_eq!(
        clock.0.active.load(Ordering::SeqCst),
        0,
        "drop releases the sole subscription"
    );
    Ok(())
}

#[test]
fn failed_waiter_admission_releases_its_subscription_and_rejects_infinite_targets()
-> Result<(), BoundsError> {
    let hard = Instant::now() + HARD_LIFETIME;
    assert!(matches!(
        Bounds::from_targets(AbsoluteTime::NEVER, hard),
        Err(BoundsError::Overflow)
    ));
    let clock = Clock::new();
    let bounds = Bounds::from_targets(AbsoluteTime::from_micros(1_000_000), hard)?;
    clock.0.slow_subscribe.store(true, Ordering::SeqCst);
    assert!(matches!(
        DeadlineGuard::new(clock.clone(), bounds),
        Err(BoundsError::Deadline)
    ));
    assert_eq!(
        clock.0.samples.load(Ordering::SeqCst),
        0,
        "expired subscription admission must not sample another source"
    );
    assert_eq!(
        clock.0.active.load(Ordering::SeqCst),
        0,
        "a failed admission retains no subscription"
    );
    Ok(())
}
