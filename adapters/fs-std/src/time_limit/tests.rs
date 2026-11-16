//! Virtual-time deadline regressions; no native IO or C interoperability credit.
use super::*;
use crate::network::{Error, TimeLimit};
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, SystemClock};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

struct Frozen {
    now: AtomicU64,
    subscriptions: AtomicUsize,
}
impl Frozen {
    fn new() -> Self {
        Self {
            now: AtomicU64::new(1000),
            subscriptions: AtomicUsize::new(0),
        }
    }
}
impl RuntimeClock for Frozen {
    fn sample(&self) -> Result<ClockSample, ProtocolError> {
        Ok(ClockSample {
            now: AbsoluteTime::from_micros(self.now.load(Ordering::Relaxed)),
            revision: 0,
        })
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, ProtocolError> {
        self.subscriptions.fetch_add(1, Ordering::Relaxed);
        SystemClock.subscribe()
    }
}
fn target() -> AbsoluteTime {
    AbsoluteTime::from_micros(1_001_000)
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Virtual-time assertions preserve the one original native allowance across progress"
)]
async fn frozen_clock_and_progress_cannot_renew_a_finite_operation() -> Result<(), Error> {
    let clock = Arc::new(Frozen::new());
    let started = Instant::now();
    let mut limit = TimeLimit::new(clock.clone(), target(), None)?;
    for _ in 0..4 {
        limit.during(std::future::ready(())).await?;
        tokio::time::advance(Duration::from_millis(200)).await;
    }
    let result = limit.during(std::future::pending::<()>()).await;
    assert!(
        matches!(result, Err(Error::Deadline { .. })),
        "a stalled source must not extend the operation"
    );
    assert_eq!(
        started.elapsed(),
        Duration::from_secs(1),
        "successful progress cannot reset the original native target"
    );
    assert_eq!(
        clock.sample()?.now.as_micros(),
        1000,
        "the logical clock never expired"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent caller/native bounds must select the earlier target"
)]
async fn an_outer_bound_can_tighten_but_never_extend_the_original_allowance() -> Result<(), Error> {
    for outer in [Duration::from_millis(500), Duration::from_secs(2)] {
        let started = Instant::now();
        let mut limit = TimeLimit::new(Arc::new(Frozen::new()), target(), Some(started + outer))?;
        let result = limit.during(std::future::pending::<()>()).await;
        assert!(
            matches!(result, Err(Error::Deadline { .. })),
            "the selected finite native target must terminate the wait"
        );
        assert_eq!(
            started.elapsed(),
            outer.min(Duration::from_secs(1)),
            "caller bounds cannot renew the source admission allowance"
        );
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Elapsed setup must be refused before reserving another provider listener"
)]
async fn elapsed_admission_origin_is_not_replaced_after_provider_setup() -> Result<(), Error> {
    let clock = Arc::new(Frozen::new());
    let origin = Instant::now();
    tokio::time::advance(Duration::from_secs(2)).await;
    let result = TimeLimit::admit(clock.clone(), target(), origin, None);
    assert!(
        matches!(result, Err(Error::Deadline { .. })),
        "admission work consumes the original native allowance"
    );
    assert_eq!(
        clock.subscriptions.load(Ordering::Relaxed),
        0,
        "expired admission cannot reserve a fresh deadline listener"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "FOREVER, rollback and an explicit outer stop remain distinct policies"
)]
async fn forever_keeps_its_policy_while_rollback_and_explicit_outer_limits_still_apply()
-> Result<(), Error> {
    let clock = Arc::new(Frozen::new());
    let forever = AbsoluteTime::from_micros(u64::MAX);
    let mut limit = TimeLimit::new(clock.clone(), forever, None)?;
    tokio::time::advance(Duration::from_secs(86_400)).await;
    limit.during(std::future::ready(())).await?;
    clock.now.store(999, Ordering::Relaxed);
    let result = limit.during(std::future::ready(())).await;
    assert!(
        matches!(result, Err(Error::Protocol(ProtocolError::TimeUncertain))),
        "FOREVER does not permit source-clock rollback"
    );
    let started = Instant::now();
    let mut limited = TimeLimit::new(
        Arc::new(Frozen::new()),
        forever,
        Some(started + Duration::from_secs(1)),
    )?;
    let result = limited.during(std::future::pending::<()>()).await;
    assert!(
        matches!(result, Err(Error::Deadline { .. })),
        "an explicit native bound still limits an infinite logical target"
    );
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    Ok(())
}

#[tokio::test(start_paused = true)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Sequential children must inherit the enclosing operation's original stop target"
)]
async fn sequential_children_cannot_renew_their_tree_allowance() -> Result<(), Error> {
    let clock = Arc::new(Frozen::new());
    let started = Instant::now();
    let tree = TimeLimit::new(clock.clone(), target(), None)?;
    let outer = tree.native_deadline();
    let mut first = TimeLimit::new(clock.clone(), target(), outer)?;
    first
        .during(tokio::time::sleep(Duration::from_millis(600)))
        .await?;
    let mut second = TimeLimit::new(clock.clone(), target(), outer)?;
    let result = second.during(std::future::pending::<()>()).await;
    assert!(matches!(result, Err(Error::Deadline { .. })));
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert_eq!(second.native_deadline(), outer);
    assert!(matches!(
        TimeLimit::new(clock, target(), outer),
        Err(Error::Deadline { .. })
    ));
    Ok(())
}
