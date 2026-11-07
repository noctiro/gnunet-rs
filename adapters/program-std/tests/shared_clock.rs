//! Actual revision/waker ownership tests; no OS time or external network changes.
use gnunet_program_host::{
    clock::Start,
    shared_clock::{SharedClock, WallClock},
};
use gnunet_types::{AbsoluteTime, Error};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};
struct Wall(AtomicU64);
impl WallClock for Wall {
    fn wall_us(&self) -> Result<u64, Error> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
fn counter() -> (Arc<Counter>, Waker) {
    let count = Arc::new(Counter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent owner and wake assertions in a fallible fixture test"
)]
fn backwards_adjustment_wakes_all_original_waits_and_returns_coherent_revision() -> Result<(), Error>
{
    let clock = SharedClock::new(2, Arc::new(Wall(AtomicU64::new(100_000_000))))?;
    let mut one = clock.subscribe()?;
    let mut two = clock.subscribe()?;
    assert!(matches!(clock.subscribe(), Err(Error::Capacity)));
    let (a, wa) = counter();
    let (b, wb) = counter();
    let mut ca = Context::from_waker(&wa);
    let mut cb = Context::from_waker(&wb);
    assert_eq!(one.poll_changed(&mut ca, 0), Poll::Pending);
    assert_eq!(two.poll_changed(&mut cb, 0), Poll::Pending);
    clock.set_offset(5_000_000)?;
    assert_eq!(a.0.load(Ordering::SeqCst), 1);
    assert_eq!(b.0.load(Ordering::SeqCst), 1);
    let sample = one.sample()?;
    assert_eq!(sample.now, AbsoluteTime::from_micros(105_000_000));
    assert_eq!(sample.revision, 1);
    assert!(one.poll_changed(&mut ca, 0).is_ready());
    clock.set_offset(2_000_000)?;
    assert_eq!(a.0.load(Ordering::SeqCst), 2);
    assert_eq!(one.sample()?.now, AbsoluteTime::from_micros(102_000_000));
    assert_eq!(one.sample()?.revision, 2);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent owner and wake assertions in a fallible fixture test"
)]
fn changed_ready_poll_retains_waker_and_cancelled_wait_can_replace_it() -> Result<(), Error> {
    let clock = SharedClock::new(1, Arc::new(Wall(AtomicU64::new(1))))?;
    let mut subscriber = clock.subscribe()?;
    clock.set_offset(1)?;
    let (old, wold) = counter();
    let (new, wnew) = counter();
    let mut oldcx = Context::from_waker(&wold);
    assert!(subscriber.poll_changed(&mut oldcx, 0).is_ready());
    let mut newcx = Context::from_waker(&wnew);
    assert_eq!(subscriber.poll_changed(&mut newcx, 1), Poll::Pending);
    clock.set_offset(2)?;
    assert_eq!(old.0.load(Ordering::SeqCst), 0);
    assert_eq!(new.0.load(Ordering::SeqCst), 1);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent owner and wake assertions in a fallible fixture test"
)]
fn drop_releases_only_its_original_slot_and_new_listener_has_no_old_wake() -> Result<(), Error> {
    let clock = SharedClock::new(1, Arc::new(Wall(AtomicU64::new(1))))?;
    let mut old = clock.subscribe()?;
    let (count, waker) = counter();
    let mut cx = Context::from_waker(&waker);
    assert_eq!(old.poll_changed(&mut cx, 0), Poll::Pending);
    drop(old);
    assert_eq!(clock.listeners()?, 0);
    let mut new = clock.subscribe()?;
    clock.set_offset(1)?;
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    assert_eq!(clock.listeners()?, 1);
    assert!(new.poll_changed(&mut cx, 0).is_ready());
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent owner and wake assertions in a fallible fixture test"
)]
fn speedup_publishes_real_effect_while_stop_keeps_offset_and_does_not_forge_wake()
-> Result<(), Box<dyn std::error::Error>> {
    let clock = SharedClock::new(1, Arc::new(Wall(AtomicU64::new(100_000_000))))?;
    let mut subscriber = clock.subscribe()?;
    let mut cfg = gnunet_config::Configuration::default();
    cfg.set_value(b"testing", b"SPEEDUP_INTERVAL", Some(b"1s"))?;
    cfg.set_value(b"testing", b"SPEEDUP_DELTA", Some(b"2s"))?;
    let Start::Ready(ticket) = clock.start(&cfg)? else {
        return Err("expected source ready effect".into());
    };
    let (count, waker) = counter();
    let mut cx = Context::from_waker(&waker);
    assert_eq!(subscriber.poll_changed(&mut cx, 0), Poll::Pending);
    let advanced = clock.tick(ticket)?;
    assert_eq!(clock.offset()?, 2_000_000);
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(clock.stop()?, Some(advanced.next));
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert_eq!(clock.offset()?, 2_000_000);
    assert_eq!(clock.tick(advanced.next), Err(Error::StaleGeneration));
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Old cleanup authority must not cancel the replacement speedup task"
)]
fn exact_stop_ticket_cannot_cancel_a_newly_started_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let clock = SharedClock::new(0, Arc::new(Wall(AtomicU64::new(1))))?;
    let mut cfg = gnunet_config::Configuration::default();
    cfg.set_value(b"testing", b"SPEEDUP_INTERVAL", Some(b"1s"))?;
    cfg.set_value(b"testing", b"SPEEDUP_DELTA", Some(b"1s"))?;
    let Start::Ready(old) = clock.start(&cfg)? else {
        return Err("expected ready".into());
    };
    assert_eq!(clock.stop_ticket(old)?, Some(old));
    let Start::Ready(new) = clock.start(&cfg)? else {
        return Err("expected replacement".into());
    };
    assert_eq!(clock.stop_ticket(old), Err(Error::StaleGeneration));
    assert_eq!(clock.stop_ticket(new)?, Some(new));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "FOREVER is a source sentinel, not a due timestamp even if the caller samples MAX"
)]
fn forever_speedup_ticket_never_becomes_due_at_max_and_failed_tick_is_atomic()
-> Result<(), Box<dyn std::error::Error>> {
    use gnunet_program_host::clock::{Clock, Start};
    let mut cfg = gnunet_config::Configuration::default();
    cfg.set_value(b"testing", b"SPEEDUP_INTERVAL", Some(b"forever"))?;
    cfg.set_value(b"testing", b"SPEEDUP_DELTA", Some(b"2s"))?;
    let mut clock = Clock::new()?;
    let Start::Ready(first) = clock.start(&cfg)? else {
        return Err("initial ready effect missing".into());
    };
    let next = clock.tick(first, 0)?.next;
    assert_eq!(next.at(), AbsoluteTime::NEVER);
    let offset = clock.offset();
    assert_eq!(
        clock.tick(next, u64::MAX),
        Err(gnunet_types::Error::WouldBlock)
    );
    assert_eq!(clock.offset(), offset);
    assert_eq!(clock.pending(), Some(next));
    Ok(())
}
