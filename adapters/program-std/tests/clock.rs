//! Source speedup effects and stale timer authority, without fake wall-clock IO.
use gnunet_program_host::clock::{Clock, Start};
use gnunet_types::{AbsoluteTime, Error};
fn config(
    interval: &[u8],
    delta: &[u8],
) -> Result<gnunet_config::Configuration, gnunet_config::Error> {
    let mut cfg = gnunet_config::Configuration::default();
    cfg.set_value(b"testing", b"SPEEDUP_INTERVAL", Some(interval))?;
    cfg.set_value(b"testing", b"SPEEDUP_DELTA", Some(delta))?;
    Ok(cfg)
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent source assertions in a fallible fixture test"
)]
fn initial_ready_nonlifeness_tick_replaces_skew_and_stop_preserves_accumulation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut clock = Clock::new()?;
    clock.set_offset(5_000_000);
    let cfg = config(b"100 ms", b"2 s")?;
    let Start::Ready(first) = clock.start(&cfg)? else {
        return Err("expected real ready effect".into());
    };
    assert_eq!(first.at(), AbsoluteTime::UNIX_EPOCH);
    assert!(!first.lifeness());
    let advanced = clock.tick(first, 1_000_000_000)?;
    assert_eq!(advanced.offset, 2_000_000);
    assert_eq!(advanced.next.at(), AbsoluteTime::from_micros(1_002_100_000));
    assert!(!advanced.next.lifeness());
    assert_eq!(clock.stop(), Some(advanced.next));
    assert_eq!(clock.offset(), 2_000_000);
    assert_eq!(
        clock.tick(advanced.next, 2_000_000_000),
        Err(Error::StaleGeneration)
    );
    let Start::Ready(restarted) = clock.start(&cfg)? else {
        return Err("expected new ready effect".into());
    };
    assert_eq!(clock.tick(restarted, 1_000_000_000)?.offset, 4_000_000);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent source assertions in a fallible fixture test"
)]
fn partial_setting_failure_zero_forever_and_unsigned_clock_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let mut clock = Clock::new()?;
    let cfg = config(b"0", b"2 s")?;
    assert_eq!(clock.start(&cfg)?, Start::Disabled);
    assert_eq!(clock.settings(), (0, 2_000_000));
    let mut partial = gnunet_config::Configuration::default();
    partial.set_value(b"testing", b"SPEEDUP_INTERVAL", Some(b"3 s"))?;
    assert!(clock.start(&partial).is_err());
    assert_eq!(clock.settings(), (3_000_000, 2_000_000));
    assert!(clock.stop_notice());
    let cfg = config(b"forever", b"2 s")?;
    let Start::Ready(ticket) = clock.start(&cfg)? else {
        return Err("expected ready effect".into());
    };
    assert_eq!(
        clock.tick(ticket, 1_000_000)?.next.at(),
        AbsoluteTime::NEVER
    );
    clock.set_offset(-1);
    assert_eq!(clock.absolute(0), AbsoluteTime::NEVER);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Independent source assertions in a fallible fixture test"
)]
fn stale_and_foreign_tickets_cannot_advance_offset_or_replace_timer()
-> Result<(), Box<dyn std::error::Error>> {
    let cfg = config(b"100ms", b"1s")?;
    let mut a = Clock::new()?;
    let mut b = Clock::new()?;
    let Start::Ready(ticket) = a.start(&cfg)? else {
        return Err("expected task".into());
    };
    let Start::Ready(other) = b.start(&cfg)? else {
        return Err("expected other task".into());
    };
    assert_eq!(a.tick(other, 0), Err(Error::StaleGeneration));
    assert_eq!(a.pending(), Some(ticket));
    let next = a.tick(ticket, 1_000_000)?.next;
    let before = a.offset();
    assert_eq!(a.tick(next, 1_000_001), Err(Error::WouldBlock));
    assert_eq!(a.offset(), before);
    assert_eq!(a.pending(), Some(next));
    assert_eq!(a.start(&cfg), Err(Error::Conflict));
    Ok(())
}
