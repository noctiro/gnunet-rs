//! Real monitor state, exact frame leases and retry ordering; no network I/O.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact monitor events, deadlines and original epoch authority."
)]
use gnunet_arm_core::{FrameSlot, monitor::*, wire::*};
use gnunet_types::{AbsoluteTime, Error};
#[test]
fn subscribe_is_monitor_not_test_and_unknown_notifications_do_not_reset_backoff()
-> Result<(), Error> {
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 16];
    let mut m = Monitor::new(&mut slots, &mut bytes, 1)?;
    let e = m
        .take_connect(AbsoluteTime::from_micros(0))?
        .ok_or(Error::NotReady)?;
    assert_eq!(m.take_connect(AbsoluteTime::from_micros(0))?, Some(e));
    m.connection_admitted(e)?;
    let tx = m.take_frame()?.ok_or(Error::NotReady)?;
    assert_eq!(m.frame(tx)?, [0, 4, 0, 14]);
    m.frame_written(tx)?;
    let s = [0, 12, 0, 11, 0, 0, 0, 0, b'a', b'r', b'm', 0];
    assert_eq!(
        m.receive(e, &s, AbsoluteTime::from_micros(1))?,
        Some(Status {
            status: MonitorStatus::MONITORING_STARTED,
            service: b"arm"
        })
    );
    assert_eq!(
        m.receive(e, &[0, 4, 0, 10], AbsoluteTime::from_micros(2))?,
        None
    );
    m.connection_lost(e, AbsoluteTime::from_micros(100))?;
    assert_eq!(m.next_wakeup(), Some(AbsoluteTime::from_micros(0)));
    assert_eq!(m.retry_backoff(), 2000);
    let e2 = m
        .take_connect(AbsoluteTime::from_micros(100))?
        .ok_or(Error::NotReady)?;
    m.connection_admitted(e2)?;
    let tx2 = m.take_frame()?.ok_or(Error::NotReady)?;
    let unknown = [0, 10, 0, 11, 255, 255, 255, 255, 255, 0];
    assert_eq!(
        m.receive(e2, &unknown, AbsoluteTime::from_micros(101))?,
        Some(Status {
            status: MonitorStatus(u32::MAX),
            service: b"\xff"
        })
    );
    assert_eq!(m.retry_backoff(), 2000);
    assert_eq!(m.frame_written(tx), Err(Error::StaleGeneration));
    assert_eq!(m.frame(tx2)?, [0, 4, 0, 14]);
    m.frame_written(tx2)?;
    m.connection_lost(e2, AbsoluteTime::from_micros(102))?;
    assert_eq!(m.next_wakeup(), Some(AbsoluteTime::from_micros(2102)));
    assert_eq!(m.take_connect(AbsoluteTime::from_micros(2101))?, None);
    assert!(m.take_connect(AbsoluteTime::from_micros(2102))?.is_some());
    Ok(())
}
#[test]
fn malformed_registered_status_reconnects_but_legal_unregistered_directions_are_ignored()
-> Result<(), Error> {
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 8];
    let mut m = Monitor::new(&mut slots, &mut bytes, 1)?;
    let e = m
        .take_connect(AbsoluteTime::from_micros(0))?
        .ok_or(Error::NotReady)?;
    m.connection_admitted(e)?;
    for kind in [8, 9, 10, 12, 13, 14, 15, 65000u16] {
        let k = kind.to_be_bytes();
        assert_eq!(
            m.receive(e, &[0, 4, k[0], k[1]], AbsoluteTime::from_micros(10))?,
            None
        );
    }
    assert!(
        m.receive(
            e,
            &[0, 9, 0, 11, 0, 0, 0, 1, b'x'],
            AbsoluteTime::from_micros(20)
        )
        .is_err()
    );
    assert_eq!(m.next_wakeup(), Some(AbsoluteTime::from_micros(0)));
    assert_eq!(
        m.receive(
            e,
            &[0, 9, 0, 11, 0, 0, 0, 1, 0],
            AbsoluteTime::from_micros(20)
        ),
        Err(Error::StaleGeneration)
    );
    Ok(())
}
#[test]
fn actual_initial_and_retry_creation_failures_are_distinct_and_never_fabricate_timers()
-> Result<(), Error> {
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 4];
    let mut m = Monitor::new(&mut slots, &mut bytes, 1)?;
    let e = m
        .take_connect(AbsoluteTime::from_micros(0))?
        .ok_or(Error::NotReady)?;
    assert_eq!(m.connection_unavailable(e)?, Unavailable { initial: true });
    assert!(m.is_closed());
    assert_eq!(m.next_wakeup(), None);
    assert_eq!(
        m.take_connect(AbsoluteTime::from_micros(u64::MAX)),
        Err(Error::Closed)
    );
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 4];
    let mut m = Monitor::new(&mut slots, &mut bytes, 2)?;
    let e = m
        .take_connect(AbsoluteTime::from_micros(0))?
        .ok_or(Error::NotReady)?;
    m.connection_admitted(e)?;
    m.connection_lost(e, AbsoluteTime::from_micros(3))?;
    let next = m
        .take_connect(AbsoluteTime::from_micros(3))?
        .ok_or(Error::NotReady)?;
    assert_eq!(
        m.connection_unavailable(next)?,
        Unavailable { initial: false }
    );
    assert!(!m.is_closed());
    assert_eq!(m.next_wakeup(), None);
    assert_eq!(m.take_connect(AbsoluteTime::from_micros(u64::MAX))?, None);
    Ok(())
}
#[test]
fn stop_revokes_pending_frame_connect_attempt_and_every_later_notification() -> Result<(), Error> {
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 8];
    let mut m = Monitor::new(&mut slots, &mut bytes, 1)?;
    let e = m
        .take_connect(AbsoluteTime::from_micros(0))?
        .ok_or(Error::NotReady)?;
    m.connection_admitted(e)?;
    let t = m.take_frame()?.ok_or(Error::NotReady)?;
    assert_eq!(m.current_frame(), Some(t));
    assert_eq!(m.stop(), Some(e));
    assert!(m.is_closed());
    assert_eq!(m.stop(), None);
    assert_eq!(m.frame_written(t), Err(Error::StaleGeneration));
    assert_eq!(
        m.receive(
            e,
            &[0, 9, 0, 11, 0, 0, 0, 1, 0],
            AbsoluteTime::from_micros(0)
        ),
        Err(Error::StaleGeneration)
    );
    assert_eq!(m.next_wakeup(), None);
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 8];
    let mut m = Monitor::new(&mut slots, &mut bytes, 2)?;
    let attempt = m
        .take_connect(AbsoluteTime::from_micros(0))?
        .ok_or(Error::NotReady)?;
    assert_eq!(m.stop(), None);
    assert_eq!(m.connection_admitted(attempt), Err(Error::StaleGeneration));
    Ok(())
}
#[test]
fn repeated_mq_loss_reaches_fifteen_minute_cap_without_notification_reset() -> Result<(), Error> {
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 4];
    let mut m = Monitor::new(&mut slots, &mut bytes, 1)?;
    let mut now = 0u64;
    let mut delay = 0u64;
    for _ in 0..40 {
        let e = m
            .take_connect(AbsoluteTime::from_micros(now))?
            .ok_or(Error::NotReady)?;
        m.connection_admitted(e)?;
        let t = m.take_frame()?.ok_or(Error::NotReady)?;
        m.frame_written(t)?;
        m.receive(
            e,
            &[0, 9, 0, 11, 0, 0, 0, 1, 0],
            AbsoluteTime::from_micros(now),
        )?;
        m.connection_lost(e, AbsoluteTime::from_micros(now))?;
        assert_eq!(
            m.next_wakeup(),
            Some(AbsoluteTime::from_micros(if delay == 0 {
                0
            } else {
                now + delay
            }))
        );
        delay = delay.max(1000).saturating_mul(2).min(900_000_000);
        assert_eq!(m.retry_backoff(), delay);
        now = m.next_wakeup().ok_or(Error::NotReady)?.as_micros();
    }
    assert_eq!(delay, 900_000_000);
    Ok(())
}

#[test]
fn saturated_reconnect_delay_remains_forever_without_minting_a_new_mq() -> Result<(), Error> {
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 16];
    let mut m = Monitor::new(&mut slots, &mut bytes, 1)?;
    let first = m
        .take_connect(AbsoluteTime::from_micros(0))?
        .ok_or(Error::NotReady)?;
    m.connection_admitted(first)?;
    m.connection_lost(first, AbsoluteTime::from_micros(0))?;
    let second = m
        .take_connect(AbsoluteTime::from_micros(0))?
        .ok_or(Error::NotReady)?;
    m.connection_admitted(second)?;
    m.connection_lost(second, AbsoluteTime::from_micros(u64::MAX - 1000))?;
    assert_eq!(m.next_wakeup(), Some(AbsoluteTime::from_micros(u64::MAX)));
    assert_eq!(
        m.take_connect(AbsoluteTime::from_micros(u64::MAX))?,
        None,
        "source saturated absolute deadline is FOREVER, not a due reconnect"
    );
    Ok(())
}

#[test]
fn already_ready_zero_delay_reconnect_survives_clock_rollback_but_forever_does_not()
-> Result<(), Error> {
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 16];
    let mut monitor = Monitor::new(&mut slots, &mut bytes, 77)?;
    let first = monitor
        .take_connect(AbsoluteTime::from_micros(1000))?
        .ok_or(Error::NotReady)?;
    monitor.connection_admitted(first)?;
    monitor.connection_lost(first, AbsoluteTime::from_micros(1000))?;
    let ready = monitor.take_connect(AbsoluteTime::from_micros(500))?;
    assert!(
        ready.is_some(),
        "an already queued ready reconnect was resuspended by a later clock rollback"
    );
    let retry = ready.ok_or(Error::NotReady)?;
    assert_ne!(first, retry);
    monitor.connection_admitted(retry)?;
    monitor.connection_lost(retry, AbsoluteTime::from_micros(500))?;
    assert_eq!(monitor.next_wakeup(), Some(AbsoluteTime::from_micros(2500)));
    assert_eq!(monitor.take_connect(AbsoluteTime::from_micros(2499))?, None);
    assert!(
        monitor
            .take_connect(AbsoluteTime::from_micros(2500))?
            .is_some()
    );

    let mut other_slots = [FrameSlot::EMPTY; 1];
    let mut other_bytes = [0; 16];
    let mut forever = Monitor::new(&mut other_slots, &mut other_bytes, 78)?;
    let original = forever
        .take_connect(AbsoluteTime::from_micros(1000))?
        .ok_or(Error::NotReady)?;
    forever.connection_admitted(original)?;
    forever.connection_lost(original, AbsoluteTime::from_micros(u64::MAX))?;
    assert_eq!(
        forever.next_wakeup(),
        Some(AbsoluteTime::from_micros(u64::MAX))
    );
    assert_eq!(forever.take_connect(AbsoluteTime::from_micros(500))?, None);
    Ok(())
}
