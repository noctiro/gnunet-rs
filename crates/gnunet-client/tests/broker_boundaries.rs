//! Deterministic source MQ/scheduler continuations for the shared host adapter.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Pure boundary tests assert exact original request/timer state"
)]
use gnunet_client::{
    resolver::{Family, FamilyProfile, Reply, encode_response},
    resolver_handle::{Completion, Event, ResolverHandle},
};
use gnunet_types::{AbsoluteTime, Duration, Error};
use gnunet_wire::official::Frame;
fn profile() -> Result<FamilyProfile, Error> {
    FamilyProfile::new(2, 30)
}
#[test]
fn synchronous_mq_admission_precedes_unrelated_due_scheduler_work() -> Result<(), Error> {
    let mut core = ResolverHandle::<4, 64>::new(profile()?, true)?;
    let warm = core.ip_get(
        b"warm",
        Family::Any,
        Duration(1_000_000),
        AbsoluteTime::from_micros(0),
    )?;
    let epoch = core.begin_connection(AbsoluteTime::from_micros(1000))?;
    let mut out = [0; 128];
    let first = core.next_request_inline(epoch, &mut out)?;
    assert_eq!(first.request, warm);
    let mut end = [0; 8];
    encode_response(first.wire_id, Reply::End, &mut end)?;
    core.receive(epoch, Frame::decode(&end)?, AbsoluteTime::from_micros(1001))?;
    assert!(
        matches!(core.next_event(AbsoluteTime::from_micros(1001)),Some(Event::Complete{request,reason:Completion::End})if request==warm)
    );
    let _local = core.ip_get(
        b"localhost",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(1002),
    )?;
    let remote = core.ip_get(
        b"immediate",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(1002),
    )?;
    assert_eq!(
        core.next_request(epoch, &mut out, AbsoluteTime::from_micros(1002)),
        Err(Error::WouldBlock)
    );
    let frame = core.next_request_inline(epoch, &mut out)?;
    assert_eq!(frame.request, remote);
    core.request_cancel(remote, AbsoluteTime::from_micros(1002))?;
    assert!(core.owns_request(remote));
    encode_response(frame.wire_id, Reply::End, &mut end)?;
    core.receive(epoch, Frame::decode(&end)?, AbsoluteTime::from_micros(1002))?;
    assert!(!core.owns_request(remote));
    Ok(())
}
#[test]
fn sole_canceled_head_reconnect_schedules_original_retry_before_next_admission() -> Result<(), Error>
{
    let mut core = ResolverHandle::<4, 64>::new(profile()?, true)?;
    let first = core.ip_get(
        b"old",
        Family::Any,
        Duration(1_000_000),
        AbsoluteTime::from_micros(0),
    )?;
    let epoch = core.begin_connection(AbsoluteTime::from_micros(1000))?;
    let mut out = [0; 128];
    core.next_request_inline(epoch, &mut out)?;
    core.request_cancel(first, AbsoluteTime::from_micros(1001))?;
    core.connection_lost(epoch, AbsoluteTime::from_micros(1002))?;
    core.reconnect_inline(AbsoluteTime::from_micros(1002))?;
    let second = core.ip_get(
        b"new",
        Family::Any,
        Duration(1_000_000),
        AbsoluteTime::from_micros(1500),
    )?;
    assert_eq!(core.next_wakeup(), Some(AbsoluteTime::from_micros(3002)));
    assert!(!core.connection_needed(AbsoluteTime::from_micros(3001)));
    assert!(core.connection_needed(AbsoluteTime::from_micros(3002)));
    let epoch = core.begin_connection(AbsoluteTime::from_micros(3002))?;
    assert_eq!(core.next_request_inline(epoch, &mut out)?.request, second);
    Ok(())
}
#[test]
fn source_callback_stack_does_not_wait_for_time_to_recover_or_interleave_timeout()
-> Result<(), Error> {
    let mut core = ResolverHandle::<4, 64>::new(profile()?, true)?;
    let local = core.ip_get(
        b"localhost",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(5_000_000),
    )?;
    assert!(
        matches!(core.next_event(AbsoluteTime::from_micros(5_000_000)),Some(Event::Address{request,address})if request==local&&address.is_ipv6())
    );
    let remote = core.ip_get(
        b"due",
        Family::Any,
        Duration(0),
        AbsoluteTime::from_micros(5_000_000),
    )?;
    assert!(
        matches!(core.next_event(AbsoluteTime::from_micros(2_000_000)),Some(Event::Address{request,address})if request==local&&address.is_ipv4())
    );
    assert!(
        matches!(core.next_event(AbsoluteTime::from_micros(2_000_000)),Some(Event::Complete{request,..})if request==local)
    );
    // The remote zero-delay task was already in the scheduler's ready queue.
    // It runs after this callback stack, regardless of the intervening rollback.
    assert!(
        matches!(core.next_event(AbsoluteTime::from_micros(2_000_000)),Some(Event::Complete{request,reason:Completion::Timeout})if request==remote)
    );
    assert!(!core.owns_request(remote));
    assert!(
        core.next_event(AbsoluteTime::from_micros(5_000_000))
            .is_none()
    );
    Ok(())
}
