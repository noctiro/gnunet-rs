//! Actual control owner transitions and logical MQ frames; no spawned processes.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Literal lifecycle traces assert exact original callback authority and framing."
)]
use gnunet_arm_core::{ConnectionEpoch, FrameSlot, client::*, wire::*};
use gnunet_types::{AbsoluteTime, Error};
fn connect(c: &mut Client<'_>) -> Result<ConnectionEpoch, Error> {
    let Some(Effect::Connect(e)) = c.take_effect(AbsoluteTime::from_micros(0))? else {
        return Err(Error::NotReady);
    };
    assert_eq!(
        c.take_effect(AbsoluteTime::from_micros(0))?,
        Some(Effect::Connect(e))
    );
    c.connection_admitted(e)?;
    let t = c.take_frame()?.ok_or(Error::NotReady)?;
    assert_eq!(c.frame(t)?, [0, 4, 0, 15]);
    c.frame_written(t)?;
    Ok(e)
}
fn frame(c: &mut Client<'_>) -> Result<Vec<u8>, Error> {
    let t = c.take_frame()?.ok_or(Error::NotReady)?;
    let b = c.frame(t)?.to_vec();
    c.frame_written(t)?;
    Ok(b)
}
fn result(
    c: &mut Client<'_>,
    e: ConnectionEpoch,
    id: WireId,
    r: ResultCode,
) -> Result<Option<Inbound<'static>>, Error> {
    let mut b = [0; 24];
    ResultReply {
        reserved: 1,
        id,
        result: r,
    }
    .encode(ArmAbi::U64Align8, &mut b)?;
    match c.receive(e, &b, AbsoluteTime::from_micros(1))? {
        None => Ok(None),
        Some(Inbound::Event(v)) => Ok(Some(Inbound::Event(v))),
        Some(Inbound::List { .. }) => Err(Error::Malformed),
    }
}
#[test]
fn test_confirmation_remote_results_cancel_envelope_and_no_remote_deadline() -> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 4];
    let mut slots = [FrameSlot::EMPTY; 4];
    let mut bytes = [0; 256];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    assert_eq!(c.request_service_list(), Err(Error::NotReady));
    let e = connect(&mut c)?;
    assert!(!c.currently_up());
    let op = c.request_service_start(b"svc", StdioInheritance(15), AbsoluteTime::from_micros(0))?;
    assert!(c.owns_operation(op));
    assert_eq!(
        Request::decode(&frame(&mut c)?)?,
        Request::Start {
            reserved: 0,
            id: WireId(1),
            service: b"svc"
        }
    );
    assert_eq!(c.tick(AbsoluteTime::from_micros(u64::MAX))?, 0);
    assert_eq!(c.next_wakeup(), None);
    assert_eq!(
        c.receive(e, &[0, 4, 0, 15], AbsoluteTime::from_micros(0))?,
        Some(Inbound::Event(Event::Connection(
            ConnectionStatus::Connected
        )))
    );
    assert!(c.currently_up());
    assert_eq!(
        c.receive(e, &[0, 4, 0, 15], AbsoluteTime::from_micros(0))?,
        None
    );
    assert_eq!(result(&mut c, e, WireId(99), ResultCode::STARTING)?, None);
    assert!(c.owns_operation(op));
    assert_eq!(
        result(&mut c, e, WireId(1), ResultCode(99))?,
        Some(Inbound::Event(Event::Result {
            operation: op,
            status: RequestStatus::SentOk,
            result: Some(ResultCode(99))
        }))
    );
    assert!(!c.owns_operation(op));
    let canceled = c.request_service_stop(b"svc")?;
    c.operation_cancel(canceled)?;
    assert_eq!(c.operation_cancel(canceled), Err(Error::StaleGeneration));
    assert!(matches!(
        Request::decode(&frame(&mut c)?)?,
        Request::Stop { id: WireId(2), .. }
    ));
    assert_eq!(result(&mut c, e, WireId(2), ResultCode::STOPPED)?, None);
    Ok(())
}
#[test]
fn successful_list_borrows_validated_rows_and_wrong_registered_reply_retires_silently()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 3];
    let mut slots = [FrameSlot::EMPTY; 4];
    let mut bytes = [0; 256];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let e = connect(&mut c)?;
    let id = c.request_service_list()?;
    frame(&mut c)?;
    let rows = [ServiceInfo {
        name: b"s",
        binary: b"b",
        status: ServiceStatus::STARTED,
        last_exit_status: 0,
        restart_at: 4,
        last_started_at: 5,
    }];
    let mut data = [0; 56];
    encode_list(ArmAbi::U64Align8, WireId(1), &rows, &mut data)?;
    match c.receive(e, &data, AbsoluteTime::from_micros(0))? {
        Some(Inbound::List { operation, list }) => {
            assert_eq!(operation, id);
            assert_eq!(list.get(0)?, Some(rows[0]));
            assert_eq!(list.id()?, WireId(1));
        }
        _ => return Err(Error::Malformed),
    }
    assert!(!c.owns_operation(id));
    let id = c.request_service_list()?;
    frame(&mut c)?;
    assert_eq!(result(&mut c, e, WireId(2), ResultCode::STARTING)?, None);
    assert!(!c.owns_operation(id));
    let id = c.request_service_stop(b"x")?;
    frame(&mut c)?;
    encode_list(ArmAbi::U64Align8, WireId(3), &[], &mut data)?;
    assert_eq!(
        c.receive(e, &data[..24], AbsoluteTime::from_micros(0))?,
        None
    );
    assert!(!c.owns_operation(id));
    Ok(())
}
#[test]
fn arm_stop_waits_eof_then_failures_before_connection_notice_and_persistent_backoff()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 5];
    let mut slots = [FrameSlot::EMPTY; 6];
    let mut bytes = [0; 512];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let e = connect(&mut c)?;
    let stop = c.request_service_stop(b"ARM")?;
    let list = c.request_service_list()?;
    let start = c.request_service_start(b"x", StdioInheritance(0), AbsoluteTime::from_micros(0))?;
    frame(&mut c)?;
    frame(&mut c)?;
    frame(&mut c)?;
    assert_eq!(result(&mut c, e, WireId(1), ResultCode::STOPPING)?, None);
    assert!(c.owns_operation(stop));
    c.connection_lost(e, AbsoluteTime::from_micros(100))?;
    assert_eq!(c.retry_backoff(), 2000);
    assert_eq!(c.next_wakeup(), Some(AbsoluteTime::from_micros(0)));
    assert_eq!(c.take_effect(AbsoluteTime::from_micros(100))?, None);
    assert_eq!(
        c.next_event(),
        Some(Event::Result {
            operation: stop,
            status: RequestStatus::SentOk,
            result: Some(ResultCode::STOPPED)
        })
    );
    assert_eq!(
        c.next_event(),
        Some(Event::ListDisconnected { operation: list })
    );
    assert_eq!(
        c.next_event(),
        Some(Event::Result {
            operation: start,
            status: RequestStatus::Disconnected,
            result: None
        })
    );
    assert_eq!(
        c.next_event(),
        Some(Event::Connection(ConnectionStatus::Disconnected))
    );
    assert_eq!(c.next_event(), None);
    let Some(Effect::Connect(new)) = c.take_effect(AbsoluteTime::from_micros(100))? else {
        return Err(Error::NotReady);
    };
    assert_ne!(e, new);
    c.connection_admitted(new)?;
    frame(&mut c)?;
    c.receive(new, &[0, 4, 0, 15], AbsoluteTime::from_micros(101))?;
    assert_eq!(c.retry_backoff(), 2000);
    c.connection_lost(new, AbsoluteTime::from_micros(102))?;
    assert_eq!(c.next_wakeup(), Some(AbsoluteTime::from_micros(2102)));
    assert_eq!(
        c.next_event(),
        Some(Event::Connection(ConnectionStatus::Disconnected))
    );
    assert_eq!(c.take_effect(AbsoluteTime::from_micros(2101))?, None);
    assert!(matches!(
        c.take_effect(AbsoluteTime::from_micros(2102))?,
        Some(Effect::Connect(_))
    ));
    Ok(())
}
#[test]
fn cancel_arm_stop_tombstone_and_explicit_disconnect_are_safe_without_false_callbacks()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 2];
    let mut slots = [FrameSlot::EMPTY; 3];
    let mut bytes = [0; 128];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let e = connect(&mut c)?;
    let op = c.request_service_stop(b"arm")?;
    frame(&mut c)?;
    result(&mut c, e, WireId(1), ResultCode::STOPPING)?;
    c.operation_cancel(op)?;
    assert!(!c.owns_operation(op));
    c.connection_lost(e, AbsoluteTime::from_micros(0))?;
    assert_eq!(
        c.next_event(),
        Some(Event::Connection(ConnectionStatus::Disconnected))
    );
    assert_eq!(c.next_event(), None);
    let Some(Effect::Connect(e)) = c.take_effect(AbsoluteTime::from_micros(0))? else {
        return Err(Error::NotReady);
    };
    c.connection_admitted(e)?;
    frame(&mut c)?;
    let stop = c.request_service_stop(b"arm")?;
    frame(&mut c)?;
    result(&mut c, e, WireId(2), ResultCode::STOPPING)?;
    assert_eq!(c.disconnect(), Some(e));
    assert!(!c.owns_operation(stop));
    assert_eq!(c.next_event(), None);
    assert!(c.is_closed());
    assert_eq!(
        c.receive(e, &[0, 4, 0, 15], AbsoluteTime::from_micros(0)),
        Err(Error::StaleGeneration)
    );
    Ok(())
}
#[test]
fn startup_capacity_defers_only_new_spawn_without_blocking_original_signal_cleanup_or_connect()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 2];
    let mut slots = [FrameSlot::EMPTY; 4];
    let mut bytes = [0; 256];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let Some(Effect::Connect(epoch)) =
        c.take_effect_with_startup_capacity(AbsoluteTime::from_micros(0), false)?
    else {
        return Err(Error::NotReady);
    };
    c.connection_admitted(epoch)?;
    frame(&mut c)?;
    let first =
        c.request_service_start(b"arm", StdioInheritance(6), AbsoluteTime::from_micros(1))?;
    let second =
        c.request_service_start(b"arm", StdioInheritance(0), AbsoluteTime::from_micros(2))?;
    assert_eq!(
        c.take_effect_with_startup_capacity(AbsoluteTime::from_micros(3), false)?,
        None
    );
    assert!(c.owns_operation(first) && c.owns_operation(second));
    let expected = Some(Effect::StartArm {
        operation: first,
        stdio: StdioInheritance(6),
    });
    assert_eq!(
        c.take_effect_with_startup_capacity(AbsoluteTime::from_micros(4), true)?,
        expected
    );
    // Resource availability cannot revoke a lease the host already holds.
    assert_eq!(
        c.take_effect_with_startup_capacity(AbsoluteTime::from_micros(5), false)?,
        expected
    );
    c.startup_report(
        first,
        StartupResult::Starting,
        true,
        AbsoluteTime::from_micros(10),
    )?;
    let original_deadline = c.next_wakeup();
    for now in [11, 100, 1000] {
        assert_eq!(
            c.take_effect_with_startup_capacity(AbsoluteTime::from_micros(now), false)?,
            None
        );
        assert_eq!(c.next_wakeup(), original_deadline);
        assert!(c.owns_operation(second));
    }
    c.startup_signal_ready(first)?;
    assert_eq!(
        c.next_event(),
        Some(Event::Result {
            operation: first,
            status: RequestStatus::SentOk,
            result: Some(ResultCode::STARTING),
        })
    );
    assert_eq!(
        c.take_effect_with_startup_capacity(AbsoluteTime::from_micros(1001), false)?,
        Some(Effect::CloseStartupSignal { operation: first })
    );
    c.startup_signal_closed(first)?;
    assert_eq!(
        c.take_effect_with_startup_capacity(AbsoluteTime::from_micros(1002), false)?,
        None
    );
    assert_eq!(
        c.take_effect_with_startup_capacity(AbsoluteTime::from_micros(1003), true)?,
        Some(Effect::StartArm {
            operation: second,
            stdio: StdioInheritance(0)
        })
    );
    c.startup_report(
        second,
        StartupResult::NotKnown,
        false,
        AbsoluteTime::from_micros(1004),
    )?;
    c.tick(AbsoluteTime::from_micros(1004))?;
    assert_eq!(
        c.next_event(),
        Some(Event::Result {
            operation: second,
            status: RequestStatus::SentOk,
            result: Some(ResultCode::IS_NOT_KNOWN),
        })
    );
    Ok(())
}
#[test]
fn local_arm_start_stored_result_original60s_signal_cleanup_and_repeated_up_notice()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 3];
    let mut slots = [FrameSlot::EMPTY; 4];
    let mut bytes = [0; 256];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let e = connect(&mut c)?;
    let op = c.request_service_start(b"aRm", StdioInheritance(6), AbsoluteTime::from_micros(10))?;
    assert_eq!(
        c.take_effect(AbsoluteTime::from_micros(10))?,
        Some(Effect::StartArm {
            operation: op,
            stdio: StdioInheritance(6)
        })
    );
    assert_eq!(
        c.take_effect(AbsoluteTime::from_micros(11))?,
        Some(Effect::StartArm {
            operation: op,
            stdio: StdioInheritance(6)
        })
    );
    c.startup_report(
        op,
        StartupResult::Starting,
        true,
        AbsoluteTime::from_micros(12),
    )?;
    assert_eq!(c.next_wakeup(), Some(AbsoluteTime::from_micros(60_000_012)));
    assert_eq!(c.tick(AbsoluteTime::from_micros(60_000_011))?, 0);
    assert_eq!(c.tick(AbsoluteTime::from_micros(60_000_012))?, 1);
    assert_eq!(
        c.next_event(),
        Some(Event::Result {
            operation: op,
            status: RequestStatus::SentOk,
            result: Some(ResultCode::STARTING)
        })
    );
    assert!(!c.currently_up());
    assert_eq!(
        c.take_effect(AbsoluteTime::from_micros(60_000_012))?,
        Some(Effect::CloseStartupSignal { operation: op })
    );
    c.startup_signal_closed(op)?;
    assert_eq!(c.startup_signal_closed(op), Err(Error::StaleGeneration));
    c.receive(e, &[0, 4, 0, 15], AbsoluteTime::from_micros(60_000_013))?;
    let running = c.request_service_start(
        b"arm",
        StdioInheritance(0),
        AbsoluteTime::from_micros(70_000_000),
    )?;
    assert_eq!(c.next_event(), None);
    assert_eq!(c.tick(AbsoluteTime::from_micros(70_000_000))?, 1);
    assert_eq!(
        c.next_event(),
        Some(Event::Result {
            operation: running,
            status: RequestStatus::SentOk,
            result: Some(ResultCode::IS_STARTED_ALREADY)
        })
    );
    assert_eq!(
        c.next_event(),
        Some(Event::Connection(ConnectionStatus::Connected))
    );
    assert_eq!(c.next_event(), None);
    Ok(())
}
#[test]
fn canceled_or_disconnected_inflight_spawn_keeps_original_resource_until_actual_report()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 1];
    let mut slots = [FrameSlot::EMPTY; 2];
    let mut bytes = [0; 128];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let e = connect(&mut c)?;
    let op = c.request_service_start(b"arm", StdioInheritance(0), AbsoluteTime::from_micros(0))?;
    c.take_effect(AbsoluteTime::from_micros(0))?;
    c.operation_cancel(op)?;
    assert!(!c.owns_operation(op));
    assert_eq!(c.request_service_list(), Err(Error::Capacity));
    c.startup_report(
        op,
        StartupResult::Failed,
        true,
        AbsoluteTime::from_micros(0),
    )?;
    assert_eq!(c.next_event(), None);
    assert_eq!(
        c.take_effect(AbsoluteTime::from_micros(0))?,
        Some(Effect::CloseStartupSignal { operation: op })
    );
    c.startup_signal_closed(op)?;
    let next =
        c.request_service_start(b"arm", StdioInheritance(0), AbsoluteTime::from_micros(0))?;
    assert_ne!(next, op);
    c.take_effect(AbsoluteTime::from_micros(0))?;
    c.connection_lost(e, AbsoluteTime::from_micros(3))?;
    assert_eq!(
        c.next_event(),
        Some(Event::Result {
            operation: next,
            status: RequestStatus::Disconnected,
            result: None
        })
    );
    assert_eq!(
        c.next_event(),
        Some(Event::Connection(ConnectionStatus::Disconnected))
    );
    assert_eq!(
        c.take_effect(AbsoluteTime::from_micros(3))?,
        Some(Effect::StartArm {
            operation: next,
            stdio: StdioInheritance(0)
        })
    );
    c.startup_report(
        next,
        StartupResult::Starting,
        true,
        AbsoluteTime::from_micros(5),
    )?;
    assert_eq!(
        c.take_effect(AbsoluteTime::from_micros(5))?,
        Some(Effect::CloseStartupSignal { operation: next })
    );
    c.startup_signal_closed(next)?;
    assert_eq!(c.next_event(), None);
    Ok(())
}
#[test]
fn initial_and_retry_mq_failure_and_unknown_frames_are_observable_without_fake_success()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 2];
    let mut slots = [FrameSlot::EMPTY; 3];
    let mut bytes = [0; 128];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let Some(Effect::Connect(e)) = c.take_effect(AbsoluteTime::from_micros(0))? else {
        return Err(Error::NotReady);
    };
    c.connection_unavailable(e)?;
    assert_eq!(
        c.next_event(),
        Some(Event::Connection(ConnectionStatus::Error))
    );
    assert!(c.is_closed());
    let mut ops = [OperationSlot::EMPTY; 2];
    let mut slots = [FrameSlot::EMPTY; 3];
    let mut bytes = [0; 128];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 2, ArmAbi::U64Align8)?;
    let e = connect(&mut c)?;
    let op = c.request_service_list()?;
    let oldtx = c.take_frame()?.ok_or(Error::NotReady)?;
    assert_eq!(
        c.receive(e, &[0, 4, 0xfd, 0xe8], AbsoluteTime::from_micros(0))?,
        None
    );
    assert!(c.owns_operation(op));
    assert_eq!(c.current_frame(), Some(oldtx));
    assert!(
        c.receive(e, &[0, 5, 0, 15, 0], AbsoluteTime::from_micros(7))
            .is_err()
    );
    assert_eq!(
        c.next_event(),
        Some(Event::ListDisconnected { operation: op })
    );
    assert_eq!(
        c.next_event(),
        Some(Event::Connection(ConnectionStatus::Disconnected))
    );
    let Some(Effect::Connect(new)) = c.take_effect(AbsoluteTime::from_micros(7))? else {
        return Err(Error::NotReady);
    };
    c.connection_unavailable(new)?;
    assert_eq!(
        c.next_event(),
        Some(Event::Connection(ConnectionStatus::Error))
    );
    assert_eq!(c.next_wakeup(), None);
    assert_eq!(c.take_effect(AbsoluteTime::from_micros(u64::MAX))?, None);
    assert_eq!(c.frame_written(oldtx), Err(Error::StaleGeneration));
    Ok(())
}

#[test]
fn saturated_startup_deadline_keeps_forever_and_original_signal_authority() -> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 2];
    let mut slots = [FrameSlot::EMPTY; 4];
    let mut bytes = [0; 256];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let _epoch = connect(&mut c)?;
    let op = c.request_service_start(
        b"arm",
        StdioInheritance(0),
        AbsoluteTime::from_micros(u64::MAX - 10),
    )?;
    assert!(
        matches!(c.take_effect(AbsoluteTime::from_micros(u64::MAX-10))?,Some(Effect::StartArm{operation,..})if operation==op)
    );
    c.startup_report(
        op,
        StartupResult::Starting,
        true,
        AbsoluteTime::from_micros(u64::MAX - 5),
    )?;
    assert_eq!(c.next_wakeup(), Some(AbsoluteTime::from_micros(u64::MAX)));
    assert_eq!(
        c.tick(AbsoluteTime::from_micros(u64::MAX))?,
        0,
        "source FOREVER never becomes a due startup timeout"
    );
    assert_eq!(c.next_event(), None);
    assert!(c.owns_operation(op));
    c.startup_signal_ready(op)?;
    assert!(
        matches!(c.next_event(),Some(Event::Result{operation,result:Some(ResultCode::STARTING),..})if operation==op)
    );
    assert_eq!(
        c.take_effect(AbsoluteTime::from_micros(u64::MAX))?,
        Some(Effect::CloseStartupSignal { operation: op })
    );
    c.startup_signal_closed(op)?;
    Ok(())
}

#[test]
fn immediate_start_notifications_keep_ready_fifo_across_logical_clock_rollback() -> Result<(), Error>
{
    let mut ops = [OperationSlot::EMPTY; 3];
    let mut frames = [FrameSlot::EMPTY; 4];
    let mut bytes = [0; 256];
    let mut c = Client::new(&mut ops, &mut frames, &mut bytes, 77, ArmAbi::U64Align8)?;
    let _epoch = connect(&mut c)?;
    let first =
        c.request_service_start(b"arm", StdioInheritance(0), AbsoluteTime::from_micros(1000))?;
    assert!(
        matches!(c.take_effect(AbsoluteTime::from_micros(1000))?,Some(Effect::StartArm{operation,..})if operation==first)
    );
    c.startup_report(
        first,
        StartupResult::Failed,
        false,
        AbsoluteTime::from_micros(1000),
    )?;
    let second =
        c.request_service_start(b"arm", StdioInheritance(0), AbsoluteTime::from_micros(500))?;
    assert!(
        matches!(c.take_effect(AbsoluteTime::from_micros(500))?,Some(Effect::StartArm{operation,..})if operation==second)
    );
    c.startup_report(
        second,
        StartupResult::NotKnown,
        false,
        AbsoluteTime::from_micros(500),
    )?;
    assert_eq!(c.next_event(), None, "add_now remains asynchronous");
    assert_eq!(
        c.tick(AbsoluteTime::from_micros(0))?,
        1,
        "ready tasks do not wait for an earlier wall-clock value"
    );
    assert!(
        matches!(c.next_event(),Some(Event::Result{operation,..})if operation==first),
        "same-priority source ready order is admission FIFO"
    );
    assert_eq!(c.tick(AbsoluteTime::from_micros(0))?, 1);
    assert!(matches!(c.next_event(),Some(Event::Result{operation,..})if operation==second));
    assert_eq!(c.tick(AbsoluteTime::from_micros(u64::MAX))?, 0);
    Ok(())
}
