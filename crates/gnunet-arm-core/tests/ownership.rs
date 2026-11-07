//! Bounded admission, exact original identities and independent local resources.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Direct core witnesses assert atomic original frames and callback generations."
)]
use gnunet_arm_core::{ConnectionEpoch, FrameSlot, client::*, wire::*};
use gnunet_types::{AbsoluteTime, Error};
fn connect(c: &mut Client<'_>) -> Result<ConnectionEpoch, Error> {
    let Some(Effect::Connect(e)) = c.take_effect(AbsoluteTime::from_micros(0))? else {
        return Err(Error::NotReady);
    };
    c.connection_admitted(e)?;
    let t = c.take_frame()?.ok_or(Error::NotReady)?;
    c.frame_written(t)?;
    Ok(e)
}
fn stopping(c: &mut Client<'_>, e: ConnectionEpoch, id: u64) -> Result<Option<Event>, Error> {
    let mut b = [0; 24];
    ResultReply {
        reserved: 0,
        id: WireId(id),
        result: ResultCode::STOPPING,
    }
    .encode(ArmAbi::U64Align8, &mut b)?;
    match c.receive(e, &b, AbsoluteTime::from_micros(0))? {
        Some(Inbound::Event(ev)) => Ok(Some(ev)),
        None => Ok(None),
        _ => Err(Error::Malformed),
    }
}
#[test]
fn canceled_callback_slot_reuse_does_not_cancel_envelope_or_consume_ids_on_capacity_error()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 1];
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 32];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let _e = connect(&mut c)?;
    let mut name = b"original".to_vec();
    let first = c.request_service_stop(&name)?;
    name.fill(b'x');
    let t = c.take_frame()?.ok_or(Error::NotReady)?;
    let original = c.frame(t)?.to_vec();
    assert_eq!(
        Request::decode(&original)?,
        Request::Stop {
            reserved: 0,
            id: WireId(1),
            service: b"original"
        }
    );
    assert_eq!(c.request_service_list(), Err(Error::Capacity));
    c.operation_cancel(first)?;
    assert!(!c.owns_operation(first));
    assert_eq!(c.request_service_list(), Err(Error::Capacity));
    assert_eq!(c.frame(t)?, original);
    c.frame_written(t)?;
    let replacement = c.request_service_list()?;
    assert_ne!(replacement, first);
    assert_eq!(c.operation_cancel(first), Err(Error::StaleGeneration));
    let t = c.take_frame()?.ok_or(Error::NotReady)?;
    assert_eq!(
        Request::decode(c.frame(t)?)?,
        Request::List {
            reserved: 0,
            id: WireId(2)
        }
    );
    assert!(c.owns_operation(replacement));
    Ok(())
}
#[test]
fn leased_frame_stays_immutable_through_aggregate_compaction_and_old_write_cannot_release_it()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 4];
    let mut slots = [FrameSlot::EMPTY; 3];
    let mut bytes = [0; 80];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let _e = connect(&mut c)?;
    c.request_service_stop(b"aaaaaaaaaa")?;
    c.request_service_stop(b"bbbbbbbbbb")?;
    let a = c.take_frame()?.ok_or(Error::NotReady)?;
    c.frame_written(a)?;
    let b = c.take_frame()?.ok_or(Error::NotReady)?;
    let original = c.frame(b)?.to_vec();
    c.request_service_stop(b"cccccccccc")?;
    assert_eq!(c.current_frame(), Some(b));
    assert_eq!(c.frame(b)?, original);
    assert_eq!(c.frame_written(a), Err(Error::StaleGeneration));
    assert_eq!(c.frame(b)?, original);
    c.frame_written(b)?;
    let t = c.take_frame()?.ok_or(Error::NotReady)?;
    assert!(matches!(
        Request::decode(c.frame(t)?)?,
        Request::Stop {
            id: WireId(3),
            service: b"cccccccccc",
            ..
        }
    ));
    Ok(())
}
#[test]
fn exact_maximum_request_uses_one_aggregate_vec_and_oversize_admission_is_atomic()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 1];
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = vec![0; 65535];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let _e = connect(&mut c)?;
    let over = vec![b'x'; 65519];
    assert_eq!(c.request_service_stop(&over), Err(Error::TooLarge));
    let max = vec![b'x'; 65518];
    let op = c.request_service_start(&max, StdioInheritance(15), AbsoluteTime::from_micros(0))?;
    let t = c.take_frame()?.ok_or(Error::NotReady)?;
    let b = c.frame(t)?;
    assert_eq!(b.len(), 65535);
    assert_eq!(&b[..4], &[255, 255, 0, 8]);
    assert!(matches!(Request::decode(b)?,Request::Start{id:WireId(1),service,..}if service==max));
    assert!(c.owns_operation(op));
    Ok(())
}
#[test]
fn foreign_owner_epoch_and_old_connection_results_cannot_change_new_operations() -> Result<(), Error>
{
    let mut o1 = [OperationSlot::EMPTY; 2];
    let mut f1 = [FrameSlot::EMPTY; 2];
    let mut b1 = [0; 128];
    let mut c1 = Client::new(&mut o1, &mut f1, &mut b1, 1, ArmAbi::U64Align8)?;
    let e1 = connect(&mut c1)?;
    let old = c1.request_service_list()?;
    let oldtx = c1.take_frame()?.ok_or(Error::NotReady)?;
    let mut o2 = [OperationSlot::EMPTY; 2];
    let mut f2 = [FrameSlot::EMPTY; 2];
    let mut b2 = [0; 128];
    let mut c2 = Client::new(&mut o2, &mut f2, &mut b2, 1, ArmAbi::U64Align8)?;
    let e2 = connect(&mut c2)?;
    let own = c2.request_service_list()?;
    let tx2 = c2.take_frame()?.ok_or(Error::NotReady)?;
    let saved = c2.frame(tx2)?.to_vec();
    assert_eq!(c2.operation_cancel(old), Err(Error::StaleGeneration));
    assert_eq!(c2.frame_written(oldtx), Err(Error::StaleGeneration));
    assert_eq!(
        c2.receive(e1, &[0, 4, 0, 15], AbsoluteTime::from_micros(0)),
        Err(Error::StaleGeneration)
    );
    assert!(c2.owns_operation(own));
    assert_eq!(c2.frame(tx2)?, saved);
    assert_ne!(e1, e2);
    c1.connection_lost(e1, AbsoluteTime::from_micros(0))?;
    assert_eq!(
        c1.next_event(),
        Some(Event::ListDisconnected { operation: old })
    );
    c1.next_event();
    let Some(Effect::Connect(e3)) = c1.take_effect(AbsoluteTime::from_micros(0))? else {
        return Err(Error::NotReady);
    };
    c1.connection_admitted(e3)?;
    let t = c1.take_frame()?.ok_or(Error::NotReady)?;
    c1.frame_written(t)?;
    let fresh = c1.request_service_list()?;
    assert_eq!(
        c1.receive(e1, &[0, 4, 0, 15], AbsoluteTime::from_micros(0)),
        Err(Error::StaleGeneration)
    );
    assert_eq!(c1.frame_written(oldtx), Err(Error::StaleGeneration));
    assert!(c1.owns_operation(fresh));
    Ok(())
}
#[test]
fn two_arm_stop_waiters_keep_original_callback_ownership_instead_of_c_mismatched_closure()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 2];
    let mut slots = [FrameSlot::EMPTY; 3];
    let mut bytes = [0; 128];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let e = connect(&mut c)?;
    let a = c.request_service_stop(b"arm")?;
    let b = c.request_service_stop(b"ARM")?;
    assert_eq!(stopping(&mut c, e, 1)?, None);
    assert_eq!(
        stopping(&mut c, e, 2)?,
        Some(Event::Result {
            operation: a,
            status: RequestStatus::SentOk,
            result: Some(ResultCode::IS_NOT_KNOWN)
        })
    );
    assert!(!c.owns_operation(a));
    assert!(c.owns_operation(b));
    c.connection_lost(e, AbsoluteTime::from_micros(0))?;
    assert_eq!(
        c.next_event(),
        Some(Event::Result {
            operation: b,
            status: RequestStatus::SentOk,
            result: Some(ResultCode::STOPPED)
        })
    );
    assert_eq!(
        c.next_event(),
        Some(Event::Connection(ConnectionStatus::Disconnected))
    );
    Ok(())
}
#[test]
fn pipe_ready_and_pipe_creation_failure_report_stored_result_without_waiting_or_fake_timeout()
-> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 2];
    let mut slots = [FrameSlot::EMPTY; 2];
    let mut bytes = [0; 128];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let _e = connect(&mut c)?;
    let a = c.request_service_start(b"arm", StdioInheritance(6), AbsoluteTime::from_micros(0))?;
    c.take_effect(AbsoluteTime::from_micros(0))?;
    c.startup_report(
        a,
        StartupResult::NotKnown,
        true,
        AbsoluteTime::from_micros(10),
    )?;
    c.startup_signal_ready(a)?;
    assert_eq!(
        c.next_event(),
        Some(Event::Result {
            operation: a,
            status: RequestStatus::SentOk,
            result: Some(ResultCode::IS_NOT_KNOWN)
        })
    );
    assert_eq!(
        c.take_effect(AbsoluteTime::from_micros(10))?,
        Some(Effect::CloseStartupSignal { operation: a })
    );
    c.startup_signal_closed(a)?;
    let b = c.request_service_start(b"arm", StdioInheritance(0), AbsoluteTime::from_micros(11))?;
    c.take_effect(AbsoluteTime::from_micros(11))?;
    c.startup_report(
        b,
        StartupResult::Failed,
        false,
        AbsoluteTime::from_micros(12),
    )?;
    assert_eq!(c.tick(AbsoluteTime::from_micros(12))?, 1);
    assert_eq!(
        c.next_event(),
        Some(Event::Result {
            operation: b,
            status: RequestStatus::SentOk,
            result: Some(ResultCode::START_FAILED)
        })
    );
    assert_eq!(c.take_effect(AbsoluteTime::from_micros(12))?, None);
    assert_eq!(c.next_wakeup(), None);
    Ok(())
}
#[test]
fn failure_callback_can_cancel_later_pending_operation_before_its_callback() -> Result<(), Error> {
    let mut ops = [OperationSlot::EMPTY; 2];
    let mut slots = [FrameSlot::EMPTY; 3];
    let mut bytes = [0; 128];
    let mut c = Client::new(&mut ops, &mut slots, &mut bytes, 1, ArmAbi::U64Align8)?;
    let e = connect(&mut c)?;
    let a = c.request_service_list()?;
    let b = c.request_service_stop(b"x")?;
    c.connection_lost(e, AbsoluteTime::from_micros(0))?;
    assert_eq!(
        c.next_event(),
        Some(Event::ListDisconnected { operation: a })
    );
    c.operation_cancel(b)?;
    assert_eq!(
        c.next_event(),
        Some(Event::Connection(ConnectionStatus::Disconnected))
    );
    assert_eq!(c.next_event(), None);
    Ok(())
}
