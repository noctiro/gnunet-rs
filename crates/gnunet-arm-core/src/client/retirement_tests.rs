//! Pure original-operation retirement cases; no clock, launcher or OS activity.
//! MQ admission/read-pipe facts below are explicit mock receipts, not evidence
//! that a child, pipe, socket or callback was exercised outside this pure core.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite pure ownership cases assert clock-free retirement state"
)]
use super::*;
use crate::wire::ArmAbi;

fn admit(client: &mut Client<'_>) -> Result<(), Error> {
    let Some(Effect::Connect(epoch)) = client.take_effect(AbsoluteTime::from_micros(0))? else {
        return Err(Error::NotReady);
    };
    client.connection_admitted(epoch)
}

#[test]
fn returned_startup_pipe_retires_without_a_clock_or_a_new_deadline() -> Result<(), Error> {
    let mut operations = [OperationSlot::EMPTY; 2];
    let mut frames = [FrameSlot::EMPTY; 2];
    let mut bytes = [0; 128];
    let mut client = Client::new(
        &mut operations,
        &mut frames,
        &mut bytes,
        1,
        ArmAbi::U64Align8,
    )?;
    admit(&mut client)?;
    let operation =
        client.request_service_start(b"arm", StdioInheritance(0), AbsoluteTime::from_micros(1))?;
    assert!(
        matches!(client.take_effect(AbsoluteTime::from_micros(1))?, Some(Effect::StartArm { operation: id, .. }) if id == operation)
    );
    assert!(!client.is_disconnecting());
    assert_eq!(
        client.retire_startup(operation, StartupResult::Starting, true),
        Err(Error::NotReady)
    );
    let _old_mq = client.disconnect();
    assert!(client.is_disconnecting());
    // The host retained a real Starting/read-pipe receipt before a source-clock
    // error. No time parameter, forged sample or startup retry is needed here.
    client.retire_startup(operation, StartupResult::Starting, true)?;
    assert_eq!(
        client.next_event(),
        Some(Event::Result {
            operation,
            status: RequestStatus::Disconnected,
            result: None,
        })
    );
    assert_eq!(client.next_event(), None);
    assert_eq!(
        client.take_retirement_effect()?,
        Some(RetirementEffect::CloseStartupSignal { operation })
    );
    assert!(!client.is_closed());
    // Explicit mock receipt of the original physical close; not a clock event.
    client.startup_signal_closed(operation)?;
    assert_eq!(client.take_retirement_effect()?, None);
    assert!(client.is_closed());
    assert_eq!(client.next_wakeup(), None);
    Ok(())
}

#[test]
fn unperformed_lease_and_report_refusal_keep_original_identity_without_new_work()
-> Result<(), Error> {
    let mut operations = [OperationSlot::EMPTY; 3];
    let mut frames = [FrameSlot::EMPTY; 2];
    let mut bytes = [0; 128];
    let mut client = Client::new(
        &mut operations,
        &mut frames,
        &mut bytes,
        1,
        ArmAbi::U64Align8,
    )?;
    admit(&mut client)?;
    assert_eq!(client.take_retirement_effect(), Err(Error::NotReady));
    let original =
        client.request_service_start(b"arm", StdioInheritance(3), AbsoluteTime::from_micros(1))?;
    let later =
        client.request_service_start(b"arm", StdioInheritance(0), AbsoluteTime::from_micros(1))?;
    assert!(
        matches!(client.take_effect(AbsoluteTime::from_micros(1))?, Some(Effect::StartArm { operation, .. }) if operation == original)
    );
    let _old_mq = client.disconnect();
    assert_eq!(
        client.retire_startup(later, StartupResult::Failed, false),
        Err(Error::StaleGeneration)
    );
    assert_eq!(client.current_local, Some(original));
    assert!(client.ops[original.id.index as usize].spawn_pending);
    for operation in [original, later] {
        assert_eq!(
            client.next_event(),
            Some(Event::Result {
                operation,
                status: RequestStatus::Disconnected,
                result: None,
            })
        );
    }
    assert_eq!(client.next_event(), None);
    // This effect has no stdio/connection/spawn permission. The host reports
    // Failed/false because the original startup lease was never performed.
    assert_eq!(
        client.take_retirement_effect()?,
        Some(RetirementEffect::ReportStartup {
            operation: original
        })
    );
    client.retire_startup(original, StartupResult::Failed, false)?;
    assert_eq!(client.take_retirement_effect()?, None);
    assert_eq!(client.next_event(), None);
    assert!(client.is_closed());
    assert_eq!(client.next_wakeup(), None);
    Ok(())
}
