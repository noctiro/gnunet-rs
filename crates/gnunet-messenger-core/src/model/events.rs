use super::*;
use gnunet_types::Error as Fault;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert that queued source loss retains its retired generation"
)]
fn source_loss_keeps_the_original_generation_after_slot_reuse() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let room = core.room([1; 64], None)?;
    let original = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    core.source_stopped(original)?;
    let replacement =
        core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    assert_eq!(
        original.observation().index(),
        replacement.observation().index()
    );
    assert_ne!(original, replacement);

    let lost = core::iter::from_fn(|| core.pop_event())
        .find_map(|event| match event {
            Event::SourceLost(source) => Some(source),
            _ => None,
        })
        .ok_or(Fault::NotFound)?;
    assert_eq!(lost, original);
    assert!(matches!(
        core.source_room(lost),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert_eq!(core.source_room(replacement)?, room);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert that queued failure reconstructs the exact provider binding and owner"
)]
fn provider_failure_preserves_the_complete_binding_and_refuses_foreign_brands() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let mut foreign_instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let foreign = Brand::new(&mut foreign_instance);
    let room = Slot {
        index: 1,
        generation: 2,
    };
    let operation = Slot {
        index: 3,
        generation: 4,
    };
    let coordinates = OperationBinding {
        source: Slot {
            index: 0,
            generation: 6,
        },
        member: Some(Slot {
            index: 7,
            generation: 8,
        }),
        message: [11; 64],
        epoch: [12; 64],
        identifier: [13; 32],
        epoch_revision: 14,
    };
    let error = Error::Protocol(Fault::Unavailable);
    let foreign_binding = coordinates.bind(foreign, room, operation);
    assert!(matches!(
        core.event(Event::ProviderFailed(foreign_binding, error)),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert!(core.pop_event().is_none());

    let original = coordinates.bind(core.instance, room, operation);
    core.event(Event::ProviderFailed(original, error))?;
    let Some(Event::ProviderFailed(binding, Error::Protocol(Fault::Unavailable))) =
        core.pop_event()
    else {
        return Err(Fault::Conflict.into());
    };
    assert_eq!(binding.operation(), original.operation());
    assert_eq!(binding.source(), original.source());
    assert_eq!(binding.member(), original.member());
    assert!(binding.coordinates() == coordinates);
    Ok(())
}
