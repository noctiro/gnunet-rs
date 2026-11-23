//! Generational proof bookkeeping over explicitly staged public graph metadata.
//! These cases exercise denial/retention; no signature or native receipt is proved.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible structural ownership assertions"
)]
use super::*;
use crate::model::{node, structural_core};
use wire::padding;

fn stage<'id>(
    core: &mut Core<'id>,
) -> Result<
    (
        Room<'id>,
        Source<'id>,
        Operation<'id>,
        Slot,
        Slot,
        Validation,
    ),
    Error,
> {
    let room = core.room([1; 64], None)?;
    let source = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    core.create_submitted(source)?;
    let mut first = node(core.instance, 1, 0, 1, 1, 1)?;
    first.epoch = [0; 64];
    first.complete = true;
    let first = core.rooms.get_mut(room.slot)?.insert_node(first)?;
    let mut candidate = node(core.instance, 2, 0, 1, 1, 2)?;
    candidate.epoch = [0; 64];
    candidate.complete = true;
    let candidate = core.rooms.get_mut(room.slot)?.insert_node(candidate)?;
    let row = core.rooms.get_mut(room.slot)?;
    row.phase = RoomPhase::Open;
    row.queues.frontier.push([1; 64])?;
    row.last_message = [1; 64];
    let operation = core.synchronize(source, 10_000)?;
    let Work::Wire { binding, frame, .. } = core.take_work(room)?.ok_or(Fault::NotReady)? else {
        return Err(Fault::Conflict.into());
    };
    core.write_progress(binding, frame.expose().len(), true)?;
    let mut validation = core
        .rooms
        .get_mut(room.slot)?
        .frontier_validation
        .take()
        .ok_or(Fault::Conflict)?;
    validation.previous = [2; 64];
    validation.epoch = [0; 64];
    validation.candidate = Some(candidate);
    validation.visited[first.index] = first.generation;
    validation.visited[candidate.index] = candidate.generation;
    validation.targets.clear();
    validation.set_stage(Stage::Normalize(0))?;
    Ok((room, source, operation, first, candidate, validation))
}

fn replace<'id>(
    core: &mut Core<'id>,
    room: Room<'id>,
    original: Slot,
    hash: u8,
) -> Result<Slot, Error> {
    let brand = core.instance;
    let row = core.rooms.get_mut(room.slot)?;
    row.index.retain(|slot| slot != original);
    row.nodes.remove(original)?;
    let mut replacement = node(brand, hash, 0, 1, 1, 3)?;
    replacement.epoch = [0; 64];
    replacement.complete = true;
    row.insert_node(replacement)
}

#[test]
fn reused_frontier_slot_is_not_covered_or_erased_by_an_old_proof() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let (room, _, operation, first, _, mut validation) = stage(&mut core)?;
    let replacement = replace(&mut core, room, first, 3)?;
    assert_eq!(replacement.index, first.index);
    assert_ne!(replacement.generation, first.generation);
    let row = core.rooms.get_mut(room.slot)?;
    row.queues.frontier.clear();
    row.queues.frontier.push([3; 64])?;
    row.last_message = [3; 64];
    for _ in 0..4 {
        core.advance_frontier_validation(room.slot, &mut validation)?;
        if core.operation_phase(operation)? == OperationPhase::Complete {
            break;
        }
    }
    let row = core.rooms.get(room.slot)?;
    assert!(row.queues.frontier.contains(&[3; 64]));
    assert_eq!(row.last_message, [3; 64]);
    assert_eq!(core.operation_phase(operation)?, OperationPhase::Complete);
    assert!(core.frontier_sync_required(room)?);
    Ok(())
}

#[test]
fn retired_candidate_generation_cannot_complete_a_sync_proof() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let (room, _, operation, _, candidate, mut validation) = stage(&mut core)?;
    let replacement = replace(&mut core, room, candidate, 4)?;
    assert_eq!(replacement.index, candidate.index);
    validation.set_stage(Stage::Commit)?;
    assert!(matches!(
        core.advance_frontier_validation(room.slot, &mut validation),
        Err(Error::Protocol(Fault::StaleGeneration))
    ));
    assert_eq!(core.operation_phase(operation)?, OperationPhase::Written);
    assert!(
        !core
            .rooms
            .get(room.slot)?
            .queues
            .frontier
            .contains(&[2; 64])
    );
    Ok(())
}
