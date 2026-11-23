//! Bounded missing-dependency ownership; all frames and sources here are public
//! structural metadata. No signatures, crypto or native I/O are substituted.
use super::*;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact dependency and first-bound metadata"
)]
fn dependency_get_keeps_its_first_deadline_after_absence() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let room = core.room([1; 64], None)?;
    let source = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    core.create_submitted(source)?;
    let hash = [42; 64];
    assert_eq!(core.pending_dependencies(room)?.count(), 0);
    core.note_dependency(source.room, hash, source)?;
    assert_eq!(
        core.pending_dependencies(room)?.collect::<Vec<_>>(),
        [(hash, source)]
    );
    let operation = core.request_missing(source, hash, 10, 100)?;
    assert_eq!(core.pending_dependencies(room)?.count(), 0);
    assert!(matches!(
        core.request_missing(source, hash, 11, 200),
        Err(Error::Protocol(gnunet_types::Error::WouldBlock))
    ));
    // Repeated causes cannot replace a queued or written original GET.
    core.note_dependency(source.room, hash, source)?;
    assert_eq!(core.pending_dependencies(room)?.count(), 0);
    assert_eq!(write_original(&mut core, room)?.operation(), operation);
    core.on_notification(
        source,
        wire::Response::Missing {
            key: &[1; 64],
            hash: &hash,
        },
        20,
    )?;
    core.retire_operation(operation)?;
    core.note_dependency(source.room, hash, source)?;
    assert_eq!(core.pending_dependencies(room)?.count(), 0);
    let missing = core
        .rooms
        .get(source.room)?
        .missing
        .iter()
        .next()
        .map(|(_, m)| m)
        .ok_or(gnunet_types::Error::NotFound)?;
    assert_eq!(missing.retry_at, 100);
    assert!(missing.absent);
    assert!(missing.operation.is_none());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert exact source generations are not substituted"
)]
fn stopped_source_dependency_is_not_rebound_to_replacement() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let room = core.room([1; 64], None)?;
    let source = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    core.note_dependency(source.room, [42; 64], source)?;
    core.source_cancelled(source)?;
    let replacement =
        core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    assert!(source != replacement);
    assert!(
        core.pending_dependencies(room)?
            .all(|(_, original)| original == source)
    );
    assert!(
        core.pending_dependencies(room)?
            .all(|(_, original)| original != replacement)
    );
    core.note_dependency(replacement.room, [42; 64], replacement)?;
    let other_room = core.room([2; 64], None)?;
    let other = core.attach_source(
        other_room,
        SourceRole::Client,
        padding::Decode::Absent,
        None,
    )?;
    assert!(other.slot == source.slot);
    assert_eq!(
        core.retire_missing(room, &[42; 64], other),
        Err(gnunet_types::Error::NotFound.into())
    );
    assert_eq!(core.pending_dependencies(room)?.count(), 2);
    core.retire_missing(room, &[42; 64], source)?;
    assert_eq!(
        core.pending_dependencies(room)?.collect::<Vec<_>>(),
        [([42; 64], replacement)]
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert minimum-capacity independent original protocol credits"
)]
fn minimum_client_capacity_keeps_sync_and_dependency_progress() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    core.limits.operations_per_room = 3;
    let room = core.room([1; 64], None)?;
    let source = core.attach_source(room, SourceRole::Client, padding::Decode::Absent, None)?;
    core.create_submitted(source)?;
    let open = core.open(source, 1_000)?;
    write_original(&mut core, room)?;
    core.on_notification(
        source,
        wire::Response::Open(wire::Room {
            key: &[1; 64],
            door: &[0; 32],
            previous: &[0; 64],
            epoch: &[0; 64],
        }),
        10,
    )?;
    core.retire_operation(open)?;
    let held_history = core.request_missing(source, [11; 64], 10, 1_000)?;
    assert_eq!(write_original(&mut core, room)?.operation(), held_history);
    assert!(matches!(
        core.request_missing(source, [12; 64], 10, 1_000),
        Err(Error::Protocol(gnunet_types::Error::WouldBlock))
    ));
    core.note_dependency(source.room, [42; 64], source)?;
    let dependency = core.request_missing(source, [42; 64], 10, 1_000)?;
    core.note_dependency(source.room, [43; 64], source)?;
    assert!(matches!(
        core.request_missing(source, [43; 64], 10, 1_000),
        Err(Error::Protocol(gnunet_types::Error::WouldBlock))
    ));
    let sync = core.synchronize(source, 1_000)?;
    assert_eq!(core.rooms.get(source.room)?.operations.len(), 3);
    assert_eq!(write_original(&mut core, room)?.operation(), dependency);
    assert_eq!(write_original(&mut core, room)?.operation(), sync);
    core.on_notification(
        source,
        wire::Response::Missing {
            key: &[1; 64],
            hash: &[42; 64],
        },
        20,
    )?;
    core.retire_operation(dependency)?;
    // An exact independent dependency can progress while the optional history
    // and original SYNC are both still waiting for their real response.
    let next = core.request_missing(source, [43; 64], 20, 1_000)?;
    assert_eq!(write_original(&mut core, room)?.operation(), next);
    assert_eq!(core.operation_phase(held_history)?, OperationPhase::Written);
    assert_eq!(core.operation_phase(sync)?, OperationPhase::Written);
    Ok(())
}
