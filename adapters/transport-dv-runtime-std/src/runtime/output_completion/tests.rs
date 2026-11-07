//! Actual output-row ownership handoff, without an Actor source or native IO.
//! Finished/Unsent rows here are metadata fixtures, not crypto/write receipts.
use super::*;
use std::rc::Rc;

fn check(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(Protocol::Conflict.into())
    }
}
struct Owner {
    id: u8,
    dropped: Rc<Cell<usize>>,
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}
fn token(instance: &Instance) -> Result<Token<'_>, Protocol> {
    Ok(Token {
        domain: instance,
        serial: instance.next()?,
    })
}
fn row<'id>(
    instance: &'id Instance,
    client: &gnunet_transport::ClientId,
    origin: Option<Owner>,
) -> Result<OutputRow<'id, 'id, 'id, Owner>, Error> {
    let mut bytes = vec![0, 4, 0, 99];
    bytes
        .try_reserve_exact(37)
        .map_err(|_| Protocol::Capacity)?;
    Ok(OutputRow {
        token: token(instance)?,
        neighbour: Neighbour {
            token: token(instance)?,
            client: client.clone(),
            peer: PeerId([3; 32]),
            queue: 7,
            reverse: true,
        },
        origin,
        parent: None,
        bounds: Bound {
            until: 123,
            hard: Instant::now()
                .checked_add(std::time::Duration::from_secs(30))
                .ok_or(Protocol::Overflow)?,
        },
        state: OutputState::Finished(WriteOutcome::Unsent),
        bytes,
        without_fc: false,
        ordered_target: None,
        exposed: false,
        queued: false,
        probe: None,
    })
}

#[test]
fn refusal_retains_the_same_non_clone_owner_and_all_original_row_facts() -> Result<(), Error> {
    let instance = Instance::new();
    let mut engine =
        gnunet_transport::Engine::new(PeerId([1; 32]), gnunet_transport::Limits::default())?;
    let client = engine.accept()?;
    let dropped = Rc::new(Cell::new(0));
    let other_dropped = Rc::new(Cell::new(0));
    let mut rows = vec![
        row(
            &instance,
            &client,
            Some(Owner {
                id: 7,
                dropped: dropped.clone(),
            }),
        )?,
        row(
            &instance,
            &client,
            Some(Owner {
                id: 9,
                dropped: other_dropped.clone(),
            }),
        )?,
    ];
    let original = rows[0].token;
    let other = rows[1].token;
    let neighbour = rows[0].neighbour.clone();
    let bounds = rows[0].bounds.budget();
    let bytes = rows[0].bytes.as_ptr();
    let capacity = rows[0].bytes.capacity();
    let seen = Cell::new(0);
    let refused = try_take(&mut rows, 0, |origin| {
        seen.set(origin.as_ref().map_or(0, |owner| owner.id));
        Err((Protocol::WouldBlock, origin))
    })?;
    check(matches!(refused, Err(Protocol::WouldBlock)))?;
    check(seen.get() == 7 && dropped.get() == 0 && other_dropped.get() == 0)?;
    check(rows.len() == 2 && rows[0].token == original && rows[1].token == other)?;
    check(rows[0].origin.as_ref().is_some_and(|owner| owner.id == 7))?;
    check(
        rows[0].neighbour == neighbour
            && rows[0].bounds.budget().hard == bounds.hard
            && rows[0].bounds.budget().until == bounds.until,
    )?;
    check(
        rows[0].bytes.as_ptr() == bytes
            && rows[0].bytes.capacity() == capacity
            && rows[0].bytes == [0, 4, 0, 99],
    )?;
    check(
        matches!(rows[0].state, OutputState::Finished(WriteOutcome::Unsent))
            && !rows[0].queued
            && !rows[0].exposed,
    )?;
    let completed = try_take(&mut rows, 0, |origin| {
        Ok::<_, (Protocol, Option<Owner>)>(origin)
    })?
    .map_err(Error::from)?;
    check(rows.len() == 1 && rows[0].token == other)?;
    check(
        completed.neighbour.as_ref() == Some(&neighbour)
            && completed.outcome == WriteOutcome::Unsent
            && completed.origin.as_ref().is_some_and(|owner| owner.id == 7),
    )?;
    check(dropped.get() == 0 && other_dropped.get() == 0)?;
    drop(completed);
    check(dropped.get() == 1 && other_dropped.get() == 0)?;
    drop(rows);
    check(dropped.get() == 1 && other_dropped.get() == 1)
}

#[test]
fn nonfinished_output_never_calls_the_handoff_or_removes_origin() -> Result<(), Error> {
    let instance = Instance::new();
    let mut engine =
        gnunet_transport::Engine::new(PeerId([1; 32]), gnunet_transport::Limits::default())?;
    let client = engine.accept()?;
    let dropped = Rc::new(Cell::new(0));
    let mut rows = vec![row(
        &instance,
        &client,
        Some(Owner {
            id: 7,
            dropped: dropped.clone(),
        }),
    )?];
    let original = rows[0].token;
    let bytes = rows[0].bytes.as_ptr();
    let called = Cell::new(0);
    rows[0].state = OutputState::Ready;
    check(matches!(
        try_take(&mut rows, 0, |origin| {
            called.set(called.get() + 1);
            Ok::<_, (Protocol, Option<Owner>)>(origin)
        }),
        Err(Error::Protocol(Protocol::NotReady))
    ))?;
    check(called.get() == 0 && dropped.get() == 0 && rows.len() == 1)?;
    check(
        rows[0].token == original
            && rows[0].bytes.as_ptr() == bytes
            && rows[0].origin.as_ref().is_some_and(|owner| owner.id == 7),
    )
}

#[test]
fn output_without_external_origin_uses_the_same_refusal_then_success_boundary() -> Result<(), Error>
{
    let instance = Instance::new();
    let mut engine =
        gnunet_transport::Engine::new(PeerId([1; 32]), gnunet_transport::Limits::default())?;
    let client = engine.accept()?;
    let mut rows = vec![row(&instance, &client, None)?];
    let original = rows[0].token;
    let neighbour = rows[0].neighbour.clone();
    check(matches!(
        try_take(&mut rows, 0, |origin| {
            Err((Protocol::WouldBlock, origin))
        })?,
        Err(Protocol::WouldBlock)
    ))?;
    check(rows.len() == 1 && rows[0].token == original && rows[0].origin.is_none())?;
    let completed = try_take(&mut rows, 0, |origin| {
        Ok::<_, (Protocol, Option<Owner>)>(origin)
    })?
    .map_err(Error::from)?;
    check(
        rows.is_empty()
            && completed.origin.is_none()
            && completed.neighbour.as_ref() == Some(&neighbour)
            && completed.outcome == WriteOutcome::Unsent,
    )
}
