//! Synchronous ownership handoff over actual retained output rows.
use super::*;

pub(super) fn try_take<'source, 'id, 'pils, J, E>(
    rows: &mut Vec<OutputRow<'source, 'id, 'pils, J>>,
    index: usize,
    handoff: impl FnOnce(Option<J>) -> Result<Option<J>, (E, Option<J>)>,
) -> Result<Result<OutputFinished<'id, J>, E>, Error> {
    let row = rows.get_mut(index).ok_or(Protocol::Stale)?;
    // The terminal variant owns the outcome; a finished row cannot have a
    // missing or independently mutable physical result.
    let OutputState::Finished(outcome) = row.state else {
        return Err(Protocol::NotReady.into());
    };
    let origin = row.origin.take();
    match handoff(origin) {
        Err((error, origin)) => {
            rows[index].origin = origin;
            Ok(Err(error))
        }
        Ok(origin) => {
            let row = rows.swap_remove(index);
            Ok(Ok(OutputFinished {
                origin,
                neighbour: Some(row.neighbour),
                outcome,
            }))
        }
    }
}

#[cfg(test)]
#[path = "output_completion/tests.rs"]
mod tests;
