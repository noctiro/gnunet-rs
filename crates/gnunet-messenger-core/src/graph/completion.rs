//! Session completion walks accepted history without mutating message records.

use crate::{
    Error, Hash, HistoryCell, SessionPhase, Slot,
    archive::CommittedRoomHistory,
    room_history::{HistoryEntry, HistoryId, HistoryRead, HistorySnapshot, LayeredHistory},
    slot_queue::SlotQueue,
    state::RoomRow,
    storage::Backing,
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::num::NonZeroU64;
use gnunet_types::Error as Fault;

use super::history_workspace::Marks;

#[derive(Clone, Copy)]
struct Flight {
    session: Slot,
    bounds: Bounds,
    revision: Option<NonZeroU64>,
}

#[derive(Clone, Copy)]
struct Bounds {
    opening: Hash,
    closing: Hash,
}

pub(crate) struct Completion<'id> {
    marks: Backing<HistoryCell, &'id mut [HistoryCell]>,
    pending: SlotQueue<Backing<Slot, &'id mut [Slot]>>,
    active: Option<Flight>,
    cursor: Marks,
}

impl<'id> Completion<'id> {
    #[cfg(feature = "alloc")]
    pub(crate) fn owned(vertices: usize, sessions: usize) -> Result<Self, Error> {
        fn filled<T: Clone>(count: usize, value: T) -> Result<Vec<T>, Error> {
            let mut storage = Vec::new();
            storage
                .try_reserve_exact(count)
                .map_err(|_| Fault::Capacity)?;
            storage.resize(storage.capacity(), value);
            Ok(storage)
        }
        Ok(Self::new(
            Backing::Owned(filled(vertices, HistoryCell::EMPTY)?),
            Backing::Owned(filled(sessions, Slot::empty())?),
        ))
    }

    pub(crate) fn fixed(marks: &'id mut [HistoryCell], pending: &'id mut [Slot]) -> Self {
        marks.fill(HistoryCell::EMPTY);
        Self::new(Backing::fixed(marks), Backing::fixed(pending))
    }

    fn new(
        marks: Backing<HistoryCell, &'id mut [HistoryCell]>,
        pending: Backing<Slot, &'id mut [Slot]>,
    ) -> Self {
        Self {
            marks,
            pending: SlotQueue::in_storage(pending),
            active: None,
            cursor: Marks::EMPTY,
        }
    }

    pub(crate) fn into_fixed(self) -> Option<(&'id mut [HistoryCell], &'id mut [Slot])> {
        Some((
            self.marks.into_fixed()?,
            self.pending.into_storage().into_fixed()?,
        ))
    }

    pub(crate) fn capacities(&self) -> [usize; 2] {
        [self.marks.capacity(), self.pending.capacity()]
    }

    fn start(&mut self, flight: Flight, root: HistoryId) -> Result<(), Error> {
        self.cursor.restart(self.marks.as_mut());
        self.push(root)?;
        self.active = Some(flight);
        Ok(())
    }

    fn push(&mut self, vertex: HistoryId) -> Result<(), Error> {
        self.cursor.schedule(self.marks.as_mut(), vertex.index())
    }

    fn stop(&mut self) {
        self.active = None;
        self.cursor.clear();
    }

    fn step(
        &mut self,
        mut history: impl HistoryRead,
        bounds: impl FnOnce(Slot) -> Result<Option<Bounds>, Error>,
    ) -> Result<Option<Slot>, Error> {
        if self.active.is_none() && self.pending.is_empty() {
            return Ok(None);
        }
        if history.limit() > self.marks.capacity() {
            return Err(Fault::Capacity.into());
        }
        let revision = history.coordinate_revision();
        if let Some(flight) = self.active {
            if flight.revision != revision {
                // Working slots and detached pages can exchange coordinates
                // after a commit. Restart from the signed closing hash; a
                // reused index cannot inherit the previous walk's marks.
                let Some(root) = accepted(&mut history, &flight.bounds.closing)? else {
                    self.stop();
                    return Ok(None);
                };
                self.start(Flight { revision, ..flight }, root)?;
            }
        } else {
            let Some(session) = self.pending.get(0) else {
                return Ok(None);
            };
            if let Some(bounds) = bounds(session)?
                && let Some(root) = accepted(&mut history, &bounds.closing)?
            {
                self.start(
                    Flight {
                        session,
                        bounds,
                        revision,
                    },
                    root,
                )?;
            }
            self.pending.pop_front();
        }

        let Some(flight) = self.active else {
            return Ok(None);
        };
        let index = self.cursor.front().ok_or(Fault::Conflict)?;
        let (_, HistoryEntry::Accepted(facts)) = history.read(index)? else {
            return Err(Fault::Conflict.into());
        };
        if facts.hash == flight.bounds.opening {
            self.stop();
            return Ok(Some(flight.session));
        }
        let mut parents = [None; 2];
        for (parent, next) in facts.parents.iter().zip(&mut parents) {
            if *parent != [0; 64] {
                *next = accepted(&mut history, parent)?;
            }
        }
        self.cursor.pop(self.marks.as_ref());
        for parent in parents.into_iter().flatten() {
            self.push(parent)?;
        }
        if self.cursor.front().is_none() {
            self.stop();
        }
        Ok(None)
    }
}

fn accepted(history: &mut impl HistoryRead, hash: &Hash) -> Result<Option<HistoryId>, Error> {
    Ok(match history.get(hash)? {
        Some((id, HistoryEntry::Accepted(_))) => Some(id),
        _ => None,
    })
}

impl RoomRow<'_> {
    /// Whether an admitted session still needs a bounded history turn.
    pub(crate) fn has_completion_work(&self) -> bool {
        let work = &self.queues.completion;
        work.active.is_some() || !work.pending.is_empty()
    }

    pub(crate) fn schedule_completion(&mut self, session: Slot) -> Result<(), Error> {
        let work = &mut self.queues.completion;
        if self.sessions.get(session)?.needs_completion()
            && !work.active.is_some_and(|flight| flight.session == session)
            && !work.pending.contains(session)
        {
            work.pending.push_back(session)?;
        }
        Ok(())
    }

    /// Find the opening bound among the closing message's authenticated ancestors.
    pub(crate) fn completion_step(
        &mut self,
        history: Option<&CommittedRoomHistory<'_, '_>>,
    ) -> Result<Option<Slot>, Error> {
        let history = LayeredHistory::new(
            HistorySnapshot::new(&self.nodes, &self.index),
            history.map(CommittedRoomHistory::detached_history),
        )?;
        let sessions = &self.sessions;
        let completed = self.queues.completion.step(history, |slot| {
            let row = sessions.get(slot)?;
            Ok(row.needs_completion().then_some(Bounds {
                opening: row.first_bound,
                closing: row.last_bound,
            }))
        })?;
        if let Some(slot) = completed {
            let session = self.sessions.get_mut(slot)?;
            session.phase = SessionPhase::Completed;
            session.historical_phase = SessionPhase::Completed;
            session.completed_at = Some(self.sequence);
        }
        Ok(completed)
    }
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::{
        Instance, MessagePhase,
        model::{node, session, structural_core},
        room_history::AcceptedFacts,
        wire::envelope::Kind,
    };

    #[test]
    #[expect(clippy::panic_in_result_fn, reason = "assert completed session bounds")]
    fn completion_resumes_through_a_tombstone_and_excludes_pending_parents() -> Result<(), Error> {
        let mut instance = Instance::new();
        let mut core = structural_core(&mut instance)?;
        let room = core.room([11; 64], None)?;
        let row = core.rooms.get_mut(room.slot)?;
        let mut member = session(1, 1);
        member.phase = SessionPhase::Closing;
        member.last_bound = [4; 64];
        let member = row.sessions.insert(member).map_err(|(error, _)| error)?;

        row.insert_node(node(core.instance, 1, 0, 1, 1, 1)?)?;
        let durable = row.insert_node(node(core.instance, 2, 1, 1, 1, 2)?)?;
        let mut pending = node(core.instance, 3, 1, 1, 1, 0)?;
        pending.auth = None;
        row.insert_node(pending)?;
        let mut closing = node(core.instance, 4, 2, 1, 1, 3)?;
        closing.parents[1] = [3; 64];
        row.insert_node(closing)?;

        row.schedule_completion(member)?;
        assert_eq!(row.completion_step(None)?.map(|_| ()), None);
        row.erase_message(&mut core.frames, durable, None)?;
        assert_eq!(row.completion_step(None)?.map(|_| ()), None);
        assert!(row.completion_step(None)? == Some(member));
        assert!(!row.has_completion_work());
        assert_eq!(row.sessions.get(member)?.phase, SessionPhase::Completed);
        Ok(())
    }

    struct Directory {
        revision: NonZeroU64,
        rows: [(u8, u8); 4],
    }

    impl HistoryRead for Directory {
        fn limit(&self) -> usize {
            self.rows.len()
        }

        fn coordinate_revision(&self) -> Option<NonZeroU64> {
            Some(self.revision)
        }

        fn locate(&mut self, hash: &Hash) -> Result<Option<HistoryId>, Error> {
            Ok(self
                .rows
                .iter()
                .position(|(key, _)| *hash == [*key; 64])
                .map(|index| HistoryId::new(index, self.revision)))
        }

        fn read(&mut self, index: usize) -> Result<(HistoryId, HistoryEntry), Error> {
            let &(key, parent) = self.rows.get(index).ok_or(Fault::NotFound)?;
            Ok((
                HistoryId::new(index, self.revision),
                HistoryEntry::Accepted(AcceptedFacts {
                    hash: [key; 64],
                    parents: [[parent; 64], [0; 64]],
                    phase: MessagePhase::Deleted,
                    kind: Kind::TEXT,
                    sequence: u64::from(key),
                    complete: true,
                    semantic_applied: true,
                    epoch_indexed: true,
                    has_original: false,
                }),
            ))
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assert exact progress across a moved graph"
    )]
    fn relocation_restarts_from_the_closing_hash() -> Result<(), Error> {
        let mut work = Completion::owned(4, 1)?;
        let member = Slot {
            index: 0,
            generation: 1,
        };
        work.pending.push_back(member)?;
        let original = Directory {
            revision: NonZeroU64::MIN,
            rows: [(1, 0), (2, 1), (3, 2), (4, 0)],
        };
        assert!(
            work.step(original, |_| Ok(Some(Bounds {
                opening: [1; 64],
                closing: [3; 64],
            })))?
            .is_none()
        );
        // Index 1, which was the next causal parent, now holds an unrelated
        // root. The signed closing hash has also moved to a different index.
        let revision = NonZeroU64::new(2).ok_or(Fault::Conflict)?;
        let directory = || Directory {
            revision,
            rows: [(2, 1), (4, 0), (1, 0), (3, 2)],
        };
        assert!(
            work.step(directory(), |_| Err(Fault::Conflict.into()))?
                .is_none()
        );
        assert!(
            work.step(directory(), |_| Err(Fault::Conflict.into()))?
                .is_none()
        );
        assert!(work.step(directory(), |_| Err(Fault::Conflict.into()))? == Some(member));
        Ok(())
    }
}
