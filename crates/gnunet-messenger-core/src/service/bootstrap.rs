//! Accepted public controls used to bootstrap a SERVICE room channel.

use super::{history::check_archive, local_history::latest_successor};
use crate::{
    CommittedServiceOriginal, Core, Error, Mode, Room, SessionPhase, archive::CommittedRoomHistory,
    graph::session_bound, wire::envelope::Kind,
};
use gnunet_types::Error as Fault;

/// Room-bound progress through a fixed prefix of the committed graph.
/// Native callers keep the returned successor only after admitting its original.
#[derive(Clone, Copy)]
pub struct ServiceBootstrap<'id> {
    room: Room<'id>,
    after: u64,
    through: u64,
}

impl ServiceBootstrap<'_> {
    /// Whether there are no unexamined acceptance sequences in the prefix.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.after == self.through
    }
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Capture the acceptance boundary for a new authenticated room channel.
    /// The caller reads originals from the exact checkpoint of this Core.
    ///
    /// # Errors
    /// Refuses client mode and an invalid room generation.
    pub fn service_bootstrap(&self, room: Room<'id>) -> Result<ServiceBootstrap<'id>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let row = self.rooms.get(self.check_room(room)?)?;
        Ok(ServiceBootstrap {
            room,
            after: 0,
            through: row.sequence,
        })
    }

    /// Select the next applied original for a current routing announcement or
    /// unfinished member lineage in acceptance order. A withdrawn or superseded
    /// PEER cannot be offered, even if it was current at the captured boundary.
    /// Originals may move to graph pages between sends without moving the cursor.
    /// The cursor and exact checkpoint must belong to the same live room owner.
    /// No archived original can grant a live source or replay a state transition.
    ///
    /// # Errors
    /// Refuses an invalid cursor, a different checkpoint or inconsistent attribution.
    pub fn service_bootstrap_next<'a>(
        &'a self,
        cursor: ServiceBootstrap<'id>,
        archive: CommittedRoomHistory<'a, '_>,
    ) -> Result<Option<(ServiceBootstrap<'id>, CommittedServiceOriginal<'a>)>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        let at = self.check_room(cursor.room)?;
        let row = self.rooms.get(at)?;
        check_archive(row, at, self.local_peer, Some(archive))?;
        let cold = archive.next_applied_original(cursor.after, cursor.through, |cold| {
            let kind = cold.original.kind();
            if kind == Kind::PEER {
                let peer = cold.auth.peer.ok_or(Fault::Authentication)?;
                let current = row.current_peer_announcement(&peer, cold.original.hash());
                return Ok(current == Some(cold.sequence));
            }
            if cold.requested || !session_bound(kind) {
                return Ok(false);
            }
            let session = cold.auth.session.ok_or(Fault::Authentication)?;
            let latest = row.sessions.get(latest_successor(row, session)?)?;
            let phase = if latest.archived {
                latest.historical_phase
            } else {
                latest.phase
            };
            Ok(matches!(
                phase,
                SessionPhase::Active | SessionPhase::Closing
            ))
        })?;
        let Some(cold) = cold else {
            return Ok(None);
        };
        self.committed_attribution(at, row, &cold)?;
        let next = ServiceBootstrap {
            after: cold.sequence.get(),
            ..cursor
        };
        Ok(Some((next, cold.original)))
    }
}
