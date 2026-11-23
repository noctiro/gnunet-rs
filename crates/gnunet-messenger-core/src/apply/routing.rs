//! Reconcile historical withdrawals with the current signed peer ring.

use crate::{
    Core, Error, MessagePhase, ShortHash, Slot, SourceRole, archive::CommittedRoomHistory,
    graph::has_signed_ancestor, room_history::LayeredHistory,
};
#[cfg(feature = "alloc")]
use crate::{HistoryWorkspace, room_history::HistoryRead};
use gnunet_types::Error as Fault;

impl<const ROOMS: usize> Core<'_, ROOMS> {
    pub(super) fn recover_peer_withdrawal(
        &mut self,
        room: Slot,
        message: Slot,
        target: &ShortHash,
        archive: Option<&CommittedRoomHistory<'_, '_>>,
    ) -> Result<(), Error> {
        let row = self.rooms.get(room)?;
        let node = row.nodes.get(message)?;
        if !node.meta.requested {
            return Ok(());
        }
        let SourceRole::Peer(origin) = node.origin.provenance().role else {
            return Ok(());
        };
        let reporter = node
            .auth
            .and_then(|auth| auth.peer)
            .ok_or(Fault::Authentication)?;
        if self.local_peer == Some(origin)
            || self.local_peer == Some(reporter)
            || reporter != origin && row.queues.peers.announcement(&reporter).is_none()
        {
            return Ok(());
        }
        let Some(announcement) = row.queues.peers.announcement(target) else {
            return Ok(());
        };

        let view = LayeredHistory::new(
            row.history_snapshot(),
            archive.map(CommittedRoomHistory::detached_history),
        )?;
        let proven = match self.ancestry.as_mut() {
            Some(workspace) => {
                has_signed_ancestor(view, &node.parents, &announcement.hash, workspace)?
            }
            None => {
                #[cfg(feature = "alloc")]
                {
                    let mut workspace =
                        HistoryWorkspace::budgeted(view.limit(), self.remaining_bytes())?;
                    has_signed_ancestor(view, &node.parents, &announcement.hash, &mut workspace)?
                }
                #[cfg(not(feature = "alloc"))]
                return Err(Fault::Conflict.into());
            }
        };
        if proven {
            // The same mutable room turn owns both the evidence and the update.
            // History recovery does not participate in the live hosting election.
            self.rooms.get_mut(room)?.queues.peers.remove(target);
        } else if !row.graph_complete(message, archive)? {
            // Admission keeps signed links and asks for missing parents. Parent
            // completion requeues this vertex without withholding CADET credit.
            self.rooms.get_mut(room)?.nodes.get_mut(message)?.phase = MessagePhase::AwaitingParents;
            return Err(Fault::NotReady.into());
        }
        Ok(())
    }
}
