//! Official Messenger routing ring over current signed room announcements.

use crate::{Core, Error, Hash, Mode, Room, ShortHash, room_queues::RoomPeers, state::PeerRow};
use core::{cmp::Ordering, fmt};

/// Tunnel count and flags advertised in a peer's signed CONNECTION control.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServiceConnection {
    /// Number of tunnels reported by the signer.
    pub amount: u32,
    /// Official CONNECTION flag bits as reported by the signer.
    pub flags: u32,
}

/// A peer's adjacency to the local peer in descending identity order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RingRole {
    /// Next peer, including wraparound from the lowest to the highest identity.
    Successor,
    /// Previous peer, including wraparound from the highest to the lowest identity.
    Predecessor,
    /// The sole other peer in a two-peer ring.
    Both,
}

/// A required neighbor according to the signed ring. This is not a tunnel status.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RingNeighbor {
    peer: ShortHash,
    role: RingRole,
}

impl RingNeighbor {
    /// Full peer identity from the signed PEER announcement.
    pub const fn peer(self) -> ShortHash {
        self.peer
    }

    /// Position relative to the local peer.
    pub const fn role(self) -> RingRole {
        self.role
    }
}

impl fmt::Debug for RingNeighbor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RingNeighbor")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

/// A snapshot of a service room's signed routing membership and local edges.
#[derive(Clone, Copy, Debug)]
pub struct ServiceRoomRing {
    members: usize,
    local_connection: Option<ServiceConnection>,
    neighbors: [Option<RingNeighbor>; 2],
}

impl ServiceRoomRing {
    /// Number of current PEER announcements, including the local peer if present.
    pub const fn members(&self) -> usize {
        self.members
    }

    /// Local CONNECTION metadata, if the local peer has a current announcement.
    /// A fresh announcement starts with zero amount and flags.
    pub const fn local_connection(&self) -> Option<ServiceConnection> {
        self.local_connection
    }

    /// Successor then predecessor, with at most one edge to each identity.
    /// Rooms without a current local PEER announcement have no local edges.
    pub fn neighbors(&self) -> impl Iterator<Item = RingNeighbor> + '_ {
        self.neighbors.iter().copied().flatten()
    }

    fn project<'a>(local: Option<ShortHash>, peers: impl Iterator<Item = &'a PeerRow>) -> Self {
        let mut ring = Self {
            members: 0,
            local_connection: None,
            neighbors: [None; 2],
        };
        let mut lower = Bounds::default();
        let mut higher = Bounds::default();
        for row in peers {
            let Some(connection) = row.connection() else {
                continue;
            };
            ring.members += 1;
            if let Some(local) = local.as_ref() {
                match row.peer.cmp(local) {
                    Ordering::Less => lower.include(&row.peer),
                    Ordering::Greater => higher.include(&row.peer),
                    Ordering::Equal => ring.local_connection = Some(connection),
                }
            }
        }
        if ring.local_connection.is_some()
            && let (Some(&successor), Some(&predecessor)) = (
                lower.greatest.or(higher.greatest),
                higher.least.or(lower.least),
            )
        {
            ring.neighbors = if successor == predecessor {
                [
                    Some(RingNeighbor {
                        peer: successor,
                        role: RingRole::Both,
                    }),
                    None,
                ]
            } else {
                [
                    Some(RingNeighbor {
                        peer: successor,
                        role: RingRole::Successor,
                    }),
                    Some(RingNeighbor {
                        peer: predecessor,
                        role: RingRole::Predecessor,
                    }),
                ]
            };
        }
        ring
    }
}

#[derive(Default)]
struct Bounds<'a> {
    least: Option<&'a ShortHash>,
    greatest: Option<&'a ShortHash>,
}

impl<'a> Bounds<'a> {
    fn include(&mut self, peer: &'a ShortHash) {
        self.least = Some(self.least.map_or(peer, |least| least.min(peer)));
        self.greatest = Some(self.greatest.map_or(peer, |greatest| greatest.max(peer)));
    }
}

impl<'id, const ROOMS: usize> Core<'id, ROOMS> {
    /// Project the official room ring in one pass without allocating. Historical
    /// peers may seed a fresh dial via [`Self::service_peer_candidates`] but do
    /// not join the ring until a current PEER announcement is applied.
    ///
    /// # Errors
    /// Rejects client mode and invalid or stale room handles.
    pub fn service_room_ring(&self, room: Room<'id>) -> Result<ServiceRoomRing, Error> {
        Ok(ServiceRoomRing::project(
            self.local_peer,
            self.service_room_peers(room)?.iter(),
        ))
    }

    /// Enumerate current and recovered PEER announcements that may seed a
    /// fresh dial. A recovered candidate grants no live routing or signing
    /// authority.
    ///
    /// # Errors
    /// Rejects client mode and invalid or stale room handles.
    pub fn service_peer_candidates(
        &self,
        room: Room<'id>,
    ) -> Result<impl Iterator<Item = &ShortHash> + '_, Error> {
        Ok(self.service_room_peers(room)?.iter().map(|p| &p.peer))
    }

    /// Return the original hash of this peer's current authenticated and applied
    /// PEER announcement. Moving the original to an archive page preserves the
    /// result; a withdrawn peer or a recovered dial candidate returns `None`.
    ///
    /// # Errors
    /// Rejects client mode and invalid or stale room handles.
    pub fn service_peer_announcement(
        &self,
        room: Room<'id>,
        peer: &ShortHash,
    ) -> Result<Option<Hash>, Error> {
        Ok(self
            .service_room_peers(room)?
            .announcement(peer)
            .map(|announcement| announcement.hash))
    }

    fn service_room_peers(&self, room: Room<'id>) -> Result<&RoomPeers<'id>, Error> {
        if self.mode != Mode::Service {
            return Err(Error::Permission);
        }
        Ok(&self.rooms.get(self.check_room(room)?)?.queues.peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RoomPeerCell, RoomQueueStorage, room_queues::RoomQueues, state::PeerAnnouncement};
    use core::num::NonZeroU64;

    fn peer(suffix: u8) -> ShortHash {
        let mut identity = [17; 32];
        identity[31] = suffix;
        identity
    }

    fn announced(suffix: u8) -> PeerRow {
        let mut row = PeerRow::candidate(peer(suffix));
        row.announce(announcement(suffix));
        row
    }

    fn announcement(revision: u8) -> PeerAnnouncement {
        PeerAnnouncement {
            hash: [revision; 64],
            sequence: NonZeroU64::MIN.saturating_add(revision.into()),
        }
    }

    fn neighbor(suffix: u8, role: RingRole) -> RingNeighbor {
        RingNeighbor {
            peer: peer(suffix),
            role,
        }
    }

    #[test]
    fn only_current_announcements_form_a_ring() {
        let local = Some(peer(2));
        let history = PeerRow::candidate(peer(2));
        let empty = ServiceRoomRing::project(None, core::iter::empty());
        assert_eq!(empty.members(), 0);
        assert_eq!(empty.local_connection(), None);
        assert_eq!(empty.neighbors().count(), 0);

        let away = ServiceRoomRing::project(local, [history, announced(3)].iter());
        assert_eq!(away.members(), 1);
        assert_eq!(away.local_connection(), None);
        assert_eq!(away.neighbors().count(), 0);

        let single = ServiceRoomRing::project(local, [announced(2)].iter());
        assert_eq!(single.members(), 1);
        assert_eq!(
            single.local_connection(),
            Some(ServiceConnection::default())
        );
        assert_eq!(single.neighbors().count(), 0);

        let pair = ServiceRoomRing::project(local, [announced(2), announced(3)].iter());
        assert!(pair.neighbors().eq([neighbor(3, RingRole::Both)]));
    }

    #[test]
    fn descending_ring_uses_full_identities_and_wraps() {
        let mut highest = announced(4);
        highest.record_connection(ServiceConnection {
            amount: 200,
            flags: u32::MAX,
        });
        let peers = [announced(3), announced(1), highest, announced(2)];
        for (local, successor, predecessor) in [(3, 2, 4), (1, 4, 2), (4, 3, 1)] {
            let ring = ServiceRoomRing::project(Some(peer(local)), peers.iter());
            assert_eq!(ring.members(), 4);
            assert!(ring.neighbors().eq([
                neighbor(successor, RingRole::Successor),
                neighbor(predecessor, RingRole::Predecessor),
            ]));
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert bounded peer membership transitions"
    )]
    fn replacement_and_miss_update_exact_live_evidence() -> Result<(), Error> {
        let local = peer(1);
        let current =
            |peers: &RoomPeers<'_>| peers.announcement(&local).map(|a| (a.hash, a.sequence));
        let mut cells = core::array::from_fn::<_, 2, _>(|_| RoomPeerCell::empty());
        let mut queue =
            RoomQueues::fixed(RoomQueueStorage::new(&mut [], &mut cells, &mut [], &mut []));
        let peers = &mut queue.peers;
        peers.push(PeerRow::candidate(local))?;
        peers.announce(peer(2), announcement(1))?;
        let connection = ServiceConnection {
            amount: 7,
            flags: 1,
        };
        peers.record_connection(&local, connection);
        assert_eq!(current(peers), None);
        let original = announcement(2);
        peers.announce(local, original)?;
        assert_eq!(current(peers), Some((original.hash, original.sequence)));
        assert_eq!(
            ServiceRoomRing::project(Some(local), peers.iter()).local_connection(),
            Some(ServiceConnection::default())
        );

        peers.record_connection(&local, connection);
        let replacement = announcement(3);
        peers.announce(local, replacement)?;
        assert_eq!(
            current(peers),
            Some((replacement.hash, replacement.sequence))
        );
        assert_eq!(
            ServiceRoomRing::project(Some(local), peers.iter()).local_connection(),
            Some(connection)
        );

        peers.remove(&local);
        peers.record_connection(&local, connection);
        let away = ServiceRoomRing::project(Some(local), peers.iter());
        assert_eq!(away.members(), 1);
        assert_eq!(away.neighbors().count(), 0);
        assert_eq!(current(peers), None);
        let fresh = announcement(4);
        peers.announce(local, fresh)?;
        assert_eq!(current(peers), Some((fresh.hash, fresh.sequence)));
        let ring = ServiceRoomRing::project(Some(local), peers.iter());
        assert_eq!(ring.local_connection(), Some(ServiceConnection::default()));
        assert!(ring.neighbors().eq([neighbor(2, RingRole::Both)]));
        Ok(())
    }
}
