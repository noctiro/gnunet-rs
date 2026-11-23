//! One storage partition per room index, independent of its generation.

use crate::{
    EpochMemberCell, Error, Limits,
    epoch::members::MemberArena,
    room_history::{RoomHistory, RoomHistoryStorage},
    room_queues::{RoomQueueStorage, RoomQueues},
    room_tables::{RoomTableStorage, RoomTables},
    slots::{Entry, Table},
    state::{AliasBuckets, EpochAliasCell, RoomRow},
    storage::Backing,
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{array, mem::size_of};
use gnunet_types::Error as Fault;

/// Caller-owned storage for the primary room tables and processing queues.
/// Each buffer is split into equal partitions by the room slot index.
pub struct ServiceRoomStorage<'id> {
    history: RoomHistoryStorage<'id>,
    tables: RoomTableStorage<'id>,
    queues: RoomQueueStorage<'id>,
    aliases: &'id mut [EpochAliasCell],
    epoch_members: &'id mut [EpochMemberCell],
}

impl<'id> ServiceRoomStorage<'id> {
    /// Supply disjoint primary room buffers. The alias slice must contain
    /// exactly [`Self::epoch_alias_cells`] entries for the selected limits.
    /// The epoch member slice divides into equal room partitions shared by
    /// all retained epoch snapshots in each room.
    pub const fn new(
        history: RoomHistoryStorage<'id>,
        tables: RoomTableStorage<'id>,
        queues: RoomQueueStorage<'id>,
        aliases: &'id mut [EpochAliasCell],
        epoch_members: &'id mut [EpochMemberCell],
    ) -> Self {
        Self {
            history,
            tables,
            queues,
            aliases,
            epoch_members,
        }
    }

    /// Total number of epoch alias cells required across all rooms.
    ///
    /// # Errors
    /// Returns an overflow error if the capacity cannot be represented.
    pub fn epoch_alias_cells(limits: Limits) -> Result<usize, Error> {
        limits
            .rooms
            .checked_mul(AliasBuckets::bucket_count(limits.messages_per_room)?)
            .ok_or_else(|| Fault::Overflow.into())
    }

    fn partitions(self, limits: Limits) -> Result<impl Iterator<Item = Self>, Error> {
        let width = AliasBuckets::bucket_count(limits.messages_per_room)?;
        if width == 0 || self.aliases.len() != Self::epoch_alias_cells(limits)? {
            return Err(Fault::Capacity.into());
        }
        let mut remaining = self.epoch_members;
        let member_width = remaining
            .len()
            .checked_div(limits.rooms)
            .ok_or(Fault::Capacity)?;
        if !remaining.len().is_multiple_of(limits.rooms) || member_width < limits.sessions_per_room
        {
            return Err(Fault::Capacity.into());
        }
        let tables = self.tables.partitions(limits)?;
        let queues = self.queues.partitions(limits)?;
        Ok(self
            .history
            .partitions(limits)?
            .zip(tables)
            .zip(queues)
            .zip(self.aliases.chunks_exact_mut(width))
            .map(move |(((history, tables), queues), aliases)| {
                let (members, rest) = core::mem::take(&mut remaining).split_at_mut(member_width);
                remaining = rest;
                Self::new(history, tables, queues, aliases, members)
            }))
    }
}

pub(crate) enum RoomPartition<'id> {
    #[cfg(feature = "alloc")]
    History(RoomHistoryStorage<'id>),
    Service(ServiceRoomStorage<'id>),
}

#[derive(Clone, Copy)]
pub(crate) struct FixedRoomCapacities {
    pub(crate) epoch_members: usize,
    pub(crate) completion_marks: usize,
}

pub(crate) struct RoomParts<'id> {
    pub history: RoomHistory<'id>,
    pub tables: RoomTables<'id>,
    pub queues: RoomQueues<'id>,
    pub aliases: AliasBuckets<'id>,
    pub member_arena: MemberArena<'id>,
}

impl<'id> RoomParts<'id> {
    #[cfg(feature = "alloc")]
    pub fn owned(limits: Limits) -> Result<Self, Error> {
        Ok(Self {
            history: RoomHistory::owned(limits.messages_per_room)?,
            tables: RoomTables::owned(limits)?,
            queues: RoomQueues::owned(limits)?,
            aliases: AliasBuckets::new(),
            member_arena: MemberArena::default(),
        })
    }

    pub fn into_partition(self) -> Result<RoomPartition<'id>, Error> {
        let history = self.history.into_fixed().ok_or(Fault::Conflict)?;
        match (
            self.tables.into_fixed(),
            self.queues.into_fixed(),
            self.aliases.into_fixed(),
            self.member_arena.into_fixed(),
        ) {
            (Some(tables), Some(queues), Some(aliases), Some(members)) => {
                Ok(RoomPartition::Service(ServiceRoomStorage::new(
                    history, tables, queues, aliases, members,
                )))
            }
            #[cfg(feature = "alloc")]
            (None, None, None, None) => Ok(RoomPartition::History(history)),
            _ => Err(Fault::Conflict.into()),
        }
    }
}

/// A partition sits in the directory while vacant and transfers to the room
/// on admission. On retirement all its live cells are dropped before reuse.
pub(crate) struct RoomPartitions<'id, const N: usize>(Backing<Partition<'id>, [Partition<'id>; N]>);

type Partition<'id> = Option<RoomPartition<'id>>;

impl<'id, const N: usize> RoomPartitions<'id, N> {
    pub fn new(storage: RoomPartition<'id>, limits: Limits) -> Result<Self, Error> {
        Ok(Self(match storage {
            #[cfg(feature = "alloc")]
            RoomPartition::History(history) => {
                let mut partitions = Vec::new();
                partitions
                    .try_reserve_exact(limits.rooms)
                    .map_err(|_| Fault::Capacity)?;
                partitions.extend(
                    history
                        .partitions(limits)?
                        .map(|partition| Some(RoomPartition::History(partition))),
                );
                Backing::Owned(partitions)
            }
            RoomPartition::Service(service) => {
                if N != limits.rooms {
                    return Err(Fault::Capacity.into());
                }
                let mut parts = service.partitions(limits)?;
                Backing::fixed(array::from_fn(|_| parts.next().map(RoomPartition::Service)))
            }
        }))
    }

    pub fn required_bytes(rooms: usize) -> Result<usize, Error> {
        rooms
            .checked_mul(size_of::<Partition<'id>>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    pub fn bytes(&self) -> Result<usize, Error> {
        Self::required_bytes(self.0.capacity())
    }

    pub fn fixed_capacities(&self, index: usize) -> Result<Option<FixedRoomCapacities>, Error> {
        let partition = self
            .0
            .as_ref()
            .get(index)
            .and_then(Option::as_ref)
            .ok_or(Fault::Conflict)?;
        Ok(match partition {
            RoomPartition::Service(storage) => Some(FixedRoomCapacities {
                epoch_members: storage.epoch_members.len(),
                completion_marks: storage.queues.completion_capacity(),
            }),
            #[cfg(feature = "alloc")]
            RoomPartition::History(_) => None,
        })
    }

    pub fn take(&mut self, index: usize, limits: Limits) -> Result<RoomParts<'id>, Error> {
        let entry = self.0.as_mut().get_mut(index).ok_or(Fault::Conflict)?;
        #[cfg(feature = "alloc")]
        let owned = match entry.as_ref().ok_or(Fault::Conflict)? {
            RoomPartition::History(_) => {
                Some((RoomTables::owned(limits)?, RoomQueues::owned(limits)?))
            }
            RoomPartition::Service(_) => None,
        };
        #[cfg(not(feature = "alloc"))]
        let _ = limits;
        match entry.take().ok_or(Fault::Conflict)? {
            #[cfg(feature = "alloc")]
            RoomPartition::History(history) => {
                let (tables, queues) = owned.ok_or(Fault::Conflict)?;
                Ok(RoomParts {
                    history: RoomHistory::fixed(history),
                    tables,
                    queues,
                    aliases: AliasBuckets::new(),
                    member_arena: MemberArena::default(),
                })
            }
            RoomPartition::Service(service) => Ok(RoomParts {
                history: RoomHistory::fixed(service.history),
                tables: RoomTables::fixed(service.tables),
                queues: RoomQueues::fixed(service.queues),
                aliases: AliasBuckets::fixed(service.aliases),
                member_arena: MemberArena::fixed(service.epoch_members),
            }),
        }
    }

    pub fn vacant_partition(
        &mut self,
        index: usize,
    ) -> Result<&mut Option<RoomPartition<'id>>, Error> {
        let partition = self.0.as_mut().get_mut(index).ok_or(Fault::Conflict)?;
        if partition.is_some() {
            return Err(Fault::Conflict.into());
        }
        Ok(partition)
    }
}

type RoomEntry<'id> = Entry<RoomRow<'id>>;

pub(crate) type RoomDirectory<'id, const N: usize> =
    Table<RoomRow<'id>, Backing<RoomEntry<'id>, [RoomEntry<'id>; N]>>;

impl<const N: usize> RoomDirectory<'_, N> {
    #[cfg(feature = "alloc")]
    pub fn owned(limit: usize) -> Result<Self, Error> {
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limit)
            .map_err(|_| Fault::Capacity)?;
        entries.resize_with(limit, Entry::vacant);
        Ok(Self::start(Backing::Owned(entries)))
    }

    pub fn inline() -> Self {
        Self::start(Backing::fixed(array::from_fn(|_| Entry::vacant())))
    }

    pub fn required_bytes(rooms: usize) -> Result<usize, Error> {
        rooms
            .checked_mul(size_of::<RoomEntry<'_>>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    pub fn bytes(&self) -> Result<usize, Error> {
        Self::required_bytes(self.storage().capacity())
    }
}
