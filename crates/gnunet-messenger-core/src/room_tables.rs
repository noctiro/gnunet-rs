//! Per-room generational metadata on owned or caller-owned storage.

use crate::{
    Error, Limits,
    slots::{Entry, EntryCell, Table},
    state::{EpochRow, MissingRow, OperationRow, SessionRow, SourceRow, Subscription},
    storage::Backing,
};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{fmt, iter, mem::size_of};
use gnunet_types::Error as Fault;

pub(crate) trait VacantRoomCell: Sized {
    fn empty_cell() -> Self;
}

macro_rules! room_cell {
    ($doc:literal, $cell:ident, $row:ty) => {
        #[doc = $doc]
        pub struct $cell(Entry<$row>);

        impl $cell {
            /// An empty cell ready for caller-owned room storage.
            pub const fn empty() -> Self {
                Self(Entry::vacant())
            }
        }

        impl fmt::Debug for $cell {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($cell), "([REDACTED])"))
            }
        }

        impl VacantRoomCell for $cell {
            fn empty_cell() -> Self {
                Self::empty()
            }
        }

        impl EntryCell<$row> for $cell {
            fn entry(&self) -> &Entry<$row> {
                &self.0
            }

            fn entry_mut(&mut self) -> &mut Entry<$row> {
                &mut self.0
            }
        }
    };
}

room_cell!("One caller-owned room source cell.", SourceCell, SourceRow);
room_cell!(
    "One caller-owned member session cell.",
    SessionCell,
    SessionRow
);
room_cell!("One caller-owned room epoch cell.", EpochCell, EpochRow);
room_cell!(
    "One caller-owned discourse subscription cell.",
    SubscriptionCell,
    Subscription
);
room_cell!(
    "One caller-owned room operation cell.",
    OperationCell,
    OperationRow
);
room_cell!(
    "One caller-owned missing-message cell.",
    MissingCell,
    MissingRow
);

/// Caller-owned cells for the six per-room state tables. Each slice must
/// contain `limits.rooms` times its corresponding per-room limit. A room's
/// slot index selects the same partition each time that slot is admitted.
pub struct RoomTableStorage<'id> {
    sources: &'id mut [SourceCell],
    sessions: &'id mut [SessionCell],
    epochs: &'id mut [EpochCell],
    subscriptions: &'id mut [SubscriptionCell],
    operations: &'id mut [OperationCell],
    missing: &'id mut [MissingCell],
}

impl<'id> RoomTableStorage<'id> {
    /// Supply disjoint backing slices for all per-room state tables.
    pub const fn new(
        sources: &'id mut [SourceCell],
        sessions: &'id mut [SessionCell],
        epochs: &'id mut [EpochCell],
        subscriptions: &'id mut [SubscriptionCell],
        operations: &'id mut [OperationCell],
        missing: &'id mut [MissingCell],
    ) -> Self {
        Self {
            sources,
            sessions,
            epochs,
            subscriptions,
            operations,
            missing,
        }
    }

    pub(crate) fn partitions(self, limits: Limits) -> Result<impl Iterator<Item = Self>, Error> {
        for (len, width) in [
            (self.sources.len(), limits.sources_per_room),
            (self.sessions.len(), limits.sessions_per_room),
            (self.epochs.len(), limits.epochs_per_room),
            (self.subscriptions.len(), limits.subscriptions_per_room),
            (self.operations.len(), limits.operations_per_room),
            (self.missing.len(), limits.missing_per_room),
        ] {
            let expected = limits.rooms.checked_mul(width).ok_or(Fault::Overflow)?;
            if width == 0 || len != expected {
                return Err(Fault::Capacity.into());
            }
        }

        self.sources.fill_with(SourceCell::empty);
        self.sessions.fill_with(SessionCell::empty);
        self.epochs.fill_with(EpochCell::empty);
        self.subscriptions.fill_with(SubscriptionCell::empty);
        self.operations.fill_with(OperationCell::empty);
        self.missing.fill_with(MissingCell::empty);

        let mut sources = self.sources.chunks_exact_mut(limits.sources_per_room);
        let mut sessions = self.sessions.chunks_exact_mut(limits.sessions_per_room);
        let mut epochs = self.epochs.chunks_exact_mut(limits.epochs_per_room);
        let mut subscriptions = self
            .subscriptions
            .chunks_exact_mut(limits.subscriptions_per_room);
        let mut operations = self.operations.chunks_exact_mut(limits.operations_per_room);
        let mut missing = self.missing.chunks_exact_mut(limits.missing_per_room);
        Ok(iter::from_fn(move || {
            Some(Self::new(
                sources.next()?,
                sessions.next()?,
                epochs.next()?,
                subscriptions.next()?,
                operations.next()?,
                missing.next()?,
            ))
        }))
    }
}

pub(crate) struct BorrowedRoomCells<'id, C: VacantRoomCell>(&'id mut [C]);

impl<'id, C: VacantRoomCell> BorrowedRoomCells<'id, C> {
    fn into_clean_cells(mut self) -> &'id mut [C] {
        let cells = core::mem::take(&mut self.0);
        cells.fill_with(C::empty_cell);
        cells
    }
}

impl<C: VacantRoomCell> AsRef<[C]> for BorrowedRoomCells<'_, C> {
    fn as_ref(&self) -> &[C] {
        self.0
    }
}

impl<C: VacantRoomCell> AsMut<[C]> for BorrowedRoomCells<'_, C> {
    fn as_mut(&mut self) -> &mut [C] {
        self.0
    }
}

impl<C: VacantRoomCell> Drop for BorrowedRoomCells<'_, C> {
    fn drop(&mut self) {
        self.0.fill_with(C::empty_cell);
    }
}

pub(crate) type RoomTable<'id, T, C> = Table<T, Backing<C, BorrowedRoomCells<'id, C>>, C>;

impl<'id, T, C: EntryCell<T> + VacantRoomCell> RoomTable<'id, T, C> {
    #[cfg(feature = "alloc")]
    fn owned(limit: usize) -> Result<Self, Error> {
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(limit)
            .map_err(|_| Fault::Capacity)?;
        cells.resize_with(limit, C::empty_cell);
        Ok(Self::start(Backing::Owned(cells)))
    }

    fn fixed(cells: &'id mut [C]) -> Self {
        Self::start(Backing::fixed(BorrowedRoomCells(cells)))
    }

    pub fn bytes(&self) -> Result<usize, Error> {
        self.storage()
            .capacity()
            .checked_mul(size_of::<C>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    fn into_fixed_cells(self) -> Option<&'id mut [C]> {
        self.into_storage()
            .into_fixed()
            .map(BorrowedRoomCells::into_clean_cells)
    }
}

pub(crate) struct RoomTables<'id> {
    pub sources: RoomTable<'id, SourceRow, SourceCell>,
    pub sessions: RoomTable<'id, SessionRow, SessionCell>,
    pub epochs: RoomTable<'id, EpochRow, EpochCell>,
    pub subscriptions: RoomTable<'id, Subscription, SubscriptionCell>,
    pub operations: RoomTable<'id, OperationRow, OperationCell>,
    pub missing: RoomTable<'id, MissingRow, MissingCell>,
}

impl<'id> RoomTables<'id> {
    #[cfg(feature = "alloc")]
    pub fn owned(limits: Limits) -> Result<Self, Error> {
        Ok(Self {
            sources: RoomTable::owned(limits.sources_per_room)?,
            sessions: RoomTable::owned(limits.sessions_per_room)?,
            epochs: RoomTable::owned(limits.epochs_per_room)?,
            subscriptions: RoomTable::owned(limits.subscriptions_per_room)?,
            operations: RoomTable::owned(limits.operations_per_room)?,
            missing: RoomTable::owned(limits.missing_per_room)?,
        })
    }

    pub fn fixed(partition: RoomTableStorage<'id>) -> Self {
        Self {
            sources: RoomTable::fixed(partition.sources),
            sessions: RoomTable::fixed(partition.sessions),
            epochs: RoomTable::fixed(partition.epochs),
            subscriptions: RoomTable::fixed(partition.subscriptions),
            operations: RoomTable::fixed(partition.operations),
            missing: RoomTable::fixed(partition.missing),
        }
    }

    pub fn into_fixed(self) -> Option<RoomTableStorage<'id>> {
        Some(RoomTableStorage::new(
            self.sources.into_fixed_cells()?,
            self.sessions.into_fixed_cells()?,
            self.epochs.into_fixed_cells()?,
            self.subscriptions.into_fixed_cells()?,
            self.operations.into_fixed_cells()?,
            self.missing.into_fixed_cells()?,
        ))
    }

    /// Minimum bytes for one room's tables, before any heap over-allocation.
    pub fn required_bytes(limits: Limits) -> Result<usize, Error> {
        [
            (limits.sources_per_room, size_of::<SourceCell>()),
            (limits.sessions_per_room, size_of::<SessionCell>()),
            (limits.epochs_per_room, size_of::<EpochCell>()),
            (limits.subscriptions_per_room, size_of::<SubscriptionCell>()),
            (limits.operations_per_room, size_of::<OperationCell>()),
            (limits.missing_per_room, size_of::<MissingCell>()),
        ]
        .into_iter()
        .try_fold(0usize, |total, (count, width)| {
            total.checked_add(count.checked_mul(width)?)
        })
        .ok_or_else(|| Fault::Overflow.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SourceRole, wire::padding};

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert room partition bounds and reuse through the actual tables"
    )]
    fn reclaimed_room_tables_do_not_retain_rows() -> Result<(), Error> {
        let limits = Limits {
            rooms: 2,
            sources_per_room: 2,
            sessions_per_room: 1,
            epochs_per_room: 1,
            subscriptions_per_room: 1,
            operations_per_room: 1,
            missing_per_room: 1,
            ..Limits::default()
        };
        let mut sources = [const { SourceCell::empty() }; 4];
        let mut sessions = [const { SessionCell::empty() }; 2];
        let mut epochs = [const { EpochCell::empty() }; 2];
        let mut subscriptions = [const { SubscriptionCell::empty() }; 2];
        let mut operations = [const { OperationCell::empty() }; 2];
        let mut missing = [const { MissingCell::empty() }; 2];
        let storage = RoomTableStorage::new(
            &mut sources,
            &mut sessions,
            &mut epochs,
            &mut subscriptions,
            &mut operations,
            &mut missing,
        );
        let mut parts = storage.partitions(limits)?;
        let mut room = RoomTables::fixed(parts.next().ok_or(Fault::Conflict)?);
        let other = RoomTables::fixed(parts.next().ok_or(Fault::Conflict)?);
        assert!(parts.next().is_none());
        assert_eq!(room.sources.limit(), 2);
        assert_eq!(
            room.sources.bytes()?
                + room.sessions.bytes()?
                + room.epochs.bytes()?
                + room.subscriptions.bytes()?
                + room.operations.bytes()?
                + room.missing.bytes()?,
            RoomTables::required_bytes(limits)?
        );

        let old = room
            .sources
            .insert(SourceRow {
                role: SourceRole::Client,
                attached: true,
                padding: padding::Decode::Absent,
                create_written: false,
                public: None,
                member_id: None,
                pending_member_id: None,
                join_required: false,
                join_operation: None,
            })
            .map_err(|(error, _)| error)?;
        assert!(other.sources.slot_at(old.index).is_none());

        let reclaimed = RoomTables::fixed(room.into_fixed().ok_or(Fault::Conflict)?);
        assert!(reclaimed.sources.slot_at(old.index).is_none());
        assert_eq!(reclaimed.sources.next_key()?.index, old.index);
        Ok(())
    }
}
