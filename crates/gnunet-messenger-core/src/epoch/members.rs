//! Epoch snapshots share the same order and capacity rules on both backings.

use crate::{Error, Hash, Slot, epoch::EpochMutation, state::RoomRow};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::{mem, ops::Range};
use gnunet_types::Error as Fault;

/// One caller-owned cell for a contact generation in an epoch snapshot.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EpochMemberCell(Slot);

impl EpochMemberCell {
    /// An unused cell ready for room storage.
    pub const fn empty() -> Self {
        Self(Slot {
            index: 0,
            generation: 0,
        })
    }

    pub(crate) const fn contact(self) -> Slot {
        self.0
    }
}

#[derive(Default)]
pub(crate) struct Snapshot(Members);

#[derive(Default)]
enum Members {
    #[default]
    Empty,
    #[cfg(feature = "alloc")]
    Owned(Vec<EpochMemberCell>),
    Fixed(Range<usize>),
}

impl Snapshot {
    #[cfg(feature = "alloc")]
    fn reserve_owned(limit: usize, budget: usize) -> Result<Vec<EpochMemberCell>, Error> {
        if MemberArena::required_bytes(limit)? > budget {
            return Err(Fault::Capacity.into());
        }
        let mut members = Vec::new();
        members
            .try_reserve_exact(limit)
            .map_err(|_| Fault::Capacity)?;
        if MemberArena::required_bytes(members.capacity())? > budget {
            return Err(Fault::Capacity.into());
        }
        Ok(members)
    }

    pub fn owned_bytes(&self) -> Result<usize, Error> {
        match &self.0 {
            #[cfg(feature = "alloc")]
            Members::Owned(members) => MemberArena::required_bytes(members.capacity()),
            Members::Empty | Members::Fixed(_) => Ok(0),
        }
    }

    fn cells<'a>(&'a self, fixed: &'a [EpochMemberCell]) -> &'a [EpochMemberCell] {
        match &self.0 {
            Members::Empty => &[],
            #[cfg(feature = "alloc")]
            Members::Owned(members) => members,
            Members::Fixed(span) => &fixed[span.clone()],
        }
    }

    #[cfg(all(test, feature = "alloc"))]
    pub fn from_contacts(contacts: impl IntoIterator<Item = Slot>) -> Self {
        Self(Members::Owned(
            contacts.into_iter().map(EpochMemberCell).collect(),
        ))
    }

    #[cfg(all(test, feature = "alloc"))]
    pub fn add_contact(&mut self, contact: Slot) {
        if let Members::Owned(members) = &mut self.0 {
            members.push(EpochMemberCell(contact));
        }
    }

    #[cfg(all(test, feature = "alloc"))]
    pub fn remove_contact(&mut self, contact: Slot) {
        if let Members::Owned(members) = &mut self.0 {
            members.retain(|member| member.contact() != contact);
        }
    }
}

#[cfg_attr(feature = "alloc", derive(Default))]
pub(crate) struct MemberArena<'id>(MemberStorage<'id>);

#[cfg_attr(feature = "alloc", derive(Default))]
enum MemberStorage<'id> {
    #[cfg(feature = "alloc")]
    #[default]
    Owned,
    Fixed(FixedMembers<'id>),
}

struct FixedMembers<'id> {
    cells: &'id mut [EpochMemberCell],
    used: usize,
}

impl Drop for FixedMembers<'_> {
    fn drop(&mut self) {
        self.cells[..self.used].fill(EpochMemberCell::empty());
    }
}

impl<'id> MemberArena<'id> {
    pub fn fixed(cells: &'id mut [EpochMemberCell]) -> Self {
        Self(MemberStorage::Fixed(FixedMembers { cells, used: 0 }))
    }

    pub fn into_fixed(self) -> Option<&'id mut [EpochMemberCell]> {
        match self.0 {
            #[cfg(feature = "alloc")]
            MemberStorage::Owned => None,
            MemberStorage::Fixed(mut fixed) => {
                fixed.cells[..fixed.used].fill(EpochMemberCell::empty());
                fixed.used = 0;
                Some(mem::take(&mut fixed.cells))
            }
        }
    }

    pub fn required_bytes(count: usize) -> Result<usize, Error> {
        count
            .checked_mul(mem::size_of::<EpochMemberCell>())
            .ok_or_else(|| Fault::Overflow.into())
    }

    pub fn bytes(&self) -> Result<usize, Error> {
        match &self.0 {
            #[cfg(feature = "alloc")]
            MemberStorage::Owned => Ok(0),
            MemberStorage::Fixed(fixed) => Self::required_bytes(fixed.cells.len()),
        }
    }

    pub fn reserve(&self, limit: usize, budget: usize) -> Result<Snapshot, Error> {
        #[cfg(not(feature = "alloc"))]
        let _ = (limit, budget);
        match &self.0 {
            #[cfg(feature = "alloc")]
            MemberStorage::Owned => Ok(Snapshot(Members::Owned(Snapshot::reserve_owned(
                limit, budget,
            )?))),
            MemberStorage::Fixed(_) => Ok(Snapshot::default()),
        }
    }

    fn committed(&self) -> &[EpochMemberCell] {
        match &self.0 {
            #[cfg(feature = "alloc")]
            MemberStorage::Owned => &[],
            MemberStorage::Fixed(fixed) => &fixed.cells[..fixed.used],
        }
    }

    pub fn cells<'a>(&'a self, snapshot: &'a Snapshot) -> &'a [EpochMemberCell] {
        snapshot.cells(self.committed())
    }

    pub fn restore(
        &mut self,
        count: usize,
        limit: usize,
        budget: usize,
        mut read: impl FnMut() -> Result<Slot, Error>,
    ) -> Result<Snapshot, Error> {
        if count > limit {
            return Err(Fault::Capacity.into());
        }
        #[cfg(not(feature = "alloc"))]
        let _ = budget;
        match &mut self.0 {
            MemberStorage::Fixed(fixed) => {
                if count == 0 {
                    return Ok(Snapshot::default());
                }
                let start = fixed.used;
                let end = start.checked_add(count).ok_or(Fault::Overflow)?;
                let output = fixed.cells.get_mut(start..end).ok_or(Fault::Capacity)?;
                let result = (0..count).try_for_each(|index| {
                    let next = EpochMemberCell(read()?);
                    if output[..index].contains(&next) {
                        return Err(Error::from(Fault::Malformed));
                    }
                    output[index] = next;
                    Ok(())
                });
                if let Err(error) = result {
                    output.fill(EpochMemberCell::empty());
                    return Err(error);
                }
                fixed.used = end;
                Ok(Snapshot(Members::Fixed(start..end)))
            }
            #[cfg(feature = "alloc")]
            MemberStorage::Owned => {
                let mut output = Snapshot::reserve_owned(limit, budget)?;
                for _ in 0..count {
                    let next = EpochMemberCell(read()?);
                    if output.contains(&next) {
                        return Err(Fault::Malformed.into());
                    }
                    output.push(next);
                }
                Ok(Snapshot(Members::Owned(output)))
            }
        }
    }

    fn finish(
        &mut self,
        snapshot: &mut Snapshot,
        parents: [Option<&Snapshot>; 2],
        mutation: EpochMutation,
        limit: usize,
    ) -> Result<(), Error> {
        match &mut self.0 {
            MemberStorage::Fixed(fixed) => {
                if !matches!(snapshot.0, Members::Empty) {
                    return Err(Fault::Conflict.into());
                }
                let start = fixed.used;
                let (previous, remaining) = fixed.cells.split_at_mut(start);
                let plan = Plan::new(parents, previous, mutation, limit)?;
                let output = remaining.get_mut(..plan.size).ok_or(Fault::Capacity)?;
                for (cell, member) in output.iter_mut().zip(plan.contacts()) {
                    *cell = member;
                }
                if plan.size != 0 {
                    let end = start + plan.size;
                    fixed.used = end;
                    *snapshot = Snapshot(Members::Fixed(start..end));
                }
            }
            #[cfg(feature = "alloc")]
            MemberStorage::Owned => {
                let plan = Plan::new(parents, &[], mutation, limit)?;
                let Members::Owned(output) = &mut snapshot.0 else {
                    return Err(Fault::Conflict.into());
                };
                if plan.size > output.capacity() {
                    return Err(Fault::Capacity.into());
                }
                output.clear();
                output.extend(plan.contacts());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Plan<'a> {
    first: &'a [EpochMemberCell],
    second: &'a [EpochMemberCell],
    added: Option<EpochMemberCell>,
    removed: Option<EpochMemberCell>,
    size: usize,
}

impl<'a> Plan<'a> {
    fn new(
        parents: [Option<&'a Snapshot>; 2],
        fixed: &'a [EpochMemberCell],
        mutation: EpochMutation,
        limit: usize,
    ) -> Result<Self, Error> {
        let [first, second] = parents.map(|parent| parent.map_or(&[][..], |p| p.cells(fixed)));
        let contains = |contact| first.contains(&contact) || second.contains(&contact);
        let (added, removed) = match mutation {
            EpochMutation::Join(contact) if !contains(EpochMemberCell(contact)) => {
                (Some(EpochMemberCell(contact)), None)
            }
            EpochMutation::Leave(contact) if contains(EpochMemberCell(contact)) => {
                (None, Some(EpochMemberCell(contact)))
            }
            _ => (None, None),
        };
        let inherited = second
            .iter()
            .filter(|member| !first.contains(member))
            .count();
        let before_leave = first
            .len()
            .checked_add(inherited)
            .and_then(|len| len.checked_add(usize::from(added.is_some())))
            .ok_or(Fault::Overflow)?;
        if before_leave > limit {
            return Err(Fault::Capacity.into());
        }
        Ok(Self {
            first,
            second,
            added,
            removed,
            size: before_leave - usize::from(removed.is_some()),
        })
    }

    fn contacts(self) -> impl Iterator<Item = EpochMemberCell> + 'a {
        self.first
            .iter()
            .copied()
            .chain(
                self.second
                    .iter()
                    .copied()
                    .filter(move |m| !self.first.contains(m)),
            )
            .chain(self.added)
            .filter(move |m| Some(*m) != self.removed)
    }
}

impl RoomRow<'_> {
    fn parent_slots(&self, parents: [[u8; 64]; 2]) -> Result<[Option<Slot>; 2], Error> {
        let parent = |hash| -> Result<Option<Slot>, Error> {
            if hash == [0; 64] {
                return Ok(None);
            }
            let slot = self.find_epoch(&hash).ok_or(Fault::NotReady)?;
            if !self.epochs.get(slot)?.complete {
                return Err(Fault::NotReady.into());
            }
            Ok(Some(slot))
        };
        let [first, second] = parents;
        Ok([parent(first)?, parent(second)?])
    }

    pub(crate) fn finish_epoch_snapshot(
        &mut self,
        parents: [Hash; 2],
        mutation: EpochMutation,
        snapshot: &mut Snapshot,
        limit: usize,
    ) -> Result<(), Error> {
        let [first, second] = self.parent_slots(parents)?;
        let parents = [
            first
                .map(|p| self.epochs.get(p).map(|e| &e.members))
                .transpose()?,
            second
                .map(|p| self.epochs.get(p).map(|e| &e.members))
                .transpose()?,
        ];
        self.member_arena.finish(snapshot, parents, mutation, limit)
    }

    pub fn complete_epoch_members(&mut self, slot: Slot, limit: usize) -> Result<(), Error> {
        let epoch = self.epochs.get(slot)?;
        if epoch.complete {
            return Err(Fault::Conflict.into());
        }
        let (parents, mutation) = (epoch.parents, epoch.mutation);
        let mut snapshot = mem::take(&mut self.epochs.get_mut(slot)?.members);
        let result = self.finish_epoch_snapshot(parents, mutation, &mut snapshot, limit);
        let epoch = self.epochs.get_mut(slot)?;
        epoch.members = snapshot;
        result?;
        epoch.complete = true;
        Ok(())
    }

    pub fn validate_epoch_members(
        &self,
        epoch: &crate::state::EpochRow,
        limit: usize,
    ) -> Result<(), Error> {
        let [first, second] = self
            .parent_slots(epoch.parents)
            .map_err(|_| Fault::Malformed)?;
        let parents = [
            first
                .map(|p| self.epochs.get(p).map(|e| &e.members))
                .transpose()?,
            second
                .map(|p| self.epochs.get(p).map(|e| &e.members))
                .transpose()?,
        ];
        let plan = Plan::new(
            parents,
            self.member_arena.committed(),
            epoch.mutation,
            limit,
        )?;
        let members = self.member_arena.cells(&epoch.members);
        if members.len() != plan.size || !plan.contacts().all(|c| members.contains(&c)) {
            return Err(Fault::Authentication.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert shared member capacity and reclamation"
    )]
    fn rejected_epoch_does_not_consume_members_needed_by_a_later_snapshot() -> Result<(), Error> {
        let mut cells = [EpochMemberCell::empty(); 4];
        let mut arena = MemberArena::fixed(&mut cells);
        let a = Slot {
            index: 0,
            generation: 1,
        };
        let b = Slot {
            index: 0,
            generation: 2,
        };
        let c = Slot {
            index: 1,
            generation: 1,
        };
        let first = arena.restore(1, 2, 0, || Ok(a))?;
        let mut input = [b, a].into_iter();
        let second = arena.restore(2, 2, 0, || input.next().ok_or(Fault::Conflict.into()))?;
        let mut pending = arena.reserve(2, 0)?;
        assert_eq!(
            arena.finish(
                &mut pending,
                [Some(&first), Some(&second)],
                EpochMutation::Merge,
                2
            ),
            Err(Fault::Capacity.into())
        );
        assert!(arena.cells(&pending).is_empty());
        // The union was within the session limit, but there was only one
        // free cell. A LEAVE shrinks the result enough for that same space.
        arena.finish(
            &mut pending,
            [Some(&first), Some(&second)],
            EpochMutation::Leave(b),
            2,
        )?;
        assert!(
            arena
                .cells(&pending)
                .iter()
                .map(|member| member.contact())
                .eq([a])
        );
        assert!(
            arena
                .cells(&second)
                .iter()
                .map(|member| member.contact())
                .eq([b, a])
        );
        let cells = arena.into_fixed().ok_or(Fault::Conflict)?;
        assert!(
            cells
                .iter()
                .all(|member| *member == EpochMemberCell::empty())
        );
        let mut reused = MemberArena::fixed(cells);
        let mut root = reused.reserve(2, 0)?;
        reused.finish(&mut root, [None; 2], EpochMutation::Join(c), 2)?;
        assert!(
            reused
                .cells(&root)
                .iter()
                .map(|member| member.contact())
                .eq([c])
        );
        Ok(())
    }
}
