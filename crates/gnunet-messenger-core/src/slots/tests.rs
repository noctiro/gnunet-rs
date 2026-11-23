#![expect(
    clippy::panic_in_result_fn,
    reason = "Slot lifecycle tests assert observable state using fallible setup"
)]

use super::*;
use core::cell::Cell;

fn coordinates(slot: Slot) -> (usize, u64) {
    (slot.index, slot.generation)
}

#[test]
fn borrowed_slots_reuse_indices_without_reissuing_handles() -> Result<(), Error> {
    let mut backing = [const { Entry::vacant() }; 2];
    let mut slots = Table::in_storage(&mut backing);
    assert_eq!(slots.limit(), 2);
    let old = slots.insert(4).map_err(|(error, _)| error)?;
    let other = slots.insert(7).map_err(|(error, _)| error)?;
    assert_eq!(slots.len(), 2);
    assert_eq!(slots.remove(old), Ok(4));
    assert_eq!(slots.get(old), Err(Fault::StaleGeneration.into()));
    let expected = slots.next_key()?;
    let new = slots.insert(8).map_err(|(error, _)| error)?;
    assert_eq!(coordinates(expected), coordinates(new));
    assert_eq!(coordinates(new), (old.index, old.generation + 1));
    assert_eq!(slots.get_mut(old), Err(Fault::StaleGeneration.into()));
    assert_eq!(slots.remove(old), Err(Fault::StaleGeneration.into()));
    assert_eq!(slots.get(other), Ok(&7));
    assert_eq!(slots.get(new), Ok(&8));
    for (_, value) in slots.iter_mut() {
        *value += 1;
    }
    assert!(slots.iter().map(|(_, value)| *value).eq([9, 8]));
    Ok(())
}

#[test]
fn restored_slots_advance_generation_and_retire_independently() -> Result<(), Error> {
    let mut backing = [const { Entry::vacant() }; 3];
    let mut slots = Table::in_storage(&mut backing);
    slots.restore_entry(1, u64::MAX, 1)?;
    slots.restore_entry(2, 41, 2)?;
    assert!(matches!(
        slots.next_key(),
        Err(Error::Protocol(Fault::Conflict))
    ));
    slots.finish_restore();
    let saturated = slots.slot_at(1).ok_or(Fault::NotReady)?;
    let restored = slots.slot_at(2).ok_or(Fault::NotReady)?;
    assert_eq!(slots.remove(restored), Ok(2));
    assert_eq!(slots.remove(saturated), Ok(1));
    assert_eq!(
        slots.restore_entry(2, restored.generation, 8),
        Err(Fault::Malformed.into()),
        "restore must not revive a previously issued generation"
    );
    let next = slots.insert(3).map_err(|(error, _)| error)?;
    assert_eq!(coordinates(next), (2, 42));
    let unused = slots.insert(4).map_err(|(error, _)| error)?;
    assert_eq!(coordinates(unused), (0, 1));
    assert!(matches!(
        slots.insert(5),
        Err((Error::Protocol(Fault::Capacity), 5))
    ));
    assert_eq!(slots.get(restored), Err(Fault::StaleGeneration.into()));
    assert_eq!(slots.get(saturated), Err(Fault::StaleGeneration.into()));
    Ok(())
}

#[test]
fn borrowed_slots_drop_owned_rows_before_returning_storage() {
    #[derive(Debug)]
    struct Row<'a>(&'a Cell<usize>);

    impl Drop for Row<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    let drops = Cell::new(0);
    let mut backing = [const { Entry::vacant() }; 1];
    {
        let mut slots = Table::in_storage(&mut backing);
        assert!(slots.insert(Row(&drops)).is_ok());
    }
    assert_eq!(drops.get(), 1, "slot ownership ends with the table");
    let mut reused = Table::in_storage(&mut backing);
    assert_eq!(reused.len(), 0);
    assert!(reused.insert(Row(&drops)).is_ok());
}

#[cfg(feature = "alloc")]
#[test]
fn owned_slots_grow_only_with_budget_and_keep_allocation_order() -> Result<(), Error> {
    let mut slots = Slots::new(3)?;
    let live = slots.insert(4).map_err(|(error, _)| error)?;
    let removed = slots.insert(7).map_err(|(error, _)| error)?;
    assert_eq!(slots.remove(removed), Ok(7));

    let old_bytes = slots.bytes()?;
    assert_eq!(slots.grow_to(5, 0), Err(Fault::Capacity.into()));
    assert_eq!(slots.limit(), 3);
    assert_eq!(slots.bytes(), Ok(old_bytes));
    assert_eq!(slots.get(live), Ok(&4));
    let next = slots.next_key()?;
    assert_eq!(coordinates(next), (1, 2));

    let growth = slots.grow_to(5, usize::MAX)?;
    assert_eq!(slots.bytes(), Ok(old_bytes + growth));
    assert_eq!(slots.limit(), 5);
    assert_eq!(slots.get(live), Ok(&4));
    for want in [(1, 2), (2, 1), (3, 1), (4, 1)] {
        let slot = slots.insert(0).map_err(|(error, _)| error)?;
        assert_eq!(coordinates(slot), want);
    }
    assert_eq!(slots.get(removed), Err(Fault::StaleGeneration.into()));
    Ok(())
}
