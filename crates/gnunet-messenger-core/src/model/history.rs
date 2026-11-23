use super::*;
use gnunet_types::Error as Fault;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions check history admission and actual tombstone traversal"
)]
fn caller_memory_preserves_tombstone_history_and_member_cutoff() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let brand = core.instance;
    let room = core.room([1; 64], None)?;
    let row = core.rooms.get_mut(room.slot)?;
    let original = row.sessions.insert(session(1, 1)).map_err(|(e, _)| e)?;
    let mut later = session(2, 1);
    later.known_from = 2;
    let later = row.sessions.insert(later).map_err(|(e, _)| e)?;

    row.insert_node(node(brand, 1, 0, 1, 1, 1)?)?;
    for (hash, parent, sequence) in [(2, 1, 2), (3, 1, 3), (4, 2, 4)] {
        let mut child = node(brand, hash, parent, 1, 1, sequence)?;
        if hash == 4 {
            child.parents[1] = [3; 64];
        }
        let slot = row.insert_node(child)?;
        row.erase_message(&mut core.frames, slot, None)?;
    }
    let member = brand.member_id(room.slot, original);
    let mut insufficient = HistoryWorkspace::new(1)?;
    assert!(matches!(
        core.history(member, &[4; 64], &mut insufficient),
        Err(Error::Protocol(Fault::Capacity))
    ));

    let mut cells = [HistoryCell::EMPTY; 16];
    let mut workspace = HistoryWorkspace::from_cells(&mut cells)?;
    {
        let mut walk = core.history(member, &[4; 64], &mut workspace)?;
        let item = walk.try_next()?.ok_or(Fault::NotReady)?;
        assert_eq!(item.hash(), &[1; 64]);
        assert_eq!(item.original(), Some(b"PUBLIC!!".as_slice()));
        assert!(walk.try_next()?.is_none());
    }
    let later = brand.member_id(room.slot, later);
    let mut walk = core.history(later, &[4; 64], &mut workspace)?;
    assert!(matches!(walk.try_next(), Err(Error::Permission)));
    Ok(())
}
