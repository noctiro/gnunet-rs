//! Parent-selection policy over explicit structural eligibility metadata.
//! Real admission/MAC/decryption coverage lives in recipient::tests::derivation.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible structural policy assertions"
)]
use super::*;
use crate::model::{node, structural_core};

const FIRST: Hash = [11; 64];
const SECOND: Hash = [12; 64];
const CHILD: Hash = [13; 64];
const ANNOUNCEMENT: ShortHash = [0; 32];
const GROUP: ShortHash = [1; 32];

fn stage(core: &mut Core<'_>) -> Result<(Slot, Slot, Slot, Slot), Error> {
    let contact = core
        .contacts
        .insert(ContactRow {
            key: [3; 36],
            name: None,
            anonymous_context: None,
            local: false,
            canonical: true,
            rooms: 1,
        })
        .map_err(|(error, _)| error)?;
    let leaving = core
        .contacts
        .insert(ContactRow {
            key: [4; 36],
            name: None,
            anonymous_context: None,
            local: false,
            canonical: true,
            rooms: 1,
        })
        .map_err(|(error, _)| error)?;
    let room = core.room([1; 64], None)?;
    let mut predecessor = node(core.instance, 14, 0, 1, 1, 1)?;
    predecessor.epoch = FIRST;
    core.rooms.get_mut(room.slot)?.insert_node(predecessor)?;
    let mut child = node(core.instance, 13, 14, 1, 1, 2)?;
    child.kind = wire::envelope::Kind::MERGE;
    child.epoch = CHILD;
    core.rooms.get_mut(room.slot)?.insert_node(child)?;
    let mut result = [room.slot; 3];
    for (index, hash) in [FIRST, SECOND, CHILD].into_iter().enumerate() {
        let mut epoch = EpochRow {
            hash,
            parents: if index == 2 {
                [FIRST, SECOND]
            } else {
                [[0; 64]; 2]
            },
            mutation: EpochMutation::Merge,
            members: crate::epoch::members::Snapshot::from_contacts([contact, leaving]),
            complete: true,
            groups: Slots::new(4)?,
            historical_groups: 0,
            nonces: Vec::with_capacity(4),
            revision: 1,
            ephemeral: None,
            best_announcement: None,
            best_group: None,
        };
        if index < 2 {
            for identifier in [ANNOUNCEMENT, GROUP] {
                let mut confirmations = alloc::vec![Confirmation {
                    contact,
                    message: [20 + index as u8; 64],
                    verified_mac: true
                }];
                if identifier == ANNOUNCEMENT {
                    confirmations.push(Confirmation {
                        contact: leaving,
                        message: [30 + index as u8; 64],
                        verified_mac: true,
                    });
                }
                epoch
                    .groups
                    .insert(GroupRow {
                        identifier,
                        identifier_order: Endian::Little,
                        target: confirmations.len(),
                        valid: true,
                        phase: KeyPhase::Present,
                        key: Some(crypto::AeadKey::from_bytes([20 + index as u8; 32])),
                        key_custody: GroupKeyCustody::Retained,
                        confirmations,
                        expires: u64::MAX,
                        appeal: None,
                        appeal_until: 0,
                        proposal: None,
                        generation: 1,
                        derived_from: None,
                    })
                    .map_err(|(error, _)| error)?;
            }
        }
        result[index] = core
            .rooms
            .get_mut(room.slot)?
            .epochs
            .insert(epoch)
            .map_err(|(error, _)| error)?;
    }
    Ok((room.slot, result[0], result[2], leaving))
}

#[test]
fn announcement_uses_the_actual_first_predecessor_and_subgroup_can_use_the_other_parent()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let (room, first, child, _) = stage(&mut core)?;
    let (_, parent) = core
        .inherited_group_key(room, child, &ANNOUNCEMENT, Endian::Little)?
        .ok_or(Fault::NotReady)?;
    assert_eq!(parent, FIRST);
    for (_, group) in core
        .rooms
        .get_mut(room)?
        .epochs
        .get_mut(first)?
        .groups
        .iter_mut()
    {
        group.key = None;
        group.phase = KeyPhase::Missing;
        group.confirmations.clear();
    }
    assert!(
        core.inherited_group_key(room, child, &ANNOUNCEMENT, Endian::Little)?
            .is_none()
    );
    let (_, parent) = core
        .inherited_group_key(room, child, &GROUP, Endian::Little)?
        .ok_or(Fault::NotReady)?;
    assert_eq!(parent, SECOND);
    Ok(())
}

#[test]
fn leave_refuses_announcement_inheritance_but_preserves_a_compatible_subgroup() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let (room, _, child, contact) = stage(&mut core)?;
    let epoch = core.rooms.get_mut(room)?.epochs.get_mut(child)?;
    epoch.mutation = EpochMutation::Leave(contact);
    epoch.members.remove_contact(contact);
    assert!(
        core.inherited_group_key(room, child, &ANNOUNCEMENT, Endian::Little)?
            .is_none()
    );
    let (_, parent) = core
        .inherited_group_key(room, child, &GROUP, Endian::Little)?
        .ok_or(Fault::NotReady)?;
    assert_eq!(parent, FIRST);
    Ok(())
}

#[test]
fn a_revoked_first_parent_tie_cannot_revive_the_other_parents_key() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let (room, first, child, _) = stage(&mut core)?;
    let (_, selected) = core
        .inherited_group_key(room, child, &GROUP, Endian::Little)?
        .ok_or(Fault::NotReady)?;
    assert_eq!(selected, FIRST);
    for (_, group) in core
        .rooms
        .get_mut(room)?
        .epochs
        .get_mut(first)?
        .groups
        .iter_mut()
    {
        group.valid = false;
        group.phase = KeyPhase::Revoked;
    }
    assert!(
        core.inherited_group_key(room, child, &GROUP, Endian::Little)?
            .is_none()
    );
    Ok(())
}
