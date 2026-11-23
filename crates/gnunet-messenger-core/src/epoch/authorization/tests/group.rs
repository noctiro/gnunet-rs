//! Group-proposal authorization keeps level, proposal and sender linkage exact.
use super::*;

#[test]
fn first_level_proposal_can_join_two_members_of_the_same_announcement() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let scope = setup(&mut core)?;
    let mut identifier = TARGET;
    identifier[0] = 0;
    let partner = core
        .contacts
        .insert(ContactRow {
            key: [11; 36],
            name: None,
            anonymous_context: None,
            local: false,
            canonical: true,
            rooms: 1,
        })
        .map_err(|(e, _)| e)?;
    let mut announcement = node(core.instance, 4, 2, 1, 1, 3)?;
    announcement.origin = NodeOrigin::from_source(scope.source, SourceRole::Client);
    announcement.epoch = EPOCH;
    announcement.kind = Kind::ANNOUNCEMENT;
    announcement.frame = Some(
        encoded(Body::Announcement {
            identifier: &identifier,
            public_key: &[0; 32],
            nonce: &[8; 32],
            timeout: gnunet_wire::official::RelativeTime::from_micros(100),
            hmac: &[0; 64],
        })?
        .into(),
    );
    announcement
        .auth
        .as_mut()
        .and_then(|auth| auth.owner.as_mut())
        .ok_or(Fault::Conflict)?
        .contact = partner;
    announcement.complete = true;
    announcement.semantic_applied = true;
    let room = core.rooms.get_mut(scope.room)?;
    let original = room.nodes.get_mut(scope.announcement)?;
    original.complete = true;
    original.semantic_applied = true;
    original.frame = Some(
        encoded(Body::Announcement {
            identifier: &identifier,
            public_key: &[0; 32],
            nonce: &[7; 32],
            timeout: gnunet_wire::official::RelativeTime::from_micros(100),
            hmac: &[0; 64],
        })?
        .into(),
    );
    let partner_node = room.insert_node(announcement)?;
    let epoch = room.epochs.get_mut(scope.epoch)?;
    epoch.members.add_contact(partner);
    let group = epoch.groups.get_mut(scope.target)?;
    group.identifier = identifier;
    group.target = 2;
    group.confirmations.push(Confirmation {
        contact: partner,
        message: [4; 64],
        verified_mac: false,
    });
    core.check_group_parents(
        scope.room,
        scope.epoch,
        1,
        [scope.announcement, partner_node],
        scope.sender,
    )?;
    assert!(matches!(
        core.check_group_parents(
            scope.room,
            scope.epoch,
            1,
            [scope.announcement, partner_node],
            partner,
        ),
        Err(Error::Permission)
    ));
    assert!(matches!(
        core.check_group_parents(
            scope.room,
            scope.epoch,
            1,
            [scope.announcement, scope.announcement],
            scope.sender,
        ),
        Err(Error::Permission)
    ));
    Ok(())
}

#[test]
fn proposal_transfer_requires_next_level_and_the_original_senders_announcement() -> Result<(), Error>
{
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let scope = setup(&mut core)?;
    let target_id = [5; 32];
    let mut group_scope = |index: u8, body: Body<'_>| -> Result<Slot, Error> {
        let mut value = node(core.instance, index, 2, 1, 1, u64::from(index))?;
        value.origin = NodeOrigin::from_source(scope.source, SourceRole::Client);
        value.epoch = EPOCH;
        value.kind = body.kind();
        value.complete = true;
        value.frame = Some(encoded(body)?.into());
        value
            .auth
            .as_mut()
            .ok_or(Fault::Conflict)?
            .owner
            .as_mut()
            .ok_or(Fault::Conflict)?
            .contact = scope.sender;
        core.rooms.get_mut(scope.room)?.insert_node(value)
    };
    let announcement = |id| Body::Announcement {
        identifier: id,
        public_key: &[0; 32],
        nonce: &[7; 32],
        timeout: gnunet_wire::official::RelativeTime::from_micros(100),
        hmac: &[0; 64],
    };
    group_scope(4, announcement(&WRAP))?;
    group_scope(5, announcement(&[7; 32]))?;
    let proposal = group_scope(
        6,
        Body::Group {
            identifier: &target_id,
            initiator: &[4; 64],
            partner: &[5; 64],
            timeout: gnunet_wire::official::RelativeTime::from_micros(100),
        },
    )?;
    let target = core
        .rooms
        .get_mut(scope.room)?
        .epochs
        .get_mut(scope.epoch)?
        .groups
        .get_mut(scope.target)?;
    target.identifier = target_id;
    target.confirmations.clear();
    target.proposal = Some([6; 64]);
    target.expires = 110;
    core.reserve_group_proposal(scope.room)?;
    core.rooms
        .get_mut(scope.room)?
        .group_proposals
        .push(GroupProposalBinding {
            identifier: target_id,
            epoch: scope.epoch,
            node: proposal,
            order: Endian::Little,
        });

    assert!(
        core.authorization_target(scope.room, scope.epoch, WRAP, proposal, scope.sender)?
            == (scope.target, None, 110),
        "the admitted proposal targets its original next-level group"
    );
    core.rooms
        .get_mut(scope.room)?
        .epochs
        .get_mut(scope.epoch)?
        .groups
        .get_mut(scope.target)?
        .proposal = Some([10; 64]);
    assert!(matches!(
        core.authorization_target(scope.room, scope.epoch, WRAP, proposal, scope.sender),
        Err(Error::Permission)
    ));
    core.rooms
        .get_mut(scope.room)?
        .epochs
        .get_mut(scope.epoch)?
        .groups
        .get_mut(scope.target)?
        .proposal = Some([6; 64]);

    let foreign = core
        .contacts
        .insert(ContactRow {
            key: [11; 36],
            name: None,
            anonymous_context: None,
            local: false,
            canonical: true,
            rooms: 1,
        })
        .map_err(|(e, _)| e)?;
    assert!(matches!(
        core.authorization_target(scope.room, scope.epoch, WRAP, proposal, foreign),
        Err(Error::Permission)
    ));
    let wrong_level = [7; 32];
    core.rooms
        .get_mut(scope.room)?
        .epochs
        .get_mut(scope.epoch)?
        .groups
        .get_mut(scope.target)?
        .identifier = wrong_level;
    core.rooms
        .get_mut(scope.room)?
        .nodes
        .get_mut(proposal)?
        .frame = Some(
        encoded(Body::Group {
            identifier: &wrong_level,
            initiator: &[4; 64],
            partner: &[5; 64],
            timeout: gnunet_wire::official::RelativeTime::from_micros(100),
        })?
        .into(),
    );
    assert!(matches!(
        core.authorization_target(scope.room, scope.epoch, WRAP, proposal, scope.sender),
        Err(Error::Permission)
    ));
    core.rooms
        .get_mut(scope.room)?
        .epochs
        .get_mut(scope.epoch)?
        .groups
        .get_mut(scope.target)?
        .identifier = target_id;
    core.rooms
        .get_mut(scope.room)?
        .nodes
        .get_mut(proposal)?
        .frame = Some(
        encoded(Body::Group {
            identifier: &target_id,
            initiator: &[4; 64],
            partner: &[5; 64],
            timeout: gnunet_wire::official::RelativeTime::from_micros(100),
        })?
        .into(),
    );
    assert!(core.events.is_empty());
    core.rooms
        .get_mut(scope.room)?
        .epochs
        .get_mut(scope.epoch)?
        .groups
        .get_mut(scope.target)?
        .expires = 110;
    apply_event(&mut core, &scope, [6; 64], false, 10)?;
    assert_eq!(
        core.rooms
            .get(scope.room)?
            .epochs
            .get(scope.epoch)?
            .groups
            .get(scope.target)?
            .phase,
        KeyPhase::Present
    );
    let deadline = core.group_proposal_deadline(scope.room, scope.epoch, target_id, [6; 64])?;
    core.rooms
        .get_mut(scope.room)?
        .epochs
        .get_mut(scope.epoch)?
        .groups
        .get_mut(scope.target)?
        .expires = deadline;
    core.expire_epochs(scope.room, deadline)?;
    let epoch = core.rooms.get(scope.room)?.epochs.get(scope.epoch)?;
    assert_eq!(epoch.groups.get(scope.target)?.proposal, Some([6; 64]));
    assert!(matches!(
        apply_event(&mut core, &scope, [6; 64], false, deadline),
        Err(Error::Protocol(Fault::Timeout))
    ));
    assert!(matches!(
        apply_event(&mut core, &scope, [6; 64], false, deadline - 1),
        Err(Error::Protocol(Fault::Timeout))
    ));
    Ok(())
}
