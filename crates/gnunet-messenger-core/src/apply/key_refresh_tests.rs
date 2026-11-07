//! Pure state transitions over the existing public mock metadata helpers.
//! No crypto/signature acceptance, codec, entropy, native or storage execution
//! is represented by these cases. Production signature admission is unchanged.
use super::*;
use crate::model::{node, session, structural_core};

fn room_state<'id>(core: &mut Core<'id>) -> Result<(Slot, Slot, Slot), Error> {
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
    let room = core.room([1; 64], None)?;
    let r = room.slot;
    let brand = core.instance;
    let mut member = session(brand, 1, 1);
    member.contact.slot = contact;
    member.first_bound = [1; 64];
    member.last_bound = [1; 64];
    let row = core.rooms.get_mut(r)?;
    let member = row.sessions.insert(member).map_err(|(error, _)| error)?;
    let mut join = node(brand, 1, 0, 1, 1, 1)?;
    join.kind = Kind::JOIN;
    join.semantic_kind = Kind::JOIN;
    join.auth.as_mut().ok_or(Fault::Conflict)?.session = Some(member);
    join.complete = true;
    row.insert_node(join).map_err(|rejected| rejected.error)?;
    let mut refresh = node(brand, 2, 1, 1, 1, 2)?;
    refresh.kind = Kind::KEY;
    refresh.semantic_kind = Kind::KEY;
    refresh.semantic_applied = false;
    refresh.auth.as_mut().ok_or(Fault::Conflict)?.session = Some(member);
    let refresh = row
        .insert_node(refresh)
        .map_err(|rejected| rejected.error)?;
    Ok((r, member, refresh))
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Fallible public structural-state setup with transition assertions"
)]
fn same_signer_hpke_refresh_and_cached_auth_follow_the_actual_key_ancestry() -> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let (r, original, refresh) = room_state(&mut core)?;
    core.switch_session(r, refresh, Some(([3; 36], [5; 36])), None)?;
    let current = core
        .rooms
        .get(r)?
        .sessions
        .get(original)?
        .successor
        .ok_or(Fault::Conflict)?;
    assert_eq!(core.rooms.get(r)?.sessions.get(original)?.hpke, [4; 36]);
    assert_eq!(core.rooms.get(r)?.sessions.get(current)?.hpke, [5; 36]);
    assert_eq!(core.rooms.get(r)?.sessions.get(current)?.generation, 2);
    // Complete the caller's original apply_one boundary; the first accepted
    // KEY's own historical authentication must remain the original generation.
    core.rooms
        .get_mut(r)?
        .nodes
        .get_mut(refresh)?
        .semantic_applied = true;
    let brand = core.instance;
    let mut bridge = node(brand, 3, 2, 1, 2, 3)?;
    bridge.auth.as_mut().ok_or(Fault::Conflict)?.session = Some(current);
    core.rooms
        .get_mut(r)?
        .insert_node(bridge)
        .map_err(|rejected| rejected.error)?;
    let mut second = node(brand, 4, 2, 1, 1, 4)?;
    second.kind = Kind::KEY;
    second.semantic_kind = Kind::KEY;
    second.semantic_applied = false;
    second.parents[1] = [3; 64]; // An actual diamond; visit each Slot only once.
    // Represents a verified response cached before the first KEY was applied.
    second.auth.as_mut().ok_or(Fault::Conflict)?.session = Some(original);
    let second = core
        .rooms
        .get_mut(r)?
        .insert_node(second)
        .map_err(|rejected| rejected.error)?;
    let baseline = core.charged_bytes();
    core.switch_session(r, second, Some(([3; 36], [6; 36])), None)?;
    assert_eq!(core.charged_bytes(), baseline);
    let row = core.rooms.get(r)?;
    let latest = row
        .sessions
        .get(current)?
        .successor
        .ok_or(Fault::Conflict)?;
    assert_eq!(row.sessions.get(latest)?.generation, 3);
    assert_eq!(row.sessions.get(latest)?.hpke, [6; 36]);
    assert!(row.nodes.get(refresh)?.auth.ok_or(Fault::Conflict)?.session == Some(original));
    assert!(row.nodes.get(second)?.auth.ok_or(Fault::Conflict)?.session == Some(current));
    assert!(
        row.nodes.get(second)?.auth.ok_or(Fault::Conflict)?.owner
            == Some(owner(row.sessions.get(current)?))
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Fallible public structural-state setup with refusal assertions"
)]
fn exact_key_unauthenticated_and_unproven_old_branch_do_not_change_the_active_key()
-> Result<(), Error> {
    let mut instance = Instance::new();
    let mut core = structural_core(&mut instance)?;
    let (r, original, refresh) = room_state(&mut core)?;
    assert_eq!(
        core.switch_session(r, refresh, Some(([3; 36], [4; 36])), None),
        Err(Fault::Replay.into())
    );
    let auth = core.rooms.get_mut(r)?.nodes.get_mut(refresh)?.auth.take();
    assert_eq!(
        core.switch_session(r, refresh, Some(([3; 36], [5; 36])), None),
        Err(Fault::Authentication.into())
    );
    core.rooms.get_mut(r)?.nodes.get_mut(refresh)?.auth = auth;
    core.switch_session(r, refresh, Some(([3; 36], [5; 36])), None)?;
    core.rooms
        .get_mut(r)?
        .nodes
        .get_mut(refresh)?
        .semantic_applied = true;
    let current = core
        .rooms
        .get(r)?
        .sessions
        .get(original)?
        .successor
        .ok_or(Fault::Conflict)?;
    let brand = core.instance;
    let mut branch = node(brand, 5, 1, 1, 1, 3)?;
    branch.kind = Kind::KEY;
    branch.semantic_kind = Kind::KEY;
    branch.semantic_applied = false;
    branch.auth.as_mut().ok_or(Fault::Conflict)?.session = Some(original);
    let branch = core
        .rooms
        .get_mut(r)?
        .insert_node(branch)
        .map_err(|rejected| rejected.error)?;
    let baseline = core.charged_bytes();
    // A fresh hash, equal public identity, and later arrival cannot authorize
    // forwarding an old branch across a KEY absent from its signed ancestry.
    assert_eq!(
        core.switch_session(r, branch, Some(([3; 36], [6; 36])), None),
        Err(Fault::Replay.into())
    );
    assert_eq!(core.charged_bytes(), baseline);
    core.rooms.get_mut(r)?.nodes.get_mut(branch)?.parents[0] = [9; 64];
    assert_eq!(
        core.switch_session(r, branch, Some(([3; 36], [6; 36])), None),
        Err(Fault::NotReady.into())
    );
    assert_eq!(core.charged_bytes(), baseline);
    let row = core.rooms.get(r)?;
    assert_eq!(row.sessions.len(), 2);
    assert_eq!(row.sessions.get(current)?.hpke, [5; 36]);
    assert!(row.nodes.get(branch)?.auth.ok_or(Fault::Conflict)?.session == Some(original));
    Ok(())
}
