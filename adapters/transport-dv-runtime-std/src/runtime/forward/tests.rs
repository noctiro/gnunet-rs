//! Owned opaque packet/metadata fixtures. These use Engine-minted client IDs
//! but no PILS Identity, crypto grant, native output, FC receipt or remote DONE.
use super::*;

fn check(condition: bool) -> Result<(), Protocol> {
    if condition {
        Ok(())
    } else {
        Err(Protocol::Conflict)
    }
}
fn token(instance: &Instance) -> Result<Token<'_>, Protocol> {
    Ok(Token {
        domain: instance,
        serial: instance.next()?,
    })
}
fn neighbour<'id>(
    instance: &'id Instance,
    client: &gnunet_transport::ClientId,
    peer: PeerId,
) -> Result<Neighbour<'id>, Protocol> {
    Ok(Neighbour {
        token: token(instance)?,
        client: client.clone(),
        peer,
        queue: 7,
        reverse: true,
    })
}
fn input<'id>(
    instance: &'id Instance,
    incoming: Neighbour<'id>,
    origin: u8,
) -> Result<InputRow<'id, 'id, 'id, 'id, u8>, Protocol> {
    let mut bytes = sized(dv::BOX_PREFIX + 64 + dv::PAYLOAD_PREFIX + 4)?;
    dv::BoxHeader {
        without_fc: false,
        encapsulation: [0x21; 32],
        nonce: [origin; 24],
        mac: [0x43; 16],
    }
    .encode(
        &[PeerId([3; 32]), PeerId([4; 32])],
        &[0x65; dv::PAYLOAD_PREFIX + 4],
        &mut bytes,
    )?;
    Ok(InputRow {
        token: token(instance)?,
        neighbour: incoming,
        origin: Some(origin),
        bytes,
        received: std::time::Instant::now(),
        bounds: Bound {
            until: 100,
            hard: Instant::now()
                .checked_add(std::time::Duration::from_secs(30))
                .ok_or(Protocol::Overflow)?,
        },
        state: InputState::Box,
        forwards: 0,
        planning: true,
        disposition: Disposition::Dropped,
        debt: None,
    })
}

#[test]
fn forwarding_moves_one_allocation_and_retains_the_original_parent() -> Result<(), Protocol> {
    let instance = Instance::new();
    let local = PeerId([1; 32]);
    let mut engine = gnunet_transport::Engine::new(local, gnunet_transport::Limits::default())?;
    let owner = engine.accept()?;
    let incoming = neighbour(&instance, &owner, PeerId([2; 32]))?;
    let next = neighbour(&instance, &owner, PeerId([3; 32]))?;
    let mut row = input(&instance, incoming.clone(), 9)?;
    // Deliberately retain a real unused allocation tail: route compaction must
    // not return that still-live capacity as new byte-pool credit.
    row.bytes
        .try_reserve_exact(37)
        .map_err(|_| Protocol::Capacity)?;
    check(row.bytes.capacity() > row.bytes.len())?;
    let original = copy(&row.bytes)?;
    let pointer = row.bytes.as_ptr();
    let capacity = row.bytes.capacity();
    let received = row.received;
    let parent = row.token;
    let budget = row.bounds.budget();
    let mut outputs = Vec::new();
    check(matches!(
        row.failure(&outputs, budget, budget.until, Instant::now(), None)
            .state,
        FailureState::Input {
            forwarding_child: None,
            ..
        }
    ))?;
    let output = start(
        &mut row,
        &mut outputs,
        core::slice::from_ref(&next),
        &instance,
        local,
        1,
        1,
    )?
    .ok_or(Protocol::NotReady)?;
    let child = outputs.first().ok_or(Protocol::NotFound)?;
    check(child.token == output && child.parent == Some(parent) && child.neighbour == next)?;
    check(
        child.bytes.as_ptr() == pointer
            && child.bytes.capacity() == capacity
            && row.bytes.capacity() == 0,
    )?;
    check(child.bytes.len() == original.len() - 32 && child.bytes[12..86] == original[12..86])?;
    let packet = dv::BoxPacket::decode(&child.bytes)?;
    check(packet.hop_count() == 1 && packet.hop(0)? == PeerId([4; 32]))?;
    check(packet.ciphertext() == [0x65; dv::PAYLOAD_PREFIX + 4])?;
    check(retained_packet_bytes(core::slice::from_ref(&row), &outputs) == capacity)?;
    check(row.origin == Some(9) && row.neighbour == incoming && row.received == received)?;
    check(row.bounds.until == budget.until.as_micros() && row.bounds.hard == budget.hard)?;
    check(child.bounds.until == row.bounds.until && child.bounds.hard == row.bounds.hard)?;
    check(matches!(row.state, InputState::Forwarding) && row.forwards == 1 && !row.planning)?;
    check(
        child.origin.is_none()
            && !child.queued
            && !child.exposed
            && child.state.outcome().is_none(),
    )?;
    // Use the same production pre-cancellation snapshot over the actual owned
    // rows. The test supplies only budget metadata, no ready PILS identity.
    let snapshot = row.failure(&outputs, budget, budget.until, Instant::now(), None);
    let FailureState::Input {
        forwarding_child: Some(forwarded),
        ..
    } = snapshot.state
    else {
        return Err(Protocol::NotFound);
    };
    check(forwarded.token == output && forwarded.phase == OutputPhase::Ready)?;
    check(!forwarded.queued && !forwarded.exposed && forwarded.outcome.is_none())?;
    check(forwarded.budget.until == budget.until && forwarded.budget.hard == budget.hard)?;
    // A missing match is diagnostic uncertainty; it cannot turn the same
    // original failure into a fabricated child result or an API refusal.
    check(matches!(
        row.failure(&[], budget, budget.until, Instant::now(), None)
            .state,
        FailureState::Input {
            forwarding_child: None,
            ..
        }
    ))?;
    // The output has never been exposed/admitted. Canceling this original
    // unadmitted child is an actual local Unsent fact, not a native success.
    check(!row.child_finished(WriteOutcome::Unsent))?;
    check(matches!(row.state, InputState::Finished) && row.forwards == 0)?;
    check(matches!(
        row.failure(&outputs, budget, budget.until, Instant::now(), None)
            .state,
        FailureState::Input {
            forwarding_child: None,
            ..
        }
    ))?;
    // The copied pre-cancel facts remain Ready/unknown, without a new receipt.
    check(forwarded.phase == OutputPhase::Ready && forwarded.outcome.is_none())?;
    check(row.origin == Some(9) && row.disposition == Disposition::Forwarded(WriteOutcome::Unsent))
}

#[test]
fn full_output_slot_preserves_input_and_only_real_release_retries_it() -> Result<(), Protocol> {
    let instance = Instance::new();
    let local = PeerId([1; 32]);
    let mut engine = gnunet_transport::Engine::new(local, gnunet_transport::Limits::default())?;
    let owner = engine.accept()?;
    let incoming = neighbour(&instance, &owner, PeerId([2; 32]))?;
    let next = neighbour(&instance, &owner, PeerId([3; 32]))?;
    let neighbours = [next];
    let mut first = input(&instance, incoming.clone(), 8)?;
    let mut blocked = input(&instance, incoming, 9)?;
    let original = copy(&blocked.bytes)?;
    let pointer = blocked.bytes.as_ptr();
    let capacity = blocked.bytes.capacity();
    let parent = blocked.token;
    let received = blocked.received;
    let budget = blocked.bounds.budget();
    let mut outputs = Vec::new();
    let first_output = start(
        &mut first,
        &mut outputs,
        &neighbours,
        &instance,
        local,
        1,
        1,
    )?
    .ok_or(Protocol::NotReady)?;
    let mut scan = InputScan::default();
    scan.begin(1);
    scan.take().ok_or(Protocol::NotFound)?;
    check(!scan.pending())?;
    for now in 2..10 {
        check(
            start(
                &mut blocked,
                &mut outputs,
                &neighbours,
                &instance,
                local,
                now,
                1,
            )?
            .is_none(),
        )?;
        check(
            blocked.bytes == original
                && blocked.bytes.as_ptr() == pointer
                && blocked.bytes.capacity() == capacity,
        )?;
        check(outputs.len() == 1 && !scan.pending())?;
        check(
            blocked.token == parent && blocked.origin == Some(9) && blocked.received == received,
        )?;
        check(
            blocked.bounds.until == budget.until.as_micros() && blocked.bounds.hard == budget.hard,
        )?;
        check(
            matches!(blocked.state, InputState::Box) && blocked.forwards == 0 && blocked.planning,
        )?;
    }
    // Retire the provably unadmitted child locally, then remove its actual
    // metadata slot. This is the same parent join used by finish_output.
    check(!first.child_finished(WriteOutcome::Unsent))?;
    let retired = outputs.pop().ok_or(Protocol::NotFound)?;
    check(!retired.queued && !retired.exposed && retired.parent == Some(first.token))?;
    drop(retired);
    scan.changed(1);
    scan.take().ok_or(Protocol::NotFound)?;
    let output = start(
        &mut blocked,
        &mut outputs,
        &neighbours,
        &instance,
        local,
        10,
        1,
    )?
    .ok_or(Protocol::NotReady)?;
    let child = outputs.first().ok_or(Protocol::NotFound)?;
    check(
        child.token == output && child.parent == Some(parent) && child.bytes.as_ptr() == pointer,
    )?;
    // Repeated refusals consumed no hidden output IDs either.
    check(
        output.serial
            == first_output
                .serial
                .checked_add(1)
                .ok_or(Protocol::Overflow)?,
    )?;
    check(child.bounds.until == budget.until.as_micros() && child.bounds.hard == budget.hard)?;
    check(
        blocked.origin == Some(9)
            && blocked.forwards == 1
            && matches!(blocked.state, InputState::Forwarding),
    )?;
    check(!scan.pending())
}

#[test]
fn original_deadline_and_invalid_layout_preserve_the_received_body() -> Result<(), Protocol> {
    let instance = Instance::new();
    let local = PeerId([1; 32]);
    let mut engine = gnunet_transport::Engine::new(local, gnunet_transport::Limits::default())?;
    let owner = engine.accept()?;
    let incoming = neighbour(&instance, &owner, PeerId([2; 32]))?;
    let next = neighbour(&instance, &owner, PeerId([4; 32]))?;
    let mut row = input(&instance, incoming, 9)?;
    let mut outputs = Vec::new();
    let original = copy(&row.bytes)?;
    let serial = token(&instance)?.serial;
    check(
        start(
            &mut row,
            &mut outputs,
            core::slice::from_ref(&next),
            &instance,
            local,
            100,
            1,
        ) == Err(Protocol::Deadline),
    )?;
    check(row.bytes == original && outputs.is_empty())?;
    check(token(&instance)?.serial == serial.checked_add(1).ok_or(Protocol::Overflow)?)?;
    // A larger opaque ciphertext makes the existing traversal counter legal,
    // but forwarding through two more entries would exceed MAX_HOPS.
    row.bytes = sized(dv::BOX_PREFIX + 64 + 600)?;
    dv::BoxHeader {
        without_fc: false,
        encapsulation: [0x21; 32],
        nonce: [9; 24],
        mac: [0x43; 16],
    }
    .encode(
        &[PeerId([3; 32]), PeerId([4; 32])],
        &[0x65; 600],
        &mut row.bytes,
    )?;
    row.bytes[8..10].copy_from_slice(&15u16.to_be_bytes());
    let original = copy(&row.bytes)?;
    check(
        start(
            &mut row,
            &mut outputs,
            core::slice::from_ref(&next),
            &instance,
            local,
            1,
            1,
        ) == Err(Protocol::TooLarge),
    )?;
    check(row.bytes == original && row.origin == Some(9) && outputs.is_empty())?;
    check(matches!(row.state, InputState::Box) && row.forwards == 0 && row.planning)
}
