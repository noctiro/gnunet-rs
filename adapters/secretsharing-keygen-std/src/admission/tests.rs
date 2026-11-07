//! Pure production-path admission cases only; no identity, proof, source,
//! Paillier key or completed DKG is supplied by these shapes.
use super::*;

fn check(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(Fault::Malformed.into())
    }
}
fn peer(index: u16) -> [u8; 32] {
    let mut value = [0; 32];
    value[..2].copy_from_slice(&index.to_be_bytes());
    value
}
fn peers(count: u16) -> Result<Vec<[u8; 32]>, Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(usize::from(count))
        .map_err(|_| Fault::Capacity)?;
    for index in 0..count {
        values.push(peer(index));
    }
    Ok(values)
}
fn normalized(
    original: &[[u8; 32]],
    local: &[u8; 32],
    threshold: usize,
    peer_limit: usize,
) -> Result<(Vec<[u8; 32]>, usize), Error> {
    let mut roster = Vec::new();
    roster
        .try_reserve_exact(normalized_count(original, local)?)
        .map_err(|_| Fault::Capacity)?;
    let capacity = roster.capacity();
    let pointer = roster.as_ptr();
    let index = normalize_reserved(&mut roster, original, local, threshold, peer_limit)?;
    check(roster.capacity() == capacity && roster.as_ptr() == pointer)?;
    Ok((roster, index))
}
fn capacity<T>(value: Result<T, Error>) -> Result<(), Error> {
    check(matches!(value, Err(Error::Protocol(Fault::Capacity))))
}

#[test]
fn actual_local_inclusion_precedes_official_reveal_envelope() -> Result<(), Error> {
    let raw = peers(38)?;
    let (roster, local) = normalized(&raw, &peer(17), 6, 1024)?;
    check(roster.len() == 38 && local == 17)?;
    check(reveal_extent(roster.len(), 6)? == 64256)?;
    // The same raw count becomes39 only when the actual local peer is missing.
    check(normalized_count(&raw, &peer(90))? == 39)?;
    capacity(normalized(&raw, &peer(90), 1, 1024))?;
    capacity(normalized(&raw, &peer(17), 7, 1024))
}

#[test]
fn empty_duplicate_threshold_and_peer_limit_keep_original_meaning() -> Result<(), Error> {
    let (roster, local) = normalized(&[], &peer(5), 1, 1024)?;
    check(roster == [peer(5)] && local == 0 && reveal_extent(1, 1)? == 1900)?;
    check(matches!(
        normalized(&[peer(1), peer(1)], &peer(1), 1, 1024),
        Err(Error::Protocol(Fault::Conflict)),
    ))?;
    capacity(normalized(&[peer(3)], &peer(2), 3, 1024))?;
    capacity(normalized(&[peer(3)], &peer(2), 1, 1))?;
    check(matches!(
        normalized(&[], &peer(5), 0, 1024),
        Err(Error::Protocol(Fault::InvalidInput)),
    ))
}

#[test]
fn original_sorted_indices_and_full_roster_survive_stage_shape_checks() -> Result<(), Error> {
    let (roster, local) = normalized(&[peer(7), peer(1)], &peer(3), 2, 1024)?;
    check(roster == [peer(1), peer(3), peer(7)] && local == 1)?;
    // This API takes the original roster, with no candidate/commitment bitmap
    // from which missing or excluded recipients could shrink the proof slots.
    check(round2_reveal_extent(&roster, 2, 65529, 65535)? == 5364)?;
    check(roster == [peer(1), peer(3), peer(7)] && roster[local] == peer(3))
}

#[test]
fn later_selected_payload_and_frame_caps_are_independent_from_round1() -> Result<(), Error> {
    let round1 = crate::Limits {
        consensus: gnunet_consensus_client_host::Limits {
            frame_bytes: 430,
            ..Default::default()
        },
        ..Default::default()
    };
    round1.validate()?;
    let (roster, _) = normalized(&[peer(1)], &peer(2), 2, round1.peers)?;
    let required = round2_reveal_extent(&roster, 2, 3696, 3702)?;
    check(required == 3696 && required > round1.consensus.frame_bytes)?;
    capacity(round2_reveal_extent(&roster, 2, 3695, 3702))?;
    capacity(round2_reveal_extent(&roster, 2, 3696, 3701))
}

#[test]
fn local_ipc_representability_does_not_widen_the_official_peer_envelope() -> Result<(), Error> {
    let roster = peers(39)?;
    let required = secretsharing::reveal_encoded_len(roster.len(), 1)?;
    check(required == 65284 && required + 6 <= 65535)?;
    capacity(round2_reveal_extent(&roster, 1, 65529, 65535))
}

#[test]
fn checked_extent_and_reserved_normalization_do_not_allocate_past_admission() -> Result<(), Error> {
    check(matches!(
        reveal_extent(usize::MAX, 1),
        Err(Error::Protocol(Fault::Overflow))
    ))?;
    check(matches!(
        reveal_extent(1, usize::MAX),
        Err(Error::Protocol(Fault::Overflow))
    ))?;
    let mut roster = Vec::new();
    capacity(normalize_reserved(
        &mut roster,
        &[peer(1)],
        &peer(2),
        1,
        1024,
    ))?;
    check(roster.is_empty() && roster.capacity() == 0)
}
