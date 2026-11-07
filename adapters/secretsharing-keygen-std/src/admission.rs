//! Original unqualified roster and reveal-envelope admission. These checks
//! create no native source, identity, entropy, secret or mathematical authority.
use crate::Error;
use gnunet_types::Error as Fault;
use gnunet_wire::official::{consensus, secretsharing};

/// Count the actual local inclusion before the owner preclaims its one roster
/// allocation and all later metadata. Duplicate peers are deliberately retained.
pub(crate) fn normalized_count(peers: &[[u8; 32]], local: &[u8; 32]) -> Result<usize, Error> {
    peers
        .len()
        .checked_add(usize::from(!peers.contains(local)))
        .ok_or_else(|| Fault::Overflow.into())
}

/// Fill only the owner's already-accounted roster allocation. The original
/// sort, duplicate Conflict, threshold and local index precede reveal admission.
/// No reserve, deduplication or reduction of the requested threshold occurs.
pub(crate) fn normalize_reserved(
    roster: &mut Vec<[u8; 32]>,
    peers: &[[u8; 32]],
    local: &[u8; 32],
    threshold: usize,
    peer_limit: usize,
) -> Result<usize, Error> {
    if !roster.is_empty() {
        return Err(Fault::Stale.into());
    }
    let include_local = !peers.contains(local);
    let count = peers
        .len()
        .checked_add(usize::from(include_local))
        .ok_or(Fault::Overflow)?;
    if roster.capacity() < count {
        return Err(Fault::Capacity.into());
    }
    roster.extend_from_slice(peers);
    if include_local {
        roster.push(*local);
    }
    roster.sort_unstable();
    if roster.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(Fault::Conflict.into());
    }
    if threshold == 0 {
        return Err(Fault::InvalidInput.into());
    }
    if roster.len() > peer_limit || threshold > roster.len() {
        return Err(Fault::Capacity.into());
    }
    let index = roster
        .binary_search(local)
        .map_err(|_| Fault::PermissionDenied)?;
    reveal_extent(roster.len(), threshold)?;
    Ok(index)
}

/// Actual official reveal envelope, before any phase's separately selected IPC
/// policy. A local CONSENSUS frame fitting u16 does not prove SET/CADET carriage.
fn reveal_extent(peers: usize, threshold: usize) -> Result<usize, Error> {
    let required = secretsharing::reveal_encoded_len(peers, threshold)?;
    if required > consensus::MAX_APPLICATION_ELEMENT_BYTES {
        return Err(Fault::Capacity.into());
    }
    Ok(required)
}

/// Use the immutable original roster, never a filtered commitment/candidate
/// count. The Round2-selected payload and complete521/523 frame caps both apply.
pub(crate) fn round2_reveal_extent(
    roster: &[[u8; 32]],
    threshold: usize,
    reveal_limit: usize,
    frame_limit: usize,
) -> Result<usize, Error> {
    let required = reveal_extent(roster.len(), threshold)?;
    // Official CONSENSUS INSERT/RECEIVED_ELEMENT: header4 + element_type2.
    let frame = required.checked_add(6).ok_or(Fault::Overflow)?;
    if required > reveal_limit || frame > frame_limit {
        return Err(Fault::Capacity.into());
    }
    Ok(required)
}

#[cfg(test)]
mod tests;
