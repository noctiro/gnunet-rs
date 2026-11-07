use super::*;
use crate::{CommitmentJob, Polynomial};
use alloc::vec;

fn scalar(value: u32) -> Result<Scalar, Error> {
    let mut bytes = [0; 128];
    bytes[124..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_bytes(&bytes)
}
fn coefficients(values: &[u32], group: &Group, limits: Limits) -> Result<Commitments, Error> {
    let mut scalars = Vec::new();
    scalars
        .try_reserve_exact(values.len())
        .map_err(|_| Error::Capacity)?;
    for value in values {
        scalars.push(scalar(*value)?);
    }
    let polynomial = Polynomial::from_coefficients(scalars, limits)?;
    let mut job = CommitmentJob::new_owned(polynomial, group)?;
    for _ in 0..100_000 {
        if job.advance(limits.units_per_turn)? == Progress::Ready {
            let (_, coefficients) = job.take_owned_result()?;
            return Ok(coefficients);
        }
    }
    Err(Error::Capacity)
}
fn contribution(
    peer: u8,
    index: u16,
    values: &[u32],
    local_share: u32,
    group: &Group,
    limits: Limits,
) -> Result<AggregateContribution, Error> {
    Ok(AggregateContribution::new(
        [peer; 32],
        index,
        coefficients(values, group, limits)?,
        scalar(local_share)?,
    ))
}
fn finish(job: &mut AggregateJob, units: u16) -> Result<AggregateMaterial, Error> {
    for _ in 0..100_000 {
        if job.advance(units)? == Progress::Ready {
            return job.take_result();
        }
    }
    Err(Error::Capacity)
}
fn check_secret(actual: &Scalar, expected: u32) -> Result<(), Error> {
    if actual.to_bytes().as_ref() != scalar(expected)?.to_bytes().as_ref() {
        return Err(Error::InvalidProof);
    }
    Ok(())
}
fn check_power(
    actual: Subgroup,
    exponent: u32,
    group: &Group,
    limits: Limits,
) -> Result<(), Error> {
    let expected = coefficients(&[exponent], group, limits)?
        .get(0)
        .ok_or(Error::NotReady)?;
    if actual != expected {
        return Err(Error::InvalidProof);
    }
    Ok(())
}

#[test]
fn two_dealer_threshold_two_preserves_gapped_order_and_original65536_point() -> Result<(), Error> {
    let group = Group::new()?;
    let limits = Limits::default();
    // f_1(x)=2+3x, f_2(x)=5+7x; local x=65536, aggregate=7+10x.
    let inputs = vec![
        contribution(9, u16::MAX, &[2, 3], 196_610, &group, limits)?,
        contribution(4, 7, &[5, 7], 458_757, &group, limits)?,
    ];
    let mut job = AggregateJob::new(inputs, [9; 32], u16::MAX, 2, &group, limits)?;
    let initial_bytes = job.retained_bytes()?;
    if !matches!(job.take_result(), Err(Error::NotReady)) {
        return Err(Error::InvalidProof);
    }
    // Single-unit turns exercise every owned-job suspension/transfer boundary.
    let material = finish(&mut job, 1)?;
    if job.retained_bytes()? != 0 || initial_bytes <= material.retained_bytes()? {
        return Err(Error::InvalidProof);
    }
    if !matches!(job.take_result(), Err(Error::Finished))
        || !matches!(job.advance(1), Err(Error::Finished))
    {
        return Err(Error::InvalidProof);
    }
    check_secret(material.secret(), 655_367)?;
    let members = material.participants();
    if material.local_position() != Some(0) || members.len() != 2 || material.threshold() != 2 {
        return Err(Error::Roster);
    }
    let first = members.first().ok_or(Error::NotReady)?;
    let second = members.get(1).ok_or(Error::NotReady)?;
    if first.peer != [9; 32]
        || first.original_index != u16::MAX
        || second.peer != [4; 32]
        || second.original_index != 7
    {
        return Err(Error::Roster);
    }
    check_power(material.public_key(), 7, &group, limits)?;
    check_power(first.sigma, 655_367, &group, limits)?;
    check_power(second.sigma, 87, &group, limits)?;
    let (secret, members, threshold, public_key, local_position) = material.into_parts();
    check_secret(&secret, 655_367)?;
    if local_position != Some(0)
        || threshold != 2
        || members.get(1).ok_or(Error::NotReady)?.original_index != 7
    {
        return Err(Error::Roster);
    }
    check_power(public_key, 7, &group, limits)?;
    Ok(())
}

#[test]
fn local_second_row_binding_survives_gaps_and_owned_transfer() -> Result<(), Error> {
    let group = Group::new()?;
    let limits = Limits::default();
    // Preserve the caller's order: original65535 is local, but is row1.
    let inputs = vec![
        contribution(4, 7, &[5, 7], 458_757, &group, limits)?,
        contribution(9, u16::MAX, &[2, 3], 196_610, &group, limits)?,
    ];
    let mut job = AggregateJob::new(inputs, [9; 32], u16::MAX, 2, &group, limits)?;
    let material = finish(&mut job, 1)?;
    if material.local_position() != Some(1) {
        return Err(Error::Roster);
    }
    let local = *material
        .participants()
        .get(material.local_position().ok_or(Error::Roster)?)
        .ok_or(Error::NotReady)?;
    if local.peer != [9; 32] || local.original_index != u16::MAX {
        return Err(Error::Roster);
    }
    check_secret(material.secret(), 655_367)?;
    check_power(local.sigma, 655_367, &group, limits)?;
    let (secret, members, threshold, public_key, local_position) = material.into_parts();
    let transferred_local = *members
        .get(local_position.ok_or(Error::Roster)?)
        .ok_or(Error::NotReady)?;
    if local_position != Some(1) || threshold != 2 || transferred_local != local {
        return Err(Error::Roster);
    }
    check_power(public_key, 7, &group, limits)?;
    check_secret(&secret, 655_367)?;
    Ok(())
}

#[test]
fn singleton_and_zero_aggregate_are_actual_mathematical_results() -> Result<(), Error> {
    let group = Group::new()?;
    let limits = Limits::default();
    let inputs = vec![contribution(3, 27, &[11], 11, &group, limits)?];
    let mut job = AggregateJob::new(inputs, [3; 32], 27, 1, &group, limits)?;
    let material = finish(&mut job, limits.units_per_turn)?;
    check_secret(material.secret(), 11)?;
    check_power(material.public_key(), 11, &group, limits)?;

    // Canonical zero shares are legal; no nonzero aggregate is fabricated.
    let inputs = vec![
        contribution(3, 27, &[0], 0, &group, limits)?,
        contribution(2, 8, &[0], 0, &group, limits)?,
    ];
    let mut job = AggregateJob::new(inputs, [3; 32], 27, 1, &group, limits)?;
    let material = finish(&mut job, limits.units_per_turn)?;
    check_secret(material.secret(), 0)?;
    if material.public_key() != Subgroup::identity()
        || material.participants().get(1).ok_or(Error::NotReady)?.sigma != Subgroup::identity()
    {
        return Err(Error::InvalidProof);
    }
    Ok(())
}

fn expect_failure(job: &mut AggregateJob, expected: Error) -> Result<(), Error> {
    for _ in 0..100_000 {
        match job.advance(1) {
            Err(error) => {
                if error != expected
                    || job.retained_bytes()? != 0
                    || job.contributions.is_some()
                    || job.aggregate.is_some()
                    || job.members.is_some()
                    || job.coefficients.is_some()
                    || job.polynomial.is_some()
                    || job.share.is_some()
                    || job.secret.is_some()
                    || job.result.is_some()
                    || !matches!(job.take_result(), Err(error) if error == expected)
                    || !matches!(job.advance(1), Err(error) if error == expected)
                {
                    return Err(Error::InvalidProof);
                }
                job.cancel();
                if !matches!(job.take_result(), Err(error) if error == expected) {
                    return Err(Error::InvalidProof);
                }
                return Ok(());
            }
            Ok(Progress::Ready) => return Err(Error::InvalidProof),
            Ok(Progress::Advanced) => {}
        }
    }
    Err(Error::Capacity)
}

#[test]
fn local_share_mismatch_never_exposes_partial_sum() -> Result<(), Error> {
    let group = Group::new()?;
    let limits = Limits::default();
    let inputs = vec![
        contribution(1, 0, &[2, 3], 5, &group, limits)?,
        contribution(2, 8, &[5, 7], 13, &group, limits)?,
    ];
    // The second real share at local x=1 is12, not13.
    let mut job = AggregateJob::new(inputs, [1; 32], 0, 2, &group, limits)?;
    expect_failure(&mut job, Error::InvalidProof)
}

#[test]
fn duplicate_peer_index_degree_and_inconsistent_local_tuple_are_refused() -> Result<(), Error> {
    let group = Group::new()?;
    let limits = Limits::default();
    for (peer, index, second_coefficients, local_peer, local_index) in [
        // Both rows differ from the local tuple: these isolate pair uniqueness.
        (1, 8, &[5][..], 99, 77),
        (2, 0, &[5][..], 99, 77),
        (2, 8, &[5, 7][..], 1, 0),
        // Exactly one local-tuple column matches, in each direction.
        (2, 8, &[5][..], 1, 4),
        (2, 8, &[5][..], 99, 0),
    ] {
        let inputs = vec![
            contribution(1, 0, &[2], 2, &group, limits)?,
            contribution(peer, index, second_coefficients, 5, &group, limits)?,
        ];
        let mut job = AggregateJob::new(inputs, [local_peer; 32], local_index, 1, &group, limits)?;
        expect_failure(&mut job, Error::Roster)?;
    }
    let inputs = vec![contribution(1, 0, &[2], 2, &group, limits)?];
    let mut wrong_degree = AggregateJob::new(inputs, [1; 32], 0, 2, &group, limits)?;
    expect_failure(&mut wrong_degree, Error::Roster)?;
    if !matches!(
        AggregateJob::new(Vec::new(), [1; 32], 0, 0, &group, limits),
        Err(Error::Roster)
    ) || !matches!(
        AggregateJob::new(
            Vec::new(),
            [1; 32],
            0,
            limits.participants + 1,
            &group,
            limits
        ),
        Err(Error::Roster)
    ) {
        return Err(Error::InvalidProof);
    }
    Ok(())
}

#[test]
fn fewer_selected_dealers_preserve_threshold_without_creating_a_usable_roster() -> Result<(), Error>
{
    let group = Group::new()?;
    let limits = Limits::default();
    // One selected dealer, with original degree2/threshold3, evaluated at x=1.
    let inputs = vec![contribution(1, 0, &[2, 3, 4], 9, &group, limits)?];
    let mut job = AggregateJob::new(inputs, [1; 32], 0, 3, &group, limits)?;
    let material = finish(&mut job, 1)?;
    if material.threshold() != 3
        || material.participants().len() != 1
        || material.local_position() != Some(0)
    {
        return Err(Error::Roster);
    }
    check_secret(material.secret(), 9)?;
    check_power(material.public_key(), 2, &group, limits)?;
    check_power(material.participants()[0].sigma, 9, &group, limits)?;
    let (_, members, threshold, public_key, _) = material.into_parts();
    if !matches!(
        crate::Roster::check(members, threshold, public_key, limits),
        Err(Error::Roster)
    ) {
        return Err(Error::InvalidProof);
    }
    Ok(())
}

#[test]
fn local_evaluation_remains_bound_when_local_is_not_a_selected_dealer() -> Result<(), Error> {
    let group = Group::new()?;
    let limits = Limits::default();
    // Local x=5 is not either selected dealer's original point1 or9.
    let inputs = vec![
        contribution(1, 0, &[2, 3], 17, &group, limits)?,
        contribution(2, 8, &[5, 7], 40, &group, limits)?,
    ];
    let mut job = AggregateJob::new(inputs, [9; 32], 4, 2, &group, limits)?;
    let material = finish(&mut job, 1)?;
    if material.local_position().is_some()
        || material.threshold() != 2
        || material.participants().len() != 2
    {
        return Err(Error::Roster);
    }
    check_secret(material.secret(), 57)?;
    check_power(material.public_key(), 7, &group, limits)?;
    check_power(material.participants()[0].sigma, 17, &group, limits)?;
    check_power(material.participants()[1].sigma, 97, &group, limits)?;
    // Missing local membership does not skip the local mathematical share check.
    let inputs = vec![contribution(1, 0, &[2, 3], 18, &group, limits)?];
    let mut wrong_share = AggregateJob::new(inputs, [9; 32], 4, 2, &group, limits)?;
    expect_failure(&mut wrong_share, Error::InvalidProof)
}

#[test]
fn empty_selection_has_zero_sum_identity_products_and_original_threshold() -> Result<(), Error> {
    let group = Group::new()?;
    let limits = Limits::default();
    let mut job = AggregateJob::new(Vec::new(), [9; 32], u16::MAX, 3, &group, limits)?;
    if job.retained_bytes()? == 0 || !matches!(job.take_result(), Err(Error::NotReady)) {
        return Err(Error::InvalidProof);
    }
    let material = finish(&mut job, 1)?;
    check_secret(material.secret(), 0)?;
    if !material.participants().is_empty()
        || material.threshold() != 3
        || material.public_key() != Subgroup::identity()
        || material.local_position().is_some()
        || material.retained_bytes()? != 0
        || job.retained_bytes()? != 0
    {
        return Err(Error::InvalidProof);
    }
    // An empty selected set still owns the full original coefficient accumulator.
    let too_small = Limits {
        retained_bytes: 3 * core::mem::size_of::<Subgroup>() - 1,
        ..limits
    };
    if !matches!(
        AggregateJob::new(Vec::new(), [9; 32], 4, 3, &group, too_small),
        Err(Error::Capacity)
    ) {
        return Err(Error::InvalidProof);
    }
    Ok(())
}

#[test]
fn cancel_invalid_units_and_combined_spare_capacity_are_sticky() -> Result<(), Error> {
    let group = Group::new()?;
    let limits = Limits::default();
    for invalid_units in [0, limits.units_per_turn + 1] {
        let inputs = vec![contribution(1, 0, &[2], 2, &group, limits)?];
        let mut job = AggregateJob::new(inputs, [1; 32], 0, 1, &group, limits)?;
        if !matches!(job.advance(invalid_units), Err(Error::Capacity)) {
            return Err(Error::InvalidProof);
        }
        expect_failure(&mut job, Error::Capacity)?;
    }
    let inputs = vec![contribution(1, 0, &[2], 2, &group, limits)?];
    let mut job = AggregateJob::new(inputs, [1; 32], 0, 1, &group, limits)?;
    job.advance(1)?;
    job.cancel();
    expect_failure(&mut job, Error::Cancelled)?;

    let mut inputs = Vec::new();
    inputs.try_reserve_exact(16).map_err(|_| Error::Capacity)?;
    inputs.push(contribution(1, 0, &[2], 2, &group, limits)?);
    let budget = Limits {
        retained_bytes: core::mem::size_of::<AggregateContribution>()
            + 2 * core::mem::size_of::<Subgroup>()
            + core::mem::size_of::<Participant>(),
        ..limits
    };
    if !matches!(
        AggregateJob::new(inputs, [1; 32], 0, 1, &group, budget),
        Err(Error::Capacity)
    ) {
        return Err(Error::InvalidProof);
    }
    Ok(())
}

#[test]
fn cancelling_a_ready_untaken_result_erases_it() -> Result<(), Error> {
    let group = Group::new()?;
    let limits = Limits::default();
    let inputs = vec![contribution(1, 0, &[2], 2, &group, limits)?];
    let mut job = AggregateJob::new(inputs, [1; 32], 0, 1, &group, limits)?;
    for _ in 0..100_000 {
        if job.advance(limits.units_per_turn)? == Progress::Ready {
            job.cancel();
            return expect_failure(&mut job, Error::Cancelled);
        }
    }
    Err(Error::Capacity)
}
