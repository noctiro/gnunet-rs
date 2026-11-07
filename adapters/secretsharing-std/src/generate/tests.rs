//! Ordinary wire/profile and real owned arithmetic cases; no PILS source runs.
use super::*;
use math::{AggregateContribution, AggregateJob, CommitmentJob, Commitments, Polynomial};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
fn check(value: bool) -> Result {
    if value {
        Ok(())
    } else {
        Err("generation source case failed".into())
    }
}
fn request(peers: &[u8], threshold: u16, start: u64, deadline: u64) -> Result<Request> {
    let raw = ipc::Request::Generate(ipc::Generate {
        session: &[7; 64],
        start,
        deadline,
        threshold,
        peers,
    });
    let mut bytes = Zeroizing::new(vec![0; raw.encoded_len()?]);
    raw.encode(bytes.as_mut())?;
    Ok(Request::from_frame(bytes, Limits::default())?)
}
#[test]
fn empty_or_exact_local_only() -> Result {
    let local = [9; 32];
    check(request(&[], 1, 10, 20)?.accepts(&local)?)?;
    check(request(&local, 1, 10, 20)?.accepts(&local)?)?;
    check(!request(&[8; 32], 1, 10, 20)?.accepts(&local)?)
}
#[test]
fn general_intent_is_admitted_but_never_uses_the_singleton_shortcut() -> Result {
    check(!request(&[], 2, 10, 20)?.accepts(&[9; 32])?)?;
    check(!request(&[9; 64], 1, 10, 20)?.accepts(&[9; 32])?)?;
    let mut peers = [9; 64];
    peers[32..].fill(10);
    let request = request(&peers, 2, 10, 20)?;
    check(!request.accepts(&[9; 32])? && !request.accepts(&[10; 32])?)
}
#[test]
fn invalid_generation_time_and_zero_threshold_are_refused() -> Result {
    check(request(&[], 0, 10, 20).is_err())?;
    check(request(&[], 1, 20, 20).is_err())?;
    check(request(&[], 1, 21, 20).is_err())
}
#[test]
fn actual_secret_ready_shape_has_one_complete_row() -> Result {
    let mut bytes = Zeroizing::new([0; 128]);
    bytes[127] = 1;
    let group = math::Group::new()?;
    let peer = [9; 32];
    let material = aggregate_constants(&[peer])?;
    check(material.local_position() == Some(0))?;
    // The shared aggregate job must derive the actual scalar/public roster
    // consumed by the normal singleton output helper, not a manually tagged key.
    let limits = Limits::default();
    let frame = encode_share(peer, &material, limits, limits.operation_bytes)?;
    check(matches!(
        encode_share(peer, &material, limits, 2 * RESPONSE_BYTES - 1),
        Err(Error::Protocol(Fault::Capacity))
    ))?;
    check(frame.bytes().len() == 430)?;
    let ipc::Response::SecretReady(share) = ipc::Response::decode(Frame::decode(frame.bytes())?)?
    else {
        return Err("wrong response kind".into());
    };
    check(share.threshold() == 1 && share.len() == 1 && share.my_peer() == 0)?;
    check(share.peer(0)? == Some(&peer))?;
    check(share.sigma(0)? == Some(&group.generator().to_bytes()))?;
    check(share.original_index(0, ipc::IndexOrder::native())? == Some(0))?;
    check(share.secret()? == bytes.as_ref())
}

fn aggregate_constants(peers: &[[u8; 32]]) -> Result<AggregateMaterial> {
    let group = math::Group::new()?;
    let limits = math::Limits::default();
    let mut contributions = Vec::new();
    for (index, peer) in peers.iter().enumerate() {
        let mut scalar = Zeroizing::new([0; 128]);
        scalar[127] = 1;
        contributions.push(AggregateContribution::new(
            *peer,
            u16::try_from(index)?,
            Commitments::from_members(vec![group.generator()], limits)?,
            math::Scalar::from_bytes(&scalar)?,
        ));
    }
    let mut job = AggregateJob::new(contributions, peers[0], 0, 1, &group, limits)?;
    for _ in 0..100_000 {
        if job.advance(limits.units_per_turn)? == math::Progress::Ready {
            return Ok(job.take_result()?);
        }
    }
    Err("aggregate did not complete within its source-case work cap".into())
}

#[test]
fn local_output_helper_cannot_promote_multi_peer_math_to_generation() -> Result {
    let peers = [[9; 32], [10; 32]];
    let material = aggregate_constants(&peers)?;
    check(material.participants().len() == 2)?;
    let limits = Limits::default();
    check(encode_share(peers[0], &material, limits, limits.operation_bytes).is_err())
}

fn constant_polynomial() -> Result<Polynomial> {
    let mut scalar = Zeroizing::new([0; 128]);
    scalar[127] = 1;
    // Spare retained slots must follow the unique polynomial through the owned
    // commitment job, rather than being charged by both the old and new stage.
    let mut coefficients = Vec::new();
    coefficients.try_reserve_exact(3)?;
    coefficients.push(math::Scalar::from_bytes(&scalar)?);
    Ok(Polynomial::from_coefficients(
        coefficients,
        math::Limits::default(),
    )?)
}

fn bounded_random() -> Random {
    Random {
        error: None,
        hard: Instant::now() + std::time::Duration::from_secs(60),
    }
}

#[test]
#[expect(
    clippy::print_stderr,
    reason = "Record compiler-derived inline storage sizes for the ownership regression, without running a benchmark."
)]
fn exclusive_jobs_transfer_actual_allocations_and_complete_original_share() -> Result {
    let previous_math_storage = size_of::<Option<PolynomialGenerator>>()
        + size_of::<Option<CommitmentJob<'static>>>()
        + size_of::<Option<Polynomial>>()
        + size_of::<Option<Commitments>>()
        + size_of::<Option<AggregateJob>>()
        + size_of::<Option<AggregateMaterial>>();
    let current_math_storage = size_of::<State>();
    check(current_math_storage < previous_math_storage)?;
    eprintln!(
        "singleton mathematical inline storage: previous={previous_math_storage}, state={current_math_storage}"
    );

    let group = math::Group::new()?;
    let peer = [9; 32];
    let limits = Limits::default();
    let polynomial = constant_polynomial()?;
    let polynomial_bytes = polynomial.retained_bytes()?;
    let commitment = CommitmentJob::new_owned(polynomial, &group)?;
    let combined_bytes = commitment.retained_bytes()?;
    check(combined_bytes > polynomial_bytes)?;
    let mut state = State::Committing(commitment);
    check(state.retained_bytes()? == combined_bytes)?;
    check(state.material().is_err())?;
    let mut random = bounded_random();

    // Run the production state method and its actual exponentiation cursor.
    // No second stage receives this call's unused arithmetic budget.
    for _ in 0..100_000 {
        state.advance(&mut random, peer, &group, limits, 0)?;
        if matches!(state, State::Coefficients { .. }) {
            break;
        }
    }
    check(matches!(state, State::Coefficients { .. }))?;
    check(state.retained_bytes()? == combined_bytes)?;
    check(state.material().is_err())?;
    check(state.advance(&mut random, peer, &group, limits, 0)?)?;
    check(matches!(state, State::Aggregating(_)))?;
    check(state.material().is_err())?;
    for _ in 0..100_000 {
        state.advance(&mut random, peer, &group, limits, 0)?;
        if matches!(state, State::Ready(_)) {
            break;
        }
    }
    let material = state.material()?;
    check(state.retained_bytes()? == material.retained_bytes()?)?;
    check(material.public_key() == group.generator())?;
    let generated = encode_share(peer, material, limits, limits.operation_bytes)?;
    check(generated.bytes().len() == RESPONSE_BYTES && RESPONSE_BYTES == 430)?;
    check(!state.advance(&mut random, peer, &group, limits, 0)?)?;
    state.close();
    check(state.is_closed() && state.retained_bytes()? == 0)?;
    check(state.material().is_err())
}

#[test]
fn cancellation_erases_live_owned_power_and_retires_state_once() -> Result {
    let group = math::Group::new()?;
    let limits = Limits::default();
    let mut state = State::Committing(CommitmentJob::new_owned(constant_polynomial()?, &group)?);
    let mut random = bounded_random();
    check(state.advance(&mut random, [9; 32], &group, limits, 0)?)?;
    check(matches!(state, State::Committing(_)))?;
    check(state.retained_bytes()? != 0)?;
    state.close();
    state.close();
    check(state.is_closed() && state.retained_bytes()? == 0)?;
    check(matches!(
        state.advance(&mut random, [9; 32], &group, limits, 0),
        Err(Error::Protocol(Fault::Closed))
    ))?;
    check(state.material().is_err())
}

#[test]
fn refused_material_handoff_still_requires_original_source_retirement() -> Result {
    let group = math::Group::new()?;
    let mut state = State::Coefficients {
        polynomial: constant_polynomial()?,
        commitments: Commitments::from_members(vec![group.generator()], math::Limits::default())?,
    };
    let limits = Limits {
        operation_bytes: 1,
        ..Limits::default()
    };
    let mut random = bounded_random();
    check(matches!(
        state.advance(&mut random, [9; 32], &group, limits, 0),
        Err(Error::Protocol(Fault::Capacity))
    ))?;
    // A failed consuming transition has dropped both unique input owners, but
    // must not make Owner::retire skip closing the real external PILS source.
    check(!state.is_closed() && state.retained_bytes()? == 0)?;
    check(state.material().is_err())?;
    state.close();
    check(state.is_closed())
}
