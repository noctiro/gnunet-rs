//! Unexecuted source cases. Test entropy/receipts are explicit pure mocks;
//! these cases grant no native, positive-runtime or C-interoperability credit.
use super::*;
use alloc::vec;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use gnunet_crypto::Entropy;
use gnunet_types::Error;
use gnunet_wire::official::scalarproduct::ResponseStatus;

struct TestEntropy(u8);
impl Entropy for TestEntropy {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(0);
        let first = output.first_mut().ok_or(Error::InvalidInput)?;
        self.0 = self.0.checked_add(1).ok_or(Error::EntropyUnavailable)?;
        *first = self.0;
        Ok(())
    }
}
struct PartialFailure;
impl Entropy for PartialFailure {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(0x55);
        Err(Error::Io)
    }
}
fn write_next(core: &mut Computation<'_>) -> Result<(), Error> {
    let id = core.effect().ok_or(Error::NotReady)?.id;
    core.admit_effect(id)?;
    core.complete_effect(id, Completion::Written)
}
fn connect(core: &mut Computation<'_>, source: PeerSource) -> Result<(), Error> {
    let id = core.effect().ok_or(Error::NotReady)?.id;
    core.admit_effect(id)?;
    core.attach_peer(source)?;
    core.complete_effect(id, Completion::Written)
}
fn vector(a: i64, b: i64) -> Result<Vector, Error> {
    Vector::new(
        vec![Value::new([0; 64], a), Value::new([2; 64], b)],
        HashOrder::Little,
        2,
        1024,
    )
}
fn limits() -> Limits {
    Limits {
        pairs_per_chunk: 1,
        dlog: DlogLimits {
            max_result: 64,
            memory: 8,
            max_retained_bytes: 64 * 1024,
        },
        ..Limits::default()
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit-source assertions compare real group arithmetic and independent expected values"
)]
fn real_signed_arithmetic_range_and_hash_profile() -> Result<(), Error> {
    let mut entropy = TestEntropy(0);
    let key = AliceKey::generate(&mut entropy)?;
    let left = key.encrypt(-3, &mut entropy)?;
    let right = key.encrypt(7, &mut entropy)?;
    let identity = ED25519_BASEPOINT_POINT * Scalar::ZERO;
    let id = identity.compress().to_bytes();
    let first = aggregate([id, id], left, 5)?;
    let products = aggregate(first, right, -2)?;
    let target = unblind(&key, products)?;
    assert!(
        target
            == (ED25519_BASEPOINT_POINT * -Scalar::from(29u64))
                .compress()
                .to_bytes()
    );
    let mut job = Dlog::new(target, limits().dlog)?;
    let mut result = DlogProgress::Pending;
    for _ in 0..1000 {
        result = job.step(1)?;
        if result != DlogProgress::Pending {
            break;
        }
    }
    assert!(result == DlogProgress::Done(-29));
    let outside = (ED25519_BASEPOINT_POINT * Scalar::from(65u64))
        .compress()
        .to_bytes();
    let mut job = Dlog::new(outside, limits().dlog)?;
    for _ in 0..1000 {
        result = job.step(1)?;
        if result != DlogProgress::Pending {
            break;
        }
    }
    assert!(result == DlogProgress::OutOfRange);
    let min = key.encrypt(i64::MIN, &mut entropy)?;
    let min = aggregate([id, id], min, 1)?;
    assert!(
        unblind(&key, min)?
            == (ED25519_BASEPOINT_POINT * -Scalar::from(1u64 << 63))
                .compress()
                .to_bytes()
    );
    assert!(matches!(
        AliceKey::generate(&mut PartialFailure),
        Err(Error::Io)
    ));
    assert!(matches!(
        aggregate([id, id], [id, id], 1),
        Err(Error::Authentication)
    ));
    let mut a = [0; 64];
    let mut b = [0; 64];
    a[60] = 1;
    b[61] = 1;
    assert!(HashOrder::Little.compare(&a, &b).is_lt());
    assert!(HashOrder::Big.compare(&a, &b).is_gt());
    assert!(matches!(
        Vector::new(
            vec![Value::new([0; 64], 0), Value::new([0; 64], 2)],
            HashOrder::Little,
            2,
            1024
        ),
        Err(Error::Conflict)
    ));
    Ok(())
}

#[test]
fn two_party_multipart_original_input_and_real_dlog() -> Result<(), Error> {
    two_party_product([-3, 7], [5, -2], 0, -29, [false, false])
}

#[test]
fn nonempty_identity_aggregates_use_real_unblinding_and_dlog() -> Result<(), Error> {
    // The controlled scalar draws are key1/r2/r3, then key2/r3/r4.
    // These are nonempty two-key intersections with nonzero coefficients.
    two_party_product([-3, 7], [3, -2], 0, -23, [true, false])?;
    two_party_product([-3, 7], [10, 1], 0, -23, [false, true])?;
    two_party_product([3, 4], [4, -3], 1, 0, [true, true])
}

#[expect(
    clippy::panic_in_result_fn,
    reason = "unit-source assertions drive actual core/effect and exact official frame paths using explicit native receipt mocks"
)]
fn two_party_product(
    left: [i64; 2],
    right: [i64; 2],
    seed: u8,
    expected: i32,
    identity_columns: [bool; 2],
) -> Result<(), Error> {
    let brand = Instance::new();
    let mut entropy = TestEntropy(seed);
    let mut alice = Computation::alice(
        &brand,
        [3; 64],
        [2; 32],
        vector(left[0], left[1])?,
        limits(),
        &mut entropy,
    )?;
    let mut bob = Computation::bob(&brand, [3; 64], vector(right[0], right[1])?, limits())?;
    let a_intersection = match alice.effect().ok_or(Error::NotReady)?.action {
        Action::ListenIntersection { id, .. } => id,
        _ => return Err(Error::Conflict),
    };
    write_next(&mut alice)?;
    let a_source = PeerSource {
        epoch: 1,
        channel: 1,
        peer: [2; 32],
    };
    let b_source = PeerSource {
        epoch: 1,
        channel: 1,
        peer: [1; 32],
    };
    connect(&mut alice, a_source)?;
    write_next(&mut bob)?;
    bob.attach_peer(b_source)?;
    let session = match &alice.effect().ok_or(Error::NotReady)?.action {
        Action::PeerSend { payload, .. } => payload.wire(),
        _ => return Err(Error::Conflict),
    };
    let input = bob.receive(b_source, 1, session)?;
    write_next(&mut alice)?;
    assert!(
        matches!(&bob.effect().ok_or(Error::NotReady)?.action,Action::ReceiveDone{input:id,..} if *id==input)
    );
    write_next(&mut bob)?;
    let b_intersection = match bob.effect().ok_or(Error::NotReady)?.action {
        Action::StartIntersection { id, .. } => id,
        _ => return Err(Error::Conflict),
    };
    write_next(&mut bob)?;
    alice.intersection_done(a_intersection, [2; 32])?;
    bob.intersection_done(b_intersection, [1; 32])?;
    for serial in 2..=3 {
        alice.step(&mut entropy, 1)?;
        let message = match &alice.effect().ok_or(Error::NotReady)?.action {
            Action::PeerSend { payload, .. } => payload.wire(),
            _ => return Err(Error::Conflict),
        };
        bob.receive(b_source, serial, message)?;
        if serial == 2 {
            let original = alice.effect().ok_or(Error::NotReady)?.id;
            alice.admit_effect(original)?;
            assert!(
                alice.complete_effect(original, Completion::Processed) == Err(Error::InvalidInput)
            );
            assert!(alice.effect().is_some_and(|effect| effect.id == original));
            alice.complete_effect(original, Completion::Written)?;
        } else {
            write_next(&mut alice)?;
        }
        bob.step(&mut entropy, 1)?;
        // Result/aggregate state cannot commit merely from input admission.
        assert!(matches!(
            &bob.effect().ok_or(Error::NotReady)?.action,
            Action::ReceiveDone { .. }
        ));
        if serial == 2 {
            // Explicit host mock: both chunks belong to one retained outer
            // Delivery. Processing this first inner does not ACK that packet.
            let id = bob.effect().ok_or(Error::NotReady)?.id;
            bob.admit_effect(id)?;
            bob.complete_effect(id, Completion::Processed)?;
            assert!(bob.effect().is_none());
        } else {
            // Only the last inner may settle the actual outer ACK as Written.
            write_next(&mut bob)?;
        }
    }
    let message = match &bob.effect().ok_or(Error::NotReady)?.action {
        Action::PeerSend { payload, .. } => payload.wire(),
        _ => return Err(Error::Conflict),
    };
    match &message {
        gnunet_wire::official::scalarproduct::PeerMessage::EccBob {
            product_g,
            product_h,
        } => {
            let identity = crate::crypto::identity_pair()[0];
            assert!((**product_g == identity) == identity_columns[0]);
            assert!((**product_h == identity) == identity_columns[1]);
        }
        _ => return Err(Error::Conflict),
    }
    alice.receive(a_source, 1, message)?;
    write_next(&mut bob)?;
    let bob_result = bob
        .effect()
        .ok_or(Error::NotReady)?
        .action
        .client_response()
        .ok_or(Error::Conflict)?;
    assert!(bob_result.status == ResponseStatus(2) && bob_result.product.is_empty());
    for _ in 0..1000 {
        alice.step(&mut entropy, 1)?;
        if alice.effect().is_some() {
            break;
        }
    }
    assert!(matches!(
        &alice.effect().ok_or(Error::NotReady)?.action,
        Action::ReceiveDone { .. }
    ));
    write_next(&mut alice)?;
    let result = alice
        .effect()
        .ok_or(Error::NotReady)?
        .action
        .client_response()
        .ok_or(Error::Conflict)?;
    let magnitude = expected.unsigned_abs().to_be_bytes();
    let first = magnitude
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(magnitude.len());
    assert!(
        result.status == ResponseStatus(2)
            && result.range == expected.signum()
            && result.product == &magnitude[first..]
    );
    assert!(
        alice
            .outcome()
            .result
            .is_some_and(|r| r.value() == expected)
    );
    assert!(!alice.outcome().client_written);
    write_next(&mut alice)?;
    assert!(alice.outcome().client_written && !alice.is_quiescent());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit-source assertions preserve original SETI DONE, empty-role results and admitted cancellation owners"
)]
fn empty_done_returns_zero_and_cancel_preserves_original_receipts() -> Result<(), Error> {
    let brand = Instance::new();
    let mut entropy = TestEntropy(0);
    let mut alice = Computation::alice(
        &brand,
        [3; 64],
        [2; 32],
        vector(1, 2)?,
        limits(),
        &mut entropy,
    )?;
    let intersection = match alice.effect().ok_or(Error::NotReady)?.action {
        Action::ListenIntersection { id, .. } => id,
        _ => return Err(Error::Conflict),
    };
    write_next(&mut alice)?;
    let source = PeerSource {
        epoch: 4,
        channel: 7,
        peer: [2; 32],
    };
    connect(&mut alice, source)?;
    write_next(&mut alice)?;
    alice.intersection_removed(intersection, [2; 32], &[0; 64])?;
    alice.intersection_removed(intersection, [2; 32], &[2; 64])?;
    // Empty rows alone and a foreign callback are not original SETI DONE.
    assert!(alice.outcome().known_value().is_none() && alice.effect().is_none());
    assert!(!alice.can_finish_locally());
    assert!(alice.intersection_done(intersection, [9; 32]) == Err(Error::Authentication));
    assert!(alice.outcome().known_value().is_none());
    alice.intersection_done(intersection, [2; 32])?;
    assert!(alice.outcome().failure.is_none() && alice.outcome().known_value() == Some(0));
    assert!(!alice.outcome().client_written && !alice.is_quiescent());
    let original = alice.effect().ok_or(Error::NotReady)?.id;
    let response = alice
        .effect()
        .ok_or(Error::NotReady)?
        .action
        .client_response()
        .ok_or(Error::Conflict)?;
    assert!(
        response.status == ResponseStatus(2) && response.range == 0 && response.product.is_empty()
    );
    // Exercise the actual normal IPC codec. Official C treats length0 success
    // as an MPI initialized to zero, independently of source EOF.
    let mut bytes = [0; 16];
    assert!(response.encode(&mut bytes)? == bytes.len());
    assert!(gnunet_wire::official::scalarproduct::ClientResponse::decode(&bytes)? == response);
    assert!(alice.intersection_done(intersection, [2; 32]) == Err(Error::NotReady));
    // Explicit physical-retirement mock: complete local work survives a real
    // post-DONE loss, preserving both its old result effect and cleanup cause.
    alice.retire_peer_for_local_work(source, Error::Closed, None)?;
    assert!(alice.effect().is_some_and(|effect| effect.id == original));
    assert!(alice.outcome().cleanup_failure == Some(Error::Closed));
    write_next(&mut alice)?;
    assert!(alice.outcome().client_written && !alice.is_quiescent());
    let cleanup = alice.effect().ok_or(Error::NotReady)?;
    assert!(matches!(cleanup.action, Action::CloseIntersection { .. }));
    let id = cleanup.id;
    alice.admit_effect(id)?;
    alice.complete_effect(id, Completion::Retired)?;
    assert!(alice.is_quiescent() && alice.outcome().failure.is_none());

    let mut bob = Computation::bob(&brand, [3; 64], vector(5, 6)?, limits())?;
    write_next(&mut bob)?;
    let b_source = PeerSource {
        peer: [1; 32],
        ..source
    };
    bob.attach_peer(b_source)?;
    bob.receive(
        b_source,
        1,
        gnunet_wire::official::scalarproduct::PeerMessage::EccSession {
            reserved: 0,
            session: &[3; 64],
        },
    )?;
    write_next(&mut bob)?;
    let intersection = match bob.effect().ok_or(Error::NotReady)?.action {
        Action::StartIntersection { id, .. } => id,
        _ => return Err(Error::Conflict),
    };
    write_next(&mut bob)?;
    bob.intersection_removed(intersection, [1; 32], &[0; 64])?;
    bob.intersection_removed(intersection, [1; 32], &[2; 64])?;
    assert!(bob.effect().is_none() && !bob.can_finish_locally());
    bob.intersection_done(intersection, [1; 32])?;
    let response = bob
        .effect()
        .ok_or(Error::NotReady)?
        .action
        .client_response()
        .ok_or(Error::Conflict)?;
    assert!(
        response.status == ResponseStatus(2) && response.range == 0 && response.product.is_empty()
    );
    assert!(bob.outcome().result.is_none() && bob.outcome().known_value().is_none());
    assert!(bob.outcome().failure.is_none() && !bob.outcome().client_written);
    write_next(&mut bob)?;
    // Actual mocked retirement remains required for all three original owners.
    for _ in 0..3 {
        let id = bob.effect().ok_or(Error::NotReady)?.id;
        bob.admit_effect(id)?;
        bob.complete_effect(id, Completion::Retired)?;
    }
    assert!(bob.is_quiescent() && bob.outcome().client_written);

    let mut alice = Computation::alice(
        &brand,
        [4; 64],
        [2; 32],
        vector(1, 2)?,
        limits(),
        &mut entropy,
    )?;
    write_next(&mut alice)?;
    connect(&mut alice, source)?;
    let original = alice.effect().ok_or(Error::NotReady)?.id;
    alice.admit_effect(original)?;
    alice.cancel()?;
    assert!(
        alice
            .effect()
            .is_some_and(|e| e.id == original && e.is_admitted())
    );
    assert!(alice.cancel() == Err(Error::Conflict));
    // Native physical close is mocked explicitly; Lost is not a new success.
    alice.complete_effect(original, Completion::Lost(Error::Io))?;
    alice.peer_lost(source, Error::Io)?;
    assert!(
        alice
            .outcome()
            .failure
            .is_some_and(|f| f.stage == Stage::Cancel && f.cause == Error::Cancelled)
    );
    assert!(alice.outcome().cleanup_failure == Some(Error::Io));
    let close = alice.effect().ok_or(Error::NotReady)?.id;
    alice.admit_effect(close)?;
    alice.complete_effect(close, Completion::Retired)?;
    assert!(alice.is_quiescent() && !alice.outcome().client_written);
    Ok(())
}
