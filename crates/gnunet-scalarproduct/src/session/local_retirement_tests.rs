//! Unexecuted pure source cases. Native tail validation and physical retirement
//! are explicit mocks, not execution or official-C interoperability evidence.
use super::*;
use crate::{DlogLimits, HashOrder, Value};
use alloc::vec;
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};

struct NoEntropy;
impl Entropy for NoEntropy {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::EntropyUnavailable)
    }
}
fn source() -> PeerSource {
    PeerSource {
        epoch: 4,
        channel: 7,
        peer: [2; 32],
    }
}
fn core(brand: &Instance, role: Role) -> Result<Computation<'_>, Error> {
    let vector = Vector::new(vec![Value::new([1; 64], 2)], HashOrder::Little, 1, 1024)?;
    let limits = Limits {
        dlog: DlogLimits {
            max_result: 64,
            memory: 8,
            max_retained_bytes: 65536,
        },
        ..Limits::default()
    };
    let mut core = Computation::base(brand, [3; 64], role, vector, limits)?;
    core.source = Some(source());
    core.intersection_done = true;
    Ok(core)
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "pure source assertions preserve actual copied DLOG input and original physical-retirement facts"
)]
fn original_final_input_retired_then_local_dlog_without_old_ack() -> Result<(), Error> {
    let brand = Instance::new();
    let mut core = core(&brand, Role::Alice { peer: [2; 32] })?;
    core.phase = Phase::AliceAwait;
    assert!(!core.can_finish_locally());
    assert!(core.retire_peer_for_local_work(source(), Error::Closed, None) == Err(Error::NotReady));
    let input = core.input(source(), 1)?;
    let target = (ED25519_BASEPOINT_POINT * -Scalar::from(29u64))
        .compress()
        .to_bytes();
    core.work = Some(Work::Log {
        job: Dlog::new(target, core.limits.dlog)?,
        input: Some(input),
    });
    core.phase = Phase::AliceLog;
    assert!(core.can_finish_locally());
    let foreign = PeerSource {
        channel: 8,
        ..source()
    };
    assert!(
        core.retire_peer_for_local_work(foreign, Error::Closed, None)
            == Err(Error::StaleGeneration)
    );
    assert!(matches!(core.work, Some(Work::Log { input: Some(_), .. })));
    // Explicit native mock: complete original outer tail validated, old IO
    // physically retired. This is neither a ReceiveDone nor a remote ACK.
    core.retire_peer_for_local_work(source(), Error::Closed, None)?;
    assert!(core.peer_source().is_none());
    for _ in 0..1000 {
        core.step(&mut NoEntropy, 1)?;
        if core.effect().is_some() {
            break;
        }
    }
    assert!(core.outcome().result.is_some_and(|v| v.value() == -29));
    assert!(core.outcome().failure.is_none());
    assert!(core.outcome().cleanup_failure == Some(Error::Closed));
    assert!(matches!(
        core.effect().map(|e| &e.action),
        Some(Action::ClientResult { .. })
    ));
    assert!(core.peer_lost(source(), Error::Io) == Err(Error::StaleGeneration));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "pure source assertions reject fake final ACK and preserve original lost receive/local-written Bob receipts"
)]
fn exact_final_ack_debt_and_bob_known_write_only() -> Result<(), Error> {
    let brand = Instance::new();
    let mut alice = core(&brand, Role::Alice { peer: [2; 32] })?;
    let input = alice.input(source(), 1)?;
    alice.outcome.result = Some(ResultValue::new(-29));
    alice.release = Some((input, AfterRelease::Alice));
    alice.phase = Phase::Release;
    alice.pump()?;
    let original = alice.effect().ok_or(Error::NotReady)?.id;
    alice.admit_effect(original)?;
    assert!(
        alice.retire_peer_for_local_work(
            source(),
            Error::Closed,
            Some((original, Completion::Processed))
        ) == Err(Error::InvalidInput)
    );
    assert!(
        alice
            .effect()
            .is_some_and(|e| e.id == original && e.admitted)
    );
    alice.retire_peer_for_local_work(
        source(),
        Error::Closed,
        Some((original, Completion::Lost(Error::Io))),
    )?;
    assert!(alice.outcome().failure.is_none());
    assert!(alice.outcome().cleanup_failure == Some(Error::Io));
    assert!(
        alice
            .effect()
            .is_some_and(|e| e.id != original && matches!(e.action, Action::ClientResult { .. }))
    );
    let mut bob = core(&brand, Role::Bob)?;
    bob.phase = Phase::BobReady;
    assert!(!bob.can_finish_locally());
    let products = [
        (ED25519_BASEPOINT_POINT * Scalar::from(3u64))
            .compress()
            .to_bytes(),
        (ED25519_BASEPOINT_POINT * Scalar::from(7u64))
            .compress()
            .to_bytes(),
    ];
    bob.publish(Action::PeerSend {
        source: source(),
        payload: PeerOutput::Bob { products },
    })?;
    let write = bob.effect().ok_or(Error::NotReady)?.id;
    bob.admit_effect(write)?;
    assert!(!bob.can_finish_locally());
    bob.complete_effect(write, Completion::Written)?;
    let result = bob.effect().ok_or(Error::NotReady)?.id;
    assert!(bob.can_finish_locally());
    bob.retire_peer_for_local_work(source(), Error::Closed, None)?;
    assert!(bob.effect().is_some_and(|e| e.id == result));
    assert!(bob.outcome().failure.is_none() && bob.outcome().result.is_none());
    Ok(())
}
