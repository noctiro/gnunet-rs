// Source-only cases. No key generation, encryption, real IO, reference process
// or default-profile cryptographic interoperability is established by these.
use crate::{AliceMath, Error, HashOrder, MatchedVector, Value};
use alloc::vec;
use crypto_bigint::U2048;

fn plain(value: u64) -> [u8; 256] {
    let mut bytes = [0; 256];
    bytes[248..].copy_from_slice(&value.to_be_bytes());
    bytes
}
fn column(value: i128) -> [u8; 256] {
    let offset = U2048::ONE.shl(683);
    let amount = U2048::from_u128(value.unsigned_abs());
    let value = if value < 0 {
        offset.wrapping_sub(&amount)
    } else {
        offset.wrapping_add(&amount)
    };
    let mut bytes = [0; 256];
    bytes.copy_from_slice(value.to_be_bytes().as_ref());
    bytes
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit source assertions compare independent arithmetic, transcript and lifecycle expectations; original API errors propagate"
)]
fn independent_columns_produce_the_real_signed_product() -> Result<(), Error> {
    // a=[-2,3], b=[5,-7], r=[4,-3], p=[1,0], q=[0,1].
    let mut math = AliceMath::new(2)?;
    math.sum(&plain(181))?;
    math.prime(&plain(25))?;
    math.left(&column(13))?;
    math.right(&column(-6))?;
    math.left(&column(-11))?;
    math.right(&column(6))?;
    let product = math.finish()?;
    assert_eq!(product.range(), -1);
    assert_eq!(product.mpi().as_bytes(), &[31]);
    assert!(matches!(math.finish(), Err(Error::Finished)));
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit source assertions compare independent arithmetic, transcript and lifecycle expectations; original API errors propagate"
)]
fn exact_division_and_full_i64_min_product_are_checked() -> Result<(), Error> {
    let mut odd = AliceMath::new(1)?;
    odd.sum(&plain(1))?;
    odd.prime(&plain(0))?;
    odd.left(&column(0))?;
    odd.right(&column(0))?;
    assert!(matches!(odd.finish(), Err(Error::InvalidResult)));
    let mut large = AliceMath::new(1)?;
    let mut s = [0; 256];
    s[240..].copy_from_slice(&(1u128 << 126).to_be_bytes());
    large.sum(&s)?;
    large.prime(&plain(0))?;
    large.left(&column(0))?;
    large.right(&column(i128::from(i64::MIN)))?;
    let product = large.finish()?;
    let mut expected = [0; 16];
    expected[0] = 0x40;
    assert_eq!(product.range(), 1);
    assert_eq!(product.mpi().as_bytes(), &expected[..]);
    let mut prefix = AliceMath::new(1)?;
    prefix.sum(&plain(128 * 128))?;
    prefix.prime(&plain(0))?;
    prefix.left(&column(-127))?;
    prefix.right(&column(1))?;
    assert_eq!(prefix.finish()?.mpi().as_bytes(), &[0, 128]);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit source assertions compare independent arithmetic, transcript and lifecycle expectations; original API errors propagate"
)]
fn missing_or_out_of_profile_values_cannot_become_a_product() -> Result<(), Error> {
    let mut math = AliceMath::new(1)?;
    assert!(matches!(math.finish(), Err(Error::Phase)));
    let mut huge = [0; 256];
    huge[0] = 1;
    assert!(matches!(math.sum(&huge), Err(Error::InvalidResult)));
    math.sum(&plain(0))?;
    math.prime(&plain(0))?;
    let mut bad_column = column(0);
    bad_column[0] = 1;
    assert!(matches!(math.left(&bad_column), Err(Error::InvalidResult)));
    math.left(&column(0))?;
    math.right(&column(0))?;
    assert_eq!(math.finish()?.mpi().as_bytes(), &[]);
    let mut empty = AliceMath::new(0)?;
    empty.sum(&plain(0))?;
    empty.prime(&plain(0))?;
    assert_eq!(empty.finish()?.range(), 0);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit source assertions compare independent arithmetic, transcript and lifecycle expectations; original API errors propagate"
)]
fn original_intersection_snapshot_is_stable_and_errors_are_atomic() -> Result<(), Error> {
    let mut other = [0; 64];
    other[0] = 1;
    let rows = vec![Value::new([0; 64], i64::MIN), Value::new(other, 5)];
    let mut vector = MatchedVector::new(rows, HashOrder::Little, 2, 4096)?;
    vector.remove(&other)?;
    assert!(vector.seal(2).is_err());
    assert!(!vector.is_sealed());
    vector.seal(1)?;
    assert_eq!(vector.len()?, 1);
    assert_eq!(vector.coefficient(0)?, i64::MIN);
    assert_eq!(vector.keys().next(), Some(&[0; 64]));
    assert!(vector.remove(&[0; 64]).is_err());
    assert!(
        MatchedVector::new(
            vec![Value::new(other, 0), Value::new(other, 1)],
            HashOrder::Little,
            2,
            4096
        )
        .is_err()
    );
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit source assertions compare independent arithmetic, transcript and lifecycle expectations; original API errors propagate"
)]
fn original_frame_generation_and_admitted_debt_survive_local_cancel() -> Result<(), Error> {
    use crate::support::{Instance, Kind, Outbox};
    use gnunet_wire::official::scalarproduct::PeerMessage;
    let instance = Instance::new();
    let foreign = Instance::new();
    let mut out = Outbox::new(&instance)?;
    let mut other = Outbox::new(&foreign)?;
    let message = PeerMessage::PaillierSession {
        reserved: 0,
        session: &[0; 64],
        public_key: &[0; 256],
    };
    assert!(out.queue(message, Kind::Introduction, 327, 1040).is_err());
    assert!(out.output().is_none());
    out.queue(message, Kind::Introduction, 1024, 1040)?;
    other.queue(message, Kind::Introduction, 1024, 1040)?;
    let id = out.output().ok_or(Error::Finished)?;
    let other_id = other.output().ok_or(Error::Finished)?;
    assert_ne!(id, other_id);
    assert!(out.admit(other_id).is_err());
    let frame = out.admit(id)?;
    out.clear_unadmitted();
    assert!(out.admitted());
    assert!(out.output().is_none());
    out.complete(frame.id())?;
    drop(frame);
    assert!(!out.admitted());
    assert!(out.complete(id).is_err());
    let mut next = Outbox::new(&instance)?;
    next.queue(message, Kind::Introduction, 1024, 1040)?;
    assert_ne!(next.output(), Some(id));
    Ok(())
}

// Only metadata/cancellation/deadline transitions are exercised; the test helper
// deliberately has no key and produces no decrypted value or synthetic result.
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "unit source assertions compare original retirement causes and deadlines; setup errors propagate"
)]
fn complete_reply_local_retirement_keeps_cause_and_original_deadline() -> Result<(), Error> {
    let instance = crate::Instance::new();
    let mut partial = crate::alice::local_retirement_metadata_case(&instance, 1)?;
    assert!(!partial.can_finish_locally());
    assert!(matches!(
        partial.retire_peer_for_local_work(
            partial.binding(),
            Error::Core(gnunet_types::Error::Closed)
        ),
        Err(Error::Phase)
    ));
    assert!(partial.peer_failure().is_none());
    let mut full = crate::alice::local_retirement_metadata_case(&instance, 2)?;
    assert!(full.can_finish_locally());
    let original = full.deadline();
    let cause = Error::Core(gnunet_types::Error::Closed);
    full.retire_peer_for_local_work(full.binding(), cause)?;
    assert_eq!(full.peer_failure(), Some(cause));
    assert_eq!(full.deadline(), original);
    assert!(full.failure().is_none());
    assert!(!full.product_computed());
    assert!(matches!(full.take_product(), Err(Error::Phase)));
    assert!(matches!(
        full.retire_peer_for_local_work(full.binding(), cause),
        Err(Error::Finished)
    ));
    full.peer_lost(full.binding(), Error::Core(gnunet_types::Error::Io))?;
    assert!(full.failure().is_none());
    struct Never;
    impl gnunet_paillier::Entropy for Never {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), gnunet_types::Error> {
            Err(gnunet_types::Error::EntropyUnavailable)
        }
    }
    assert!(matches!(
        full.progress(110, &mut Never, 1),
        Err(Error::Deadline)
    ));
    assert_eq!(full.peer_failure(), Some(cause));
    assert!(!full.product_computed());
    Ok(())
}
