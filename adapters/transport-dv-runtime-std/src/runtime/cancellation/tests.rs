//! Production cancellation-ledger decisions over opaque local identifiers.
//! These fixtures claim no PILS admission, physical close, crypto or peer result.
use super::*;

fn check(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(Protocol::Conflict.into())
    }
}

#[test]
fn refused_cancel_still_retains_original_native_debt_without_renewing_it() -> Result<(), Error> {
    let original = Instant::now();
    let grace = std::time::Duration::from_secs(3);
    let mut rows = Vec::with_capacity(1);
    let actual = retain(
        &mut rows,
        7_u8,
        original,
        grace,
        1,
        Err(Protocol::Stale.into()),
        Ok(false),
    );
    check(!actual.fence && rows.len() == 1 && rows[0].operation == 7)?;
    let hard = rows[0].hard;
    check(hard == original.checked_add(grace).ok_or(Protocol::Overflow)?)?;
    let mut cleanup = None;
    check(matches!(
        actual.errors.finish(&mut cleanup),
        Err(Error::Protocol(Protocol::Stale))
    ))?;
    check(cleanup.is_none())?;
    let later = original
        .checked_add(std::time::Duration::from_secs(30))
        .ok_or(Protocol::Overflow)?;
    let repeated = retain(&mut rows, 7, later, grace, 1, Ok(()), Ok(false));
    check(!repeated.fence && rows.len() == 1 && rows[0].hard == hard)?;
    repeated.errors.finish(&mut cleanup)
}

#[test]
fn unknown_quiescence_requires_fencing_and_preserves_both_original_errors() -> Result<(), Error> {
    let mut rows: Vec<Retiring<u8>> = Vec::new();
    let actual = retain(
        &mut rows,
        7,
        Instant::now(),
        std::time::Duration::from_secs(3),
        1,
        Err(Protocol::Stale.into()),
        Err(Protocol::OutcomeUnknown.into()),
    );
    check(actual.fence && rows.is_empty())?;
    let mut cleanup = None;
    check(matches!(
        actual.errors.finish(&mut cleanup),
        Err(Error::Protocol(Protocol::Stale))
    ))?;
    check(matches!(
        cleanup,
        Some(Error::Protocol(Protocol::OutcomeUnknown))
    ))
}

#[test]
fn full_retirement_ledger_never_evicts_or_renews_another_original_operation() -> Result<(), Error> {
    let hard = Instant::now();
    let mut rows = vec![Retiring {
        operation: 3_u8,
        hard,
    }];
    let actual = retain(
        &mut rows,
        7,
        hard,
        std::time::Duration::from_secs(3),
        1,
        Ok(()),
        Ok(false),
    );
    check(actual.fence && rows.len() == 1 && rows[0].operation == 3 && rows[0].hard == hard)?;
    let mut cleanup = None;
    check(matches!(
        actual.errors.finish(&mut cleanup),
        Err(Error::Protocol(Protocol::Capacity))
    ))?;
    check(cleanup.is_none())
}

#[test]
fn actual_quiescence_needs_no_retirement_slot_even_when_cancel_refused() -> Result<(), Error> {
    let mut rows: Vec<Retiring<u8>> = Vec::new();
    let actual = retain(
        &mut rows,
        7,
        Instant::now(),
        std::time::Duration::from_secs(3),
        0,
        Err(Protocol::Stale.into()),
        Ok(true),
    );
    check(!actual.fence && rows.is_empty())?;
    let mut cleanup = None;
    check(matches!(
        actual.errors.finish(&mut cleanup),
        Err(Error::Protocol(Protocol::Stale))
    ))?;
    check(cleanup.is_none())
}

#[test]
fn unrepresentable_retirement_target_requires_fencing_without_losing_cause() -> Result<(), Error> {
    let mut rows: Vec<Retiring<u8>> = Vec::new();
    let actual = retain(
        &mut rows,
        7,
        Instant::now(),
        std::time::Duration::MAX,
        1,
        Err(Protocol::Stale.into()),
        Ok(false),
    );
    check(actual.fence && rows.is_empty())?;
    let mut cleanup = None;
    check(matches!(
        actual.errors.finish(&mut cleanup),
        Err(Error::Protocol(Protocol::Stale))
    ))?;
    check(matches!(cleanup, Some(Error::Protocol(Protocol::Overflow))))
}
