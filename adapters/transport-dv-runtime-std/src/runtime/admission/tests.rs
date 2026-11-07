//! Actual structural decoder and local refusal metadata fixtures. These do not
//! construct an Actor, invoke a Clock/PILS provider or assert crypto/native facts.
use super::*;
use std::rc::Rc;

fn check(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(Protocol::Conflict.into())
    }
}
struct Origin {
    serial: u8,
    dropped: Rc<Cell<usize>>,
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.dropped.set(self.dropped.get() + 1);
    }
}

#[test]
fn truncated_final_box_rejects_the_same_non_clone_input_owner() -> Result<(), Error> {
    // Structurally valid outer BOX with only four opaque ciphertext bytes.
    // The actual final-recipient check requires a whole inner payload prefix.
    let mut bytes = [0_u8; dv::BOX_PREFIX + 4];
    let length = u16::try_from(bytes.len()).map_err(|_| Protocol::Overflow)?;
    bytes[..2].copy_from_slice(&length.to_be_bytes());
    bytes[2..4].copy_from_slice(&dv::BOX_TYPE.to_be_bytes());
    let original =
        u16::try_from(dv::BOX_PREFIX + dv::PAYLOAD_PREFIX + 4).map_err(|_| Protocol::Overflow)?;
    bytes[84..86].copy_from_slice(&original.to_be_bytes());
    let original_bytes = bytes;
    let failure = inspect(&bytes, PeerId([1; 32]), PeerId([2; 32]))
        .err()
        .ok_or(Protocol::Conflict)?;
    let dropped = Rc::new(Cell::new(0));
    let owner = Origin {
        serial: 7,
        dropped: dropped.clone(),
    };
    let refused = failure.with_origin(owner);
    check(refused.disposition == InputRefusalDisposition::Rejected)?;
    check(matches!(
        refused.error,
        Error::Protocol(Protocol::Truncated)
    ))?;
    check(refused.origin.serial == 7 && dropped.get() == 0 && bytes == original_bytes)?;
    drop(refused);
    check(dropped.get() == 1)
}

#[test]
fn original_neighbour_shape_failure_rejects_input_without_source_scope() -> Result<(), Error> {
    let local = PeerId([1; 32]);
    let initiator = PeerId([2; 32]);
    // No signature authority is asserted: admission only inspects the exact
    // original public shape; the real Actor verifies signatures after admission.
    let bytes = dv::initiate(initiator, 7, &[3; 32], &[0; 64]);
    check(matches!(
        inspect(&bytes, local, initiator),
        Ok(Shape::Learn)
    ))?;
    let failure = inspect(&bytes, local, PeerId([4; 32]))
        .err()
        .ok_or(Protocol::Conflict)?;
    let refused = failure.with_origin(9_u8);
    check(refused.origin == 9 && refused.disposition == InputRefusalDisposition::Rejected)?;
    check(matches!(
        refused.error,
        Error::Protocol(Protocol::Malformed)
    ))
}

#[test]
fn equal_numeric_causes_keep_their_actual_stage_disposition_and_owner() -> Result<(), Error> {
    let dropped = Rc::new(Cell::new(0));
    for (serial, failure, disposition, cause) in [
        (
            1,
            Failure::deferred(Protocol::Capacity),
            InputRefusalDisposition::Deferred,
            Protocol::Capacity,
        ),
        (
            2,
            Failure::source(Protocol::Capacity),
            InputRefusalDisposition::Source,
            Protocol::Capacity,
        ),
        (
            3,
            Failure::rejected(Protocol::Malformed),
            InputRefusalDisposition::Rejected,
            Protocol::Malformed,
        ),
        (
            4,
            Failure::source(Protocol::Malformed),
            InputRefusalDisposition::Source,
            Protocol::Malformed,
        ),
    ] {
        let refused = failure.with_origin(Origin {
            serial,
            dropped: dropped.clone(),
        });
        check(refused.origin.serial == serial && refused.disposition == disposition)?;
        check(matches!(refused.error, Error::Protocol(actual) if actual == cause))?;
        check(dropped.get() == usize::from(serial - 1))?;
        drop(refused);
        check(dropped.get() == usize::from(serial))?;
    }
    Ok(())
}

#[test]
fn original_input_expiration_is_distinct_from_shared_admission_expiration() -> Result<(), Error> {
    let hard = Instant::now()
        .checked_add(std::time::Duration::from_secs(30))
        .ok_or(Protocol::Overflow)?;
    let bounds = Bound { until: 20, hard };
    let original = Budget {
        until: gnunet_wire::official::AbsoluteTime::from_micros(20),
        hard,
    };
    let input = check_bounds(&bounds, Some(original), 20)
        .err()
        .ok_or(Protocol::Conflict)?
        .with_origin(7_u8);
    check(input.origin == 7 && input.disposition == InputRefusalDisposition::Expired)?;
    check(matches!(input.error, Error::InputBudgetExpired))?;
    let source = check_bounds(&bounds, None, 20)
        .err()
        .ok_or(Protocol::Conflict)?
        .with_origin(9_u8);
    check(source.origin == 9 && source.disposition == InputRefusalDisposition::Source)?;
    check(matches!(source.error, Error::Protocol(Protocol::Deadline)))
}
