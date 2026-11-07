//! Independent literal WATCH notifications and connection ownership boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible tests assert independent official bytes and cancelled request ownership"
)]
use gnunet_client::statistics::{Selector, WatchSession, WatchValue};
use gnunet_types::Error;

const PERSISTENT_ZERO: &[u8] = b"\0\x18\0\xad\0\0\0\x02\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

#[test]
fn service_flags_reserved_and_exact_size_are_preserved() -> Result<(), Error> {
    let value = WatchValue::decode(PERSISTENT_ZERO)?;
    assert!(value.persistent());
    assert_eq!(value.flags, 2);
    assert_eq!(value.value, 0);
    let mut future = PERSISTENT_ZERO.to_vec();
    future[4..8].copy_from_slice(&0x8000_0000u32.to_be_bytes());
    future[12..16].copy_from_slice(&7u32.to_be_bytes());
    let value = WatchValue::decode(&future)?;
    assert!(!value.persistent());
    assert_eq!(value.reserved, 7);
    for size in 0..24 {
        assert!(WatchValue::decode(&PERSISTENT_ZERO[..size]).is_err());
    }
    future.push(0);
    assert!(WatchValue::decode(&future).is_err());
    assert!(WatchValue::decode(b"\0\x04\0\xab").is_err());
    Ok(())
}

#[test]
fn cancellation_does_not_reassign_a_wire_id_to_a_new_selector() -> Result<(), Error> {
    let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
    let mut session = WatchSession::<2>::new(&mut statistics_instance_1);
    let first = Selector {
        subsystem: b"a",
        name: b"old",
    };
    let second = Selector {
        subsystem: b"a",
        name: b"new",
    };
    let mut output = [0xa5; 32];
    assert_eq!(session.start(first, &mut output[..1]), Err(Error::Capacity));
    assert_eq!(output, [0xa5; 32]);
    let (old, size) = session.start(first, &mut output)?;
    assert_eq!(old.value(), 0);
    assert_eq!(&output[..size], b"\0\x0a\0\xaca\0old\0");
    session.cancel(old)?;
    assert_eq!(session.cancel(old), Err(Error::NotFound));
    let (new, _) = session.start(second, &mut output)?;
    assert_eq!(new.value(), 1);
    assert_eq!(session.receive(PERSISTENT_ZERO)?, None);
    let mut next = PERSISTENT_ZERO.to_vec();
    next[8..12].copy_from_slice(&1u32.to_be_bytes());
    let update = session.receive(&next)?.ok_or(Error::NotFound)?;
    assert_eq!(update.selector, second);
    assert_eq!(update.id, new);
    session.cancel(new)?;
    assert_eq!(session.start(first, &mut output), Err(Error::Capacity));
    next[8..12].copy_from_slice(&2u32.to_be_bytes());
    assert_eq!(session.receive(&next), Err(Error::Malformed));
    assert!(session.is_closed());
    assert_eq!(session.receive(PERSISTENT_ZERO), Err(Error::Closed));
    assert_eq!(session.start(first, &mut output), Err(Error::Closed));
    Ok(())
}
